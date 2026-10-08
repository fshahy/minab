# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Minab is a set of Nim programs demonstrating TLS SNI-based traffic filtering (the **blocker**) and the TCP-segmentation technique that defeats it (the **bypass**, in Linux and Windows variants). See `README.md` for the full protocol-level walkthrough and usage; this file covers what isn't obvious from a single file.

## Build

```bash
cd blocker   && make      # -> blocker.bin   (nim c -d:release)
cd bypass    && make      # -> bypass.bin
cd winbypass && make      # -> winbypass.exe (cross-compiled via x86_64-w64-mingw32-gcc)
make clean                # per-directory; removes the binary and nimcache/
```

Requires the Nim 2.x compiler. Linux targets link `libnetfilter_queue`/`libnfnetlink` (`{.passL.}` in the source) and need `libnetfilter-queue-dev libmnl-dev`. The Windows cross-compile needs `mingw-w64`; it links `WinDivert.lib` and ships alongside `WinDivert.dll` + `WinDivert64.sys`.

Built binaries (`*.bin`, `winbypass.exe`) are gitignored.

## Running / testing

End-to-end test harness:

```bash
sudo ./test/netns-test.sh    # builds binaries if needed, runs the allow/block/bypass matrix
```

It spins up two throwaway network namespaces (client + TLS server), runs the real `blocker.bin`/`bypass.bin` with the actual `rules.sh`, and asserts the allow/block/bypass behavior without touching the host network. Needs `root` and Nim (or pre-built binaries); see `test/README.md`. This covers the Linux path only — manual verification with real HTTPS traffic is still the way to exercise ECH and the Windows `winbypass`.

Key operational invariants when running the Linux tools:

- The **blocker rule must be installed before the bypass rule.** `bypass/rules.sh` inserts at `OUTPUT`/`FORWARD` position 1, so the blocker's queue-0 rule must already exist below it.
- Both daemons must run together once the bypass rule is active: that rule has **no `--queue-bypass`**, so with nothing listening on queue 1 all TCP/443 packets are dropped.
- `rules.sh` uses `iptables-legacy` / `ip6tables-legacy`, not `nft`.

## Architecture

**Two NFQUEUE daemons chained in iptables** (`blocker` on queue 0, `bypass` on queue 1, bypass first). Each reads raw packets off its queue, parses IP+TCP headers by hand, and returns an NFQUEUE verdict.

- `blocker/blocker.nim` — whitelist filter. `isClientHello` + `findSni` parse the TLS ClientHello; `isAllowed` does **substring** matching against the passlist loaded from the file given as `argv[1]` (default `passed.txt`). On block it crafts a spoofed TCP **RST** (src/dst swapped, seq = client's ACK) via a raw `IPPROTO_RAW` socket and returns `NF_DROP`. A ClientHello whose SNI can't be read (ECH) is dropped, not accepted.
- `bypass/bypass.nim` — defeats the blocker by splitting each ClientHello at `SPLIT_AT = 3` bytes into two raw-socket-injected TCP segments (seq advanced by 3 on the second), then dropping the original. The raw socket carries `SO_MARK=1`, which the queue-1 iptables rule (`-m mark ! --mark 1`) uses to let re-injected segments skip the bypass and flow to the blocker, where neither 3-byte fragment matches `isClientHello`/`findSni`. The attack depends on the blocker doing **per-packet** inspection with no TCP reassembly.
- `winbypass/winbypass.nim` — Windows port of the bypass using **WinDivert** instead of NFQUEUE/raw sockets; same 3-byte split logic.

**Cross-file coupling to keep in sync when editing:**

- `blocker.nim` and `bypass.nim` each carry their own hand-written copy of the libnetfilter_queue C bindings and the IP/TCP header + checksum helpers (`ipChecksum`, `tcpChecksum`, `getIpHeaderLen`, `getTcpHeaderLen`). These are duplicated, not shared — changes to one are not automatically reflected in the other.
- `bypass.nim` and `winbypass.nim` implement the same split algorithm against different packet-capture backends; keep their fragmentation behavior aligned.
- The `SO_MARK=1` value in `bypass.nim` and the `--mark 1` match in `bypass/rules.sh` must agree.
- `SPLIT_AT = 3` in the bypass corresponds to the blocker's `payloadLen < 6` guard in `isClientHello`/`findSni`; both halves of the split must individually fail detection.
