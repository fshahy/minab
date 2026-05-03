# Minab: TLS SNI Blocker & Bypass

A set of Linux and Windows tools that demonstrate TLS SNI-based traffic filtering and how TCP segmentation defeats it. The Linux tools hook into the kernel via **NFQUEUE** — no userspace proxy, no certificate installation. The Windows bypass uses **WinDivert**.

## How it works

### Blocker

Sits on **NFQUEUE 0**. For every outgoing TCP/443 packet it:

1. Parses the IP and TCP headers to find the TLS payload
2. Checks whether the packet is a TLS ClientHello (`isClientHello`)
3. Parses the ClientHello to extract the SNI hostname
4. If the packet is a ClientHello but the SNI cannot be read (e.g. ECH), drops it immediately
5. If the SNI is readable, checks it against `passed.txt` — if found, accepts; otherwise drops
6. On drop, sends a TCP RST back to the client for an immediate connection error

This is a **whitelist** model: only SNIs listed in `passed.txt` are allowed through. Connections using **ECH (Encrypted Client Hello)** — where the SNI is encrypted — are blocked entirely.

### Bypass (Linux)

Sits on **NFQUEUE 1**, inserted **before** the blocker in the iptables chain. For every TLS ClientHello it receives — including ECH ClientHellos — it:

1. Drops the original packet from queue 1
2. Re-injects the payload split across two raw TCP segments:
   - **Segment A** — first 3 bytes (TLS record header only)
   - **Segment B** — the rest of the record, with sequence number advanced by 3
3. Marks both injected packets (`SO_MARK=1`) so they skip queue 1 and pass directly to queue 0

The blocker sees each segment individually and finds no complete ClientHello in either:
- Segment A: `payloadLen = 3 < 6` → neither `isClientHello` nor `findSni` match → `NF_ACCEPT`
- Segment B: first byte ≠ `0x16` → same result → `NF_ACCEPT`

The server's TCP stack reassembles both segments and the TLS handshake succeeds normally — whether SNI is plaintext or ECH.

```
Browser → [queue 1: bypass] → [queue 0: blocker] → Internet
                  ↓ any ClientHello (including ECH)
           DROP original
           inject segment A (3 bytes,  mark=1) ──→ [queue 0] → ACCEPT
           inject segment B (rest,     mark=1) ──→ [queue 0] → ACCEPT
```

### Bypass (Windows)

`winbypass.nim` is the Windows port of `bypass.nim`. It uses **WinDivert** to intercept outgoing TLS ClientHellos (including ECH) and re-injects the payload split across two TCP segments using the same 3-byte split. Requires Administrator privileges and `WinDivert.dll` in the same directory or on `PATH`.

---

## Files

```
blocker/
  blocker.nim    SNI-based traffic filter (whitelist + ECH block)
  Makefile       Build the blocker binary
  passed.txt     Whitelisted SNI substrings — one per line
  rules.sh       iptables rule management for the blocker

bypass/
  bypass.nim     TCP segmentation bypass for the blocker (Linux)
  Makefile       Build the bypass binary
  rules.sh       iptables rule management for the bypass

winbypass/
  winbypass.nim  TCP segmentation bypass for the blocker (Windows)
  Makefile       Cross-compile winbypass.exe using MinGW
  windivert.h    WinDivert C header
  WinDivert.dll  WinDivert runtime (ship with the .exe)
  WinDivert.lib  WinDivert import library (link at build time)
  WinDivert64.sys WinDivert kernel driver
```

---

## Dependencies

### Linux (blocker & bypass)

| Package | Required by |
|---------|-------------|
| `libnetfilter-queue-dev` | blocker, bypass |
| `libmnl-dev` | blocker, bypass |

```bash
sudo apt install libnetfilter-queue-dev libmnl-dev
```

Nim 2.x compiler required.

### Windows (winbypass)

Cross-compile from Linux using MinGW:

```bash
sudo apt install mingw-w64
```

Nim 2.x compiler required.

---

## Build

### Linux

```bash
cd blocker && make
cd bypass  && make
```

### Windows (cross-compile from Linux)

```bash
cd winbypass && make
```

This produces `winbypass.exe`. Copy `winbypass.exe`, `WinDivert.dll`, and `WinDivert64.sys` to the target Windows machine.

---

## Usage

### Blocker only

```bash
cd blocker
sudo ./rules.sh set                  # add iptables rules
sudo ./blocker.bin passed.txt        # allow only SNIs in passed.txt; block ECH
```

```bash
sudo ./rules.sh clear                # remove rules when done
```

### Blocker + Bypass (Linux)

Run in order — the bypass rule inserts at position 1, so the blocker's rule must exist first:

```bash
# Terminal 1 — deploy blocker
cd blocker
sudo ./rules.sh set
sudo ./blocker.bin passed.txt

# Terminal 2 — deploy bypass (inserts before blocker's rule)
cd bypass
sudo ./rules.sh set
sudo ./bypass.bin
```

```bash
cd bypass  && sudo ./rules.sh clear   # remove bypass rule
cd blocker && sudo ./rules.sh clear   # remove blocker rule
```

### Bypass (Windows)

Run `winbypass.exe` as Administrator. No iptables equivalent is needed — WinDivert intercepts packets at the kernel level.

```
winbypass.exe
```

`WinDivert.dll` and `WinDivert64.sys` must be in the same directory as `winbypass.exe`.

### iptables rule order after both Linux tools are active

```
1. tcp dport 443, mark != 1  →  NFQUEUE 1  (bypass)
2. tcp dport 443             →  NFQUEUE 0  (blocker)
3. udp dport 443             →  DROP       (disable QUIC/HTTP3)
4. ip6 tcp dport 443         →  DROP       (force IPv4 fallback)
5. ip6 udp dport 443         →  DROP       (disable IPv6 QUIC)
```

Rule 1 has no `--queue-bypass`. If `./bypass` is not running, packets are dropped (no listener on queue 1). Both programs must be running together once the bypass rule is active.

---

## passed.txt format

```
# Comments start with #
google
microsoft
claude
```

Matching is by **substring**: an entry of `google` matches `google.com`, `www.google.com`, `accounts.google.com`, etc.

---

## Notes

- All programs require `root` / Administrator
- Linux rules cover both `OUTPUT` (local machine) and `FORWARD` (gateway) chains
- UDP 443 and all IPv6 port 443 traffic is dropped by `blocker/rules.sh set` to prevent QUIC and IPv6 bypass
- The bypass exploits single-packet inspection: the blocker has no TCP stream reassembly. A blocker that buffers and reassembles TCP streams across packets would defeat this technique
- **ECH (Encrypted Client Hello)**: the blocker detects and drops any ClientHello whose SNI cannot be read, so ECH connections are blocked rather than silently accepted. The bypass fragments ECH ClientHellos the same way it handles plain-SNI ones, defeating the ECH block

---

## Motivation

This project is created in memory of schoolchildren killed in the <a href="https://en.wikipedia.org/wiki/2026_Minab_school_attack" target="_blank">2026 Minab school attack</a> — a US air strike on a school in Minab, Iran. May they rest in peace.
