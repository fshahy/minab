# TLS SNI Blocker & Bypass

A pair of Linux kernel-level tools that demonstrate TLS SNI-based traffic filtering and how TCP segmentation defeats it. Both programs hook into the kernel via **NFQUEUE** — no userspace proxy, no certificate installation.

## How it works

### Blocker

Sits on **NFQUEUE 0**. For every outgoing TCP/443 packet it:

1. Parses the IP and TCP headers to find the TLS payload
2. Parses the TLS ClientHello to extract the SNI hostname
3. Checks the SNI against `passed.txt` — if found, accepts; otherwise drops
4. On drop, sends a TCP RST back to the client for an immediate connection error

This is a **whitelist** model: only SNIs listed in `passed.txt` are allowed through. Everything else is blocked.

### Bypass

Sits on **NFQUEUE 1**, inserted **before** the blocker in the iptables chain. For every TLS ClientHello it receives, it:

1. Drops the original packet from queue 1
2. Re-injects the payload split across two raw TCP segments:
   - **Segment A** — first 3 bytes (TLS record header only)
   - **Segment B** — the rest of the record, with sequence number advanced by 3
3. Marks both injected packets (`SO_MARK=1`) so they skip queue 1 and pass directly to queue 0

The blocker sees each segment individually and finds no complete SNI in either:
- Segment A: `payloadLen = 3 < 6` → SNI parser returns `""` → `NF_ACCEPT`
- Segment B: first byte ≠ `0x16` → SNI parser returns `""` → `NF_ACCEPT`

The server's TCP stack reassembles both segments and the TLS handshake succeeds normally.

```
Browser → [queue 1: bypass] → [queue 0: blocker] → Internet
                  ↓ any ClientHello
           DROP original
           inject segment A (3 bytes,  mark=1) ──→ [queue 0] → ACCEPT
           inject segment B (rest,     mark=1) ──→ [queue 0] → ACCEPT
```

---

## Files

| File | Purpose |
|------|---------|
| `blocker.nim` | SNI-based traffic filter (whitelist mode) |
| `bypass.nim` | TCP segmentation bypass for the blocker |
| `rules.sh` | iptables rule management |
| `passed.txt` | Whitelisted SNI substrings — one per line |

---

## Dependencies

| Package | Required by |
|---------|-------------|
| `libnetfilter-queue-dev` | blocker, **bypass** |
| `libmnl-dev` | blocker, bypass |

```bash
sudo apt install libnetfilter-queue-dev libmnl-dev
```

> **Note:** The bypass program requires `libnetfilter-queue-dev` at both build time and runtime. Install it before compiling or running `bypass`.

Nim 2.x compiler required.

---

## Build

```bash
nim c -d:release blocker.nim
nim c -d:release bypass.nim
```

---

## Usage

### Blocker only

```bash
sudo ./rules.sh set                  # add iptables rules
sudo ./blocker passed.txt            # allow only SNIs in passed.txt
```

```bash
sudo ./rules.sh clear                # remove rules when done
```

### Blocker + Bypass

Run in order — `bypass-set` inserts at position 1, so the blocker's rule must exist first:

```bash
# Terminal 1 — deploy blocker
sudo ./rules.sh set
sudo ./blocker passed.txt

# Terminal 2 — deploy bypass (inserts before blocker's rule)
sudo ./rules.sh bypass-set
sudo ./bypass
```

```bash
sudo ./rules.sh bypass-clear         # remove bypass rule
sudo ./rules.sh clear                # remove blocker rule
```

### iptables rule order after both are active

```
1. tcp dport 443, mark != 1  →  NFQUEUE 1  (bypass)
2. tcp dport 443             →  NFQUEUE 0  (blocker)
3. udp dport 443             →  DROP       (disable QUIC/HTTP3)
4. ip6 tcp dport 443         →  DROP       (force IPv4 fallback)
5. ip6 udp dport 443         →  DROP       (disable IPv6 QUIC)
```

Rule 1 has no `--queue-bypass`. If `./bypass` is not running, packets are dropped (no listener on queue 1). Both programs must be running together once `bypass-set` is active.

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

- Both programs require `root` (`sudo`)
- Rules cover both `OUTPUT` (local machine) and `FORWARD` (gateway) chains
- UDP 443 and all IPv6 port 443 traffic is dropped by `rules.sh set` to prevent QUIC and IPv6 bypass
- The bypass exploits single-packet inspection: the blocker has no TCP stream reassembly. A blocker that buffers and reassembles TCP streams across packets would defeat this technique
- Sites using **ECH (Encrypted Client Hello)** hide the real SNI inside an encrypted extension — neither blocking nor bypass based on SNI works against ECH
