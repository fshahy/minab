# Tests

## `netns-test.sh` — end-to-end harness

Runs the real `blocker.bin` and `bypass.bin` against a real `openssl` TLS
server inside throwaway Linux network namespaces, so the full NFQUEUE +
iptables path is exercised **without touching the host network**.

```bash
sudo ./test/netns-test.sh
```

### Topology

```
minab-cli (10.200.0.1)  <-- veth -->  minab-srv (10.200.0.2)
     │                                      │
blocker / bypass + iptables            openssl s_server :443
```

An `openssl s_client` in the client namespace sends TLS ClientHellos with
different SNIs; the script asserts whether each handshake completes.

### What it checks

The test passlist allows only hostnames containing `allowed`.

| Phase | Tools running | `allowed.*` | `blocked.*` |
|-------|---------------|-------------|-------------|
| 0 baseline | none | connects | connects |
| 1 blocker  | blocker | connects | **reset** |
| 2 bypass   | blocker + bypass | connects | **connects** (smuggled through) |

Phase 2 is the point of the project: TCP segmentation defeats the SNI
blocker even for a name the blocker is configured to drop.

### Requirements

- `root` (namespaces, iptables, NFQUEUE, raw sockets)
- `ip`, `openssl`, `iptables-legacy`, `timeout`, `make`
- The binaries, or `nim` (2.x) to build them — the script runs `make` in
  `blocker/` and `bypass/` if `blocker.bin` / `bypass.bin` are missing.

On failure the namespaces are torn down but the logs
(`blocker.log`, `bypass.log`, `server.log`) are kept under a
`/tmp/minab-test.*` directory for inspection.
