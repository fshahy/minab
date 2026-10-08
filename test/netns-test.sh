#!/bin/bash
# netns-test.sh — end-to-end test for the Minab blocker and bypass.
#
# Builds two isolated network namespaces connected by a veth pair:
#
#   minab-cli (10.200.0.1)  <--veth-->  minab-srv (10.200.0.2)
#        │                                   │
#   blocker / bypass run here           openssl s_server :443
#   (NFQUEUE 0 / 1, iptables)           (self-signed cert)
#
# An `openssl s_client` inside the client namespace sends TLS ClientHellos
# with different SNIs; the script asserts whether each handshake completes.
# Nothing touches the host's real network — all iptables/NFQUEUE state lives
# inside the throwaway namespaces and is discarded on teardown.
#
# Requires root. Usage: sudo ./test/netns-test.sh
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS_CLI=minab-cli
NS_SRV=minab-srv
VCLI=minab-vcli
VSRV=minab-vsrv
IP_CLI=10.200.0.1
IP_SRV=10.200.0.2
PREFIX=24
PORT=443
WORK="$(mktemp -d /tmp/minab-test.XXXXXX)"

BLOCKER_PID=""
BYPASS_PID=""
SERVER_PID=""
PASS=0
FAIL=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m%s\033[0m\n' "$*"; }

cleanup() {
  [ -n "$BYPASS_PID" ]  && kill "$BYPASS_PID"  2>/dev/null
  [ -n "$BLOCKER_PID" ] && kill "$BLOCKER_PID" 2>/dev/null
  [ -n "$SERVER_PID" ]  && kill "$SERVER_PID"  2>/dev/null
  # Deleting the namespaces drops their veths and all iptables/NFQUEUE state.
  ip netns del "$NS_CLI" 2>/dev/null
  ip netns del "$NS_SRV" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

die() { red "FATAL: $*"; exit 1; }

# ── Preflight ──────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || die "must run as root (sudo $0)"
for c in ip openssl iptables-legacy timeout make; do
  command -v "$c" >/dev/null || die "missing required command: $c"
done

# Build the binaries if they are not already present.
BLOCKER_BIN="$REPO/blocker/blocker.bin"
BYPASS_BIN="$REPO/bypass/bypass.bin"
if [ ! -x "$BLOCKER_BIN" ] || [ ! -x "$BYPASS_BIN" ]; then
  command -v nim >/dev/null || die "binaries not built and 'nim' not found — install Nim 2.x, or run 'make' in blocker/ and bypass/ first"
  info "Building blocker and bypass..."
  make -C "$REPO/blocker" >/dev/null || die "blocker build failed"
  make -C "$REPO/bypass"  >/dev/null || die "bypass build failed"
fi

# ── Namespace + link setup ───────────────────────────────────────────────────
info "Setting up namespaces $NS_CLI <-> $NS_SRV ..."
ip netns add "$NS_CLI" || die "netns add $NS_CLI"
ip netns add "$NS_SRV" || die "netns add $NS_SRV"
ip link add "$VCLI" type veth peer name "$VSRV" || die "veth create"
ip link set "$VCLI" netns "$NS_CLI"
ip link set "$VSRV" netns "$NS_SRV"

ip netns exec "$NS_CLI" ip addr add "$IP_CLI/$PREFIX" dev "$VCLI"
ip netns exec "$NS_SRV" ip addr add "$IP_SRV/$PREFIX" dev "$VSRV"
ip netns exec "$NS_CLI" ip link set "$VCLI" up
ip netns exec "$NS_SRV" ip link set "$VSRV" up
ip netns exec "$NS_CLI" ip link set lo up
ip netns exec "$NS_SRV" ip link set lo up

# ── TLS server ───────────────────────────────────────────────────────────────
info "Generating self-signed cert and starting TLS server..."
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
  -subj "/CN=minab-test" >/dev/null 2>&1 || die "cert generation failed"

ip netns exec "$NS_SRV" openssl s_server -quiet -www \
  -accept "$PORT" -cert "$WORK/cert.pem" -key "$WORK/key.pem" \
  >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || die "TLS server failed to start (see $WORK/server.log)"

# passlist: only hostnames containing "allowed" are permitted
printf '# test passlist\nallowed\n' > "$WORK/passed.txt"

# ── Helpers ──────────────────────────────────────────────────────────────────
# Returns 0 if the TLS handshake to the server completes, non-zero otherwise.
tls_connect() {
  local sni="$1" out
  out="$(ip netns exec "$NS_CLI" bash -c \
    "echo Q | timeout 6 openssl s_client -brief -connect $IP_SRV:$PORT -servername '$sni' 2>&1")"
  grep -q "CONNECTION ESTABLISHED" <<<"$out"
}

# assert <expected: up|down> <sni> <description>
assert() {
  local expect="$1" sni="$2" desc="$3"
  if tls_connect "$sni"; then result=up; else result=down; fi
  if [ "$result" = "$expect" ]; then
    green "  PASS: $desc (SNI=$sni, handshake $result)"
    PASS=$((PASS + 1))
  else
    red   "  FAIL: $desc (SNI=$sni, expected $expect, got $result)"
    FAIL=$((FAIL + 1))
  fi
}

start_blocker() {
  ip netns exec "$NS_CLI" "$REPO/blocker/rules.sh" set >/dev/null
  ip netns exec "$NS_CLI" "$BLOCKER_BIN" "$WORK/passed.txt" >"$WORK/blocker.log" 2>&1 &
  BLOCKER_PID=$!
  sleep 1
  kill -0 "$BLOCKER_PID" 2>/dev/null || die "blocker failed to start (see $WORK/blocker.log)"
}

start_bypass() {
  ip netns exec "$NS_CLI" "$REPO/bypass/rules.sh" set >/dev/null
  ip netns exec "$NS_CLI" "$BYPASS_BIN" >"$WORK/bypass.log" 2>&1 &
  BYPASS_PID=$!
  sleep 1
  kill -0 "$BYPASS_PID" 2>/dev/null || die "bypass failed to start (see $WORK/bypass.log)"
}

# ── Phase 0: baseline (no tools) ─────────────────────────────────────────────
echo
info "Phase 0: no filtering — both SNIs should connect"
assert up allowed.minab-test "baseline, whitelisted name"
assert up blocked.minab-test "baseline, non-whitelisted name"

# ── Phase 1: blocker only ────────────────────────────────────────────────────
echo
info "Phase 1: blocker active — whitelist enforced"
start_blocker
assert up   allowed.minab-test "blocker allows whitelisted SNI"
assert down blocked.minab-test "blocker blocks non-whitelisted SNI"

# ── Phase 2: blocker + bypass ────────────────────────────────────────────────
echo
info "Phase 2: bypass active — segmentation defeats the blocker"
start_bypass
assert up blocked.minab-test "bypass smuggles the blocked SNI through"
assert up allowed.minab-test "whitelisted SNI still works with bypass"

# ── Summary ──────────────────────────────────────────────────────────────────
echo
if [ "$FAIL" -eq 0 ]; then
  green "All $PASS checks passed."
  exit 0
else
  red "$FAIL of $((PASS + FAIL)) checks FAILED."
  echo "Logs preserved under $WORK (not deleted on failure)."
  trap - EXIT
  [ -n "$BYPASS_PID" ]  && kill "$BYPASS_PID"  2>/dev/null
  [ -n "$BLOCKER_PID" ] && kill "$BLOCKER_PID" 2>/dev/null
  [ -n "$SERVER_PID" ]  && kill "$SERVER_PID"  2>/dev/null
  ip netns del "$NS_CLI" 2>/dev/null
  ip netns del "$NS_SRV" 2>/dev/null
  exit 1
fi
