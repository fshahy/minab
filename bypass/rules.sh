#!/bin/bash
set -e

IPT=iptables-legacy

case "$1" in
  set)
    # Packets already marked 1 (re-injected splits) skip queue 1 and go straight to queue 0.
    # No --queue-bypass: if bypass is not running, packets are dropped (not silently accepted).
    $IPT -I OUTPUT  1 -p tcp --dport 443 -m mark ! --mark 1 -j NFQUEUE --queue-num 1
    $IPT -I FORWARD 1 -p tcp --dport 443 -m mark ! --mark 1 -j NFQUEUE --queue-num 1
    echo "Bypass rules added (queue 1 before queue 0)."
    ;;
  clear)
    $IPT -D OUTPUT  -p tcp --dport 443 -m mark ! --mark 1 -j NFQUEUE --queue-num 1 2>/dev/null && echo "OUTPUT bypass rule removed."  || echo "OUTPUT bypass rule not found."
    $IPT -D FORWARD -p tcp --dport 443 -m mark ! --mark 1 -j NFQUEUE --queue-num 1 2>/dev/null && echo "FORWARD bypass rule removed." || echo "FORWARD bypass rule not found."
    ;;
  *)
    echo "Usage: sudo $0 {set|clear}"
    exit 1
    ;;
esac
