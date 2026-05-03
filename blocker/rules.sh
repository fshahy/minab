#!/bin/bash
set -e

IPT=iptables-legacy
IP6T=ip6tables-legacy
QUEUE=0
RULE="-p tcp --dport 443 -j NFQUEUE --queue-num $QUEUE"
QUIC="-p udp --dport 443 -j DROP"
IP6_TCP="-p tcp --dport 443 -j DROP"
IP6_UDP="-p udp --dport 443 -j DROP"

case "$1" in
  set)
    $IPT  -I OUTPUT  $RULE
    $IPT  -I FORWARD $RULE
    $IPT  -I OUTPUT  $QUIC
    $IPT  -I FORWARD $QUIC
    $IP6T -I OUTPUT  $IP6_TCP
    $IP6T -I FORWARD $IP6_TCP
    $IP6T -I OUTPUT  $IP6_UDP
    $IP6T -I FORWARD $IP6_UDP
    echo "Rules added (IPv4 TCP→NFQUEUE, IPv4 UDP→DROP, IPv6→DROP)."
    ;;
  clear)
    $IPT  -D OUTPUT  $RULE     2>/dev/null && echo "OUTPUT TCP rule removed."       || echo "OUTPUT TCP rule not found."
    $IPT  -D FORWARD $RULE     2>/dev/null && echo "FORWARD TCP rule removed."      || echo "FORWARD TCP rule not found."
    $IPT  -D OUTPUT  $QUIC     2>/dev/null && echo "OUTPUT UDP rule removed."       || echo "OUTPUT UDP rule not found."
    $IPT  -D FORWARD $QUIC     2>/dev/null && echo "FORWARD UDP rule removed."      || echo "FORWARD UDP rule not found."
    $IP6T -D OUTPUT  $IP6_TCP  2>/dev/null && echo "OUTPUT IPv6 TCP rule removed."  || echo "OUTPUT IPv6 TCP rule not found."
    $IP6T -D FORWARD $IP6_TCP  2>/dev/null && echo "FORWARD IPv6 TCP rule removed." || echo "FORWARD IPv6 TCP rule not found."
    $IP6T -D OUTPUT  $IP6_UDP  2>/dev/null && echo "OUTPUT IPv6 UDP rule removed."  || echo "OUTPUT IPv6 UDP rule not found."
    $IP6T -D FORWARD $IP6_UDP  2>/dev/null && echo "FORWARD IPv6 UDP rule removed." || echo "FORWARD IPv6 UDP rule not found."
    ;;
  *)
    echo "Usage: sudo $0 {set|clear}"
    exit 1
    ;;
esac
