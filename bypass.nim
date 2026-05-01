# bypass.nim
# Defeats the SNI blocker (blocker.nim) via TCP segmentation.
#
# Exploits the fact that blocker.nim inspects each TCP segment in
# isolation with no stream reassembly. For every TLS ClientHello it
# receives on queue 1, it:
#   - DROPs the original packet
#   - Re-injects the payload split across two raw TCP segments:
#       segment A: first 3 bytes (TLS record header only)
#       segment B: remainder of the record, seq += 3
#   Both segments carry SO_MARK=1 so they skip queue 1 and pass
#   directly to queue 0. The blocker's findSni sees:
#     segment A: payloadLen=3 < 6  → returns ""  → NF_ACCEPT
#     segment B: p[0] ≠ 0x16       → returns ""  → NF_ACCEPT
#   The server's TCP stack reassembles both segments normally and
#   the TLS handshake completes unblocked.
#
# Build: nim c -d:release bypass.nim
# Run:   sudo ./bypass   (requires: sudo ./rules.sh bypass-set)

import std/[posix, strutils]

{.passL: "-lnetfilter_queue -lnfnetlink".}

# ── Linux constants not in std/posix ─────────────────────────────────────────

const
  IPPROTO_RAW = 255.cint
  IP_HDRINCL  = 3.cint
  SO_MARK     = 36.cint
  BYPASS_MARK = 1u32

# ── libnetfilter_queue bindings ───────────────────────────────────────────────

type
  NfqHandle   = pointer
  NfqQHandle  = pointer
  NfqData     = pointer
  NfqMsgPacketHdr {.importc: "struct nfqnl_msg_packet_hdr",
                    header: "<linux/netfilter/nfnetlink_queue.h>".} = object
    packet_id: uint32
    hw_protocol: uint16
    hook: uint8

proc nfq_open(): NfqHandle
  {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}
proc nfq_close(h: NfqHandle): cint
  {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}
proc nfq_bind_pf(h: NfqHandle, pf: uint16): cint
  {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}
proc nfq_create_queue(h: NfqHandle, num: uint16,
                      cb: proc(qh: NfqQHandle, nfmsg: pointer,
                               nfd: NfqData, data: pointer): cint {.cdecl.},
                      data: pointer): NfqQHandle
  {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}
proc nfq_destroy_queue(qh: NfqQHandle): cint
  {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}
proc nfq_set_mode(qh: NfqQHandle, mode: uint8, range: uint32): cint
  {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}
proc nfq_fd(h: NfqHandle): cint
  {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}
proc nfq_get_msg_packet_hdr(nfd: NfqData): ptr NfqMsgPacketHdr
  {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}
proc nfq_get_payload(nfd: NfqData, data: ptr ptr uint8): cint
  {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}
proc nfq_set_verdict(qh: NfqQHandle, id: uint32,
                     verdict: uint32, data_len: uint32,
                     buf: ptr uint8): cint
  {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}
proc nfq_handle_packet(h: NfqHandle, buf: ptr char, len: cint): cint
  {.importc, header: "<libnetfilter_queue/libnetfilter_queue.h>".}

const
  NF_DROP           = 0u32
  NF_ACCEPT         = 1u32
  NFQNL_COPY_PACKET = 2u8
  SPLIT_AT          = 3

# ── Packet parsing (mirrors blocker.nim) ─────────────────────────────────────

proc getIpHeaderLen(pkt: ptr uint8): int =
  (cast[ptr UncheckedArray[uint8]](pkt)[0] and 0x0F).int * 4

proc getTcpHeaderLen(tcp: ptr uint8): int =
  (cast[ptr UncheckedArray[uint8]](tcp)[12] shr 4).int * 4

proc findSni(payload: ptr uint8, payloadLen: int): string =
  let p = cast[ptr UncheckedArray[uint8]](payload)
  if payloadLen < 6: return ""
  if p[0] != 0x16: return ""
  if p[5] != 0x01: return ""
  var pos = 43
  if pos >= payloadLen: return ""
  let sessionIdLen = p[pos].int
  pos += 1 + sessionIdLen
  if pos + 2 >= payloadLen: return ""
  let cipherSuitesLen = (p[pos].int shl 8) or p[pos+1].int
  pos += 2 + cipherSuitesLen
  if pos >= payloadLen: return ""
  let compressionLen = p[pos].int
  pos += 1 + compressionLen
  if pos + 2 >= payloadLen: return ""
  pos += 2
  while pos + 4 <= payloadLen:
    let extType = (p[pos].int shl 8) or p[pos+1].int
    let extLen  = (p[pos+2].int shl 8) or p[pos+3].int
    pos += 4
    if extType == 0x0000:
      if pos + 5 <= payloadLen:
        let nameLen = (p[pos+3].int shl 8) or p[pos+4].int
        let nameStart = pos + 5
        if nameStart + nameLen <= payloadLen:
          var sni = newString(nameLen)
          for i in 0 ..< nameLen: sni[i] = char(p[nameStart + i])
          return sni
    pos += extLen
  return ""

# ── Raw packet injection ──────────────────────────────────────────────────────

var rawSock: cint = -1

proc ipChecksum(buf: ptr uint8, len: int): uint16 =
  var sum: uint32 = 0
  let p = cast[ptr UncheckedArray[uint8]](buf)
  var i = 0
  while i + 1 < len:
    sum += (p[i].uint32 shl 8) or p[i+1].uint32
    i += 2
  if (len and 1) != 0: sum += p[len-1].uint32 shl 8
  while (sum shr 16) != 0: sum = (sum and 0xFFFF) + (sum shr 16)
  uint16(not sum)

proc tcpChecksum(ipHdr: ptr uint8, ipHdrLen: int,
                 tcpSeg: ptr uint8, tcpSegLen: int): uint16 =
  var pseudo = newSeq[uint8](12 + tcpSegLen)
  let ip  = cast[ptr UncheckedArray[uint8]](ipHdr)
  let tcp = cast[ptr UncheckedArray[uint8]](tcpSeg)
  pseudo[0] = ip[12]; pseudo[1] = ip[13]; pseudo[2] = ip[14]; pseudo[3] = ip[15]
  pseudo[4] = ip[16]; pseudo[5] = ip[17]; pseudo[6] = ip[18]; pseudo[7] = ip[19]
  pseudo[8] = 0; pseudo[9] = 6
  pseudo[10] = uint8(tcpSegLen shr 8); pseudo[11] = uint8(tcpSegLen)
  for i in 0..<tcpSegLen: pseudo[12+i] = tcp[i]
  pseudo[12+16] = 0; pseudo[12+17] = 0   # zero TCP checksum field before computing
  ipChecksum(addr pseudo[0], pseudo.len)

proc sendSplitPackets(pkt: ptr uint8, pktLen: int) =
  let p         = cast[ptr UncheckedArray[uint8]](pkt)
  let ipLen     = pkt.getIpHeaderLen
  let tcpHdrLen = cast[ptr uint8](cast[int](pkt) + ipLen).getTcpHeaderLen
  let dataOff   = ipLen + tcpHdrLen
  let dataLen   = pktLen - dataOff

  var dst: Sockaddr_in
  dst.sin_family = uint16(AF_INET)
  copyMem(addr dst.sin_addr, addr p[16], 4)

  if dataLen <= SPLIT_AT:
    discard sendto(SocketHandle(rawSock), pkt, pktLen, 0.cint,
                   cast[ptr SockAddr](addr dst), SockLen(sizeof(dst)))
    return

  let origSeq = (p[ipLen+4].uint32 shl 24) or (p[ipLen+5].uint32 shl 16) or
                (p[ipLen+6].uint32 shl 8)  or  p[ipLen+7].uint32

  # Packet A: headers + first SPLIT_AT bytes of TLS record
  let pktALen = dataOff + SPLIT_AT
  var pktA = newSeq[uint8](pktALen)
  copyMem(addr pktA[0], pkt, dataOff)
  copyMem(addr pktA[dataOff], addr p[dataOff], SPLIT_AT)
  pktA[2] = uint8(pktALen shr 8); pktA[3] = uint8(pktALen)
  pktA[10] = 0; pktA[11] = 0
  let ckA_ip = ipChecksum(addr pktA[0], ipLen)
  pktA[10] = uint8(ckA_ip shr 8); pktA[11] = uint8(ckA_ip)
  pktA[ipLen+16] = 0; pktA[ipLen+17] = 0
  let ckA_tcp = tcpChecksum(addr pktA[0], ipLen, addr pktA[ipLen], tcpHdrLen + SPLIT_AT)
  pktA[ipLen+16] = uint8(ckA_tcp shr 8); pktA[ipLen+17] = uint8(ckA_tcp)

  # Packet B: headers (seq += SPLIT_AT) + remaining TLS bytes
  let restLen = dataLen - SPLIT_AT
  let pktBLen = dataOff + restLen
  var pktB = newSeq[uint8](pktBLen)
  copyMem(addr pktB[0], pkt, dataOff)
  copyMem(addr pktB[dataOff], addr p[dataOff + SPLIT_AT], restLen)
  pktB[2] = uint8(pktBLen shr 8); pktB[3] = uint8(pktBLen)
  let newSeq = origSeq + uint32(SPLIT_AT)
  pktB[ipLen+4] = uint8(newSeq shr 24); pktB[ipLen+5] = uint8(newSeq shr 16)
  pktB[ipLen+6] = uint8(newSeq shr 8);  pktB[ipLen+7] = uint8(newSeq)
  pktB[10] = 0; pktB[11] = 0
  let ckB_ip = ipChecksum(addr pktB[0], ipLen)
  pktB[10] = uint8(ckB_ip shr 8); pktB[11] = uint8(ckB_ip)
  pktB[ipLen+16] = 0; pktB[ipLen+17] = 0
  let ckB_tcp = tcpChecksum(addr pktB[0], ipLen, addr pktB[ipLen], tcpHdrLen + restLen)
  pktB[ipLen+16] = uint8(ckB_tcp shr 8); pktB[ipLen+17] = uint8(ckB_tcp)

  discard sendto(SocketHandle(rawSock), addr pktA[0], pktALen, 0.cint,
                 cast[ptr SockAddr](addr dst), SockLen(sizeof(dst)))
  discard sendto(SocketHandle(rawSock), addr pktB[0], pktBLen, 0.cint,
                 cast[ptr SockAddr](addr dst), SockLen(sizeof(dst)))

# ── Queue callback ────────────────────────────────────────────────────────────

proc packetCallback(qh: NfqQHandle, nfmsg: pointer,
                    nfd: NfqData, data: pointer): cint {.cdecl.} =
  let hdr = nfq_get_msg_packet_hdr(nfd)
  if hdr == nil: return 0

  let pktId = ((hdr.packet_id and 0xFF) shl 24) or
              (((hdr.packet_id shr 8) and 0xFF) shl 16) or
              (((hdr.packet_id shr 16) and 0xFF) shl 8) or
              ((hdr.packet_id shr 24) and 0xFF)

  var rawPkt: ptr uint8
  let pktLen = nfq_get_payload(nfd, addr rawPkt)
  if pktLen < 40 or rawPkt == nil:
    discard nfq_set_verdict(qh, pktId, NF_ACCEPT, 0, nil)
    return 0

  let ipLen   = rawPkt.getIpHeaderLen
  let tcpLen  = cast[ptr uint8](cast[int](rawPkt) + ipLen).getTcpHeaderLen
  let dataOff = ipLen + tcpLen
  let dataLen = pktLen.int - dataOff

  if dataLen > 0:
    let tlsStart = cast[ptr uint8](cast[int](rawPkt) + dataOff)
    let sni = findSni(tlsStart, dataLen)
    if sni.len > 0 and "nvidia.com" in sni:
      echo "[BYPASS] fragmenting SNI=", sni
      sendSplitPackets(rawPkt, pktLen.int)
      discard nfq_set_verdict(qh, pktId, NF_DROP, 0, nil)
      return 0

  discard nfq_set_verdict(qh, pktId, NF_ACCEPT, 0, nil)
  return 0

# ── Main ─────────────────────────────────────────────────────────────────────

var running = true
proc sigHandler(sig: cint) {.noconv.} = running = false

proc main() =
  rawSock = cint(socket(AF_INET.cint, SOCK_RAW.cint, IPPROTO_RAW))
  if rawSock < 0:
    echo "socket() failed — are you root?"
    quit(1)
  var one: cint = 1
  discard setsockopt(SocketHandle(rawSock), IPPROTO_IP.cint, IP_HDRINCL,
                     addr one, SockLen(sizeof(one)))
  var mark = BYPASS_MARK
  discard setsockopt(SocketHandle(rawSock), SOL_SOCKET.cint, SO_MARK,
                     addr mark, SockLen(sizeof(mark)))

  let h = nfq_open()
  if h == nil:
    echo "nfq_open() failed — are you root?"
    quit(1)
  discard nfq_bind_pf(h, 2u16)
  let qh = nfq_create_queue(h, 1, packetCallback, nil)
  if qh == nil:
    echo "nfq_create_queue() failed"
    quit(1)
  discard nfq_set_mode(qh, NFQNL_COPY_PACKET, 65535)
  discard signal(SIGINT, sigHandler)
  discard signal(SIGTERM, sigHandler)

  echo """
#   #  ###  #   #    #    ####
## ##   #   ##  #   # #   #   #
# # #   #   # # #  #####  ####
#   #   #   #  ##  #   #  #   #
#   #  ###  #   #  #   #  ####
"""
  echo "In memory of the students killed in Minab city by US air invasion on February 28, 2026"
  echo "Bypass active on queue 1 — fragmenting nvidia.com ClientHellos"
  echo "Press Ctrl+C to stop"

  let fd = nfq_fd(h)
  var buf: array[65536, char]
  while running:
    let rv = recv(SocketHandle(fd), addr buf[0], buf.len, 0)
    if rv >= 0:
      discard nfq_handle_packet(h, addr buf[0], cint(rv))

  discard nfq_destroy_queue(qh)
  discard nfq_close(h)
  discard close(rawSock)

main()
