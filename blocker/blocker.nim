import std/posix, std/strutils, std/os

# blocker.nim
# Intercepts outgoing TLS packets via NFQUEUE, parses the ClientHello,
# and blocks any connection whose SNI is NOT in the passlist file.
# Sends a TCP RST to the client on block for an immediate connection error.
#
# Build: nim c -d:release blocker.nim
# Run:   sudo ./blocker <passed.txt>

{.passL: "-lnetfilter_queue -lnfnetlink".}

# ── libnetfilter_queue C bindings ─────────────────────────────────────────────

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
  IPPROTO_RAW       = 255.cint
  IP_HDRINCL        = 3.cint

# ── Packet Parsing ────────────────────────────────────────────────────────────

proc getIpHeaderLen(pkt: ptr uint8): int =
  let p = cast[ptr UncheckedArray[uint8]](pkt)
  (p[0] and 0x0F).int * 4

proc getTcpHeaderLen(tcpStart: ptr uint8): int =
  let p = cast[ptr UncheckedArray[uint8]](tcpStart)
  (p[12] shr 4).int * 4

proc isClientHello(payload: ptr uint8, payloadLen: int): bool =
  if payloadLen < 6: return false
  let p = cast[ptr UncheckedArray[uint8]](payload)
  p[0] == 0x16 and p[5] == 0x01

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
          for i in 0 ..< nameLen:
            sni[i] = char(p[nameStart + i])
          return sni

    pos += extLen

  return ""

# ── RST injection ────────────────────────────────────────────────────────────

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
  pseudo[12+16] = 0; pseudo[12+17] = 0
  ipChecksum(addr pseudo[0], pseudo.len)

proc sendRst(pkt: ptr uint8, pktLen: int) =
  if rawSock < 0: return
  let p      = cast[ptr UncheckedArray[uint8]](pkt)
  let ipLen  = pkt.getIpHeaderLen
  let tcpOff = ipLen

  # Sequence number for the RST: use the client's ACK field, which is
  # what the client currently believes is the server's next sequence number.
  let rstSeq = (p[tcpOff+8].uint32 shl 24) or (p[tcpOff+9].uint32 shl 16) or
               (p[tcpOff+10].uint32 shl 8) or  p[tcpOff+11].uint32

  # Build a minimal 40-byte IP+TCP packet (no options, no payload)
  var rst: array[40, uint8]

  # IP header — src/dst swapped (RST appears to come from the server)
  rst[0]  = 0x45              # version=4, IHL=5
  rst[2]  = 0; rst[3] = 40   # total length
  rst[6]  = 0x40              # DF flag
  rst[8]  = 64                # TTL
  rst[9]  = 6                 # protocol: TCP
  rst[12] = p[16]; rst[13] = p[17]; rst[14] = p[18]; rst[15] = p[19]  # src = server IP
  rst[16] = p[12]; rst[17] = p[13]; rst[18] = p[14]; rst[19] = p[15]  # dst = client IP

  # TCP header — ports swapped
  rst[20] = p[tcpOff+2]; rst[21] = p[tcpOff+3]  # sport = 443
  rst[22] = p[tcpOff+0]; rst[23] = p[tcpOff+1]  # dport = client port
  rst[24] = uint8(rstSeq shr 24); rst[25] = uint8(rstSeq shr 16)
  rst[26] = uint8(rstSeq shr 8);  rst[27] = uint8(rstSeq)
  rst[32] = 0x50              # data offset = 5
  rst[33] = 0x04              # flags: RST

  let ckIp = ipChecksum(addr rst[0], 20)
  rst[10] = uint8(ckIp shr 8); rst[11] = uint8(ckIp)
  let ckTcp = tcpChecksum(addr rst[0], 20, addr rst[20], 20)
  rst[36] = uint8(ckTcp shr 8); rst[37] = uint8(ckTcp)

  var dst: Sockaddr_in
  dst.sin_family = uint16(AF_INET)
  copyMem(addr dst.sin_addr, addr rst[16], 4)
  discard sendto(SocketHandle(rawSock), addr rst[0], 40, 0.cint,
                 cast[ptr SockAddr](addr dst), SockLen(sizeof(dst)))

# ── Passlist ─────────────────────────────────────────────────────────────────

var passlist: seq[string]

proc loadPasslist(path: string) =
  passlist.setLen(0)
  for line in lines(path):
    let entry = line.strip()
    if entry.len > 0 and not entry.startsWith("#"):
      passlist.add(entry)
  echo "Loaded ", passlist.len, " passed SNIs from ", path

proc isAllowed(sni: string): bool =
  for entry in passlist:
    if entry in sni: return true
  false

# ── Queue callback — called for every queued packet ──────────────────────────

proc packetCallback(qh: NfqQHandle, nfmsg: pointer,
                    nfd: NfqData, data: pointer): cint {.cdecl.} =
  let hdr = nfq_get_msg_packet_hdr(nfd)
  if hdr == nil:
    return 0

  # packet_id is big-endian in the struct
  let pktId = ((hdr.packet_id and 0xFF) shl 24) or
              (((hdr.packet_id shr 8) and 0xFF) shl 16) or
              (((hdr.packet_id shr 16) and 0xFF) shl 8) or
              ((hdr.packet_id shr 24) and 0xFF)

  var rawPkt: ptr uint8
  let pktLen = nfq_get_payload(nfd, addr rawPkt)

  if pktLen < 40 or rawPkt == nil:
    discard nfq_set_verdict(qh, pktId, NF_ACCEPT, 0, nil)
    return 0

  let ipLen  = rawPkt.getIpHeaderLen
  let tcpLen = cast[ptr uint8](cast[int](rawPkt) + ipLen).getTcpHeaderLen

  let dataOffset = ipLen + tcpLen
  let dataLen    = pktLen.int - dataOffset

  if dataLen > 0:
    let tlsStart = cast[ptr uint8](cast[int](rawPkt) + dataOffset)
    if isClientHello(tlsStart, dataLen):
      let sni = findSni(tlsStart, dataLen)
      if sni.len > 0:
        if isAllowed(sni):
          echo "[ALLOW] TLS ClientHello → SNI: ", sni
        else:
          echo "[BLOCK] TLS ClientHello → SNI: ", sni
          sendRst(rawPkt, pktLen.int)
          discard nfq_set_verdict(qh, pktId, NF_DROP, 0, nil)
          return 0
      else:
        echo "[BLOCK] TLS ClientHello → SNI unreadable (ECH?)"
        sendRst(rawPkt, pktLen.int)
        discard nfq_set_verdict(qh, pktId, NF_DROP, 0, nil)
        return 0

  discard nfq_set_verdict(qh, pktId, NF_ACCEPT, 0, nil)
  return 0

# ── Main ──────────────────────────────────────────────────────────────────────

var running = true
proc sigHandler(sig: cint) {.noconv.} = running = false

proc main() =
  if paramCount() < 1:
    echo "Usage: sudo ./blocker <passed.txt>"
    quit(1)
  loadPasslist(paramStr(1))

  rawSock = cint(socket(AF_INET.cint, SOCK_RAW.cint, IPPROTO_RAW))
  if rawSock < 0:
    echo "raw socket failed — are you root?"
    quit(1)
  var one: cint = 1
  discard setsockopt(SocketHandle(rawSock), IPPROTO_IP.cint, IP_HDRINCL,
                     addr one, SockLen(sizeof(one)))

  let h = nfq_open()
  if h == nil:
    echo "nfq_open() failed — are you root?"
    quit(1)

  discard nfq_bind_pf(h, 2u16)  # AF_INET = 2

  let qh = nfq_create_queue(h, 0, packetCallback, nil)
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
  echo "In memory of the schoolchildren killed in Minab city by US air invasion on February 28, 2026"
  echo "Watching TLS handshakes on queue 0..."
  echo "Passing ", passlist.len, " SNIs — all others blocked"
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