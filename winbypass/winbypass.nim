# winbypass.nim
# Windows port of bypass.nim — defeats the SNI blocker via TCP segmentation.
#
# Uses WinDivert to intercept outgoing TLS ClientHellos and re-injects the
# payload split across two TCP segments, identical to the Linux bypass:
#   segment A: first 3 bytes (TLS record header only)
#   segment B: remainder with seq += 3
# The blocker's findSni sees incomplete fragments and accepts both.
#
# Build: nim c -d:release -d:windows --os:windows --cpu:amd64 \
#             --cc:gcc --gcc.exe:x86_64-w64-mingw32-gcc \
#             --gcc.linkerexe:x86_64-w64-mingw32-gcc \
#             winbypass.nim
# Run:   winbypass.exe   (requires Administrator)
#        WinDivert.dll must be in the same directory or on PATH.
#        WinDivert: https://reqrypt.org/windivert.html


when not defined(windows):
  {.error: "winbypass.nim is Windows-only — use bypass.nim on Linux".}

{.passC: "-I.".}
{.passL: "-L. -lWinDivert".}

const SPLIT_AT = 3

# ── WinDivert bindings ────────────────────────────────────────────────────────

const WINDIVERT_LAYER_NETWORK = 0.cint

proc GetLastError(): uint32 {.importc, header: "<windows.h>".}

type
  WinDivertHandle = pointer
  WinDivertAddress {.importc: "WINDIVERT_ADDRESS",
                     header: "<windivert.h>".} = object

proc WinDivertOpen(filter: cstring, layer: cint, priority: int16,
                   flags: uint64): WinDivertHandle
  {.importc, header: "<windivert.h>".}

proc WinDivertRecv(handle: WinDivertHandle, pPacket: pointer,
                   packetLen: cuint, pRecvLen: ptr cuint,
                   pAddr: ptr WinDivertAddress): bool
  {.importc, header: "<windivert.h>".}

proc WinDivertSend(handle: WinDivertHandle, pPacket: pointer,
                   packetLen: cuint, pSendLen: ptr cuint,
                   pAddr: ptr WinDivertAddress): bool
  {.importc, header: "<windivert.h>".}

proc WinDivertClose(handle: WinDivertHandle): bool
  {.importc, header: "<windivert.h>".}

proc WinDivertHelperCalcChecksums(pPacket: pointer, packetLen: cuint,
                                   pAddr: ptr WinDivertAddress,
                                   flags: uint64): bool
  {.importc, header: "<windivert.h>".}

# ── Packet parsing (mirrors bypass.nim) ──────────────────────────────────────

proc getIpHeaderLen(pkt: ptr uint8): int =
  (cast[ptr UncheckedArray[uint8]](pkt)[0] and 0x0F).int * 4

proc getTcpHeaderLen(tcp: ptr uint8): int =
  (cast[ptr UncheckedArray[uint8]](tcp)[12] shr 4).int * 4

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
          for i in 0 ..< nameLen: sni[i] = char(p[nameStart + i])
          return sni
    pos += extLen
  return ""

# ── Split and reinject via WinDivert ─────────────────────────────────────────

proc sendSplitPackets(handle: WinDivertHandle, pkt: ptr uint8, pktLen: int,
                      pAddr: ptr WinDivertAddress) =
  let p         = cast[ptr UncheckedArray[uint8]](pkt)
  let ipLen     = pkt.getIpHeaderLen
  let tcpHdrLen = cast[ptr uint8](cast[int](pkt) + ipLen).getTcpHeaderLen
  let dataOff   = ipLen + tcpHdrLen
  let dataLen   = pktLen - dataOff

  if dataLen <= SPLIT_AT:
    discard WinDivertSend(handle, pkt, cuint(pktLen), nil, pAddr)
    return

  let origSeq = (p[ipLen+4].uint32 shl 24) or (p[ipLen+5].uint32 shl 16) or
                (p[ipLen+6].uint32 shl 8)  or  p[ipLen+7].uint32

  # Packet A: IP+TCP headers + first SPLIT_AT bytes of TLS record
  let pktALen = dataOff + SPLIT_AT
  var pktA = newSeq[uint8](pktALen)
  copyMem(addr pktA[0], pkt, dataOff)
  copyMem(addr pktA[dataOff], addr p[dataOff], SPLIT_AT)
  pktA[2] = uint8(pktALen shr 8); pktA[3] = uint8(pktALen)
  discard WinDivertHelperCalcChecksums(addr pktA[0], cuint(pktALen), pAddr, 0)
  discard WinDivertSend(handle, addr pktA[0], cuint(pktALen), nil, pAddr)

  # Packet B: IP+TCP headers (seq += SPLIT_AT) + remaining TLS bytes
  let restLen = dataLen - SPLIT_AT
  let pktBLen = dataOff + restLen
  var pktB = newSeq[uint8](pktBLen)
  copyMem(addr pktB[0], pkt, dataOff)
  copyMem(addr pktB[dataOff], addr p[dataOff + SPLIT_AT], restLen)
  pktB[2] = uint8(pktBLen shr 8); pktB[3] = uint8(pktBLen)
  let newSeq = origSeq + uint32(SPLIT_AT)
  pktB[ipLen+4] = uint8(newSeq shr 24); pktB[ipLen+5] = uint8(newSeq shr 16)
  pktB[ipLen+6] = uint8(newSeq shr 8);  pktB[ipLen+7] = uint8(newSeq)
  discard WinDivertHelperCalcChecksums(addr pktB[0], cuint(pktBLen), pAddr, 0)
  discard WinDivertSend(handle, addr pktB[0], cuint(pktBLen), nil, pAddr)

# ── Main ─────────────────────────────────────────────────────────────────────

proc ctrlHandler() {.noconv.} =
  echo "\nStopping..."
  quit(0)

proc main() =
  setControlCHook(ctrlHandler)

  let handle = WinDivertOpen(
    "outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0",
    WINDIVERT_LAYER_NETWORK, 0, 0)
  if cast[int](handle) == -1 or handle == nil:
    let err = GetLastError()
    echo "WinDivertOpen() failed (error ", err, ")"
    case err
    of 5:   echo "  → Access denied: run as Administrator"
    of 2:   echo "  → WinDivert64.sys not found: place it next to the .exe"
    of 577: echo "  → Driver signature check failed: enable test signing or use a signed WinDivert release"
    else:   discard
    quit(1)

  echo """
#   #  ###  #   #    #    ####
## ##   #   ##  #   # #   #   #
# # #   #   # # #  #####  ####
#   #   #   #  ##  #   #  #   #
#   #  ###  #   #  #   #  ####
"""
  echo "In memory of the schoolchildren killed in Minab city by US air invasion on February 28, 2026"
  echo "Bypass active — intercepting outbound TLS ClientHellos on port 443"
  echo "Press Ctrl+C to stop"

  var buf: array[65536, uint8]
  var pktAddr: WinDivertAddress
  var recvLen: cuint

  while true:
    if not WinDivertRecv(handle, addr buf[0], cuint(buf.len), addr recvLen, addr pktAddr):
      continue

    let pktLen = recvLen.int
    if pktLen < 40:
      discard WinDivertSend(handle, addr buf[0], recvLen, nil, addr pktAddr)
      continue

    let ipLen   = (addr buf[0]).getIpHeaderLen
    let tcpLen  = cast[ptr uint8](cast[int](addr buf[0]) + ipLen).getTcpHeaderLen
    let dataOff = ipLen + tcpLen
    let dataLen = pktLen - dataOff

    if dataLen > 0:
      let tlsStart = cast[ptr uint8](cast[int](addr buf[0]) + dataOff)
      if isClientHello(tlsStart, dataLen):
        let sni = findSni(tlsStart, dataLen)
        let label = if sni.len > 0: "SNI=" & sni else: "ECH/unreadable"
        echo "[BYPASS] fragmenting ", label
        sendSplitPackets(handle, addr buf[0], pktLen, addr pktAddr)
        continue

    discard WinDivertSend(handle, addr buf[0], recvLen, nil, addr pktAddr)

  discard WinDivertClose(handle)

main()
