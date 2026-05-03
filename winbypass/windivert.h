/* Minimal WinDivert 2.x header for cross-compilation.
   WINDIVERT_ADDRESS is intentionally oversized (80 bytes) and treated
   opaquely — we only pass a pointer to it, never inspect fields. */
#pragma once
#include <windows.h>

typedef HANDLE WINDIVERT_HANDLE;

typedef struct { UINT8 _opaque[80]; } WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;

typedef enum {
    WINDIVERT_LAYER_NETWORK = 0,
} WINDIVERT_LAYER;

WINDIVERT_HANDLE WinDivertOpen(const char *filter, WINDIVERT_LAYER layer,
                                INT16 priority, UINT64 flags);
BOOL WinDivertRecv(WINDIVERT_HANDLE handle, VOID *pPacket, UINT packetLen,
                   UINT *pRecvLen, WINDIVERT_ADDRESS *pAddr);
BOOL WinDivertSend(WINDIVERT_HANDLE handle, const VOID *pPacket, UINT packetLen,
                   UINT *pSendLen, const WINDIVERT_ADDRESS *pAddr);
BOOL WinDivertClose(WINDIVERT_HANDLE handle);
BOOL WinDivertHelperCalcChecksums(VOID *pPacket, UINT packetLen,
                                   WINDIVERT_ADDRESS *pAddr, UINT64 flags);
