/*
 * ndisapi_reac.c
 *
 * Drop-in replacement for Roland's ndisapi.dll (WinpkFilter 3.0.8.1 + Roland
 * SetPacketSignalRate) so that REAC.dll runs on the current NT Kernel
 * "Windows Packet Filter" driver (\\.\NDISRD, 3.6.x).
 *
 * Implements exactly the 13 CNdisApi members REAC.dll imports, with the
 * MSVC-mangled names REAC.dll links against (see ndisapi_x86.def /
 * ndisapi_x64.def). One source builds both the 32-bit DLL (for REAC.dll
 * x86 under WOW64) and the 64-bit DLL (for REAC.dll x64).
 *
 * What it translates:
 *   - Device name: REAC asks for "RDEANDIS"; we open "\\.\NDISRD".
 *   - INTERMEDIATE_BUFFER: REAC (3.0.8 headers) has frame data at +0x14 (x86)
 *     or +0x1C (x64). The 3.6 driver always uses the x64 layout with frame
 *     data at +0x34. We bounce every packet through a driver-layout buffer.
 *   - WOW64: on 64-bit Windows the driver only understands 64-bit structures,
 *     so the 32-bit build widens handles/pointers, as both the old and the
 *     current NT Kernel ndisapi.dll do.
 *   - SetPacketSignalRate (Roland IOCTL 0x830030C0): unknown to the stock
 *     driver. Accepted and ignored; the stock driver signals on every frame
 *     and REAC drains the queue on each wake, so nothing is lost.
 *
 * Adapter handles given to REAC are small integers 1..32 that index a
 * table of the driver's 64-bit handles, refreshed on every
 * GetTcpipBoundAdaptersInfo call.
 *
 * Diagnostics: OutputDebugString lines prefixed "[reac-ndisapi]"
 * (view with Sysinternals DebugView, "Capture Win32" enabled).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN64
#  define MEMBER            /* x64: this in RCX, normal ABI */
#else
#  define MEMBER __attribute__((thiscall))
#endif

/* ------------------------------------------------------------------ */
/* IOCTLs (unchanged between 3.0.8 and 3.6.x)                          */
/* ------------------------------------------------------------------ */
#define IOCTL_NDISRD_GET_TCPIP_INTERFACES    0x830020C4
#define IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER  0x830020C8
#define IOCTL_NDISRD_SEND_PACKET_TO_MSTCP    0x830020CC
#define IOCTL_NDISRD_READ_PACKET             0x830020D0
#define IOCTL_NDISRD_SET_ADAPTER_MODE        0x830020D4
#define IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE     0x830020D8
#define IOCTL_NDISRD_SET_EVENT               0x830020DC
#define IOCTL_NDISRD_NDIS_SET_REQUEST        0x830020E0
#define IOCTL_NDISRD_NDIS_GET_REQUEST        0x830020E4

#define OID_GEN_CURRENT_PACKET_FILTER        0x0001010E

#define ADAPTER_NAME_SIZE   256
#define ADAPTER_LIST_SIZE   32
#define ETHER_ADDR_LENGTH   6
#define REAC_MAX_FRAME      1514   /* what REAC.dll's buffers hold        */
#define DRV_MAX_FRAME       9014   /* jumbo-capable driver builds         */

#pragma pack(push, 1)

/* ---- REAC.dll side: WinpkFilter 3.0.8.1 layouts, native pointer size ---- */
typedef struct {
    LIST_ENTRY m_qLink;
    DWORD      m_dwDeviceFlags;
    DWORD      m_Length;
    DWORD      m_Flags;
    UCHAR      m_IBuffer[REAC_MAX_FRAME];
} R_INTERMEDIATE_BUFFER;

typedef struct {
    HANDLE                 hAdapterHandle;
    R_INTERMEDIATE_BUFFER *EthPacket;
} R_ETH_REQUEST;

typedef struct {
    HANDLE hAdapterHandle;
    DWORD  dwFlags;
} R_ADAPTER_MODE;

typedef struct {
    DWORD          m_nAdapterCount;
    unsigned char  m_szAdapterNameList[ADAPTER_LIST_SIZE][ADAPTER_NAME_SIZE];
    HANDLE         m_nAdapterHandle[ADAPTER_LIST_SIZE];
    unsigned int   m_nAdapterMediumList[ADAPTER_LIST_SIZE];
    unsigned char  m_czCurrentAddress[ADAPTER_LIST_SIZE][ETHER_ADDR_LENGTH];
    unsigned short m_usMTU[ADAPTER_LIST_SIZE];
} R_TCP_AdapterList;

/* ---- Driver side: 3.6.x x64 kernel layouts (also what WOW64 must send) ---- */
typedef struct {
    ULONGLONG m_qLink[2];
    DWORD     m_dwDeviceFlags;
    DWORD     m_Length;
    DWORD     m_Flags;
    DWORD     m_8021q;
    DWORD     m_FilterID;
    DWORD     m_Reserved[4];
    UCHAR     m_IBuffer[DRV_MAX_FRAME];
} K_INTERMEDIATE_BUFFER;

typedef struct {
    ULONGLONG hAdapterHandle;
    ULONGLONG EthPacket;        /* user-mode address of a K_INTERMEDIATE_BUFFER */
} K_ETH_REQUEST;

typedef struct {
    ULONGLONG hAdapterHandle;
    DWORD     dwFlags;
} K_ADAPTER_MODE;

typedef struct {
    ULONGLONG hAdapterHandle;
    ULONGLONG hEvent;
} K_ADAPTER_EVENT;

typedef struct {
    ULONGLONG hAdapterHandle;
    DWORD     Oid;
    DWORD     Length;
    DWORD     Data;             /* every OID we send is a single DWORD */
} K_PACKET_OID_DATA_DWORD;

typedef struct {
    DWORD          m_nAdapterCount;
    unsigned char  m_szAdapterNameList[ADAPTER_LIST_SIZE][ADAPTER_NAME_SIZE];
    ULONGLONG      m_nAdapterHandle[ADAPTER_LIST_SIZE];
    unsigned int   m_nAdapterMediumList[ADAPTER_LIST_SIZE];
    unsigned char  m_czCurrentAddress[ADAPTER_LIST_SIZE][ETHER_ADDR_LENGTH];
    unsigned short m_usMTU[ADAPTER_LIST_SIZE];
} K_TCP_AdapterList;

#pragma pack(pop)

/* Layout checks against what was measured in the Roland binaries / Common.h */
_Static_assert(offsetof(K_INTERMEDIATE_BUFFER, m_IBuffer) == 0x34, "3.6 IB");
_Static_assert(sizeof(K_ETH_REQUEST) == 0x10, "ETH_REQUEST_WOW64");
_Static_assert(sizeof(K_ADAPTER_MODE) == 0x0C, "ADAPTER_MODE_WOW64");
_Static_assert(sizeof(K_ADAPTER_EVENT) == 0x10, "ADAPTER_EVENT_WOW64");
_Static_assert(sizeof(K_TCP_AdapterList) == 0x2284, "TCP_AdapterList_WOW64");
#ifdef _WIN64
_Static_assert(offsetof(R_INTERMEDIATE_BUFFER, m_IBuffer) == 0x1C, "3.0.8 x64 IB");
#else
_Static_assert(offsetof(R_INTERMEDIATE_BUFFER, m_IBuffer) == 0x14, "3.0.8 x86 IB");
_Static_assert(offsetof(R_TCP_AdapterList, m_nAdapterHandle) == 0x2004, "x86 list");
_Static_assert(offsetof(R_TCP_AdapterList, m_nAdapterMediumList) == 0x2084, "x86 list");
_Static_assert(offsetof(R_TCP_AdapterList, m_czCurrentAddress) == 0x2104, "x86 list");
_Static_assert(offsetof(R_TCP_AdapterList, m_usMTU) == 0x21C4, "x86 list");
#endif

/* ------------------------------------------------------------------ */
/* Object layout. REAC.dll reserves the old CNdisApi's size inside its */
/* own object (0x2344 bytes on x86) and constructs us in place, so the */
/* state must fit there. Offset 0 must be a vtable pointer (the old    */
/* class has a virtual destructor).                                    */
/* ------------------------------------------------------------------ */
typedef struct {
    const void *const *vtbl;
    HANDLE     hDevice;
    BOOL       bLoaded;
    SRWLOCK    lock;
    ULONGLONG  handle64[ADAPTER_LIST_SIZE];
} SHIM;

#ifndef _WIN64
_Static_assert(sizeof(SHIM) <= 0x2344, "must fit REAC's CNdisApi slot");
#endif

/* ------------------------------------------------------------------ */
/* Diagnostics                                                         */
/* ------------------------------------------------------------------ */
static void dbg(const char *fmt, ...)
{
    char buf[256];
    int n = snprintf(buf, sizeof buf, "[reac-ndisapi] ");
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf + n, sizeof buf - n, fmt, ap);
    va_end(ap);
    OutputDebugStringA(buf);
}

static volatile LONG c_rx_ok, c_rx_empty, c_rx_err, c_reac, c_tx_ok, c_tx_err;
static volatile LONG c_last_err;
static volatile LONG t_last;

static void stats_tick(void)
{
    LONG now = (LONG)GetTickCount();
    LONG last = t_last;
    if ((LONG)(now - last) < 1000) return;
    if (InterlockedCompareExchange(&t_last, now, last) != last) return;
    dbg("rx %ld/s (REAC bcast %ld/s), empty-queue %ld/s (~wakeups), rx err %ld/s, "
        "tx %ld/s, tx err %ld/s, last err %ld\n",
        InterlockedExchange(&c_rx_ok, 0), InterlockedExchange(&c_reac, 0),
        InterlockedExchange(&c_rx_empty, 0), InterlockedExchange(&c_rx_err, 0),
        InterlockedExchange(&c_tx_ok, 0), InterlockedExchange(&c_tx_err, 0),
        c_last_err);
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
static BOOL ioctl(SHIM *s, DWORD code, void *in, DWORD inLen, void *out, DWORD outLen)
{
    DWORD br = 0;
    if (!s->bLoaded) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    BOOL ok = DeviceIoControl(s->hDevice, code, in, inLen, out, outLen, &br, NULL);
    if (!ok) c_last_err = (LONG)GetLastError();
    return ok;
}

/* REAC handle (1..32) -> driver 64-bit handle. 0 stays 0. */
static BOOL to64(SHIM *s, HANDLE h, ULONGLONG *out)
{
    ULONG_PTR idx = (ULONG_PTR)h;
    *out = 0;
    if (idx == 0) return TRUE;
    if (idx > ADAPTER_LIST_SIZE) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    AcquireSRWLockShared(&s->lock);
    *out = s->handle64[idx - 1];
    ReleaseSRWLockShared(&s->lock);
    if (*out == 0) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    return TRUE;
}

static BOOL refresh_adapters(SHIM *s, K_TCP_AdapterList *k)
{
    memset(k, 0, sizeof *k);
    if (!ioctl(s, IOCTL_NDISRD_GET_TCPIP_INTERFACES, k, sizeof *k, k, sizeof *k))
        return FALSE;
    if (k->m_nAdapterCount > ADAPTER_LIST_SIZE) k->m_nAdapterCount = ADAPTER_LIST_SIZE;
    AcquireSRWLockExclusive(&s->lock);
    for (DWORD i = 0; i < ADAPTER_LIST_SIZE; i++)
        s->handle64[i] = (i < k->m_nAdapterCount) ? k->m_nAdapterHandle[i] : 0;
    ReleaseSRWLockExclusive(&s->lock);
    return TRUE;
}

static BOOL oid_dword(SHIM *s, HANDLE h, BOOL set, DWORD oid, DWORD *val)
{
    K_PACKET_OID_DATA_DWORD r;
    memset(&r, 0, sizeof r);
    if (!to64(s, h, &r.hAdapterHandle)) return FALSE;
    r.Oid = oid;
    r.Length = sizeof(DWORD);
    r.Data = set ? *val : 0;
    if (!ioctl(s, set ? IOCTL_NDISRD_NDIS_SET_REQUEST : IOCTL_NDISRD_NDIS_GET_REQUEST,
               &r, sizeof r, &r, sizeof r))
        return FALSE;
    if (!set) *val = r.Data;
    return TRUE;
}

static BOOL send_common(SHIM *s, DWORD code, R_ETH_REQUEST *req)
{
    if (!req || !req->EthPacket) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    R_INTERMEDIATE_BUFFER *src = req->EthPacket;
    if (src->m_Length > REAC_MAX_FRAME) {
        InterlockedIncrement(&c_tx_err);
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    K_INTERMEDIATE_BUFFER kb;
    memset(&kb, 0, offsetof(K_INTERMEDIATE_BUFFER, m_IBuffer));
    kb.m_dwDeviceFlags = src->m_dwDeviceFlags;
    kb.m_Length        = src->m_Length;
    kb.m_Flags         = src->m_Flags;
    memcpy(kb.m_IBuffer, src->m_IBuffer, src->m_Length);

    K_ETH_REQUEST r;
    if (!to64(s, req->hAdapterHandle, &r.hAdapterHandle)) return FALSE;
    r.EthPacket = (ULONGLONG)(ULONG_PTR)&kb;

    BOOL ok = ioctl(s, code, &r, sizeof r, NULL, 0);
    InterlockedIncrement(ok ? &c_tx_ok : &c_tx_err);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Exported members                                                    */
/* ------------------------------------------------------------------ */
MEMBER void Shim_Dtor(SHIM *s);
MEMBER void *Shim_ScalarDeletingDtor(SHIM *s, unsigned flags);

static const void *const g_vtbl[] = { (const void *)Shim_ScalarDeletingDtor };

/* ??0CNdisApi@@QAE@PBD@Z / ??0CNdisApi@@QEAA@PEBD@Z */
MEMBER SHIM *Shim_Ctor(SHIM *s, const char *name)
{
    memset(s, 0, sizeof *s);
    s->vtbl = g_vtbl;
    s->hDevice = INVALID_HANDLE_VALUE;
    InitializeSRWLock(&s->lock);

#ifndef _WIN64
    BOOL wow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &wow64);
    if (!wow64) {
        dbg("32-bit Windows is not supported by this shim (driver structures differ)\n");
        return s;
    }
#endif

    const char *dev = "NDISRD";
    if (name && *name && _stricmp(name, "RDEANDIS") != 0) dev = name;
    char path[64];
    snprintf(path, sizeof path, "\\\\.\\%s", dev);

    s->hDevice = CreateFileA(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, 0, NULL);
    s->bLoaded = (s->hDevice != INVALID_HANDLE_VALUE);
    dbg("CNdisApi(\"%s\") -> %s %s (err %lu)\n", name ? name : "(null)", path,
        s->bLoaded ? "opened" : "FAILED", s->bLoaded ? 0UL : GetLastError());

    if (s->bLoaded) {
        K_TCP_AdapterList k;
        refresh_adapters(s, &k);
    }
    return s;
}

/* ??1CNdisApi@@UAE@XZ / ??1CNdisApi@@UEAA@XZ */
MEMBER void Shim_Dtor(SHIM *s)
{
    if (s->hDevice != INVALID_HANDLE_VALUE) CloseHandle(s->hDevice);
    s->hDevice = INVALID_HANDLE_VALUE;
    s->bLoaded = FALSE;
}

MEMBER void *Shim_ScalarDeletingDtor(SHIM *s, unsigned flags)
{
    Shim_Dtor(s);
    if (flags & 1) dbg("delete of CNdisApi requested; storage belongs to the caller, not freed\n");
    return s;
}

/* ?IsDriverLoaded@CNdisApi@@QAEHXZ */
MEMBER BOOL Shim_IsDriverLoaded(SHIM *s)
{
    return s->bLoaded;
}

/* ?GetTcpipBoundAdaptersInfo@CNdisApi@@QAEHPAU_TCP_AdapterList@@@Z */
MEMBER BOOL Shim_GetTcpipBoundAdaptersInfo(SHIM *s, R_TCP_AdapterList *out)
{
    if (!out) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    static K_TCP_AdapterList k;   /* 8.8 KB: keep off the caller's stack */
    static SRWLOCK klock = SRWLOCK_INIT;

    AcquireSRWLockExclusive(&klock);
    BOOL ok = refresh_adapters(s, &k);
    if (ok) {
        out->m_nAdapterCount = k.m_nAdapterCount;
        memcpy(out->m_szAdapterNameList, k.m_szAdapterNameList, sizeof out->m_szAdapterNameList);
        for (DWORD i = 0; i < ADAPTER_LIST_SIZE; i++)
            out->m_nAdapterHandle[i] = (i < k.m_nAdapterCount) ? (HANDLE)(ULONG_PTR)(i + 1) : NULL;
        memcpy(out->m_nAdapterMediumList, k.m_nAdapterMediumList, sizeof out->m_nAdapterMediumList);
        memcpy(out->m_czCurrentAddress, k.m_czCurrentAddress, sizeof out->m_czCurrentAddress);
        memcpy(out->m_usMTU, k.m_usMTU, sizeof out->m_usMTU);
    }
    ReleaseSRWLockExclusive(&klock);
    return ok;
}

/* ?SetAdapterMode@CNdisApi@@QAEHPAU_ADAPTER_MODE@@@Z */
MEMBER BOOL Shim_SetAdapterMode(SHIM *s, R_ADAPTER_MODE *m)
{
    if (!m) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    K_ADAPTER_MODE k;
    if (!to64(s, m->hAdapterHandle, &k.hAdapterHandle)) return FALSE;
    k.dwFlags = m->dwFlags;
    BOOL ok = ioctl(s, IOCTL_NDISRD_SET_ADAPTER_MODE, &k, sizeof k, NULL, 0);
    dbg("SetAdapterMode(adapter %u, 0x%lx) -> %d\n",
        (unsigned)(ULONG_PTR)m->hAdapterHandle, m->dwFlags, ok);
    return ok;
}

/* ?SetHwPacketFilter@CNdisApi@@QAEHPAXK@Z */
MEMBER BOOL Shim_SetHwPacketFilter(SHIM *s, HANDLE h, DWORD filter)
{
    BOOL ok = oid_dword(s, h, TRUE, OID_GEN_CURRENT_PACKET_FILTER, &filter);
    dbg("SetHwPacketFilter(adapter %u, 0x%lx) -> %d\n", (unsigned)(ULONG_PTR)h, filter, ok);
    return ok;
}

/* ?GetHwPacketFilter@CNdisApi@@QAEHPAXPAK@Z */
MEMBER BOOL Shim_GetHwPacketFilter(SHIM *s, HANDLE h, DWORD *filter)
{
    if (!filter) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return oid_dword(s, h, FALSE, OID_GEN_CURRENT_PACKET_FILTER, filter);
}

/* ?SetPacketEvent@CNdisApi@@QAEHPAX0@Z */
MEMBER BOOL Shim_SetPacketEvent(SHIM *s, HANDLE h, HANDLE hEvent)
{
    K_ADAPTER_EVENT k;
    if (!to64(s, h, &k.hAdapterHandle)) return FALSE;
    k.hEvent = (ULONGLONG)(ULONG_PTR)hEvent;
    BOOL ok = ioctl(s, IOCTL_NDISRD_SET_EVENT, &k, sizeof k, NULL, 0);
    dbg("SetPacketEvent(adapter %u, event %p) -> %d\n", (unsigned)(ULONG_PTR)h, hEvent, ok);
    return ok;
}

/* ?SetPacketSignalRate@CNdisApi@@QAEHPAXK@Z  (Roland-only) */
MEMBER BOOL Shim_SetPacketSignalRate(SHIM *s, HANDLE h, DWORD rate)
{
    (void)s;
    dbg("SetPacketSignalRate(adapter %u, %lu) accepted, ignored\n", (unsigned)(ULONG_PTR)h, rate);
    return TRUE;
}

/* ?FlushAdapterPacketQueue@CNdisApi@@QAEHPAX@Z */
MEMBER BOOL Shim_FlushAdapterPacketQueue(SHIM *s, HANDLE h)
{
    ULONGLONG h64;
    if (!to64(s, h, &h64)) return FALSE;
    return ioctl(s, IOCTL_NDISRD_FLUSH_ADAPTER_QUEUE, &h64, sizeof h64, NULL, 0);
}

/* ?ReadPacket@CNdisApi@@QAEHPAU_ETH_REQUEST@@@Z */
MEMBER BOOL Shim_ReadPacket(SHIM *s, R_ETH_REQUEST *req)
{
    stats_tick();
    if (!req || !req->EthPacket) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }

    K_INTERMEDIATE_BUFFER kb;
    K_ETH_REQUEST r;
    if (!to64(s, req->hAdapterHandle, &r.hAdapterHandle)) {
        InterlockedIncrement(&c_rx_err);
        return FALSE;
    }
    r.EthPacket = (ULONGLONG)(ULONG_PTR)&kb;

    if (!ioctl(s, IOCTL_NDISRD_READ_PACKET, &r, sizeof r, &r, sizeof r)) {
        /* Empty queue is the normal way REAC's drain loop ends. */
        InterlockedIncrement(&c_rx_empty);
        return FALSE;
    }
    if (kb.m_Length > REAC_MAX_FRAME) {
        InterlockedIncrement(&c_rx_err);
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    R_INTERMEDIATE_BUFFER *dst = req->EthPacket;
    dst->m_dwDeviceFlags = kb.m_dwDeviceFlags;
    dst->m_Length        = kb.m_Length;
    dst->m_Flags         = kb.m_Flags;
    memcpy(dst->m_IBuffer, kb.m_IBuffer, kb.m_Length);

    InterlockedIncrement(&c_rx_ok);
    if (kb.m_Length >= 14 &&
        memcmp(kb.m_IBuffer, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0 &&
        kb.m_IBuffer[12] == 0x88 && kb.m_IBuffer[13] == 0x19)
        InterlockedIncrement(&c_reac);
    return TRUE;
}

/* ?SendPacketToAdapter@CNdisApi@@QAEHPAU_ETH_REQUEST@@@Z */
MEMBER BOOL Shim_SendPacketToAdapter(SHIM *s, R_ETH_REQUEST *req)
{
    return send_common(s, IOCTL_NDISRD_SEND_PACKET_TO_ADAPTER, req);
}

/* ?SendPacketToMstcp@CNdisApi@@QAEHPAU_ETH_REQUEST@@@Z */
MEMBER BOOL Shim_SendPacketToMstcp(SHIM *s, R_ETH_REQUEST *req)
{
    return send_common(s, IOCTL_NDISRD_SEND_PACKET_TO_MSTCP, req);
}
