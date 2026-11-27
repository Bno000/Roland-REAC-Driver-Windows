# REAC on the current Windows Packet Filter driver

Replacement `ndisapi.dll` that lets Roland's REAC.dll (ASIO) and REACPanel run on
NT Kernel's current **Windows Packet Filter** driver (`\\.\NDISRD`, 3.6.2 or later)
instead of Roland's `rdeandis.sys`, which Windows 8 and later cannot load (NDIS 5.x).

## Install

1. **Install the driver.** Use NT Kernel's Windows Packet Filter x64 installer, 3.6.2 or later
   (3.6.1 has an expired signing certificate). Reboot if asked.
2. **Remove Roland's driver** if it's still registered: Network adapter → Properties →
   "Roland Ethernet Audio Network Driver" → Uninstall (or `netcfg -u nt_rdeandis`).
3. **Find every copy of Roland's `ndisapi.dll`** (REAC install folder, `C:\Windows\SysWOW64`,
   `C:\Windows\System32`). Rename each one to `ndisapi.dll.roland`.
4. **Copy in the replacement**, matching REAC.dll's bitness:
   - 32-bit REAC.dll (FileVersion 2.0.0.000, the one analysed) → `out/x86/ndisapi.dll`
     next to REAC.dll (and into `SysWOW64` if Roland's copy was there).
   - 64-bit REAC.dll → `out/x64/ndisapi.dll` next to REAC.dll (and into `System32`
     if Roland's copy was there).
5. Start DebugView (Sysinternals, *Capture Win32* on), then start REACPanel or your DAW.

A 32-bit ASIO driver only loads in a 32-bit host, and a 64-bit one only in a 64-bit host.

## What you should see in DebugView

```
[reac-ndisapi] CNdisApi("RDEANDIS") -> \\.\NDISRD opened (err 0)
[reac-ndisapi] SetHwPacketFilter(adapter 1, 0x20) -> 1
[reac-ndisapi] SetAdapterMode(adapter 1, 0x58) -> 1
[reac-ndisapi] SetPacketEvent(adapter 1, event ...) -> 1
[reac-ndisapi] SetPacketSignalRate(adapter 1, 96) accepted, ignored
[reac-ndisapi] rx 4000/s (REAC bcast 4000/s), empty-queue .../s, rx err 0/s, tx .../s ...
```

| Symptom | Meaning |
|---|---|
| `FAILED (err 2)` | Driver not installed or not running |
| `FAILED (err 5)` | Access denied: run the host as administrator |
| `-> 0` on SetAdapterMode/SetPacketEvent | Bad adapter handle: check "last err" |
| rx ~0/s, but the panel works | Event not firing or wrong adapter selected in REACPanel |
| rx fine, REAC bcast ~0/s | Wrong adapter, or REAC traffic isn't reaching this NIC |

## What it does

The 13 `CNdisApi` members REAC.dll imports, re-implemented on the stock driver:

- Opens `\\.\NDISRD` when REAC asks for `RDEANDIS`.
- Translates packet buffers: REAC's 3.0.8 layout (frame data at +0x14 on x86, +0x1C on x64)
  ↔ the 3.6 driver's layout (+0x34).
- 32-bit build: converts handles and pointers to the 64-bit structures the x64 driver expects
  (WOW64), the same way NT Kernel's own DLLs do. 32-bit Windows is not supported.
- `SetPacketSignalRate` (Roland-only IOCTL `0x830030C0`): accepted and ignored. The stock
  driver signals on every frame and REAC drains the queue on each wake, so nothing is lost.
- Adapter handles given to REAC are 1..32, mapped to the driver's 64-bit handles.

IOCTL codes, struct sizes and adapter-list layout were checked against Roland's
ndisapi 3.0.8.1, rdeandis.sys 3.0.8.1 and NT Kernel's current `Common.h`.

## Build

```
sh build.sh      # needs i686-w64-mingw32-gcc and x86_64-w64-mingw32-gcc
```
