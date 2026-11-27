# Roland-REAC-Driver-Windows
How to guide for getting the Roland REAC Driver working on Modern systems, Windows 10 and 11

# reac-ndisapi

Run Roland's **REAC Driver (S-RDK)** on Windows 10 and 11.

Roland's REAC ASIO driver depends on `rdeandis.sys`, a Roland build of NT Kernel's
Windows Packet Filter driver. It is an NDIS 5.x driver, and Windows 8 and later won't load it,
so REAC Panel can't find the network and nothing records.

This project replaces one file, Roland's `ndisapi.dll`, with a compatible implementation
that talks to the **current, signed Windows Packet Filter driver** from NT Kernel instead.
REAC.dll, REAC Panel and the rest of Roland's software are left untouched.

> **Status:** working with REAC Driver 2.0 (REAC.dll 2.0.0.000) on 64-bit Windows,
> recording into an ASIO DAW.

---

## Requirements

- 64-bit Windows 10 or 11 (32-bit Windows is not supported)
- [Roland REAC Driver 2.0 (S-RDK)](https://proav.roland.com/global/products/s-rdk/)
- [NT Kernel Windows Packet Filter](https://www.ntkernel.com/windows-packet-filter/download/) 3.6.2 or later
- A wired Ethernet adapter connected to your REAC network

## Installation

### 1. Install the Roland REAC Driver

Download and install **REAC Driver Version 2.0** from Roland's S-RDK page:
<https://proav.roland.com/global/products/s-rdk/>

You must accept Roland's software licence agreement to download it.

### 2. Install the NT Kernel Windows Packet Filter driver

Download and install the **x64** Windows Packet Filter package, version **3.6.2 or later**:
<https://www.ntkernel.com/windows-packet-filter/download/>

Don't use 3.6.1: its drivers can fail to load because their signing certificate has expired.
Reboot if the installer asks you to.

### 3. Rename Roland's `ndisapi.dll`

Rename `ndisapi.dll` to `ndisapi.dll.old` in **both** of these folders:

```
C:\Program Files\Roland\REACDriver\ndisapi.dll        ->  ndisapi.dll.old
C:\Program Files (x86)\Roland\REACDriver\ndisapi.dll  ->  ndisapi.dll.old
```

### 4. Copy in the replacement DLLs

Download the latest release (or build it yourself, see [Building](#building)) and copy:

| From this repo | To |
|---|---|
| `out/x64/ndisapi.dll` | `C:\Program Files\Roland\REACDriver\` |
| `out/x86/ndisapi.dll` | `C:\Program Files (x86)\Roland\REACDriver\` |

The 64-bit DLL serves 64-bit DAWs, and the 32-bit DLL serves 32-bit hosts and REAC Panel's
32-bit components. Install both.

### 5. Start REAC Panel

Open REAC Panel, select the Ethernet adapter connected to your REAC network, and check that
the status reaches **Locked**. Then select the REAC ASIO driver in your DAW.

---

## Verifying and troubleshooting

The DLL writes diagnostics with `OutputDebugString`. To see them, run
[Sysinternals DebugView](https://learn.microsoft.com/sysinternals/downloads/debugview)
with **Capture → Capture Win32** turned on, then start REAC Panel or your DAW.

A healthy start looks like this:

```
[reac-ndisapi] CNdisApi("RDEANDIS") -> \\.\NDISRD opened (err 0)
[reac-ndisapi] SetHwPacketFilter(adapter 1, 0x20) -> 1
[reac-ndisapi] SetAdapterMode(adapter 1, 0x58) -> 1
[reac-ndisapi] SetPacketEvent(adapter 1, event ...) -> 1
[reac-ndisapi] SetPacketSignalRate(adapter 1, 96) accepted, ignored
[reac-ndisapi] rx 4000/s (REAC bcast 4000/s), empty-queue .../s, rx err 0/s, tx .../s, tx err 0/s
```

| What you see | What it means |
|---|---|
| No `[reac-ndisapi]` lines at all | Roland's original `ndisapi.dll` is still being loaded. Check step 3 in both folders. |
| `FAILED (err 2)` | The Windows Packet Filter driver isn't installed or isn't running. Repeat step 2. |
| `FAILED (err 5)` | Access denied. Run REAC Panel or your DAW as administrator. |
| `-> 0` after `SetAdapterMode` or `SetPacketEvent` | The adapter handle was rejected. Reselect the adapter in REAC Panel. |
| `rx` near 0/s | No packets are being delivered. Check the selected adapter and the cable. |
| `rx` normal but `REAC bcast` near 0/s | Traffic is arriving but it isn't REAC. Wrong adapter, or REAC isn't reaching this port. |
| `rx err` or `tx err` above 0 | Send the DebugView log with your bug report. |

If Roland's installer added the "Roland Ethernet Audio Network Driver" to your network
adapter, it does nothing on Windows 10 or 11. You can leave it or uninstall it from the
adapter's Properties.

---

## How it works

REAC.dll imports 13 functions from `ndisapi.dll`. This DLL re-implements those 13 functions,
with the same C++ export names, on top of the stock Windows Packet Filter driver:

| | Roland stack | Stock driver (3.6.x) | What the replacement does |
|---|---|---|---|
| Device | `\\.\RDEANDIS` | `\\.\NDISRD` | Opens `NDISRD` when REAC asks for `RDEANDIS` |
| Control codes | `0x830020C0`... | Same | Passes them through |
| Adapter list, mode, event and OID structures | WinpkFilter 3.0.8 | Same layout | Passes them through |
| Frame data in the packet buffer | +0x14 (x86) / +0x1C (x64) | +0x34 | Copies each packet through a buffer in the driver's layout |
| `SetPacketSignalRate` | Roland-only control code `0x830030C0` | Doesn't exist | Accepted and ignored |
| 32-bit callers on 64-bit Windows | Converted to 64-bit structures | Same | Converts to 64-bit structures |

`SetPacketSignalRate` told Roland's driver to wake REAC once every N packets instead of on
every packet. The stock driver wakes it on every packet, and REAC reads the queue until it's
empty each time it wakes, so ignoring the call loses nothing.

Adapter handles given to REAC are small integers (1–32) that map to the driver's 64-bit
handles. The table is refreshed every time REAC lists the adapters.

## Building

The DLLs are built with mingw-w64 (on Linux or WSL):

```sh
sudo apt install gcc-mingw-w64-i686 gcc-mingw-w64-x86-64
sh build.sh
# -> out/x86/ndisapi.dll, out/x64/ndisapi.dll
```

| File | Purpose |
|---|---|
| `ndisapi_reac.c` | The implementation (one source for both architectures) |
| `ndisapi_x86.def` | 32-bit export names (MSVC `thiscall` mangling) |
| `ndisapi_x64.def` | 64-bit export names |
| `build.sh` | Builds both DLLs |

---

## Licensing and legal

**This repository contains only original code.** It does not include or redistribute any Roland
software or any NT Kernel driver. You download both yourself from their publishers and accept
their licence terms when you do.

### Roland REAC Driver (S-RDK)

S-RDK is a discontinued Roland product. REAC Driver 2.0 is offered as a free download, and it is
covered by the **Roland Software License Agreement** shown on the download page. Among other
things, that agreement:

- limits use to a single computer at a time, and allows one backup copy
- prohibits unauthorised copying, uploading to another network and distribution
- prohibits loaning, renting, leasing, sublicensing or transferring the software to a third party
- prohibits modifying, reverse engineering, decompiling or disassembling the software

**Don't add Roland's files** (REAC.dll, REACPanel.exe, REACResource.dll, Roland's `ndisapi.dll`,
`rdeandis.sys`, or the installer) to this repository or its releases.
Point users to Roland's download page instead.

### NT Kernel Windows Packet Filter

- The **driver installers** are free for non-commercial personal use, educational use and
  commercial evaluation. Commercial use and redistribution of the driver need a paid licence.
  See <https://www.ntkernel.com/windows-packet-filter/licensing/>.
- The **NDISAPI user-mode library and SDK** source
  ([github.com/wiresock/ndisapi](https://github.com/wiresock/ndisapi)) is MIT-licensed,
  © 2018 Vadim Smirnov. This project doesn't include that code. Its structure layouts and
  control codes were checked against the SDK's public `Common.h`.

Using this project for commercial work (for example, recording paid gigs) is commercial use of
the Windows Packet Filter driver under NT Kernel's terms. Check whether you need a licence.

### This project

Released under the licence in [`LICENSE`](LICENSE).

This project is not affiliated with, endorsed by, or supported by Roland Corporation or
NT Kernel. "Roland", "REAC" and "V-Mixing System" are trademarks of Roland Corporation.
"Windows Packet Filter" and "WinpkFilter" are trademarks of NT Kernel.
Use at your own risk.
