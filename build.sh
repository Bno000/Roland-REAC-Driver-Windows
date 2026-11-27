#!/bin/sh
# Builds out/x86/ndisapi.dll and out/x64/ndisapi.dll with mingw-w64.
set -e
cd "$(dirname "$0")"
CFLAGS="-O2 -Wall -Wextra -shared -static-libgcc -s -D_WIN32_WINNT=0x0600"
mkdir -p out/x86 out/x64
i686-w64-mingw32-gcc   $CFLAGS -o out/x86/ndisapi.dll ndisapi_reac.c ndisapi_x86.def
x86_64-w64-mingw32-gcc $CFLAGS -o out/x64/ndisapi.dll ndisapi_reac.c ndisapi_x64.def
echo built out/x86/ndisapi.dll out/x64/ndisapi.dll
