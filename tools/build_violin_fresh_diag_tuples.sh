#!/usr/bin/env bash
set -euo pipefail

# Build only the three bounded Violin diagnostics.  This script never invokes
# adb and never runs the resulting ELF on a device.
NDK_ROOT="${NDK_ROOT:-/tmp/ndk}"
SRC="${SRC:-/mnt/e/workspace/projects/xiaomi-root/exploit-repo/IonStack/CVE-2026-43499/exploit}"
CC="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang"
SYSROOT="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/sysroot"

cd "$SRC"
COMMON=(
  --target=aarch64-linux-android35
  --sysroot="$SYSROOT"
  -O2 -g0 -Wall -Wextra -Isrc
  -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function
  '-DTARGET_CONFIG_H="targets/violin-v-oss/target.h"'
)
SRCS=(
  src/main.c src/util.c src/targets/violin-v-oss/slide.c src/fops.c
  src/pipe.c src/root.c src/preload.c src/su_blob.S src/wallpaper_blob.S
)

mkdir -p \
  build/violin-v-oss-fresh-cfgprobe-20260722/bin \
  build/violin-v-oss-fresh-route-20260722/bin \
  build/violin-v-oss-fresh-cfi-20260722/bin

"$CC" "${COMMON[@]}" -DCFGPROBE_ONLY_DIAG=1 "${SRCS[@]}" \
  -fPIC -shared -pthread \
  -o build/violin-v-oss-fresh-cfgprobe-20260722/bin/preload.so

"$CC" "${COMMON[@]}" -DDIRECT_WRITE_ROUTE_ONLY_PROBE=1 \
  -DCFGPROBE_ONLY_DIAG=0 -DPSELECT_CFI_ROUTE_ATTEMPTS=1 "${SRCS[@]}" \
  -fPIC -shared -pthread \
  -o build/violin-v-oss-fresh-route-20260722/bin/preload.so

"$CC" "${COMMON[@]}" -DCFI_TRANSPORT_ONLY_DIAG=1 "${SRCS[@]}" \
  -fPIC -shared -pthread \
  -o build/violin-v-oss-fresh-cfi-20260722/bin/preload.so

file \
  build/violin-v-oss-fresh-cfgprobe-20260722/bin/preload.so \
  build/violin-v-oss-fresh-route-20260722/bin/preload.so \
  build/violin-v-oss-fresh-cfi-20260722/bin/preload.so
sha256sum \
  build/violin-v-oss-fresh-cfgprobe-20260722/bin/preload.so \
  build/violin-v-oss-fresh-route-20260722/bin/preload.so \
  build/violin-v-oss-fresh-cfi-20260722/bin/preload.so
