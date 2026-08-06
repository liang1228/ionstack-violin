#!/usr/bin/env bash
set -euo pipefail

# Build-only artifact for the Stage-2 wiring change.  This script does not
# invoke adb and does not run the resulting shared object.
NDK_ROOT="${NDK_ROOT:-/mnt/e/workspace/projects/xiaomi-root/ndk}"
SRC="${SRC:-/mnt/e/workspace/projects/xiaomi-root/exploit-repo/IonStack/CVE-2026-43499/exploit}"
CC="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang"
SYSROOT="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
OUT="${OUT:-build/violin-v-oss-root-stage-20260722/bin}"

cd "$SRC"
COMMON=(
  --target=aarch64-linux-android35
  --sysroot="$SYSROOT"
  -O2 -g0 -Wall -Wextra -Isrc
  -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function
  '-DTARGET_CONFIG_H="targets/violin-v-oss/target.h"'
  -DLEGACY_CONFIGFS_CRED_STAGE=0
)
SRCS=(
  src/main.c src/util.c src/targets/violin-v-oss/slide.c src/fops.c
  src/pipe.c src/root.c src/preload.c src/su_blob.S src/wallpaper_blob.S
)

mkdir -p "$OUT"
"$CC" "${COMMON[@]}" "${SRCS[@]}" -fPIC -shared -pthread \
  -o "$OUT/preload.so"
file "$OUT/preload.so"
sha256sum "$OUT/preload.so"
