#!/bin/bash
set -e
NDK=/mnt/e/ZEOON3/Downloads/Compressed/android-ndk-r29-linux/android-ndk-r29
CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang"
SYSROOT="$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
SRC=/mnt/e/workspace/projects/xiaomi-root/exploit-repo/IonStack/CVE-2026-43499/exploit
OUT=/mnt/e/workspace/projects/xiaomi-root/outputs
cd "$SRC"
echo '=== NDK ==='
"$CC" --version 2>&1 | head -1
echo '=== Building ==='
"$CC" \
    --target=aarch64-linux-android35 \
    --sysroot="$SYSROOT" \
    -O2 -fPIC -shared \
    -DTARGET_CONFIG_H='"targets/violin-v-oss/target.h"' \
    -Isrc \
    -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
    src/main.c src/preload.c src/slide.c src/fops.c src/pipe.c \
    src/root.c src/util.c src/su_blob.S src/wallpaper_blob.S \
    -o "$OUT/preload.so" \
    -pthread
echo '=== Verify ==='
readelf -d "$OUT/preload.so" | grep NEEDED
ls -lh "$OUT/preload.so"
echo 'DONE'
