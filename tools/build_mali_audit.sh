#!/bin/bash
set -e
CC=/tmp/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang
SYSROOT=/tmp/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot
SRC=/mnt/e/workspace/projects/xiaomi-root/tools/mali_iov_audit.c
OUT=/mnt/e/workspace/projects/xiaomi-root/tools/mali_iov_audit

"$CC" --target=aarch64-linux-android35 --sysroot="$SYSROOT" -O2 -o "$OUT" "$SRC"
echo "BUILD_OK"
