#!/bin/bash
NDK=/mnt/e/workspace/projects/xiaomi-root/ndk
CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang"
SYSROOT="$NDK/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
RESOURCE="$NDK/toolchains/llvm/prebuilt/linux-x86_64/lib/clang/21"

cd /mnt/e/workspace/projects/xiaomi-root/session-20260723-cred-patch

"$CC" \
  --target=aarch64-linux-android35 \
  --sysroot="$SYSROOT" \
  -resource-dir "$RESOURCE" \
  --rtlib=compiler-rt \
  --unwindlib=none \
  -shared -fPIC -O2 \
  -o loader.so loader.c -ldl

echo "EXIT=$?"
ls -la loader.so
