#!/bin/bash
# 编译 kcore_read 并打包诊断工具
set -e
NDK=/mnt/e/workspace/projects/xiaomi-root/ndk/toolchains/llvm/prebuilt/linux-x86_64
SRC=/mnt/e/workspace/projects/xiaomi-root/tools/kcore_read.c
OUT=/mnt/e/workspace/projects/xiaomi-root/tools/kcore_read

ln -sf "$NDK/bin/lld" /tmp/ld.lld 2>/dev/null

"$NDK/bin/clang-21" --target=aarch64-linux-android35 \
    -O2 -static -B/tmp -Wno-macro-redefined \
    -o "$OUT" "$SRC"

ls -la "$OUT"
sha256sum "$OUT"
echo "DONE"
