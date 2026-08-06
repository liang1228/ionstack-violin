#!/bin/bash
set -e
NDK=/mnt/e/workspace/projects/xiaomi-root/ndk/toolchains/llvm/prebuilt/linux-x86_64
SRC=/mnt/e/workspace/projects/xiaomi-root/tools/trace-kaslr-leak/trace_kaslr_leak.c
OUT=/mnt/e/workspace/projects/xiaomi-root/tools/trace-kaslr-leak/trace_kaslr_leak

# Create proper ld.lld symlink
ln -sf "$NDK/bin/lld" /tmp/ld.lld

cd /tmp
"$NDK/bin/clang-21" --target=aarch64-linux-android35 \
    -O2 -static \
    -B/tmp \
    -Wno-macro-redefined \
    -o "$OUT" "$SRC"

ls -la "$OUT"
sha256sum "$OUT"
echo "DONE"
