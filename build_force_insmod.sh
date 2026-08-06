#!/bin/bash
export PATH=/mnt/e/workspace/projects/xiaomi-root/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
cp /mnt/e/workspace/projects/xiaomi-root/force_insmod.c ~/force_insmod.c
clang-21 --target=aarch64-linux-android35 -static -o ~/force_insmod ~/force_insmod.c
echo "ret=$?"
ls -la ~/force_insmod
