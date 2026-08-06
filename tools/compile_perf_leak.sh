#!/bin/bash
set -e
cd /mnt/e/workspace/projects/xiaomi-root/exploit-repo/IonStack/CVE-2026-43499/exploit
make PROJECT=violin-v-oss NDK_ROOT=/mnt/e/workspace/projects/xiaomi-root/ndk \
  OUTDIR=build/violin-perf-leak/bin clean preload \
  COMMON_CFLAGS='-O2 -g0 -Wall -Wextra -Isrc -DPERF_LEAK_ONLY=1' 2>&1
sha256sum build/violin-perf-leak/bin/preload.so
ls -la build/violin-perf-leak/bin/preload.so
echo "DONE"
