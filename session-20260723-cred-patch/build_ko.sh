#!/bin/bash
set -e
cd /mnt/e/workspace/projects/xiaomi-root/kernel-src-wsl/common-gki
OUT=/tmp/kernel-out
XCFG=/mnt/e/workspace/projects/xiaomi-root/kernel-src-wsl/xring-configs

# defconfig
cat arch/arm64/configs/gki_defconfig > /tmp/vc
[ -f "$XCFG/O1/O1_gki.fragment" ] && cat "$XCFG/O1/O1_gki.fragment" >> /tmp/vc
[ -f "$XCFG/xiaomi/xiaomi_deconfig.common" ] && cat "$XCFG/xiaomi/xiaomi_deconfig.common" >> /tmp/vc
echo "CONFIG_KALLSYMS_ALL=y" >> /tmp/vc
cp /tmp/vc arch/arm64/configs/violin_defconfig
echo "[1] defconfig ready"

# build with clang
export ARCH=arm64
export CC=clang
export LLVM=1

make O=$OUT violin_defconfig 2>&1 | tail -2
echo "[2] defconfig done"

make O=$OUT modules_prepare -j$(nproc) 2>&1 | tail -3
echo "[3] modules_prepare done"

# Build minimal modules to generate Module.symvers
make O=$OUT -j$(nproc) M=scripts/mod 2>&1 | tail -3
echo "[4] scripts/mod done"

# Check
if [ -f "$OUT/Module.symvers" ]; then
    echo "=== SUCCESS ==="
    wc -l "$OUT/Module.symvers"
    cp "$OUT/Module.symvers" /mnt/e/workspace/projects/xiaomi-root/outputs/Module.symvers
    echo "Copied to outputs/"
else
    echo "=== FAILED ==="
    echo "Trying full modules build..."
    make O=$OUT -j$(nproc) modules 2>&1 | tail -5
    if [ -f "$OUT/Module.symvers" ]; then
        echo "SUCCESS (from full build)"
        wc -l "$OUT/Module.symvers"
        cp "$OUT/Module.symvers" /mnt/e/workspace/projects/xiaomi-root/outputs/Module.symvers
    fi
fi
