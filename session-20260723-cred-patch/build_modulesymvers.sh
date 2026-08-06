#!/bin/bash
# build_modulesymvers.sh — 最小化编译生成 Module.symvers
set -e

KSRC=/mnt/e/workspace/projects/xiaomi-root/kernel-src-wsl/common-gki
OUTDIR=/tmp/kernel-out

cd "$KSRC"

# 确保干净
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

# defconfig
XCFG=/mnt/e/workspace/projects/xiaomi-root/kernel-src-wsl/xring-configs
cat arch/arm64/configs/gki_defconfig > /tmp/vc
[ -f "$XCFG/O1/O1_gki.fragment" ] && cat "$XCFG/O1/O1_gki.fragment" >> /tmp/vc
[ -f "$XCFG/xiaomi/xiaomi_deconfig.common" ] && cat "$XCFG/xiaomi/xiaomi_deconfig.common" >> /tmp/vc
echo "CONFIG_KALLSYMS_ALL=y" >> /tmp/vc
cp /tmp/vc arch/arm64/configs/violin_defconfig
echo "[1] defconfig ready"

# 用 clang 编译（匹配设备内核的编译器）
export ARCH=arm64
export CC=clang
export LLVM=1

make O=$OUTDIR violin_defconfig 2>&1 | tail -2
echo "[2] defconfig done"

# modules_prepare
make O=$OUTDIR modules_prepare -j$(nproc) 2>&1 | tail -3
echo "[3] modules_prepare done"

# 编译最小模块集生成 Module.symvers
# drivers/base/ 有几个小模块
make O=$OUTDIR -j$(nproc) M=drivers/base 2>&1 | tail -5
echo "[4] drivers/base done"

# 检查
if [ -f "$OUTDIR/Module.symvers" ]; then
    echo "=== SUCCESS ==="
    wc -l "$OUTDIR/Module.symvers"
    cp "$OUTDIR/Module.symvers" /mnt/e/workspace/projects/xiaomi-root/outputs/Module.symvers
    echo "Copied to outputs/"
else
    echo "=== Module.symvers not found, trying full modules ==="
    make O=$OUTDIR -j$(nproc) modules 2>&1 | tail -5
    if [ -f "$OUTDIR/Module.symvers" ]; then
        echo "=== SUCCESS (full build) ==="
        wc -l "$OUTDIR/Module.symvers"
        cp "$OUTDIR/Module.symvers" /mnt/e/workspace/projects/xiaomi-root/outputs/Module.symvers
    else
        echo "=== FAILED ==="
    fi
fi
