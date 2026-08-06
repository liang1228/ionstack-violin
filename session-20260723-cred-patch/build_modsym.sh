#!/bin/bash
cd /mnt/e/workspace/projects/xiaomi-root/kernel-src-wsl/common-gki
XCFG=/mnt/e/workspace/projects/xiaomi-root/kernel-src-wsl/xring-configs
OUTDIR=/tmp/kernel-out

cat arch/arm64/configs/gki_defconfig > /tmp/violin_defconfig
[ -f "$XCFG/O1/O1_gki.fragment" ] && cat "$XCFG/O1/O1_gki.fragment" >> /tmp/violin_defconfig
[ -f "$XCFG/xiaomi/xiaomi_deconfig.common" ] && cat "$XCFG/xiaomi/xiaomi_deconfig.common" >> /tmp/violin_defconfig
echo "CONFIG_KALLSYMS_ALL=y" >> /tmp/violin_defconfig
cp /tmp/violin_defconfig arch/arm64/configs/violin_defconfig
echo "defconfig: $(wc -l < arch/arm64/configs/violin_defconfig) lines"

make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O=$OUTDIR violin_defconfig 2>&1 | tail -3
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O=$OUTDIR -j1 modules_prepare 2>&1 | tail -10

if [ -f $OUTDIR/Module.symvers ]; then
    echo "=== SUCCESS ==="
    wc -l $OUTDIR/Module.symvers
    cp $OUTDIR/Module.symvers /mnt/e/workspace/projects/xiaomi-root/outputs/Module.symvers
    echo "Copied to outputs/"
else
    echo "=== FAILED ==="
fi
