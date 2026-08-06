#!/bin/bash
set -e

KSRC=/mnt/e/workspace/projects/xiaomi-root/kernel-src-wsl/common-gki
XCFG=/mnt/e/workspace/projects/xiaomi-root/kernel-src-wsl/xring-configs
OUTDIR=/tmp/kernel-out

echo "=== Step 1: Merge defconfig ==="
cd "$KSRC"
echo "In: $(pwd)"

cat arch/arm64/configs/gki_defconfig > /tmp/violin_defconfig
[ -f "$XCFG/O1/O1_gki.fragment" ] && cat "$XCFG/O1/O1_gki.fragment" >> /tmp/violin_defconfig
[ -f "$XCFG/xiaomi/xiaomi_deconfig.common" ] && cat "$XCFG/xiaomi/xiaomi_deconfig.common" >> /tmp/violin_defconfig
echo "CONFIG_KALLSYMS_ALL=y" >> /tmp/violin_defconfig
cp /tmp/violin_defconfig arch/arm64/configs/violin_defconfig
echo "Defconfig: $(wc -l < arch/arm64/configs/violin_defconfig) lines"

echo ""
echo "=== Step 2: make defconfig ==="
mkdir -p "$OUTDIR"
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$OUTDIR" violin_defconfig 2>&1 | tail -5

echo ""
echo "=== Step 3: Build kernel ==="
echo "Cores: $(nproc)"
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$OUTDIR" -j$(nproc) Image 2>&1 | tail -30

echo ""
echo "=== Step 4: Copy System.map ==="
if [ -f "$OUTDIR/System.map" ]; then
    cp "$OUTDIR/System.map" /mnt/e/workspace/projects/xiaomi-root/outputs/System.map
    echo "SUCCESS! System.map:"
    wc -l /mnt/e/workspace/projects/xiaomi-root/outputs/System.map
    echo ""
    echo "Sample symbols:"
    grep -E "init_task|noop_llseek|ashmem_ioctl|anon_pipe_buf" /mnt/e/workspace/projects/xiaomi-root/outputs/System.map | head -10
else
    echo "System.map not found!"
    find "$OUTDIR" -name System.map 2>/dev/null
fi
