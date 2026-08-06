#!/bin/bash
# Complete kernel build for Xiaomi Pad 7S Pro (violin)
# Step 1: Extract full source to WSL local filesystem
# Step 2: Build kernel
# Step 3: Generate System.map

set -e

TARBALL="/mnt/e/workspace/projects/xiaomi-root/kernel-src.tar.gz"
EXTRACT_DIR="/tmp/kernel-full"
DEST="/mnt/e/workspace/projects/xiaomi-root/outputs"

echo "============================================"
echo "  Kernel Build for System.map"
echo "============================================"

# ── Step 1: Extract tarball ──
if [ -f "$EXTRACT_DIR/common-gki/Makefile" ]; then
    echo "[1/4] Source already extracted"
else
    echo "[1/4] Extracting full source to $EXTRACT_DIR ..."
    rm -rf "$EXTRACT_DIR"
    mkdir -p "$EXTRACT_DIR"
    # Extract everything, strip the leading MiCode-Xiaomi_Kernel_OpenSource-xxx/ component
    tar -xzf "$TARBALL" -C "$EXTRACT_DIR" --strip-components=1 2>&1 | tail -3
    echo "Extracted. Files: $(find "$EXTRACT_DIR" -type f | wc -l)"
fi

KSRC="$EXTRACT_DIR/common-gki"
XCFG="$EXTRACT_DIR/xring-configs"
KOUT="/tmp/kbuild"

echo ""
echo "[2/4] Configuring kernel ..."
cd "$KSRC"

# Create merged defconfig
cat arch/arm64/configs/gki_defconfig > /tmp/violin_defconfig
[ -f "$XCFG/O1/O1_gki.fragment" ] && cat "$XCFG/O1/O1_gki.fragment" >> /tmp/violin_defconfig
[ -f "$XCFG/xiaomi/xiaomi_deconfig.common" ] && cat "$XCFG/xiaomi/xiaomi_deconfig.common" >> /tmp/violin_defconfig
cp /tmp/violin_defconfig arch/arm64/configs/violin_defconfig

rm -rf "$KOUT"
mkdir -p "$KOUT"
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" violin_defconfig 2>&1 | tail -3

# Disable DTS to avoid missing file issues
sed -i 's/CONFIG_BUILD_ARM64_DT_OVERLAYS=y/# CONFIG_BUILD_ARM64_DT_OVERLAYS is not set/' "$KOUT/.config"
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" olddefconfig 2>&1 | tail -3
echo "Config ready: $(wc -l < "$KOUT/.config") lines"

echo ""
echo "[3/4] Building vmlinux (this takes 10-30 min on 32 cores) ..."
echo "Start: $(date)"
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" -j$(nproc) vmlinux 2>&1
echo "End: $(date)"

echo ""
echo "[4/4] Extracting System.map ..."
VMLINUX="$KOUT/vmlinux"
SMAP="$DEST/System.map"

if [ -f "$KOUT/System.map" ]; then
    cp "$KOUT/System.map" "$SMAP"
elif [ -f "$VMLINUX" ]; then
    aarch64-linux-gnu-nm "$VMLINUX" | sort > "$SMAP"
fi

if [ -f "$SMAP" ]; then
    echo "=== SUCCESS ==="
    wc -l "$SMAP"
    echo ""
    echo "Key symbols:"
    grep -w "init_task\|noop_llseek\|ashmem_ioctl\|anon_pipe_buf_ops\|copy_splice_read\|configfs_read_iter\|selinux_enforcing\|kmalloc_caches\|security_hook_heads\|root_task_group\|init_uts_ns\|empty_zero_page\|nfulnl_logger\|random_boot_id\|sysctl_bootid" "$SMAP"
else
    echo "FAILED - no vmlinux or System.map"
    ls -lh "$VMLINUX" 2>/dev/null
fi
