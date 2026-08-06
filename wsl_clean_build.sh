#!/bin/bash
# Clean build - kill everything first, then build step by step
set -e

KSRC=/tmp/kernel-full/common-gki
XCFG=/tmp/kernel-full/xring-configs
KOUT=/tmp/kbuild2
DEST=/mnt/e/workspace/projects/xiaomi-root/outputs

# Kill ALL stale make processes
echo "=== Cleaning up ==="
pkill -9 -f "make" 2>/dev/null || true
sleep 2

rm -rf "$KOUT"
mkdir -p "$KOUT"

cd "$KSRC"

# Merge config
echo "=== Configuring ==="
cat arch/arm64/configs/gki_defconfig > /tmp/v2_defconfig
[ -f "$XCFG/O1/O1_gki.fragment" ] && cat "$XCFG/O1/O1_gki.fragment" >> /tmp/v2_defconfig
[ -f "$XCFG/xiaomi/xiaomi_deconfig.common" ] && cat "$XCFG/xiaomi/xiaomi_deconfig.common" >> /tmp/v2_defconfig
cp /tmp/v2_defconfig arch/arm64/configs/violin_defconfig2

make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" violin_defconfig2 2>&1 | tail -3

# Disable DTS
sed -i 's/CONFIG_BUILD_ARM64_DT_OVERLAYS=y/# CONFIG_BUILD_ARM64_DT_OVERLAYS is not set/' "$KOUT/.config"
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" olddefconfig 2>&1 | tail -3

echo "=== Building prepare ==="
# Build prepare first (single-threaded to avoid fork bomb)
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" -j1 prepare 2>&1 | tail -20

echo "=== Building scripts ==="
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" -j1 scripts 2>&1 | tail -10

echo "=== Building vmlinux ==="
echo "Start: $(date)"
CORES=$(nproc)
echo "Using $CORES cores"
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" -j$CORES vmlinux 2>&1 | tail -30
echo "End: $(date)"

echo ""
echo "=== Result ==="
if [ -f "$KOUT/System.map" ]; then
    cp "$KOUT/System.map" "$DEST/System.map"
    echo "SUCCESS!"
    wc -l "$DEST/System.map"
    grep -w "init_task\|noop_llseek\|ashmem_ioctl\|anon_pipe_buf_ops\|copy_splice_read\|configfs_read_iter\|selinux_enforcing\|kmalloc_caches\|security_hook_heads\|root_task_group\|init_uts_ns\|empty_zero_page\|nfulnl_logger\|random_boot_id\|sysctl_bootid" "$DEST/System.map"
elif [ -f "$KOUT/vmlinux" ]; then
    aarch64-linux-gnu-nm "$KOUT/vmlinux" | sort > "$DEST/System.map"
    echo "Generated from vmlinux!"
    wc -l "$DEST/System.map"
    grep -w "init_task\|noop_llseek\|ashmem_ioctl\|anon_pipe_buf_ops\|copy_splice_read\|configfs_read_iter\|selinux_enforcing\|kmalloc_caches\|security_hook_heads\|root_task_group" "$DEST/System.map"
else
    echo "FAILED"
    ls -lh "$KOUT/vmlinux" 2>/dev/null || echo "no vmlinux"
fi
