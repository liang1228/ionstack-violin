#!/bin/bash
# Build vmlinux only (skip DTS), then generate System.map
set -e

KSRC=/tmp/ksrc
KOUT=/tmp/kout3
DEST=/mnt/e/workspace/projects/xiaomi-root/outputs

rm -rf "$KOUT"
mkdir -p "$KOUT"

cd "$KSRC"

echo "=== Configuring ==="
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" violin_defconfig 2>&1 | tail -3

# Disable DTS building to avoid missing file errors
sed -i 's/CONFIG_ARCH_QCOM=y/# CONFIG_ARCH_QCOM is not set/' "$KOUT/.config"
sed -i 's/CONFIG_ARCH_MEDIATEK=y/# CONFIG_ARCH_MEDIATEK is not set/' "$KOUT/.config"
sed -i 's/CONFIG_ARCH_EXYNOS=y/# CONFIG_ARCH_EXYNOS is not set/' "$KOUT/.config"
sed -i 's/CONFIG_ARCH_TEGRA=y/# CONFIG_ARCH_TEGRA is not set/' "$KOUT/.config"
# Disable all DTS
echo "# CONFIG_BUILD_ARM64_DT_OVERLAYS is not set" >> "$KOUT/.config"

# Regenerate config with dependencies resolved
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" olddefconfig 2>&1 | tail -5

echo "=== Building vmlinux ==="
echo "Start: $(date)"
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" -j$(nproc) vmlinux 2>&1 | tail -30
echo "End: $(date)"

echo ""
echo "=== Result ==="
if [ -f "$KOUT/System.map" ]; then
    cp "$KOUT/System.map" "$DEST/System.map"
    echo "SUCCESS! System.map saved to $DEST/System.map"
    wc -l "$DEST/System.map"
    echo ""
    echo "Key symbols:"
    grep -w "init_task\|noop_llseek\|ashmem_ioctl\|anon_pipe_buf_ops\|copy_splice_read\|configfs_read_iter\|selinux_enforcing\|kmalloc_caches\|security_hook_heads\|root_task_group\|init_uts_ns\|empty_zero_page\|nfulnl_logger\|random_boot_id\|sysctl_bootid" "$DEST/System.map"
elif [ -f "$KOUT/vmlinux" ]; then
    echo "vmlinux built, generating System.map from nm..."
    aarch64-linux-gnu-nm "$KOUT/vmlinux" | sort > "$DEST/System.map"
    echo "System.map generated from vmlinux"
    wc -l "$DEST/System.map"
    grep -w "init_task\|noop_llseek\|ashmem_ioctl" "$DEST/System.map"
else
    echo "FAILED"
fi
