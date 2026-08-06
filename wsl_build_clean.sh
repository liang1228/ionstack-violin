#!/bin/bash
# Minimal kernel build script - clean version
# Run in WSL: bash /tmp/build_kernel.sh

set -e

KSRC=/tmp/ksrc
KOUT=/tmp/kout2
DEST=/mnt/e/workspace/projects/xiaomi-root/outputs

echo "=== Cleaning old output ==="
rm -rf "$KOUT"
mkdir -p "$KOUT"

echo "=== Configuring ==="
cd "$KSRC"
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" violin_defconfig 2>&1 | tail -3

echo "=== Building ==="
echo "Start: $(date)"
echo "Cores: $(nproc)"
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- O="$KOUT" -j$(nproc) 2>&1 | tail -50
echo "End: $(date)"

echo ""
echo "=== Checking System.map ==="
if [ -f "$KOUT/System.map" ]; then
    cp "$KOUT/System.map" "$DEST/System.map"
    echo "SUCCESS! System.map saved"
    wc -l "$DEST/System.map"
    echo ""
    echo "Key symbols:"
    grep -w "init_task\|noop_llseek\|ashmem_ioctl\|anon_pipe_buf_ops\|copy_splice_read\|configfs_read_iter\|selinux_enforcing\|kmalloc_caches\|security_hook_heads\|root_task_group\|init_uts_ns" "$DEST/System.map"
else
    echo "FAILED - no System.map"
    echo "Checking vmlinux..."
    ls -lh "$KOUT/vmlinux" 2>/dev/null && nm "$KOUT/vmlinux" 2>/dev/null | head -5
fi
