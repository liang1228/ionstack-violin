#!/system/bin/sh
# collect-violin-kernel.sh
# 在已 root 的 Xiaomi Pad 7S Pro (violin) 上收集 canonical 内核地址
# 用法：在设备终端运行 su -c 'sh /path/to/collect-violin-kernel1.sh'
# 或由 collect-violin-kernel-remote.ps1 通过 ADB 运行。
# 默认不修改 kptr_restrict；只有 ALLOW_KPTR_RELAXATION=1 时临时改为 0，退出时恢复。

OUTDIR="${OUTDIR:-/data/local/tmp/violin-kernel-info-$(date +%Y%m%d-%H%M%S)}"
ALLOW_KPTR_RELAXATION="${ALLOW_KPTR_RELAXATION:-0}"
KPTR_PATH="/proc/sys/kernel/kptr_restrict"
KPTR_BEFORE=""
KPTR_CHANGED=0

restore_kptr() {
    if [ "$KPTR_CHANGED" = "1" ] && [ -n "$KPTR_BEFORE" ]; then
        echo "$KPTR_BEFORE" > "$KPTR_PATH" 2>/dev/null || true
    fi
}
trap restore_kptr EXIT HUP INT TERM

mkdir -p "$OUTDIR"

echo "=========================================="
echo " Violin Kernel Info Collection"
echo "=========================================="
echo ""
echo "Output: $OUTDIR"
echo "Context: $(cat /proc/self/attr/current 2>/dev/null)"
echo ""

# 0. 可选的、可恢复的 kptr_restrict 调整
echo "[0/9] kptr_restrict policy..."
KPTR_BEFORE=$(cat "$KPTR_PATH" 2>/dev/null || true)
echo "  before=${KPTR_BEFORE:-unreadable}, allow_relaxation=$ALLOW_KPTR_RELAXATION"
if [ "$ALLOW_KPTR_RELAXATION" = "1" ] && [ -n "$KPTR_BEFORE" ] && [ "$KPTR_BEFORE" != "0" ]; then
    if echo 0 > "$KPTR_PATH" 2>/dev/null; then
        KPTR_CHANGED=1
        echo "  temporarily set to 0; restoration is registered"
    else
        echo "  unable to set kptr_restrict; collection continues without mutation"
    fi
fi
KPTR=$(cat "$KPTR_PATH" 2>/dev/null || true)
echo "  during=${KPTR:-unreadable}"
echo ""

# 1. kallsyms - 最重要
echo "[1/9] Collecting kallsyms..."
cat /proc/kallsyms > "$OUTDIR/kallsyms.txt" 2>/dev/null
FIRST=$(head -1 "$OUTDIR/kallsyms.txt" 2>/dev/null)
SIZE=$(wc -c < "$OUTDIR/kallsyms.txt")
echo "  Size: $SIZE bytes"
echo "  First: $FIRST"

if echo "$FIRST" | grep -q "0000000000000000"; then
    echo ""
    echo "  ❌ kallsyms is ALL ZEROS!"
    echo "  This means the root context hides kernel addresses."
    echo "  Try running with: su -c 'sh $0'"
    echo ""
else
    echo "  ✅ kallsyms has real addresses!"
fi

# 2. 关键符号
echo "[2/9] Extracting key symbols..."
grep -E "_text$|_stext$|sysctl_bootid|nfulnl_logger|loggers |init_task |root_task_group|misc_fops|ashmem_fops|anon_pipe_buf_ops|KASLR|selinux_enforcing|selinux_blob_sizes|security_hook_heads|kmalloc_caches" "$OUTDIR/kallsyms.txt" > "$OUTDIR/key-symbols.txt" 2>/dev/null
echo "  Found $(wc -l < "$OUTDIR/key-symbols.txt") key symbols"
echo ""
echo "  === Key Symbols ==="
cat "$OUTDIR/key-symbols.txt"
echo ""

# 3. iomem
echo "[3/9] Collecting iomem..."
cat /proc/iomem > "$OUTDIR/iomem.txt" 2>/dev/null

# 4. cmdline + version
echo "[4/9] Collecting cmdline + version..."
cat /proc/cmdline > "$OUTDIR/cmdline.txt" 2>/dev/null
cat /proc/version > "$OUTDIR/version.txt" 2>/dev/null

# 5. modules
echo "[5/9] Collecting modules..."
cat /proc/modules > "$OUTDIR/modules.txt" 2>/dev/null

# 6. vmallocinfo
echo "[6/9] Collecting vmallocinfo..."
cat /proc/vmallocinfo > "$OUTDIR/vmallocinfo.txt" 2>/dev/null

# 7. module sections
echo "[7/9] Collecting module sections..."
for d in /sys/module/*/sections; do
    mod=$(basename $(dirname "$d"))
    for f in "$d"/*; do
        [ -r "$f" ] && echo "$mod/$(basename "$f")=$(cat "$f")" >> "$OUTDIR/module-sections.txt"
    done
done

# 8. 设备信息与采集元数据
echo "[8/9] Collecting device info..."
getprop ro.build.fingerprint > "$OUTDIR/fingerprint.txt" 2>/dev/null
getprop ro.product.model > "$OUTDIR/model.txt" 2>/dev/null
cat /proc/self/attr/current > "$OUTDIR/selinux-context.txt" 2>/dev/null
getenforce > "$OUTDIR/selinux-enforce.txt" 2>/dev/null
cat /proc/sys/kernel/random/boot_id > "$OUTDIR/boot-id.txt" 2>/dev/null
{
    echo "collector=collect-violin-kernel1.sh"
    echo "uid=$(id -u)"
    echo "context=$(cat /proc/self/attr/current 2>/dev/null)"
    echo "kptr_before=${KPTR_BEFORE:-unreadable}"
    echo "kptr_during=${KPTR:-unreadable}"
    echo "kptr_will_restore=$KPTR_CHANGED"
    echo "timestamp=$(date -Iseconds 2>/dev/null || date)"
} > "$OUTDIR/collection-meta.txt"

# 9. 完整性清单和压缩包
echo "[9/9] Creating integrity manifest..."
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUTDIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum) > "$OUTDIR/SHA256SUMS"
fi
ARCHIVE="$OUTDIR.tar.gz"
if command -v tar >/dev/null 2>&1; then
    tar -C "$(dirname "$OUTDIR")" -czf "$ARCHIVE" "$(basename "$OUTDIR")" 2>/dev/null || ARCHIVE=""
fi

# 摘要
echo ""
echo "=========================================="
echo " Collection Complete!"
echo "=========================================="
echo ""
echo "Output directory: $OUTDIR"
echo ""
echo "Files:"
ls -lh "$OUTDIR/"
echo ""

FIRST=$(head -1 "$OUTDIR/kallsyms.txt" 2>/dev/null)
if echo "$FIRST" | grep -q "0000000000000000"; then
    echo "⚠️  kallsyms is all zeros - root context issue"
    echo "   Try: su -c 'sh $0'"
elif echo "$FIRST" | grep -qE "^[0-9a-f]+ "; then
    echo "✅ kallsyms has real canonical addresses!"
    echo "   Key file: $OUTDIR/key-symbols.txt"
else
    echo "❓ Could not determine kallsyms status"
fi

echo ""
echo "Please send the entire '$OUTDIR' folder to the developer."
echo "OUTDIR=$OUTDIR"
[ -n "$ARCHIVE" ] && echo "ARCHIVE=$ARCHIVE"
