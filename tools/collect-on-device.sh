#!/system/bin/sh
# collect-on-device.sh
# 直接在已 root 设备上运行，收集 canonical 内核信息
# 输出到 /sdcard/Download/canonical-kernel-<timestamp>/

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTDIR="/sdcard/Download/canonical-kernel-$TIMESTAMP"
mkdir -p "$OUTDIR"

echo "=== Canonical Kernel Info Collection ==="
echo "Output: $OUTDIR"
echo "Context: $(cat /proc/self/attr/current 2>/dev/null)"

# 1. kallsyms - 最重要
echo "[1/8] Collecting kallsyms..."
cat /proc/kallsyms > "$OUTDIR/kallsyms.txt" 2>/dev/null
FIRST=$(head -1 "$OUTDIR/kallsyms.txt" 2>/dev/null)
SIZE=$(wc -c < "$OUTDIR/kallsyms.txt")
echo "  Size: $SIZE bytes"
echo "  First: $FIRST"

if echo "$FIRST" | grep -q "0000000000000000"; then
    echo "  WARNING: All zeros! Trying su..."
    su -c "cat /proc/kallsyms" > "$OUTDIR/kallsyms_su.txt" 2>/dev/null
    SU_FIRST=$(head -1 "$OUTDIR/kallsyms_su.txt" 2>/dev/null)
    if ! echo "$SU_first" | grep -q "0000000000000000"; then
        echo "  su version has real addresses!"
        cp "$OUTDIR/kallsyms_su.txt" "$OUTDIR/kallsyms.txt"
    fi
fi

# 2. 关键符号
echo "[2/8] Extracting key symbols..."
grep -E "_text|_stext|sysctl_bootid|nfulnl_logger|^.*loggers$|init_task|root_task_group|rt_mutex_adjust|futex_requeue" "$OUTDIR/kallsyms.txt" | head -20 > "$OUTDIR/key-symbols.txt"
cat "$OUTDIR/key-symbols.txt"

# 3. iomem
echo "[3/8] Collecting iomem..."
cat /proc/iomem > "$OUTDIR/iomem.txt" 2>/dev/null

# 4. cmdline + version
echo "[4/8] Collecting cmdline + version..."
cat /proc/cmdline > "$OUTDIR/cmdline.txt" 2>/dev/null
cat /proc/version > "$OUTDIR/version.txt" 2>/dev/null

# 5. modules
echo "[5/8] Collecting modules..."
cat /proc/modules > "$OUTDIR/modules.txt" 2>/dev/null

# 6. vmallocinfo
echo "[6/8] Collecting vmallocinfo..."
cat /proc/vmallocinfo > "$OUTDIR/vmallocinfo.txt" 2>/dev/null

# 7. module sections
echo "[7/8] Collecting module sections..."
for d in /sys/module/*/sections; do
    mod=$(basename $(dirname "$d"))
    for f in "$d"/*; do
        [ -r "$f" ] && echo "$mod/$(basename "$f")=$(cat "$f")" >> "$OUTDIR/module-sections.txt"
    done
done

# 8. dev list
echo "[8/8] Collecting dev list..."
ls -la /dev/ > "$OUTDIR/dev-list.txt" 2>/dev/null

# 摘要
echo ""
echo "=== Collection Complete ==="
echo "Output: $OUTDIR"
echo "Files:"
ls -lh "$OUTDIR/"
echo ""
FIRST=$(head -1 "$OUTDIR/kallsyms.txt" 2>/dev/null)
if echo "$FIRST" | grep -q "0000000000000000"; then
    echo "WARNING: kallsyms is all zeros!"
    echo "Try running with: su -c 'sh $0'"
else
    echo "SUCCESS: kallsyms has real addresses!"
fi
