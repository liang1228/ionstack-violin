#!/bin/bash
# run-collect-canonical.sh
# 通过 ADB 在已 root 设备上收集 canonical 内核信息
# 输出到 tools/ 目录

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ADB="C:/Users/zeooon3/AppData/Local/Android/Sdk/platform-tools/adb.exe"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="$SCRIPT_DIR/canonical-kernel-$TIMESTAMP"

echo "=== Canonical Kernel Info Collection ==="
echo "Output: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# 检查设备连接
echo "[1/12] Checking device..."
"$ADB" devices -l | grep -v "List" | head -1

# 检查 root
echo "[2/12] Checking root access..."
ROOT_CHECK=$("$ADB" shell "su -c 'id'" 2>&1)
if echo "$ROOT_CHECK" | grep -q "uid=0"; then
    echo "  Root: OK"
else
    echo "  Root: FAILED - $ROOT_CHECK"
    exit 1
fi

# 收集 kallsyms
echo "[3/12] Collecting kallsyms..."
"$ADB" shell "su -c 'cat /proc/kallsyms'" > "$OUTPUT_DIR/kallsyms.txt" 2>/dev/null
KALLSYMS_SIZE=$(wc -c < "$OUTPUT_DIR/kallsyms.txt")
FIRST_LINE=$(head -1 "$OUTPUT_DIR/kallsyms.txt" 2>/dev/null)
echo "  Size: $KALLSYMS_SIZE bytes"
echo "  First line: $FIRST_LINE"

if echo "$FIRST_LINE" | grep -q "0000000000000000"; then
    echo "  WARNING: kallsyms is all zeros (Magisk context)"
    echo "  Trying alternative: read from /proc/kcore..."
    # 尝试通过 kcore 读取（需要特殊处理）
    echo "  Please run this script directly on the device with:"
    echo "    su -c 'sh /data/local/tmp/collect-on-device.sh'"
else
    echo "  kallsyms has real addresses!"
fi

# 提取关键符号
echo "[4/12] Extracting key symbols..."
grep -E "^[0-9a-f]+ [tT] _text$|^[0-9a-f]+ [tT] _stext$|^[0-9a-f]+ [dDbB] sysctl_bootid$|^[0-9a-f]+ [dDbB] nfulnl_logger$|^[0-9a-f]+ [dDbB] loggers$|^[0-9a-f]+ [tT] init_task$|^[0-9a-f]+ [dDbB] root_task_group$|^[0-9a-f]+ [tT] rt_mutex_adjust_prio_chain$|^[0-9a-f]+ [tT] futex_requeue_pi$" "$OUTPUT_DIR/kallsyms.txt" > "$OUTPUT_DIR/key-symbols.txt" 2>/dev/null
echo "  Key symbols:"
cat "$OUTPUT_DIR/key-symbols.txt" 2>/dev/null

# 收集 iomem
echo "[5/12] Collecting iomem..."
"$ADB" shell "su -c 'cat /proc/iomem'" > "$OUTPUT_DIR/iomem.txt" 2>/dev/null

# 收集 cmdline
echo "[6/12] Collecting cmdline..."
"$ADB" shell "cat /proc/cmdline" > "$OUTPUT_DIR/cmdline.txt" 2>/dev/null

# 收集 version
echo "[7/12] Collecting version..."
"$ADB" shell "cat /proc/version" > "$OUTPUT_DIR/version.txt" 2>/dev/null

# 收集 modules
echo "[8/12] Collecting modules..."
"$ADB" shell "cat /proc/modules" > "$OUTPUT_DIR/modules.txt" 2>/dev/null

# 收集 vmallocinfo
echo "[9/12] Collecting vmallocinfo..."
"$ADB" shell "su -c 'cat /proc/vmallocinfo'" > "$OUTPUT_DIR/vmallocinfo.txt" 2>/dev/null

# 收集 module sections
echo "[10/12] Collecting module sections..."
"$ADB" shell "su -c 'for d in /sys/module/*/sections; do mod=\$(basename \$(dirname \$d)); for f in \$d/*; do [ -r \$f ] && echo \$mod/\$(basename \$f)=\$(cat \$f); done; done'" > "$OUTPUT_DIR/module-sections.txt" 2>/dev/null

# 收集 dev list
echo "[11/12] Collecting dev list..."
"$ADB" shell "ls -la /dev/" > "$OUTPUT_DIR/dev-list.txt" 2>/dev/null

# 收集 SELinux info
echo "[12/12] Collecting SELinux info..."
"$ADB" shell "cat /proc/self/attr/current" > "$OUTPUT_DIR/selinux-context.txt" 2>/dev/null
"$ADB" shell "getenforce" > "$OUTPUT_DIR/selinux-enforce.txt" 2>/dev/null
"$ADB" shell "getprop ro.build.fingerprint" > "$OUTPUT_DIR/fingerprint.txt" 2>/dev/null

# 生成摘要
cat > "$OUTPUT_DIR/SUMMARY.md" << EOF
# Canonical Kernel Info Collection

## Status
- kallsyms: $(if echo "$FIRST_LINE" | grep -q "0000000000000000"; then echo "ALL ZEROS (Magisk)"; else echo "VALID"; fi)
- Key symbols: $(wc -l < "$OUTPUT_DIR/key-symbols.txt" 2>/dev/null || echo "0") entries

## Key Symbols
\`\`\`
$(cat "$OUTPUT_DIR/key-symbols.txt" 2>/dev/null || echo "Not available")
\`\`\`

## Collection
- Date: $(date)
- Output: $OUTPUT_DIR
EOF

echo ""
echo "=== Collection Complete ==="
echo "Output directory: $OUTPUT_DIR"
echo ""
echo "Files:"
ls -lh "$OUTPUT_DIR/"
echo ""
if echo "$FIRST_LINE" | grep -q "0000000000000000"; then
    echo "WARNING: kallsyms is all zeros!"
    echo "To get real addresses, run this script directly on the device:"
    echo "  1. adb shell"
    echo "  2. su"
    echo "  3. sh /data/local/tmp/collect-on-device.sh"
else
    echo "SUCCESS: kallsyms has real addresses!"
    echo "Key symbols extracted to: $OUTPUT_DIR/key-symbols.txt"
fi
