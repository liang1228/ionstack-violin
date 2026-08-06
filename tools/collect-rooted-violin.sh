#!/bin/bash
# collect-rooted-violin.sh
# 通过 ADB 在 rooted violin 上收集 canonical 内核信息，输出到本地 tools/ 目录
# 用法：bash tools/collect-rooted-violin.sh

set -e

ADB="C:/Users/zeooon3/AppData/Local/Android/Sdk/platform-tools/adb.exe"
TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOCAL_OUTPUT="$TOOLS_DIR/canonical-kernel-$TIMESTAMP"
DEVICE_OUTPUT="/data/local/tmp/canonical-kernel-$TIMESTAMP"

echo "=== Canonical Kernel Info Collection ==="
echo "Local output: $LOCAL_OUTPUT"
mkdir -p "$LOCAL_OUTPUT"

# 检查设备
echo "[1/5] Checking device..."
"$ADB" devices -l | grep -v "List" | head -1

# 检查 root
echo "[2/5] Checking root..."
# 尝试不同的 su 路径
SU_CMD=""
for su_path in "/system/bin/su" "/system/xbin/su" "/sbin/su" "/data/adb/magisk/su" "/data/adb/ap/su"; do
    if "$ADB" shell "test -x $su_path" 2>/dev/null; then
        SU_CMD="$su_path"
        echo "  Found su at: $SU_CMD"
        break
    fi
done

if [ -z "$SU_CMD" ]; then
    echo "  su not found, trying direct..."
    SU_CMD=""
fi

# 在设备上运行收集脚本
echo "[3/5] Running collection on device..."
"$ADB" shell "mkdir -p $DEVICE_OUTPUT"

# 收集 kallsyms
echo "  Collecting kallsyms..."
if [ -n "$SU_CMD" ]; then
    "$ADB" shell "$SU_CMD -c 'cat /proc/kallsyms > $DEVICE_OUTPUT/kallsyms.txt'" 2>/dev/null
else
    "$ADB" shell "cat /proc/kallsyms > $DEVICE_OUTPUT/kallsyms.txt" 2>/dev/null
fi

# 检查 kallsyms
FIRST_LINE=$("$ADB" shell "head -1 $DEVICE_OUTPUT/kallsyms.txt" 2>/dev/null | tr -d '\r\n')
echo "  kallsyms first line: $FIRST_LINE"

if echo "$FIRST_LINE" | grep -q "0000000000000000"; then
    echo "  WARNING: All zeros! Trying Magisk su..."
    # 尝试 Magisk su
    "$ADB" shell "/data/adb/magisk/su -c 'cat /proc/kallsyms > $DEVICE_OUTPUT/kallsyms_magisk.txt'" 2>/dev/null
    MAGISK_FIRST=$("$ADB" shell "head -1 $DEVICE_OUTPUT/kallsyms_magisk.txt" 2>/dev/null | tr -d '\r\n')
    if ! echo "$MAGISK_FIRST" | grep -q "0000000000000000"; then
        echo "  Magisk su has real addresses!"
        "$ADB" shell "cp $DEVICE_OUTPUT/kallsyms_magisk.txt $DEVICE_OUTPUT/kallsyms.txt"
    fi
fi

# 收集其他信息
echo "  Collecting iomem..."
if [ -n "$SU_CMD" ]; then
    "$ADB" shell "$SU_CMD -c 'cat /proc/iomem > $DEVICE_OUTPUT/iomem.txt'" 2>/dev/null
else
    "$ADB" shell "cat /proc/iomem > $DEVICE_OUTPUT/iomem.txt" 2>/dev/null
fi

echo "  Collecting cmdline + version..."
"$ADB" shell "cat /proc/cmdline > $DEVICE_OUTPUT/cmdline.txt" 2>/dev/null
"$ADB" shell "cat /proc/version > $DEVICE_OUTPUT/version.txt" 2>/dev/null

echo "  Collecting modules..."
"$ADB" shell "cat /proc/modules > $DEVICE_OUTPUT/modules.txt" 2>/dev/null

echo "  Collecting vmallocinfo..."
if [ -n "$SU_CMD" ]; then
    "$ADB" shell "$SU_CMD -c 'cat /proc/vmallocinfo > $DEVICE_OUTPUT/vmallocinfo.txt'" 2>/dev/null
else
    "$ADB" shell "cat /proc/vmallocinfo > $DEVICE_OUTPUT/vmallocinfo.txt" 2>/dev/null
fi

echo "  Collecting module sections..."
"$ADB" shell "for d in /sys/module/*/sections; do mod=\$(basename \$(dirname \$d)); for f in \$d/*; do [ -r \$f ] && echo \$mod/\$(basename \$f)=\$(cat \$f); done; done > $DEVICE_OUTPUT/module-sections.txt" 2>/dev/null

echo "  Collecting dev list..."
"$ADB" shell "ls -la /dev/ > $DEVICE_OUTPUT/dev-list.txt" 2>/dev/null

echo "  Collecting SELinux info..."
"$ADB" shell "cat /proc/self/attr/current > $DEVICE_OUTPUT/selinux-context.txt" 2>/dev/null
"$ADB" shell "getenforce > $DEVICE_OUTPUT/selinux-enforce.txt" 2>/dev/null
"$ADB" shell "getprop ro.build.fingerprint > $DEVICE_OUTPUT/fingerprint.txt" 2>/dev/null

# 提取关键符号
echo "  Extracting key symbols..."
"$ADB" shell "grep -E '_text|_stext|sysctl_bootid|nfulnl_logger|loggers|init_task|root_task_group|rt_mutex_adjust|futex_requeue' $DEVICE_OUTPUT/kallsyms.txt > $DEVICE_OUTPUT/key-symbols.txt" 2>/dev/null

# 拉取结果
echo "[4/5] Pulling results..."
"$ADB" pull "$DEVICE_OUTPUT/" "$LOCAL_OUTPUT/" 2>&1

# 清理设备
echo "[5/5] Cleaning up device..."
"$ADB" shell "rm -rf $DEVICE_OUTPUT" 2>/dev/null

# 生成摘要
cat > "$LOCAL_OUTPUT/SUMMARY.md" << EOF
# Canonical Kernel Info Collection

## Status
- Date: $(date)
- kallsyms: $(head -1 "$LOCAL_OUTPUT/kallsyms.txt" 2>/dev/null || echo "N/A")
- Key symbols: $(wc -l < "$LOCAL_OUTPUT/key-symbols.txt" 2>/dev/null || echo "0") entries

## Key Symbols
\`\`\`
$(cat "$LOCAL_OUTPUT/key-symbols.txt" 2>/dev/null || echo "Not available")
\`\`\`
EOF

echo ""
echo "=== Collection Complete ==="
echo "Output: $LOCAL_OUTPUT"
echo ""
echo "Files:"
ls -lh "$LOCAL_OUTPUT/"
echo ""

FIRST_LINE=$(head -1 "$LOCAL_OUTPUT/kallsyms.txt" 2>/dev/null || echo "")
if echo "$FIRST_LINE" | grep -q "0000000000000000"; then
    echo "⚠️  WARNING: kallsyms is all zeros!"
    echo "   The device may need a different root method."
elif echo "$FIRST_LINE" | grep -qE "^[0-9a-f]+ "; then
    echo "✅ SUCCESS: kallsyms has real addresses!"
    echo "   Key symbols in: $LOCAL_OUTPUT/key-symbols.txt"
else
    echo "❓ UNKNOWN: Could not determine kallsyms status"
fi
