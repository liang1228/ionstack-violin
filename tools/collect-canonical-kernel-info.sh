#!/system/bin/sh
# collect-canonical-kernel-info.sh
# 在已 root 设备上收集 canonical 内核地址信息
# 用法：adb shell "sh /data/local/tmp/collect-canonical-kernel-info.sh"
#
# 关键：Magisk 的 u:r:magisk:s0 会让 /proc/kallsyms 返回全零
# 需要通过以下方式绕过：
# 1. 使用 su 切换到 root 上下文
# 2. 直接读取 /proc/kallsyms（非 Magisk 上下文）
# 3. 收集其他有用的内核信息

OUTDIR="/data/local/tmp/ionstack-canonical-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

echo "[ionstack] collecting to $OUTDIR"
echo "[ionstack] uid=$(id -u) context=$(cat /proc/self/attr/current 2>/dev/null)"

# 1. kallsyms - 最重要！需要 canonical 地址
echo "[ionstack] collecting kallsyms..."
cat /proc/kallsyms > "$OUTDIR/kallsyms.txt" 2>/dev/null
KALLSYMS_SIZE=$(wc -c < "$OUTDIR/kallsyms.txt")
echo "[ionstack] kallsyms size: $KALLSYMS_SIZE bytes"

# 检查是否全零
FIRST_LINE=$(head -1 "$OUTDIR/kallsyms.txt" 2>/dev/null)
if echo "$FIRST_LINE" | grep -q "0000000000000000"; then
    echo "[ionstack] WARNING: kallsyms is all zeros - Magisk context issue!"
    echo "[ionstack] Trying alternative methods..."

    # 尝试通过 /proc/kcore 读取
    if [ -r /proc/kcore ]; then
        echo "[ionstack] /proc/kcore is readable, extracting..."
        # kcore 是 ELF 格式，需要特殊处理
        cat /proc/kcore > "$OUTDIR/kcore.bin" 2>/dev/null
    fi

    # 尝试通过 /proc/kallsyms 的不同方式读取
    # 有时候 su -c 可以绕过
    echo "[ionstack] trying su -c approach..."
    su -c "cat /proc/kallsyms" > "$OUTDIR/kallsyms_su.txt" 2>/dev/null
    SU_SIZE=$(wc -c < "$OUTDIR/kallsyms_su.txt" 2>/dev/null)
    echo "[ionstack] kallsyms_su size: $SU_SIZE bytes"

    # 检查 su 版本是否全零
    SU_FIRST=$(head -1 "$OUTDIR/kallsyms_su.txt" 2>/dev/null)
    if echo "$SU_FIRST" | grep -q "0000000000000000"; then
        echo "[ionstack] WARNING: su -c kallsyms also all zeros"
    else
        echo "[ionstack] su -c kallsyms has real addresses!"
        cp "$OUTDIR/kallsyms_su.txt" "$OUTDIR/kallsyms.txt"
    fi
fi

# 2. /proc/iomem - 物理内存布局
echo "[ionstack] collecting iomem..."
cat /proc/iomem > "$OUTDIR/iomem.txt" 2>/dev/null

# 3. /proc/cmdline - 内核启动参数
echo "[ionstack] collecting cmdline..."
cat /proc/cmdline > "$OUTDIR/cmdline.txt" 2>/dev/null

# 4. /proc/version
echo "[ionstack] collecting version..."
cat /proc/version > "$OUTDIR/version.txt" 2>/dev/null

# 5. /proc/modules - 加载的内核模块
echo "[ionstack] collecting modules..."
cat /proc/modules > "$OUTDIR/modules.txt" 2>/dev/null

# 6. /proc/vmallocinfo - 虚拟内存分配
echo "[ionstack] collecting vmallocinfo..."
cat /proc/vmallocinfo > "$OUTDIR/vmallocinfo.txt" 2>/dev/null

# 7. /proc/slabinfo - slab 分配器信息
echo "[ionstack] collecting slabinfo..."
cat /proc/slabinfo > "$OUTDIR/slabinfo.txt" 2>/dev/null

# 8. /sys/module/*/sections/* - 模块段地址
echo "[ionstack] collecting module sections..."
mkdir -p "$OUTDIR/module-sections"
for mod_dir in /sys/module/*/sections; do
    mod_name=$(basename $(dirname "$mod_dir"))
    for section in "$mod_dir"/*; do
        if [ -r "$section" ]; then
            sec_name=$(basename "$section")
            value=$(cat "$section" 2>/dev/null)
            echo "$mod_name/$sec_name=$value" >> "$OUTDIR/module-sections.txt"
        fi
    done
done

# 9. 字符设备列表
echo "[ionstack] collecting dev list..."
ls -la /dev/ > "$OUTDIR/dev-list.txt" 2>/dev/null

# 10. /proc/misc
echo "[ionstack] collecting misc..."
cat /proc/misc > "$OUTDIR/misc-list.txt" 2>/dev/null

# 11. SELinux 上下文
echo "[ionstack] collecting SELinux info..."
cat /proc/self/attr/current > "$OUTDIR/selinux-context.txt" 2>/dev/null
getenforce > "$OUTDIR/selinux-enforce.txt" 2>/dev/null

# 12. 设备信息
echo "[ionstack] collecting device info..."
getprop ro.build.fingerprint > "$OUTDIR/fingerprint.txt" 2>/dev/null
getprop ro.product.model > "$OUTDIR/model.txt" 2>/dev/null
getprop ro.build.version.sdk > "$OUTDIR/sdk.txt" 2>/dev/null

# 13. 关键内核符号地址（从 kallsyms 提取）
echo "[ionstack] extracting key symbols..."
if [ -s "$OUTDIR/kallsyms.txt" ] && ! head -1 "$OUTDIR/kallsyms.txt" | grep -q "0000000000000000"; then
    grep -E "^[0-9a-f]+ [tT] _text$|^[0-9a-f]+ [tT] _stext$|^[0-9a-f]+ [dDbB] sysctl_bootid$|^[0-9a-f]+ [dDbB] nfulnl_logger$|^[0-9a-f]+ [dDbB] loggers$|^[0-9a-f]+ [tT] init_task$|^[0-9a-f]+ [dDbB] root_task_group$" "$OUTDIR/kallsyms.txt" > "$OUTDIR/key-symbols.txt"
    echo "[ionstack] key symbols:"
    cat "$OUTDIR/key-symbols.txt"
else
    echo "[ionstack] WARNING: kallsyms not available, skipping key symbols"
fi

# 14. BTF 信息（如果可用）
if [ -r /sys/kernel/btf/vmlinux ]; then
    echo "[ionstack] collecting BTF..."
    cp /sys/kernel/btf/vmlinux "$OUTDIR/vmlinux.btf" 2>/dev/null
fi

# 15. 生成摘要
echo "[ionstack] generating summary..."
cat > "$OUTDIR/SUMMARY.md" << EOF
# Canonical Kernel Info Collection

## Device
- Model: $(cat "$OUTDIR/model.txt" 2>/dev/null)
- Fingerprint: $(cat "$OUTDIR/fingerprint.txt" 2>/dev/null)
- SDK: $(cat "$OUTDIR/sdk.txt" 2>/dev/null)
- SELinux: $(cat "$OUTDIR/selinux-context.txt" 2>/dev/null) $(cat "$OUTDIR/selinux-enforce.txt" 2>/dev/null)

## Key Symbols
\`\`\`
$(cat "$OUTDIR/key-symbols.txt" 2>/dev/null || echo "Not available")
\`\`\`

## Collection Info
- Date: $(date)
- Output: $OUTDIR
EOF

echo "[ionstack] done! Output at: $OUTDIR"
echo "[ionstack] files:"
ls -la "$OUTDIR/"
