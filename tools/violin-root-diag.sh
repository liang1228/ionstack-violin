#!/system/bin/sh
# violin-root-diag.sh — root 设备诊断 (处理 SELinux Enforcing)
# 用法: su -c "sh /sdcard/Download/violin-root-diag.sh"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
OUTDIR="$SCRIPT_DIR/violin-diag"
KREAD="$SCRIPT_DIR/kcore_read"
mkdir -p "$OUTDIR"

log() { echo "$@"; echo "$@" >> "$OUTDIR/diag.txt"; }

log "=== violin-root-diag $(date) ==="
log "boot_id: $(cat /proc/sys/kernel/random/boot_id)"
log "selinux: $(getenforce)"
log ""

# 关键: 临时关闭 SELinux + kptr_restrict, 才能读到真实地址
log "=== 临时提权 ==="
setenforce 0 2>/dev/null && log "selinux -> permissive (临时)" || log "setenforce 失败"
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null && log "kptr_restrict -> 0" || log "kptr_restrict 失败"
log ""

# 1. 关键符号
log "=== KEY SYMBOLS ==="
for sym in _text do_select core_sys_select __arm64_sys_pselect6 \
           selinux_enforcing_boot selinux_state init_cred init_task \
           misc_fops ashmem_fops configfs_read_iter configfs_bin_write_iter \
           anon_pipe_buf_ops sysctl_bootid worker_thread; do
    line=$(grep -w "$sym" /proc/kallsyms | head -1)
    [ -n "$line" ] && log "  $line"
done
log ""

# 2. do_select 二进制 dump
log "=== DO_SELECT DUMP ==="
DO_ADDR=$(grep -w do_select /proc/kallsyms | head -1 | awk '{print $1}')
log "do_select = 0x$DO_ADDR"
if [ -n "$DO_ADDR" ] && [ "$DO_ADDR" != "0000000000000000" ] && [ -x "$KREAD" ]; then
    $KREAD "0x$DO_ADDR" 4096 "$OUTDIR/do_select.bin" && \
        log "  dumped 4096 bytes to do_select.bin" || \
        log "  dump 失败"
else
    log "  跳过 (地址为0 或 kcore 不可读)"
fi
log ""

# 3. misc_fops dump
log "=== MISC_FOPS DUMP ==="
MISC=$(grep -w misc_fops /proc/kallsyms | head -1 | awk '{print $1}')
log "misc_fops = 0x$MISC"
if [ -n "$MISC" ] && [ "$MISC" != "0000000000000000" ] && [ -x "$KREAD" ]; then
    $KREAD "0x$MISC" 256 "$OUTDIR/misc_fops.bin" && \
        xxd "$OUTDIR/misc_fops.bin" | head -16 | while read l; do log "  $l"; done
fi
log ""

# 4. ashmem_fops dump
log "=== ASHMEM_FOPS DUMP ==="
ASHMEM=$(grep -w ashmem_fops /proc/kallsyms | head -1 | awk '{print $1}')
log "ashmem_fops = 0x$ASHMEM"
if [ -n "$ASHMEM" ] && [ "$ASHMEM" != "0000000000000000" ] && [ -x "$KREAD" ]; then
    $KREAD "0x$ASHMEM" 256 "$OUTDIR/ashmem_fops.bin" && \
        xxd "$OUTDIR/ashmem_fops.bin" | head -16 | while read l; do log "  $l"; done
fi
log ""

# 5. selinux_enforcing
log "=== SELINUX ==="
grep -i "selinux_enforc" /proc/kallsyms | while read line; do log "  $line"; done
log ""

# 6. 内核配置
log "=== KERNEL CONFIG ==="
zcat /proc/config.gz 2>/dev/null | grep -E "UBSAN_TRAP|CFI_CLANG|SHADOW_CALL|PANIC_ON_OOPS|DEBUG_SPINLOCK|LOCKDEP" | while read l; do log "  $l"; done
log ""

# 7. slabinfo
log "=== SLABINFO ==="
grep -i "filp\|kmalloc-2k" /proc/slabinfo | head -5 | while read l; do log "  $l"; done
log ""

# 恢复 SELinux
setenforce 1 2>/dev/null && log "selinux -> enforcing (已恢复)"
echo 1 > /proc/sys/kernel/kptr_restrict 2>/dev/null

log ""
log "=== DONE ==="
