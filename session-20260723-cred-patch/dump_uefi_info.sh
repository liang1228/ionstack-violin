#!/system/bin/sh
# dump_uefi_info.sh — 导出 UEFI/kCFI 相关内核信息
# 在已 root 的 violin 设备上以 root 身份运行
# 保存到 /data/local/tmp/uefi_dump/

OUTDIR="/data/local/tmp/uefi_dump"
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

echo "[*] 输出目录: $OUTDIR"
echo "[*] 当前 uid: $(id)"

# ========== 1. 内核基础信息 ==========
echo "[1/10] 内核信息..."
uname -a > "$OUTDIR/uname.txt"
cat /proc/version > "$OUTDIR/version.txt"
cat /proc/config.gz 2>/dev/null | gunzip > "$OUTDIR/config.txt" 2>/dev/null

# ========== 2. kCFI 相关配置 ==========
echo "[2/10] kCFI 配置..."
grep -i "cfi\|kcfi\|shadow_call" "$OUTDIR/config.txt" > "$OUTDIR/kcfi_config.txt" 2>/dev/null

# ========== 3. UEFI 相关内核符号 ==========
echo "[3/10] UEFI 内核符号..."
cat /proc/kallsyms | grep -i "efi\|uefi\|runtime_services\|efi_rt\|efi_call" > "$OUTDIR/efi_symbols.txt"
cat /proc/kallsyms | grep -i "selinux_enforcing\|selinux_state" >> "$OUTDIR/efi_symbols.txt"

# ========== 4. UEFI firmware 信息 ==========
echo "[4/10] UEFI firmware..."
mkdir -p "$OUTDIR/efi"
cat /sys/firmware/efi/fw_platform_size 2>/dev/null > "$OUTDIR/efi/fw_platform_size.txt"
cat /sys/firmware/efi/systab 2>/dev/null > "$OUTDIR/efi/systab.txt"
ls -la /sys/firmware/efi/ > "$OUTDIR/efi/efi_dir.txt" 2>&1
ls -laR /sys/firmware/efi/runtime-map/ > "$OUTDIR/efi/runtime_map.txt" 2>&1
ls -la /sys/firmware/efi/efivars/ > "$OUTDIR/efi/efivars.txt" 2>&1

# ========== 5. 内核内存布局 ==========
echo "[5/10] 内存布局..."
cat /proc/iomem > "$OUTDIR/iomem.txt" 2>&1
cat /proc/vmallocinfo > "$OUTDIR/vmallocinfo.txt" 2>&1

# ========== 6. 关键结构体地址 ==========
echo "[6/10] 关键地址..."
cat /proc/kallsyms | grep -E "selinux_state$|selinux_enforcing|init_cred$|_text$|_stext$|_etext$|init_task$" > "$OUTDIR/key_addresses.txt"

# ========== 7. SELinux 状态 ==========
echo "[7/10] SELinux 状态..."
getenforce > "$OUTDIR/selinux_enforce.txt"
cat /sys/fs/selinux/enforce > "$OUTDIR/selinux_enforce_sysfs.txt" 2>&1
cat /sys/fs/selinux/policy > "$OUTDIR/selinux_policy.bin" 2>&1
ls -la /sys/fs/selinux/ > "$OUTDIR/selinux_dir.txt" 2>&1

# ========== 8. fops 相关符号 ==========
echo "[8/10] fops 符号..."
cat /proc/kallsyms | grep -E "ashmem_misc|ashmem_fops|configfs_bin_write|misc_fops|anon_pipe_buf" > "$OUTDIR/fops_symbols.txt"

# ========== 9. 任务结构体布局信息 ==========
echo "[9/10] 任务结构体..."
cat /proc/kallsyms | grep -E "init_task|comm_offset|cred_offset" > "$OUTDIR/task_struct_info.txt"

# ========== 10. 内核模块信息 ==========
echo "[10/10] 内核模块..."
lsmod > "$OUTDIR/lsmod.txt" 2>&1
cat /proc/modules > "$OUTDIR/modules.txt" 2>&1

# ========== 完成 ==========
echo ""
echo "[✓] 导出完成！"
echo "[✓] 保存位置: $OUTDIR"
echo ""
ls -la "$OUTDIR/"
echo ""
echo "[i] 请将 $OUTDIR 目录打包分享"
echo "[i] 命令: cd /data/local/tmp && tar czf uefi_dump.tar.gz uefi_dump/"
