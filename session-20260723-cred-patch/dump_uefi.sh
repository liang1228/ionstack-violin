#!/system/bin/sh
# dump_uefi.sh — MT管理器运行 | su -c sh dump_uefi.sh
# 导出 UEFI/kCFI/SELinux 内核信息用于 kCFI bypass 研究

DIR="/sdcard/uefi_dump"
rm -rf "$DIR"
mkdir -p "$DIR"

echo "========================================="
echo " UEFI/kCFI Dump Tool"
echo "========================================="

# 宽容 SELinux
echo 0 > /sys/fs/selinux/enforce 2>/dev/null
echo "[*] SELinux: $(getenforce)"

# 1. 基础信息
echo "[1] 基础信息..."
uname -a > "$DIR/uname.txt"
cat /proc/version > "$DIR/version.txt"
getprop ro.build.display.id > "$DIR/build_id.txt"
getprop ro.product.model > "$DIR/model.txt"
cat /proc/config.gz 2>/dev/null | gunzip > "$DIR/config.txt" 2>/dev/null

# 2. kCFI 配置
echo "[2] kCFI 配置..."
grep -iE "CONFIG_CFI|CONFIG_SHADOW_CALL" "$DIR/config.txt" > "$DIR/kcfi.txt" 2>/dev/null
cat "$DIR/kcfi.txt"

# 3. 关键内核符号
echo "[3] 关键符号..."
grep -E "selinux_state |selinux_enforcing|init_cred |_text$|_stext$|misc_fops |ashmem_fops |ashmem_misc |configfs_bin_write|anon_pipe_buf|efi_runtime|efi_call" /proc/kallsyms > "$DIR/key_syms.txt"
wc -l < "$DIR/key_syms.txt"
echo "  保存到 key_syms.txt"

# 4. UEFI 信息
echo "[4] UEFI..."
mkdir -p "$DIR/efi"
ls -la /sys/firmware/efi/ > "$DIR/efi/dir.txt" 2>&1
cat /sys/firmware/efi/fw_platform_size > "$DIR/efi/platform_size.txt" 2>&1
cat /sys/firmware/efi/systab > "$DIR/efi/systab.txt" 2>&1
ls -laR /sys/firmware/efi/runtime-map/ > "$DIR/efi/runtime_map.txt" 2>&1

# 5. 内存布局
echo "[5] 内存布局..."
cat /proc/iomem > "$DIR/iomem.txt" 2>&1
cat /proc/vmallocinfo > "$DIR/vmallocinfo.txt" 2>&1

# 6. SELinux
echo "[6] SELinux..."
getenforce > "$DIR/enforce.txt"
cat /sys/fs/selinux/enforce > "$DIR/enforce_sysfs.txt" 2>&1

# 7. fops/misc
echo "[7] fops 符号..."
grep -E "misc_fops |ashmem|configfs_bin|anon_pipe" /proc/kallsyms > "$DIR/fops.txt"
cat "$DIR/fops.txt"

# 8. 模块
echo "[8] 内核模块..."
cat /proc/modules > "$DIR/modules.txt" 2>&1

# 9. 全部 kallsyms（可选，文件较大）
echo "[9] kallsyms 完整导出..."
cat /proc/kallsyms > "$DIR/kallsyms_full.txt"

# 打包
echo ""
echo "========================================="
echo " 打包中..."
echo "========================================="
cd /sdcard
tar czf uefi_dump.tar.gz uefi_dump/ 2>&1
ls -lh uefi_dump.tar.gz

echo ""
echo "========================================="
echo " 完成！"
echo " 文件: /sdcard/uefi_dump.tar.gz"
echo " 请通过云盘分享"
echo "========================================="
