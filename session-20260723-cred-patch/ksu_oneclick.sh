#!/system/bin/sh
# ksu_oneclick.sh — 一键 KernelSU 提权 + 恢复 Enforcing
#
# 用法:
#   adb push ksu_oneclick.sh /data/local/tmp/
#   adb shell sh /data/local/tmp/ksu_oneclick.sh
#
# 功能:
#   1. 用 preload_jinghu.so 获取 root + 加载 KernelSU ko
#   2. 恢复 SELinux Enforcing
#   3. 验证 root + framework + app
#   4. 输出结果

LOG=/data/local/tmp/ksu.log

echo "[1/4] 提权中..."
LD_PRELOAD=/data/local/tmp/preload_jinghu.so /system/bin/true >"$LOG" 2>&1
KO=$(grep -c 'module_loaded=1' "$LOG")
echo "    ko=$KO"

echo "[2/4] 恢复 Enforcing..."
echo 1 > /sys/fs/selinux/enforce
sleep 2
EN=$(cat /sys/fs/selinux/enforce)
echo "    enforce=$EN"

echo "[3/4] 验证..."
ROOT=$(su -c id 2>&1 | grep -c 'uid=0')
SVC=$(service list 2>/dev/null | wc -l)
echo "    root=$ROOT services=$SVC"

echo "[4/4] 完成"
echo ""
echo "========================================="
echo " KernelSU: ko=$KO"
echo " SELinux:  $EN"
echo " Root:     $ROOT"
echo " Services: $SVC"
echo "========================================="

if [ "$ROOT" = "1" ]; then
    echo ""
    echo "su -c '你的命令'  ← 随时获取 root"
fi
