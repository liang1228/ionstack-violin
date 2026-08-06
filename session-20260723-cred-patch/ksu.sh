#!/system/bin/sh
# KSU一键提权 — 在 aShellYou 中运行
# 用法: sh /data/local/tmp/ksu.sh

echo "========================================="
echo " KernelSU 一键提权"
echo "========================================="

# 1. 检查 preload.so
if [ ! -f /data/local/tmp/preload_jinghu.so ]; then
    echo "[!] 缺少 preload_jinghu.so"
    echo "[!] 请先通过 adb push 推送"
    exit 1
fi

# 2. 检查是否已 root
if su -c id 2>/dev/null | grep -q 'uid=0'; then
    echo "[✓] 已经是 root"
    su -c id
    echo "========================================="
    exit 0
fi

# 3. 运行 exploit
echo "[*] 提权中... (约30秒)"
LD_PRELOAD=/data/local/tmp/preload_jinghu.so /system/bin/true 2>/dev/null
sleep 2

# 4. 检查 KernelSU
if lsmod 2>/dev/null | grep -q kernelsu; then
    echo "[✓] KernelSU 模块已加载"
else
    echo "[✗] KernelSU 模块未加载"
fi

# 5. 检查 su
if su -c id 2>/dev/null | grep -q 'uid=0'; then
    echo "[✓] Root 成功!"
    su -c id
else
    echo "[*] 启动 su daemon..."
    setsid /data/local/tmp/su --daemon </dev/null >/dev/null 2>&1 &
    sleep 3
    if su -c id 2>/dev/null | grep -q 'uid=0'; then
        echo "[✓] Root 成功!"
        su -c id
    else
        echo "[✗] Root 失败"
    fi
fi

# 6. 恢复 Enforcing
if [ "$(getenforce)" = "Permissive" ]; then
    echo "[*] 恢复 Enforcing..."
    su -c 'echo 1 > /sys/fs/selinux/enforce' 2>/dev/null
    sleep 2
fi

echo ""
echo "========================================="
echo " 状态"
echo "========================================="
echo " Root:  $(su -c id 2>/dev/null || echo '无')"
echo " SELinux: $(getenforce)"
echo " Services: $(service list 2>/dev/null | wc -l)"
echo "========================================="
echo ""
echo " su -c '命令'  ← 随时获取 root"
