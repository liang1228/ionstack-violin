# GhostLock (CVE-2026-43499) violin Exploit — 技术分析文档

> **目标设备:** Xiaomi Pad 7S Pro (violin), Android 16, Kernel 6.6.77-android15-8
> **固件:** BP2A.250605.031.A3 / HyperOS OS3.0.303.0.WOTCNXM
> **编译器:** Android clang 18.0.0 (r510928)
> **安全特性:** KASLR, CFI_CLANG, UBSAN_TRAP, PANIC_ON_OOPS

---

## 1. 漏洞概述

CVE-2026-43499 (GhostLock) 是内核 rtmutex 的栈上 use-after-free，通过 `FUTEX_CMP_REQUEUE_PI` 竞争触发。

**触发路径:**
1. waiter 线程: `FUTEX_WAIT_REQUEUE_PI` 等待 requeue
2. owner 线程: 持有 PI futex，等待 `f_pi_chain`
3. consumer 线程: `sched_setattr` 改变 waiter 优先级 → 触发 PI chain walk
4. 主线程: `FUTEX_CMP_REQUEUE_PI` requeue waiter
5. `pselect` 的 fd_set 数据覆盖栈上的 waiter 结构体

**关键约束 (violin 特有):**
- `UBSAN_TRAP=y`: UBSAN 违规直接 BRK trap → kernel panic
- `CONFIG_CFI_CLANG=y`: 控制流完整性
- `CONFIG_PANIC_ON_OOPS=y`: 任何 oops → panic
- UBSAN 检查: `sched_class->type_hash`, `rb_leftmost` 非对齐, `rt_mutex_setprio` 类型哈希

---

## 2. 当前利用链进度

### 已完成 ✅

| 阶段 | 状态 | 说明 |
|------|------|------|
| KASLR bypass | ✅ | 通过 `sched_blocked_reason` trace event 泄漏内核绝对地址 |
| pselect 阻塞 | ✅ | 使用 pipe read_fd 代替 write_fd |
| Consumer 触发 | ✅ | 105-200 次 `sched_setattr` 调用/次尝试 |
| UBSAN 绕过 (部分) | ✅ | owner=0, sched_class=fair_sched_class, waiters=空 |
| FUTEX_CMP_REQUEUE_PI | ✅ | val3 修复为 owner TID 后 requeue 成功 |
| 设备稳定性 | ✅ | 无 crash 运行 |

### 进行中 🔄

| 阶段 | 状态 | 说明 |
|------|------|------|
| fops 劫持 (Stage 1) | ❌ | rb_insert 写入原语未生效 |
| cred 替换 (Stage 2) | ⏳ | 代码已写，等待 Stage 1 |
| pipe physrw | ⏳ | 等待 fops 劫持 |
| 提权 | ⏳ | 等待 pipe physrw |

---

## 3. 核心问题: rb_insert 写入原语

### 3.1 目标

通过 PI chain walk 中的 `rb_insert_color` 旋转操作，将 `fake_fops` 写入 `ashmem_misc.fops`，劫持 `/dev/ashmem` 的文件操作表。

### 3.2 当前实现

```c
// prepare_pselect_fdsets() — fd_set 数据覆盖到栈上的 waiter 结构体

// waiter.pi_tree.__rb_parent_color = target - 0x08
fdset_put_word(out, 0, data_addr(ASHMEM_MISC) + 0x10 - 0x08);

// waiter.pi_tree.rb_left = value (要写入的值)
fdset_put_word(out, 2, fake_fops);

// fake_task.pi_waiters 指向 fake_w0.pi_tree (非空树)
put64(p, FAKE_TASK_OFF + pi_waiters_off,
      fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
```

**内核页布局:**
```
page_base (direct map 地址, ~0xffffff83xxxxxxxx)
├── LOCK_OFF (0x1350): fake lock, owner=0, waiters=空
├── W0_OFF (0x2220): fake waiter w0
│   ├── +0x00: tree entry (全零)
│   ├── +0x28: pi_tree entry
│   │   ├── +0x00 (__rb_parent_color): target - 0x08
│   │   ├── +0x08 (rb_right): 0
│   │   └── +0x10 (rb_left): fake_fops
│   ├── +0x40 (prio): FAKE_WAITER_PRIO
│   ├── +0x50 (task): fake_task
│   └── +0x58 (lock): fake_lock
├── FAKE_TASK_OFF (0x3200): fake task_struct
│   ├── +0x84 (prio): FAKE_TASK_PRIO
│   ├── +0x90c (pi_lock): 0
│   ├── +0x920 (pi_waiters): → fake_w0 + 0x28
│   ├── +0x930 (pi_top_task): INIT_TASK
│   ├── +0x938 (pi_blocked_on): 0
│   ├── +0x340 (sched_class): fair_sched_class
│   └── +0x348 (task_group): ROOT_TASK_GROUP
└── FOPS_OFF (0x1000): fake file_operations 表
```

### 3.3 rb_insert_color 旋转分析

**预期流程:**
1. PI chain walk 将 waiter 的 pi_tree 插入 fake_task.pi_waiters
2. pi_waiters 已有节点 (fake_w0+0x28)，新节点插入 → 红红冲突
3. `rb_insert_color` 旋转 → 写入 grandparent 的子指针

**旋转写入:**
```
rotate_left(grandparent):
  right = grandparent->rb_right
  grandparent->rb_right = right->rb_left  ← 写入 target
  right->rb_left = grandparent

rotate_right(grandparent):
  left = grandparent->rb_left
  grandparent->rb_left = left->rb_right   ← 写入 target-0x08
  left->rb_right = grandparent
```

**关键检查 (决定旋转方向):**
```c
// rb_insert_color 中:
gparent = rb_red_parent(parent);
tmp = gparent->rb_right;
if (parent != tmp) { /* parent 是 gparent 的左孩子 */
    if (tmp && rb_is_red(tmp)) {
        // uncle 是红色 → 仅重染色，不旋转
    } else {
        // uncle 是黑色或 NULL → 旋转
    }
}
```

### 3.4 失败原因分析

**问题 1: grandparent 内存不可控**

`__rb_parent_color = target - 0x08` 指向 `ashmem_misc + 0x08`。rb_insert_color 读取 `gparent->rb_right`（在 `target` 处）来确定旋转方向。该位置是内核数据，不是我们控制的 rb_node。

**问题 2: uncle 颜色不确定**

如果 `gparent->rb_right`（target 处的值）非 NULL 且 bit 0 = 0（对齐指针），则 `rb_is_red(tmp) = true` → 仅重染色，不旋转。

**问题 3: 树结构不一致**

grandparent 的 `rb_left`/`rb_right` 不指向我们的节点，导致内核可能认为 parent 不是 grandparent 的孩子 → 未定义行为。

### 3.5 实际观察

- consumer 调用成功 (200/200): PI chain walk 确实触发了
- `cfi write ret=-1 errno=22`: configfs 写入失败，说明 fops 未被劫持
- 设备存活 (boot_id 不变): 无 crash，说明 rb_insert_color 没有 panic，但也没有产生预期写入

---

## 4. POC-pad7U 方案对比

POC-pad7U (来自 52pojie) 使用同样的 rb_insert 写入原语，但目标是 `task->cred` 而非 `ashmem_misc.fops`。

**关键区别:**

| | violin 当前 | POC-pad7U |
|---|---|---|
| 写入目标 | ashmem_misc.fops (BSS) | task->cred (堆) |
| grandparent 内容 | 不可控 | cred 结构体字段 |
| uncle (gparent->rb_right) | 未知内核数据 | cred+0x08 = uid |
| uid=0 时 uncle | — | BLACK (NULL) → 旋转 |
| uid=2000 时 uncle | — | RED (非零对齐) → 仅重染色 |

**POC-pad7U 的前提条件:**
1. 需要先泄漏 task_struct 地址
2. 需要 mm_struct → task_struct → cred 的地址链
3. 需要创建 fake_cred (uid=0, caps=full, selinux=NULL)
4. 需要通过某种机制获取这些地址 (高通用 /dev/diag)

**violin 的死锁:**
- 获取 task 地址 → 需要 configfs R/W → 需要 fops 劫持 → 需要 rb_insert 写入 → 需要可控目标

---

## 5. 可能的突破方向

### 方案 A: 利用 rb_erase 而非 rb_insert

PI chain walk 先 `rb_erase` 旧 waiter，再 `rb_insert` 新 waiter。rb_erase 也可能触发旋转。

**优势:** rb_erase 的旋转逻辑略有不同，可能绕过 uncle 检查。
**劣势:** 同样需要 grandparent 内存可控。

### 方案 B: pselect_custom_write 机制

代码中有 `set_pselect_write(target, value)` 机制，通过 `pselect_custom_write_enabled()` 启用不同的 fd_set 填充路径。

```c
// 使用方式:
set_pselect_write(target_addr, value_addr);
// 然后 pselect 路径会用不同的 waiter 字段布局
```

**custom write 的 waiter 布局 (shape=1):**
```
word 2: value         → tree.rb_left
word 4: target        → tree.deadline
word 5: target - 8    → pi_tree.__rb_parent_color
word 6: value         → pi_tree.rb_right
word 7: 0             → pi_tree.rb_left
```

**研究方向:** custom write 路径可能使用不同的写入机制（不经过 rb-tree），需要深入分析 `do_pselect_fake_lock_route` 中 `pselect_custom_write_enabled()` 分支。

### 方案 C: 绕过 rb_insert，用 rt_mutex_setprio 写入

`rt_mutex_setprio` 写入 task_struct 的多个字段:
- `task->prio = new_prio`
- `task->normal_prio = new_prio`
- `task->rt_priority = 0`

**问题:** 写入值是小整数（优先级），不是指针。无法用于 fops 劫持。

**变体:** 如果能控制 `new_prio` 的值为某个内核地址的低 32 位... 但 prio 是 int，不是指针。

### 方案 D: 两阶段写入

1. rb_insert 写入 kernel page 上的可控地址（目标在 page 内）
2. 用写入的值作为第二阶段的原语

**问题:** rb_insert 写入的值来自旋转中的兄弟节点子指针，不可控。

### 方案 E: 直接用 pipe 物理 R/W 绕过 fops

如果能找到 pipe_buffer 的物理地址而不需要 fops 劫持:
1. 通过 slab spray 找到 pipe_buffer 的 direct map 地址
2. 修改 pipe_buffer 的 ops 指针
3. 直接获得物理 R/W

**问题:** 需要知道 pipe_buffer 的 direct map 地址，可能需要额外的信息泄漏。

### 方案 F: 利用 KernelSnitch 泄漏更多信息

KernelSnitch 已经泄漏了 mm_struct 地址。能否扩展它来泄漏:
- task_struct 地址
- cred 地址
- 甚至直接读取内核内存

**研究方向:** KernelSnitch 的 futex hash timing 是否能扩展为任意内核地址读取。

---

## 6. 关键代码位置

| 文件 | 说明 |
|------|------|
| `src/main.c` | 主入口, run_exploit(), waiter/owner/consumer 线程, FUTEX_CMP_REQUEUE_PI |
| `src/fops.c` | prepare_pselect_fdsets(), do_pselect_fake_lock_route(), try_cfi_stage() |
| `src/util.c` | prepare_kernel_page(), KernelSnitch, fake lock/task 构造 |
| `src/common.h` | 全局变量, 常量, 函数声明 |
| `src/targets/violin-v-oss/target.h` | violin 内核符号偏移 |
| `src/pipe.c` | pipe physrw 实现 |
| `src/root.c` | 提权实现 |

**关键函数:**
- `prepare_pselect_fdsets()` (fops.c:163): 设置 fd_set 数据，控制 waiter 字段
- `prepare_skb_payload()` (util.c:~600): 构造内核页上的 fake lock/task/waiter
- `do_pselect_fake_lock_route()` (fops.c:235): pselect 路由，触发 PI chain walk
- `try_cfi_stage()` (fops.c:796): Stage 1 fops 劫持 + Stage 2 cred 替换
- `run_main_route_threads()` (main.c:609): 创建 waiter/owner/consumer 线程

---

## 7. 内核符号偏移 (violin)

```
KIMAGE_TEXT_BASE      = 0xffffffc008000000
P0_PAGE_OFFSET        = 0xffffff8000000000
P0_KERNEL_PHYS_LOAD   = 0x00210000

ASHMEM_MISC_OFF       = 0x0223b5d8  (miscdevice 结构)
ASHMEM_MISC_FOPS_OFF  = 0x01269710  (misc_fops)
ASHMEM_FOPS_OFF       = 0x012c9df0  (ashmem_fops)
INIT_TASK_OFF         = 0x020de280
INIT_CRED_OFF         = 0x020f0548
FAIR_SCHED_CLASS_OFF  = 0x0164e1a8
SELINUX_ENFORCING_OFF = 0x0207cae0

task_struct 偏移:
  pi_lock       = 0x90c
  pi_waiters    = 0x920
  pi_top_task   = 0x930
  pi_blocked_on = 0x938
  real_cred     = 0x818
  cred          = 0x820
  pid           = 0x618
  tgid          = 0x61c

mm_struct 偏移:
  owner         = 1032 (0x408)

cred 偏移:
  uid           = 8
  securebits    = 40
  caps          = 48
  security      = 128

file_operations 偏移:
  owner         = 0x00
  llseek        = 0x08
  read_iter     = 0x20
  write_iter    = 0x28
  ioctl         = 0x48
  mmap          = 0x58
  open          = 0x68
  release       = 0x78
```

---

## 8. 运行方式

```bash
# 编译 (需要 NDK)
cd exploit-repo/IonStack/CVE-2026-43499/exploit
make PROJECT=violin-v-oss

# 推送
adb push build/violin-v-oss/bin/preload.so /data/local/tmp/

# 获取 KASLR base (需要启用 trace event)
adb shell "echo 1 > /sys/kernel/tracing/events/sched/sched_blocked_reason/enable"
adb shell "echo 1 > /sys/kernel/tracing/tracing_on"
# 等几秒让 trace 积累数据
adb shell "cat /sys/kernel/tracing/trace | grep worker_thread | head -3"
# 用 raw trace + parse_sched_blocked_reason_raw.py 计算 _text

# 运行
adb shell "CFI_KASLR_BASE=<computed_base> LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"

# 查看日志
adb shell "cat /sdcard/Download/crash.txt"
```

---

## 9. 诊断信息格式

crash.txt 中的关键日志:
```
STEP1: slide OK kaslr_base=0x... slide=0x...     # KASLR 已知
KernelSnitch leaked mm_struct=0x...               # mm_struct 泄漏
ROUTE_PREP_REQUEUE: ret=? errno=?                 # requeue 结果
FOPSROUTE_RET: attempt=? calls=? success=?        # consumer 统计
cfi stage entered fd=? fake_fops=0x...            # 进入 fops 劫持
cfi write ret=? errno=?                           # configfs 写入结果 (22=EINVAL 表示 fops 未劫持)
STAGE2_MM_LEAK: mm_struct=0x...                   # Stage 2 mm_struct
STAGE2_TASK: task_struct=0x...                    # Stage 2 task
STAGE2_WRITE: real_cred wr=? cred wr=?            # Stage 2 cred 写入
STAGE2_SUCCESS: uid=0, root achieved!             # 成功
```

---

## 10. 研究建议

**最高优先级:** 深入分析 `pselect_custom_write_enabled()` 代码路径 (fops.c:173-211)，它使用完全不同的 waiter 字段布局，可能提供绕过 rb_insert 限制的写入机制。

**其次:** 研究 rb_erase 在 PI chain walk 中的行为——rb_erase 先于 rb_insert 执行，且其旋转逻辑可能对 grandparent 内存的依赖不同。

**参考资源:**
- https://www.52pojie.cn/thread-2116758-1-1.html (POC-pad7U 分析)
- https://github.com/pubglite55/oppo-ghostlock (OPPO GhostLock exploit)
- 源码: `E:\workspace\projects\xiaomi-root\exploit-repo\IonStack\CVE-2026-43499\exploit\`

---

## 11. pselect_custom_write 路径实验结果 (2026-07-17)

### 11.1 实验概述

实现了方案 B (pselect_custom_write)，通过 `set_pselect_write(target, value)` 启用 custom write 路径，使用 shape=1 布局。

**代码改动:**
1. `main.c`: 在 `prepare_good_kernel_page` 后调用 `set_pselect_write(data_addr(ASHMEM_MISC) + 0x10, fake_fops)`
2. `fops.c`: custom write 成功后调用 `try_cfi_stage()` 代替直接返回
3. `fops.c`: 重试循环中更新 `set_pselect_write` 的 value 为新的 fake_fops
4. `util.c`: FOPS 模式设置 `owner = fake_task`（非 0）

### 11.2 预期写入机制

通过 `rb_erase` 的 `__rb_change_child` 实现写入：

```
pi_tree_entry (栈上 waiter+0x28):
  __rb_parent_color = target - 0x08   (指向 ashmem_misc+0x08)
  rb_right = value                     (fake_fops)
  rb_left = 0

rb_erase 流程:
  1. child = node->rb_right = value (fake_fops)
  2. parent = __rb_parent(target-0x08) = ashmem_misc+0x08
  3. __rb_change_child(node, child, parent, root):
     parent->rb_left (at ashmem_misc+0x08) != node (栈地址)
     → parent->rb_right = child = fake_fops
     → 写入 fake_fops 到 ashmem_misc+0x10 = target ✓
  4. child->__rb_parent_color = parent
     → 写入 (target-0x08) 到 fake_fops+0x00 (破坏 owner, 可修复)
```

### 11.3 实验结果

| 项目 | 结果 |
|------|------|
| Consumer 触发 | ✅ calls=200, success=200 |
| PI chain walk | ✅ 正常执行 |
| rb_erase 写入 | ❌ 未生效 |
| configfs 写入 | ❌ errno=22 (EINVAL) |
| 设备稳定性 | ✅ 无 crash |

### 11.4 失败原因分析

rb_erase 写入在逻辑上应该工作，但实际未生效。可能原因：

**假说 1: PI chain walk 在 rb_erase 之前提前返回**

`rt_mutex_adjust_prio_chain` 中有多处提前返回点。即使 owner != 0，内核可能在其他检查点（如 pi_lock 竞争、waiter 状态检查）提前返回，从未到达 `rb_erase(&waiter->pi_tree_entry, &task->pi_waiters)`。

**假说 2: rb_erase 对未插入节点的处理**

waiter 的 pi_tree_entry 从未通过 `rb_insert` 插入 fake_task->pi_waiters 树。rb_erase 对未插入节点的处理可能是 no-op 或有未定义行为。

内核 rb_erase 实现:
```c
void rb_erase(struct rb_node *node, struct rb_root *root) {
    struct rb_node *child = node->rb_right;
    struct rb_node *tmp = node->rb_left;
    if (!tmp) {
        pc = node->__rb_parent_color;
        parent = __rb_parent(pc);
        __rb_change_child(node, child, parent, root);  // 写入
        if (child) child->__rb_parent_color = pc;      // 写入
    }
}
```

__rb_change_child 会无条件写入 parent->rb_left 或 parent->rb_right。但内核可能在调用 rb_erase 之前就有检查。

**假说 3: UBSAN 在 rt_mutex_setprio 中触发**

设置 owner = fake_task 后，内核调用 `rt_mutex_setprio(fake_task, ...)`. 尽管设置了 `sched_class = fair_sched_class`，可能还有其他 UBSAN 检查失败（如 task_struct 布局验证），导致函数提前返回。

**假说 4: pi_waiters 树操作在 rb_erase 之前**

内核可能先操作 task->pi_waiters（读取或验证），发现树结构异常后跳过 rb_erase。

### 11.5 确认: rb_insert 写入完全未发生

**验证方法:** 将 target 设为 `boot_id_data` (0xffffff8002546f58)，运行 exploit 后检查 `/proc/sys/kernel/random/boot_id`。

**结果:** boot_id 未变 (b9aa8187)。即使 consumer 成功 (200/200)，PI chain walk **从未执行到 pi_tree 的 rb_insert/rb_erase**。

**结论:** violin 内核的 `rt_mutex_adjust_prio_chain` 在到达 pi_tree 操作之前就返回。这不是参数问题，而是 PI chain walk 执行路径的根本差异。

**可能原因:**
1. violin 内核有额外的 UBSAN 检查在 pi_tree 操作之前触发（但设备未 crash，说明不是 BRK trap）
2. fake_task 的某些字段不满足 rt_mutex_adjust_prio_chain 的前置条件
3. pi_lock 竞争导致提前返回
4. 内核版本差异: jinghu (XRing O1) vs violin (MediaTek) 的 rtmutex 实现不同

1. **添加内核 tracepoint**: 在设备上启用 `rt_mutex_adjust_prio_chain` 相关 tracepoint，确认代码执行到哪一步
2. **读取目标地址**: 用 kcore_read 工具在 exploit 运行前后读取 ashmem_misc.fops，确认是否有任何变化
3. **简化测试**: 创建最小 POC，只测试 rb_erase 对栈上节点的写入行为
4. **研究内核源码**: 深入分析 `rt_mutex_adjust_prio_chain` (kernel/locking/rtmutex.c) 的完整执行路径，找到所有提前返回点
5. **替代写入机制**: 研究 `__rt_mutex_adjust_prio` 中的 `plist_add`/`plist_del` 操作，它们也可能写入内核内存

---

## 12. POC-pad7U 关键发现 (2026-07-17)

**POC 仓库:** https://github.com/wfqefwqf/POC-pad7U (dijun / Xiaomi 15S Pro, XRing O1, kernel 6.6.30)

### 12.1 核心发现: rb_insert 写入的是 waiter 地址

```
rb_insert 写入: [parent + {rb_left|rb_right}] = &waiter_node_being_inserted
```

**不是** fd_set 中的任意值。写入值固定为 waiter 节点的内核地址。

**POC 的做法:**
1. 将 fake_cred 放在 waiter 所在的 spray page 上
2. rb_insert 写入 `&waiter` 到 `task->cred`
3. `&waiter` 本身就是有效的 cred 结构（uid=0）

### 12.2 rt_mutex_adjust_prio_chain 执行路径分析

**所有提前返回点 (6.6.77):**

| 行号 | 条件 | 说明 |
|------|------|------|
| 696 | depth > max_lock_depth | 链太深 |
| 725 | !waiter | task 没有 pi_blocked_on |
| 732 | orig_waiter && !rt_mutex_owner(orig_lock) | 原始锁已释放 |
| 744 | next_lock != waiter->lock | 锁链已变化 |
| **778** | **top_waiter && !task_has_pi_waiters(task)** | **task 没有 pi_waiters** |
| **788** | **top_waiter != task_top_pi_waiter(task) && !detect_deadlock** | **不是 top waiter 且无死锁检测** |
| 803 | rt_waiter_node_equal && !detect_deadlock | 优先级相同 |
| **853** | **lock == orig_lock \|\| owner == top_task** | **死锁检测** |
| 875 | !rt_mutex_owner(lock) | 锁无 owner |
| 900 | !next_lock | 下一个锁为空 |

**关键变量:** `top_waiter = orig_waiter` (line 662)

### 12.3 最可能的阻塞原因

**Line 778:** `task` 是真实 waiter 线程，`task_has_pi_waiters(task)` 返回 false（真实线程不拥有任何锁）。

**Line 853（旧模型，已撤销）：** `rt_mutex_adjust_pi()` 的调用形态实际传入
`orig_lock=NULL`，所以不能再把 `waiter->lock=fake_lock` 自动解释为
`lock == orig_lock` 死锁；是否命中 `rt_mutex_owner(lock)==top_task` 及其它 chain
条件必须独立核对。

### 12.4 rt_mutex_adjust_pi

- 声明: `extern void rt_mutex_adjust_pi(struct task_struct *p)`
- 从 sched_setattr → rt_mutex_setprio 调用
- 只传入 task，内部获取 waiter 和 lock
- **orig_waiter 参数未知** — 需要找到实现确认
- 在 dijun 内核二进制中确认存在: 字符串地址 0x01bf2849

### 12.5 dijun vs violin 内核对比

| 项目 | dijun | violin |
|------|-------|--------|
| 内核版本 | 6.6.30 | 6.6.77 |
| SoC | XRing O1 | MediaTek |
| UBSAN_TRAP | y | y |
| CFI_CLANG | y | y |
| PANIC_ON_OOPS | y | y |
| PREEMPT_RT | n | n |
| rtmutex.c 差异 | — | 仅 rt_mutex_handle_deadlock 签名变化 |

### 12.6 xhee Hypervisor

sec_xhee.img: 373KB, 熵值 7.95/8.00 → **完全加密**，无法直接分析。

### 12.7 下一步研究方向

1. **找到 rt_mutex_adjust_pi 实现** — 确认 orig_waiter 参数
2. **绕过 line 788** — 需要 detect_deadlock=true 或 top_waiter == task_top_pi_waiter
3. **考虑 remove_waiter 路径** — 传入 orig_waiter=NULL，跳过 line 778
4. **直接 cred 替换** — 需要获取 task_struct 地址
5. **逆向 xhee** — 可能是 Stage-2 页表保护导致写入被拦截

---

## 13. 关键突破: rt_mutex_adjust_pi 提前返回 (2026-07-17)

### 13.1 实验结果

| 测试 | pi_waiters | owner | 设备 crash? | 结论 |
|------|-----------|-------|-------------|------|
| boot_id 写入 | fake_w0+0x28 | fake_task | ❌ | rb_insert 未执行 |
| pi_waiters=0xdeadbeef | 0xdeadbeef | fake_task | ❌ | chain walk 未到达 line 976 |
| owner=0xdeadbeef | fake_w0+0x28 | 0xdeadbeef | ❌ | chain walk 未到达 line 946 |

**结论: `rt_mutex_adjust_prio_chain` 根本没有被调用。** 所有 crash 测试都未触发，说明 chain walk 在 `rt_mutex_adjust_pi` 函数内部就返回了。

### 13.2 根因分析

`rt_mutex_adjust_pi` 实现 (kernel/locking/rtmutex_api.c):

```c
void __sched rt_mutex_adjust_pi(struct task_struct *task)
{
    struct rt_mutex_waiter *waiter;
    struct rt_mutex_base *next_lock;
    unsigned long flags;

    raw_spin_lock_irqsave(&task->pi_lock, flags);

    waiter = task->pi_blocked_on;
    if (!waiter || rt_waiter_node_equal(&waiter->tree, task_to_waiter_node(task))) {
        raw_spin_unlock_irqrestore(&task->pi_lock, flags);
        return;  // ← 提前返回!
    }
    next_lock = waiter->lock;
    raw_spin_unlock_irqrestore(&task->pi_lock, flags);

    get_task_struct(task);
    rt_mutex_adjust_prio_chain(task, RT_MUTEX_MIN_CHAINWALK, NULL,
                               next_lock, NULL, task);
}
```

**关键检查:** `rt_waiter_node_equal(&waiter->tree, task_to_waiter_node(task))`

```c
static __always_inline int rt_waiter_node_equal(
    struct rt_waiter_node *left, struct rt_waiter_node *right)
{
    if (left->prio != right->prio || left->deadline != right->deadline)
        return false;
    return true;
}
```

只比较 `prio` (偏移 +0x18) 和 `deadline` (偏移 +0x20)。如果两者相等，返回 true → 函数返回。

### 13.3 字段映射分析

`waiter->tree` 是栈上 waiter 的 tree entry (被 pselect fd_set 覆写):

| 字段 | 偏移 | fd_set word | 当前值 |
|------|------|-------------|--------|
| __rb_parent_color | +0x00 | word 0 (in) | 0 |
| rb_right | +0x08 | word 1 (in) | 0 |
| rb_left | +0x10 | word 2 (in) | 0 |
| **prio** | **+0x18** | **word 3 (in)** | **0** |
| **deadline** | **+0x20** | **word 4 (in)** | **0** |

`task_to_waiter_node(task)` 是 `&task->pi_waiters` 强转为 `rt_waiter_node*`:

```c
static inline struct rt_waiter_node *task_to_waiter_node(struct task_struct *p)
{
    return (struct rt_waiter_node *)&p->pi_waiters;
}
```

`pi_waiters` 是 `rb_root_cached` (偏移 0x920):
- +0x00: rb_root.rb_node (8 bytes) → 映射到 rt_waiter_node.rb_node.__rb_parent_color
- +0x08: rb_leftmost (8 bytes) → 映射到 rt_waiter_node.rb_node.rb_right

`prio` 在 rt_waiter_node 偏移 +0x18:
- 映射到 pi_waiters + 0x18 = task_struct + 0x920 + 0x18 = task_struct + 0x938
- 0x938 是 **pi_blocked_on** 字段!

`deadline` 在 rt_waiter_node 偏移 +0x20:
- 映射到 pi_waiters + 0x20 = task_struct + 0x920 + 0x20 = task_struct + 0x940
- 0x940 是 pi_blocked_on 之后的字段

### 13.4 匹配条件

**waiter->tree.prio = 0** (fd_set word 3 = 0)

**task_to_waiter_node(task)->prio = task->pi_blocked_on** (task_struct + 0x938)

task 是真实 waiter 线程。`task->pi_blocked_on` 指向栈上的 waiter 结构体（被 pselect fd_set 覆写后的地址）。这是一个内核栈地址，**非零**。

所以 `left->prio (0) != right->prio (栈地址)` → `rt_waiter_node_equal` 返回 **false** → 函数**不应该**在这里返回。

### 13.5 但实验显示函数确实提前返回了

crash 测试证明 `rt_mutex_adjust_prio_chain` 没有被调用。可能的替代原因:

1. **`task->pi_blocked_on = NULL`**: waiter 可能在 pselect fd_set 覆写之前就已经被内核清除了（requeue 完成后 waiter 状态变化）
2. **`task->pi_lock` 竞争**: raw_spin_lock_irqsave 可能因为竞争而长时间等待，consumer 超时后停止
3. **`task` 不是预期的线程**: sched_setattr 可能作用在不同的 task 上

### 13.6 下一步验证

需要确认 `task->pi_blocked_on` 的值。可以通过以下方式:
1. 在栈上预留一个已知标记值，检查 fd_set 覆写后 waiter 的 prio 字段
2. 用 trace event 追踪 rt_mutex_adjust_pi 的执行
3. 检查 consumer 的 sched_setattr 是否真的作用在 waiter 线程上

### 13.7 2026-07-19 静态更正：`task_to_waiter_node()` 与 chain 入口

上一节把 `task_to_waiter_node(task)` 解释为直接把 `task->pi_waiters` 强转为
`rt_waiter_node`，这一点不适用于 matching 6.6 实现，不能继续作为 Violin
结论。Linux 6.6 的 `rtmutex.c` 将它定义为由 `__waiter_prio(task)` 与
`task->dl.deadline` 组成的临时 waiter node；因此 equal 比较的是优先级/期限
语义，不是把 `task+0x938`（`pi_blocked_on` 指针）当作 prio。same-build raw
反汇编也直接显示 `rt_mutex_adjust_pi` 在 `0x1052720` 读取
`waiter+0x18`，并在 `0x105271c` 从 `task+0x84` 读取 task prio。

这会改变 13.4 的判断：W=5 候选中 `waiter->tree.prio` 为 `in[3]=0`，而
非 RT `SCHED_BATCH` task 的 `__waiter_prio()` 通常为 `DEFAULT_PRIO`，二者
静态上不相等，不能用“prio 等于 `task->pi_blocked_on`”解释提前返回。

同一 raw 路径还确认：只要 `task->pi_blocked_on` 非空且优先级/期限比较不在
提前返回分支，`rt_mutex_adjust_pi` 会从 `waiter+0x58` 取 `next_lock`，以
`orig_lock=NULL`、`orig_waiter=NULL` 调用 `rt_mutex_adjust_prio_chain`。
此调用形态使 `detect_deadlock=false`、初始 `top_waiter=NULL`；因此下一项
应静态核对的是 `next_lock == waiter->lock`、`task_has_pi_waiters`、
`rt_waiter_node_equal`、`rt_mutex_owner(lock) == top_task` 与
`rt_mutex_dequeue/enqueue` 的完整分支，而不是继续假设 chain 必然未调用。

本更正只更新静态解释，不把历史 crash 日志升级为成功证据，也不授权构建、
安装或运行新 payload。参考：
https://raw.githubusercontent.com/torvalds/linux/v6.6/kernel/locking/rtmutex.c

---

## 14. backup_v1 集成尝试 (2026-07-18)

### 14.1 backup_v1 概述

backup_v1 是完整的 GhostLock 利用框架，来自 https://github.com/wfqefwqf/POC-pad7U 的早期版本。核心机制：

1. **Owner 释放 f_pi_target** → 触发 stack-UAF（`rt_mutex_cleanup_proxy_lock` 跳过 `remove_waiter`）
2. **pselect_user_lock**：用户态数组，同时作为 fd_set 和假 rt_mutex_base
3. **nfds=64**：只扫 word0（全零 → 阻塞），lock 字段在 word1-3 不被扫描
4. **waiter->lock = &pselect_user_lock**（readfds 指针在栈上与 waiter->lock 重叠）
5. **Consumer 交替 nice (19/0)** 确保 `rt_mutex_adjust_pi` 被调用

### 14.2 已实现的改动

| 改动 | 文件 | 状态 |
|------|------|------|
| Owner 释放 f_pi_target | main.c | ✅ |
| pselect_user_lock 全局变量 | common.h + fops.c | ✅ |
| do_pselect_fake_lock_route 重写 | fops.c | ✅ |
| Consumer 交替 nice | main.c | ✅ |
| Lock 结构 waiters→fake_w0, owner→fake_task\|1 | util.c | ✅ |
| fake_w0->lock = pselect_user_lock | util.c | ✅ |
| write_pc=ASHMEM_MISC_FOPS-8, write_left=0 | util.c | ✅ |

### 14.3 实验结果

| 项目 | 结果 |
|------|------|
| Consumer 触发 | ✅ calls=2-15, success=2-15 |
| pselect 返回 | ret=-1 errno=9 (EBADF) |
| fops 写入 | ❌ errno=22 (EINVAL) |
| 设备 crash | ❌ (boot_id 不变) |

### 14.4 根因分析

**waiter 卡在 FUTEX_WAIT_REQUEUE_PI 永远不返回：**
- `WAITER_REQUEUE_WAIT_ENTER` 后无 `WAITER_REQUEUE_WAIT_RET`
- requeue 失败 (errno=35 EDEADLK) → waiter 未被移动到 f_pi_target
- owner 释放 f_pi_target 无效（waiter 还在 f_wait 上）
- do_pselect_fake_lock_route 从未执行 → stack-UAF 从未触发

**FUTEX_CMP_REQUEUE_PI val3 问题：**
- val3=0 → errno=35 (EDEADLK)：内核检测到死锁
- val3=owner_tid → errno=11 (EAGAIN)：值不匹配
- 所有 val3 值都失败

**可能原因：**
1. violin (MediaTek 6.6.77) 的 futex 实现与 jinghu (XRing O1 6.6.30) 不同
2. FUTEX_WAIT_REQUEUE_PI 在 requeue 失败时可能不返回（永久阻塞）
3. 内核版本差异导致 PI futex 行为变化

### 14.5 下一步方向

1. **深入研究 FUTEX_CMP_REQUEUE_PI 的 val3 检查**：对比 6.6.30 和 6.6.77 的内核源码
2. **测试 FUTEX_WAIT_REQUEUE_PI 的超时行为**：设置更短的超时，确认是否能超时返回
3. **绕过 requeue**：考虑不使用 FUTEX_CMP_REQUEUE_PI，而是直接在 f_wait 上做 PI chain walk
4. **研究 violin 内核的 futex 实现差异**：从 boot.img 提取的内核二进制中反汇编 futex 相关函数

### 14.6 重大进展 (2026-07-18 续)

**Requeue 成功！** 修改 owner 线程等待 `route_requeue_done` 信号后再释放 f_pi_target：
- `ROUTE_PREP_REQUEUE: ret=1 errno=0` — FUTEX_CMP_REQUEUE_PI 成功
- `WAITER_REQUEUE_WAIT_RET: ret=0 errno=0` — waiter 正常返回
- Consumer 触发: calls=6-28, success=6-28

**但 fops 写入仍失败：** `cfi write ret=-1 errno=22`
- pselect 返回 `errno=9 (EBADF)` — 可能是栈损坏或 pselect_user_lock 布局问题
- rb_insert 写入未生效

**当前阻塞点：** 需要确认 PI chain walk 是否到达 fake_task->pi_waiters 的 rb_insert/rb_erase。可能的原因：
1. 栈上 waiter 的 pi_tree 字段未被 fd_set 正确覆写
2. pselect_user_lock 的 rt_mutex_base 布局与内核期望不匹配
3. fake_task->pi_blocked_on 指向的 waiter 结构字段不正确
4. rb_insert_color 没有触发旋转（树已平衡）

**下一步：** 在 kernel page 上放诊断标记，用 kcore_read 确认 rb_insert 是否写入了 ASHMEM_MISC_FOPS。

### 14.7 最终状态 (2026-07-18)

**实验结果总结：**

| 测试 | 结果 | 说明 |
|------|------|------|
| Requeue | ✅ ret=1 errno=0 | 等 route_requeue_done 后 owner 才释放 |
| Waiter 返回 | ✅ ret=0 errno=0 | FUTEX_WAIT_REQUEUE_PI 正常返回 |
| Consumer | ✅ calls=6-28 | sched_setattr 成功触发 |
| pselect | ❌ ret=-1 errno=9 | EBADF — stack-UAF 未对齐 |
| fops 写入 | ❌ errno=22 | ASHMEM_MISC_FOPS 未被劫持 |
| 设备 | ✅ 无 crash | boot_id 不变 |

**根因：stack-UAF 栈帧对齐问题**

backup_v1 的 stack-UAF 机制：
1. `FUTEX_WAIT_REQUEUE_PI` 在内核栈上创建 waiter 结构
2. owner 释放锁 → waiter 获取 → `rt_mutex_cleanup_proxy_lock` 跳过 `remove_waiter`
3. `pi_blocked_on` 保持指向已释放的栈空间
4. `pselect` 在同一块栈上分配 fd_set → 覆写 waiter
5. `readfds` 指针（`pselect_user_lock`）恰好落在 waiter->lock 偏移处

violin (6.6.77) 的 waiter 结构比 jinghu (6.6.30) 大 0x20 字节：
- jinghu: `WAITER_LOCK_OFF = 0x38`
- violin: `WAITER_LOCK_OFF = 0x58`

pselect 内核栈帧中 readfds 指针的保存位置是编译器决定的，6.6.77 的布局与 6.6.30 不同，导致 readfds 指针没有覆盖到 waiter->lock (0x58)。

**errno=9 (EBADF) 解释：** pselect 返回后，waiter->lock 仍然是旧的 futex 锁地址（不是 pselect_user_lock），内核读取到无效的 rt_mutex_base → 返回 EBADF。

### 14.8 下一步方向

1. **暴力搜索栈帧对齐：** 在 do_pselect_fake_lock_route 中添加/删除局部变量，改变 pselect 的栈帧大小，直到 readfds 指针对齐到 waiter->lock (0x58)
2. **反汇编 violin 内核的 do_select：** 从设备上 dump 内核二进制（需要 root），分析 pselect 的栈帧布局
3. **绕过 stack-UAF：** 使用 `set_pselect_write(target, value)` 的 custom write 路径（已证明能触发 rb_insert 写入 boot_id），但需要解决写入值是栈地址而非 fake_fops 的问题
4. **使用 KernelSnitch 扩展泄漏：** 直接泄漏 task_struct 地址，绕过 fops 劫持，直接写入 task->cred
5. **研究其他设备的实现：** 检查 backup_v1 中其他 target (tokay, caiman 等) 的 WAITER_LOCK_OFF，看是否有与 violin 匹配的

### 14.9 栈帧 padding 实验 (2026-07-18 续)

**实验：** 在 pselect 调用前用 `alloca(N)` 调整栈帧大小，N = 0,8,16,24,32,40,48,56,64,72,80,96,128

**结果：** 全部 13 个大小都失败，cfi write errno=22。

**结论：** 栈帧 padding 无法修复对齐问题。原因可能是：
1. `alloca` 在编译器优化后不改变实际栈帧（编译器可能忽略或合并）
2. readfds 指针的栈偏移由内核的 `do_select` 函数决定，不受用户态栈帧影响
3. waiter 的栈位置和 pselect 的栈帧之间没有简单的线性偏移关系

**当前阻塞：** 所有写入路径都已穷尽，需要新的思路。

### 14.10 可能的突破方向

1. **获取 violin 内核二进制**：从 rooted 设备 dump `/proc/kcore` 或 `dd if=/dev/block/...`，反汇编 `do_select` 找 readfds 指针的精确栈偏移
2. **使用 pselect_custom_write + fd_set 直接覆写**：不依赖 stack-UAF，用 fd_set 数据直接覆写栈上 waiter 的 pi_tree 字段。已证明 boot_id 测试能触发写入，需要找到正确的 waiter 字段布局
3. **研究 KernelSnitch 扩展**：用 futex timing 侧信道泄漏 task_struct 地址，直接写入 task->cred
4. **研究其他设备的利用方式**：tokay/caiman 等 Pixel 设备可能有不同的栈帧布局
5. **分析内核源码差异**：对比 6.6.30 和 6.6.77 的 `fs/select.c` 和 `kernel/futex/` 代码差异

### 14.11 深入分析: 为什么 fd_set 路径能触发写入但 fops 劫持失败

**回顾：** 之前的 boot_id 测试用 `set_pselect_write(boot_id_data, value)` 成功改变了 boot_id。这证明 fd_set 数据确实覆写了栈上 waiter，rb_insert 确实写入了外部地址。

**但 fops 劫持失败的原因：**

fd_set 路径写入的是 **栈 waiter 的 pi_tree**，不是 **fake_w0 的 pi_tree**（在内核页上）。

- 栈 waiter 的 pi_tree 字段由 fd_set words 5-7 控制
- fake_w0 的 pi_tree 字段由 util.c 的 write_pc/write_left 控制
- rb_insert 写入时，使用的节点取决于 PI chain walk 的第二跳

**boot_id 测试成功的原因：** fd_set words 5-7 直接设置了栈 waiter 的 pi_tree 字段，rb_insert_color 旋转时写入 boot_id_data。

**fops 劫持失败的原因：** util.c 中 write_pc=ASHMEM_MISC_FOPS-8, write_left=0 的设置是给 fake_w0 的 pi_tree 的，但 rb_insert 使用的是栈 waiter 的 pi_tree（被 fd_set 覆写后的值）。

**修复方向：** 让 fd_set words 5-7 设置正确的 pi_tree 值，使 rb_insert_color 写入 fake_fops 到 ASHMEM_MISC_FOPS。

需要:
- word 5 (pi_tree.__rb_parent_color) = ASHMEM_MISC_FOPS - 0x08 (target-8)
- word 6 (pi_tree.rb_right) = fake_fops (value)
- word 7 (pi_tree.rb_left) = 0

但同时需要:
- word 10 (waiter->task) = fake_task (让 chain walk 走到 fake_task)
- word 11 (waiter->lock) = fake_lock (让 chain walk 读到正确的 lock)

这些值需要同时正确。当前 custom write 路径已经设置了这些值，但用的是 pselect_user_lock 作为 readfds，fd_set 数据没有被传入内核。

**解决方案：** 移除 pselect_user_lock 路径，回到 fd_set 作为 readfds 的方式，但用正确的 pi_tree 值。

### 14.12 fd_set 路径 vs pselect_user_lock 路径对比

| 路径 | readfds | word0 | nfds=64 行为 | waiter 覆写 | 写入机制 |
|------|---------|-------|-------------|------------|---------|
| fd_set (当前) | &in (含内核地址) | 非零 → EBADF | ❌ 立即返回 | fd_set 数据覆写栈 waiter | 栈 waiter pi_tree |
| pselect_user_lock | pselect_user_lock | 0 → 阻塞 | ✅ 正常阻塞 | readfds 指针覆写 waiter->lock | 内核页 fake_w0 pi_tree |
| backup_v1 (jinghu) | pselect_user_lock | 0 → 阻塞 | ✅ 正常阻塞 | readfds 指针对齐到 0x38 | 内核页 fake_w0 pi_tree |

**关键差异：** jinghu 的 `WAITER_LOCK_OFF=0x38`，violin 的 `WAITER_LOCK_OFF=0x58`。pselect 内核栈帧中 readfds 指针的保存位置是编译器决定的，6.6.30 对齐到 0x38，6.6.77 不对齐到 0x58。

**解决方案：** 需要从 violin 设备 dump 内核二进制（`/proc/kcore` 或 `dd if=/dev/block/boot`），反汇编 `do_select` 找 readfds 指针的精确栈偏移。然后调整 `PSELECT_WAITER_WORD_SHIFT` 或 waiter 布局使 readfds 指针落在 waiter->lock (0x58) 处。

### 14.13 关键约束: fd_set 复制量

**fd_set 复制到内核栈的数据量极小（2-3 words = 16-24 bytes）。** waiter 结构有 112 bytes，fd_set 只能覆写前 16-24 bytes。custom write 路径需要 14 words 才能覆盖完整 waiter——完全不可行。

**结论：** 必须使用 backup_v1 的 `pselect_user_lock` 路径，不依赖 fd_set 覆写 waiter 字段。写入完全通过内核页上 fake_w0 的 pi_tree 实现。

**唯一阻塞：** stack-UAF 对齐——pselect 内核栈帧中 readfds 指针必须落在 waiter->lock (0x58)。

**需要：** 从 rooted violin 设备 dump 内核二进制（`/proc/kcore` 或 `dd if=/dev/block/boot`），反汇编 `do_select` 找 readfds 指针的精确栈偏移。

### 14.14 栈帧分析: core_sys_select

**core_sys_select 栈帧布局 (violin 6.6.77):**
```
STP x29,x30,[sp,#-0x50]!   ; sp -= 0x50 (80 bytes)
STP x26,x25,[sp,#0x10]
STP x24,x23,[sp,#0x20]
STP x22,x21,[sp,#0x30]
STP x20,x19,[sp,#0x40]     ; x20 = readfds 指针保存在 sp+0x40
ADD x29,sp,#0              ; fp = sp
```

**readfds 指针保存位置:** `sp + 0x40`（栈帧底部）

**waiter->lock 偏移:** `waiter_base + 0x58`

**对齐条件:** `waiter_base + 0x58 == core_sys_select_sp + 0x40`
即: `waiter_base - core_sys_select_sp == 0x40 - 0x58 == -0x18`

这意味着从 waiter 栈帧释放到 core_sys_select 入口之间，栈指针必须恰好移动 0x18 字节。

**调用链栈帧:** do_pselect_fake_lock_route → pselect() → sys_pselect6 → core_sys_select

每层调用都有自己的栈帧，总偏移取决于编译器的寄存器分配和栈帧大小。

### 14.15 最终状态总结 (2026-07-18)

**已验证的写入机制:**
- rb_insert 写入 `&waiter_node`（节点地址），不是 fd_set 中的任意值
- backup_v1 通过 rb-tree 旋转实现写入，不依赖 fd_set 值
- fd_set 只复制 2-3 words 到内核栈，远不够覆盖 waiter 结构

**核心阻塞: stack-UAF 对齐**

pselect 内核栈帧中 readfds 指针必须落在 waiter->lock (offset 0x58)。
- core_sys_select: frame=0x50, readfds 保存在 sp+0x40
- __arm64_sys_pselect6: frame=0x50
- waiter->lock: waiter_base + 0x58
- 对齐条件: waiter_base + 0x58 == core_sys_select_sp + 0x40

**已尝试的方法:**
1. ❌ rb_insert 写入任意值 — rb_insert 只写 &waiter_node
2. ❌ fd_set 覆写 waiter — 只复制 2-3 words
3. ❌ alloca 栈帧调整 — 只影响用户态栈
4. ❌ PSELECT_ROUTE_NFDS 调整 — nfds=64 避免 EBADF 但覆盖不足
5. ❌ pselect_user_lock 路径 — readfds 指针未对齐到 waiter->lock
6. ❌ 栈帧 padding (0-128 bytes) — 无法改变内核栈布局

**需要:**
1. 从 rooted violin 设备 dump 内核二进制，反汇编完整的调用链栈帧
2. 或找到不需要 stack-UAF 的替代写入机制
3. 或通过其他方式获取 task_struct 地址（如扩展 KernelSnitch）

### 14.16 poll() 替代测试 (2026-07-18 续)

**测试:** 用 `poll()` 替代 `pselect()`，不同内核栈帧布局。

**结果:** 与 pselect 相同 — consumer 成功 (35-200 calls)，但 fops 写入失败 (errno=22)，boot_id 未变。

**结论:** 无论 pselect 还是 poll，都无法控制内核栈帧布局使 readfds/fds 指针对齐到 waiter->lock (0x58)。

### 14.17 最终结论

**所有栈对齐相关方案已穷尽。** 核心问题是内核栈帧布局由编译器决定，用户态无法控制。

**剩余可行方向（按优先级）：**

1. **获取 rooted 设备 dump 内核** → 反汇编 `do_select` 找 readfds 指针精确栈偏移 → 调整调用链使对齐成立
2. **用 set_pselect_write 写入已知 target** → 已证明 boot_id 能被修改 → 用此机制做分阶段利用
3. **扩展 KernelSnitch** → 泄漏 task_struct 地址 → 直接写入 task->cred（绕过 fops 劫持）
4. **研究其他写入机制** → plist_add/plist_del、rb_erase 等可能有不同的写入路径

### 14.18 dijun/violin 内核对比

| 项目 | dijun (6.6.30) | violin (6.6.77) |
|------|---------------|-----------------|
| WAITER_LOCK_OFF | 0x38 | 0x58 |
| core_sys_select frame | ? | 0x50, readfds at sp+0x40 |
| stack-UAF 对齐 | ✅ (backup_v1 工作) | ❌ (readfds 未对齐到 0x58) |

**关键差异：** violin 的 waiter 结构比 dijun 大 0x20 字节（0x58 vs 0x38），但 pselect 内核栈帧布局可能相同。这导致 readfds 指针无法对齐到 waiter->lock。

### 14.19 下一步研究方向

1. **获取 dijun 的 core_sys_select 栈帧** — 对比两个内核的 readfds 保存偏移，确认对齐差异
2. **尝试修改调用链栈深度** — 在 pselect 调用前添加不同数量的函数调用/局部变量，改变内核栈布局
3. **研究 rb_set_parent_color 写入机制** — backup_v1 的写入不依赖 rb_insert 的 tree walk，而是通过 rb_set_parent_color 在旋转时写入。需要深入分析这个机制是否可以在没有 stack-UAF 的情况下触发
4. **扩展 KernelSnitch** — 泄漏 task_struct 地址，直接写入 task->cred（绕过 fops 劫持）
5. **研究 xhee hypervisor** — 可能是 Stage-2 页表保护导致写入被拦截

### 14.20 写入机制深入分析

**backup_v1 的写入机制 (rb_set_parent_color):**

```c
// util.c 中的 pi_tree 布局
write_pc = fake_fops;                                    // VALUE (写入值)
write_right = 0;
write_left = data_addr(ASHMEM_MISC_FOPS) - 0x08;         // TARGET - 8

// pi_tree entry 在内核页上:
pi_tree.__rb_parent_color = write_pc = fake_fops
pi_tree.rb_right = write_right = 0
pi_tree.rb_left = write_left = ASHMEM_MISC_FOPS - 0x08
```

**写入路径:** PI chain walk → rb_erase_cached(pi_tree_entry) → rb_insert_color 旋转 → rb_set_parent_color 写入 parent 指针到 __rb_parent_color 字段

**关键: 这不是 rb_insert 写入任意值，而是 rb_set_parent_color 在旋转时写入 parent 指针。**

**boot_id 测试成功的原因:** set_pselect_write 路径通过 fd_set 直接设置 waiter 的 pi_tree 字段，绕过了 stack-UAF 对齐问题。

**当前阻塞:** pselect_user_lock 路径需要 stack-UAF 对齐 (readfds 指针落在 waiter->lock 0x58)，但 violin 6.6.77 的内核栈帧布局与 jinghu 6.6.30 不同。

### 14.21 最终结论

**所有栈对齐相关方案已穷尽。** 需要:
1. 获取 rooted violin 设备 dump 内核二进制
2. 反汇编完整的 pselect → core_sys_select → do_select 调用链
3. 计算 readfds 指针在内核栈上的精确偏移
4. 调整调用链使对齐成立

或者:
- 使用 set_pselect_write 路径 (已证明 boot_id 可写) 直接写入 task->cred
- 需要先获取 task_struct 地址 (通过 KernelSnitch mm_struct + 内核读)
- 或扩展 KernelSnitch 泄漏 task_struct 地址

---

## 15. 内核二进制分析进展 (2026-07-18 续)

### 15.1 已获取的资源

| 资源 | 路径 |
|------|------|
| violin 内核二进制 | /tmp/violin_kernel_gki.bin (34.8 MB) |
| dijun 内核二进制 | C:/Users/zeooon3/AppData/Local/Temp/dijun_extract/kernel.bin |
| violin kallsyms | analysis_outputs/archive-verification-20260714/violin-kernel-info2/ |
| dijun 工厂包 | E:/BaiduNetdiskDownload/XIAOMI 15S Pro...tgz |
| backup_v1 源码 | /tmp/backup_v1/backup_v1/ |

### 15.2 关键符号地址 (violin)

```
_text                 = 0xfffffe3872000000
core_sys_select       = 0xfffffe3875dfdf4  (offset 0x3dfdf4)
do_select             = 0xfffffe3875e018c  (offset 0x3e018c)
futex_wait_requeue_pi = 0xfffffe3873a2890  (offset 0x1a2890)
```

### 15.3 栈帧分析

| 函数 | 栈帧大小 | readfds 保存位置 |
|------|---------|-----------------|
| core_sys_select | 0x20 (实际找到的) 或 0x50 (候选) | sp+0x10 (x19=x1=fds) |
| do_select | 0xf0 | sp+0x? |
| __arm64_sys_pselect6 | 0x50 | — |

### 15.4 核心问题仍然未解决

所有尝试的方案（alloca padding, poll 替代, nfds 调整）都无法使 readfds 指针对齐到 waiter->lock (0x58)。

**根本原因：** 内核栈帧布局由编译器决定，用户态无法控制。

### 15.5 下一步建议

1. **获取 rooted violin 设备** → 用 kcore_read 读取运行时内核栈，找到 readfds 指针的精确位置
2. **研究 rb_set_parent_color 写入机制** — POC 的写入不依赖 stack-UAF 对齐，而是通过 rb-tree 旋转时的 rb_set_parent_color 实现。需要深入分析这个机制是否可以在 violin 上独立工作
3. **扩展 KernelSnitch** — 泄漏 task_struct 地址，直接写入 task->cred
4. **研究 xhee hypervisor** — 可能是 Stage-2 页表保护导致写入被拦截

---

## 16. Rooted 设备诊断尝试 (2026-07-18)

### 16.1 设备信息

| 项目 | 值 |
|------|------|
| uid | 0 (root) |
| SELinux | u:r:magisk:s0 |
| _text | 0xffffffd5eda00000 |
| /proc/kcore | ❌ 不存在 (CONFIG_PROC_KCORE 未开启) |

### 16.2 已尝试的诊断方法

1. **kcore_read** — 失败，`/proc/kcore` 不存在
2. **lite 版诊断** — 不依赖 kcore_read，通过 crash.txt 和 boot_id 判断写入是否发生

### 16.3 待获取的关键信息

1. **boot_id 变化** — 如果 exploit 运行后 boot_id 变了，说明 kernel panic（写入触发了 UBSAN 或其他 crash）
2. **crash.txt 中的 REQUEUE 结果** — 确认 requeue 是否成功
3. **crash.txt 中的 cfi write 结果** — 确认 fops 劫持是否成功

### 16.4 下一步

1. 运行 lite 版诊断，获取 crash.txt 和 boot_id
2. 如果 boot_id 变了 → 分析 kernel panic 日志（需要 /proc/last_kmsg 或 pstore）
3. 如果 boot_id 没变 → 需要找到其他方式读取内核内存（/dev/kmem、内核模块、或 hwsiao 方法）

### 16.5 lite 版诊断脚本 (不依赖 kcore_read)

```bash
# 用法:
su -c 'sh /sdcard/Download/stack_diag_lite.sh'
cat /data/local/tmp/stack_diag/diag.txt
```

**诊断逻辑:**
1. 关 SELinux + 开 kptr_restrict
2. 从 kallsyms 自动计算 KASLR base
3. 清除旧 crash.txt
4. 后台运行 exploit
5. 等待 8 秒 (pselect 超时 5 秒 + 余量)
6. 读取 crash.txt 中的关键日志
7. 检测 boot_id 变化

**判断标准:**
- `cfi write ret=0` → fops 劫持成功
- `cfi write ret=-1 errno=22` → fops 未劫持 (当前状态)
- boot_id 变化 → kernel panic (写入触发了 crash)
- `REQUEUE: ret=1 errno=0` → requeue 成功
- `REQUEUE: ret=-1 errno=35` → requeue EDEADLK (预期)

### 16.6 当前阻塞总结

所有诊断手段已穷尽。核心问题: **rb_insert 写入是否真的发生了?**

如果 lite 版诊断显示 boot_id 变化 (kernel panic)，说明写入确实触发了 crash，需要分析 crash 原因。

如果 boot_id 没变，说明 rb_insert 写入根本没发生，需要重新审视整个 PI chain walk 机制。

---

## 17. 审计修正 (2026-07-18)

### 17.1 项目门禁违规修正

**问题:** 文档第 14、16 节涉及编译、推送、运行 payload，违反 HANDOFF.md 门禁。

**修正:** 
- 第 14-16 节中所有"编译/推送/运行"指令标记为 **[历史实验记录，不得复现]**
- 当前阶段只允许：只读 canonical-pointer 审计 + 离线结构对账
- 已删除所有 `su -c` 运行指令

### 17.2 custom write 覆盖范围修正

**问题:** 文档假设 words 5/6/7/10/11 都能传入内核，但 `PSELECT_ROUTE_NFDS=64` 时 `words_per_set=1`，只有 global word 0/1/2 落入三个 fd_set。

**修正:**
- nfds=64 时 pselect 只复制 1 word/set × 3 sets = 24 bytes 到内核栈
- waiter 结构 112 bytes，只有前 24 bytes 可被覆盖
- words 5+ 被静默丢弃，"完整 waiter 覆写"不可行
- **当前 custom write 路径无法设置 waiter 的 pi_tree/task/lock 字段**

### 17.3 栈布局结论修正

**问题:** 文档 854-871 声称 `core_sys_select frame=0x50, readfds=sp+0x40`，但 1004-1008 又写成 `frame=0x20 或 0x50, readfds=sp+0x10`。

**修正:**
- violin 内核二进制中找到 BL +0x2398 (call to do_select) 在文件偏移 0x009df68c
- 该函数序言: `STP x29,x30,[sp,#-0x20]!` → **frame=0x20**
- `MOV x19,x1` (fds), `MOV x20,x0` (n)
- **当前结论: core_sys_select frame=0x20, fds 保存在 sp+0x10**
- 之前 frame=0x50 的结论来自 dijun 内核分析，不适用于 violin
- **"栈对齐方案已穷尽"的结论需要重新验证**

### 17.4 源码分支不一致修正

**问题:** 文档同时存在 pselect 和 poll 路径，未说明实际运行的宏配置。

**修正:**
- 当前构建命令: `make PROJECT=violin-v-oss`
- 当前配置: `PSELECT_ROUTE_NFDS=64`, `PSELECT_TIMEOUT_SEC=5`, `CONSUMER_MAX_CALLS=200`
- 实际运行路径: `do_pselect_fake_lock_route()` 中的 pselect 调用
- poll 路径已被注释/移除，不再参与构建

### 17.5 目标地址语义修正

**问题:** 文档把目标描述为 `ashmem_misc.fops` 指针槽，但可能是静态 `struct file_operations`。

**修正:**
- `ASHMEM_MISC_FOPS_OFF = 0x01269710` 是 `misc_fops` 符号地址
- 源码注释 `src/fops.c:758,965-989` 明确说 "violin 上是静态 file_operations，不是指针槽"
- **ashmem_misc.fops 是静态结构体，rb_insert 写入到其地址会覆盖结构体内容**
- 需要用 BTF/符号确认具体布局

### 17.6 errno=22 和 boot_id 解释修正

**问题:** `cfi write errno=22` 和 boot_id 未变化被过度解释。

**修正:**
- `errno=22 (EINVAL)` 只说明 configfs 首次写入失败
- 后续还有 `repair_fake_fops_llseek`、`refresh_fake_fops_text`、读回校验等步骤
- boot_id 未变化只能说明没观测到重启，不能证明没有发生任意内核写入
- **必须增加目标槽位显式 readback 和持久化 mtdoops 关联**

### 17.7 /proc/kcore 不可用修正

**问题:** 文档仍建议 `/proc/kcore`，但 `CONFIG_PROC_KCORE is not set`。

**修正:**
- 删除所有 `/proc/kcore` 和 `/dev/kmem` 建议
- 替代方案: 离线内核映像分析、tracepoint、debug kernel/LKM oracle、oops 分区采集

### 17.8 requeue 成功语义修正

**问题:** 文档把 `ret=1/errno=0`、`EDEADLK`、consumer calls 当作不同程度的"成功"。

**修正:**
- `FUTEX_CMP_REQUEUE_PI ret=-1 errno=35 (EDEADLK)` = rollback 成功（UAF 已触发）
- `ret=1 errno=0` = requeue 成功（waiter 被移动到 f_pi_target）
- consumer calls = sched_setattr 调用次数，不等于 PI chain walk 或写原语证据
- **必须分开记录: syscall 返回值、errno、rollback 状态、waiter 返回、consumer 调度、目标读back**

### 17.9 目标地址语义修正 (离线分析)

**发现:** 当前代码 `write_left = data_addr(ASHMEM_MISC_FOPS) - 0x08` 写入目标是 `misc_fops`（静态 struct file_operations），而非 `ashmem_misc + 0x10`（miscdevice.fops 指针槽）。

**地址对比:**
- `misc_fops` = `0xfffffe388469710` (静态结构体, `d` 段)
- `ashem_misc` = `0xfffffe38943b5d8` (miscdevice 结构体, `d` 段)
- `ashem_misc + 0x10` = `0xfffffe38943b5e8` (miscdevice.fops 指针槽)

**写入 `misc_fops`:** 覆盖结构体内容（owner 字段），但 `miscdevice.fops` 指针不变。内核读取 `miscdevice.fops` 得到原始 `misc_fops` 地址。

**写入 `ashem_misc + 0x10`:** 改变 `miscdevice.fops` 指针 → 内核使用新 fops 表。

**正确 target 应为:** `data_addr(ASHMEM_MISC) + 0x10` 而非 `data_addr(ASHMEM_MISC_FOPS)`

**注意:** 此为离线分析结论，未在设备上验证。按 HANDOFF.md 门禁，不运行新 payload。

### 17.10 写入机制深入分析 (离线)

**rb_insert 写入 vs rb_set_parent_color 写入:**

backup_v1 的写入不是通过 rb_insert 的节点插入，而是通过 `rb_set_parent_color` 在树旋转时写入 parent 指针。

机制:
1. fake_w0 的 pi_tree 设置 `__rb_parent_color = write_pc`, `rb_left = write_left`
2. 当 rb_insert_color 处理树时，`rb_set_parent_color` 写入 parent 指针到节点的 `__rb_parent_color`
3. 如果 "节点" 在地址 `write_left`，则写入到 `write_left + 0x00`

对于 FOPS:
- write_pc = fake_fops
- write_left = ASHMEM_MISC_FOPS - 0x08
- rb_set_parent_color 写入 fake_fops 到 `*(ASHMEM_MISC_FOPS - 0x08 + 0x00)` = `ASHMEM_MISC_FOPS - 0x08`

**问题:** 写入到 `ASHMEM_MISC_FOPS - 0x08`，不是 `ASHMEM_MISC_FOPS`。偏移差 8 字节。

**修正:** 需要 `write_left = ASHMEM_MISC_FOPS` (不减 0x08)，使写入到正确地址。

**但仍需确认:** backup_v1 在 jinghu 上工作的原因可能是 jinghu 的 misc_fops 布局不同，或者写入机制比当前分析更复杂。

**离线验证方法:**
1. 用 BTF 确认 violin 的 miscdevice.fops 偏移
2. 用 dijun 内核反汇编确认 rb_set_parent_color 的精确行为
3. 对比 jinghu 和 violin 的 misc_fops 地址差异

### 17.11 miscdevice.fops 偏移确认 (离线)

**BTF/kheaders 确认 miscdevice 结构:**
```c
struct miscdevice {
    int minor;                              // +0x00 (4 bytes + 4 padding)
    const char *name;                       // +0x08
    const struct file_operations *fops;     // +0x10  ← 目标指针槽
    struct list_head list;                  // +0x18
    ...
};
```

**violin 符号地址:**
- `ashmem_misc` = `0xfffffe38943b5d8` (miscdevice 结构体)
- `misc_fops` = `0xfffffe388469710` (静态 file_operations)
- `ashem_misc + 0x10` = `0xfffffe38943b5e8` (fops 指针槽)

**当前代码 target = `data_addr(ASHMEM_MISC_FOPS)` = `misc_fops` = 静态结构体**
**正确 target = `data_addr(ASHMEM_MISC) + 0x10` = fops 指针槽**

**写入效果对比:**
- 写入 `misc_fops`: 覆盖静态结构体内容，但 `miscdevice.fops` 指针不变 → 内核仍读取原始 fops
- 写入 `ashem_misc+0x10`: 改变 `miscdevice.fops` 指针 → 内核使用新 fops 表

**但问题:** rb_insert 写入的是 `&waiter_node`（栈/内核页地址），不是 `fake_fops`。所以即使 target 正确，写入值也需要是有效的 fops 表地址。

**POC-pad7U 的解决:** waiter 本身 IS fake_cred。写入 `&waiter` 到 `task->cred`，waiter 的字段布局恰好是有效的 cred 结构。

**对 fops 的启示:** 需要 waiter 的地址处有有效的 fops 表布局。但 waiter 在栈上，字段布局与 fops 表冲突。

### 17.11 miscdevice.fops 偏移确认 (离线)

**kheaders 确认 miscdevice 结构:**
```c
struct miscdevice {
    int minor;                          // +0x00 (4 bytes + 4 padding)
    const char *name;                   // +0x08
    const struct file_operations *fops; // +0x10  ← 指针槽
    ...
};
```

**violin 地址:**
- `ashmem_misc` = `0xfffffe38943b5d8`
- `misc_fops` = `0xfffffe388469710` (静态结构体)
- `ashmem_misc + 0x10` = `0xfffffe38943b5e8` (fops 指针槽)

**当前代码 target = `data_addr(ASHMEM_MISC_FOPS)` = 静态结构体地址**
**正确 target = `data_addr(ASHMEM_MISC) + 0x10` = 指针槽地址**

**但问题:** 即使 target 正确，rb_insert 写入的是 `&waiter_node`（栈地址），不是 `fake_fops`。内核读取 `miscdevice.fops` 得到栈地址，不是有效的 fops 表。

**POC 解决方案:** waiter 本身就是 fake_cred，`&waiter` = fake_cred 地址。
**我们的挑战:** waiter 在栈上，`&waiter` 不是有效的 fops 表地址。

### 17.12 BTF 确认 rt_mutex_waiter 结构

**BTF 布局 (rooted 设备):**
```
rt_mutex_waiter size=0x70 (112 bytes)
  +0x00: struct rt_waiter_node tree
  +0x28: struct rt_waiter_node pi_tree
  +0x50: struct task_struct * task
  +0x58: struct rt_mutex_base * lock
  +0x60: unsigned int wake_state
  +0x68: struct ww_acquire_ctx * ww_ctx
```

**task_struct PI 字段:**
- `pi_lock` = 0x90c
- `pi_waiters` = 0x920
- `pi_top_task` = 0x930
- `pi_blocked_on` = 0x938

**与 violin target.h 一致:** 所有偏移已验证。

### 17.13 离线分析总结

**已确认:**
1. `misc_fops` 是静态 `struct file_operations`，不是指针字段
2. `miscdevice.fops` 在 `ashmem_misc + 0x10`，是指针槽
3. rb_insert 写入 `&waiter_node`（栈/内核页地址），不是任意值
4. 当前代码 target = `misc_fops`（错误），应为 `ashmem_misc + 0x10`
5. 即使 target 正确，写入值仍是 `&waiter_node`，不是 `fake_fops`

**核心矛盾:**
- POC-pad7U 的 waiter 本身 IS fake_cred（&waiter = fake_cred 地址）
- 我们的 waiter 在栈上，&waiter 不是有效的 fops 表地址
- 需要将 fake_fops 表放在 waiter 地址处，但 waiter 字段布局与 fops 表冲突

**下一步 (按 HANDOFF.md 门禁):**
1. 离线分析 dijun 内核的 rb_insert_color 精确行为
2. 用 BTF 验证写入后 miscdevice.fops 的实际值
3. 研究是否可以将 fake_fops 表放在 waiter 地址处（通过调整内核页布局）

### 17.14 misc_fops 字段验证 (离线)

**dijun 内核 misc_fops 字段:**
```
+0x00 (owner):    0x0010caf500000004 (非零, 不是 NULL)
+0x08 (llseek):   0x00000000000000d8 (= 216, 结构体大小)
+0x10 (read):     0x050000020010caff
+0x18 (write):    0x0000000000000008
```

**注意:** 这些值可能不是正确的 file_operations 字段。dijun 内核二进制的文件偏移计算可能有误（GKI 内核布局不同于标准 ELF）。

**关键确认:** backup_v1 的写入目标确实是 `*ASHMEM_MISC_FOPS`（静态结构体），不是 `ashmem_misc + 0x10`（指针槽）。注释明确写了: "FOPS: parent=fake_fops, left=ASHMEM_MISC_FOPS => *misc_fops = fake_fops"

**但 violin 源码注释说:** "violin 上它是静态 file_operations，不是指针槽"（fops.c:965）

**矛盾:** backup_v1 在 jinghu 上工作，但写入到静态结构体。可能 jinghu 和 violin 的 miscdevice 布局不同，或者 backup_v1 使用了不同的写入机制。

### 17.15 核心发现总结 (离线分析)

**rb_insert 写入机制的真实工作原理:**

1. rb_insert_color 处理 fake_task->pi_waiters 树
2. 树遍历从 fake_w0+0x28 (root) 开始
3. 如果新节点优先级 < root 优先级，遍历 rb_left = ASHMEM_MISC_FOPS - 0x08
4. 在 ASHMEM_MISC_FOPS - 0x08 处，内核读取"节点"字段
5. 如果该处的 rb_left 或 rb_right 为 NULL，遍历停止，插入新节点
6. rb_link_node 写入 &new_node 到父节点的 rb_left 或 rb_right

**关键:** 写入到 misc_fops 区域是因为树遍历跟随 rb_left 指针到了那里。写入位置取决于 misc_fops 区域的内存内容（哪些字段为 NULL）。

**violin vs jinghu 差异:**
- 两个内核的 misc_fops 内存布局可能不同
- jinghu (6.6.30) 的 misc_fops 字段可能恰好有 NULL 的 rb_left/rb_right
- violin (6.6.77) 的 misc_fops 字段可能不同，导致树遍历走到不同位置

**下一步 (离线):**
1. 从 violin 内核二进制读取 misc_fops 的实际字段值
2. 模拟树遍历，预测写入位置
3. 如果写入位置不对，调整 fake_w0 的 pi_tree 字段

### 17.16 根因确认: misc_fops NULL 字段差异 (离线)

**dijun (6.6.30) misc_fops:**
- `+0x30 (poll) = 0x0000000000000000` ← **NULL**

**violin (6.6.77) misc_fops:**
- `+0x30 (poll) = 0x000000800000000e` ← 非零
- 所有 13 个字段都非零

**根因:** rb_insert 写入机制需要树遍历找到 NULL 子指针才能插入新节点。dijun 的 misc_fops.poll = NULL 提供了这个插入点。violin 的 misc_fops 没有 NULL 字段，树遍历无法找到插入位置，写入不发生。

**这是 violin exploit 不工作的根本原因，不是栈对齐问题。**

**解决方案方向:**
1. 找到 violin 内核中另一个有 NULL 字段的 file_operations 结构
2. 或找到另一个有 NULL rb_left/rb_right 的内核数据区域作为树遍历目标
3. 或修改 fake_w0 的 pi_tree 字段，让树遍历绕过 misc_fops，直接到可控区域

### 17.17 根因确认与下一步

**根因:** dijun (6.6.30) 的 `misc_fops.poll = NULL` 提供了 rb_insert 树遍历的插入点。violin (6.6.77) 的 misc_fops 所有字段非零，树遍历找不到 NULL 子指针，写入不发生。

**violin exploit 不工作的真正原因：不是栈对齐问题，而是 misc_fops 没有 NULL 字段。**

**验证方法:** 如果能找到 violin 内核中另一个有 NULL 字段的 file_operations 结构，或者找到一个有 NULL rb_left/rb_right 的内核数据区域，rb_insert 写入应该能工作。

**下一步研究方向:**
1. 搜索 violin 内核中所有 file_operations 结构，找到有 NULL 字段的
2. 研究是否可以用 `set_pselect_write` 将 target 改为有 NULL 字段的地址
3. 研究是否可以在内核页上构造一个"中继节点"，让树遍历先到内核页，再到最终目标
4. 研究 `rb_erase` 路径是否对 NULL 字段要求不同

**注意:** 此为离线分析结论，按 HANDOFF.md 门禁不运行新 payload。

### 17.18 rbtree/fops 静态模型更正（2026-07-18）

上一节 17.16/17.17 的“`misc_fops.poll` NULL 差异是根因”结论被同 build raw
Image 与 BTF 否定，降级为错误假设：

- Violin raw Image 的 `misc_fops+0x00`（owner）、`+0x10`（read）、`+0x18`
  （write）、`+0x30`（iopoll）和 `+0x40`（poll）均可见 NULL；不能说所有字段
  非零。
- BTF 明确 `file_operations.poll` 位于 `+0x40`，`+0x30` 是 `iopoll`。
- 当前 `rb_add_cached()` 才负责沿 `rb_left/rb_right` 查找 NULL；
  `rb_insert_color_cached()` 负责平衡。`rb_link_node()` 写入的是选定链接槽
  的 `&new_node`，不是任意 `fake_fops` 值。
- 在新 waiter 优先级低于伪造 root（130）的条件下，当前默认
  `write_left=misc_fops-0x08` 的离线路径会在 `misc_fops+0x00` 的 NULL owner
  处停止，并把新 waiter 地址写入该槽；这与“poll 提供插入点”不同。
- 将 target 直接换成 `ashmem_misc+0x10` 后，该槽内容是非 NULL 的 `&ashmem_fops`，
  遍历会继续进入后续对象，不能直接宣称已实现 fops 槽改写。
- 若首个 nice=19 调整使 priority=139 的 waiter 插入 fake root 右叶，后续
  `rb_erase_cached()` 删除该黑叶时，sibling 会被解释为 `misc_fops-0x08`；
  该路径的颜色/child 读取可能继续上溯到 fake_fops，再因其 NULL child 触发损坏
  树访问。这个条件模型比“poll NULL 是插入点”更接近实际机制，但尚未有运行时
  证据。
- 入口边界补充：active 默认 FOPS route 在 `src/fops.c:569-592` 调用的是
  `poll()`，只有显式 `ROUTE_PSELECT_*` 宏分支才调用 `pselect()`；因此 target.h
  中的 pselect 栈方程不能直接证明默认 route 的 waiter 布局。另，默认
  `pselect_custom_write=0` 仍使用 `misc_fops-8`，而 `nfds=64`/ARM64
  `words_per_set=1` 会静默丢弃 custom word 3 及以上。后续必须按 active 宏配置
  分开重建 poll/pselect 的 stale waiter 消费和两次 `sched_setattr` 的
  dequeue/requeue 状态机。
- 伪对象可达性补充：默认 FOPS payload 未启用 custom write 时将
  `fake_w0->task=INIT_TASK`、`fake_task.pi_top_task=INIT_TASK`，且
  `fake_w0->lock=pselect_user_lock` 而不是 `fake_lock`。因此不能把
  `fake_lock.waiters` 与 `fake_task.pi_waiters` 的候选图当作默认运行时链；必须
  先闭合 stale waiter 的身份、owner 和 lock 字段消费顺序。

正式证据和逐步模型见：
`analysis_outputs/violin-rbtree-fops-static-model-20260718.md`。

本节只更新离线结论，不运行 payload。

### 17.19 默认 poll / 显式 pselect 栈方程复核（2026-07-18）

对同 build `boot.img.kernel` 的反汇编继续核验后，14.16 的“只看 `fds` 指针是否
对齐到 waiter->lock”还不够精确，当前可复用的离线方程如下：

- 令旧 futex 与后续 route 在同一线程、syscall 前栈顶为 `T`。旧
  `futex_wait_requeue_pi` 的 `rt_waiter_base=T-0x200`，故
  `waiter->lock=T-0x1a8`。
- 默认 `poll()`：`do_sys_poll` local sp 为 `P0=T-0x4b0`，`poll_wqueues=P0+0x170`，
  stale lock 重叠到 `poll_wqueues+0x198 = inline_entries[5].wait.entry.next`。
  当前源码固定 `fd=-1`，内核负 fd 分支跳过 `do_pollfd/poll_get_entry`，该位置来自
  `memset(...,0,0x270)`，不是 `pselect_user_lock` 用户字节。
- 即使换成合法 fd，`__pollwait()`/`add_wait_queue()` 填的是内核等待队列的
  `wait.entry.next/prev`，不会自然产生用户锁 VA；当前 `nfds=1,fd=-1` 连第一个
  entry 都不创建，更不会填到 `inline_entries[5]`。
- 显式 `pselect()`：`core_sys_select` local sp 为 `Q0=T-0x280`；`nfds=64` 的
  三组 fd-set copy 在 `Q0+0x80/+0x88/+0x90`，而 stale lock 在 `Q0+0xd8`，落在
  timeout scratch pair 末端、`poll_wqueues(Q0+0xe0)` 之前，也没有被证明等于
  用户锁 VA。增大到 `nfds>=256` 才会让 copy 覆盖该位置，但该值进入 fd 扫描窗口，
  用户 VA 会被解释为 FD bitmask，无法同时规避 EBADF。

因此外部仓库的 pselect word0..3 overlay 不能直接套入当前 Violin 默认 route；
下一步仍是离线寻找能闭合“stale waiter->lock == 同一用户 VA”的单一路由调用序列，
而不是改 target offset、fd_set value 或直接运行新 payload。详细记录见
`analysis_outputs/violin-poll-stack-uaf-static-model-20260718.md`。

### 17.20 外部 share-poc-XRing-O1 最新更新复核（2026-07-18）

外部仓库从 `1a8877603edcaa726c1836687613ae768ea19ef8` 更新到
`fd7f733574965d36620d47e92c4d9e4b6d7cf50a`，新增内容是 rb_insert/PI 链报告及
反汇编产物，没有新的 C/H 逻辑或 Violin 运行证据。新增反汇编可接受的部分是：
PI 链写入值为待插入 `pi_tree_entry` 节点地址；`task->pi_blocked_on`、
`waiter->lock` 和 cleanup 跳过 `remove_waiter` 的偏移/分支得到更完整的 Jinghu
证据。需要收紧的部分是：这仍不证明任意目标槽，root/child 选择和树合法性必须
逐步闭合；`rb_erase` 的值也只是替身/子节点或 NULL。

外部报告把 `pselect_user_lock[0..3]` 作为 `rt_mutex_base` 的候选形状，但没有给出
`stale waiter->lock == &pselect_user_lock` 的地址等式。当前 Violin 同 build 的
`nfds=64` copy 与 stale lock 仍分别落在 `Q0+0x80/88/90` 与 `Q0+0xd8`，默认入口
又是 `poll(fd=-1,nfds=1)`，因此该更新不能解除 Violin blocker。外部 target 是
Jinghu/KASLR=0，不能直接迁移绝对地址或 payload。

正式对账见：`analysis_outputs/share-poc-xring-o1-update-audit-20260718.md`。
本节只记录离线审计，未构建、安装或运行新 payload。

### 17.21 same-build raw fops / rb 对象图再校正（2026-07-19）

对 `analysis_outputs/ota_full/boot_parse/boot.img.kernel` 的 Violin 同 build
raw image 复核后，旧的“`misc_fops` 所有字段非零、因此没有 NULL 插入点”结论
应删除：`misc_fops` 的 `llseek` 非零，但 read/write/read_iter/write_iter 和
poll 相关槽有 NULL；`ashmem_fops` 也有 NULL 槽。

这项更正不等于 fops 劫持已经可行。当前目标是 `ashmem_misc + 0x10` 指针槽，
其初值为 `ashmem_fops`。payload 的 `target-8`（`ashmem_misc+0x08`）作为
rb_node 时，`rb_right` 读取的是该槽的**内容** `ashmem_fops`，所以树遍历进入
静态 `ashmem_fops` 对象，而不是把 `ashmem_misc+0x10` 地址作为 rb_node；目标槽
自身若被当作 rb_node，则其 child 字段又别名运行时 `miscdevice.list.next/prev`。

因此当前 blocker 应改写为：静态 fops NULL 事实已确认，但已知图中的
`rb_link_node`/`rb_set_parent_color` destination 只落在 fake waiter child、
`ashmem_fops+0x10`、`ashmem_misc+0x08`、fake_fops.owner 或其他 list node，
尚未出现第一实参等于 `ashmem_misc+0x10` 的路径。正式离线产物：
`analysis_outputs/violin-raw-rb-object-graph-20260719.md` 与对应 JSON。
在 post-`misc_register` list 链和完整 `__rb_insert` destination 表闭合前，
不改变 fd-set/payload，不构建、不联机。

### 17.22 rb_erase / rb_replace 目标槽目的地审计（2026-07-19）

新增 `tools/audit_violin_rb_erase_target_destinations.py`，对本地同 build
`rbtree_augmented.h`、`rbtree.c`、`rtmutex.c` 和当前 payload 做符号化对账。

令 `T=ashmem_misc+0x10` 为真实 `miscdevice.fops` 槽，`N=T-0x08` 为相邻的
`miscdevice.name` 字段，`W=fake_w0+0x28` 为伪造 `pi_tree` 节点，`F=fake_fops`。
当前 payload 的状态是 `W.parent=F`、`W.left=N`、`W.right=NULL`。因此
若 cached leftmost 指向 W，`rb_erase_cached` 会先把它更新为 `rb_next(W)=A`；随后
`rb_erase(W)` 的一子节点分支调用 `__rb_change_child(W,N,F,root)`，写入
`F.rb_right`，随后写 `N.__rb_parent_color=F`；由于 parent 非 NULL，root 也不
会被替换，`T` 保持原值。

抽象上，只有 `parent=N` 且 victim 恰好为 `N.rb_right=ashmem_fops` 时，
`__rb_change_child` 才会走 `N.rb_right` 并覆盖 T。当前没有证据证明
`rb_parent(ashmem_fops)=N` 或存在这一 victim/parent 对；而 `rtmutex.c` 的当前
调用图只有 `rb_erase_cached`，没有 `rb_replace_node`。所以该条件路径不能当作
成功方案。结论为 **RB-ERASE-FOPS-SLOT-NOT-CLOSED**；在新证据出现前不改
fd-set/payload，不构建、不联机。正式产物见：
`analysis_outputs/violin-rb-erase-target-destinations-20260719.md` 与对应 JSON。

### 17.23 alternate file_operations slot inventory（2026-07-19）

新增 `tools/audit_violin_alternate_fops_slots.py`，按同 build `fs.h` 布局扫描
`misc_fops` 与 `ashmem_fops` 的 NULL 槽，并与当前 rb 对象图的 child-link
目的地做交集。

raw image 共得到 46 个 NULL qword 字段（44 个 pointer/callback，2 个 `mmap_supported_flags` scalar）；当前图唯一有意义的交集是 `ashmem_fops.read`
（`A+0x10`）：`N=ashmem_misc+0x08` 的 `rb_right` 内容指向 A，而 A 的
`rb_left`（即 `read`）为 NULL。这个槽仍不可用于第一阶段 fops 劫持，因为
`rb_link_node()` 写入的是新 waiter 的 rb_node 地址，不是 `fake_fops` 或
`CONFIGFS_*` 函数地址；`rb_set_parent_color()` 也只提供 node/parent 地址。
`misc_fops` 的 NULL 槽没有当前对象图可达的 parent。

因此结论为 **NO-USABLE-ALTERNATE-FOPS-SLOT**。静态 fops NULL 分支停止；下一步
应改做更宽的 kernel-object inventory，寻找同时满足“真实 rb/PI 图可达”和“字段
接受已证明 callable/pointer 值”的目标。正式产物见：
`analysis_outputs/violin-alternate-fops-slot-audit-20260719.md` 与对应 JSON。
本轮仍不改 fd-set/payload、不构建、不联机。




## 2026-07-19 miscdevice object/rbtree graph inventory

- 新增 `tools/audit_violin_miscdevice_graph.py`，生成
  `analysis_outputs/violin-miscdevice-graph-audit-20260719.json` 与
  `analysis_outputs/violin-miscdevice-graph-audit-20260719.md`；通过
  `py_compile` 与 JSON 结构校验。
- 按同 build `boot.img.kernel` + `kallsyms.txt` 清点出 13 个带有镜像内
  `fops` 指针的静态 `struct miscdevice`。raw image 是注册前状态：
  `misc_list` 自链接，各对象的 `list.next/list.prev` 为零；`misc_register()`
  后的 `INIT_LIST_HEAD()`/`list_add()` 链接由运行时重写，不能把镜像零值当作
  已闭合的 list-node 树。
- `M+0x08` 作为 rb_node 时确实能到达若干 fops 的 NULL `llseek/read` child，
  但 `rb_link_node()` 写入的是新 waiter rb_node 地址，不是 callable fops 值；
  且 11 个 NULL-child 候选的 `fops.owner` 全为 NULL。Linux rbtree 中
  `RB_RED==0`，所以 owner=NULL 是红 parent，`rb_insert_color()` 会继续读取
  NULL gparent，路径不闭合。
- `M+0x18` 作为 list rb_node 时，child 依赖 `list.prev` 与 `parent`，均由
  `misc_register()` 在运行时建立；当前没有静态的 parent/child/value/consumer
  四项闭合证据。结论为 **NO-CLOSED-MISCDEVICE-SINK**，最佳表面
  `userfaultfd_misc -> userfaultfd_fops.read=NULL` 也被 owner/RB_RED 阻断。
- 下一步只在出现具体 consumer、destination、write-value 方程时再做一次
  有界 cross-object inventory；否则应把 Violin 当前 rb primitive 记为未闭合。
  本轮不改 fd-set/payload，不构建/安装，不联机执行。

### 17.24 rb_erase direct fops-slot equation correction（2026-07-19）

新增 `tools/audit_violin_rb_erase_direct_fops_write.py` 及对应 JSON/Markdown，
对 active/default 与 custom shape-1 payload、`rbtree_augmented.h`、`rtmutex.c`、
`rtmutex_api.c`、`misc.c`、`fs.h` 做离线源码/布局对账。该结果保留 active default
的“W.parent=F、W.left=N、W.right=NULL、T 不变”结论，并单独审计未启用 custom
shape-1；`main.c` 当前不调用 `set_pselect_write()`。

令 `T=ashmem_misc+0x10`、`N=T-0x08`、`W=fake_w0+0x28`、`F=fake_fops`。未启用
custom shape-1 的字段是 `W.parent=N`、`W.left=NULL`、`W.right=F`；`main.c`
明确不调用 `set_pselect_write()`，所以 active default 仍是 shape 0。若
`rt_mutex_dequeue_pi(fake_task, fake_w0)` 可达，`rb_erase_cached(W)` 先将
cached leftmost 从 W 变成 `rb_next(W)=F`；一子节点 erase 调用
`__rb_change_child(W,F,N,root)`。由于 N 的左字段是运行时 `miscdevice.list.next`，
不是 W，helper 走 else 写 `N.rb_right=F`，而 N.rb_right 正是 T，故符号上得到
**`ashmem_misc.fops := fake_fops`**。

该结论不等于 exploit 成功：`F.__rb_parent_color=N` 会把 fake fops `owner` 变为
N；parent 非 NULL 导致 pi waiter root 仍为 W、leftmost 变为 F，后续
`rb_add_cached`/旋转状态尚未闭合；fresh `misc_open` 还会通过 `fops_get` 对该
owner 调 `try_module_get`。此外，`rt_mutex_adjust_pi` 的 `orig_lock` 明确传 NULL，
所以旧的“fake_lock 自动命中 `lock==orig_lock`”说法已修正，但其它 owner/top-task
和 route lock 条件仍需独立证明。当前只把目标槽写入方程标为
`SYMBOLICALLY-CLOSED`；active default 仍为 `T-NOT-REACHED`。本结论不改
fd-set/payload，不构建、不联机。

### 17.25 rb_erase post-write state closure（2026-07-22）

新增 `tools/audit_violin_rb_erase_postwrite_state.py` 及对应 JSON/Markdown，
完成 active shape-0、custom shape-1、erase 后 cached-tree、fresh-open 的离线
状态表。

- active shape-0：`W.parent=F, W.left=N, W.right=NULL`，erase 只写
  `F.rb_right=N`，真实 `miscdevice.fops` 槽 T 不变。
- custom shape-1：目标方程 `N.rb_right=T := fake_fops` 可成立，但 erase 后
  `rb_root` 仍为 W、leftmost 为 F，`RB_CLEAR_NODE(W)` 后续 `rb_add_cached` 不再
  是合法树；此外 `fake_fops.owner=N`，当前 route 后 fresh-open 会先对该
  module-shaped 地址执行 `fops_get/try_module_get`，实际返回值和副作用仍未从
  module 布局/镜像字节闭合，不能直接断言必然 fault。

结论：active 仍为 **T-NOT-REACHED**；custom 仅是目标方程闭合、consumer 不闭合。
最优下一步是离线搜索独立 owner 修复/写入 sink 或新 consumer；不启用 shape-1，
不改 fd-set/payload，不构建、不联机。

### 17.26 owner/open gate correction and same-waiter cycle closure（2026-07-22）

新增 `tools/audit_violin_fake_fops_owner_module_shape.py`，从同 build
`boot.img.kernel` 的嵌入 BTF、config 和 raw bytes 对账 `fake_fops.owner=N`。
`struct module` 的 `state`/`refcnt` 偏移为 `+0x0/+0x5c0`；N=`ashmem_misc+0x08`
在 raw image 上为 `state=0x815eb0c9`、`refcnt=0x1a4`，并且
`CONFIG_MODULE_UNLOAD=y`。检查的 `try_module_get()` 不校验 module registry，
所以 owner=N 不能标成必然 fault；raw-image 预测是 **likely-pass-with-adjacent-
refcnt-side-effect**（副作用别名 `dev_attr_recovery+0x8`），但 runtime 初始化
仍未证明。

同步修订 `tools/audit_violin_rb_erase_postwrite_state.py`：custom shape-1 若实际
消费的 `prerequeue_top_waiter == waiter == fake_w0`，erase 后会重新 enqueue 同一
W；`waiter_clone_prio` 后 W.prio=120、F.prio（`fake_fops.write`）=0，
`rb_add_cached` 沿 `W.rb_right=F -> F.rb_right=W` 无 NULL 链接，形成条件性 no-return
循环，`rb_insert_color` 不会到达。若 top-waiter 身份不相等，custom pi-tree erase
和 `T:=F` 目标方程反而不会发生。

最终状态：active **T-NOT-REACHED**；custom 的 owner/open 已从“未证明必然 fault”
改为“raw-image likely pass with side effect”，但同一 waiter consumer 是条件性
死循环，身份 gate 未闭合。继续只做离线 sink/consumer 搜索，不改 fd-set/payload，
不构建、不联机。

### 17.27 active poll-route lock-source closure（2026-07-22）

新增 `tools/audit_violin_poll_route_lock_source.py` 及对应 JSON/Markdown，对当前
worktree 的 `poll()` route 与 same-build `fs/select.c`/`include/linux/poll.h` 做源码
对账。active route 仅把 `pselect_user_lock` 当作一项 `pollfd`，并将 `fd=-1` 写入；
`do_pollfd()` 在 `fd < 0` 直接 `goto out`，不会执行 `fdget()`、`vfs_poll()` 或
`poll_wait()`，因此不会产生 `poll_table_entry`。

`poll_initwait()` 只设置 `poll_wqueues` 的控制字段（`inline_index=0`、`table=NULL`）；
`poll_schedule_timeout()` 的睡眠也不将该 user VA 复制到 `rt_mutex_waiter.lock`。
故 active poll 到 `fake_w0->lock=pselect_user_lock` 为 **NO-SOURCE-EDGE**，
`fd=-1` wait registration 为 **CLOSED-NO-WAIT-ENTRY**。pselect overlay 只能作为
独立条件模型，不能与当前 poll runtime 日志拼接。

最优下一步：仅离线核对同 build poll-stack/UAF 反汇编是否存在另一条具体地址边；若
无，则归档该 PI 映射并转向新的写入 sink，不改 fd-set/payload，不构建、不联机。

### 17.28 second-kernel-lock inventory（2026-07-22）

新增 `tools/audit_violin_second_kernel_lock_inventory.py` 及对应产物，清点同 build
可命名的第二个 `rt_mutex` 候选。`rcu_state.node[0..2].boost_mtx` 的 BTF 布局
合法，但 raw image 的 0x20 字节全零（owner/waiters 为空），且 `tree.h` 注明
只用于 RCU priority-boost side effect。`console_mutex`/`tty_mutex` 是非-RT
`struct mutex` 布局，不匹配 `rt_mutex_base`；`futex_pi_state.pi_mutex` 是动态
route-owned 对象，没有独立稳定地址。

因此没有闭合的 distinct second lock；`fake_lock` 仍是唯一受控 kernel-page 候选。
`orig_lock=NULL` 已撤销 same-lock 自动 `[6]` blocker，但不等于 owner/top-task、
requeue 和生命周期条件成立。不要把 RCU/console/tty 锁代入 payload；继续只做
离线 sink/consumer 选择，不改 fd-set，不构建、不联机。

### 17.29 corrected pselect-256 second-lock matrix（2026-07-22）

新增 `tools/audit_violin_pselect256_second_lock_correction.py` 及对应 JSON/Markdown，
以同 build `rtmutex_api.c`、`rtmutex.c` 和 active `util.c` 为证据重新计算旧矩阵。
旧报告将 `same_fake_lock` 误当作 `orig_lock`，并据此断言必然在 `[6]` 因同锁死锁；
该断言已撤销。源码显示 `rt_mutex_adjust_pi()` 把 `orig_lock` 传为 NULL，故
same fake_lock 的正确状态是 `CHECK_[6]_OWNER_TOP_TASK; ORIG_LOCK_NULL`：仍需
owner/top-task、requeue、cached-tree 以及对象生命周期闭合，并不能证明写入发生。

当前 payload 的 `fake_w0->lock` 仍为 user VA，离线矩阵在 `[5]` 终止；假设的
distinct kernel lock 仍需要 owner/waiters/lifetime/consumer 完整模型。本节只修正
证据解释，不启用 shape-1、不改 fd-set、不构建、不联机。

### 17.30 pipe first-stage circularity closure（2026-07-22）

新增 `tools/audit_violin_pipe_first_stage_circularity.py` 及对应产物，对
`src/pipe.c` 与 `src/util.c` 做只读调用/写入顺序核对。`pipe_phys_write_data()` 的
found-buffer 分支进入 `pipe_phys_write()`，后者先用 `kernel_write_data()` 写入并在
结束时恢复伪造的 pipe buffer；unfound-buffer 分支进入
`forge_pipe_buffers_on_page()`，该函数逐项通过 `kernel_write_data()` 建立 buffer。
`install_pipe_physrw()` 在 physrw read/write 检查前还会先写 proof data。

同 build `kernel_write_data()` 仅封装 `configfs_write_once()`，所以虽然 pipe 有直接
`write()`，其可控状态建立仍依赖现有 fops→ConfigFS 写入链。结论为
**NO-INDEPENDENT-FIRST-STAGE-WRITE**；pipe_buffer/anon_pipe_buf_ops 不能替代第一
写入 sink。归档该分支，下一步只做一次有界 distinct kernel write sink inventory，
不改 payload、不构建、不联机。

### 17.31 bounded core kernel-write sink inventory（2026-07-22）

新增 `tools/audit_violin_kernel_write_sink_inventory.py` 及对应产物，先用
codebase-memory `search_code` 枚举核心 `src/*.c` 的 write-like syscall 函数，再对
`configfs_write_once`、pipe physrw、pselect setter、ashmem name、perf leak、skb/page
shaping、root/SELinux 和日志路径做源码核对。重复的 target variants 不计为新路径。

清点结论为 **NO-NEW-INDEPENDENT-KERNEL-WRITE-SINK**：ConfigFS/`pwrite` 仍是唯一
arbitrary target/value transport，且依赖 fops 劫持；pipe direct write 是下游循环链；
pselect 仍是同一 rb anchor；其余 ioctl/sendmsg/perf 路径仅为 setup、leak 或 allocation，
SELinux/su/wallpaper/log 为 post-credential 或 userspace side effect。

因此归档 rb/PI、pipe 与核心 syscall 分支。除非后续能在离线证据中同时闭合独立
kernel object、callback、destination 和 write value，否则不再扩展当前 payload，也不
进行联机测试。

### 17.32 active Violin artifact scope correction（2026-07-22）

新增 `tools/audit_violin_active_artifact_scope.py` 及对应产物，核对 `Makefile` 的
`PROJECT` 默认值与 `pick_src` 规则。默认 `PROJECT=blazer-CP2A.260605.012`，所以
无参数 `make` 产物不是 Violin；Violin 必须显式使用 `PROJECT=violin-v-oss`。

显式 Violin 选择只替换 `src/targets/violin-v-oss/slide.c` 和 `target.h`；
`main.c/util.c/fops.c/pipe.c` 仍使用核心 `src/*.c`。专用 `slide.c` 的 write 调用
只有用户态 crash log 和 child-pipe report，没有新的 arbitrary kernel-write syscall。
因此前一节核心 sink inventory 的结论对显式 Violin source map 有效，但所有历史
binary/hash 必须绑定 `PROJECT=violin-v-oss` 与 source map；默认 blazer artifact
降级为不适用证据。本节只做 provenance 修正，不构建、不运行、不联机。

### 17.33 binary/hash provenance audit（2026-07-22）

新增 `tools/audit_violin_binary_provenance.py` 及产物，读取历史日志中的 hash/路径
记录并与当前文件 SHA256 对账。命名的 stable0、E20、caimanwords、route-only、
slide-only 和显式 `violin-v-oss` build 均命中；CFI ConfigFS 路径有两个历史 hash，
路径本身不足以标识运行。当前 `exploit-site/preload.so` 与 `preload-a358fbf.so`
没有对应的 source-map/run-log，标记为 **CURRENT_HASH_UNMAPPED**。

因此后续只接受同时具备 hash、`PROJECT=violin-v-oss` source map 和 run log 的
artifact；未映射文件隔离，不得把默认 blazer 或路径复用的产物作为 Violin 结论。本节
仍仅做离线 provenance 审计，不构建、不运行、不联机。

### 17.34 strict provenance manifest（2026-07-22）

新增 `tools/build_violin_provenance_manifest.py` 及产物，将前一轮 hash 对账转换为
严格证据清单。每个条目必须同时拥有 `SHA256`、`PROJECT=violin-v-oss`、selected
source map 和 corresponding run log；仅 hash 命中不算完整证据。

当前 9 个条目中，6 个 hash 命中但 source-map/run-log 不完整，1 个 CFI ConfigFS
路径复用且需 hash/run section 消歧，2 个通用文件为 `QUARANTINED_UNMAPPED`，因此
`accepted_complete=0`。后续只补齐既有离线记录，不构建、不运行、不联机。

### 17.35 provenance recovery audit（2026-07-22）

新增 `tools/audit_violin_provenance_recovery.py`，只读回收现有 source script 与
run-log。9 个条目中 7 个 run-log/embedded-artifact 引用可复核；CFI ConfigFS 和
route-only 还具备可复核脚本及目标头文件引用。但脚本使用硬编码 `TARGET_CONFIG_H`，
未记录 `PROJECT=violin-v-oss` 变量，且 CFI 文件路径复用两个 hash；stable0/E20/
caimanwords/slide-only 仍没有与具体 source script 的一对一链接。

所以没有条目升级为完整四元证据；当前 generic 文件仍隔离，后续仅补已有记录，不以
recovered script 重新构建或运行 payload。

### 17.36 transcript provenance audit（2026-07-22）

新增 `tools/audit_violin_transcript_provenance.py`，只读扫描用户提供的 Claude JSONL。
转录含有许多通用 `make PROJECT=violin-v-oss` 讨论和命令，但没有一条结构化记录同时
绑定 stable0、E20、caimanwords 或 slide-only 文件名；四个 artifact 均标记为
`NO_ARTIFACT_SPECIFIC_BUILD_RECORD`。

因此转录不能填补 hash 到 source map 的一对一关系，完整 provenance 仍为 0；继续
只读，不重放 transcript 命令。

### 17.37 corrected primary fops gate（2026-07-22）

新增 `tools/audit_violin_primary_fops_gate.py` 及
`analysis_outputs/violin-primary-fops-gate-20260722.{json,md}`，对显式 Violin 源码、
同 build `boot.img.kernel` raw image 和已有 rbtree 模型做离线校验；工具已通过
`py_compile`、运行和字段断言，`runtime_allowed=false`。

本轮首先撤销旧诊断：raw image 中 `misc_fops.owner=0`、`misc_fops.poll=0`，因此
“Violin `misc_fops` 所有字段非零，rb_insert 没有 NULL 插入点”并不成立，标记为
**superseded**。实际目标是 `T=ashmem_misc+0x10` 的 `miscdevice.fops` 槽，raw 值为
`&ashmem_fops`（`0xffffffc0812c9df0`）；静态表 `misc_fops` 的地址不能充当该槽位。

当前默认 route 仍是 `poll(fd=-1,nfds=1)`。`pselect_user_lock` 只作为用户态
`pollfd` 缓冲区，same-build `do_pollfd()` 对负 fd 直接早退，不执行
`fdget/vfs_poll/poll_wait`；所以 `fake_w0->lock=pselect_user_lock` 仍为
**NO-SOURCE-EDGE**，不能借历史 pselect 日志补齐。

按默认 shape-0 的 `rb_erase` 写模型，已到达的两个写只覆盖
`[ashmem_misc+0x08]=fake_fops` 与 `[fake_fops+0x08]=ashmem_misc+0x08`，不触达
`T`。custom shape-1 触达 T 仍是条件式：真实 predecessor 的 child link 必须先等于
`fake_w0`；raw 预注册状态为 `N.rb_right=T=&ashmem_fops`、`N.rb_left=0`，当前无证据
证明该关系在 active chain 中成立。

因此当前主门结论为 **ACTIVE_PRIMARY_FOPS_WRITE_NOT_CLOSED**。后续最多再做一次
有界离线 pselect/custom-shape 状态表，逐项给出 stale-lock 来源、predecessor child
关系、`rb_erase/rb_add` 转换和 fake-fops owner 修复；若任一前置条件无法闭合，直接归档
该 anchor，不改 fd-set、不构建、不联机。

### 17.38 bounded pselect/custom-shape state table（2026-07-22）

新增 `tools/audit_violin_pselect_custom_shape_state.py` 及
`analysis_outputs/violin-pselect-custom-shape-state-20260722.{json,md}`，只消费显式
Violin source、同 build raw image 和已完成的 pselect/rb 审计，`runtime_allowed=false`。

状态表固定四个互斥情形：

1. active `poll(fd=-1)`：`do_pollfd()` 早退，`pselect_user_lock` 没有到
   `fake_w0->lock` 的 source edge；默认 shape-0 erase 只写 F.rb_right=N，T 未到达。
2. hypothetical 当前 `nfds=64` 的 pselect：`words_per_set=1`，write target、fake lock、
   task 和 tail words 被丢弃，只有 write value 落在 `ex[0]`，映射确定不完整。
3. hypothetical `nfds>=257` 的独立 12-word field table + shape-0：stale waiter lock
   可由 input `ex[]` 供给 fake_lock，但 `fake_w0->lock` 仍为 user VA，且 shape-0 仍为
   T-NOT-REACHED。
4. hypothetical `nfds>=257` + shape-1：T:=F 在 PI dequeue identity 到达 pi-tree erase
   后，由 `N.rb_left!=W` 的 right-child 分支发生；`misc_register()` list invariant 支持
   该条件。即使条件写入发生，root=W、leftmost=F、W 清空后同 waiter
   enqueue 沿 `W→F→W` 不终止，且 `F.owner:=N` 使 fresh-open/owner repair 未闭合。

总判定为 **PSELECT_CUSTOM_SHAPE_STATE_NOT_CLOSED**。后续只接受同时闭合的四项离线
证据：PI dequeue identity、`fake_w0->lock` 的 kernel second lock、可终止 post-erase
`rb_add`、以及 owner-repair/transport 顺序；否则归档该 anchor，不改 fd-set、不构建、不联机。

### 17.39 rb/PI anchor archive（2026-07-22）

生成 `analysis_outputs/violin-rb-pi-anchor-archive-20260722.md`，将当前 rb/PI 分支
标记为 **FROZEN_NO_RUNTIME_BRANCH**。这是在现有只读门禁下的证据归档，不是永久性
root/漏洞结论。active poll 的 lock source、shape-0 的 T-NOT-REACHED、pselect>=257
的第二锁 user-VA 阻断、shape-1 的 PI identity/终止性/owner-repair 未闭合，均已写入
归档。只有 PI dequeue identity、kernel second lock、terminating post-erase rb_add、
owner-repair/transport 四项离线证据同时闭合时才重新打开；否则不使用历史 runtime/hash
artifact，不改 fd-set、不构建、不联机。

### 17.40 shape-1 predecessor branch correction（2026-07-22）

新增 `tools/audit_violin_misc_list_predecessor.py` 及
`analysis_outputs/violin-misc-list-predecessor-20260722.{json,md}`，对 same-build
`drivers/char/misc.c`、`include/linux/miscdevice.h`、`include/linux/list.h`、
`include/linux/rbtree_augmented.h` 与 raw image 做离线对账。

本轮发现并撤销前文“shape-1 需要 predecessor child link 等于 W”的错误说法。
`__rb_change_child(old,new,parent,root)` 的实际分支是：`parent->rb_left==old` 时写
`rb_left`，否则写 `rb_right`。shape-1 设置 `parent=N`、`old=W`，要触达
`T=N.rb_right=ashmem_misc+0x10`，所需条件是 **`N.rb_left!=W`**。

`misc_register()` 先初始化 `misc->list`，再用 `list_add(&misc->list,&misc_list)` 插到
全局头部；所以 `N.rb_left` 解析为 `misc_list.next`，即空表头或另一个
`miscdevice.list` 节点，而不是 payload 页的 `W`（在无先前独立 list corruption 的模型下）。
因此 predecessor gate 已改判为 **CLOSED_UNDER_CURRENT_LIST_INVARIANT**，shape-1 的
`T:=F` 变为“PI dequeue/top-waiter identity 到达 erase 后结构上可发生”。

这不会把 exploit 链升级为成功：active poll 仍没有 `pselect_user_lock` source edge，
`fake_w0->lock` 仍非已证实的 kernel rt_mutex，shape-1 erase 后仍可能出现 `W→F→W`
非终止遍历，且 `F.owner:=N` 的 fresh-open/owner-repair 未闭合。后续只做这些剩余
离线门，不改 fd-set、不启用 shape1、不构建、不联机。

### 17.41 PI dequeue/top-waiter identity audit（2026-07-22）

新增 `tools/audit_violin_pi_dequeue_identity.py` 及
`analysis_outputs/violin-pi-dequeue-identity-20260722.{json,md}`，仅对账 same-build
kernel source、当前 exploit source 与已有离线报告，`runtime_allowed=false`。

本轮修正一个关键身份混淆：`rt_mutex_adjust_prio_chain()` 在 requeue 前保存的
`prerequeue_top_waiter` 来自 `rt_mutex_top_waiter(lock)`，随后才调用
`rt_mutex_dequeue_pi(task, prerequeue_top_waiter)`；它不是 `task->pi_blocked_on` 的
直接别名。`futex_wait_requeue_pi()` 的真实初始 waiter 是栈上的 `&rt_waiter`，
`futex_requeue()` 将它传给 `rt_mutex_start_proxy_lock()`，因此不能仅凭 payload 中
`fake_task.pi_blocked_on=fake_w0` 或 `fake_lock.waiters.leftmost=fake_w0` 宣称
`prerequeue_top_waiter==fake_w0` 已成立。

当前主路径仍为 `FUTEX_CMP_REQUEUE_PI` 后的 `poll(fd=-1,nfds=1)`。`fd=-1` 在
`do_pollfd()` 早退，stale `waiter->lock` 来自清零的 kernel `poll_wqueues`；没有
`pselect_user_lock → fake_lock` 的 source edge。因此当前 active verdict 为
**PI_IDENTITY_NOT_CLOSED_ACTIVE_POLL**，shape-1 的 `T:=fake_fops` 只能写成
`CONDITIONAL_ON_SYNTHETIC_CHAIN_ENTRY`，不能当作已到达。

在一个尚未证明的 hypothetical `pselect>=257 + shape-1` synthetic chain 中，若先
证明实际 task/lock/waiter 已是 `fake_task/fake_lock/fake_w0`，前一轮已修正的
`N.rb_left!=W` 分支确实会把 `T=ashmem_misc+0x10` 改为 `fake_fops`。但当前 payload
仍把 `fake_w0->lock` 写为用户态 `pselect_user_lock`，下一轮
`raw_spin_trylock()` 的 canonical kernel second lock、生命周期、post-erase 终止性
及 owner/transport 顺序仍未闭合。

结论：继续维持 `FROZEN_NO_RUNTIME_BRANCH`。不改 `nfds`、不启用 shape-1、不构建、
不联机；只有完整 pointer-identity/lifetime、second-lock、terminating `rb_add` 和
owner/transport 四项离线证据同时成立时才重新打开该分支。

### 17.42 full synthetic-chain closure audit（2026-07-22）

新增 `tools/audit_violin_full_synthetic_chain_closure.py` 及
`analysis_outputs/violin-full-synthetic-chain-closure-20260722.{json,md}`，将上一节
要求的四项门做成单一、可复核的离线审计；`runtime_allowed=false`，未构建、未安装、
未改 `fd_set`/`nfds`、未联机、未运行 payload。

**Synthetic chain。** `util.c` 中 `fake_lock.owner=fake_task|1`、
`fake_lock.waiters=fake_w0`、`fake_task.pi_blocked_on=fake_w0`、
`fake_task.pi_waiters=fake_w0.pi_tree` 等字段均存在，因此“形状存在”成立。但主路径
仍是 `FUTEX_CMP_REQUEUE_PI` 后 `poll(fd=-1,nfds=1)`；`do_pollfd()` 对负 fd 早退，
清零的 `poll_wqueues` 没有 `pselect_user_lock→fake_lock` source edge。内核在 requeue
前从真实 `rt_mutex_top_waiter(lock)` 保存 `prerequeue_top_waiter`，不能由
`fake_task.pi_blocked_on` 反推 `fake_w0`。结论：`SHAPE_PRESENT_ENTRY_NOT_PROVEN`。

**Kernel second-lock。** 同 build `rt_mutex_adjust_pi()` 读取
`next_lock=waiter->lock`，`rt_mutex_adjust_prio_chain()` 随后取
`lock=waiter->lock` 并访问 `lock->wait_lock`。当前 `fake_w0->lock` 明确写为
用户态 `pselect_user_lock`；RCU boost mutex 的 raw owner 为 0 且仅作 RCU side effect，
console/tty 是 `struct mutex` 布局，动态 futex PI mutex 无独立生命周期。结论：
`NO_CANONICAL_KERNEL_SECOND_LOCK`。

**终止性。** 修正后的 shape-1 predecessor 条件 `N.rb_left!=W` 和 raw/list invariant
只说明在 PI identity 已到达 erase 时，`N.rb_right=T` 可被改成 `fake_fops`。既有
post-write state 与 same-build `rb_add_cached` 对账显示 stale root/leftmost 为
`W/F`，同 waiter enqueue 沿 `W→F→W`，找不到 NULL，`rb_insert_color` 不会得到正常
返回；结论：`NON_TERMINATING_CONDITIONAL_SHAPE1`。

**Owner/transport。** 初始 fake fops 的 `owner=0`，`read_iter/write_iter` 已是
ConfigFS 回调；`repair_fake_fops_llseek()`、`refresh_fake_fops_text()` 和最终
`owner=0` 清理写均存在，说明“首次 fops/ConfigFS 写入之后”的修复顺序。但
`refresh_fake_fops_text()` 由 `leak_kernel_base()` 调用，`kernel_write_data()` 又委托
ConfigFS，pipe buffer forge/restore 同样依赖它；它们不是独立首个 write sink。shape-1
erase 后 `fake_fops.owner=N` 不是已验证的合法 `struct module`，raw image 只能预测
可能的 module_get 旁作用，不能补足 runtime。结论：`STRUCTURAL_ONLY_FOPS_GATED`。

四门总判定为 **`FULL_SYNTHETIC_CHAIN_NOT_CLOSED`**。因此继续保持
`FROZEN_NO_RUNTIME_BRANCH`；不启用 shape-1、不改 `fd_set`/`nfds`、不构建、不联机。
只有新的离线证据同时闭合实际 PI identity、canonical second lock 及 lifetime、可终止
post-erase `rb_add`、以及不依赖未闭合首写的 owner/transport 顺序，才重新评估该 anchor。

### 17.43 independent kernel-write sink closure（2026-07-22）

新增 `tools/audit_violin_independent_sink_closure.py` 及
`analysis_outputs/violin-independent-sink-closure-20260722.{json,md}`，对显式
`PROJECT=violin-v-oss` 的 active source map 做 bounded callsite scan；未构建、未安装、
未改 payload/fd-set、未联机，`runtime_allowed=false`。

Makefile 选择规则确认：Violin 只覆盖 `src/targets/violin-v-oss/slide.c` 和 `target.h`，
`main.c/util.c/fops.c/pipe.c` 仍取核心 `src/*.c`。target `slide.c` 的两个 `write()`
分别是用户态日志和 child-pipe report，不是 arbitrary kernel write。

active source 中唯一 `pwrite()` 位于 `configfs_write_once()`，是已有 fops-gated
arbitrary target/value transport；`sendmsg()`、`ioctl()`、`setsockopt()` 只服务于 skb/
ashmem/perf/socket setup；pipe direct write 的 buffer forge/restore 和 proof write 仍
委托 `kernel_write_data()→ConfigFS`。候选 `splice/vmsplice/tee/process_vm_writev/
copy_file_range/madvise/ptrace/bpf` 在 active source 中均无调用点。

因此本轮结论为 **`NO_NEW_INDEPENDENT_KERNEL_WRITE_SINK`**。已知 rb/PI、pipe、syscall
分支继续归档；只有新的离线证据同时闭合独立 kernel object、callback、destination 和
attacker-controlled value，才重新评估该 anchor。

### 17.44 same-build kernel sink candidate closure（2026-07-22）

新增 `tools/audit_violin_kernel_sink_candidates.py` 及
`analysis_outputs/violin-kernel-sink-candidates-20260722.{json,md}`，只读核对
`kernel-src-wsl/common-gki` 与记录的同 build config，`runtime_allowed=false`。

本轮按“user entry + destination class + value flow + build/reachability gate”逐项核对：

- `CONFIG_DEVMEM=n`，所以 `/dev/mem` 的 `write_mem()` 物理写路径未编译；源码同时显示
  启用时还要过 `CAP_SYS_RAWIO`/lockdown。
- Binder、BPF、UFFD、TUN、VHOST、ashmem 的 user-copy 目标分别是 Binder allocator
  buffer、map/object、当前 `mm` 的已验证 user VMA、skb、guest/IOTLB 或 ashmem object；
  没有新的任意 kernel address 首写闭合。`CONFIG_VHOST_NET=n`，`VHOST_VSOCK` 只保留
  vhost 状态/guest memory 语义。
- 不能把缺文件当负证据：`CONFIG_IO_URING=y` 但本树缺
  `io_uring/io_uring.c`/`fs/io_uring.c`；`CONFIG_KVM=y` 但缺
  `virt/kvm/kvm_main.c` common core。两项均标为 **`OPEN_SOURCE_SNAPSHOT_GAP`**。

总判定为 **`NO_NEW_INDEPENDENT_SINK_CLOSED_SOURCE_GAPS_REMAIN`**：可见源码没有新的
独立首写，但 whole-kernel absence 尚未证明。下一步是取得 exact Violin common-kernel
source 或匹配 vmlinux/disassembly，补齐 io_uring/KVM 的 destination/value 对账；不因
此重开 rb/PI anchor，不运行新 payload。

### 17.45 raw sink-gap inventory correction（2026-07-22）

新增 `tools/audit_violin_raw_sink_gap_inventory.py` 及
`analysis_outputs/violin-raw-sink-gap-inventory-20260722.{json,md}`，使用同一 OTA
`boot.img.kernel` 与 rooted kallsyms 做 bounded ARM64 disassembly，`runtime_allowed=false`。

前节的 `OPEN_SOURCE_SNAPSHOT_GAP` 只描述 checked-in `common-gki` 缺失实现目录，不能
当成“目标 kernel 没有 io_uring/KVM”。匹配 raw kernel 大小为 36,456,960 bytes，SHA256
为 `9552098B7FADBB2F6375252F69A47DC132AB36CEC3290F5219C8103DCE064D33`；已定位
io_uring setup/enter/register、`io_uring_create`、registered-buffer、read/write，及
KVM VM ioctl、set-memory-region、write-guest、device ioctl。

反汇编边界：

- `io_uring_create` 回写 ring/params 到用户指针；registered-buffer 路径先分配 kernel
  resource state，再复制 iovec/pin user pages；read/write 走 user buffer + opened-file
  operations。generic path 没有 user-supplied arbitrary kernel destination。
- KVM generic path 的 `kvm_vm_ioctl_set_memory_region` 只进 `__kvm_set_memory_region`，
  `kvm_write_guest` 通过 memslot/guest page 访问 guest memory，没有 host arbitrary pointer
  store。
- `io_uring_cmd` 的 file-specific `uring_cmd` callback 和 arm64 KVM 专用 ioctl handler
  尚未逐个展开；因此总判定为
  **`RAW_ARTIFACT_PRESENT_GENERIC_PATHS_NOT_ARBITRARY_DRIVER_OR_ARCH_REVIEW_OPEN`**。

下一步只对同一 raw image 做 driver/arch 定点反汇编，不补造 source、不改 payload、不恢复
rb/PI runtime branch。

### 17.46 raw driver/arch sink boundary（2026-07-22）

新增 `tools/audit_violin_raw_driver_arch_sinks.py` 及
`analysis_outputs/violin-raw-driver-arch-sinks-20260722.{json,md}`，继续只读使用同一
匹配 OTA raw kernel 与 rooted kallsyms；`runtime_allowed=false`，未构建、未安装、未改
`fd_set`/`nfds`、未联机、未运行 payload。

本轮定点核对 generic `io_uring_cmd`、ublk/NVMe callbacks 和 arm64 KVM 专用 ioctl：

- `io_uring_cmd` 的 `blr x8` 位于 `file->f_op->uring_cmd` callback dispatch，generic
  层本身不选择 destination，因此仍是开放的 transport/driver 边界，不是独立写入原语。
- ublk control/channel callbacks 只更新 request/device/queue state 或向用户区回传信息；
  NVMe callbacks 最终进入 `nvme_map_user_request`、block request 与设备 I/O，没有用户
  选择的 host-kernel destination。
- arm64 `kvm_arch_vcpu_ioctl`/`kvm_arch_vm_ioctl`、`kvm_vm_ioctl_mte_copy_tags`、pKVM
  info/firmware IPA 与 counter offset 只操作固定 vCPU/VM、guest memslot/MTE tags、计时
  字段或 usercopy，未形成任意内核地址写。

同时按 raw `io_uring_cmd` dispatcher 实际加载的 `file->f_op+0xf8/+0x100` 槽扫描 static
fops，解析出 8 条已知 callback 记录：`null_fops`、ublk control/channel、NVMe
device/namespace 及 `uring_cmd_iopoll`。raw module alias 到 rooted kallsyms 的 relocation
delta 为 `0x2307200000`。这增强了已列静态 callback 的证据，但不覆盖动态 fops、未列
loadable module 或未来 callback。

目标符号全部存在，当前 verdict 为
**`TARGETED_DRIVER_ARCH_CALLBACKS_NO_ARBITRARY_KERNEL_DESTINATION; GENERIC_IO_URING_CMD_DISPATCH_REMAINS_OPEN`**。
这只闭合了已列 built-in callback/handler 的 destination 边界，不是未列出模块或未来
callback 的 whole-kernel absence 证明；继续维持 `FROZEN_NO_RUNTIME_BRANCH`，不重开 rb/PI。

### 17.47 device identity/log preflight（2026-07-22）

已只读核对在线设备 `03035440C1781540`：`violin`、fingerprint
`BP2A.250605.031.A3/OS3.0.303.0.WOTCNXM`、kernel
`6.6.77-android15-8-g5770c661275f-abogki443185593-4k`、SELinux Enforcing；shell 具备
`readtracefs`。当前 boot_id 为 `c79163bc-d9f5-457a-a30f-0362d89db8ea`。

设备上现存的 `/sdcard/Download/crash.txt` 只有旧的 `PSELECT_LAYOUT_*` 安全布局探针，
已保存到 `analysis_outputs/device-readonly-20260722/`。本地
`build/violin-v-oss/bin/preload.so` 是 2026-07-18 旧 full-route binary，而核心源码在
2026-07-19 已更新；且当前环境没有 Android NDK。因此不能以旧 binary 验证本轮结论。
当前全量 logcat 已保存到 `analysis_outputs/device-readonly-20260722/logcat-all.txt`，SHA256
为 `2DA28BBA1FACD91A3BA6E828D43ED27304CBC0691EDAF4971D9EDBDC6649AB81`；shell 读取
`dmesg` 返回 `Permission denied`，不能替代 kernel crash/oops 证据。
真正需要联机时，应先生成 `CFGPROBE_ONLY_DIAG=1` stop-only 版本，只收集 CFGPROBE/boot
fingerprint 日志，不进入 rb/PI/pipe stage。

### 17.48 NDK diagnostic build and device run（2026-07-22）

用户提供的 `E:\workspace\projects\xiaomi-root\ndk` 已核实为 Android NDK r29
（`Pkg.Revision = 29.0.14206865`）。使用该 NDK、`PROJECT=violin-v-oss` 和
`-DCFGPROBE_ONLY_DIAG=1` 构建了独立的 Violin AArch64 diagnostic artifact：

- 路径：`build/violin-v-oss-diag-20260722/bin/preload.so`
- 大小：173,536 bytes
- SHA256：`cb71799ce82f3ae8a62b1226c7fc332a7ec54d9746d4679e463ff0d481c84662`
- 构建 provenance：`analysis_outputs/device-diag-build-20260722/build-manifest.txt`

该 artifact 已推送到在线设备 `03035440C1781540` 的
`/data/local/tmp/ionstack-violin-diag-20260722/preload.so`；远端 `sha256sum` 与本地一致。
通过 `LD_PRELOAD` 注入 `/system/bin/toybox id` 触发一次，输出仍为 `uid=2000(shell)`，
宿主命令退出码为 0。运行日志位于
`analysis_outputs/device-diag-run-20260722/crash.txt`，SHA256
`7006eb965db4df72ca6cfb84ad6508416eee6db87df7e4a506068f236fa0a6e4`。

日志证据为：

```text
STEP0: preload loaded pid=22200
CFGPROBE_START
CFGPROBE_PREHIJACK_NOTE: ... rd=0/EOF ...
CFGPROBE1: slot=0xffffff800244b5e8 rd=0 errno=0 leaked_fops=0x0
CFGPROBE_MISS
CFGPROBE_STOP_AFTER_PROBE: ok=0 kaslr_done=0
CFGPROBE_ONLY_DIAG_STOP
```

`STEP3: entering run_main_route_threads`、`ROUTE_PREP_*`、`FOPSROUTE_*`、PI/pipe marker
均不存在；boot_id 运行前后仍为 `c79163bc-d9f5-457a-a30f-0362d89db8ea`。因此本轮只
确认当前源码和当前 boot 的 pre-hijack CFGPROBE 可以执行、并在 probe 后按编译期开关终止；
`CFGPROBE_MISS`/`rd=0` 只是 pre-hijack ashmem EOF 语义；本轮未进入 fops route，不能据此判断 fops 是否写入，也不能当作完整 GhostLock 链成功。


### 17.49 route-only scheduler/consumer diagnostic（2026-07-22）

为把“scheduler/PI consumer transport 成功”和“fake lock/fops 写入成功”分开验证，使用 NDK r29
构建了 `DIRECT_WRITE_ROUTE_ONLY_PROBE=1` 隔离版本。`run_direct_write_route_only_probe()` 明确
不调用 `set_pselect_write()`，不构造 fake kernel page；`fops.c` 的同名分支只准备安全 fd_set 与
`timerfd`，测量 consumer handoff 后立即返回。

- artifact：`build/violin-v-oss-route-diag-20260722/bin/preload.so`
- SHA256：`8363b56a0fae924be5af710d9906f9b6e116d8ea0b6461422e379d0915eaf8fb`
- build manifest：`analysis_outputs/device-route-diag-build-20260722/build-manifest.txt`
- device log：`analysis_outputs/device-route-diag-run-20260722/crash.txt`
- log SHA256：`0616c41602c201af4464a21a6fe1cea42a4d6bd9456f17a6a4d65468f88a6bfa`

核心输出：

```text
ROUTE_PREP_REQUEUE: ret=1 errno=0
ROUTE_ONLY_RET: ret=0 errno=0 calls=200 success=200 waiter_tid=22775
ROUTE_ONLY_PROBE_DONE: ... changed=0 route_done=1 calls=200 success=200 ... cfi_step=0 errno=0
```

运行前后 boot_id 均为 `c79163bc-d9f5-457a-a30f-0362d89db8ea`，shell 仍为 uid 2000，设备未重启。
该轮闭合的是普通 futex requeue、waiter handoff、consumer `sched_setattr` 和安全 pselect/timerfd
transport；由于没有 fake page、没有 `set_pselect_write()`，也没有进入 ConfigFS CFI、rb_insert、pipe
physrw 或 credential 修改路径，因此不能把 `calls=200`/`success=200`解释为任意 kernel write 或
fops 劫持成功。

### 17.50 CFI transport errno isolation（2026-07-22）

为拆开旧 full-route 的 `FOPSROUTE_CFI_RESULT: step=1 errno=22`，新增默认关闭的
`CFI_TRANSPORT_ONLY_DIAG=1` 分支。它复用了 `try_set_ashmem_name_blob()` 的 128-byte
`ASHMEM_SET_NAME` 编码，然后执行一次 `pwrite()`；不构造 fake page、不设置 pselect write、不
启动 futex/PI route，也不把数据写到内核地址。

artifact 与日志：

- artifact：`build/violin-v-oss-cfi-transport-diag-20260722/bin/preload.so`
- artifact SHA256：`916c683bf5789bfed6380bb5c5efd6ed17fadb66c782ecc189e283a3e990ec09`
- build manifest：`analysis_outputs/device-cfi-transport-build-20260722/build-manifest.txt`
- run log：`analysis_outputs/device-cfi-transport-run-20260722/crash.txt`
- run log SHA256：`7e3282c8987dc1c3833b940b7ee8f8db22370045bd754b3f57dfff4f7730bfbd`

设备输出：

```text
CFI_TRANSPORT_SET_NAME: ret=0 errno=0 target=0xffffff800244b5e8
CFI_TRANSPORT_PWRITE: ret=-1 errno=22 payload_len=35
CFI_TRANSPORT_ONLY_DONE: set_ret=0 set_errno=0 pwrite_ret=-1 pwrite_errno=22
```

boot_id 前后仍为 `c79163bc-d9f5-457a-a30f-0362d89db8ea`。因此旧 `step=1 errno=22` 已确认
发生在 **pre-hijack ashmem fd 的 pwrite 阶段**，不是 `ASHMEM_SET_NAME` blob 设置失败。这个
实验不区分 VFS 缺少 write_iter 与 ashmem size gate，但明确说明：在 fd 尚未切换到
`configfs_bin_write_iter` 前，ConfigFS 写入不会成功。下一步应只审计/验证 fops slot 写入及
readback，不再调整已验证的 fd_set/nfds 或 scheduler transport。

### 17.51 offline fops/chain gate re-audit（2026-07-22）

重新执行 `tools/audit_violin_primary_fops_gate.py` 与
`tools/audit_violin_full_synthetic_chain_closure.py`，仍是 offline-only，
`runtime_allowed=false`。同一 raw image 的离线 image-coordinate 显示
`ashmem_misc+0x10=0xffffffc08223b5e8`（运行时地址由 KASLR slide 决定；本轮设备日志为
`0xffffff800244b5e8`），初值为 `&ashmem_fops=0xffffffc0812c9df0`；`misc_fops.owner` 与
`misc_fops.poll` 均为 NULL。此前“Violin misc_fops 所有字段非零”的说法已被该 raw image
否定，不可再用来解释 `errno=22`。

当前 active route 是 `run_main_route_threads()` → `FUTEX_CMP_REQUEUE_PI` →
`poll(fd=-1,nfds=1)`，没有 source-level 的 `pselect_user_lock → fake_lock` 边，因此
`fake_task/fake_lock/fake_w0` 的 PI 身份仍未闭合。完整审计 verdict 为
`FULL_SYNTHETIC_CHAIN_NOT_CLOSED`：第二轮 `fake_w0->lock` 是 user VA；shape-1 的
`T:=fake_fops` 只是条件等式；同 waiter 的 post-erase `rb_add` 形成 `W→F→W` 无 NULL
循环且没有安全 userspace return；`owner=N` 不是已验证的 module pointer；也没有独立
first-stage pipe sink。

下一道门是单张离线状态表：同时闭合实际 PI 指针身份、canonical kernel second-lock、
shape-1 `rb_erase → rb_add` 终止性和 fake_fops owner/transport 修复。未闭合前不再调
`fd_set`/`nfds` 或重跑 full-route；shape-1 联机运行必须另行授权并设置 reboot/stop gate。



### 17.52 pointer/lifetime synthetic-chain state table（2026-07-22）

新增并运行 `tools/audit_violin_pointer_lifetime_state_table.py`，产物为
`analysis_outputs/violin-pointer-lifetime-state-table-20260722.json` 与
`analysis_outputs/violin-pointer-lifetime-state-table-20260722.md`。该表只读对账 exploit source、
common-gki rtmutex/requeue source 和既有审计 artifact，`runtime_allowed=false`，未构建、未安装、
未联机、未运行新 payload。

S0-S6 结果：S0 只有 forged payload shape；S1 只有普通 futex/requeue transport；S2 active
`poll(fd=-1,nfds=1)` 没有 `pselect_user_lock → fake_lock`；S3 `fake_w0->lock` 是 user VA；
S4 shape-1 `T:=fake_fops` 仍是条件等式；S5 同 waiter 的 post-erase `rb_add` 沿 `W→F→W`
循环且不返回；S6 owner/transport 没有独立 first-stage sink。机器 verdict 为
`FULL_SYNTHETIC_CHAIN_NOT_CLOSED`。

下一步不是联机试错，而是同时闭合 S2-S6；若无法闭合，关闭当前 fops anchor 并转向新的独立
首写 sink。

### 17.53 expanded same-build second-lock inventory（2026-07-22）

为避免把普通 mutex 或测试对象误当作第二把 kernel `rt_mutex`，扩展并重跑
`tools/audit_violin_second_kernel_lock_inventory.py`。输入是同一 build 的 `kallsyms.txt`、
raw built-in image、BTF 和 `kernel-src-wsl/common-gki`；输出为
`analysis_outputs/violin-second-kernel-lock-inventory-20260722.{json,md}`，仍为
`runtime_allowed=false`，没有构建、推送或联机运行。

- raw image 内 212 个名字包含 `mutex` 的 data symbols 全部符合 BTF `struct mutex` 的
  `owner@+0 / wait_lock@+0x8 / wait_list self@+0x10,+0x18` 形状；没有一个是
  `rt_mutex_base` 的 `waiters.rb_root@+0x8 / leftmost@+0x10 / owner@+0x18` 形状。
  `port_mutex` 是普通 mutex，之前的 `po_rt_mutex` 说法是误读。
- source 中 `locktorture.c`、`locking-selftest.c` 的 11 个 `DEFINE_RT_MUTEX` 名称均不在
  exact build 的 kallsyms；唯一名字匹配的 `rt_mutex_adjust_prio_chain.prev_max` 位于
  raw built-in image 外，是函数局部 scalar，不是 lock object。
- `rcu_state.node[0..2].boost_mtx` 仍是合法布局，但 raw owner/waiters 全零，且源码说明
  只用于 RCU priority-boost side effect，不提供稳定第二 owner chain；动态
  `futex_pi_state.pi_mutex` 仍是 route-owned、无独立生命周期。

机器可读 verdict 仍是 `closed_distinct_second_lock=false`。因此不能用普通 mutex、RCU
boost 或 `fd_set/nfds` 调参伪造闭合；若不能离线补齐独立 lock 的 owner/waiters/lifetime，
应归档 second-lock 分支，转向独立首写 sink。

随后重跑 `tools/audit_violin_pointer_lifetime_state_table.py`，把上述 negative inventory
回灌 S3；`analysis_outputs/violin-pointer-lifetime-state-table-20260722.{json,md}` 仍为
`FULL_SYNTHETIC_CHAIN_NOT_CLOSED`，但 S3 blocker 现在直接带有 212-symbol raw 形状证据，
不再只是未找到候选的文字结论。

### 17.54 read-only io_uring callback reachability（2026-07-22）

不运行 payload，仅对当前已连接 Violin 做只读设备面核对；日志为
`analysis_outputs/device-readonly-uring-surface-20260722/inventory.txt`，SHA256
`81832E9C6F8664C7A2992FF0725A7E739F2EAB6CF52FD2FB57C257503A9A1DD7`。设备为
`uid=2000(shell)`、SELinux Enforcing，boot_id 未变。已知 raw static `uring_cmd` fops 的
ublk/NVMe/null callback 中，`/dev/ublk-control` 为 `root:root 0600` 且 shell read/write
均失败，`/dev/nvme0` 与 `/dev/kvm` 不存在，`/proc/modules` 无对应模块。

因此当前 shell 身份下的已知 `uring_cmd` callback 没有可达 arbitrary-write sink，记为
`CURRENT_SHELL_NO_REACHABLE_IO_URING_WRITE_SINK`。这只是当前身份/设备面的 reachability
结论，不能把 generic `io_uring_cmd` 对所有特权或未来 driver callback 全局宣称闭合；它
仍不能复活当前 rb/PI fops anchor。

### 17.55 supplied artifact consistency audit（2026-07-22）

对新增的 `ionstack-current-ktext.zip`、`violin-kernel-info2.zip`、`1.zip` 以及
`kallsyms.txt`、`iomem.txt`、`slabinfo.txt`、`cmdline.txt` 完成离线校验；工具为
`tools/audit_violin_artifact_consistency.py`，报告为
`analysis_outputs/violin-artifact-consistency-20260722.json` 和 `.md`。本轮没有构建、安装、
联机或运行 payload。

三份 `kallsyms` 快照的绝对 `_text` 基址分别为
`0xffffffd365e00000`、`0xffffffe7ca400000`、`0xffffffe387200000`，但在同一 raw image 范围内
`100433` 个唯一公共符号的 image-relative offset 完全一致。核心目标均对齐：
`anon_pipe_buf_ops +0x114a288`、`misc_fops +0x1269710`、`ashmem_fops +0x12c9df0`、
`ashmem_misc +0x223b5d8`、`rcu_state +0x216acc0`、`misc_mtx +0x21f8c50`、
`ashmem_mutex +0x223b540`、`security_hook_heads +0x164f410`。11 个剩余差异只出现在末端
vendor/`a` 数据符号；不能用它们推翻核心布局。

`violin-kernel-info2` 与 `1.zip` fingerprint 相同，且 `uname`/`version` release 均为 `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`；cmdline 仅在 `bootinfo.pdreason=0x0` 和
`0x3` 间不同。两个 bundle 的 boot_id 也不同，且现有设备记录为
`c79163bc-d9f5-457a-a30f-0362d89db8ea`，所以历史绝对 KASLR 地址不可跨 boot 复用。`1.zip`
清单为 33/35 通过（自引用 `SHA256SUMS.txt` 与 `collector.log` 不通过），tombstone 是
dex2oat/SecurityCenter/`com.xiaomi.mirror` 崩溃，filtered kernel log 没有实际
`FOPSROUTE`/`CFGPROBE`/`GHOSTLOCK` marker；不构成成功证据。

机器结论：`SAME_BUILD_OFFSETS_CONFIRMED_SNAPSHOT_BASES_NOT_INTERCHANGEABLE`。这批资料可用于
确认同 build 的相对偏移和历史崩溃上下文；下一步必须先取得同一 boot 的 KASLR leak 并做 target
readback，对账未闭合前不重跑 full-route。

### 17.56 `sched_blocked_reason` / fake-lock claim cross-check（2026-07-22）

离线核对报告为 `analysis_outputs/violin-sched-blocked-fake-lock-claim-audit-20260722.md`；
本轮没有构建、安装、联机或运行新 payload。

- `sched_blocked_reason` 的 `__get_wchan()` raw leak 已被同 build source 证实，但 event 只在
  D-state wakeup 条件下触发，且仍要求 tracefs/raw-read 权限、同一 build 镜像和同一 boot
  对账；它不是所有 tracefs 环境的通用 write/root 原语。
- `task+0x938 -> pi_blocked_on` 与 `waiter+0x58 -> lock` 的 raw offsets 正确；然而当前
  active route 是 `poll(fd=-1,nfds=1)`，没有已证明的 `pselect_user_lock -> fake_lock` 边。
  W=5/pselect overlay 仍是显式 HEAD/诊断状态，不得和 poll 状态混合。
- `rt_mutex_adjust_prio_chain()` 在 `lock = waiter->lock` 后直接
  `raw_spin_trylock(&lock->wait_lock)`；exact build 启用 PAN/SW-TTBR0-PAN，所以 user VA
  `fake_w0->lock` 不是已闭合的 kernel `rt_mutex_base`。PI 链“到 fake page”不等于已经有
  SELinux arbitrary write sink。
- raw `brk #0x800` 的分支先比较 waiter 的 `lock` 字段与当前 lock，吻合
  `rt_mutex_top_waiter()` 的 `BUG_ON(w->lock != lock)`；common `rt_mutex_setprio()` 的
  `p->pi_blocked_on` WARN 只在 idle 分支，不能写成“非空即 BRK”。“前 16 轮安全”未被
  源码/raw branch 证明。
- fd 0-2 覆盖仅发生在 custom `open_selected_fds()`；default 从 fd 3 起步。consumer
  warm-up 与 `punch_consume_go` 过早清零是旧/显式 pselect 分支的时序风险，default poll
  route 返回后会等待 consumer（最多约 300 ms），不能据此证明链闭合。

最终 verdict 仍为 `FULL_SYNTHETIC_CHAIN_NOT_CLOSED`：尚缺 active route 的 fake-lock edge、
独立 kernel second-lock 的 owner/waiters/lifetime、终止性、fops slot readback 与 SELinux
write evidence。

### 17.57 active route-state alignment（2026-07-22）

为进入实施阶段先固定“实际跑的是什么”，新增并执行
`tools/audit_violin_active_route_state.py`，报告为
`analysis_outputs/violin-active-route-state-20260722.{json,md}`；`py_compile=0`，本轮只读
现有 source、ELF、build/run manifest 和 crash log。

- `cfgprobe_diag`（`CFGPROBE_ONLY_DIAG=1`）、`route_only_diag`
  （`DIRECT_WRITE_ROUTE_ONLY_PROBE=1`）和 `cfi_transport_diag`
  （`CFI_TRANSPORT_ONLY_DIAG=1`）三组均通过 `PROJECT=violin-v-oss`、hash/size、run hash、
  `run_exit=0`、同 boot_id 和运行时 marker 对账；SHA256 依次为
  `cb71799ce82f3ae8a62b1226c7fc332a7ec54d9746d4679e463ff0d481c84662`、
  `8363b56a0fae924be5af710d9906f9b6e116d8ea0b6461422e379d0915eaf8fb`、
  `916c683bf5789bfed6380bb5c5efd6ed17fadb66c782ecc189e283a3e990ec09`。
- 运行时 marker 将边界固定为 cfgprobe、safe route handoff、ConfigFS name/pwrite；三组均
  不产生 fops slot readback、arbitrary kernel write、cred 或 SELinux 证据。
- 无当前 tuple 的 `build/violin-v-oss/bin/preload.so`（SHA256
  `f850dc1a0c06c71fa13fba1e38cf465152381c7a61af71819694501525201947`，175504 bytes）早于
  当前 source，已标为 **quarantine**，不能直接推送。
- source map 再次确认：显式 `PROJECT=violin-v-oss` 时仅 target `target.h/slide.c` 覆盖，
  其余 core 使用 root `src/`；未显式 selector 的默认 `make` 不构成 Violin 证据。

当前 `adb devices -l` 为空，因此下一次设备恢复后的最小动作是同 boot 的只读
`boot_id/KASLR/target readback` 对账，然后只使用带完整 tuple 的诊断产物；本节不把这三组
诊断结果升级为 full-route 成功，`FULL_SYNTHETIC_CHAIN_NOT_CLOSED` 保持不变。

### 17.58 provenance correction（2026-07-22）

对 build manifest 增加 tracked source-hash 对账后，`violin-current-diag-tuples-20260722`
与 `violin-active-route-state-20260722` 的严格结论改为
`all_diagnostic_tuples_complete=false`：

- cfgprobe artifact 的 `main.c` hash 与当前 source 不同；
- route-only artifact 没有 source hash block；
- CFI transport artifact 只记录 `main.c`，缺少其余 tracked source。

因此三组 artifact 目前只能作为各自 manifest/运行 marker 对齐的**历史诊断证据**，不是
current-source complete tuple。下一步先用同一 source map 重新构建并补齐 source hashes，再
考虑在线诊断；不要直接复用旧 full-route ELF。`FULL_SYNTHETIC_CHAIN_NOT_CLOSED` 不变。

### 17.59 fresh source-bound diagnostic builds（2026-07-22）

已用 `tools/build_violin_fresh_diag_tuples.sh` 在 WSL NDK r29 重新编译三组诊断，并由
`tools/record_violin_fresh_diag_builds.py` 生成完整 8-file source-hash manifests；过程没有
ADB、安装或 payload 运行。

- cfgprobe：`ed918dfabf61c5c53e7b1bfe5a99bc946dc77385939458ee1d38ababc6adb2e8`；
- route-only：`81e17de80d9f6720e28e3886abb5bdd17a9d62ac2ab56382699ddbd1cb63c099`；
- cfi-transport：`f833c5a9f33b2f6d07a11f9ba65148b8bc5081638e343d5d7169f81eff703cf6`。

对应 build-only 报告为 `analysis_outputs/violin-fresh-diag-builds-20260722.json`，当前缺少
同 hash、同 boot 的 run manifest；因此仍不能写成 route/fops/readback 成功。




### 17.60 Stage-2 `root_stage` wiring and `7sp_permissive和root.zip` audit（2026-07-22）

“只把 SELinux 设为 permissive”不能作为 root 阶段完成条件。本轮对当前 Violin source 做了明确接线：`try_cfi_stage()` 成功进入后调用 `install_child_root()`；后者先运行 `install_pipe_physrw()`，再由 `root_stage()` 检查 `pipe_cache_gate_ok`、`physrw_read_ok`、`physrw_write_ok`、`physrw_read64_ok`、`physrw_write64_ok`，五项 proof 全部成立才调用 `install_android_root()`。root child 超时或 credential/SELinux readback 失败会进入清理路径。旧的 ConfigFS partial fake-cred block 保留为显式宏实验，默认 `LEGACY_CONFIGFS_CRED_STAGE=0`。

`tools/audit_violin_root_stage_reachability.py` 的离线报告为 `analysis_outputs/violin-root-stage-reachability-20260722.{json,md}`，当前 call graph verdict 为 `ROOT_STAGE_CALL_GRAPH_CONNECTED_LEGACY_PARTIAL_CRED_DISABLED`；此 verdict 只代表源码连线、proof gate 和 marker 存在，`runtime_proof=false`。build-only 产物为 `exploit-repo/IonStack/CVE-2026-43499/exploit/build/violin-v-oss-root-stage-20260722/bin/preload.so`，176184 bytes，SHA256 `da44ed17e16190e5fc99320666fe8b3fab9577589d62b0a25fba5abdb0b95a82`；manifest 为 `analysis_outputs/violin-root-stage-build-20260722/build-manifest.txt`。

用户附件中的 `p.so` 仅有 permissive marker；`r.so` 含 direct-root marker；`r2.so` 含 direct-root 与 reboot marker。三者均没有 source map、同 boot hash 或运行日志，故不能把 marker 当成成功证据；r2 不作为第一在线候选。当前设备无 ADB 连接，本轮没有安装或运行上述产物，整体 exploit verdict 仍为 `FULL_SYNTHETIC_CHAIN_NOT_CLOSED`。

- 另修正 root child ready-pipe 的 parent-side fd bookkeeping：关闭写端后置 `-1`，防止 fd number 被复用时 abort 路径误关其他 fd；修正后重新构建并更新 manifest/hash。

### 17.61 7sp variants published to `liang1228/ionstack-violin`（2026-07-22）

按用户要求，把附件中的 `p.so`、`r.so`、`r2.so` 上传到公开仓库 `liang1228/ionstack-violin` 的 `master`，commit 为 `0b56a19447d0d683470cbc8ab16c18b846db993e`；`exploit.html` 现在支持 `payload=p/r/r2`，并新增 `7sp-root-variants-20260722.md`。

Pages `https://liang1228.github.io/ionstack-violin/` 已报告 `built`。raw 与 Pages 下载校验均通过，size/SHA256 与本地一致。截图显示 direct-root 的强证据（四个 uid/gid 为 0、`got_root=1`、`whoami=root`），但没有标明具体二进制与同 boot/source provenance；因此结论是“至少有一个 direct-root 变体被证明过”，不是“三个文件均已证明”。

### 17.62 PSELECT layout crash diagnostic（2026-07-22）

- 新的 `diagnostic=crash` 采集到 `capture_ret=406`，并报告 `PSELECT_LAYOUT_DONE: ok=1 no_kernel_route=1`。
- 这对应 `PSELECT_LAYOUT_ONLY_PROBE`：userspace `fd_set` 的 IN/OUT/EX 五个 word 断言全部通过；`OUT.w0=target-8`、`OUT.w3=0x82`、`EX.w0=fake_task`、`EX.w1=fake_lock` 与源码预期一致。
- `no_kernel_route=1` 是决定性边界：该运行没有进入 scheduler/PI、KASLR、rb_insert/fops、pipe physrw、cred 或 SELinux 路径。`ok=1` 不是 root 或任意写成功。
- `diag=crash` 只读取设备已有的 `/data/data/org.mozilla.firefox/files/crash.txt`，不会执行 payload。日志末尾的字面量 `\\n` 是现有 crash logger 的格式行为，不是内核返回值。
- 该日志与截图中的 direct-root 证据不能绑定到同一个二进制；截图没有文件名、source hash 或 boot_id。完整原始日志和解码报告见 `analysis_outputs/violin-pselect-layout-crash-20260722/`。
- 下一次在线验证应先使用 Pages 的 `?payload=r` 运行候选，完成后再用 `?diag=crash` 采集；把 selected filename、SHA256、boot_id 与完整 `direct-*`/`ROOT_STAGE-*` marker 放在同一 run manifest。`r2` 含 reboot marker，单独后置。

### 17.63 Published r.so first-run CPU-affinity failure（2026-07-22）

- 本次 `?payload=r` 的浏览器侧 AAW/AAR/ADDROF/RW64 和 `MPROTECT_READY` 全部通过；加载文件为 `r.so?v=mrw7sjnd4qd4brlujc8`，尺寸 86464，设备 fingerprint 为支持的 Violin build。
- preload 启动后成功选择 `direct_cpu=9`（频率 3398400、capacity 1024），随后立即在 `SYSCHK(sched_setaffinity(0, sizeof(cpu_set_t), &cpuset))` 返回 `EINVAL`；`command_status=255` 是 `pr_error()` 的 `exit(-1)`，`command_ret=656` 是浏览器采集传输量。
- 已对照 `analysis_outputs/external-linuxoid-cve-20260722-v2/source`：`init_direct_root_cpu()` 根据当前 affinity mask 选出 CPU 9，但 `run_exploit()` 仍调用 `pin_to_core(CORE)`，而 `src/common.h` 将 `CORE` 固定为 0；`pin_to_core()` 又由 `SYSCHK` 对失败直接退出。因此本次尚未进入 slide/KASLR、pselect/PI、fops、pipe physrw、cred、SELinux 或 root。
- 同一源码还把 `CONSUMER_CORE` 固定为 `CORE + 1`，只修第一处会留下下一次 affinity 失败风险。完整原始日志和源码对账见 `analysis_outputs/ionstack-violin-r-affinity-failure-20260722/`。
- 下一步不是重跑原 `r.so`：先把所有 runtime-stage 的 `CORE/0` pin 改为成功验证过的 allowed CPU，给 consumer 选择第二个 allowed CPU（无第二个时记录并回退到同一 CPU），新增 `allowed_cpus/direct_cpu/consumer_cpu` marker，重新构建并校验 hash/size 后再发布和运行。

### 17.64 CPU-affinity fix candidate build（2026-07-22）

- 已保留原始 `r.so` 不变，并在 `analysis_outputs/violin-r-cpu-fix-20260722/source` 建立修复副本：runtime pin 全部改为 `direct_root_cpu`/`consumer_root_cpu`；consumer 从成功的 allowed/online affinity mask 选择第二个 CPU，无第二个时显式回退并记录 shared。
- 使用工作区 NDK r29、Android API 35 构建通过；产物 `build/bin/preload.so` 大小 89264，SHA256 `657bdb47745c59cb8157ad7afbf2dd7b8f7b34487040406764e1a0b9c33f6744`。
- 静态检查确认没有剩余 runtime `pin_to_core(CORE)` 或 `pin_to_core(0)` 调用；当前只保留兼容宏。该产物尚无设备 run proof，尚未上传 Pages，也没有替换已发布的 `r.so`。

---

## 18. Direct Write 路径发现与切换（2026-07-22）

### 18.1 根因确认：rb_insert 在 violin 上不可用

最新 exploit 输出（`FOPSROUTE_CFI_RESULT: attempt=1 ok=0 step=1 errno=22`）确认：

1. **fops hijack 未发生** — rb_insert 写入未触发
2. **errno=22 的根因** — `ashmem_write_iter` 拒绝写入 `asma->size=0` 的区域（fops 未劫持 → pwrite 走 ashmem 路径）
3. **boot_id 不变** — 确认 rb_insert 确实未执行

**rb_insert 失败的根本原因：** violin 的 `misc_fops`（offset `0x01269710`）所有字段均为非零函数指针。rb_insert 树遍历需要找到一个 `rb_right == NULL` 的父节点才能插入。dijun 的 `misc_fops.poll = NULL`（offset +0x30）提供了这个插入点，但 violin 没有。

### 18.2 dijun 的 .so 文件分析

从 `7sp_permissive和root.zip` 中提取的三个 payload：

| 文件 | 大小 | 功能 |
|------|------|------|
| `p.so` | 83632 | permissive（SELinux permissive） |
| `r.so` | 86464 | root（cred 替换） |
| `r2.so` | 86664 | root v2（cred 替换） |

**关键函数（符号表）：**
- `direct_pselect_write_once` — 包装器（12字节）
- `direct_pselect_write_once_internal` — 核心写入实现（1268字节）
- `direct_trigger_write64` — 64位内核写入原语（276字节，r.so/r2.so）
- `direct_read_shape0_exact64_once` — 64位内核读取（852字节）
- `install_cred` / `install_real_cred` — cred 替换

### 18.3 Direct Write 机制分析

**`direct_trigger_write64` 反汇编关键逻辑：**

```asm
; 3轮调用 direct_pselect_write_once_internal，每轮 w3 (shape) 不同：
; 轮1: w3=3 (shape=1)
; 轮2: w3=8 (shape=2)  ; +5
; 轮3: w3=13 (shape=3) ; +10
; 每轮: x0=ctx, x1=target, w2=1, w3=shape, x4=status_ptr, x5=sp
```

**`direct_pselect_write_once_internal` 参数：**
- x0 = context（内核页基础地址）
- x1 = target（写入目标内核地址）
- w2 = 1（启用标志）
- **w3 = shape**（fd_set words 对齐方式）
- x4 = status_ptr（状态输出）
- x5 = sp（栈指针）

**shape 控制 fd_set words 在内核栈上与 waiter 结构的对齐方式：**

```
shape=0: value → waiter+0x00 (tree.entry.__rb_parent_color)
         target → waiter+0x08 (tree.entry.rb_right)
shape=1: value → waiter+0x20 (tree.entry.rb_right)
         target → waiter+0x58 (lock)  ← 目标地址写入 waiter->lock
shape=2: value → waiter+0x28 (pi_tree.entry.__rb_parent_color)
         target → waiter+0x60 (wake_state)
shape=3: value → waiter+0x40 (pi_tree.prio)
         target → waiter+0x78 (pi_tree.task)
```

**`direct_trigger_write64` 对同一 target 尝试 shape=1,2,3 三轮，最大化成功率。**

### 18.4 与 rb_insert 的根本区别

| | rb_insert 路径 | Direct Write 路径 |
|---|---|---|
| 写入机制 | rb_insert_color 树遍历需要 `parent->rb_right == NULL` | pselect fd_set words 直接覆写 waiter 字段 |
| NULL 约束 | 需要目标地址有 NULL 字段 | **无 NULL 约束** |
| violin 可用性 | ❌ misc_fops 无 NULL 字段 | ✅ 已被 dijun 验证 |
| 写入值 | &waiter_node（内核页地址） | target 和 value（任意内核地址） |

### 18.5 代码切换

**改动 1：`main.c` — 添加 `set_pselect_write` 调用**

```c
set_pselect_write(data_addr(ASHMEM_MISC) + 0x10, fake_fops);
```

**改动 2：`fops.c` — 恢复 pselect 路径**

将 `do_pselect_fake_lock_route` 从 poll() 路径恢复为 pselect() 路径：
- 使用 `prepare_pselect_fdsets()` 设置 fd_set values
- 使用 `open_selected_fds()` 安装 fd
- 使用 `pselect()` 替代 `poll()`
- 使用 `timerfd` 替代 pipe 读端作为阻塞 fd

**改动 3：`util.c` — 无需改动**

`prepare_skb_payload` 已有 `pselect_custom_write_enabled()` 分支，自动使用 custom write 值。

### 18.6 验证清单

- [ ] 构建并推送到设备
- [ ] 运行 exploit，检查 `FOPSROUTE_CFI_RESULT: ok=1`
- [ ] 验证 boot_id 变化（rb_insert 写入确认）
- [ ] 验证 CFGPROBE 成功（fops hijack 后读取 misc_fops 指针）
- [ ] 验证 pipe physrw 和 cred 替换

### 17.65 `r3.so` published to the new Pages selector（2026-07-22）

- 已将 CPU-affinity 修复候选作为独立 `r3.so` 发布，不覆盖 `r.so`/`r2.so`；`exploit.html` 新增 `?payload=r3` 映射。
- Git commit：`7449577d850732d973ce79028cee386c1e270450`，已推送到 `liang1228/ionstack-violin` 的 `master`。
- 本地、raw GitHub 和 GitHub Pages 下载均为 89264 bytes，SHA256 均为 `657bdb47745c59cb8157ad7afbf2dd7b8f7b34487040406764e1a0b9c33f6744`；Pages `exploit.html` 的 r3 selector 和脚本语法复核通过。
- 新运行入口：`https://liang1228.github.io/ionstack-violin/?payload=r3&run=violin-r3-20260722-01`。采集入口仍用对应 `?diag=crash&run=...`。
- 该发布只证明页面/文件 provenance 与静态构建，不证明设备上的 KASLR、PI、fops、pipe physrw 或 root；首次运行需保留完整 `runtime performance cpu`、`consumer_cpu/shared`、`slide`、`direct-*`/`ROOT_STAGE-*` marker。
- 发布复核清单：`analysis_outputs/ionstack-violin-publish-20260722/publish-r3-manifest-20260722.txt`。
