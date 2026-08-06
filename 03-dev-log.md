# xiaomi-root 开发日志

## 2026-07-11 15:12 +08:00 full OTA 包解析与内核基准切换

### 输入

- 用户提供完整 OTA：`E:\workspace\projects\xiaomi-root\violin-ota_full-OS3.0.303.0.WOTCNXM-user-16.0-9a8ce5da78.zip`
- ZIP SHA256：`23C0171B9868DFFEB1BFDDC26B936D001CC9FA2613343A127459E0E87E20D011`

### 已完成

- 解析 OTA `payload.bin` manifest：共 38 个分区。
- 选择性重建关键分区到：`analysis_outputs\ota_full\partitions\`
  - `boot.img` SHA256 `AF4D00C69704B18E50F6E50F4B7844B4870E616510C03F7BE37688D18005BBD8`
  - `init_boot.img` SHA256 `3B19DCF7F1D0DD284E126682609CE2BF36BC010CF6A980D4A348848E09BDB2E0`
  - `vendor_boot.img` SHA256 `57F8E7C9200EAB04D6BFC32D85F0D139D5360EE8D88ADE43F520FA7F720CE240`
  - `vendor_dlkm.img` SHA256 `BA69409CA4B7B6FE510DCBD14DFB3542EA22B621E9EA51EAB697227300065E82`
  - `system_dlkm.img` SHA256 `D70DFF02F146C5DF291193A963E4FBDE02614D7085DED96920547DB88B74E881`
  - `odm_dlkm.img` SHA256 `1C90B1886F3EBB7F5D5153D8A236165A3B131CE5F293C35DB7E19BB2460A2851`
- 解出 boot image 内容到：`analysis_outputs\ota_full\boot_parse\`
  - `boot.img.kernel`：36,456,960 bytes，SHA256 `9552098B7FADBB2F6375252F69A47DC132AB36CEC3290F5219C8103DCE064D33`
  - 版本串：`Linux version 6.6.77-android15-8-g5770c661275f-abogki443185593-4k ... Thu Sep 4 08:11:25 UTC 2025`
  - `vendor_boot.img.dtb`：180,674 bytes，SHA256 `5DDC32EFC5A323A3A07617A5CD567F7D54C9B4EF1FC0EC98803712F0C4309BAA`
- 解出 ramdisk / DLKM 到：`analysis_outputs\ota_full\extracted\`
  - 共 846 个文件、782 个 `.ko`。
  - `system_dlkm` 中 `kheaders.ko` 可用，`vermagic=6.6.77-android15-8-g5770c661275f-abogki443185593-4k`。
  - 已从 `kheaders.ko` 提取头文件树到：`analysis_outputs\ota_full\kheaders\`。
  - `kheaders` 中存在 `include/generated/autoconf.h`、`include/generated/asm-offsets.h`、`include/linux/sched.h`、`include/linux/rtmutex.h`，后续可用于 fake task / rt_mutex 结构体审计。

### 关键新结论

- 旧文件 `E:\workspace\kernel.decompressed` 与 full OTA 提取的 `boot.img.kernel` **大小相同但 SHA256 不同**。
- 差异从偏移 `0x9ff000` 开始，旧 `kernel.decompressed` 在大量后续区域为 0，且找不到 `Linux version` 字符串。
- 因此旧 `E:\workspace\kernel.decompressed` 不应继续作为 OS3.0.303.0.WOTCNXM 的静态分析基准；后续应改用：
  - `E:\workspace\projects\xiaomi-root\analysis_outputs\ota_full\boot_parse\boot.img.kernel`
  - `E:\workspace\projects\xiaomi-root\analysis_outputs\ota_full\kheaders\`

### 下一步建议

- 用 full OTA 的 `kheaders` 重新审计 `task_struct` / `rt_mutex_waiter` / `rt_mutex_base` / `rb_node` / `rb_root_cached` 相关布局。
- 如果要继续解释 `init_task + 0x90c`、`pi_lock`、`pi_waiters`、`pi_top_task` 路径，应优先基于新 `kheaders` 和 full OTA kernel，而不是旧 `kernel.decompressed`。

## 2026-07-11 kheaders PI 偏移修正后的安全基线与 reboot 结论

- full OTA `kheaders` 实测 `task_struct.pi_lock/pi_waiters/pi_top_task/pi_blocked_on` 为 `0x90c/0x920/0x930/0x938`，已修正 `target.h`。
- `stable0-faketask-khdrpi`（SHA256 `272FB4FB7E96075DD8AE6DA9E4CE08F227CD55DF2DBA0084AE6A499E4AB0BF5A`）可无 reboot 通过 `sched_setattr`、`pselect` 与 slide route，但 boot_id 仍为 UUID，尚未泄漏内核地址。
- `caimanwords-khdrpi-faketask`（SHA256 `E737AB30F94607C8CCAE465DF1ADC71D19D8604D84DE49906CB32A93F58AC0A9`）会 reboot；不要作为默认测试包。
- 后续以 stable0 + kheaders 真实 PI offsets 为唯一安全基线，tree/PI/tail 字段一次只改一个变量。继续连设备前，先将 `exploit-site/exploit.html` 从 caiman artifact 切回 stable0 artifact。

## 2026-07-11 16:01 安全基线回归尝试：页面确认门阻断了自动化

### 本轮配置与部署确认

- 已将 `exploit-site/exploit.html` 默认 artifact 从 caimanwords 恢复为：
  - `preload-local-violin-stable0-faketask-khdrpi.so`
- HTML、PC 本地 HTTP 返回和 artifact SHA256 均确认是：
  - `272FB4FB7E96075DD8AE6DA9E4CE08F227CD55DF2DBA0084AE6A499E4AB0BF5A`
- 回归配置已写入：
  - `tools/device-regression-stable0-khdrpi.json`

### 真实运行证据

回归目录：

- `outputs/device-regression/run-20260711-160148/`

本轮 outer page 与 iframe 确实被设备拉取：

- `GET /?v=violin-stable0-faketask-khdrpi&rr=01&ts=1783756909`
- `GET /exploit.html?run=mrg2t4vjdwdivqym5h&attempt=1`
- `GET /exploit.html?run=mrg2t4vjdwdivqym5h&attempt=2`

但在自动化窗口内没有看到 `.so` fetch 或新的 remote crash/log 文件；boot_id 保持：

- `4a37950b-45de-4297-8769-b1b50fdeaacf`

随后 UI Automator 明确观察到 Firefox 的两级确认弹窗：

1. “Your device is supported, but it may reboot. Continue?”
2. “Are you sure? Save your work before clicking OK.”

这解释了回归脚本无法自主走到 payload：它目前只负责启动/采证，不会处理浏览器确认 UI。手动发送两次“确定”后弹窗消失，但随后的约 20 秒内仍未出现 payload fetch；因此当前不能把这轮标为 stable0 成功复现，也不能把它当成崩溃。

## 2026-07-11 16:27 E1 实验构建：tree_entry RED 颜色位 + 诊断日志修复

### 实验设计

- **实验名称**：E1 — RED color bit on `tree_entry.__rb_parent_color`
- **假设**：stable0 中 `__rb_parent_color` 的颜色位为 BLACK(0)，rb-tree 插入后不触发 `rb_insert_color` 再平衡，因此 `sysctl_bootid` 的覆盖写入从未发生。
- **单变量变更**：仅将 tree_entry 的 `__rb_parent_color` 值从 `SLIDE_LOGGERS_0_1` 改为 `SLIDE_LOGGERS_0_1 | 1`（设置 RB_RED），pi_parent 保持 BLACK。
- **控制宏**：`VIOLIN_SLIDE_RED_TREE_PC=1`、`VIOLIN_SLIDE_RED_PI_PARENT=0`（`target.h:49-50`）
- **其他参数**：与 stable0 完全一致（tree_shift=0, pi_shift=0, tail_shift=0, base=1, fake_task=1）

### 代码变更

- `src/slide.c`：
  - 新增 `VIOLIN_SLIDE_RED_TREE_PC` / `VIOLIN_SLIDE_RED_PI_PARENT` 条件宏
  - words[0]（tree_pc）值通过 `| (VIOLIN_SLIDE_RED_TREE_PC ? 1ULL : 0ULL)` 控制 RED 位
  - words[3]（pi_parent）同理
  - 修复 `SLIDEP1_LAYOUT` 日志：之前 tree/pi/tail 硬编码为 `0,0,0`，现打印实际 shift 值与 red_tree/red_pi 标志；日志移至 `prepare_slide_pselect_fdsets()` 内部以访问局部变量
- `src/targets/violin-v-oss/target.h`：
  - 更新注释说明 E1 实验背景
  - 新增 `VIOLIN_SLIDE_RED_TREE_PC 1`、`VIOLIN_SLIDE_RED_PI_PARENT 0`

### 构建与部署

- 构建命令：`MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash /mnt/e/workspace/projects/xiaomi-root/build_e1_experiment.sh`
- 编译器：Android NDK r563880c clang 21.0.0（`/tmp/ndk/`）
- 产物：`outputs/preload.so` → `exploit-site/preload-local-violin-e1-redtreepc.so`
- 大小：221,000 bytes
- SHA256：`E95225C34340ECF8DEAAFECD55343F019437C5B5BC320322817C347CEBFE5DDC`

### 安全注意事项

- RED 位可能触发 kernel 在 fake parent（`loggers[0]`）上做 rb-tree 再平衡，导致读取 `loggers[0]->__rb_parent_color`（即 `nf_loggers[0]` 指向的地址）作为 grandparent rb_node。若该地址不是有效 rb_node，可能 panic。
- 这是单变量实验，若 reboot 应立即停止继续此方向。

## 2026-07-11 17:30 E1+E2+E3 实验结果汇总

### 实验结果

| 实验 | CMP_REQUEUE | boot_id | 设备 | 结论 |
|------|-------------|---------|------|------|
| stable0（原始） | errno=35 (EAGAIN) | UUID | 无 reboot | requeue 失败，write 不触发 |
| E2（cmpval 修复）attempt=1 | **errno=0** | UUID | 无 reboot | requeue 成功，但 lock->owner=0，PI chain walk 终止 |
| E2 attempt=2 | errno=35 | UUID | reboot | 时序竞态 |
| E3（lock owner）attempt=1 | **errno=0** | UUID | reboot(attempt=2) | lock->owner 设置正确，PI chain walk 触发 rb_erase |
| E1+E2+E3（RED+cmpval+owner）attempt=1 | errno=35 | ? | reboot | sched_setattr 触发 crash，__rb_parent_color=RED 导致 rb_erase 尝试再平衡 |

### 关键发现

1. **E2 修复了 requeue**：`expected_val = TID | (1<<30)` 使 CMP_REQUEUE_PI 成功率从 0% 提升到约 50%（时序竞态）
2. **lock->owner 设置是 PI chain walk 的开关**：owner=0 时 chain walk 立即终止；owner=fake_task 时 chain walk 继续到 rb_erase
3. **rb_erase crash 发生在 `loggers[0]` 解引用**：__rb_parent_color 指向 loggers 数组，但 loggers 不是有效的 rb_node → rb_erase 访问 loggers[1]/loggers[2] 作为 rb_node 子指针时触发 page fault
4. **pselect ret=0 是正常的**：fd_sets 在 pselect 返回前已复制到内核栈

### 下一步方向

核心问题是：**如何让 rb_erase 成功写入 sysctl_bootid 而不 crash？**

当前的 rb-tree 布局：
- `pi_tree_entry.__rb_parent_color = SLIDE_LOGGERS_0_1 | RED`（指向 loggers 数组作为 fake parent）
- `pi_tree_entry.rb_left = SLIDE_RANDOM_BOOT_ID_DATA`（sysctl_bootid 地址）
- `pi_tree_entry.rb_right = 0`

rb_erase 需要从 parent（loggers[0]）读取子节点，但 loggers 不是有效的 rb_node。

**可能的修复方向：**
1. **设置 `SLIDE_STAGE0_LOCK_SHAPE=1`**（caiman 风格）：使用不同的 lock 布局
2. **调整 __rb_parent_color 指向真正的 rb-tree 节点**：不指向 loggers，而是指向目标 futex 的 PI tree 中的真实节点
3. **使用 `pselect_custom_write_enabled()` 路径**：在 pselect 中直接写入目标地址
4. **先用 CFGPROBE 获取 KASLR slide**：绕过 slide leak，直接计算内核地址

## 2026-07-11 16:45 kmsg 分析：确认 pselect 数据被内核使用 + CMP_REQUEUE_PI 时序问题

### 关键发现

从 `run-diagnostics-20260710` 的 `last_kmsg` 中提取到 caimanwords 版本的内核崩溃完整 call trace：

```
Unable to handle kernel paging request at virtual address ffffff9360136f58
Call trace:
  rb_erase+0x8c/0x2fc
  rt_mutex_adjust_pi+0xcc/0x1a0
  __sched_setscheduler+0x934/0xb40
  __arm64_sys_sched_setattr+0x368/0x45c
```

**寄存器确认目标地址被使用：**
- `x9 = 0xffffff935fed21b8` — 低 16 位 `21b8` 匹配 `SLIDE_LOGGERS_0_1`（loggers 数组地址）
- `x10 = 0xffffff9360136f58` — 低 16 位 `6f58` 匹配 `SLIDE_RANDOM_BOOT_ID_DATA`（sysctl_bootid 地址）

这证明 pselect 确实将 fd_set 数据复制到了内核栈上的 waiter 结构体中，内核的 `sched_setattr` → `rt_mutex_adjust_pi` → `rb_erase` 路径确实在使用我们构造的值。崩溃发生在 `rb_erase` 尝试解引用 `sysctl_bootid` 地址（当作 rb_node）时。

### stable0 的真正卡点

从 stable0 crash log 看到的时序问题：

```
SLIDEC3: after FUTEX_CMP_REQUEUE_PI errno=35 (EAGAIN)
SLIDEW3: after FUTEX_WAIT_REQUEUE_PI errno=110 (ETIMEDOUT)
```

- `FUTEX_CMP_REQUEUE_PI` 带 `expected_val=1` 检查 `*slide_f_wait == 1`
- 但 `FUTEX_WAIT_REQUEUE_PI` 已将 `slide_f_wait` 设为 `TID | FUTEX_WAITER_BIT`（远大于 1）
- 因此 `CMP_REQUEUE_PI` 几乎总是返回 EAGAIN（attempts 1-2）
- waiter 从未被成功 requeue 到 target futex 的 PI tree
- pselect 覆写 waiter 字段后，没有内核代码路径处理这些值

**attempt 3 的异常成功：** `CMP_REQUEUE_PI errno=0` — 可能是时序竞态使得 CMP_REQUEUE_PI 在 WAIT_REQUEUE_PI 完成锁定前运行。此时 waiter 被成功 requeue，sched_setattr 触发了 PI chain 走查 → rb_erase → 崩溃（caimanwords 的 PI offset 不对）。

### 结论

pselect 机制本身在 violin 上是有效的。问题有两层：
1. **stable0 层**：`FUTEX_CMP_REQUEUE_PI` 的 `expected_val=1` 与实际 futex 值不匹配 → requeue 失败 → write 不触发
2. **caimanwords 层**：requeue 成功但 waiter task/lock/PI offset 不对 → `rb_erase` 访问无效地址 → panic

E1 实验（RED 位）在 stable0 下可能不会触发任何变化（因为 requeue 本身就失败了）。**更优先的修复方向是 `expected_val` 问题** — 这才是 stable0 slide route 走完但无写入的根因。

### 下一步建议

1. **E1 先跑一次**：即使 requeue 失败，RED 位可能在某些时序下改变行为，值得快速验证
2. **E2：修复 expected_val**：将 `FUTEX_CMP_REQUEUE_PI` 的 expected_val 从固定 `1` 改为动态读取 `slide_f_wait` 的当前值，或改为 `0`（无锁状态），使 requeue 更容易成功
3. **E3：requeue 成功后验证**：在 E2 基础上观察是否能稳定进入 `rb_erase` 路径，并根据崩溃寄存器调整 waiter 字段

## 2026-07-12 18:50 字符设备审计结果

### 测试的设备

| 设备 | 权限 | 结果 |
|------|------|------|
| `/dev/mali0` | `rw-rw-rw-` | EPERM (SELinux) |
| `/dev/io_monitor` | `rw-rw-rw-` | EPERM (SELinux) |
| `/dev/camlog` | `rw-rw-rw-` | EPERM (SELinux) |
| `/dev/ashmem` | `rw-rw-rw-` | 可读但 name buffer trick 不支持 |

### 当前状态

所有已知的 canonical KASLR leak 方法都失败。需要：
1. 找到绕过 SELinux 的方法
2. 或修复 slide leak（解决 `task_has_pi_waiters` 问题）
3. 或尝试完全不同的攻击面

### 结果

所有 `/dev/mali0` ioctl 命令返回 `EPERM (Operation not permitted)`。SELinux 阻止了 `u:r:shell:s0` 上下文的 ioctl 访问。

### 当前卡点总结

| 方法 | 结果 | 原因 |
|------|------|------|
| slide leak (rb-tree) | ❌ | `task_has_pi_waiters` 返回 false |
| CFGPROBE (ashmem) | ❌ | GKI 6.6 不支持 name buffer trick |
| pagemap | ❌ | 全 0，安全限制 |
| mali ioctl | ❌ | SELinux 阻止 ioctl 访问 |
| dmesg/cmdline | ❌ | 需要 root |

### 下一步

1. **尝试其他字符设备**：ashmem、XRing 节点
2. **或尝试修复 slide leak**：解决 `task_has_pi_waiters` 问题
3. **或尝试完全不同的方法**：如利用 Firefox 漏洞或其他攻击面

### 关键发现

从 `rtmutex_common.h:142` 确认：
```c
static inline int task_has_pi_waiters(struct task_struct *p) {
    return !RB_EMPTY_ROOT(&p->pi_waiters.rb_root);
}
```

`rt_mutex_adjust_prio_chain` 在 line 786 检查 `task_has_pi_waiters(task)`。如果返回 false，函数直接退出，不执行 rb-tree 操作。

### 为什么 waiter 线程没有 pi_waiters？

Waiter 线程持有 `slide_f_pi_chain`（通过 FUTEX_LOCK_PI）。但没有人等待这个锁。Owner 线程尝试 `FUTEX_LOCK_PI(&slide_f_pi_chain)` 时返回 `errno=13 (EACCES)`，没有成功阻塞。

```
SLIDEO1: owner started, lock chain
SLIDEO2: owner chain lock returned errno=13
```

### 根因链

1. Waiter 持有 `slide_f_pi_chain`，但无人等待 → `pi_waiters` 为空
2. `task_has_pi_waiters(waiter_thread)` 返回 false
3. `rt_mutex_adjust_prio_chain` 在 line 786 退出
4. rb-tree 写入不触发
5. `boot_id` 仍是 UUID

### 下一步

1. **让 owner 成功阻塞在 `slide_f_pi_chain`**：修复 EACCES 问题
2. **或让 waiter 持有另一个有人等待的锁**
3. **或绕过 `task_has_pi_waiters` 检查**：使用不同的 exploit primitive

### E25：consumer 线程跳过 sched_setattr

- **问题**：EDEADLK rollback 后内核状态被破坏，`sched_setattr` 挂起导致设备重启
- **修复**：添加 `slide_uaf_primed` 和 `slide_consume_stop` 信号，consumer 线程在检测到信号后跳过 `sched_setattr`
- **结果**：设备不再重启 ✅

### E26：CMP_REQUEUE_PI 成功后 break

- **问题**：CMP_REQUEUE_PI 成功（ret=0）后代码继续重试，第二次触发 EDEADLK
- **修复**：`ret==0` 时立即 break
- **结果**：有一次 requeue 成功且没有 EDEADLK

### 关键发现

```
SLIDEC2: CMP_REQUEUE_PI retry=0 ret=0 errno=0
SLIDEC2_OK: requeue succeeded at retry=0
SLIDEC2_NO_ROLLBACK: requeue succeeded without EDEADLK
SLIDECONS0: before sched_setattr tid=23748 nice=1 call=1
SLIDECONS1: after sched_setattr ret=0 errno=13
SLIDER1: boot_id d5103b5a-9c68-4158-90f7-c0a1190151e0  ← 仍是 UUID
```

**即使 requeue 成功且没有 EDEADLK，`boot_id` 仍是 UUID。** 这证明：
1. 不是 EDEADLK rollback 的问题
2. 不是 `sched_setattr` 挂起的问题
3. 而是 **rb-tree 写入机制本身不工作**

### 根因分析

`rt_mutex_adjust_prio_chain` 在某个条件检查处提前退出，不执行 rb_erase。可能的退出条件：
1. `pi_blocked_on == NULL`
2. `next_lock != waiter->lock`
3. `!task_has_pi_waiters(task)`
4. `waiter->tree.prio == task->prio && waiter->tree.deadline == task->deadline`

### 可用信息源

| 源 | 可读性 | 用途 |
|----|--------|------|
| `/proc/self/pagemap` | ✅ 可读 | 虚拟→物理页映射 |
| `/proc/self/maps` | ✅ 可读 | 进程虚拟地址布局 |
| `/proc/kallsyms` | ❌ 需要 root | 内核符号表 |
| `/proc/iomem` | ❌ 需要 root | 物理内存布局 |
| ashmem name buffer | ❌ GKI 6.6 不支持 | CFGPROBE |

### 下一步方向

1. **pagemap KASLR leak**：通过 `/proc/self/pagemap` 找到内核物理地址，计算 KASLR slide
2. **slide leak 诊断**：添加更详细的内核级诊断，确定 `rt_mutex_adjust_prio_chain` 的退出条件
3. **CFGPROBE 修复**：尝试使用 configfs binary write 替代 ashmem name buffer

### 反编译发现

从 full OTA 内核二进制反编译 `ashmem_read_iter`（offset 0x0c7a56c）：

```c
if (asma->size == 0)
    goto out_unlock;  // 返回 0
if (!asma->file) {
    ret = -EBADF;
    goto out_unlock;
}
ret = vfs_iter_read(asma->file, iter, &iocb->ki_pos, 0);
```

1. `pread` 从 `asma->file`（backing shmem file）读取，**不是**从 name buffer
2. `asma->size == 0` 时直接返回 0（CFGPROBE 没有调用 `ASHMEM_SET_SIZE`）
3. 即使设置了 size，`pread` 在 offset `0x6d6873612f76655c` 处也远超文件大小

### 结论

CFGPROBE 的 ashmem name buffer trick 在 violin 的 GKI 6.6 内核上不工作。需要：
1. 修复 CFGPROBE（设置 size + 使用正确的读取机制）
2. 或使用完全不同的 KASLR leak 方法
3. 或继续修复 slide leak（`rt_mutex_adjust_prio_chain` 提前退出问题）

### 下一步优先级

1. **修复 slide leak**：添加更详细的内核级诊断，确定 `rt_mutex_adjust_prio_chain` 的哪个条件检查失败
2. **替代 KASLR leak**：研究 `/proc/pid/pagemap`、`dmesg` 泄漏、或修改 CFGPROBE 使用 configfs 而非 ashmem
3. **CFGPROBE 修复**：设置 ashmem size + 使用 `ioctl(ASHMEM_GET_NAME)` 读取 name buffer

### 测试方式

```bash
adb push outputs/preload.so /data/local/tmp/preload.so
adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/toybox id"
```

### 环境差异

| 属性 | Firefox | LD_PRELOAD (adb shell) |
|------|---------|------------------------|
| uid | 10270 (app) | 2000 (shell) |
| SELinux | u:r:untrusted_app:s0 | u:r:shell:s0 |
| Seccomp | 2 | 0 |
| Seccomp_filters | 1 | 0 |

### 结果

- 行为与 Firefox 方式完全一致
- CMP_REQUEUE_PI 成功，waiter 在 futex_wait_queue，sched_setattr ret=0
- boot_id 仍为 UUID
- errno=13 (EACCES) 出现在多个 syscall 后（可能是前一个 syscall 残留）
- 设备无 reboot

### 结论

LD_PRELOAD 方式不改变 slide leak 的根本行为。问题在于内核的 `rt_mutex_adjust_prio_chain` 机制，不在于调用环境。

### E17 结果

- 覆写 `tree.prio=0x7fffffff`、`tree.deadline=0`，确保与 task 优先级不同
- boot_id 仍为 UUID（`b681dd70-a2a4-4bb0-9c3b-6aea9f17edf1`）
- 设备无 reboot

### 17 轮实验总结

| 阶段 | 实验 | 解决的问题 | boot_id |
|------|------|-----------|---------|
| 偏移修正 | E5 | waiter 结构偏移错误 | UUID |
| 时序修复 | E8 | CMP_REQUEUE_PI 时序竞态 | UUID |
| PI tree | E9-E14 | lock/pi_tree 各种组合 | UUID |
| wchan 诊断 | E16 | 确认 waiter 在 PI tree 中 | UUID |
| 优先级 | E17 | 确保 prio/deadline 不相等 | UUID |

### 已确认

1. ✅ waiter 结构偏移修正
2. ✅ CMP_REQUEUE_PI 100% 成功
3. ✅ waiter 在 PI tree 中（wchan=futex_wait_queue）
4. ✅ sched_setattr 成功执行
5. ❌ rb-tree 写入从未发生

### 根因判断

`rt_mutex_adjust_prio_chain` 在某个条件检查处提前退出。最可疑的条件：
- `task_has_pi_waiters(task)` 返回 false（task 的 pi_waiters 为空）
- `next_lock != waiter->lock`（lock 值不匹配）
- `orig_waiter && !rt_mutex_owner(orig_lock)`（orig_lock 无 owner）

### 下一步建议

1. **尝试 CFGPROBE bypass**：修复 ashmem name buffer trick，直接获取 KASLR slide，绕过整个 slide leak
2. **深入内核反编译**：检查 `__sched_setscheduler` 中 `rt_mutex_adjust_pi` 的调用条件
3. **尝试信号机制**：用 signal handler 在 futex 阻塞期间中断并覆写 waiter 字段
4. **考虑其他 KASLR leak 方法**：如 `/proc/kallsyms` 读取、`/proc/pid/pagemap` 等

### wchan 诊断

```
SLIDEC2B_WCHAN_BEFORE: tid=23686 wchan=futex_wait_queue
SLIDEC2B: parent sched_setattr tid=23686 nice=10
SLIDEC2C: parent sched_setattr ret=0 errno=0
SLIDEC2D_WCHAN_AFTER: tid=23686 wchan=futex_wait_queue
```

**waiter 在 sched_setattr 前后都阻塞在 `futex_wait_queue`**。这确认：
1. waiter 在 CMP_REQUEUE_PI 后仍在内核中阻塞
2. waiter 应该仍在 PI tree 中
3. parent 的 sched_setattr 成功执行（ret=0）
4. 但 rb-tree 写入仍未发生

### 分析

waiter 确实在 PI tree 中（wchan=futex_wait_queue），sched_setattr 成功执行，但 `rt_mutex_adjust_prio_chain` 没有触发写入。

最可能的原因：`rt_mutex_adjust_prio_chain` 在某个条件检查处提前退出。从内核反编译看，可能的退出点：
1. `waiter->lock != next_lock`（line 752）
2. `!task_has_pi_waiters(task)`（line 786）
3. `waiter->tree.prio == task->prio && waiter->tree.deadline == task->deadline`（line 809，优先级相等时退出）

条件 3 最可疑——waiter 的 priority/deadline 可能与 task 的 priority/deadline 匹配，导致函数认为"不需要调整"而退出。

### 下一步

1. **覆写 waiter->tree.prio（word 3）**为一个极端值（如 0 或 99），确保与 task 优先级不同
2. **覆写 waiter->tree.deadline（word 4）**为 0，确保与 task deadline 不同
3. 检查 `task_has_pi_waiters` 是否返回 true（需要读取 task->pi_waiters）

### E14 结果

- 使用 caiman 旧 word mapping（task→pi_tree.prio, lock→pi_tree.deadline）
- CMP_REQUEUE_PI 成功，parent sched_setattr 成功
- boot_id 仍为 UUID（`b681dd70-a2a4-4bb0-9c3b-6aea9f17edf1`，跨所有尝试稳定不变）

### 阶段性结论

经过 E1-E14 共 14 轮实验，boot_id 始终为同一 UUID，说明 **rb-tree 写入从未发生**。

**最可能的根因**：waiter 的 `pi_blocked_on` 在 `FUTEX_CMP_REQUEUE_PI` 期间被内核清除。`rt_mutex_adjust_prio_chain` 在 `retry:` 标签处读取 `task->pi_blocked_on`（rtmutex.c:722），如果为 NULL 则直接返回（line733-734），不执行任何 rb-tree 操作。

### 已确认解决的问题

1. ✅ waiter 结构偏移（E5）
2. ✅ CMP_REQUEUE_PI 时序（E8）
3. ✅ parent sched_setattr 不死锁（E12）

### 下一步方向

1. **验证 pi_blocked_on 状态**：在 parent sched_setattr 前读取 waiter thread 的 `/proc/<tid>/status` 或通过 `/proc/<tid>/wchan` 判断是否仍在 PI chain
2. **尝试不依赖 FUTEX requeue 的替代机制**：直接用 FUTEX_LOCK_PI 在 waiter thread 上建立 PI chain，绕过 requeue
3. **深入内核源码**：检查 `futex_requeue_pi` 和 `rt_mutex_adjust_prio_chain` 中 pi_blocked_on 的清除时机
4. **考虑 CFGPROBE bypass**：如果能通过 ConfigFS 获取 KASLR slide，可以跳过整个 slide leak 阶段

### E8-E13 进展

| 实验 | 关键改动 | CMP_REQUEUE | sched_setattr | boot_id | 设备 |
|------|---------|-------------|---------------|---------|------|
| E8 | retry 循环 | **成功(retry=0)** | consumer: ret=0 | UUID | OK |
| E9 | +keep kernel lock | 成功 | consumer: ret=0 | UUID | OK |
| E10 | +remove pi_tree overwrite | 成功 | consumer: ret=0 | UUID | OK |
| E11 | +parent sched_setattr | 成功 | **死锁** | — | 进程被杀 |
| E12 | +1s timeout | 成功 | parent: ret=0 | UUID | OK |
| E13 | +restore pi_tree +kernel lock | 成功 | parent: ret=0 | UUID | OK |

### 已解决的问题

1. ✅ waiter 结构偏移修正（E5）
2. ✅ CMP_REQUEUE_PI 时序（E8 retry 循环）
3. ✅ parent sched_setattr 不再死锁（E12 1s timeout）

### 当前卡点

所有条件都满足：
- CMP_REQUEUE_PI 成功（retry=0）
- parent sched_setattr 在 waiter 仍在 PI tree 时运行（SLIDEC2B/C 在 SLIDEW3 之前）
- 设备无 reboot
- 但 boot_id 仍为 UUID

**可能原因：**
1. waiter 的 `pi_blocked_on` 在 CMP_REQUEUE_PI 期间被内核清除，导致 `rt_mutex_adjust_pi` 找不到 waiter
2. rb_erase 操作的是错误的 tree（不是我们想写入的 tree）
3. pi_tree_entry 的 `__rb_parent_color` 指向的 fake parent 没有正确的子节点关系

### 下一步

需要更深入理解内核的 PI chain walk 机制。建议：
1. 在 kernel-src-wsl 中搜索 `rt_mutex_adjust_prio_chain` 和 `task_blocks_on_rt_mutex` 的实现
2. 检查 `pi_blocked_on` 在 CMP_REQUEUE_PI 后是否仍有效
3. 考虑使用 `pselect_custom_write_enabled()` 路径（caiman 有此机制）

### E8 配置

- waiter 偏移修正（E5）+ cmpval 修复（E2）+ retry 循环（200 次，1ms 间隔）
- lock owner = fake_task | 1
- pi_parent → fake_w0 + 0x28（页面 rb_node）+ RED 位

### 结果

- **CMP_REQUEUE_PI 两次都成功（retry=0）** ✅
- **sched_setattr ret=0** — 无 crash ✅
- **pselect ret=0** — fd_sets 已复制
- **boot_id 仍为 UUID** — 写入未发生 ❌
- **设备无 reboot** ✅

### 分析

CMP_REQUEUE_PI 成功意味着 waiter 被正确 requeue 到 target futex 的 PI tree。pselect 覆写了 waiter 字段。sched_setattr 触发了 rt_mutex_adjust_pi。但 rb_erase 没有写入 sysctl_bootid。

**可能原因：**
1. waiter 在 CMP_REQUEUE_PI 后已被从 PI tree 中移除（requeue 后 owner 释放 lock 导致 dequeue）
2. pselect 覆写后 waiter 的 __rb_parent_color 指向页面上的 fake parent，但 rb_erase 没有触发目标写入
3. 需要检查 kmsg 中的寄存器值来确定 rb_erase 的实际行为

### 下一步

1. 获取 E8 的 kmsg（如果设备有崩溃日志）
2. 检查 waiter 在 CMP_REQUEUE_PI 成功后是否仍在 PI tree 中
3. 考虑不覆写 __rb_parent_color（保留内核原始值），只覆写 rb_left/rb_right

### 核心发现：`target.h` 的 `WAITER_*_OFF` 用了旧版结构体偏移

从内核源码 `kernel-src-wsl/common-gki/kernel/locking/rtmutex_common.h` 读到真实 `rt_mutex_waiter` 布局：

```c
struct rt_waiter_node {
    struct rb_node entry;   // 0x00 (24 bytes)
    int prio;               // 0x18
    u64 deadline;           // 0x20
};  // total: 0x28

struct rt_mutex_waiter {
    struct rt_waiter_node tree;    // 0x00
    struct rt_waiter_node pi_tree; // 0x28  ← 旧值 0x18
    struct task_struct *task;      // 0x50  ← 旧值 0x30
    struct rt_mutex_base *lock;    // 0x58  ← 旧值 0x38
    unsigned int wake_state;       // 0x60
    struct ww_acquire_ctx *ww_ctx; // 0x68
};
```

旧 `target.h` 把 `WAITER_PI_TREE_ENTRY_OFF` 写成 `0x18`（应为 `0x28`），`WAITER_TASK_OFF` 写成 `0x30`（应为 `0x50`），`WAITER_LOCK_OFF` 写成 `0x38`（应为 `0x58`）。导致 pselect 的 word 映射全部错位。

### E5 修正结果

- 修正了 slide.c 的 waiter word indices：tree→0,1,2；pi→5,6,7；task→10；lock→11
- 修正了 target.h 的 WAITER_*_OFF
- **attempt 1 设备无 reboot**（之前所有带 lock owner 的实验都在 attempt 1 reboot）
- pselect ret=5（正确），sched_setattr ret=0（无 crash）
- 但 CMP_REQUEUE_PI 仍 errno=35，boot_id 仍 UUID

### E6 添加 100ms 延时

- 尝试在 CMP_REQUEUE_PI 前加 100ms 延时
- CMP_REQUEUE_PI 仍 errno=35
- 设备在 sched_setattr 时 reboot（可能是时序变化导致）

### 完整实验矩阵（最终）

| 实验 | 关键改动 | CMP_REQUEUE | boot_id | 设备 |
|------|---------|-------------|---------|------|
| stable0 | 基线 | 失败 | UUID | OK |
| E2 | cmpval=TID\|WAITER_BIT | ~50%成功 | UUID | OK |
| E3 | +lock owner | ~50%成功 | UUID | crash |
| E5 | +waiter偏移修正 | 失败 | UUID | **OK(attempt 1)** |
| E6 | +100ms延时 | 失败 | UUID | crash |

### 下一步

1. **CMP_REQUEUE_PI 时序问题**：需要确保 WAIT_REQUEUE_PI 已注册后再调用 CMP_REQUEUE_PI。当前 100ms 延时不够，可能需要轮询 futex 值。
2. **requeue 成功后的行为**：E2+E5（cmpval + 修正偏移）组合尚未测试——这可能是关键组合。
3. **CFGPROBE bypass**：ashmem name buffer trick 在 violin 上 rd=0，需要调查 configfs 实现差异。

## 2026-07-11 E18/E19：确认 GhostLock UAF 触发条件，定位此前实验的上游错误

### 本轮使用技能
- `explore-code`
- `debugging-and-error-recovery`
- `security-and-hardening`
- 代码发现优先使用 `codebase-memory-mcp`；图谱确认主链为 `src/slide.c`，具体参数/栈布局因图谱 snippet 错位而回退到精确文件读取。

### 确认的两个根因
1. `FUTEX_CMP_REQUEUE_PI` 参数曾被错误解释：第四个 syscall 参数在该操作下是 `nr_requeue`，比较值位于第六个参数 `val3`。正确调用为 `futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &slide_f_pi_target, 0)`。
2. 漏洞触发标志不是 `ret == 0`，而是 `ret == -1 && errno == EDEADLK (35)`。`ret == 0` 只说明 waiter 尚未进入 source futex queue，应该继续重试。

### 设备实证
- 设备：`03035440C1781540`，Android 16，kernel `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`。
- E18/E19 都稳定出现：retry 0 `ret=0 errno=0`；retry 1 `ret=-1 errno=35`；日志标记 `SLIDEC2_UAF_PRIMED`。
- 随后 waiter 从 `FUTEX_WAIT_REQUEUE_PI` 返回，进入 `pselect` 栈回收；consumer 对 waiter 执行 `sched_setattr` 时设备立即 panic/reboot。
- 这证明 CVE-2026-43499 的 EDEADLK rollback / dangling `pi_blocked_on` 已真实触发；此前“CMP_REQUEUE 成功但 boot_id 不变”的实验实际上没有触发漏洞。

### waiter 布局修正
GKI 6.6 `rt_mutex_waiter` qword：tree `0..4`，pi_tree `5..9`，task `10`，lock `11`，wake_state `12`，ww_ctx `13`。当前 `src/slide.c` 已按该布局写入，并保留 target 的 `PSELECT_WAITER_WORD_SHIFT=1`。

### E18 / E19
- E18：修正 futex 参数与布局，但保留 fake_task + fabricated lock owner；触发 UAF 后在 `sched_setattr` panic。
  - `exploit-site/preload-local-violin-e18-futexargs-layout.so`
  - SHA256 `409402F76715D6021F8EA7D0F5B300A044592B883084C5B66B83A815A24487E0`
- E19：改为 published chain 风格（`init_task`、ownerless fake lock、无 RB_RED）；仍在 `sched_setattr` panic。
  - `exploit-site/preload-local-violin-e19-upstream-chain.so`
  - SHA256 `EAB51DB992397DA970FD914BC212A8EC1A5B8C1D286CD7DCD96D76E0A772E399`
  - 日志：`analysis_outputs/e19/crash.txt`

### 下一步（停止盲扫）
必须先从同版本已 root 设备取得 `/sys/kernel/btf/vmlinux`，并从发生 panic 的设备取得 `/sys/fs/pstore/*`（另一台设备的 pstore 不能替代本次 panic）。当前非 root 设备对这两个路径均 `Permission denied`。在拿到 panic PC/寄存器和 BTF 精确类型布局前，不再继续真机 shift/颜色盲扫。

### 安全基线
`exploit-site/exploit.html` 仍指向 `preload-local-violin-stable0-faketask-khdrpi.so`，E18/E19 未设为网页默认 payload。

## 2026-07-11 一次性设备证据采集包

为避免 E19 后继续来回补文件，新增完整采集工具：

- `tools/collect-rooted-baseline.sh`：root 设备端采集 BTF、kheaders、kallsyms、config、bootconfig、device tree、模块/BTF、SELinux policy、内存布局和当前 slot boot-chain 镜像，并生成 SHA256SUMS。
- `tools/pull-kernel-evidence.ps1`：电脑端一键 push、root 执行、pull、解包和计算归档哈希。
- `ROOTED_DEVICE_EVIDENCE_CHECKLIST.md`：区分“同版本已 root 设备可替代的静态基线”和“只有发生 panic 的目标设备才能提供的 pstore/ramoops”。

验证：WSL `bash -n` 通过；PowerShell AST parser 通过。验证时目标设备已不在 ADB 列表，因此本轮未实际采集。下一次连接已 root 同版本设备后直接执行 PowerShell 脚本。

- 2026-07-11：	ools/collect-rooted-baseline.sh 已改为通过 $0 自动识别脚本目录；work 目录、总归档及归档 SHA-256 均输出到脚本同目录。BTF/config/kheaders 已包含在总归档中，不再额外重复生成独立副本。WSL ash -n 通过。

## 2026-07-12 E20：root 证据包验证与 pselect 精确栈偏移

### 证据包
- 来源：`violin-kernel-evidence-work/violin-kernel-evidence-work`
- 归档：`DLManager2/violin-kernel-evidence.tar.gz`
- 归档 SHA256：`1C6EC98B01BA93CDD4DA80A0BC22249708D43D0793990F453DB87147680CF952`
- 内部 `SHA256SUMS` 校验：0 个不匹配。
- root 设备 fingerprint、型号、系统版本、kernel release 与目标完全一致：`Xiaomi/violin/violin:16/BP2A.250605.031.A3/OS3.0.303.0.WOTCNXM:user/release-keys`，`6.6.77-android15-8-g5770c661275f-abogki443185593-4k`。
- root 设备 boot.img 与原厂 boot.img 哈希不同（Magisk patched boot），但运行 kernel release 与完整 kallsyms 均匹配；内核类型/符号证据可用。
- 此设备的 `pstore/` 只有当前 dmesg，没有 E19 panic ramoops；E19 panic 专属 pstore 仍只能来自发生崩溃的目标设备。

### BTF 精确验证
新增无外部依赖解析器 `tools/dump_btf_struct.py`，输出保存到 `analysis_outputs/btf-layouts-rooted-device.txt`。确认：
- `rt_mutex_waiter` size `0x70`：tree `0x00`、pi_tree `0x28`、task `0x50`、lock `0x58`、wake_state `0x60`、ww_ctx `0x68`。
- `task_struct`：pi_lock `0x90c`、pi_waiters `0x920`、pi_top_task `0x930`、pi_blocked_on `0x938`。
- `rt_mutex_base` size `0x20`：wait_lock `0x00`、waiters `0x08`、owner `0x18`。
- 现有 target.h 的上述结构偏移全部正确。

### E19 panic 根因：PSELECT_WAITER_WORD_SHIFT 错 1 qword
对原厂 `boot.img.kernel` 精确反汇编：
- `__arm64_sys_futex` frame `0x70`
- `do_futex` frame `0x60`
- `futex_wait_requeue_pi` frame `0x1c0`，waiter base 为本 frame `sp+0x90`
- waiter 绝对位置：syscall_sp `-0x70-0x60-0x1c0+0x90 = -0x200`
- `__arm64_sys_pselect6` frame `0x90`
- `core_sys_select` frame `0x1f0`，小 fdset buffer base 为本 frame `sp+0x80`
- fdset 绝对位置：syscall_sp `-0x90-0x1f0+0x80 = -0x200`

两者精确重合，因此 violin 必须 `PSELECT_WAITER_WORD_SHIFT=0`。原值 1 会让全部伪造字段错后 8 字节，解释了 E19 在 consumer `sched_setattr` 处立即 panic。

### E20
- target.h 已改为 `PSELECT_WAITER_WORD_SHIFT 0`，并写入精确栈公式注释。
- 构建通过：`exploit-site/preload-local-violin-e20-exact-stack0.so`
- SHA256：`82010A66D2A0B15CDB6E4A580697F0E633CC8EF022FB234DA7E6D72448CCE92B`
- 当前无 ADB 设备，尚未真机运行。
- 网页仍保持 stable0 默认 payload。

## 2026-07-12 GitHub Pages 发布 E20

- 仓库：`https://github.com/liang1228/ionstack-violin`
- commit：`363a1aa Deploy opt-in violin E20 payload`
- 推送：`master -> origin/master` 成功。
- 发布文件：E20 与 stable0；`exploit.html` 默认 stable0，仅 `?payload=e20` 选择 E20。
- GitHub Pages 首次 5 次请求为 404，第 6 次部署完成；线上 E20 SHA256 验证为 `82010A66D2A0B15CDB6E4A580697F0E633CC8EF022FB234DA7E6D72448CCE92B`，与本地一致。
- 其他未跟踪实验 payload、`preload.so` 和 `diag.html` 的历史工作区改动均未提交。

## 2026-07-12 GitHub Pages 实时日志持久化

- commit：`8773044 Persist and restore live exploit logs`，已推送 `origin/master`。
- 每次 progress 都实时写入 latest、backup 和当前 RUN_ID 三个 localStorage key，并记录 payload、更新时间、字节数元数据。
- 页面刷新或 Firefox/设备重启后重新打开，会立即恢复上次已保存日志并显示 `Download Saved Log`。
- 首页现已把 `?payload=e20` 透传给 exploit iframe，修复之前入口参数丢失导致仍加载 stable0 的问题。
- `node --check` 通过；GitHub Pages 线上内容已验证包含持久化与恢复逻辑。

## 2026-07-12 用户导出浏览器日志 `ionstack-log-1783788035227.txt`

- 已归档：`analysis_outputs/browser_logs/2026-07-12/ionstack-log-1783788035227.txt`。
- 该次运行**不是 E20**：日志明确显示 `kernel_file=preload-a358fbf.so`、`kernel_size=218064`；E20 应显示 `preload-local-violin-e20-exact-stack0.so`、大小 `221360`。
- 浏览器/JIT 链全部成功：AAW、AAR、addrof、RW64、mprotect 均 READY；设备 fingerprint 正确。
- native 阶段旧 payload 连续读取到原始 UUID `e798cbff-...`，未发生 KASLR 指针覆写；前三次 attempt 均失败，第四次仍运行到 `polls=228 bytes=10134`。
- 日志中没有 E20 的 `SLIDEC2_UAF_PRIMED`，不能用于验证 shift=0 修复。
- 原因属于旧 GitHub Pages/Firefox 页面缓存或打开了旧入口；下一次必须使用带 payload 与 cache-buster 的最新入口，并先在日志核对 `kernel_file`。

## 2026-07-12 E20 浏览器日志 `ionstack-log-1783788433342.txt`

- SHA256：`6BE665040F491CAEA55086370178315715AB0E5D99F6CA16F6C27C87F6AFF669`。
- 已确认真正加载 E20：`kernel_file=preload-local-violin-e20-exact-stack0.so`，size `221360`。
- Firefox/JIT 链全部 READY，E20 native preload 在 untrusted_app / seccomp2 中启动成功。
- slide page 与 fake objects 已准备完成，child context 已创建。
- 浏览器日志只到 `native command still running polls=5 bytes=2428`，尚未包含 CMP_REQUEUE/EDEADLK、pselect、boot_id 或 root 结果；若设备随后重启，高概率是在 E20 waiter/consumer 阶段 panic，但仅凭此浏览器日志不能确定精确点。
- 下一证据必须是目标设备 `/sdcard/Download/crash.txt`；该文件由 native `slide_crash_log` fsync 写入，通常能保留到重启后。若能 root，再同时取 `/sys/fs/pstore/*`。

## 2026-07-12 私有 crash 日志回读入口

- 目标设备的 `/sdcard/Download/crash.txt` 未出现，原因很可能是 Firefox `untrusted_app` 的共享存储写入受限；native 同时写入的私有副本为 `/data/data/org.mozilla.firefox/files/crash.txt`。
- 已发布 `?diag=crash` 只读诊断入口，浏览器利用链建立后读取该私有文件、经父页实时持久化日志返回，并在 payload 下载前退出。
- URL：`https://liang1228.github.io/ionstack-violin/index.html?diag=crash&v=18fe113`
- commit：`18fe113 Add private crash-log diagnostic route`；JS 语法检查和线上内容验证通过。

## 2026-07-12 目标设备直连：E20 状态与日志回读

- 目标设备 ADB serial `03035440C1781540` 已连接；uptime 为 9h20m，说明 E20 没有触发设备重启。
- `/sdcard/Download/crash.txt` 时间戳 `2026-07-11 19:56:25`、1902 bytes，是旧 E19 crash，已备份到 `analysis_outputs/e19/crash-from-connected-target.txt`。
- E20 页面持续轮询 Firefox 私有 `result/result.done`，对应 native command 未完成；浏览器日志仅到 poll 5，不能代表 E20 已结束。
- 已启动私有日志诊断链接 `?diag=crash&v=18fe113`，待用户在设备上确认后导出日志。该诊断不会下载或运行 payload。

## 2026-07-12 恢复本地 E20 调试

- 本机 `exploit-site` 静态服务器确认监听 `127.0.0.1:18000`，本地 E20 SHA256 与发布产物一致：`82010A66D2A0B15CDB6E4A580697F0E633CC8EF022FB234DA7E6D72448CCE92B`。
- ADB reverse 已设置：`tcp:18000 -> tcp:18000`。
- 修正了此前默认浏览器问题：先解析 Firefox launcher，使用显式组件 `org.mozilla.firefox/.App` 启动本地 URL；`topResumedActivity` 已确认是 Firefox。
- 当前本地调试 URL：`http://127.0.0.1:18000/index.html?payload=e20&local=1`。

## 2026-07-12 本地 E20 结束后检查

- 目标设备未重启，boot_id 与运行前一致；Firefox PID 仍存在。
- 公共 `/sdcard/Download/crash.txt` 未更新，仍为 E19 文件。
- 未在本机常见下载目录自动发现新的 `ionstack-log-*.txt`。
- 已通过显式 Firefox Activity 打开本地私有日志诊断：`http://127.0.0.1:18000/index.html?diag=crash&local=1`，待用户确认并导出。

## 2026-07-12 E20 本地私有日志：精确停点与 E21 观测设计

- 本地诊断 URL 已由 Firefox 的显式 `IntentReceiverActivity` 打开；UI dump 确认页面为 `diagnostic_complete`，不是此前被 Firefox 恢复的 GitHub 旧 tab。
- 私有 crash 日志已存档为 `analysis_outputs/e20/private-crash-from-local-diag.txt`，SHA256 `1B3DA0CC259D28ECD41A0F4732D5031B8EC7B243792CF8C243FBB2800FAA0B8D`。
- E20 的 `SLIDEC2_UAF_PRIMED` 证明 `CMP_REQUEUE_PI` 的 `-1/EDEADLK` rollback 已稳定触发；`SLIDEP2` 证明 shift=0 的 pselect copy 路径进入。
- 停点严格位于 `SLIDECONS0` 与 `SLIDECONS1` 之间，即 consumer `sched_setattr_tid()` 内核路径未返回；设备没有重启。
- 已在实际 E20 构建源 `exploit-repo/IonStack/CVE-2026-43499/exploit/src/slide.c` 加 E21 sibling watchdog：记录 consumer TID，启动前置原子标记，随后 10 次读取该线程 `/proc/<tid>/wchan` 与 `/proc/<tid>/stat`。该改动只增加用户态观测，不改变 futex、伪造 waiter 或 pselect fdset。
- `src/slide.c` 使用 host clang 的 `-fsyntax-only` 检查通过（仅已有 `pi_parent_addr` unused warning）。实际 Android 链接暂未完成：本地 `ndk/.../bin/clang` 是 8-byte stub，原先 `/tmp/ndk` 不在当前 WSL；需要恢复完整 NDK 后重建 E21，禁止把 stub NDK 产物推送或上机。

## 2026-07-12 E21-E23 watchdog experiments: reboot evidence and stop condition

- E21 (sibling watchdog) and E22 (correct consumer TID publication) each caused a reboot after `SLIDEWATCH0`; both still reached `SLIDEC2_UAF_PRIMED` and `SLIDECONS0`, but never logged a scheduler return.
- E23 removed the fourth child thread and instead sampled the forked child from the parent. It also rebooted, proving the reboot is not the `/proc/0` TID bug or only the child-watchdog implementation.
- E23 private log was recovered after boot through local `?diag=crash`: parent sample 4 shows the child plus waiter/owner/consumer threads; then the normal path reaches `SLIDEP2` and `SLIDECONS0`, after which the device resets before `SLIDECONS1`.
- This is decisive: every perturbation that permits observation around the `sched_setattr` transition converts E20's prior hang into a kernel reset. Do not run E21/E22/E23 again. Keep web default stable0; the E21/E22/E23 files remain local-only and were not pushed to GitHub.
- Next work is static: disassemble the exact violin `__sched_setscheduler` -> `rt_mutex_adjust_prio_chain` path and compare the forged `rt_mutex` RB-tree/owner state with source. No additional device-run should occur until that control-flow model is fixed.

## 2026-07-12 静态调度链还原

- 已保存 `analysis_outputs/e23/STATIC_SCHEDULER_RECONSTRUCTION.md`：精确映射 `__sched_setscheduler` / `rt_mutex_adjust_prio_chain`，并还原 forged waiter 的 `rb_erase` 分支。
- 当前 forged shape 进入 one-left-child erase：先把 `SLIDE_LOGGERS_0_1` 写进 `boot_id_data+0`，随后 ownerless requeue 触发 `wake_up_state(init_task, 3)`；这与 `SLIDECONS0` 后无返回的现场一致。
- 已移除 E21/E22/E23 全部观测代码，恢复 E20 的三线程拓扑；`VIOLIN_SLIDE_WAKE_STATE` 默认保持 3。仅提出未执行的 state=0 最小候选，尚未构建或上机。
- 已反汇编同一内核的 `try_to_wake_up`（image offset `0x0ef7d4`）：state=0 在 `p->__state & state` 检查处直接走 no-match 退出，不进入 runqueue/CPU 唤醒路径。因此 `VIOLIN_SLIDE_WAKE_STATE=0` 是只绕过 `wake_up_state(init_task, 3)` 的最小候选；仍未构建或上机。
## 2026-07-12 E24 wake_state=0 result

- E24 (`preload-local-violin-e24-wake0.so`, SHA256 `DEA0E08C39BC3C524D8B7A7BDCA7F1DC9B9977904CEEE9F51ED5C6829F89D91C`) kept the exact E20 forged tree and changed only `VIOLIN_SLIDE_WAKE_STATE` from 3 to 0.
- Target rebooted again. Private crash log still ends immediately after `SLIDECONS0`; there is no `SLIDECONS1`, boot-id read, or root result.
- This falsifies `wake_up_state(init_task, 3)` as the sole crash point. The failure is earlier in, or concurrent with, the malformed `rt_mutex` requeue / `rb_erase` data corruption.
- Postboot non-root logcat is preserved as `analysis_outputs/e24/postboot-logcat-matches.txt`; no privileged pstore/reboot directory was readable through ADB shell. E24 is local-only and not pushed.

## 2026-07-12 rooted panic evidence script

- 新增 `tools/collect-rooted-panic-evidence.sh`：可在同版本 root 设备重启后直接运行；自动切换 su，并把 pstore、last_kmsg、dmesg、all-logcat、MIUI reboot/prereboot、tombstones、设备标识与 SHA256 清单全部保存到脚本自身目录下的时间戳文件夹及 `.tar.gz`。
- 已用 WSL `sh -n` 和 LF 行尾检查验证。

## 2026-07-12 root device evidence archive 1.zip

- 已解包并验证同版本 root 设备：kernel `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`，collector 以 uid 0 / Magisk context 成功运行。
- 该包不是 E24 复现后的 panic 证据：pstore 为空、`/proc/last_kmsg` 不存在，且没有 `SLIDECONS`/Gecko preload 记录。dmesg 的两段 Call trace 分别来自 boot-time `do_dentry_open` 与 `nvt_ts_work_func`，与 IonStack 无关。
- 已新增并发布 `run-rooted-e24-live-capture.sh`：先在 root 设备开启持久化 dmesg/kernel-logcat，再自动启动 E24；重启后再运行 collector，可保留 reset 前的实时内核输出。

## 2026-07-12 E24 offset re-audit

- 已复核 rooted 同版本 `/proc/kallsyms`：`target.h` 里 25 个带 symbol 标记的偏移全部精确一致，报告为 `analysis_outputs/e24/symbol-offset-audit.txt`。
- 已用 rooted `/proc/iomem` 校验 `_text` 物理加载地址 `0x00210000`，所有 P0/direct-map alias 均落入可见 kernel code/data 范围，报告为 `analysis_outputs/e24/p0-direct-map-audit.txt`。
- 修复 `src/main.c` 的 CFGPROBE 诊断双重 P0 转换：`SLIDE_SYSCTL_BOOTID` 已是 direct alias，不能再次传给 `data_addr()`；此前 E24 中的 `0xffffffbffa756f58` 只影响该诊断 probe，不影响真实 slide route。
- 结论：当前 reset 不能归因于符号、BTF 字段、pselect shift 或 P0 load 数值偏移；下一项是精确核对 `rb_erase_cached` 的第二次写入是否破坏 live `loggers` BSS。

## 2026-07-12 KASLR pointer-domain audit

- 进一步静态审计发现根本逻辑问题：当前 forged tree 写入 `sysctl_bootid+0` 的是 P0/direct-map `SLIDE_LOGGERS_0_1=0xffffff80022e21b8`，而不是 canonical/KASLR `loggers=0xffffffd367ed21b8`。
- 现有 reader 将该泄漏值减去 P0 alias offset 后得到 `0xffffff800020ff48`，仍在 P0 区，绝不可能是 canonical kernel text base `0xffffffd3...`。完整推导记录在 `analysis_outputs/e24/slide-kaslr-address-domain-audit.md`。
- 因此，即使不发生 reset，当前 P0 leak 设计也无法产生 KASLR slide；在重新设计 canonical-pointer leak 或有效转换链之前，不构建、不运行下一版 payload。
- 已在 `src/slide.c` 添加 domain gate：若 boot-id 回读值属于 `DIRECT_MAP_BASE..DIRECT_MAP_END`，记录 `SLIDER2_BAD_DOMAIN` 并立即失败，不再把伪合法的 `ffff...` P0 指针误当 `stext`。violin target 的 `clang -fsyntax-only` 已通过。

## 2026-07-12 live target canonical-pointer reconnaissance

- 已在连接的非 root target 上确认 `/proc/kallsyms`、`/proc/iomem`、`/proc/vmallocinfo` 均被 SELinux 拒绝；`/proc/kcore` 不存在，不能直接取得 canonical 地址。
- 内核启用 `CONFIG_KALLSYMS_ALL=y`、`CONFIG_KPROBES=y`、`CONFIG_BPF=y`、`CONFIG_DEBUG_INFO=y`；tracefs 中存在 MIUI BPF 创建的 kprobe events，且 format 含 `__probe_ip`（理论上可泄漏 canonical IP）。
- 实测 shell 可读 trace、可切换 `tracing_on`，但不能新建 kprobe (`kprobe_events: Device or resource busy`) 也不能 enable 现有 kprobe event (`Permission denied`)；因此该 tracefs 路径当前不能作为无 root KASLR leak。已关闭 trace，并保持原 event disable 状态。
- 进一步测试了 target 自带 `/system/bin/simpleperf`：system-wide record 明确要求 root；对自身的 `cpu-clock` 与 `task-clock` record 也被内核拒绝为 unsupported。因此 `perf_event_paranoid=-1` 在该 SELinux/PMU 配置下不能提供 kernel-IP 采样泄漏。

## 2026-07-12 upstream/public-disclosure cross-check

- 已重新 clone 官方 `NebuSec/CyberMeowfia` main；本地上游提交与当前基线同为 `1a10c4e`。公开仓库没有 violin target，也没有额外 Android 端 exploit stage。
- 官方 CVE writeup 明确说明其公开的完整 exploit strategy 是 generic x86 路线；Android 的 ASLR/CFI bypass “next blog” 尚未公开。其公开 summary 的第一步是 prefetch 取得 canonical image slide/physmap，而不是当前 violin 代码的 P0 boot-id 算法。
- 因此不能把 public x86 CEA/`inet6_protos` 链直接移植到 ARM64 violin；当前 `slide` 代码的 P0-to-stext 算法也不能作为替代。violin port 需要独立 ARM64 canonical KASLR leak 与可控内核页方案。

## 2026-07-12 rooted-device canonical-surface collector

- 新增 `tools/collect-rooted-canonical-leak-surface.sh`，自动提权并在脚本目录创建时间戳目录/压缩包，收集同 boot 的 kallsyms、iomem、vmallocinfo、module sections、GPU/Mali sysfs、字符设备 ACL、trace kprobes/events 与 kcore 可读性。
- 已以 WSL `sh -n` 验证，首字节为 shebang `#!`，SHA256 为 `93A5E7070679B964EAAE82EFE5D0F5DC3344CC3BA815D8D43E46ED97D263E7AD`。

## 2026-07-12 rooted canonical-surface archive

- 已解包 `ionstack-canonical-surface-20260712-172004.zip` 至 `analysis_outputs/rooted-canonical-surface-20260712-172004/`；确认同一 violin build，collector 以 `uid=0` / `u:r:magisk:s0` 运行。
- 收集到 `/proc/iomem` 的物理 image 布局与可访问设备 ACL；shell 可打开的优先候选仍是 `ashmem` 和 `mali0`。Mali 运行模块为 `mali_kbase`。
- 该 root context 的 `/proc/kallsyms` 和 `/sys/module/*/sections/*` 全部为零地址，说明 Magisk `u:r:magisk:s0` 不具有查看 kptr 的能力；不能将该包当作 canonical runtime symbol evidence。此前有效的 rooted kallsyms/BTF 证据仍在 `violin-kernel-evidence-work/`。
- 当前 archive 缺少预期的 GPU/trace/kcore 输出文件，说明旧 collector 静默中断；新版脚本已改为逐步骤显示进度，文件名也已从误保存的 `.sh.txt` 修复为 `.sh`。

## 2026-07-12 target character-device read-only audit: Mali

- 从 root archive 解出同版本 `mali_kbase.ko`（Arm Avalon `r49p1-04eac0`），保存反汇编候选至 `analysis_outputs/rooted-canonical-surface-20260712-172004/modules/`。
- 新增 `tools/mali_readonly_probe.c`，只执行 `/dev/mali0` open 与标准 `MALI_IOCTL_VERSION_CHECK` (`0xc0048000`)，不分配 GPU 内存、不提交任务、不写驱动状态。
- 已交叉编译 ARM64 Android 35 probe 并在未 root target 执行：open 成功，但 ioctl 返回 `EPERM`。因此 `/dev/mali0` 虽存在宽松 DAC mode，实际被 SELinux/driver policy 拦截，不能作为 shell 侧 canonical KASLR leak。
- `/dev/xr_meminfo` 也被 shell 读取时拒绝。下一轮继续限定在允许 shell 实际读取的接口，禁止盲 ioctl/fuzz。

## 2026-07-13 HANDOFF1 / HANDOFF 事实对账

- 新增 `analysis_outputs/handoff-reconciliation-2026-07-13.md`，以当前 `HANDOFF.md` 为运行基线，对账 `HANDOFF1.md`、最新开发日志、`ndk_build.sh`、`Makefile`、当前 slide 源与 `violin-kernel-info2.zip`。
- ZIP 的 fingerprint、kernel release 与关键符号地址同当前 violin 证据一致；APK 工程、asset 和 debug APK 仍存在，但三者/`outputs/preload.so` 的现有 SHA256 不同，不能从文件存在性反推 APK asset 的构建来源。
- 更正源码选择表述：`ndk_build.sh` 直接编译 `src/slide.c`；`make PROJECT=violin-v-oss` 的 `pick_src` 优先使用 `src/targets/violin-v-oss/slide.c`。以后每个二进制必须记录构建命令、源选择与 SHA256。
- `HANDOFF1.md` 已加历史/禁止执行横幅。E21–E24 重启证据与 P0/direct-map 非 canonical 的结论保持有效；未找到目标同次 boot 的可验证 canonical 地址前，只允许只读、结构化的泄漏面审计。

## 2026-07-13 复用 popsicle 的离线 target 审计思路

- 新增 `tools/audit_violin_kernel_baseline.py` 与 `tools/tests/test_audit_violin_kernel_baseline.py`。工具只读取 `target.h`、rooted `kallsyms.txt` 和 `iomem.txt`，不调用 ADB、不执行 shell、不构建或运行 payload；输出 JSON 审计报告。
- 该工具将 `target.h` 中带 `/* symbol: ... */` 的 `_OFF` 宏与非模块 kallsyms 相对 `_text` 的偏移逐项比对，并校验 `P0_PHYS_OFFSET` 和 `P0_KERNEL_PHYS_LOAD` 的 violin 物理布局语义。
- 用当前 evidence 生成 `analysis_outputs/target-audit-2026-07-13.json`：25 个标注符号偏移全部匹配，物理布局字段匹配，`mismatches=0`。单元测试 2/2 通过，且脚本通过 `python -m py_compile`。
- 特别区分 profile 语义：popsicle 的物理 load 计算不能直接复制到 violin；violin 的 `P0_KERNEL_PHYS_LOAD` 对应当前 `/proc/iomem` 的 `Kernel code` 起点 `0x00210000`。复用的是“强校验与来源可追溯”方法，而不是跨设备数值或 payload。

## 2026-07-13 目标设备重新连接后的只读 canonical 面复核

- 当前目标 boot：`d933bd9e-797a-421d-8473-998e50cbd938`；型号 `25053RP5CC`、fingerprint `Xiaomi/violin/violin:16/BP2A.250605.031.A3/OS3.0.303.0.WOTCNXM:user/release-keys`、kernel `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`、SELinux `Enforcing`。基线存档：`analysis_outputs/target-readonly-baseline-20260713.txt`。
- shell context 为 `u:r:shell:s0`；`/proc/kallsyms`、`/proc/iomem`、`/proc/vmallocinfo`、`/proc/misc` 都拒绝读取。`/dev/mali0`、`/dev/ashmem`、`/dev/xr_meminfo` 存在，但本轮未执行 ioctl、写入或 payload。
- 现存 MIUI BPF kprobe 事件格式均含 `unsigned long __probe_ip`（理论 canonical-IP 面），但全部 `enable=0`，`tracing_on=0`，trace buffer `entries-written=0`；只读 `trace` 和 2 秒 `trace_pipe` 样本均无事件。记录：`analysis_outputs/target-trace-module-surface-20260713.txt`、`analysis_outputs/target-existing-kprobe-buffer-20260713.txt`。
- 结论：本 boot 尚未取得 canonical 地址，且现存 trace 事件在不修改内核 tracing 状态的条件下不能提供数据。保持“不重跑 E21–E24、不把 P0 当 canonical”的门禁；下一步只能先建立新的、只读且可重复的合法泄漏面模型，再考虑任何 payload。

## 2026-07-13 KSU Loader / popsicle / 用户 ZIP 实际链路对照

- 新增 `analysis_outputs/ksu-popsicle-violin-chain-comparison-20260713.md`。已把 KSU Loader 的两个 native asset、popsicle commit `98cf38fcf6f2e3f508979d6ad46abffb1837a246` 和用户 `violin-kernel-info2.zip` 纳入同一对账。
- KSU `preload.so`（`63A553AC...A22EA`）与 `preload_v220.so`（`8207A2A9...CDB30`）都可见 `slide_read_stext`、boot-id、P0 profile 和 `slide-kaslr-ok` 字符串；popsicle `slide_read_stext()` 也把 boot-id 前 8 字节按 P0 alias 偏移回推 `stext`。这不是 violin 缺失的 canonical-pointer 泄漏，不能移植为下一次运行候选。
- ZIP 的 rooted kallsyms 继续用于同 build offset 验证（`_text`、`nfulnl_logger`、`init_task`、`sysctl_bootid` 均已复核），但其 canonical 地址来自另一次 boot，不能硬编码到当前目标。
- 结论收敛：可以复用 KSU 的 APK/logging 工程与 popsicle 的严格 profile 生成；禁止复用两者的 boot-id/P0 KASLR 算法、popsicle 6.12 profile 和任何已假设 canonical/读写原语成立的 root 后利用代码。

## 2026-07-13 任务约束：仅无解锁 root 路径

- 用户明确无法正常解锁 bootloader。后续只推进 CVE-2026-43499 / 无解锁本地提权研究与验证，不再把 bootloader 解锁或 patch boot 作为建议、备选或验收路径。

## 2026-07-13 popsicle 路线纠正：P0 direct-data 而非 canonical-text 前提

- 重新逐函数核对 popsicle `slide_read_stext()`、`run_exploit()` 与 `run_direct_root_stage()`：其 slide 读 boot-id 并用 `p0_alias_image_offset()` 得到 P0/direct-map 基址；它没有先获得 canonical kernel text 地址。
- 关键在于后利用：`run_direct_root_stage()` 明确要求 `is_direct_ptr()`，用 direct pselect read/write 读取 per-CPU/current-task，再修改 `init_cred`。因此 P0 不能用于 violin 的 CFI/fops 控制流，却可能是 data-only root 路线所需的有效地址域。
- 先前把“canonical text 泄漏”视为唯一前置条件的说法只适用于当前 fops/pipe 路线，不能外推到 popsicle direct-data 路线。后续任务改为：从 violin boot/profile 静态生成 direct-data 所需字段，隔离移植 direct read/write 候选，先做只读形状验证，禁止直接进入 cred patch。

## 2026-07-13 violin-kernel-info2 有效 canonical kallsyms 与 mtdoops 线索

- 已验证用户上传的 `violin-kernel-info2.zip`（SHA-256 `94999DC250D1E653B8324974D8A1D8289F283ED0D3C99F0869E0D490D42273B5`）并写入 `analysis_outputs/violin-kernel-info2/analysis.md`。其 kallsyms 有真实 canonical 地址，`_text=0xffffffe387200000`、`loggers=0xffffffe3892d21b8`、`sysctl_bootid=0xffffffe389536f58`；相对符号布局继续匹配 violin header。
- 与早先有效 root boot 的 `_text=0xffffffd365e00000` 相差 `0x1021400000`，直接证实 KASLR slide 逐 boot 改变。本包只可用于 offset/static 审计，不能向未 root 目标移植 absolute 地址。
- cmdline 明确配置 `block2mtd=/dev/block/by-name/oops` 和 1 MiB `mtdoops` record，且启用 `mtdoops.dump_oops`/`printk.always_kmsg_dump`。新增只读 `tools/collect-rooted-oops-partition.sh`，用于 root 同版本设备受控复现重启后的 oops 分区提取；已避免再次依赖空 pstore/不存在 last_kmsg。
- 根据“文件不能为 0”的要求，collector 已强化为强校验：必须解析为 block device，`dd` 返回 0 且输出严格等于 `1048576` bytes 才保留 `oops-record.bin` 并标记 `EVIDENCE_STATUS.txt` 为 `RESULT=OK`；任何短读/读错会标记 `FAILED` 并删除 raw 文件。WSL `sh -n`、shebang 与 LF 行尾检查通过，当前 SHA-256 为 `56123EC301CBB5961A4ED168DBDC1E86DDB2118652E624C7116DAC2CC2DB2C0F`。

## 2026-07-13 Violin popsicle direct-data probe：重启，未到 direct read

- 以同 build rooted kallsyms/BTF 生成 `analysis_outputs/violin-popsicle-direct/src/target.h`，从 popsicle source 构建 probe；二进制 `build/bin/preload.so` SHA-256 为 `005E585C4C6F7A121F92A211706A31FCD21E3C761A22A34D226895820E95436B`。`IONSTACK_DIRECT_PROBE_ONLY=1` 的早退点位于第一笔 direct per-CPU read 成功后、所有 credential target/write 之前。
- 在目标 boot `d933bd9e-797a-421d-8473-998e50cbd938` 运行后，实时输出止于 `slide consumer before sched ...`；没有 `direct-probe-ok`，随后设备重启并回到 boot `02dbe33b-7783-40c1-8bc2-62103a98f1df`。当前已通过 ADB 复核在线、shell/SELinux 状态正常。
- 这次执行未到 direct read 早退点，故没有执行 credential 写入。`analysis_outputs/violin-direct-probe-postboot-crash-20260713.txt` 经 PID/前缀核对为旧 CFGPROBE 文件，不能作为本次 crash 定位证据。
- 新增静态对账 `analysis_outputs/violin-popsicle-direct/STATIC_RECONCILIATION_2026-07-13.md`：候选原版 slide 仍是 `loggers -> boot_id_data` 的 one-left-child `rb_erase_cached` 形状；既有同 build 反汇编模型已证明该形状会破坏 boot-id 数据并触发 ownerless waiter 后续路径。日志停点一致，但没有足够证据归因到单一分支。
- 停止条件：禁止重跑该 binary 或只改时序重跑同一 tree shape；下一候选必须先把所有 rbtree 写、parent-color、fake lock/task 与 wake 分支在同 build 静态对账，并证明其写目标不破坏 live kernel state。

## 2026-07-13 direct stage 前置和 shape-0 静态收敛

- 新增 `analysis_outputs/violin-popsicle-direct/DIRECT_STAGE_PRECONDITION_AUDIT_2026-07-13.md`。从候选实际代码确认：`slide_leak_kernel_base()` 的成功产物只是 P0 image base；Violin profile 可静态算得 `0xffffff8000210000`，不等同 canonical text base。该结论没有生成、构建或运行任何跳过 slide 的变体。
- 同时确认 `direct_read_shape0_exact64_once()` 不是只读：它以 `B=sysctl_bootid data`、`Q=待读地址` 构造 `parent=Q/right=0/left=B` 的 tree 和 pi-tree。one-left-child erase 至少会向 B 写 parent，并把 Q 当作 rb parent 解引用/更新。因此 Q 为 `__per_cpu_offset[cpu]` 或 entry slot 时，必须先完成同 build 的实际 `rb_erase_cached` / `__rb_change_child` child-slot 静态还原。
- 门禁更新：可以离线研究“静态 P0 base 初始化”是否能消除初始 slide，但严禁将 shape-0 称为 read-only 或在没有 Q 分支/写地址证明前上机。

## 2026-07-13 direct shape-0 的 Violin 6.6 child-slot 写入：已静态证伪

- 已从同 build `boot.img.kernel` 导出 `analysis_outputs/violin-popsicle-direct/rb_erase_cached-violin.disasm.txt`。`rb_erase_cached` 位于 image offset `0x128074`，其 one-child helper 位于 `0x102da44`；原始 kallsyms 交叉定位见 `violin-kernel-evidence-work/violin-kernel-evidence-work/proc/kallsyms`。
- 对 direct shape-0 的 `parent=Q/right=0/left=B`，helper 精确执行：读取 `*(Q+16)` 与当前 node 比较；相等则 `*(Q+16)=B`，否则 `*(Q+8)=B`，随后 `*(B+0)=Q`。Q 由 source 指定为 `percpu_slot` 或 `entry_slot`，两类都是 live per-CPU 数据，而不是受控 scratch。
- 这在第一棵 tree 上已构成决定性否定：shape-0 必然改写 live `Q+8` 或 `Q+16`，不能作为 Violin direct read primitive 上机；无需再把 pi-tree 第二次处理当作是否重跑的前置谜题。`DIRECT_STAGE_PRECONDITION_AUDIT_2026-07-13.md` 已更新为精确指令级证据。
- 决策：停止对当前 popsicle direct-data source tree 的“跳过 slide / shape-0 读”变体研究。后续只有在新 primitive 能静态证明全部 child-slot 写限制于受控 scratch 后，才允许讨论新的构建或设备运行。

## 2026-07-13 同品牌 popsicle 的适用范围校正

- `x-spy/CVE-2026-43499-popsicle` 确实是同品牌 Xiaomi 的强参考：其 README 目标为 Xiaomi 17 Pro Max / Android 16 / `6.12.23-android16-5-...`，说明 P0、Kernelsnitch、strict target generation 这条总体工程路线值得保留。
- 但 Violin 为 Pad 7S Pro / `6.6.77-android15-8-...`，且 profile 从 popsicle 的 `p0_phys_offset=0x80000000, p0_kernel_phys_load=0xc7800000` 改为 Violin 的 `0, 0x00210000`。同 OEM 不能替代同 kernel ABI/调用栈证明。
- 本项目的 `rb_erase_cached` 结论仅限定 Violin 6.6：当前 source 的 shape-0 会写 live `Q+8/Q+16`，不能原样上机；这不反驳 popsicle 在其列明 Xiaomi 17/6.12 环境的验证。完整范围说明已补入 `DIRECT_STAGE_PRECONDITION_AUDIT_2026-07-13.md`。

## 2026-07-13 P0 seed / 首次 per-CPU direct probe：route 触发但 oracle 未建立

- 发现并纠正了过宽结论：Violin `possible=online=0-9`、当前选中 CPU=9，而 config `CONFIG_NR_CPUS=32`。首次 `Q=__per_cpu_offset[9]` 的 `Q+8/Q+16` 为非 possible CPU 10/11 slot；第二次 `Q=entry_task[9]` 才会触及 `overflow_stack` 邻域。因此仅允许 first-stage 早退 probe，禁止 entry-task stage。
- 在候选 source 增加双 opt-in gate：`IONSTACK_P0_SEED_PROBE_ONLY=1` 静态设置 P0 base `0xffffff8000210000` 并跳过已重启的 initial slide；与 `IONSTACK_DIRECT_PROBE_ONLY=1` 联用后，只执行一次 `per_cpu_offset` shape-0 并在其后退出。新 binary SHA-256 `855F77BDF2D0696D67B1B62CB6FC65187F402E132CF51EED7990297647EA167B`，完整 NDK build 成功。
- 目标 boot `02dbe33b-7783-40c1-8bc2-62103a98f1df` 上执行无重启；`pselect attempt=1 ret=4 calls=1 success=1`，但 boot-id oracle 仍是运行前原 UUID 的 16 bytes，`ok=0`。这证明 direct scheduler route 返回而没有得到预期 overwrite/read primitive；没有进入 entry-task、SELinux 或 credential path。
- 记录：`analysis_outputs/violin-popsicle-direct/P0_SEED_PERCPU_PROBE_2026-07-13.md` 与 `analysis_outputs/violin-p0-seed-probe-20260713.txt`。停止原样重跑；下一项是离线对账该次 no-overwrite 的 pselect/waiter 真正 field mapping，而不是推进 credential stage。

## 2026-07-13 popsicle 全源码与历史审计

- 按要求已把 `analysis_outputs/references/CVE-2026-43499-popsicle/` 从 shallow clone 补全为完整公开历史并执行 `git pull --ff-only`；当前 HEAD/`origin/main` 均为 `98cf38fcf6f2e3f508979d6ad46abffb1837a246`，无本地源码修改（仅 Python `__pycache__/` 未跟踪）。
- 新增 `analysis_outputs/popsicle-source-audit-20260713.md`，逐模块覆盖 latest direct chain 和 initial→simplified 的演进。关键发现：initial profile 显式使用最后 CPU 7，最新改动态 CPU；Violin 选中最后 possible CPU 9，首次 per-CPU Q 的相邻 slot 10/11 因而符合该设计前提。
- initial `fops.c` 有 8 档 `route_delay_usec()`（首档 50ms），latest simplified direct chain 固定 delay=0。Violin first-stage 记录为 `pselect ret=4/calls=1/success=1/oracle=0`；在不进入 entry-task 的前提下，恢复一个历史 timing 值是后续唯一可审计的单变量候选。BTF 的 waiter word13 `ww_ctx` 未由 latest fops 显式放入，是另一个候选，但不得与 timing 改动合并。

## 2026-07-13 popsicle initial 50ms timing 回归：未建立 oracle

- 构建单变量 candidate，仅新增有界环境变量 `IONSTACK_DIRECT_ROUTE_DELAY_USEC`，然后以 initial source 的首档 `50000` 运行 P0 seed + first per-CPU early-exit；binary SHA-256 `CB6CEFCEA2023728C8DB688184035D78475F03680BE7E4F0C0F7469DC7C43C58`。
- 结果为 `pselect ret=5/calls=1/success=1/delay=50000/oracle=0`，boot-id 仍是运行前原 UUID，和 default delay=0 的 `oracle=0` 一致。设备未重启，boot ID、shell UID、SELinux Enforcing 均不变；日志 `analysis_outputs/violin-p0-seed-delay50k-probe-20260713.txt`。
- 结论：latest direct chain 删除 initial 的 50ms delay 不能单独解释 Violin 的 no-overwrite；停止 timing sweep。下一项仅可独立审计/验证 BTF waiter word13 (`ww_ctx`) 显式清零差异，不能进入 entry-task。

## 2026-07-13 popsicle waiter word13 (`ww_ctx=0`) 回归：未建立 oracle

- 已按 Violin BTF `rt_mutex_waiter.ww_ctx=0x68` 在 direct fops 的 fdset 覆盖增加唯一 word13=`0`；P0 seed + first per-CPU early-exit、delay=0 保持不变。binary SHA-256 `69979EFFC6B70BC3AFB795EFD7004C4D78357F13988B16326A488338622B06D5`；构建和 target audit 单测 2/2 通过。
- 实机结果仍为 `pselect ret=4/calls=1/success=1/oracle=0`，boot-id 是原 UUID，设备未重启且 UID/SELinux/boot ID 不变。记录 `analysis_outputs/violin-p0-seed-wwctx0-probe-20260713.txt`。
- 结论：latest fops 漏填 ww_ctx 不是 Violin no-overwrite 的单独根因。停止原样/时序/word13 shape-0 回归；下一步回到 initial release 中已被 simplified commit 删除的独立 `TMP_PAGE_UNAME` / pipe primitive，先纯静态读透其前置与 Violin 配置可用性。

## 2026-07-13 popsicle initial TMP_PAGE / pipe 路线：静态否决为当前绕过

- 已读完 `28f5d45` 被 `ed6a86d` 删除的 `TMP_PAGE_UNAME` / pipe / root 代码。它不是独立 bypass：先通过 `pselect_write_once_child()` 向推测的 `pipe_inode_info.tmp_page` 写入 UTS page，uname 改变才是 oracle，之后才由 pipe physical R/W 做 credential patch。
- 初始源码明确 `PIPEI_LIVE_DEFAULT_BIASES=""`，未知机型没有 bias 时拒绝 auto-write；其 historical profile 还固定 Xiaomi 17 的 `/dev/uinput` 与 CPU7。Violin 没有同 build pipe inode bias/anchor，且 current pselect route 已两次 oracle=0，因此此分支不能绕过当前 primitive 失败。
- 决策：TMP_PAGE 仅保留为静态设计参考，不上机写入或扫描。下一阶段回到 Violin 当前 pselect no-overwrite 的根因定位，必须找到 independent stack/object placement evidence，不能继续从 popsicle 的 post-primitive 代码寻找 root 路径。

## 2026-07-13 Popsicle 目标生成器在 Violin 原始镜像上的独立 pselect 复算

- 新增可复跑离线驱动 `analysis_outputs/violin-popsicle-direct/audit_popsicle_pselect_layout.py`，输出 `popsicle-pselect-layout-violin-20260713.json`、对应五个函数反汇编和 `POPSICLE_PSELECT_LAYOUT_RECONCILIATION_2026-07-13.md`。只读取 OTA boot 与公开 Popsicle source；未构建、安装、运行 payload，未触碰设备。
- 该驱动直接复用 Popsicle HEAD `generate_target.py` 的 `derive_pselect_layout()`；因 host 无 `llvm-objdump` 用 Capstone 输出其所需的 ARM64 指令文本。Popsicle 外围生成器的 Xiaomi 17 kallsyms prefix/self-description 假设不匹配 Violin，故仅替换这两个识别器，并以 Violin 的 unique u32 RVA table、`_text/_stext/_edata/_end` 闭合和 upstream BTF `__start_BTF/__stop_BTF` 闭合验证输入。
- 结果：Violin kernel SHA-256 `9552098b7fadbb2f6375252f69a47dc132ab36cec3290f5219c8103dce064d33` 上，`PSELECT_WAITER_WORD_SHIFT=0`，pselect word0 与 futex waiter 均为 syscall stack `sp-0x200`；pselect frames `0x90+0x1f0`，futex frames `0x70+0x60+0x1c0`。这独立确认 `target.h` 的 shift，不支持任何 `shift=1` 重跑。
- 读透 latest direct source 后补充：`source/src/fops.c` 的 pselect stack fdset 只填 words 0..12，确实不填 word13 `ww_ctx`；`source/src/util.c` 虽会在另一份 sprayed fake object 中置零 `ww_ctx`，两者不能混同。已完成的 Violin word13=0 single-variable 回归因而是有效测试，但 oracle 仍为 0。
- `source/src/pipe.c` 的 `ret/calls/success` 成功只由 `route_done && consumer_calls && consumer_success` 决定，child 不校验 `sysctl_bootid`；boot-id oracle 在父端 `direct_read_shape0_exact64_once()` 才验证。因此历史 `ret=4/calls=1/success=1/oracle=0` 不能被解释为写入成功。下一步保持纯离线 waiter 消费/生命周期静态重建，禁止据此上机重跑。

## 2026-07-13 direct route CVE 激活门禁缺失

- 新增 `analysis_outputs/violin-popsicle-direct/CVE_TRIGGER_GATE_AUDIT_2026-07-13.md`。Popsicle HEAD 和当前 Violin candidate 的 `waiter_thread()` 丢弃 `FUTEX_WAIT_REQUEUE_PI` 的返回；`run_main_route_threads()` 也丢弃 `FUTEX_CMP_REQUEUE_PI` 的返回及 errno。底层 `futex_op()` 只是 raw syscall wrapper。
- 历史 Violin trigger 定义要求 `CMP_REQUEUE_PI=-1/errno=EDEADLK`；`ret=0` 不是 rollback/UAF 成功。此前 P0-seed 日志只记录 pselect 和 consumer 计数，没有这两个 futex 状态。因此 `ret=N/calls=1/success=1/oracle=0` 完全可能只是普通 `sched_setattr(nice=19)` 成功，并不能证明伪 waiter/UAF 存在。
- 结论：当前 oracle 失败尚不能区分“CVE 未激活”和“已激活但后续对象/栈消费失败”。唯一允许的下一动态步骤是 trigger-only 诊断：保留 futex 同步，记录两次 syscall return/errno；禁止 pselect、skb/page 准备、scheduler consumer、boot-id/entry-task/credential/SELinux 操作。只有 `EDEADLK` 才能为后续离线分析提供激活证据。

## 2026-07-13 trigger-only：CVE rollback 已确认，未进入后利用

- 使用完整 `/tmp/ndk` NDK r29 编译隔离诊断 binary `analysis_outputs/violin-popsicle-direct/build/bin/preload.so`，SHA-256 `00E0576A983E8393C8565089F691DF5E308132F3C1F716302CD0B9516D497BA3`。新的 `IONSTACK_TRIGGER_ONLY_PROBE=1` 在 `run_exploit()` 的最前端分叉，子进程只创建原 futex waiter/owner 同步并记录 syscall status；静态检查和 Android 35 AArch64 ELF 构建通过。
- 目标当前 boot 上只运行一次：`CMP_REQUEUE_PI` 为 `ret=-1 errno=35(EDEADLK)`，满足历史定义的 rollback/UAF 激活；waiter 本身在其 timeout 后为 `ret=-1 errno=110(ETIMEDOUT)`。完整输出 `analysis_outputs/violin-trigger-only-probe-20260713.txt`。
- 该诊断不执行 pselect、page/spray、scheduler consumer、boot-id、per-CPU/entry-task、credential 或 SELinux 操作。后检设备仍为 boot `02dbe33b-7783-40c1-8bc2-62103a98f1df`、`uid=2000(shell)`、SELinux Enforcing；远端临时 `.so` 已删除。
- 结论：历史 P0 `oracle=0` 不再可归因于 CVE 未触发；后续仅离线定位 timeout 后 pselect stack placement / forged waiter 被 scheduler 消费为何未产生 boot-id write。trigger-only 成功不是 memory read 或 root 成功。

## 2026-07-13 pselect readiness control 与 trace 回归：trace 重启

- 新增 userspace-only `analysis_outputs/violin-popsicle-direct/pselect_ready_probe.c`，只复制历史 15 个 fdset qword 的 bit pattern，不含 futex/UAF、page/spray、scheduler、boot-id 或任何 kernel address dereference。NDK r29 Android 35 binary SHA-256 `89987915DE3A14B38AAF995A935A808C1B6BA8908B8E30D70AFD963ED7F46CF5`。
- target 实测该 control 在 5006ms 后 `pselect ret=0 errno=0`，所有 returned fdset words 清零；日志 `analysis_outputs/violin-pselect-ready-probe-20260713.txt`。因此先前 direct route 的 `ret=4/5` 不能归因于原始 fdset 本身立即 ready，consumer/scheduler 是必要差异。
- 基于这个独立结果，对 P0+first-perCPU direct 仅加 before/after fdset 与 elapsed 时间打印（`IONSTACK_PSELECT_TRACE=1`，binary SHA-256 `710B37BD4EA3B5FE0D59D29B028944689BC9F3A3B165E412EBF44071E25B8F8A`）进行一次 trace。该 run 在进入 pselect、打印 before fdsets 后设备断开并重启；无 pselect return、after fdsets、oracle、entry-task 或 credential 输出。
- 设备从 `02dbe33b-7783-40c1-8bc2-62103a98f1df` 重启到 `e8a179a4-3225-4e3c-92c1-dd2a10860e8a`，随后 shell UID 与 SELinux Enforcing 正常；临时 remote binary 已删除。记录 `analysis_outputs/violin-p0-pselect-trace-probe-20260713.txt`、总结 `PSELECT_READINESS_AND_TRACE_AUDIT_2026-07-13.md`。
- 决策：trace logging 没有提供可用 oracle，反而证明 current direct shape 在此阶段 crash-sensitive。停止全部 current direct shape/timing/word13/trace 重跑；接下来只允许同 build rooted crash/oops 证据恢复与离线 `rt_mutex` waiter-consumption reconstruction。
- 重启后已做一次 shell-only crash surface 读取：`/sys/fs/pstore`、`/dev/kmsg` 均拒绝，`/dev/block/by-name/oops -> /dev/block/sdc79` 存在但未越权读取；记录 `analysis_outputs/post-trace-crash-readonly-surface-20260713.txt`。因此当前无本机 crash stack，后续若能从同次 boot 的 root context 恢复 mtdoops，才可将其作为归因证据。

## 2026-07-13 direct consumer 与 pselect stack-copy 无序竞争

- 新增 `analysis_outputs/violin-popsicle-direct/CONSUMER_ORDERING_RACE_AUDIT_2026-07-13.md`。精确 `core_sys_select` 反汇编确认 `nfds=320` 时三段 fdset 连续位于 base `sp+0x80/+0x28/+0x50`，pselect/futex waiter 仍精确同为 syscall `sp-0x200`；不支持“三 fdset 不连续”或 shift 错误的解释。
- 代码顺序缺口：`do_pselect_fake_lock_route()` 先置 `punch_consume_go`，后调用 pselect；consumer 收到该值即可 sched_setattr，没有“pselect 已进内核并完成 fdset copy”的确认。trace 在二者之间增加打印后重启，说明该 pre-copy window crash-sensitive，虽无 crash stack 不能断言精确故障指令。
- 同 fdset standalone control 的 `ret=0/5s` 与 consumer-active direct 的 `ret=4/5` 结合表明 consumer/scheduler 是必要差异。此前 50ms 只是一个固定晚延迟，不构成 stack-copy barrier，也不能否定该 race。
- 决策不变：缺少可验证的 deterministic post-copy synchronization 时，禁止 timing sweep/current direct shape 运行；继续纯静态 waiter lifecycle 对账和同 boot privileged crash evidence 恢复。

## 2026-07-13 post-copy wchan barrier：仍无 boot-id oracle

- userspace-only `pselect_wchan_probe.c`（SHA-256 `E370D3B69722E76DE732D3F610B5E90E7685683A8153AB7AF8B505BB615100D9`）在目标证实：pselect thread 处于 `do_select` 时，`/proc/self/task/<tid>/wchan` 与 `syscall` 可由同进程读取；日志 `analysis_outputs/violin-pselect-wchan-probe-20260713.txt`。结合 exact `core_sys_select` copy-before-select 反汇编，该值是可验证的 fdset post-copy barrier。
- candidate consumer 改为只有显式 `IONSTACK_POSTCOPY_WCHAN_BARRIER=1` 且见到 `do_select` 后才 sched_setattr；未设置时禁用 consumer，防止旧 pre-copy race。Android r29 build 的 binary SHA-256 `FAB1CCFA46AB676BE5E777B30F64B2D455718E9C11A3CE86049A8C64BF4084CC`。
- 单次 P0 + first-perCPU early-exit barrier run 在 boot `e8a179a4-3225-4e3c-92c1-dd2a10860e8a` 记录 `pselect-postcopy-barrier ... do_select`、`ret=5/calls=1/success=1`，但 boot-id oracle 仍 `ok=0`；无重启，未进 entry-task/credential，后检 UID shell / SELinux Enforcing / boot ID 不变。日志 `analysis_outputs/violin-p0-wchan-barrier-probe-20260713.txt`。
- 结论：消除了 pre-copy consumer race 与 fdset layout 两个解释。若 task 的 `pi_blocked_on` 在 sched_setattr 时仍是伪造 waiter，已验证的 `rt_mutex_adjust_prio_chain` 应走 rb erase 并改变 B；oracle 不变故问题收敛到 waiter 实际 lifetime/identity 或更早 exact rt-mutex exit。写入 `POSTCOPY_BARRIER_RESULT_2026-07-13.md`，停止所有 current direct shape 动态运行。

## 2026-07-13 EDEADLK + ETIMEDOUT 的 direct waiter 生命周期闭合

- 保存 Android common `android15-6.6` 的 `kernel/futex/requeue.c` 到 `analysis_outputs/references/android15-6.6-requeue.c`，并在 `FUTEX_WAITER_LIFETIME_RECONCILIATION_2026-07-13.md` 与 Violin raw image 交叉审计。
- Android 6.6 状态机表明：proxy deadlock 的 `ret<0` 把 in-progress requeue 回滚到 `Q_REQUEUE_PI_NONE`；waiter 随后 timeout 时转为 `Q_REQUEUE_PI_IGNORE`，early cleanup 移除 waiter 并返回 `ETIMEDOUT`。只有 completed requeue 才暂时处于 `pi_blocked_on`，且该路径返回前也有 cleanup。
- Violin exact `futex_wait_requeue_pi@0x1a2890` 有相同的 stack waiter、state local `sp+0x6c`、`futex_wait_queue@0x1a2a68`、proxy wait/cleanup/unqueue call structure；target 实测正是 EDEADLK + ETIMEDOUT，且 post-copy barrier 后 B oracle 不变。该组合支持正常 teardown，而非存活到用户态 sched_setattr 的 stale waiter。
- 决策：EDEADLK 只能证明 proxy requeue deadlock，不是 direct UAF/read primitive 建立。没有独立证明能越过 timeout cleanup 的 lifetime break 前，direct-data route 语义上在 rbtree 前阻断；停止它并将研究重心转回不同 primitive/canonical leak 路线。

## 2026-07-13 waiter lifecycle 结论更正：Violin 含未修复的 `remove_waiter()`

- 上一节的“timeout cleanup 清除了 stale waiter”推断已撤回。它只按 Android requeue 的正常状态机推演，却遗漏 CVE-2026-43499 修复所针对的 `remove_waiter()` 错任务清理缺陷。
- 已将上游 fix 原样保存为 `analysis_outputs/references/CVE-2026-43499-fix-3bfdc639.patch`：proxy rollback 时 `waiter->task != current`；易受影响版本对 `current` 加 `pi_lock`、dequeue supplied waiter、清 `current->pi_blocked_on`，使 `waiter->task->pi_blocked_on` 指向已释放的 stack waiter。
- Violin exact raw image 已验证未修复：`remove_waiter` runtime `0xffffffe3882520f0` / image `0x10520f0`，先 `mrs x20, sp_el0`，再 `add x21,x20,#0x90c`，并于 `0x1052178` 执行 `str xzr,[x20,#2360]`（`0x938`）；仅更晚读取 `[waiter,#0x50]`，没有将其用于上述 lock/clear。完整指令证据及更正报告：`analysis_outputs/violin-popsicle-direct/FUTEX_WAITER_LIFETIME_RECONCILIATION_2026-07-13.md`。
- 因此实测 `EDEADLK` + `ETIMEDOUT` 与 CVE 预期的 dangling `waiter->task->pi_blocked_on` 相容，不能再视为 no-UAF 证据。post-copy barrier 的 `oracle=0` 仍有效，但根因应继续离线审计 stale waiter identity / `sched_setattr` 的精确 `rt_mutex_adjust_pi` 分支；不再运行 current direct shape。

## 2026-07-13 `sched_setattr` → stale waiter 静态路径已核验

- 新增 `analysis_outputs/violin-popsicle-direct/SCHED_STALE_WAITER_PATH_AUDIT_2026-07-13.md`。同 build 反汇编表明 `sched_setattr@0xf2e68` 以 `w2=w3=1` 进入 `__sched_setscheduler`，并在 `0xf37bc` 调 `rt_mutex_adjust_pi@0x10526c8`；candidate consumer 不会因为调用了非 PI scheduler API 而跳过此路径。
- `rt_mutex_adjust_pi` 精确读取 `task->pi_blocked_on@0x938`，从 waiter 读取 priority `+0x18` 与 lock `+0x58`，不等时进入 `rt_mutex_adjust_prio_chain`。candidate pselect 覆盖正写这些字段；`FAKE_WAITER_PRIO=130` 与 `nice=19` 对应普通优先级 139 不相等，不能视作静态 no-op。
- 因而 post-copy barrier + oracle=0 的剩余未知已收窄为 scheduler 当刻 `pi_blocked_on` 的真实值/状态转换及后续 chain 分支；静态模型不伪称能证明它。没有恢复 current direct shape 的设备运行。

## 2026-07-13 当前 boot passive trace-buffer canonical audit：无记录

- 目标在线 boot `e8a179a4-3225-4e3c-92c1-dd2a10860e8a`、shell/Enforcing 下，只读读取 tracefs；没有 enable event、写 filter、创建 kprobe 或运行 payload。此前可见 BCC kprobe format 含 `unsigned long __probe_ip`，若 buffer 已有 record 可成为同次 boot canonical text 候选，故先检查被动 buffer。
- `tracing_on=0`；`/sys/kernel/tracing/trace` 与 `per_cpu/cpu0/trace` 均显示 `tracer:nop`、`entries-in-buffer/entries-written: 0/0`；`current_tracer` 被 SELinux 拒绝。旧 `dma_buf_vmap_miuibpf_bcc_2817` event 的 `enable/id` 在本 boot 不存在。
- 结论：本 boot passive trace buffer 不提供 canonical address；这只否定“读取既有 buffer”这个面，不授权或尝试 tracefs 写入。完整证据 `analysis_outputs/trace-buffer-readonly-canonical-audit-20260713.md`。

## 2026-07-13 `/dev/hpc-cdev` 单命令只读 ABI audit：仅温度标量

- 同 OTA `hpc_cdev.ko` 反汇编 `hcdev_ioctl`：仅三个 dispatch；`0x5800` 调 `hdev_boot()`（控制动作，禁止测试），`0x5801` 只返回 atomic status，`0xc0085802` 读写 8-byte `{int32 tsens_id,int32 temperature}` 并调用 `xr_tsens_read_temp`。最后一个是唯一可定义为只读结构化查询的 command，输出 ABI 无 pointer-sized field。
- 新增极小 probe `tools/hpc_cdev_readonly_probe.c`，NDK r29 Android35 `-Wall -Wextra -Werror` build，SHA-256 `884CB83C27686AF93B09785639F358E7045C2C62EE5473C9E9E986B78BC33A97`。在目标 current boot 上以 O_RDONLY 调 `0xc0085802`，返回 `ret=0,id=0,temp=41000`；未发送任何 boot/control/allocator ioctl，远端 binary 已删除。
- 后检 boot `e8a179a4-3225-4e3c-92c1-dd2a10860e8a` 不变，UID shell / Enforcing。结论：节点可访问但无 canonical pointer 输出；禁止扩展为 ioctl scan。证据 `analysis_outputs/hpc-cdev-readonly-audit-20260713.md`。
- 补充静态排除 `/dev/hpc-rpmsg`：同 OTA `hpc_rpmsg.ko` 的 `hrpdev_open()` 不是无状态 open，它分配 `3520` bytes 的 per-file object 并调用 `rpmsg_create_ept()`；`hrpdev_read()` 消费/释放 rpmsg queue 或在空队列 schedule。因此没有在目标 open/read，不能把这个节点列为 passive read-only probe。记录并入 `hpc-cdev-readonly-audit-20260713.md`。

## 2026-07-13 `/dev/ocm-buf` 静态排除：无无副作用 query

- 按 OTA `xring-ocm.ko` 还原 `ocm_ioctl`，只有 `0xc0044f02`（读取 userspace clock value 后调 regulator/clock-rate control）和 `0xc0084f01`（读取 allocation request、`npu_ocm_alloc`、IDR 分配并回传结果）。二者都改变 kernel/device state；虽 `ocm_open()` 本身空操作，也没有合法 passive information query。
- 因此 target 未被 open 或 ioctl；world-readable mode 不构成 candidate leak。详细指令级结论：`analysis_outputs/ocm-buf-static-exclusion-20260713.md`。

## 2026-07-13 `/dev/io_monitor` 静态排除：read 会写全局 monitor flag

- 精确 OTA `io_monitor.ko`：`io_monitor_dev_open()` 直接 return 0，但 `io_monitor_dev_read()` 会分配 4MiB temporary buffer，`0x6704` 把 `io_monitor_enabled` 写为 0，再在 `0x71f8` 写为 1，然后才 copy-to-user。故 read 不是无副作用观测。
- 输出逻辑是 `sprintf` I/O records/counter/timestamp；没有声明的 canonical pointer ABI。没有对 target open/read。结论和偏移见 `analysis_outputs/io-monitor-static-exclusion-20260713.md`。

## 2026-07-13 `/dev/camlog` 静态排除：read 消费共享 FIFO

- 匹配 OTA `cameralog.ko` 的 `cameralog_read()` 在 copy-to-user 前调用 `__kfifo_out(..., 0x408)`，一次 read 会从共享 camera-log FIFO 移除一条固定大小记录，故不是 passive read。
- ioctl dispatch 同时存在 logger-state 写与 FIFO output/消费路径，未发现具有固定 pointer-sized 输出字段的无副作用 canonical-address 查询 ABI。
- target 未打开、读取或 ioctl `/dev/camlog`。它不应因节点权限可访问而列为 canonical leak probe；完整静态证据：`analysis_outputs/camlog-static-exclusion-20260713.md`。

## 2026-07-13 标准 canonical-address surface：当前 boot 无输出

- 在 boot `e8a179a4-3225-4e3c-92c1-dd2a10860e8a`、shell UID 2000 / Enforcing 下纯读复核：`/proc/kallsyms`、`/proc/vmallocinfo`、`/proc/iomem`，及 `mali_kbase`、`xring_hpc`、`io_monitor`、`hpc_cdev`、`xring_ocm` 的 `sections/.text` 都返回 `Permission denied`。
- `/proc/modules` 可读，但输出中的模块 load-address 字段均为 `0x0000000000000000`；这代表地址隐藏，不能作为 KASLR 候选或用于任何 slide 推导。
- 未修改 SELinux、trace、模块或设备状态。完整命令输出与结论：`analysis_outputs/standard-canonical-surface-readonly-audit-20260713.md`。

## 2026-07-13 `/dev/timestamp`：仅 timer 标量且 shell open 被拒

- OTA matching `xr_timestamp.ko` 的 `ts_ioctl()` 只接收 `0x80086b00`（counter）与 `0x80086b01`（时间），各自仅 copy-to-user 一个 `u64`；没有结构体指针或内核地址输出。
- 最小 `O_RDONLY` probe（SHA-256 `04034DFD3659FBF665AE0D6FCE5B5D9864C54FCBCF6769AE16C4FC3F3D5437CD`）实测 `open(/dev/timestamp)=EPERM`，故没有发送 ioctl；临时 binary 已删除。boot、shell UID 和 Enforcing 均不变。
- 结论：该节点既无 canonical 地址 ABI 又被 SELinux 拦截，禁止为它改 policy 或 fuzz。完整记录：`analysis_outputs/timestamp-readonly-audit-20260713/TIMESTAMP_READONLY_AUDIT.md`。

## 2026-07-13 `/dev/hpc-heap` 静态排除：open/ ioctl 均是分配控制面

- matching `hpc_mem.ko` 中 `hpc_mem_ctrl_open@0x8dc` 为 file 建立约 `0xdc0` bytes 的 controller object、写 `private_data` 并初始化状态；它不是 passive open。
- `hpc_mem_ctrl_ioctl@0x57c` 的首个 command `0x80045800` 随后进入 heap info、DMA-buf/IOMMU/heap allocation 路径；不存在已证明无副作用、固定地址输出的 query。
- target 未 open 或 ioctl `/dev/hpc-heap`。详细静态证据：`analysis_outputs/hpc-heap-static-exclusion-20260713.md`。

## 2026-07-13 `/dev/hpc-mitee-crypto` 静态排除：secure key 服务而非地址面

- matching `hpc_mitee_crypto.ko` 的 `hpc_crypto_open()` 是空返回，但 `hpc_crypto_ioctl@0xdc` 仅识别 `0xc0885800`（0x88-byte 双向结构体），进入 secure model-key 获取、长度检查和 copy-to-user 路径。
- 该 ABI 不返回可解释的 kernel object / canonical pointer，并会触发 key-service 处理，故不是 passive canonical leak candidate。
- target 未打开或 ioctl 该节点；完整依据：`analysis_outputs/hpc-mitee-crypto-static-exclusion-20260713.md`。

## 2026-07-13 Popsicle `KernelSnitch`：只能给 P0 `mm_struct`，不是 canonical text leak

- 读透 bundled `src/kernelsnitch/kernelsnitch.h`：ARM/VA_BITS=39 默认 brute-force range 是 `0xffffff8000000000` 起的 64GiB，即 Violin 已证伪为 KASLR text 的 P0/direct-map 域；成功结果至多是 `mm_struct` direct-data anchor。
- BTF 确认 Violin `mm_struct` 为 `0x4c0`，当前 CPU feature 不含 `mte`；这些输入不改变地址域。默认 `kernelsnitch()` 在 10 CPU target 上会启动 20 threads、映射 64GiB、创建 4096 个 parked futex waiter，并以 16 collisions/327680候选测量进行大规模工作。
- 该机制不符合当前 passive canonical audit，也无法提供 fops/CFI 所需 text address。更正：它并非“从未运行”——历史 P0 first-stage 的 `prepare_kernel_page()` 已间接使用它，五份日志的 `workspace=` 均是成功取得的 P0 slab base；当前 boot post-copy 为 `0xffffff801dc28000`。这只证明 preparation anchor，不证明 pselect overwrite 或 root，故不恢复 direct shape。完整可行性/地址域结论：`analysis_outputs/kernelsnitch-violin-feasibility-audit-20260713.md`。
- 复核一个潜在配置疑点：BTF 的 `struct mm_struct` payload 为 `0x4c0`，candidate 配置使用 `MM_STRUCT_SZ=0x500`；同 build rooted `/proc/slabinfo` 显示 `mm_struct ... 1280`，即 SLUB object stride 正是 `0x500`。因此该常量正确，不是 oracle=0 的根因。此项也写入 `kernelsnitch-violin-feasibility-audit-20260713.md` 与 `popsicle-violin-source-drift-closure-20260713.md`。

## 2026-07-13 Violin candidate 对 Popsicle HEAD 的完整 source-drift 闭合

- 对 official `98cf38fcf6f2e3f508979d6ad46abffb1837a246/source/src` 与 `violin-popsicle-direct/src` 做 full `git diff --no-index`。差异只在新增 `target.h`、一个 `common.h` 配置、`fops.c` 诊断/word13/bounded-delay，以及 `main.c` trigger-only、post-copy barrier 和 early-exit probes。
- `pipe.c`、`util.c`、`slide.c`、`offset.h`、`preload.c`、`su_daemon.c` 与 Kernelsnitch 均无差异。此前 `EDEADLK` 也已独立证明 trigger 生效。
- 所以 Violin oracle=0 不能解释为未记录的本地 core-source drift；剩余是 target-specific forged waiter/rt-mutex 语义问题。此结论不授权重跑 shape。记录：`analysis_outputs/popsicle-violin-source-drift-closure-20260713.md`。
- 继续核对 initial `28f5d45`：其巨大 diff 主要删除成功 primitive 后才使用的 configfs fops/pipe/root stage；默认 first-stage 的 memfd guard-mm lifetime、context 数量、`MM_STRUCT_SZ=0x500`/order-3、4 skb reclaim 与 fops waiter content 与 latest direct core 等价。initial 的 `childs[]` 对 memfd path 实际填 `-1`，不构成另一种存活对象布局。故不能把“切回 initial”当作无证据的 first-stage 绕过；详情并入 source-drift closure。

## 2026-07-13 KSULaoderv2 / Shizuku 不是当前 root bootstrap

- Graph 读到 loader 的 `ShizukuManager` 仅检查/请求 Shizuku permission，MainActivity injection/boot workflow 均要求 service available；没有内核 exploit 或 KernelSU kernel injection primitive。它至多委托至 Shizuku server 的 shell 域。
- target 只读确认已装 `me.weishu.kernelsu` 与 `moe.shizuku.privileged.api`，并有 `shell` 用户的 `shizuku_server`；未见 `ksud`/kernelsu daemon，当前 ADB shell 仍 UID 2000 / Enforcing。
- 结论：Manager/Shizuku 安装状态不能证明或产生 KernelSU root；本轮未调用 su、未执行 loader injection。完整证据：`analysis_outputs/ksu-loader-shizuku-bootstrap-audit-20260713.md`。

## 2026-07-13 `sysctl_bootid` 双命名静态闭合：只有一个 boot-ID data buffer

- Rooted same-build kallsyms 的 `sysctl_bootid` 是 `b`（BSS）符号，canonical `ffffffe389536f58` 对 `_text` 的 offset 精确为 `0x2336f58`；raw boot kernel 文件长度 `0x22c4a00` 小于该 BSS offset，和零初始化 runtime storage 一致。
- Android common Android15-6.6 random.c 明确定义 `static u8 sysctl_bootid[UUID_SIZE]`，而 `random_table[]` 中的 `boot_id` ctl_table 使用 `.data = &sysctl_bootid`。故符号是 16-byte UUID buffer，不是 ctl_table entry；不存在本轮可由该符号推导的第二个 boot-ID 地址。
- 已将 `target.h` 的 `SLIDE_SYSCTL_BOOTID_OFF` 改为说明性 compatibility alias（仍等于 `SLIDE_RANDOM_BOOT_ID_DATA_OFF`），不改变任何生成地址。此结论只修正命名；历史 target 的 P0 boot-ID oracle 仍为 0，未产生 canonical leak，不得恢复 direct shape。完整对账：`analysis_outputs/sysctl-bootid-symbol-reconciliation-20260713.md`。

## 2026-07-13 `/dev/mali0` 静态排除：open 本身创建 GPU context

- exact OTA `mali_kbase.ko` 的 `kbase_open@0x20700` 在 open 中先执行 `kbase_device_firmware_init_once`，随后 `kmalloc_trace(0xcc0)`、写 `file->private_data` 并置 file flag；release 会走 `kbase_destroy_context`。因此 `/dev/mali0` 不存在可在不改变 GPU/device state 的前提下到达的 ioctl 查询面。
- `kbase_ioctl@0x1f5d8` 可辨认的 `0xc0048000` 分支只是 4-byte version negotiation copy-in/out，无 pointer-sized 输出；其余分支为 GPU memory/context/queue/profile 等状态接口，禁止 scan。target 未 open/ioctl。完整离线证据：`analysis_outputs/mali0-static-exclusion-20260713.md`。

## 2026-07-13 `/dev/npu_freq_qos_{min,max}` 静态排除：open 安装 QoS request

- matching `npu_freq_qos.ko` 中 min/max `open()` 都 `kmalloc_trace(0xdc0)`、写 `file->private_data` 并调用 `freq_qos_add_request`；`release()` 调 `freq_qos_remove_request`，write 调 `freq_qos_update_request`。因此 open 不是 passive action。
- read 最终只经 `simple_read_from_buffer` 回传 4-byte frequency scalar，不含 canonical pointer，但到达它前已经改变 QoS bookkeeping。target 未 open/read/write，禁止 scan。详细反汇编与结论：`analysis_outputs/npu-freq-qos-static-exclusion-20260713.md`。

## 2026-07-13 `/dev/tango32` 静态排除：翻译控制 ABI 不泄漏完整地址

- exact `tango32.ko` 只有 `tango32_ioctl`，并处理 binary-translator 的 per-thread state、caller fd/directory、`iterate_dir` 和 `vfs_llseek` 等控制工作，不是无副作用 read 面。
- 两个表面 output 命令中 `0x800474a0` 仅 copy-out 常量 2，`0x800874a5` 仅输出一个 current-task 字段的低 32 bits 加常量 12；没有 64-bit canonical pointer，不能推导同次 boot KASLR 基址。target 未 ioctl 或 scan。完整反汇编记录：`analysis_outputs/tango32-static-exclusion-20260713.md`。

## 2026-07-13 公开 Linux LPE 路线配置级排除

- 解压 matching config 后确认 `CONFIG_CRYPTO_USER_API_AEAD`、`CONFIG_AF_RXRPC`、`CONFIG_NF_TABLES`、`CONFIG_USER_NS` 均未设置；同 boot shell 的 `CapEff=0`、SELinux Enforcing。live 读取 `/proc/sys/user/max_user_namespaces` 被策略拒绝，但 config 已对 user namespace 给出决定性否定。
- 因此 Copy Fail 的 AF_ALG AEAD 前提、Dirty Frag 的 RxRPC path、CVE-2026-23111 的 nf_tables/userns 前提均不成立。Fragnesia 虽涉及 target 已启用的 XFRM/ESP，公开路径仍要求 `CLONE_NEWUSER|CLONE_NEWNET`，而 `CONFIG_USER_NS` 未设置，不能因 `CONFIG_XFRM_ESP=y` 误报为可达。
- 没有创建 namespace、运行 exploit 或改变设备。完整 source/config 对账：`analysis_outputs/public-lpe-route-config-triage-20260713.md`。

## 2026-07-13 CVE-2026-46333 ptrace exit-race：未找到 Android carrier

- 该公开 route 依赖可在 exit/MM-null window 捕获 FD 的同 UID privileged-transition process。对 `/system`、`/system_ext`、`/product`、`/vendor`、`/odm`、`/apex` 做 metadata-only `find -perm /6000` 与 `getcap -r`，输出均为空。
- 因此本 build 未发现传统 `ssh-keysign`/setuid helper 类型 carrier，不能直接移植公开 server-distribution PoC；这不是对内核 patch 状态的声明。未调用 `pidfd_getfd`、未实施 race。记录已并入 `analysis_outputs/public-lpe-route-config-triage-20260713.md`。

## 2026-07-13 CVE-2025-48595 SQLite lookaside：版本候选成立，root carrier 未证实

- 只读 pull 的 target `/system/lib64/libsqlite.so` SHA-256 为 `12C3DA1C8A261541A648C77F41C0A7BDE4BC0B0DFA72F1C0F912D59AA2E3F89E`，嵌入版本为 SQLite `3.44.3`；target SPL 是 `2026-05-01`。官方 Android 2026-06-01 公告将 CVE-2025-48595/A-430889718 列为 Android 14/15/16 的 High EoP，AOSP 对应修复升级/选择 SQLite 3.44.5。
- local AOSP source diff 确认旧 `setupLookaside()` 在 slot size cap 前计算 `szAlloc`；修复后先 round/cap `sz` 至最多 65528、处理负 `cnt`，再以 64-bit 计算。AOSP Framework public builder 允许正整数 `setLookasideConfig`，并经 `SQLiteConnection.nativeOpen` 调用 `sqlite3_db_config(SQLITE_DBCONFIG_LOOKASIDE, ..., sz, cnt)`。
- 该链在调用方 app 进程中运行；没有证据证明未授权 app 可以通过 binder/服务把这两个值交给特权 UID 的 SQLite 打开路径。因此只记录“版本候选 + app-process reachability”，不记录 root、稳定利用或 privileged code execution。未创建/安装/执行测试 APK 或 native trigger。完整证据/限制：`analysis_outputs/cve-2025-48595-violin-feasibility-20260713.md`。
- carrier 搜索扩大后仍为负：本地 AOSP `frameworks/base` checkout 的 `core/services/packages` 中，排除 API implementation/test 后无 `.setLookasideConfig()` caller；target 只读扫描 framework/vendor/APEX JAR 及 `/system`、`/system_ext`、`/product`、`/vendor`、`/odm`、`/apex` 的所有 preinstalled APK 的 `classes*.dex`，只有 `/system/framework/framework.jar`（API 自身）命中，APK 为零。该方法仅排除普通 direct Java bytecode，不证明 reflection/native/dynamic code 不存在；未打开 app、未写入或安装任何内容。
- 同一分区所有可读 `.so` 的 `sqlite3_db_config` string scan 仅命中 `/system/lib{,64}/libsqlite.so` 与 `/system/lib{,64}/libandroid_runtime.so`；后者是已验证 JNI bridge。未见 vendor/product native direct importer。该证据继续收窄 carrier，不排除 static link、reflection 或 dynamic code。

## 2026-07-13 Popsicle 当前树 EDEADLK consumer gate

- `exploit/src/slide.c` 的当前未提交 E25 hunk 在 `CMP_REQUEUE_PI=-1/EDEADLK` 后置 `slide_uaf_primed` 与 `slide_consume_stop`；consumer 在其唯一 `sched_setattr_tid()` 前检查两者并写 `SLIDECONS_SKIP` 后退出。因此从当前 tree 构建的 APK/ELF 不会消费刚触发的 stale waiter，EDEADLK 只能作为 trigger diagnostic，不能产生 pselect/rbtree primitive。
- upstream base 是 `1a10c4e500238c2bc0a46833c4caf728740f3aee`，该 gate 是 local working-tree modification；历史上机 binary 的 hash/log 必须单独看待。未改 gate、未构建/安装/运行，current direct shape 仍冻结。详见 `analysis_outputs/popsicle-uaf-consumer-gate-audit-20260713.md`。
- 已将 gate 与历史 `analysis_outputs/violin-popsicle-direct/src/slide.c` source snapshot 对齐：历史 source 无 `slide_uaf_primed`/`SLIDECONS_SKIP`，consumer 会实际 `sched_setattr_tid()`，CMP fourth arg 为 `(void *)1`；其 post-copy scheduler-success/oracle=0 是实测负结果。当前 tree 同时引入 gate 和 `(void *)0` 参数，故不是历史 binary 的复现，也不能用 gate 否定历史 oracle。未构建或运行。

## 2026-07-13 Bad Epoll / CVE-2026-46242：Violin raw kernel 静态条件成立

- matching kheaders 明确 `CONFIG_EPOLL=1`。rooted same-build `_text=ffffffe387200000` 对齐 raw `boot.img.kernel` 后，`ep_clear_and_put@0x429b6c` 调用的 local `ep_remove@0x427dec` 仍直接读取 `epi->ffd.file` 并在 `file->f_lock` 后检查 dying；缺失 fix `a6dc643c693` 所要求的 `epi_fget()` file pin。
- 同一 terminal free path `0x429cd4..0x429cf4` 直接 `bl 0x311774`，same-build kallsyms 对应 `kfree`，没有 `07712db8` 的 `kfree_rcu`/RCU defer。这意味着公开 kernelCTF chain 所依赖的 eventpoll UAF 未被该相关修复削弱。此为 exact binary evidence，不只是 6.6.77 < stable version 的推测。
- 公共 writeup/patch/source 已本地保存至 `analysis_outputs/references/bad-epoll-source/`；公开 exploit 是 x86-64 6.12/COS，作者明示 Android exploit still in progress。只记录 Violin static-vulnerable candidate，不记录 root/可运行 port；未 build/install/run。完整结论：`analysis_outputs/bad-epoll-violin-static-audit-20260713.md`。
- Bad Epoll port feasibility：live readonly `/proc/slabinfo` 显示 `filp=320 bytes, 25 objs, 2 pages`，公开 exploit 只实现 filp 192/256 及对应 cross-cache geometry；target config 启用 `SLUB_DEBUG`、freelist hardened/random。raw `ep_remove` 可观测 active randomized file 的 `f_lock +0x10` 与 `f_ep +0xe0`，不能沿用 public x86 `struct file` constants。`CONFIG_RANDOMIZE_BASE/CFI_CLANG/SHADOW_CALL_STACK/ARM64_PTR_AUTH[_KERNEL]` 均开启，而 canonical surface 仍为负；公开 rdtscp/prefetch leak、x86 ROP/JOP f_op poll pivot 不可直接 port。UAF 保留但 root chain 未建立，详见同一 audit；本轮只读 slabinfo/CPU metadata，无 build/install/run。

## 2026-07-13 Bad Epoll：in-image BTF 闭合 fdinfo constrained-AAR layout

- 从 matching `analysis_outputs/ota_full/boot_parse/boot.img.kernel` 的 file offset `0x016d8efc` 解析完整 BTF（v1；type section `0x3644a4`、string section `0x25a180`），而不是从通用 GKI 猜测 randomized layout。BTF 给出 `struct file=0x108`，`f_lock=0x10`、`f_inode=0xb8`、`f_op=0xc0`、`private_data=0xd8`、`f_ep=0xe0`；`inode.i_sb=0x28`/`i_ino=0x40`，`super_block.s_dev=0x10`，以及 task `real_cred=0x818`/`comm=0x830`/`sas_ss_sp=0x8b8`。
- 因 `ep_show_fdinfo()` 同时取 `i_ino` 与 `i_sb->s_dev`，目标 `A` 的 constrained 8-byte `ino` read 需伪造 `f_inode=A-0x40`，并要求 `A-0x18` 存放可解引用指针。冻结的 Violin P0 profile 推得 `P0(init_task)=0xffffff80022ee280`；取 `A=+0x830` 时，guard 地址 `0xffffff80022eea98` 正好是 `init_task.real_cred@+0x818`。这提供条件性的 data-only 首个 fdinfo 验证锚点（预期 `swapper/`），不是 canonical KASLR text leak。
- 严格边界：BTF 的 C object size `0x108` 不等于 live `filp` slab object size `320`；后者连同 25 objects/2 pages、SLUB debug、hardened/random freelist 仍使 public 192/256 cross-cache 失效。未在设备触发 race/fdinfo，未证明 AAR/写入/提权，也未 build/install/run。完整记录：`analysis_outputs/bad-epoll-violin-fdinfo-bootstrap-audit-20260713.md`。

## 2026-07-13 cautious-octo-disco 方案静态审计

- 对 `https://localhosts-a.github.io/cautious-octo-disco/` 和 GitHub repo `localhosts-a/cautious-octo-disco` commit `e8a2e0877eb04369070064cb25631c892cb6bbcf` 做了**只读**审计；本地快照在 `analysis_outputs/cautious-octo-disco-source-20260713/`，完整报告在 `analysis_outputs/cautious-octo-disco-scheme-audit-20260713.md`。未运行网页、JavaScript 或 `os*.so`。
- 方案是两段式：Firefox 151 ARM64 的对象/JIT 内存破坏先构造 AAW/AAR/RW64，再以硬编码 `libxul.so` 偏移、WASM unchecked-entry 覆写调用 `mprotect` 和 shellcode；shellcode 把 `os2.so`/`os3.so` 写进 Firefox 私有目录，并以 `LD_PRELOAD` 启动。ELF 静态内容包含 futex/pselect/KernelSnitch/pipe phys-RW/KASLR/cred/SELinux/embedded KernelSU 路径，不是只读工具。
- 站点 UI 的“K80 Ultra / >95%”没有源码级正向验证：supported fingerprint list 只有 `dummy` 与 Google `frankel`，OS 按钮仅选择 `os2.so`/`os3.so`；`os3.so` 含 `dali` profile，不匹配本项目已核验 Violin baseline。其组件命名虽类似 Popsicle/IonStack direct route，但不能据此推导可移植性或 root 成功；Violin 当前 direct-shape 禁令保持不变。

## 2026-07-13 ADB live-state recheck: active `violin` target is still non-root

- After receiving screenshots of a separate rooted Android device (`turner` prompt), verified the configured target serial `03035440C1781540` directly with non-mutating ADB commands: `id`, `su -c id`, `getenforce`, `cat /proc/sys/kernel/random/boot_id`, `getprop ro.build.fingerprint`, and `uname -a`.
- Result on active target: shell is `uid=2000`; `su` is inaccessible/not found; SELinux is `Enforcing`; boot ID is `e8a179a4-3225-4e3c-92c1-dd2a10860e8a`; fingerprint is `Xiaomi/violin/violin:16/BP2A.250605.031.A3/OS3.0.303.0.WOTCNXM:user/release-keys`; kernel is `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`.
- Therefore the supplied root/Permissive screenshots confirm that another device can provide rooted evidence, but they do not establish root or a disabled SELinux state on this project's active `violin` target. The `HANDOFF.md` read-only/analysis gate remains unchanged; no payload, push, SELinux change, install, or reboot was performed.

## 2026-07-13 手工 `LD_PRELOAD` 提权尝试（未成功）

- 在用户明确要求下，对活动目标 `03035440C1781540`（Violin，boot `e8a179a4-3225-4e3c-92c1-dd2a10860e8a`）执行一次截图所示流程。使用 `outputs/preload.so`（163,560 bytes，SHA-256 `9A85EF4A41D57459BAE9035BA037CB7BCE6262DC42C217E51041F14936D4D3A0`），已推送至 `/data/local/tmp/preload.so`，远端 `toybox sha256sum` 完全一致，随后执行 `chmod +x` 与 `LD_PRELOAD=/data/local/tmp/preload.so id`。
- push/chmod 均返回 0；触发命令没有任何 stdout/stderr，且执行包装器未写出触发后的退出码。随后 ADB 立即恢复可用，boot ID 未变；`id` 仍是 `uid=2000(shell)`，`su` 仍 inaccessible/not found，`getenforce` 仍为 `Enforcing`。`/data/local/tmp` 未出现 `crash.txt`、`log.txt`、`preload.log` 或 `ksud`；普通 shell `dmesg` 仍 Permission denied。
- 结论：本次 artifact 在此 boot 上未获得 root，亦未关闭 SELinux，且未出现预期的重启。原始 push/trigger/事后只读采集已保存于 `analysis_outputs/manual-preload-attempt-20260713/`；在没有新的、可归因的 artifact 或输出证据前，不将该无输出触发重复作为成功路径。

## 2026-07-13 — `sysctl_bootid + 0x08` 不是 `ctl_table.data`

- 静态复核 Violin matching Android 15 / 6.6 源码：`drivers/char/random.c` 将 `sysctl_bootid` 定义为 `static u8 sysctl_bootid[UUID_SIZE]`；`random_table[]` 的 `boot_id` `struct ctl_table` 是另一对象，初始化时以 `.data = &sysctl_bootid` 指向该缓冲区。
- 因而符号 `sysctl_bootid` 的 `+0x00/+0x08` 分别只是 UUID 缓冲区的第 0/8 字节，不是 `procname` / `.data` 字段。`rb_node` 视角下若 child 指向 `sysctl_bootid+8`，`child->__rb_parent_color` 的写入落在 UUID 后 8 字节；它不会改写 `random_table[].data`。
- `proc_do_uuid()` 始终使用真实 `table->data` 指针，并将其指向的 16 个字节格式化为 UUID。它只能作为“缓冲区内容是否被实际覆盖”的 oracle；不能凭 `sysctl_bootid+8` 推导出对任意指针 `.data` 的重定向或 canonical-pointer 读原语。历史 target 宏已是 `SLIDE_RANDOM_BOOT_ID_DATA_OFF = sysctl_bootid + 0x08`，且受限 run 的 boot-id oracle 仍保留原 UUID，故该写入路径尚未建立。
- 关联：`analysis_outputs/sysctl-bootid-symbol-reconciliation-20260713.md`；`HANDOFF.md` §9。

## 2026-07-13 — 已授权设备执行：stable0 单次回归停在 `sched_setattr`

- 用户明确授权后，在连接的 Violin（boot `269560ec-5a6c-48fc-80c5-a5fa3d483fd1`）执行既有 `stable0-faketask-khdrpi` 浏览器路径一次，并记录回归目录 `outputs/device-regression/run-20260713-135823/`。
- 设备日志确认实际载入并到达：`CFGPROBE_MISS` → `CMP_REQUEUE_PI=-1/EDEADLK` → `SLIDEW4` → `SLIDEP2` → `SLIDECONS0: before sched_setattr`；没有 `SLIDECONS1`、`SLIDEP3`、`SLIDEW5` 或 boot-ID oracle 输出。
- 约 35 秒观察后设备未重启，boot ID、`uid=2000(shell)`、SELinux Enforcing 都不变。随后 `am force-stop org.mozilla.firefox` 清理挂起进程。该尝试未证明 rb-tree write、UUID 覆盖、canonical leak 或 root；也不支持将 `sysctl_bootid+8` 误解为 `ctl_table.data`。
- 完整证据：`analysis_outputs/device-exec-20260713-135823/REPORT.md`。

## 2026-07-13 — scheduler control excludes generic `sched_setattr` failure

- 为解释 stable0 run 停在 `SLIDECONS0`，编译并在已授权 Violin 上运行最小 Android 35 ARM64 PIE：不创建 futex/pselect/伪 waiter，仅对自身调用 `SYS_sched_setattr(SCHED_BATCH,nice=1)`。
- 目标实测 `sched_setattr_self ret=0 errno=0 (Success)`，boot、shell UID 与 SELinux 状态不变。故此前 consumer 无 `SLIDECONS1` 不是 syscall ABI 或 SELinux 的通用拒绝，只能由 stale PI/futex 状态导致。
- 同次 exploit log 在 consumer 调用前已有 `SLIDEO2: owner chain lock returned errno=13`；所以“owner→waiter PI chain 已建立”尚未被证实。下一诊断需记录 consumer 卡住时的内核 wait site，并保持当前 chain，不应继续改写 boot-id offset。证据：`analysis_outputs/scheduler-control-20260713/REPORT.md`。

## 2026-07-13 — wchan 诊断部署与证据更正

- 已构建 consumer wchan watchdog 诊断 artifact（SHA-256 `C8E3F3405E23B181F264664E52580A7BB3CA44CC1B475A1C7AD0B7EB6C2B3271`）：它只在 consumer 进入 `sched_setattr` 后采样 `/proc/self/task/<tid>/wchan`，不改 rbtree 字段或 scheduler 参数。
- target 收到 `index.html` / `exploit.html?payload=sched-wchan`，但未 fetch `.so`；清空后的 `/sdcard/Download/crash.txt` 仍不存在，故本轮没有运行 payload、没有 consumer、没有可用 wchan 数据。
- 纠正：前一轮回归读取的 crash 文件 mtime 为 13:47，而启动时间为 13:58，应作为历史日志而非本轮 payload 已执行证据。后续必须以 fresh payload fetch 与新 crash 文件时间为门禁。
- 详情：`analysis_outputs/sched-wchan-run-20260713/REPORT.md`。

## 2026-07-13 — Bad Epoll：320-byte `filp` cross-cache 源码复核

- 对本地 `violin-v-oss` `fs/file_table.c` 和既有 live `/proc/slabinfo` 做只读复核：`filp=320 bytes, 25 objs, 2 pages`；公共 Bad Epoll 代码只内建 192/21 与 256/16 两组 geometry，以及由其派生的 CPU-partial/enclosing spray 数。故不能仅把 `FILE_SIZE` 改成 320，也不能沿用任一固定计数。
- `file_free()` 对每个 file 执行 `call_rcu(..., file_free_rcu)`，回调中才 `kmem_cache_free(filp_cachep, f)`；`files_init()` 的 `filp` cache flags 不包含 `SLAB_TYPESAFE_BY_RCU`。该时序更接近公共 COS 的 per-file RCU 模型，而不是其 LTS 固定 10 ms `rcu_free_slab` 模型；未来任何受控验证须重新量化回收时序。
- 更正早期表述：本次可从 `violin_defconfig` 直接确认的是 `CONFIG_SLAB_FREELIST_RANDOM=y`、`CONFIG_SLAB_FREELIST_HARDENED=y` 和默认 slab merge 关闭；本地 defconfig 片段不单独声明 `CONFIG_SLUB_DEBUG`。无论如何，live 320/25/2 geometry 已足以否定公共 192/256 参数复用。
- 结论仍为静态候选：320-byte 几何未证明 cross-cache 不可能，但 race、页回收、fdinfo 受限读、同 boot canonical leak 均未建立；未 build/install/run。完整报告：`analysis_outputs/bad-epoll-violin-320b-crosscache-audit-20260713.md`。

## 2026-07-13 — Firefox payload delivery：失败可观测性修复

- `exploit-site/exploit.html` 原先把 `main().catch()` 的异常完全吞掉，只发无内容 `fail`；因此“iframe 已加载但 `.so` 未 fetch”无法区分浏览器 primitive 早期异常、fingerprint/decision 丢失或 payload fetch 前异常。
- 已改为把异常 name/message 与最多三行 stack 序列化为最多 1000 字节的 `JS_FAILURE`，写入 child localStorage，并随 `fail.finalMessage` 发给 parent；`index.html` 在已确认阶段保存并显示该失败日志，而非立即清理且丢弃原因。仅改浏览器诊断可观测性，不改 payload、rbtree 或 scheduler 参数。
- 用 Node 对两份抽取的 inline script 执行 `node --check`，均通过。仍需一次 fresh Firefox 页面运行来验证实际消息和 `.so` fetch；在该运行前不把旧 crash 日志作为新证据。

## 2026-07-13 — fresh `sched-wchan` run：consumer 未被触发，watchdog 时序错误

- 已在 Firefox 151 对 `payload=sched-wchan` 执行 fresh run，并从新建 `/sdcard/Download/crash.txt` 拉取证据至 `analysis_outputs/sched-wchan-run-20260713/crash-1431.txt`。该 artifact 确实执行：`CMP_REQUEUE_PI` 在 retry 0 返回 `EDEADLK`；这不是历史 stale log。运行后已 `am force-stop org.mozilla.firefox`，当前 shell UID/SELinux 仍为 `2000`/Enforcing。
- 日志没有 `SLIDECONS0`。源码闭环确认原因：consumer 只在 `slide_consume_go=1` 后调用 `sched_setattr`，而当前 run 的唯一写入位于 waiter 的 `slide_pselect_stack_copy()`；该函数要等 `FUTEX_WAIT_REQUEUE_PI` 返回后才会到达。EDEADLK 后 child 却直接等待 `slide_route_done`，故没有任何路径 signal consumer，也没有 `SLIDEW3/4`。这解释了 consumer/scheduler 路径未运行，并非通用 `sched_setattr` 拒绝。
- 12 个 `SCHEDWATCH` 均为 `wchan=0`：watchdog 在 consumer 建线程后固定 500 ms 开始采样，早于未被 signal 的 consumer 进入 scheduler syscall，故本次未获得 kernel wait site。后续诊断应以 `slide_consume_enter_sched` 为 armed 条件，并先建立独立的 consumer-go signal；当前 artifact 不能回答 scheduler wait-site 问题。

## 2026-07-13 — consumer-go 补信号复跑：consumer 已进 sched，但未触发目标 PI wait-site

本轮将 `exploit-repo/IonStack/CVE-2026-43499/exploit/src/targets/violin-v-oss/slide.c` 的诊断路径改为：`SLIDEC3_OK(EDEADLK)` 后立即 `slide_consume_go=1`，并让 `SCHEDWATCH` 等到 `slide_consume_enter_sched` 后再采样。重建后的站点 artifact 为 `exploit-site/preload-local-violin-sched-wchan.so`，SHA256 `7832EDEC7B3AFB43A8CA9FA5F5DFD7CD1ADBCBE0001C99D4F1CE49600822520E`，size `164152`。

新鲜设备证据在 `analysis_outputs/sched-wchan-run-20260713/crash-consumer-signal.txt`。启动前 boot_id `bd8b7c6e-bddc-4935-b7a1-82770c8f6988`、uptime `1062.15 8738.52`；采集后 boot_id 仍为 `bd8b7c6e-bddc-4935-b7a1-82770c8f6988`、uptime `1092.92 8981.50`，shell UID/SELinux 未变。关键日志：`SLIDEC3_OK` 后 `SLIDEC3_SIGNAL: consumer_go=1`，随即出现 `SLIDECONS0: before sched_setattr tid=8115 nice=1 call=1` 和 `SLIDECONS1: after sched_setattr ret=0 errno=0`。`SCHEDWATCH` 的首个样本为 `fuse_simple_request`，后续样本全为 `0`。

结论：此前没有 `SLIDECONS0` 是编排问题，已验证补信号后 consumer 会执行；当前真正卡点变为 `sched_setattr(waiter_tid)` 正常返回，没有触发目标 PI-chain/rb-tree 处理。`fuse_simple_request` 不是 scheduler wait-site，而是 consumer 写 `/sdcard` crash log 时的 FUSE 阻塞。下一步应基于 Violin 6.6.77 源码审计 `sched_setattr`/`set_user_nice`/`rt_mutex_adjust_prio_chain`/futex requeue 状态，确认应对哪个 task 做 priority/deadline 操作才会触发 PI chain walk。

## 2026-07-13 — pre-CMP_REQUEUE_PI race-loop：单 consumer 500 次未命中 PI blocked 窗口

基于源码确认：`sched_setattr()` 走 `__sched_setscheduler(..., pi=true)`，真实参数变更后会调用 `rt_mutex_adjust_pi(p)`；但 `rt_mutex_adjust_pi()` 在 `p->pi_blocked_on == NULL` 或 waiter node 未发生有效变化时立即返回。`rt_mutex_start_proxy_lock()` 的公开 wrapper 在任何非零/error 返回后会 `remove_waiter()`，所以等 `FUTEX_CMP_REQUEUE_PI` 返回 `-EDEADLK` 后再触发 consumer 已经太晚，waiter 的 `pi_blocked_on` 已被清理。

为撞窗口，将 `slide.c` 改成在 `SLIDEC2` 前设置 `consumer_go=2`，consumer 在 hot loop 中最多连续 500 次 `sched_setattr(waiter_tid, nice=1..19)`，减少循环内 crash log。新 artifact SHA256 `21F994719E9343193A1BB92E4C2387472EFBB530C2847EC1623FF61D9CCB5BE6`，size `164856`。新证据 `analysis_outputs/sched-wchan-run-20260713/crash-raceloop.txt`：本轮启动前/后 boot_id 均为 `141bb985-b1b1-439b-94c1-918dd3c312ad`；该 boot_id 在本轮启动前已不同于上轮，故上轮后到本轮前曾重启，但本轮未重启。

结果：consumer call 1 在 `SLIDEW2`/`SLIDEC2_SIGNAL` 附近开始，call 3 横跨 `SLIDEC2: before FUTEX_CMP_REQUEUE_PI`，`SLIDEC3` retry0 返回 `errno=35(EDEADLK)`，随后 hot loop 跑满 `SLIDECONSR_DONE: calls=500 ok=500 last_ret=0 last_errno=0`；`SCHEDWATCH` 全为 `wchan=0`。结论：单 consumer race-loop 没命中 `task_blocks_on_rt_mutex()` 设置 `task->pi_blocked_on` 到 EDEADLK 清理之间的极短窗口。下一步优先尝试多 consumer 无日志 hot loop，或构造更长 PI chain 来放大 `rt_mutex_adjust_prio_chain()` 返回 EDEADLK 前的窗口；可另做 owner_tid 诊断证明稳定 `pi_blocked_on` 上 `rt_mutex_adjust_pi()` 可进入，但它不等价于处理 forged requeue waiter。

## 2026-07-13 — multi-consumer race-loop：8 线程/8000 次仍未命中，转向拉长 PI chain

将 `slide.c` 改为 `SLIDE_CONSUMER_THREADS=8`、全局 `SLIDE_CONSUMER_RACE_CALLS=8000`，多 consumer 共享 atomic call index，并减少 hot loop 内 `/sdcard` 日志。artifact SHA256 `91D3196D4FC74E29FCD9C9751BAD68F7981C6382D762F07661BFA422A478AE70`，size `165224`。新鲜证据 `analysis_outputs/sched-wchan-run-20260713/crash-multiconsumer.txt`；本轮启动前/后 boot_id 均为 `54aa2807-ccf1-4574-b430-eefb4e80911b`，未观察到本轮重启。

结果：`SLIDEC2_SIGNAL: consumer race go=2 ready=8 ... budget=8000` 后，8 个 consumer 横跨 `SLIDEC2`/`SLIDEC3(EDEADLK)` 跑到 `SLIDECONSR_DONE`，最终 `calls=8003`、`ok=8003`，没有 `sched_setattr` 错误，也没有 scheduler/rtmutex wait-site；`SCHEDWATCH` 除一次 FUSE 写日志外仍为 `wchan=0`。这说明单纯增加用户态并发不足以命中当前两任务循环中的 `pi_blocked_on` 短窗口。下一步应构造更长 PI chain：`owner -> link0 -> link1 -> ... -> waiter`，让 `rt_mutex_adjust_prio_chain()` 返回 `EDEADLK` 前多走几层，从而放大 requeue waiter 被清理前的窗口。

## 2026-07-13 — long PI chain 4 层：链已形成，但仍未命中目标窗口

将 `slide.c` 从直接 `owner -> waiter` 改为 4 层长链：`owner -> link0 -> link1 -> link2 -> link3 -> waiter`。artifact SHA256 `8C53610EF59D3EE988FCA938D5FD19A1BB4A060CEB49041549020B8953ECA398`，size `166736`。新鲜证据 `analysis_outputs/sched-wchan-run-20260713/crash-longchain.txt`；本轮启动前/后 boot_id 均为 `54aa2807-ccf1-4574-b430-eefb4e80911b`，未观察到本轮重启。

日志确认长链形成：`SLIDELINK1 idx=0..3 holds=1..4`，`SLIDELINK2 idx=3 next=waiter`，`SLIDELINK2 idx=0 next=link`，随后 `SLIDEO1: owner started, lock link0 chain_links=4`。但 8 consumer/8000 次 `sched_setattr(waiter_tid)` 仍全部成功返回，`SLIDEC3` retry0 仍为 `EDEADLK`，`SCHEDWATCH` 除一次 FUSE 写日志外仍为 `wchan=0`。结论：4 层链不足以把 requeue waiter 的 `pi_blocked_on` 可命中窗口放大到用户态 race 能稳定命中的程度，或 `sched_setattr(waiter)` 被同一 `pi_lock` 序列化到 cleanup 后。下一步可继续加大链长/consumer 压力，或改测 owner/link task 的稳定 `pi_blocked_on` 路径用于验证 `rt_mutex_adjust_pi()` 行为。

## 2026-07-13 — aggressive long-chain：16 链/16 consumer/50k 仍失败，停止继续盲目撞 waiter 窗口

将参数推到 `SLIDE_CHAIN_LINKS=16`、`SLIDE_CONSUMER_THREADS=16`、`SLIDE_CONSUMER_RACE_CALLS=50000`。artifact SHA256 `C5821F2597F0888EF9DB1DDED2AF49E75928DD005ABC10B60863A22D8B0821C6`，size `167408`。新鲜证据 `analysis_outputs/sched-wchan-run-20260713/crash-longchain16.txt`；本轮启动前/后 boot_id 均为 `54aa2807-ccf1-4574-b430-eefb4e80911b`，未观察到本轮重启。

结果：16 层链形成，`SLIDELINK2: idx=15 blocking=16 next=waiter`，`SLIDEO1: owner started, lock link0 chain_links=16`；`SLIDEC2` 后 `SLIDEC3` retry0 仍返回 `EDEADLK`。16 个 consumer 产生约 50k 次 `sched_setattr(waiter_tid)`，`SLIDECONSR_DONE` 最终 `calls=50006`、`ok` 约 49976，未出现有意义的 scheduler/rtmutex wait-site，`SCHEDWATCH` 仅见 FUSE 写日志或 `wchan=0`。

结论：继续扩大同一用户态 race 的收益很低。当前证据强烈指向 `sched_setattr(waiter_tid)` 被 waiter's `pi_lock`/EDEADLK cleanup 序列化，无法在 cleanup 前有效触发目标 requeue waiter 的 rb-tree 处理。下一步不要再简单加 consumer/calls；应改触发对象/触发点：先用 `owner_tid` 或 link task 的稳定 `pi_blocked_on` 诊断 `rt_mutex_adjust_pi()` 是否可由 `sched_setattr` 触发，再判断是否能把稳定链路径适配到处理目标 waiter；否则应回到寻找其他 kernel read/write primitive。

## 2026-07-13 — owner stable pi_blocked_on 诊断：sched_setattr(owner_tid) 可稳定执行，下一步与 requeue 叠加

将诊断改为不进入 `FUTEX_CMP_REQUEUE_PI`，而是在 16 层链稳定形成后把 consumer 目标从 `waiter_tid` 切到 `owner_tid`：`SLIDEODIAG_SIGNAL: owner sched go=3 ready=16 owner=24083 waiter=24066 link0=24067 link_last=24082 budget=50000`。artifact SHA256 `9F767B6693186BFC7A2A08F291BBEA7E49F98578E32B2F8EFDE67663BEB8530B`，size `167296`。新鲜证据 `analysis_outputs/sched-wchan-run-20260713/crash-ownerdiag.txt`；本轮启动前/后 boot_id 均为 `54aa2807-ccf1-4574-b430-eefb4e80911b`。

结果：`sched_setattr(owner_tid)` 50k 次全部为正常返回，`SLIDEODIAG_DONE: calls=50001 enter=50001 ok=49963 last_ret=0 last_errno=0 max_us=968 target=24083 go=3`；大部分调用 duration 为个位数微秒，最大记录 `968us`。结论：稳定 `pi_blocked_on` 的 owner 目标可以被调度 syscall 稳定触达/扰动，但 owner-only 诊断没有 requeue waiter，因此不会产生目标 rb-tree 效果。下一步应把两者叠加：consumer 继续打 `owner_tid`，同时进入 `FUTEX_CMP_REQUEUE_PI`，让 owner-side `rt_mutex_adjust_pi()` 与 requeue waiter 附着到 owner-held `f_pi_target` 的时刻重叠。

## 2026-07-13 — owner+requeue overlap：最强 scheduler route 仍失败，停止扩大该路径

将 owner stable `pi_blocked_on` 诊断与 requeue 叠加：consumer 目标设为 `owner_tid`，同时继续进入 `FUTEX_CMP_REQUEUE_PI`。artifact SHA256 `593238FCFF2587731A8BDCBFC1555C5D04C5C7ADE71453F4C22D496622DD2A4A`，size `168208`。新鲜证据 `analysis_outputs/sched-wchan-run-20260713/crash-owner-requeue.txt`；本轮启动前/后 boot_id 均为 `54aa2807-ccf1-4574-b430-eefb4e80911b`。

关键日志：16 链形成，`SLIDEOQ_SIGNAL: owner sched go=3 ready=16 owner=31262 waiter=31245 link0=31246 link_last=31261 budget=50000; entering requeue`；随后 `SLIDEC2: before FUTEX_CMP_REQUEUE_PI`，`SLIDEC3: retry=0 ret=-1 errno=35`，`SLIDEC3_OK`；consumer 在 `SLIDEC3_SIGNAL` 时已进入 `14864` 次、`SLIDEC3_AFTER_SIGNAL` 时 `18000` 次，最终 `SLIDEOWNR_DONE` 到约 `calls=50008`、`ok≈49993`、`max_us=732`，但没有有意义的 scheduler/rtmutex wait-site、没有 route_done/读出、也没有本轮重启。

结论：这是目前最强的 scheduler route 验证（稳定 owner 目标 + 16 层链 + requeue overlap + 16 consumer + 50k 调度调用），仍未触发目标 rb-tree 处理。应停止继续扩大 consumer/calls/chain 的同一路径；当前假设“用户态 `sched_setattr()` 压力可在 Violin 6.6.77 上驱动 requeue waiter 的 vulnerable rb-tree processing”被实测否定。下一步要么转向内核 trace/可观测性证明具体 early-return 条件，要么回到寻找其他 kernel read/write primitive。

## 2026-07-13 — tracefs 初探：kprobe 可注册但不可 enable；一次 sched_pi trace 尝试后设备重启

设备 tracefs 状态：`/sys/kernel/tracing` 存在，shell 属于 `readtracefs`；`trace`、`tracing_on`、`buffer_size_kb` 等文件可写，`kprobe_events` 为 `rwxrwxrwx`，可通过 shell 动态注册 kprobe。已验证能写入 `p:codex_rt/rt_adjust_pi rt_mutex_adjust_pi task=%x0` 并出现在 `kprobe_events`。但 `events/codex_rt/*/enable` 由 root/readtracefs 只读，shell 写入报 `Permission denied`，`set_event` 也不可写，因此动态 kprobe 不能实际 enable。内置 `sched:sched_pi_setprio/enable` 是 world-writable，已可用于有限可观测性。

一次尝试启用 `sched_pi_setprio` 后运行当前 owner+requeue artifact，因 PowerShell quoting 导致 trace 控制命令未正确设置/拉取 trace；payload crash 仍拉到 `analysis_outputs/sched-wchan-run-20260713/crash-trace-schedpi.txt`。该运行前记录 boot_id 为 `f43f250c-4a0f-4d9a-bc4a-a2d1fae7b834`；随后 ADB 短暂掉线并恢复，当前 boot_id 变为 `4eb17240-592f-4772-9921-4165e213f8ec`、uptime `21.87`，shell 仍为 uid 2000/SELinux Enforcing。因此这轮发生了设备重启但未 root。由于 trace 命令自身执行异常且未拿到 trace，暂不能把重启归因于 scheduler route 成功；下一步应使用推送脚本而非 PowerShell inline，降低 payload 强度，做轻量 `sched_pi_setprio` trace 复现。

## 2026-07-13 — lightweight `sched_pi_setprio` trace：只见 owner 自身 priority flip，随后设备重启

按上一轮 tracefs 结论改用推送脚本，降低 payload 强度为 4 层 chain / 4 consumer / 2000 calls，并启用内置 `sched:sched_pi_setprio` tracepoint。artifact `exploit-site/preload-local-violin-sched-wchan.so` SHA256 `A077F7D22CA9E0EBE86E4BFF2DF30D2B2F69FBBBEDA4758270BC4D16983C72A2`，size `167280`。新鲜证据：`analysis_outputs/sched-wchan-run-20260713/crash-trace-lite.txt`、`trace-schedpi-lite.txt`、`trace-schedpi-lite-summary.txt`，trace 行数 `238`。

运行前 boot_id 为 `4eb17240-592f-4772-9921-4165e213f8ec`。拉取 crash/trace 后尝试 `am force-stop` 时 ADB 短暂消失；轮询恢复后 boot_id 变为 `7d770eb0-ac91-4b93-a73a-02bc18afd38a`、uptime `95.13 621.95`，shell 仍为 uid 2000、SELinux Enforcing。本轮因此发生了设备重启，但 trace/crash 没有 root、route_done 或 leak 成功标记。

crash 显示链路正常走到 `SLIDEOQ_SIGNAL: owner sched go=3 ready=4 owner=21631 waiter=21626 link0=21627 link_last=21630 budget=2000; entering requeue`，随后 `SLIDEC2`、`SLIDEC3: retry=0 ret=-1 errno=35`、`SLIDEC3_OK`。四个 consumer 约 2000 次 `sched_setattr(owner_tid)` 正常返回，最大记录 `max_us=8`；watchdog 首样本仍是 FUSE 写日志，后续为 `wchan=0`。

trace 中与 payload pid 相关的命中只有：`sh-21625 ... sched_pi_setprio: comm=sh pid=21631 oldprio=137 newprio=120` 和紧随其后的 `21631 oldprio=120 newprio=137`。waiter `21626`、link0..link3 `21627..21630`、consumer `21632..21635` 都没有相关 `sched_pi_setprio` 命中。结论：tracepoint 已工作，但 scheduler route 只造成 owner 自身 priority flip，没有可观察到的链式 PI propagation / waiter 处理；结合源码早退/cleanup 行为，应停止继续扩大 consumer/calls/chain，转向其他 kernel read/write primitive 或源码导向的 leak/read 面。

## 2026-07-13 — scheduler 后 pivot：shell 可见 leak 面与 kprobe oracle 均未成立

在轻量 `sched_pi_setprio` trace 重启但无 root/leak 标记后，转为检查设备侧是否存在 shell 可读 canonical 地址泄露或 tracefs KASLR oracle。shell UID 2000 / SELinux Enforcing 下：`/proc/kallsyms`、binderfs logs、`/proc/iomem`、`/sys/fs/pstore` 均被权限挡住；`/proc/modules` 可读但模块地址全部清零；`/proc/slabinfo` 可读但只适合 cache geometry；`/sys/kernel/tracing/trace` 可读写但无直接地址。

`kprobe_events` 虽为 0777 且可按 symbol 注册，但 dynamic event enable/profile 不可用；`available_filter_functions{,_addrs}` 不存在或权限拒绝。进一步测试绝对地址注册：`0x1`、`0x7fffffffff`、`0xffffff8000000000`、`0xffffffc008000000`、旧 boot canonical base `0xffffffe388200000` 等非零地址都能注册，且 `kprobe_events` 用哈希 `%p` 显示，不给 raw 地址。因此 kprobe 注册不能作为 KASLR slide oracle。

下一步转向两个具体分支：一是修正/隔离 ConfigFS/ashmem read primitive，当前 `configfs_read_once()` 的 `pos = ASHMEM_PREFIX_COUNT - len` 误把 `0x6d6873612f766564`（`/dev/ashm` 字符串）当计数导致 `pread` 超 EOF 返回 0；应做最小 probe 枚举小 `pos`，确认能否触达 `configfs_read_iter()` 的 `buffer->page + pos` 路径。二是基于已解包 OTA 的 393 个 `.ko` 与 live device nodes 自动枚举 Xiaomi/XRing 专有 procfs/sysfs/debugfs/ioctl 面；本地 MiCode checkout 是 sparse（`common-gki`、`xring-configs`），远端完整 tree fetch 本轮因 TLS handshake 失败，先不用阻塞在网络上。

## 2026-07-13 — 修正 ConfigFS/ashmem read primitive：pre-hijack 读 0 是 ashmem EOF，不是 ConfigFS pos 错

本轮修复 `exploit-repo/IonStack/CVE-2026-43499/exploit/src/util.c`：将 `configfs_read_once_at_pos(fd, target, data, len, pos)` 从 legacy `configfs_read_once()` 拆出；保留 `pos = ASHMEM_PREFIX_COUNT - len`，并补充注释说明该公式只在 ashmem fd 已被 fops hijack 到 `configfs_read_iter()` 后成立。`ASHMEM_PREFIX_COUNT == 0x6d6873612f766564` 是 ashmem 固定前缀 `"/dev/ashm"` 的小端整数；在 forged `configfs_buffer` 里它对应 `count`，因此 `pos=count-len` 正好让 `copy_to_iter(buffer->page + pos, len)` 从目标地址读 `len` 字节。此前把它简单当成“错误计数”是不完整的。

同步修改 `common.h` 增加 helper prototype；修改 `main.c` 去掉 duplicated pread setup，加入 `cfgprobe_prehijack_pos_sanity()` 和 `CFGPROBE_ONLY_DIAG` 编译期开关。源码核对 `drivers/staging/android/ashmem.c`：pre-hijack 时 fd 仍走 `ashmem_read_iter()`，且 `asma->size == 0` 会直接 EOF；这解释了之前所有 `rd=0 errno=0`。

已构建两个 artifact：diagnostic-only `build/violin-cfgread-diag/bin/preload.so` SHA256 `2D479507268190B952EB32F796402B9594F3C684D3D49C86F05A479AF080EC00`；默认正常构建 `build/violin-cfgread/bin/preload.so` SHA256 `4D4101C17E8EC2D225B83B3BAF42E38599C8D11784607122CAA3A81CA734CCD4`。用 diagnostic-only artifact 在设备 fresh run，日志拉到 `analysis_outputs/sched-wchan-run-20260713/crash-cfgread-diag.txt`，boot_id 前后均为 `7d770eb0-ac91-4b93-a73a-02bc18afd38a`，未重启，shell 仍 uid 2000 / Enforcing。

设备日志证明：`prehijack_pos_0/1/8/16/32/64/128` 全部 `rd=0 rd_errno=0 value=0`，legacy huge pos 也 `rd=0`，随后 `CFGPROBE_ONLY_DIAG_STOP`。结论：pre-hijack direct cfgprobe 不可能靠改小 pos 读出内核地址；必须先完成 fops hijack/re-route，然后在 CFI/fops stage 调用 `configfs_read_once()`。下一步应围绕“先 hijack fops，再读 canonical 指针”重排流程，而不是继续调 direct startup probe。

## 2026-07-13 — 修 CFI/fops stage gate：不再把 `misc_fops` 当 pointer slot

继续修 `exploit-repo/IonStack/CVE-2026-43499/exploit/src/fops.c`：移除 `try_cfi_stage()` 开头和 payload readback 后两处 `configfs_read_once(fd, data_addr(ASHMEM_MISC_FOPS)) == fake_fops` gate。该判断继承了旧误解：violin 的 `misc_fops` 是静态 `struct file_operations`，不是 ashmem fops 指针槽；用它验证 hijack 必然错误，成功/失败路径写回 `misc_fops` 也会写静态 fops 结构而不是恢复 fd 的 `f_op`。

新的 CFI stage 验证顺序为：进入 stage 后记录 fd/path/fake_fops/binwrite_target/misc_fops；先用 `configfs_write_once()` 写 `binwrite_target`，再用 `configfs_read_once()` 读回同一 payload；然后读取 `fake_fops + FOPS_LLSEEK_OFF` 并要求等于 `text_addr(NOOP_LLSEEK)`，作为 ConfigFS read primitive 已经作用于 forged fops 页面自身的 self-check。同步禁用 `restore_slide_boot_id()` gate，因为 violin 的 `sysctl_bootid` 是 UUID 数据缓冲，不是带 `.data` 字段的 `ctl_table`。成功和失败路径均不再写 `misc_fops`，只清 `fake_fops->owner`。

已构建 `build/violin-cfigate/bin/preload.so`，SHA256 `1FC082B6B1813D697D673AF281CE8E98979BED7A516C10C321FBE01FC887906D`，编译无 warning。此 artifact 本轮没有推到站点执行：原因是 `main()` 仍会先走已判死的 slide/scheduler KASLR 路径，然后使用旧 boot hardcoded base；当前缺少 current-boot KASLR 时，直接 full run 主要是在测试 stale KASLR/重启，而不是测试已修好的 CFI stage。下一步要么找到非 scheduler 的 current-boot KASLR，要么增加一个受控 test mode，从外部注入 current-boot KASLR 后直接进入 `prepare_good_kernel_page(PAGE_PAYLOAD_FOPS)` / `run_main_route_threads()`。


## 2026-07-13 CFI stage-only guard 与 ConfigFS read primitive 复测

- 阅读上下文：沿 `E:\workspace\README.md`、global SOP/偏好/效率档案、`HANDOFF.md` 和本日志继续；项目 `README.md` 当前不存在。
- 代码改动：`E:\workspace\projects\xiaomi-root\exploit-repo\IonStack\CVE-2026-43499\exploit\src\main.c` 新增 `CFI_STAGE_ONLY`、`CFI_KASLR_BASE_CONST`、`CFI_KASLR_BASE` env override、`ALLOW_STALE_HARDCODED_KASLR` 宏；默认禁用 stale hardcoded KASLR fallback。无同 boot canonical base 时会记录 `CFI_STAGE_ONLY_STOP_NO_KASLR` / `STEP1_NO_KASLR_STOP` 并退出，不再进入已证伪 scheduler slide。
- 构建验证：stage-only artifact `E:\workspace\projects\xiaomi-root\exploit-repo\IonStack\CVE-2026-43499\exploit\build\violin-cfi-external-kaslr\bin\preload.so`，SHA256 `F61B77771BBE5734F7E2C4DCB899E639688CA88F77B200550A13EF1F7A304A28`；normal guarded artifact `build\violin-normal-guarded\bin\preload.so`，SHA256 `803255C4354CB1510F6AA51F56D98FF9534E88B6069AFA88A907E6AE92A1A9C8`。
- 设备复测：通过 Firefox `http://127.0.0.1:18000/index.html?payload=cfi-stage` 运行 `E:\workspace\projects\xiaomi-root\exploit-site\preload-local-violin-cfi-stage-only.so`。boot_id 保持 `7d770eb0-ac91-4b93-a73a-02bc18afd38a`，未重启。
- 关键日志：`CFGPROBE_MISS` 后出现 `CFI_STAGE_ONLY_STOP_NO_KASLR: no same-boot canonical base; not entering scheduler slide or stale fallback`。说明 ConfigFS/ashmem pre-hijack read 仍是 EOF，stage-only 门禁生效，后续必须先拿同 boot canonical KASLR 或用 compile/env 注入再测 CFI，不应再让页面默认跑 sched-wchan。
- 证据文件：`E:\workspace\projects\xiaomi-root\analysis_outputs\sched-wchan-run-20260713\crash-cfi-stage-only-20260713.txt`。

## 2026-07-13 — Android shell collector 的 CRLF 传输修复

- 用户在 Android MT 管理器终端运行 `collect-current-boot-ktext-root1.sh` 时出现 `line N: $'\\r': command not found`、`set: invalid option`、函数定义 `syntax error`；这证明手机端副本被保存为 CRLF，`/system/bin/sh` 在解析前即把 `\\r` 当作语法内容，因此脚本内部无法自修复。
- 新增 `tools/package-current-boot-ktext-root1.ps1`：读取源脚本后强制规范为 UTF-8 无 BOM、LF-only，再生成 `tools/collect-current-boot-ktext-root1-lf.zip`。对 ZIP 内条目实测 `CR bytes=0`、`LF count=167`，并以 `bash -n` 完成语法检查。
- 手机侧必须传输 ZIP 后在 DLManager 解压，再运行解压出的 `.sh`；不要在聊天/文本编辑器中打开、另存或单独复制脚本。当前 ZIP SHA-256：`7AD66DE37416E7F447823E76FF8FAC13A6022D5523DF80326F58BF945373F096`。


## 2026-07-13 current-ktext 包核验：有效 canonical base，但与目标 boot 不匹配

- 输入包：`E:\workspace\projects\xiaomi-root\ionstack-current-ktext.zip`
- ZIP SHA256：`E4FA4B73A1EF2DB305350A0AC3311DFE00BA19B5B9066FDB8ECD5920AE422D1B`
- 解包目录：`E:\workspace\projects\xiaomi-root\analysis_outputs\current-ktext-20260713\ionstack-current-ktext\`
- 包内状态：`status=OK`，`uid=0(root)`，`context=u:r:magisk:s0`，`kptr_restrict_during=0`。
- 包内 boot_id：`2988e1dc-3130-4ba7-9985-74a91a2296cd`
- 包内 canonical symbols：`_text=0xffffffe7ca400000`、`_stext=0xffffffe7ca410000`、`ashmem_fops=0xffffffe7cb6c9df0`、`sysctl_bootid=0xffffffe7cc736f58`、`loggers=0xffffffe7cc4d21b8`、`init_task=0xffffffe7cc4de280`、`root_task_group=0xffffffe7cc6d4580`。
- 包内建议 `CFI_KASLR_BASE=0xffffffe7ca400000`，但明确要求仅在 boot_id 仍为 `2988e1dc-3130-4ba7-9985-74a91a2296cd` 时使用。
- 目标设备 `03035440C1781540` 当前 boot_id 实测为 `11f91eb2-4acf-4faf-84e8-480b5bc1e2e3`，与包内 boot_id 不匹配。
- 结论：该包是有效 rooted canonical 证据，但**不能用于当前目标 boot 的 `payload=cfi-stage&kbase=...` 测试**。必须重新采集与目标当前 boot_id 一致的 `_text`，或等待目标 boot_id 与采集包一致时再用。

## 2026-07-13 — perf_event_open KASLR bootstrap 集成

从用户提供的 CVE43499.zip（含 perf_leak.c + target.h.final）发现完整机制：
- rb_erase 不是 KASLR 的 bootstrap，perf_event_open 才是
- target.h.final 注释 `KIMAGE_TEXT_BASE = 0xffffffedb6680000ULL /* runtime: perf leak */` 确认
- 完整链：perf leak → KASLR slide → 填真实 KIMAGE_TEXT_BASE → GhostLock pselect + rb_erase → boot_id 确认

已将 perf_leak 集成进现有 preload.so：
- 新增 `PERF_LEAK_ONLY=1` 编译标志
- `main.c` 新增 `run_perf_leak()`：PERF_TYPE_HARDWARE + PERF_SAMPLE_CALLCHAIN + exclude_user=1
- 扫描 callchain 中最低 0xffffffc0... 地址 → 报告 CFI_KASLR_BASE
- 构建：`make PROJECT=violin-v-oss COMMON_CFLAGS='-DPERF_LEAK_ONLY=1'`
- 产物：`build/violin-perf-leak/bin/preload.so` SHA256 `f9403ee4c240df6cec0d152182bf7ea9567c3099d12965a0e05983e607cd9994`
- 站点：`preload-local-violin-perf-leak.so`，URL `?payload=perf-leak`

待测：perf_event_open 从 Firefox untrusted_app 域是否允许（shell 域 EACCES 已确认）。


## 2026-07-14 incoming CVE43499 HTML/ZIP triage

- 输入：`E:\ZEOON3\Downloads\CVE-2026-43499漏洞利用全纪录.html`（SHA256 `0A2C3C7DB81CF50B16D47F6A6441A1CCBD2478B14BE59DAEA3DA2868B9C1562F`）和 `E:\ZEOON3\Downloads\CVE43499.zip`（SHA256 `8A9FD03E23B0AAD0A190C381B9AAC9ADD8262687CE1C2E36F95805E1E4C6575A`）。
- ZIP 解包到 `E:\workspace\projects\xiaomi-root\analysis_outputs\incoming-cve43499-20260714\`，包含 `perf_leak.c`、`parse_kallsyms.py`、`unpack_boot.py`、`target.h.final`。
- `target.h.final` 是 vivo V2279A / MT6833 / Android 12 / Linux 5.10.149，不适用于 Xiaomi violin / Android 16 / Linux 6.6.77；不能复制 offset 或 struct layout。
- HTML 中真正可迁移的新思路是 perf callchain 泄露 runtime kernel text，用于解决同 boot KASLR。目标设备当前 `/proc/sys/kernel/perf_event_paranoid=-1`，但 simpleperf 实测 `cpu-cycles`、`sched:sched_switch`、raw PMU、`instructions`、`page-faults`、`cpu-clock` 等 record/stat 均报 unsupported，未生成 perf.data。
- 结论：材料不是现成突破；下一步若要验证 perf oracle，需先恢复可用 Android aarch64 编译器，编译一个直接调用 `perf_event_open` 的最小 probe，绕过 simpleperf 事件名层，记录 errno 和 kernel IP。当前项目 NDK clang 是 8 字节 `clang-21` shim，WSL 下不可用。
- 详细记录：`E:\workspace\projects\xiaomi-root\analysis_outputs\incoming-cve43499-20260714\SUMMARY.md`。


## 2026-07-14 perf_event_open direct probe：kernel sampling 被 EACCES 挡住

- 按 incoming HTML 的思路，绕过 simpleperf 事件名层，直接编译/运行 native `perf_event_open` probe。
- 修复本地 NDK 调用方式：`clang` 和 `ld.lld` 是 shim；可直接调用 `clang-21`，并在分析目录建临时 `ld.lld -> lld` symlink 后用 `--ld-path` 链接。
- 构建 `perf_leak_aarch64`（SHA256 `9EA4F9D5F11F8EDA49FF32D1B807D848F7657D0F49BDB843F66CE512B5976AEF`）并在设备运行：`tp_id=0`，fallback `perf_event_open` 返回 `errno=13`。
- 构建矩阵 probe `perf_matrix_aarch64`（SHA256 `E76EC58B971655E32BFB98A2A09DFFF600C03629DCD5EBAE3B3B7CCCA96B5C8D`）：`PERF_TYPE_SOFTWARE`、`PERF_TYPE_HARDWARE`、`PERF_TYPE_TRACEPOINT` 只要 `exclude_kernel=0` 全部 `errno=13`；同类事件在 `exclude_kernel=1` 时可成功打开 fd，包括 callchain。
- 结论：当前 violin 目标虽然 `perf_event_paranoid=-1`，但 shell context 下 kernel sampling/callchain 被权限挡住，只允许 user-only perf。HTML 中的 perf KASLR oracle 不能直接用于当前 shell/untrusted_app 获取 canonical `_text`；除非有更高权限上下文，否则仍需寻找其他同 boot KASLR oracle。
- 证据：`E:\workspace\projects\xiaomi-root\analysis_outputs\incoming-cve43499-20260714\perf_leak_run.txt`、`perf_matrix_run.txt`、`SUMMARY.md`。

## 2026-07-14 Firefox 上机 perf-leak 复测：漏洞链可执行 native，但 kernel perf 仍 EACCES

- 时间：2026-07-14 11:15:12 +08:00
- 设备： 3035440C1781540
- boot_id：9d97fd1d-acc6-470c-9b95-df0c5a221db3
- 页面：http://127.0.0.1:18000/index.html?payload=perf-leak
- 执行上下文：Firefox (org.mozilla.firefox)，不是 adb shell 直接执行。
- 结果：JS AAR/AAW、mprotect、native preload 执行均成功；页面最终 JS_DONE。
- native 结果：command_result=perf_event_open failed: errno=13 (Permission denied)，command_status=0。
- 证据：E:\workspace\projects\xiaomi-root\analysis_outputs\incoming-cve43499-20260714\firefox_perf_window.xml
- 结论：HTML/CVE43499 的 perf callchain 思路已在 Firefox 真实触发链上验证，当前 violin build 仍拒绝 kernel perf sampling；Firefox 上下文没有绕过 perf_event_open 对 kernel sampling 的 EACCES 门。
- 下一步：如果还要沿 perf 思路推进，应做 Firefox 内 matrix 版（多 event/exclude_kernel 组合）确认策略粒度；否则转回寻找非 perf KASLR oracle。

# 2026-07-14 slide-only Firefox 上机：验证 boot_id 泄露链，未命中且触发重启

- 时间：2026-07-14 11:24:43 +08:00
- 起始 boot_id：9d97fd1d-acc6-470c-9b95-df0c5a221db3
- 重启后 boot_id：4a646d0c-2954-4db4-979d-17746c40a9df
- 新增诊断开关：SLIDE_ONLY_DIAG=1，只跑 configfs probe + scheduler slide，停止在 KASLR 阶段，不进入 fops/root。
- 构建产物：E:\workspace\projects\xiaomi-root\exploit-site\preload-local-violin-slide-only.so
- SHA256：DD7DDB2A10C31D775C1C220421ED30C739A0F32FE9A9EEB76AF5EB71738480D7
- 页面入口：http://127.0.0.1:18000/index.html?payload=slide-only
- 证据：
  - E:\workspace\projects\xiaomi-root\analysis_outputs\slide-only-20260714\crash-after-poll24.txt
  - E:\workspace\projects\xiaomi-root\analysis_outputs\slide-only-20260714\crash-after-reboot.txt
  - E:\workspace\projects\xiaomi-root\analysis_outputs\slide-only-20260714\logcat-tail-after-reboot.txt

关键观测：

`	ext
SLIDEC3_OK: EDEADLK rollback triggered at retry=0
SLIDEOWNR_DONE: ... calls≈2001 ok≈2000 target=<owner_tid>
SLIDEP3: after pselect ret=0 errno=0 calls=0 sched_ok=0 last_sched_ret=-1 last_sched_errno=0
SLIDEC4: route_done, read_stext
SLIDER1: boot_id n=37 value=9d97fd1d-acc6-470c-9b95-df0c5a221db3
SLIDER2_BAD: leaked=0x0c47c6ac1dfd979d hi=0x0c47
SLIDE4_CHILD_FAIL: attempt=1/2 no stext
`

解释：

- FUTEX_CMP_REQUEUE_PI 的 EDEADLK rollback 可稳定触发。
- owner-target sched_setattr 压力也确实执行了 2000+ 次且大量返回 0。
- 但是进入 pselect/读 boot_id 后，/proc/sys/kernel/random/boot_id 仍是原始 UUID 文本；解析出的  x0c47... 是 UUID 字节，不是 canonical kernel pointer。
- 因此 b_erase -> sysctl_bootid.data -> nfulnl_logger 写入没有发生，或者未写到预期字段。
- 第 3 个 attempt 尚未完成时设备断连，随后 ADB 返回且 boot_id 改变，确认本轮 slide-only 触发重启。

结论：slide.c 的 boot_id/nfulnl_logger KASLR 设计链在源码层成立，但当前 violin 实测未命中写入；继续重复同 payload 风险高且收益低。下一步应改为更窄的判据：减少 attempt，并在 SLIDEP3 后立即停止/读 boot_id，或转向用源码定位 scheduler 实际没有执行 forged waiter rb_erase 的原因。

## 2026-07-14 ElevateMe direct-cred write 分析

详见：E:\workspace\projects\xiaomi-root\analysis_outputs\external-ghostlock-20260714\ELEVATEME-PORT-ANALYSIS.md

结论：KernelSnitch/SKB/pselect shape=1 可移植，但 ElevateMe 依赖 /proc/sweep LKM 提供 current_task/init_cred；当前未 root violin 缺这两个同 boot 地址。下一步应做显式 env-gated DIRECT_WRITE_ONLY_DIAG，默认拒绝 stale 地址。


## 2026-07-14 direct-write diag 安全门禁落地

- 背景：评估 ElevateMe 的 direct cred write 形态时，确认其核心 `shape=1` 是 `parent=target-8, right=value, left=0`，可让 `rb_erase/__rb_change_child` 把 `value` 写入 `target`；但当前 violin 未 root 设备仍缺少同 boot `current_task` 与 `init_cred` 绝对地址，不能盲跑旧地址。
- 代码变更：
  - `exploit/src/targets/violin-v-oss/target.h` 新增 `INIT_CRED_OFF=0x20f0548` / `INIT_CRED`，该偏移由 `ionstack-current-ktext.zip` 与 `violin-kernel-info2.zip` 两个旧 rooted boot 交叉验证；只代表 offset，不代表当前 boot 地址。
  - `exploit/src/util.c` / `common.h` 新增 `set_pselect_write()`、`clear_pselect_write()`、`pselect_write_target/value/shape()`，支持 env-gated 自定义 pselect 写入形态。
  - `exploit/src/fops.c` 新增 custom pselect fd_set waiter 布局分支，并允许 `PSELECT_CFI_ROUTE_ATTEMPTS` 编译期覆盖；custom 写入命中 route signal 后不再进入 CFI 读写 gate。
  - `exploit/src/main.c` 新增 `DIRECT_WRITE_ONLY_DIAG`：没有 `DIRECT_WRITE_ARM=1 DIRECT_WRITE_TARGET=0x... DIRECT_WRITE_VALUE=0x...` 时直接停止，不进入 futex/pselect 写路径。
  - `exploit-site/index.html` / `exploit.html` 新增 `?payload=direct-write-diag`，当前站点不透传 target/value/arm，所以浏览器入口默认也只会停在安全门。
- 构建：
  - 命令：`make PROJECT=violin-v-oss OUTDIR=build/violin-direct-write-diag/bin ... COMMON_CFLAGS="-O2 -g0 -Wall -Wextra -Isrc -DDIRECT_WRITE_ONLY_DIAG=1 -DPSELECT_CFI_ROUTE_ATTEMPTS=3" preload`
  - 产物：`E:\workspace\projects\xiaomi-root\exploit-site\preload-local-violin-direct-write-diag.so`
  - SHA256：`B531A8FFD5351E48F392CFDF9D271759E5AC4691CC375505CB220E193346F340`
- 验证：
  - ADB shell `LD_PRELOAD=/data/local/tmp/preload-direct-write-diag.so /system/bin/true`：日志出现 `DIRECT_WRITE_ONLY_DIAG_STOP_MISSING_ENV`，boot_id 保持 `4a646d0c-2954-4db4-979d-17746c40a9df`。
  - Firefox 上机 `http://127.0.0.1:18000/index.html?payload=direct-write-diag`：同样出现 `DIRECT_WRITE_ONLY_DIAG_STOP_MISSING_ENV`，boot_id 仍为 `4a646d0c-2954-4db4-979d-17746c40a9df`。
- 结论：direct-write 代码路径已经可编译且默认安全拒绝 stale/缺参；下一步仍不是盲跑，而是解决 `current_task` 同 boot 地址来源，或在同 boot root 侧提供 `DIRECT_WRITE_TARGET=current_task+TASK_CRED_OFF` 与 `DIRECT_WRITE_VALUE=current_boot_init_cred` 后再单次执行。
- 不要踩坑：不要把旧 zip 的 `init_cred` 绝对地址用于当前 boot；只可复用 `INIT_CRED_OFF`。不要在没有 `DIRECT_WRITE_ARM=1` 和同 boot target/value 时运行实际写入。

## 2026-07-14 same-boot current/init_cred oracle 脚本

- 用户问题：direct-write 需要的 `current` / `&init_cred` 是否要求 boot_id 一样。
- 结论：如果只是验证 image-relative offset（如 `INIT_CRED_OFF=0x20f0548`），不要求同 boot；如果要把绝对地址直接喂给当前 exploit（`DIRECT_WRITE_TARGET=current_task+TASK_CRED_OFF`、`DIRECT_WRITE_VALUE=init_cred`），必须同 boot_id。`current` 是当前进程的 `task_struct` 指针，不能从旧 boot 或其他进程归档复用。
- 新增工具：`E:\workspace\projects\xiaomi-root\tools\collect-sameboot-root-oracle.sh`。
- 脚本行为：Android 本地运行，自动 `su -c` 提权；临时放宽 `/proc/sys/kernel/kptr_restrict` 并退出恢复；采集 `boot_id`、`_text`、`init_cred`、`init_task`、`root_task_group`、`sysctl_bootid`、`loggers`、`modprobe_path`、offset；如果存在 `/proc/sweep`、`/proc/ionstack_oracle`、`/proc/current_task_oracle` 或 `/sys/kernel/debug/ionstack_oracle`，会读取 LKM/eBPF oracle 输出并解析 `current/current_task/g_current_task`、`cred`、`real_cred`。
- 边界：纯 root shell/kallsyms 不能推出当前 shell 的 `current` 指针；没有同 boot LKM/eBPF oracle 时脚本会输出 `current_task_status=NEEDS_LKM_ORACLE`。这不是失败，而是防止误用旧地址。
- 本地验证：`wsl sh -n tools/collect-sameboot-root-oracle.sh` 通过。

## 2026-07-14 52pojie OnePlus GhostLock 方案静态审计

- 阅读上下文：`E:\workspace\README.md`、global 核心文档、项目 `HANDOFF.md`、交接对账、开发日志与 root 证据清单；以 `HANDOFF.md` 为当前 baseline，只做静态审计。
- 已抓取并固定网页 `https://www.52pojie.cn/thread-2116758-1-1.html` 到 `analysis_outputs\52pojie-thread-2116758-20260714.html`，SHA-256=`D951C6BDE83EF827D1A91839E7279302B67CF2CA6F99779D32D218DA60C20598`；完整审计见 `analysis_outputs\52pojie-oneplus-ghostlock-plan-audit-20260714.md`。
- 结论：作者的符号/BTF/iomem/Image 四路离线适配方法可借鉴，但其实现没有越过 `slide_leak_kernel_base()`：仅证明 PoC panic，未建立 KASLR leak、fops、phys-r/w 或 root，不能视为可复用成功链。
- 核验出的关键限制：CVE 的 stale waiter 来自 `CMP_REQUEUE_PI=-EDEADLK` rollback 的错误 `remove_waiter()` 清理对象，不是“timeout 清理 UAF”；文章的 `PSELECT_WAITER_WORD_SHIFT=1` 无动态成功证据，且对 Violin 已独立排除（应为 0）。任何 PLC110 绝对地址、物理装载常量或 shift 都不得迁入 Violin。

## 2026-07-14 allroot 仓库静态审计

- 固定来源：Gitee `ytngtaoaaa/allroot` commit `57f2cc98bb32d68e262c729f234c53eeb581f7e1`，本地镜像 `analysis_outputs\allroot-source-20260714\`；Release `a` 的 `device.sh` SHA-256=`505FFF485A170EF0CAB03EA330CEF88CE427D0E722F6CD2063F9F320F547807F`，`wsl sh -n` 通过。
- 结论：仓库只有 README 与占位 README；release 脚本仅采集 uname/getprop/ABI/patch/su/SELinux 等基本设备信息，未包含 boot 解包、BTF/kallsyms/config/iomem、offset 计算、CVE patch 判定或 `preload.so`。README 的“自动偏移”“完成 90%”与脚本实际能力不符。
- 不可作为 Violin 的 root/适配方案。它没有解决 current-boot canonical KASLR oracle 或后续 primitive 的验证缺口；任何真正的 target 必须继续使用同 boot 绑定、BTF/反汇编、CVE patch/backport 与每阶段 self-check。完整审计：`analysis_outputs\allroot-static-audit-20260714.md`。

## 2026-07-14 same-boot oracle 当前非 root 设备预跑

- 执行：将 `tools/collect-sameboot-root-oracle.sh` 推送到当前设备 `/data/local/tmp/collect-sameboot-root-oracle.sh` 并运行。
- 当前设备 boot_id：`4a646d0c-2954-4db4-979d-17746c40a9df`。
- 当前权限：`uid=2000(shell)`，SELinux `Enforcing`，`command -v su` 无输出。
- 结果：脚本按预期失败并输出 `status=FAILED` / `reason=not_root_and_su_not_found`；这证明当前未 root 设备不能采集 same-boot `current/init_cred` 绝对地址。
- 安全性：脚本未进入 root 分支，未修改 `kptr_restrict`，未执行任何 direct-write；运行后 boot_id 仍为 `4a646d0c-2954-4db4-979d-17746c40a9df`。
- 证据目录：`E:\workspace\projects\xiaomi-root\analysis_outputs\sameboot-oracle-current-nonroot-20260714\`。
- 已准备两天后 rooted 设备可用采集包：`E:\workspace\projects\xiaomi-root\tools\collect-sameboot-root-oracle-ready.zip`，SHA256 `85FE76E71380D42E8E9FD547F31CBB5DD99D5954AF3ACA414C0EC049889B8913`。
- 下一步：rooted 设备到手后，先确认 boot_id，然后运行该脚本；若输出 `current_task_status=OK_CURRENT_FOUND`，即可用 `DIRECT_WRITE_TARGET_current_cred` 与 `DIRECT_WRITE_VALUE_init_cred` 喂 `direct-write-diag`。若仍为 `NEEDS_LKM_ORACLE`，说明只有 kallsyms，没有 current oracle，需要加载/运行同 boot LKM/eBPF oracle。

## 2026-07-14 P0 boot_id direct-write probe 上机

- 目标：先不拿 `current_task`，验证 direct-write route 是否能把固定 P0 值写进固定 P0 全局目标。
- 新增：
  - `src/targets/violin-v-oss/target.h`：`INIT_CRED_P0 = P0_DATA_ALIAS_CONST(INIT_CRED)`。
  - `src/main.c`：`DIRECT_WRITE_BOOTID_PROBE`，固定 `target=SLIDE_RANDOM_BOOT_ID_DATA`、`value=INIT_CRED_P0`、`shape=1`，并在 route 后读取 `/proc/sys/kernel/random/boot_id` 对比。
  - `exploit-site/index.html` / `exploit.html`：新增 `?payload=bootid-write-probe`。
- 构建：`DIRECT_WRITE_BOOTID_PROBE=1 -DPSELECT_CFI_ROUTE_ATTEMPTS=1`，产物 `E:\workspace\projects\xiaomi-root\exploit-site\preload-local-violin-bootid-write-probe.so`，SHA256 `D6025B395E914002E2C0A265B3A231D87FFBB301FE15FAB93A0C2A2853CA0E6E`。
- Firefox 上机入口：`http://127.0.0.1:18000/index.html?payload=bootid-write-probe`。
- 设备 boot_id 前后均为：`4a646d0c-2954-4db4-979d-17746c40a9df`，设备未重启。
- crash.txt 关键日志：
  - `BOOTID_WRITE_PROBE_START: before=4a646d0c-2954-4db4-979d-17746c40a9df target=0xffffff8002546f60 value=0xffffff8002300548 shape=1 uid=10270 euid=10270`
  - `BOOTID_WRITE_PROBE_PAGE: page=0xffffff83c9e10000 lock=0xffffff83c9e104d0 w0=0xffffff83c9e113a0 task=0xffffff83c9e12380`
  - `BOOTID_WRITE_PROBE_DONE: before=4a646d0c-2954-4db4-979d-17746c40a9df after=4a646d0c-2954-4db4-979d-17746c40a9df changed=0 route_done=1 calls=0 success=0 cfi_step=33 errno=0`
- 结论：固定 P0 boot_id write probe 未写入；不是 target/value 选择问题，而是本轮 direct-write route 没有触发 consumer/sched_setattr（`calls=0 success=0`）。这说明在当前 custom fd_set/direct-write 形态下，pselect 路径返回/结束太早或没有打开 consumer 触发窗口。下一步应先修 route timing/consumer handoff，而不是继续换写入目标。
- 验证：默认 normal artifact 重新编译通过，SHA256 `3618FBD032653F6FF6EC41DD3D73F2DEF61AFCF8AE414D8A5B70E06E5E059669`。
- 证据目录：`E:\workspace\projects\xiaomi-root\analysis_outputs\bootid-write-probe-20260714\`。

## 2026-07-14 Violin target.h 偏移交叉验证

- 仅做离线验证：以 rooted same-build 的两份 kallsyms（不同 `_text` boot）和 BTF/OTA kheaders 对账；未构建、安装或运行 payload。完整报告 `analysis_outputs\violin-offset-crosscheck-20260714.md`，可复跑 `tools\audit-violin-target-offsets.py`。
- 结果：26/26 `target.h` image-relative symbol offsets 与 `violin-kernel-info2` 的 `_text` 基准精确一致；其中 25 个可跨两份 rooted boot 比较的符号相对 offset 也全部一致。关键 waiter/task/fops/cred/seccomp/pipe/configfs layout 与 BTF 一致。
- 修复：`SLIDE_RANDOM_BOOT_ID_DATA_OFF` 原来错误地为 `sysctl_bootid + 8`（`0x2336f60`），而本机 `sysctl_bootid` 本身就是 UUID data buffer（`0x2336f58`）。已改为 `0x2336f58ULL`，当前 26/26 全绿；WSL `clang-21 -fsyntax-only` 验证通过。
- 边界：这是静态 offset/layout 结论，不产生当前未 root boot 的 canonical runtime 地址，也不证明任一 write/CFI/root primitive 已成立。
- 补充分类：除 26 个 symbol offsets 和 BTF layout fields 外，`P0_KERNEL_PHYS_LOAD=0x00210000` 已由 same-build iomem 的 Kernel code 起点验证；pselect shift=0 已由 OTA Image 反汇编验证。`WAITER_LOCAL_OFF`、`MM_OWNER_OFF`、KernelSnitch identity range 当前无 C 源码消费；DIRECT_MAP_END 是 64GiB 判定边界而非 symbol offset；KIMAGE_TEXT_BASE 不是 runtime KASLR base。并已更正 target.h 将实际 39-bit VA 注释误写为 48-bit 的文档错误。
- 按用户指定格式新增 `analysis_outputs\violin-offset-validation-report-20260714.md`：含 boot/kernel 提取状态、符号提取详情、26 项源码预期与实际提取对照表，以及通过/失败边界。结论保持：26/26 image-relative symbol offsets 通过；当前 boot canonical runtime 地址与各后续原语不在该静态报告的证明范围。
- 按用户指定格式新增 `analysis_outputs\violin-offset-validation-report-20260714.md`：含 boot/kernel 提取状态、符号提取详情、26 项源码预期与实际提取对照表，以及通过/失败边界。结论保持：26/26 image-relative symbol offsets 通过；当前 boot canonical runtime 地址与各后续原语不在该静态报告的证明范围。
- 上游参照已复核：NebuSec `IonStack/CVE-2026-43499` 的 exploit/poc 目录与本地引用一致。已将本机 static/KASLR-invariant values 固化在 `exploit-repo\IonStack\CVE-2026-43499\exploit\src\targets\violin-v-oss\target.h`：26 项 symbol offset、BTF layout 与 P0 physical load 均有对应证据；未填入任何旧 boot runtime absolute address。修正 boot-id data offset 后，对 `src/*.c` 的 WSL clang-21 syntax-only 全量检查通过。
- 更正上一条的验证说明：最初尝试对 `src/*.c` 批量 syntax-only 时遇到 PowerShell→WSL 引号传递错误，未把该失败误作源码失败；随后以 `analysis_outputs\check-violin-target-syntax-20260714.sh` 运行同一检查，`src/*.c` 全部通过 clang-21 `-fsyntax-only`。

## 2026-07-14 boot_id direct-write probe：consumer handoff 修复与 timerfd 结果

- 起点：上一轮 `BOOTID_WRITE_PROBE_DONE ... calls=0 success=0`，怀疑 pselect route 太早返回，consumer 没机会 `sched_setattr`。
- 根因定位 1：generic `open_selected_fds()` 在 custom direct-write 时把 fd_set 中置位 fd dup 到 pipe write end；write fd 天然 ready，`pselect()` 立即返回，因此 consumer 延迟尚未结束就看到 `calls=0`。
- 修复 1：custom direct-write 分支改为 dup blocking read fd；并给 `fops.c` 增加 `FOPSROUTE_SETUP/GO/RET` crash 文件日志。
- 结果 1：仍未写入。关键日志：`FOPSROUTE_RET: attempt=1 ret=70 errno=0 calls=0 success=0 delay=50000`。说明 pselect 仍立即 ready，原因是 forged waiter words 分布在 `out`/`ex` fd_set，pipe read fd 对这些集合仍导致 ready。
- 修复 2：参考 tokay/Pixel 分支，custom direct-write route 使用 `timerfd_create(CLOCK_MONOTONIC, 0)` 作为 blocking fd；同时让 `FOPS_KERNEL_PAGE_SETUP_ATTEMPTS` 可编译期覆盖，bootid probe 构建用 `-DFOPS_KERNEL_PAGE_SETUP_ATTEMPTS=1`，并加 `BOOTID_WRITE_PROBE_PREPARE_BEGIN` 日志。
- timerfd 构建：`E:\workspace\projects\xiaomi-root\exploit-site\preload-local-violin-bootid-write-probe.so`，SHA256 `75D8DC383B24FB3C9A002948D3CBEAFDEB0277590C5FB107F9F2CD277C4FD471`。
- timerfd 上机入口：`http://127.0.0.1:18000/index.html?payload=bootid-write-probe`。
- timerfd 结果：设备重启，boot_id 从 `4a646d0c-2954-4db4-979d-17746c40a9df` 变为 `91696838-3344-4129-b19a-f41a5ecb41c8`；`crash.txt` 未保留有效 `FOPSROUTE` 日志，pstore/last_kmsg/mtdoops 没抓到 panic 栈关键词。
- 解释：timerfd 版很可能终于让 pselect 停留到 scheduler/PI 写路径窗口，但 custom waiter/fake task/lock 形态仍不安全，导致内核重启；与之前 calls=0 的“没触发”不同，这次是“触发后不稳”。
- 当前不要继续盲跑 timerfd direct-write。下一步应做更窄的 scheduler route probe：不写 boot_id/global target，先只让 timerfd custom route 打印/证明 `calls>0`，并使用 dummy/safe fake waiter 形态或停在 sched_setattr 前后，避免进入 rb_erase 写路径；或者等 rooted same-boot 设备拿 crash/oops 后再继续。
- 验证：默认 normal artifact 重新编译通过，SHA256 `F8704278AB4793146B8FE53D364AF5ECFDBDA0A17C9CDF96FF019647B774FE33`。
- 证据目录：`E:\workspace\projects\xiaomi-root\analysis_outputs\bootid-write-probe-instr-20260714\`、`E:\workspace\projects\xiaomi-root\analysis_outputs\bootid-write-probe-timerfd-20260714\`。

## 2026-07-14 KernelSnitch route-only probe 实机否证

- 目的：将 KernelSnitch / slab reclaim / fake waiter payload 与 scheduler 写入拆开，先只验证 `pselect` consumer handoff；route-only 分支不调用 `set_pselect_write()`，不准备 fake kernel page，`fd_set` 只置 `PSELECT_ROUTE_NFDS - 1` 的读位。
- 构建：`analysis_outputs\build-violin-route-only-probe-20260714.sh` 生成 `exploit-site\preload-local-violin-route-only-probe.so`；AArch64 ELF / `libdl.so` / `libc.so` 校验通过。另以 `-DVIOLIN_SKIP_SCHED_SETATTR=1` 构建 `preload-local-violin-route-only-nosched.so`，并在站点加入 `?payload=route-only-nosched`，用于排除 `sched_setattr` 本身。
- 实机：当前非 root Violin 先后以 Firefox 打开 `?payload=route-only-probe` 和 `?payload=route-only-nosched`。首次 boot_id `91696838-3344-4129-b19a-f41a5ecb41c8` 重启为 `805f6726-fa92-476e-b40a-c583e69ef868`，日志停在 `ROUTE_ONLY_GO`；nosched 版本再从 `805f6726-fa92-476e-b40a-c583e69ef868` 重启为 `9668d46b-4917-4ae2-b717-dab05eef25be`，日志仅到 `ROUTE_ONLY_PROBE_START`。
- 结论：该 route-only 设计并不安全；即使完全跳过 consumer 的 `sched_setattr`，构造 CVE requeue 链并进入该探针仍足以导致重启。当前不能把它作为 timing/consumer 的安全探针，禁止继续盲跑或据此推断 `consumer_calls`。下一步应改为完全不建立 `FUTEX_CMP_REQUEUE_PI` stale-waiter 链的独立 pselect/timerfd 时序测试，或先取得同 boot root oops/mtdoops，再决定如何最小化原始链。

## 2026-07-14 独立 timerfd/pselect 基线实机通过

- 实现/产物：`PSELECT_ONLY_PROBE` 只创建 pipe + 未 armed timerfd，将其复制到 fd `PSELECT_ROUTE_NFDS - 1`，以仅包含该读位的 `fd_set` 调用 1 秒 `pselect()`；没有创建 futex、`FUTEX_CMP_REQUEUE_PI`、waiter/owner/consumer 线程或 fake payload。入口 `http://127.0.0.1:18000/index.html?payload=pselect-only`，产物 `exploit-site\preload-local-violin-pselect-only.so`。
- 实机证据：`analysis_outputs\pselect-only-20260714\`。boot_id 前后均为 `9668d46b-4917-4ae2-b717-dab05eef25be`；`crash-sdcard.txt` 记录 `PSELECT_ONLY_RET: ret=0 errno=0 ... changed=0 isset=0`。
- 结论：纯 timerfd + `pselect(nfds=320)` 在当前 Firefox/Violin 环境稳定且按超时返回；此前重启由进入 CVE requeue/stale-waiter 链引入，不能归因于 timerfd、fd 复制或 pselect 基线本身。该基线只能证明 syscall/FD 形态可用，不能证明 scheduler consumer handoff。

## 2026-07-14 正常 PI waiter + sched_setattr 实机通过

- 新增 `NORMAL_PI_SCHED_PROBE`：owner 线程正常 `FUTEX_LOCK_PI`，waiter 线程对同一 futex 正常阻塞；主线程只对该真实 waiter TID 调用 `sched_setattr`，随后释放 owner 并等待 waiter 获取/解锁。没有 `FUTEX_CMP_REQUEUE_PI`、pselect、fake waiter/task/lock 或 KernelSnitch。
- 构建：`analysis_outputs\build-violin-normal-pi-sched-20260714.sh` 生成 `exploit-site\preload-local-violin-normal-pi-sched.so`，AArch64 ELF / 依赖验证通过，SHA-256=`520849D4C35D3C0EA00C9FB87B14A91180FA82DE49C6F23100BD090556C9527F`。
- 实机：`?payload=normal-pi-sched`；证据目录 `analysis_outputs\normal-pi-sched-20260714\`。boot_id 前后均为 `9668d46b-4917-4ae2-b717-dab05eef25be`；日志 `sched_ret=0 sched_errno=0 waiter_ret=0`。
- 结论：当前未 root Violin 上，真实 PI waiter 的 scheduler 优先级调整和正常 unlock/transfer 稳定。此前 requeue + pselect 的重启不能归因于普通 PI 或 `sched_setattr`；剩余不稳定边界收敛到 stale-waiter 与 pselect stack-copy 的组合。

## 2026-07-14 requeue route + pselect NULL sets 实机通过

- 新增 `ROUTE_PSELECT_NULLSETS_PROBE`：保留 `FUTEX_CMP_REQUEUE_PI` 路由，但不创建 consumer；在 stale-waiter 上下文调用 `pselect(PSELECT_ROUTE_NFDS, NULL, NULL, NULL, timeout, NULL)`，因此不发生任何 `fd_set` 用户态到内核栈的 copy。
- 构建：`analysis_outputs\build-violin-route-nullsets-20260714.sh`，产物 `exploit-site\preload-local-violin-route-nullsets.so`，SHA-256=`9BBB4796FD921807E424BFE525FCE9B6D9C1AA0BE113556B4615F4A6353EAFF3`；AArch64 ELF/动态依赖检查通过。
- 实机：证据目录 `analysis_outputs\route-nullsets-20260714\`；boot_id 前后均为 `9668d46b-4917-4ae2-b717-dab05eef25be`。日志依次记录 `ROUTE_NULLSETS_ENTER`、`ROUTE_NULLSETS_RET: ret=0 errno=0`、`ROUTE_ONLY_PROBE_DONE ... calls=0 success=0`。
- 结论：stale-waiter route 与 pselect syscall/timeout 本身可稳定共存；此前重启需要至少一个非 NULL `fd_set` copy。下一步是同样无 consumer 的单一全零 read `fd_set`，将“有无 copy”与“非零 bit 内容”分开。

## 2026-07-14 requeue route + pselect 全零 read set 实机通过

- 新增 `ROUTE_PSELECT_EMPTYIN_PROBE`：同一 `FUTEX_CMP_REQUEUE_PI` route、无 consumer，仅将全零 `fd_set in` 作为 read set 传给 `pselect(PSELECT_ROUTE_NFDS, &in, NULL, NULL, timeout, NULL)`；日志记录 copy 前后 `word0`。
- 构建：`analysis_outputs\build-violin-route-emptyin-20260714.sh`，产物 `exploit-site\preload-local-violin-route-emptyin.so`，SHA-256=`304488A85CA2F987BD68AEAC7FD77938BE69B87A78A5A45719BC6B1F9C6C32D7`；ELF/依赖检查通过。
- 实机：证据目录 `analysis_outputs\route-emptyin-20260714\`；boot_id 前后均为 `9668d46b-4917-4ae2-b717-dab05eef25be`。`ROUTE_EMPTYIN_ENTER` 与 `RET` 均记录 `word0=0000000000000000`，`ret=0 errno=0`。
- 结论：仅发生全零 read `fd_set` copy 不会触发重启；不稳定性进一步收敛到非零 `fd_set` 位/其覆盖内容，而非 pselect 的任何 copy。下一步可保持无 consumer，只设一个经过 dup2 绑定的未触发 timerfd read bit，确定“单个非零位”是否已足以触发。

## 2026-07-14 requeue route + 单个 timerfd read bit 实机通过

- 新增 `ROUTE_PSELECT_ONEBIT_PROBE`：同一 requeue route、无 consumer；仅将未触发 timerfd `dup2` 到 fd 319，并以 read set 的 bit 319 调用 pselect，其余两个 set 为 `NULL`。
- 构建：`analysis_outputs\build-violin-route-onebit-20260714.sh`，产物 `exploit-site\preload-local-violin-route-onebit.so`，SHA-256=`C2E147AE401FBAFA4EC7DC8D9CA8487B0F109D5EC7ED68CB193A7CABD2DC9A99`；ELF/依赖检查通过。
- 实机：证据目录 `analysis_outputs\route-onebit-20260714\`；boot_id 前后保持 `9668d46b-4917-4ae2-b717-dab05eef25be`。日志显示进入 `word4=8000000000000000`，pselect 超时返回后该 word 清零，`ret=0 errno=0`。
- 结论：单个非零 read bit 和一个 read-set copy 本身稳定；先前重启不由“任意非零 bit”触发。下一步应在仍无 consumer 时传入 `in` one-bit 加两个全零 `out/ex` sets，判断是否是三套 `fd_set` 连续 copy 的总体 stack footprint 引入破坏。

## 2026-07-14 requeue route + 三套 fd_set copy 实机通过

- 新增 `ROUTE_PSELECT_THREESETS_PROBE`：无 consumer；`in` 仅含未触发 timerfd 的 fd 319 bit，`out/ex` 为全零且非 NULL，完整覆盖普通 pselect 的三套 set-copy 形态。
- 构建：`analysis_outputs\build-violin-route-threesets-20260714.sh`，产物 `exploit-site\preload-local-violin-route-threesets.so`，SHA-256=`CDFEA70D61A80FC9E4464B064A2C062113EB41C543CA096B05550B415817AAD6`；ELF/依赖检查通过。
- 实机：证据目录 `analysis_outputs\route-threesets-20260714\`；boot_id 前后为 `9668d46b-4917-4ae2-b717-dab05eef25be`。日志记录 enter 时 `in4=8000000000000000,out4=0,ex4=0`，返回后均清零，`ret=0 errno=0`。
- 结论：三套连续 `fd_set` copy 的长度与单个非零 bit 仍稳定；仅凭 stack footprint 不能解释先前重启。对照已失败的 `route-only-nosched`，剩余差异是 consumer 激活时序（即使其跳过 `sched_setattr`）。下一步先在不调用 pselect 的 route 中只激活 no-sched consumer，检查 consumer 的 go/burst 并发本身是否改变 stale-waiter 生命周期。

## 2026-07-14 requeue route + no-sched consumer burst 实机通过

- 新增 `ROUTE_CONSUMER_ONLY_PROBE`：不调用 pselect；保留 route，创建 consumer 并设置 `punch_consume_go=1` 150ms。编译定义 `VIOLIN_SKIP_SCHED_SETATTR=1`，consumer 只递增 calls，不执行 scheduler syscall。
- 构建：`analysis_outputs\build-violin-route-consumer-only-20260714.sh`，产物 `exploit-site\preload-local-violin-route-consumer-only.so`，SHA-256=`8AD038AFC8DBD969B234C7EFB802540A0D9BA3C7CE9265DD787AB0FEA8D8D359`；ELF/依赖检查通过。
- 实机：证据目录 `analysis_outputs\route-consumer-only-20260714\`；boot_id 前后为 `9668d46b-4917-4ae2-b717-dab05eef25be`。日志 `calls=1 success=0`，route 正常完成。
- 结论：单独激活无 scheduler syscall 的 consumer burst 也稳定。现有失败只剩“pselect 的 fd_set copy 与已激活 consumer 的并发交错”；下一步先运行三套 fd_set copy、consumer 已创建但不发 go 的 idle-consumer 对照，再与历史 `route-only-nosched` 的 go 版本对比。

## 2026-07-14 requeue route + 三套 fd_set copy + idle consumer 实机通过

- 构建：复用 `ROUTE_PSELECT_THREESETS_PROBE`，但不定义 `ROUTE_SKIP_CONSUMER`，同时定义 `VIOLIN_SKIP_SCHED_SETATTR=1`；consumer 已创建但 route 不设置 go。产物 `exploit-site\preload-local-violin-route-threesets-idle.so`，SHA-256=`721318F3ED0BB169FF622423BA2D6289A5DBBCE161CFCD627141A70B948ABE2A`。
- 实机：`analysis_outputs\route-threesets-idle-20260714\`；boot_id 前后为 `9668d46b-4917-4ae2-b717-dab05eef25be`，三 sets copy 正常返回，`calls=0 success=0`。
- 结论：仅创建 consumer 不会改变结果；先前失败所需的最后差异为 `punch_consume_go` 激活与 pselect 同窗口。下一步做 active no-sched consumer + `pselect(NULL,NULL,NULL)`，先判断是否需要任何 set-copy。

## 2026-07-14 requeue route + active no-sched consumer + pselect NULL sets 实机通过

- 新增 `ROUTE_NULLSETS_CONSUMER_PROBE`：创建并激活 consumer，定义 `VIOLIN_SKIP_SCHED_SETATTR=1`；其调用计数在 pselect 窗口内递增，但 pselect 的 `in/out/ex` 均为 `NULL`。
- 构建：`analysis_outputs\build-violin-route-nullsets-consumer-20260714.sh`，产物 `exploit-site\preload-local-violin-route-nullsets-consumer.so`，SHA-256=`1DB45D29760D7308D49B890C66D3462A76610E57D6B8A39FD3A4BE7B0A44B0C4`；ELF/依赖检查通过。
- 实机：证据目录 `analysis_outputs\route-nullsets-consumer-20260714\`；boot_id 前后为 `9668d46b-4917-4ae2-b717-dab05eef25be`。日志 `ret=0 errno=0 calls=1 success=0`。
- 结论：active consumer 与 pselect syscall/timeout 仍稳定；现在已明确需要“active consumer + 实际非 NULL fd_set copy”。下一步以 active no-sched consumer 加单个 one-bit read set（out/ex 继续 NULL）来确定最小崩溃输入；其与此前重启路径相比不含另两套 sets，也不含 scheduler syscall。

## 2026-07-15 requeue route + active no-sched consumer + 单一 one-bit read set 实机通过

- 新增 `ROUTE_ONEBIT_CONSUMER_PROBE`：active consumer 定义 `VIOLIN_SKIP_SCHED_SETATTR=1`；pselect 仅传入含 fd 319 timerfd bit 的 `in`，`out/ex=NULL`。
- 构建：`analysis_outputs\build-violin-route-onebit-consumer-20260715.sh`，产物 `exploit-site\preload-local-violin-route-onebit-consumer.so`，SHA-256=`6ED7DF48755857B150A5D133E61111A679873D4B1FC87F65E7344D6BC144E889`；ELF/依赖检查通过。
- 实机：`analysis_outputs\route-onebit-consumer-20260715\`；boot_id 前后为 `9668d46b-4917-4ae2-b717-dab05eef25be`。`ROUTE_ONEBIT_CONSUMER_RET: ret=0 errno=0 calls=1 success=0`，copy 后 in word4 清零。
- 结论：单一 non-NULL one-bit set 即使在 active consumer 窗口也稳定。此前历史 route-only-nosched 重启必须还依赖 `out/ex` 两套 set 或旧分支差异；下一步以当前同一代码基线构建 active no-sched consumer + 三套 sets，重新取得可比较的决定性结果。

## 2026-07-15 requeue route + active no-sched consumer + 三套 sets 实机通过

- 新增 `ROUTE_THREESETS_CONSUMER_PROBE`：当前同一基线中，active consumer 定义 `VIOLIN_SKIP_SCHED_SETATTR=1`；`in` 为 fd 319 timerfd bit，`out/ex` 为全零且非 NULL。
- 构建：`analysis_outputs\build-violin-route-threesets-consumer-20260715.sh`，产物 `exploit-site\preload-local-violin-route-threesets-consumer.so`，SHA-256=`DF513E43C2A66EB23184AAE1E3F552B701A28982DF86956D8D77E8A9CD6DACD4`；ELF/依赖检查通过。
- 实机：`analysis_outputs\route-threesets-consumer-20260715\`；boot_id 前后为 `9668d46b-4917-4ae2-b717-dab05eef25be`。`ret=0 errno=0 calls=1 success=0`，三套 word4 均在返回后清零。
- 结论：当前可比代码中，完整三套 fd_set copy 加 active no-sched consumer 仍稳定；历史 `route-only-nosched` 的重启不能再归因于该组合，需视为旧构建/旧时序证据，不能继续作最小触发条件。下一阶段应恢复且严格限制为一次真实 `sched_setattr`，但须先用当前 pselect 覆盖布局建立可安全消费的 waiter 字段，而不能直接将全零 set 喂给 `rt_mutex_dequeue_pi`。

## 2026-07-15 custom pselect waiter layout 静态修正

- 发现：`PSELECT_WAITER_WORD_SHIFT=0` 且 `PSELECT_ROUTE_NFDS=320` 时每个 set 有 5 个 64-bit word；custom map 的 global word 5 对应 `waiter.pi_tree.entry + 0x00`（waiter + `0x28`）。原 `src\fops.c` 将 `fake_task`/`fake_lock` 放在 words 8/9，实际落在 `pi_tree.prio`/`pi_tree.deadline`，并将 task/lock 所在 words 10/11 填成了 wake-prio/0，字段错位两 word。
- 修复：words 8..13 现在依次为 `pi_tree.prio`、deadline、`waiter.task=fake_task`、`waiter.lock=fake_lock`、wake_state、ww_ctx；新增静态审计 `analysis_outputs\violin-pselect-waiter-layout-audit-20260715.md`。
- 验证：`analysis_outputs\check-violin-pselect-layout-syntax-20260715.sh` 通过 arm64 Android clang `src/fops.c -fsyntax-only`；未构建/运行触发 scheduler 的 payload。
- Gate：下次先做 layout-only emitted-word 日志验证，保持 scheduler disabled；真正 `sched_setattr` 的首轮必须以可观测的良性目标和当前轮 fake-page reclaim 证明为前置，不能直接使用 cred 写入目标。

## 2026-07-15 自动化测试入口去除确认弹窗

- 用户要求测试自动化不再被确认交互阻塞。`exploit-site\index.html` 在收到 device message 后直接设置 `confirmed = true`，移除了设备 ID/支持状态确认和第二层确认。
- 验证：`index.html` 不再包含 `confirm()` 调用；本地 HTTP 入口 `http://127.0.0.1:18000/index.html?payload=pselect-layout-only` 返回 HTTP 200。

## 2026-07-15 corrected custom layout-only runtime validation

- 产物：`exploit-site\preload-local-violin-pselect-layout-only.so`，修正后 SHA-256=`A7217B01C639BFF8C27766795964FD71CF1B0EC8FA4DF11FD594F1F644806885`。
- 实机：`analysis_outputs\pselect-layout-only-20260715-rerun\`；无 requeue、pselect、consumer 或 scheduler。boot_id 前后均为 `9668d46b-4917-4ae2-b717-dab05eef25be`，`PSELECT_LAYOUT_DONE: ok=1 no_kernel_route=1`。
- emitted words：in[2]=value、in[4]=target；out[0]=target-8、out[1]=value、out[3]=prio；ex[0]=fake_task、ex[1]=fake_lock、ex[2..4]=0。初次 layout-only run 的 `ok=0` 仅为 probe assertion 把 global word 8/9 错认成 ex[0/1]；实际 emitted words 已正确，assertion 已修正并重跑通过。
- Gate：用户态 emitted-word 布局已证明；仍未证明内核 copy 到 stale waiter 的 runtime stack 对齐或 fake-page reclaim。下步只可做该两项的受控验证，不能直接切回 cred 写入。

## 2026-07-15 KernelSnitch to SKB fake-page reclaim probe through

- 新增 `KERNEL_PAGE_RECLAIM_PROBE`：仅调用 `prepare_good_kernel_page(PAGE_PAYLOAD_FOPS)`，不启动 requeue/pselect/consumer/scheduler；记录 page 与 fake object 指针。
- 构建：`analysis_outputs\build-violin-kernel-page-reclaim-20260715.sh`，产物 `exploit-site\preload-local-violin-kernel-page-reclaim.so`，SHA-256=`B90CC8382F6FC3FF54420485D632F1B56F123DB77BAA076880157AC118A787E3`；AArch64 ELF/依赖检查通过。
- 实机：`analysis_outputs\kernel-page-reclaim-20260715\`；boot_id 前后保持 `9668d46b-4917-4ae2-b717-dab05eef25be`。返回 `base=ffffff8146cd8000`，`aligned=1`，并得到 `lock=ffffff8146cd84d0`、`w0=ffffff8146cd93a0`、`task=ffffff8146cda380`、`fops=ffffff8146cd8180`，`ordered=1`。
- 结论：当前轮 KernelSnitch / reclaim / fake payload 布局准备通过，且没有 route 副作用。剩余唯一运行时门槛是 pselect copy 到 stale waiter 的 stack alignment；下一次真实 scheduler 之前先需要一个只观察、可从用户态读取的 alignment oracle，而不是直接使用 rb_erase 写 cred。

## 2026-07-14 四个输入包解包与符号偏移复核

- 完成 `violin-kernel-info2.zip`、`ionstack-current-ktext.zip`、`1.zip` 的 ZIP CRC、路径穿越检查与安全解包；报告 `analysis_outputs\archive-verification-20260714\REPORT.md`，机器清单 `manifest.json`。
- 前两包的 kallsyms 在不同 rooted boot（不同 `_text`）下对 `violin-v-oss/target.h` 完成独立交叉检查，26/26 image-relative offsets 全部精确一致；没有复用任何 runtime 绝对地址。
- `1.zip` 是 panic evidence，内部 tar snapshot 的 34 个非自引用 manifest 项通过；外层 `collector.log` 是归档后续追加版本，不影响其他证据文件。它不含 kallsyms。
- 用户指定的 `ionstack-canonical-surface-20260712-172004.zip` 当前实际缺失，未把旧目录代替本轮归档核验；待重新提供后再验证。

## 2026-07-14 21:12 +08:00 route-only 卡死/重启收窄：问题落在 futex route + pselect 组合，不是 pselect 本身

### 输入

- 用户反馈：`卡了`
- 当前未 root 设备：ADB `03035440C1781540`
- 相关 payload：`route-only-probe`、`route-only-nosched`、`pselect-only`

### 实测结果

1. `route-only-probe`
   - 站点 artifact：`exploit-site/preload-local-violin-route-only-probe.so`
   - SHA256：`CF80CC26686FA604778F9A899A3F9F29EE397E3EAC6FC39C3BABDDB1979D8969`
   - 日志停在：`ROUTE_ONLY_PROBE_START` / `ROUTE_ONLY_GO: waiter_tid=... in_last=1`
   - 无 `ROUTE_ONLY_RET`；设备重启，boot_id 从 `91696838-3344-4129-b19a-f41a5ecb41c8` 变为 `805f6726-fa92-476e-b40a-c583e69ef868`。
   - 证据目录：`analysis_outputs/route-only-probe-20260714/`

2. `route-only-nosched`
   - 编译参数：`-DDIRECT_WRITE_ROUTE_ONLY_PROBE=1 -DVIOLIN_SKIP_SCHED_SETATTR=1 -DPSELECT_CFI_ROUTE_ATTEMPTS=1`
   - 站点 artifact：`exploit-site/preload-local-violin-route-only-nosched.so`
   - SHA256：`0CEECCEC4D4571CBB6C11C760D67AAE1DE96DD5A542199A9F7697354CFE08099`
   - consumer 不调用 `sched_setattr()`，仍导致 ADB 掉线/设备重启，boot_id 从 `805f6726-fa92-476e-b40a-c583e69ef868` 变为 `9668d46b-4917-4ae2-b717-dab05eef25be`。
   - 证据目录：`analysis_outputs/route-only-nosched-20260714/`

3. `pselect-only`
   - 新增编译宏：`PSELECT_ONLY_PROBE`
   - 不创建 futex waiter/owner/consumer，不走 `FUTEX_WAIT_REQUEUE_PI`/`FUTEX_CMP_REQUEUE_PI`，只执行同类 `pselect(PSELECT_ROUTE_NFDS=320)` safe fdset + 1s timeout。
   - 站点 artifact：`exploit-site/preload-local-violin-pselect-only.so`
   - SHA256：`9AEBE17B092512C1E53550ED7DA9275322D1629FB1D48B0FCDC752EAAA35D60D`
   - 结果正常返回且不重启：`PSELECT_ONLY_RET: ret=0 errno=0 ... changed=0 isset=0`；boot_id 保持 `9668d46b-4917-4ae2-b717-dab05eef25be`。
   - 证据目录：`analysis_outputs/pselect-only-20260714/`

### 结论

- `pselect`/timerfd/high-fd/fdset 构造本身是安全的。
- 重启不依赖 direct-write forged rb-node，也不依赖 `sched_setattr()`，因为 `route-only-nosched` 仍重启。
- 当前卡点收窄为：`run_main_route_threads()` 的 futex requeue/PI route 之后，waiter 线程执行 `do_pselect_fake_lock_route()` 的组合路径；更可能是 futex route 后 waiter 栈/PI 状态与 pselect 栈帧重叠方式在 Violin 上不安全，不能继续靠加大 consumer/scheduler 参数轰。

### 下一步

- 做更窄的 `route-no-pselect` 或 `futex-route-only` probe：创建 waiter/owner、执行 requeue，但 waiter 醒来后不进入 pselect，只记录 futex 返回与 route_done，验证单纯 futex route 是否会重启。
- 若 `route-no-pselect` 安全，再做 `route-pselect-delay/exit-before-pselect` 变体定位 pselect 进入时机；若仍重启，则回到 futex route/UAF rollback 状态机排查。
- 禁止继续重跑 `bootid-write-probe` 或带 forged rb-node 的 timerfd direct-write；它们已经造成重启且没有可用 crash site。

## 2026-07-14 21:18 +08:00 route-no-pselect 证实：futex route 单独安全，重启来自 route 后 pselect fdset 覆盖

### 新增 probe

- 新增宏：`ROUTE_NO_PSELECT_PROBE`
- 代码位置：`exploit-repo/IonStack/CVE-2026-43499/exploit/src/fops.c`
- 行为：`run_main_route_threads()` 照常创建 waiter/owner/consumer 并执行 futex requeue；waiter 从 `FUTEX_WAIT_REQUEUE_PI` 返回后进入 `do_pselect_fake_lock_route()`，只打印 `ROUTE_NO_PSELECT_ENTER` 并返回，不调用 `pselect()`。
- 编译参数：`-DDIRECT_WRITE_ROUTE_ONLY_PROBE=1 -DROUTE_NO_PSELECT_PROBE=1 -DVIOLIN_SKIP_SCHED_SETATTR=1 -DPSELECT_CFI_ROUTE_ATTEMPTS=1`
- artifact：`exploit-site/preload-local-violin-route-no-pselect.so`
- SHA256：`54FAFC1D65C3E35117E179859B3C6BAED654368BB4C7BE99D450A631C03F582C`
- 证据目录：`analysis_outputs/route-no-pselect-20260714/`

### 实测结果

当前 boot_id：`9668d46b-4917-4ae2-b717-dab05eef25be`。

日志：

```text
STEP0: preload loaded pid=17391
ROUTE_ONLY_PROBE_START: boot=9668d46b-4917-4ae2-b717-dab05eef25be uid=10270 euid=10270
ROUTE_NO_PSELECT_ENTER: waiter_tid=17392
ROUTE_ONLY_PROBE_DONE: before=9668d46b-4917-4ae2-b717-dab05eef25be after=9668d46b-4917-4ae2-b717-dab05eef25be changed=0 route_done=1 calls=0 success=0 waiter_tid=17392 cfi_step=0 errno=0
```

设备未重启，boot_id 未变化。

### 更新后的定位

- `pselect-only` 安全：说明 pselect/timerfd/high-fd/fdset 基础构造不导致重启。
- `route-no-pselect` 安全：说明 futex waiter/owner/requeue route 本身不导致重启。
- `route-only-nosched` 仍重启：说明不是 `sched_setattr()` 单点。
- 因此当前最可能根因是：futex route 之后 waiter 栈上仍存在内核会继续引用/校验的 `rt_mutex_waiter`/PI 状态，而 route 后的 `pselect(PSELECT_ROUTE_NFDS=320)` 会把三组 fd_set copy 到同一 syscall stack 区域，哪怕 fdset 是“safe fdset”，大块清零/覆盖也会破坏仍活跃的 waiter/PI 链。

### 下一步

做 `route-pselect-null/small-nfds`：保留 futex route，但 route 后调用 `pselect(0/1, NULL 或极小 fdset)`，避免覆盖 `sp-0x200` 大块 waiter 区。若安全，则证明关键是 fd_set copy 覆盖窗口；后续要改成只写最小必要 word、或换不会清零整块 fdset 的 stack-copy primitive。

### 2026-07-15 — same-boot root oracle 包校验

- 校验 `tools/collect-sameboot-root-oracle-ready.zip` 与 `tools/collect-sameboot-root-oracle.zip`：解包后的唯一脚本 `collect-sameboot-root-oracle.sh` SHA-256 均为 `87F0AADDCB7CD609731B4E1692743DE0CA07396AA083E33274696D0FDF9B5C62`，逐字节一致；以 `sh -n` 通过 POSIX 语法检查。
- 两个 ZIP 只是归档层不同，功能不互补；执行一个即可，优先 `collect-sameboot-root-oracle-ready.zip`。
- 该采集器在**同一已 root boot**中读取符号和既有 `/proc` / debugfs `current_task` oracle，生成 `current->cred` 写入目标；它不会自行加载 LKM/eBPF oracle，也不验证 pselect 对 stale waiter 的栈对齐。因此仍须先在同一 boot 暴露 current-task/waiter 观测端点。

### 2026-07-15 — same-boot kprobe/LKM 只读 oracle

- 新增 	ools/sameboot-kprobe-oracle/，并重打 collect-sameboot-root-oracle-ready.zip 与 collect-sameboot-root-oracle.zip（同一内容；ready ZIP SHA-256：$hash）。归档包含主采集脚本和 LKM 源、Kbuild、构建/加载采集脚本及说明。
- LKM 固定以 arm64 Violin ABI 探测 do_select(x0=n,x1=fd_set_bits*)；此入口已位于 core_sys_select() 三次 get_fd_set() 之后，因此输出三套实际内核 copy 起点和前五个 word。针对目标 TGID，它还把 t_mutex_dequeue_pi(task, waiter) 入口的 waiter 地址、tree/pi_tree RB 指针、prio/deadline、task/lock/wake_state/ww_ctx、以及相对三套 fd_set 起点的有符号差值写入 /proc/ionstack_oracle。
- PSELECT_WAITER_WORD_SHIFT 以模块参数记录，默认由 loader 传  ；输出同时给出 xpected_waiter_minus_pselect_in_for_shift 以便与实测 delta 对账。模块不使用 copy_to_user、rb mutation、cred mutation 或 target 调度调用。
- 限制已固化：目标内核的 t_mutex_dequeue_pi 在源码中为 __always_inline。若生产 image 无该精确 kallsyms 符号，模块明确报告 t_mutex_dequeue_pi_probe=unavailable 和 errno，绝不把结果冒充为该函数入口观测；do_select 不可探测时模块加载失败。当前工作区没有 exact configured kernel KDIR/Module.symvers，故仅完成脚本语法、必需输出 schema、源码锚点与无写入原语审计，未生成或加载 .ko。

## 2026-07-15 sched_blocked_reason tracefs canonical KASLR leak confirmed

- Current unrooted Violin shell (`uid=2000`, `u:r:shell:s0`, `readtracefs`, SELinux Enforcing) has live `sched:sched_blocked_reason` (`ID=109`) with a writable `enable` node and writable `tracing_on`; write probe restored `enable` from `0 -> 1 -> 0`.
- A two-second bounded capture with trap-based state restore yielded `336` formatted entries and CPU0 `trace_pipe_raw` capture `analysis_outputs/sched-blocked-reason-raw-cpu0-20260715.bin` (SHA-256 `A4F48EB86863802758773315BA532DD9005D05AE62E2AD5E81EF2C54A9E3158C`). Exact live format stores `caller` at payload offset `16`, size `8`; raw record `pid=25045` has canonical `caller=0xffffffd30a6d797c` and formatted counterpart `worker_thread+0x9c/0x334`.
- Same-build image-relative arithmetic (`worker_thread-_text=0xd78e0`) gives current `_text=0xffffffd30a600000`. This is a valid canonical text base, not P0/direct-map; it satisfies the fops/CFI route's same-boot pointer requirement for a process with tracefs privileges.
- Scope gate: the verified principal is ADB shell, not the existing browser/app payload UID. Do not treat it as an in-process payload oracle until that UID's tracefs access or a same-boot transfer mechanism is independently proven. Event/tracing state after capture: both `0`; device boot unchanged. Full evidence: `analysis_outputs/sched-blocked-reason-kaslr-leak-20260715.md`; reusable offline decoder: `tools/parse_sched_blocked_reason_raw.py`.
- Firefox execution-domain check completed: main process `org.mozilla.firefox` is `uid/gid=10270` (`u0_a270`), SELinux `u:r:untrusted_app:s0:c14,c257,c512,c768`, no capabilities, supplementary groups `3003,9997,20270,50270,99909997`; it lacks `readtracefs`. `trace_pipe_raw` is `0440 root:readtracefs`, so Firefox fails DAC read access (and remains subject to untrusted_app SELinux) even though event `enable` is `0666`. This KASLR leak is therefore shell-only and cannot be used directly by the Firefox payload.
- Firefox in-process tracefs test completed via explicit `org.mozilla.firefox/org.mozilla.fenix.IntentReceiverActivity` local page (`adb reverse`, then removed). Existing Firefox application-UID command bridge executed only `ls`/`head -c 1` on `trace_pipe_raw`; both returned `Permission denied`, `FIREFOX_TRACEFS_RAW_READ_STATUS=1`, UID `10270`, SELinux `u:r:untrusted_app:s0:c14,c257,c512,c768`. This directly confirms the Firefox payload cannot consume the sched_blocked_reason raw-pointer leak. Screenshot: `analysis_outputs/firefox-tracefs-probe-rev2-20260715.png`; no trace event enabled and no CVE route invoked.
- Shell-assisted CFI run: current same-boot trace base `0xffffffd30a600000` was injected through Firefox `?payload=cfi-stage&kbase=...` and handed to `CFI_KASLR_BASE`. The full downstream CFI/configfs/pipe chain rebooted the device; post-run boot changed `9668d46b-4917-4ae2-b717-dab05eef25be` -> `c1d5962f-411e-4596-93c8-9fb54957e003`, ADB shell remains UID 2000/Enforcing, no root. Treat this as downstream chain failure, not base-leak failure; do not rerun unchanged. Evidence `analysis_outputs/firefox-cfi-shell-assist-20260715.png` and sched trace report.

### 2026-07-15 — sched_blocked_reason tracefs KASLR-leak 面审计

- Violin GKI 6.6 源码确认 `include/trace/events/sched.h` 的 `sched_blocked_reason` 把 `__get_wchan(tsk)` 原始 `void *caller` 写入 event（record offset `16`、size `8`）；文本渲染仅为 `caller=%pS`。事件只在 `kernel/sched/core.c` 观察到被唤醒 task 仍带 `TASK_UNINTERRUPTIBLE` 时发出。
- 在当前非 root ADB `shell` 实测：属于 `readtracefs`；`/sys/kernel/tracing/events/sched/sched_blocked_reason/enable` 是 `0666`，可写 1 并已恢复 0；`tracing_on` 也是 `0666`，可写 1 并已恢复 0；`trace_pipe`、`per_cpu/cpu0/trace_pipe_raw` 可由 readtracefs 读取。format 实测 event ID=109，`caller` 原始字段为 offset 16/8 bytes。
- 采样窗口内系统 `tracing_on` 初始为 0，故未产生 event；这不是“已取得 leak”。实际利用还需要在短窗口内启用 tracing、捕获一个 blocked-reason record，并从 raw trace 解析 caller 的原始 64-bit 值，再与同一 build 的本地 vmlinux offset 对齐。文本 `%pS` 本身不提供 runtime 数值地址。
- 结论：本设备满足 tracefs 权限和 raw-field 可读这两个关键前提；`tracing_on` 初始关闭与“需要一次可观测的 D-state wakeup”是剩余运行时门槛。此路径可作为 target same-boot canonical text anchor 候选，替代此前 root-only kallsyms/LKM address oracle 的前置，但必须先实际捕获 raw caller 并做 build/地址域校验。

### 2026-07-15 — shell-assisted CFI base 注入复核

- 复核 `analysis_outputs/sched-blocked-reason-kaslr-leak-20260715.md`（SHA-256 `4C4253503AD9EFC824FCCDA96E4F22E0581B97E41A49D7BD3823DF59E5A9D97E`）和 recovery 截图（SHA-256 `107A1C55FC59B8BE72EF2FD8B91EA37ECBA21ED596EBF9101617FEF32C9FAABB`）：run 前 boot `9668d46b-4917-4ae2-b717-dab05eef25be` 的 raw trace caller 推导 `_text=0xffffffd30a600000`；`cfi-stage` 后重启到 `c1d5962f-411e-4596-93c8-9fb54957e003`，当前 ADB shell 仍 uid 2000 / Enforcing，未获 root。
- 源码复核：`exploit-site/exploit.html` 将 query `kbase` 作为 `CFI_KASLR_BASE` 环境变量传给 payload；`src/main.c` 优先解析该环境变量，检查 canonical text 与对齐，再写入 `cfi_kaslr_base`。因此本次报告所述的 shell-assisted base 的确进入 CFI payload；旧 boot base 已随重启失效，禁止重放。
- 阶段结论更新：target same-boot canonical text anchor 已实证，不再是 CFI 路线 blocker；重启发生在其后的 configfs/pipe/CFI 链。下一项必须是 fresh-boot、single-variable 的下游阶段定位，不重复完整 `cfi-stage`。

### 2026-07-15 — fresh boot anchor 与 CFI configfs-only 首轮

- 新 boot `c1d5962f-411e-4596-93c8-9fb54957e003` 重新采集 tracefs：CPU1 raw record 中 `worker_thread+0x9c` 为 `0xffffffd3002d797c`，按同 build static offset `0xd797c` 推导 `_text=0xffffffd300200000`。采集目录 `analysis_outputs/sched-blocked-reason-freshboot-20260715/`；trace enable/tracing_on 均已恢复 0。
- 新增 `CFI_CONFIGFS_ONLY_DIAG` 分支、路由 `payload=cfi-configfs-only` 与 AArch64 asset `exploit-site/preload-local-violin-cfi-configfs-only.so`（SHA-256 `C9B81F9EF0A804BA0EE0D9D53D1BEAF43BBBE4923798085D3E85B44F88F5D088`）。该分支应在 configfs write/read/forged-llseek 校验后、pipe/physrw 前清 owner 并退出；完整 build 已通过。
- 首次启动未重启，boot 不变；但应用内 crash 日志显示 `CFI_STAGE_ONLY_STOP_NO_KASLR`，即本次 `kbase` 没有到达 payload 的 `CFI_KASLR_BASE` 环境变量，因而没有进入 route/configfs-only gate。下一步先修复/验证页面 query-to-env 注入，再重跑该诊断版本；不得把本轮“无重启”解释为 configfs route 成功。

## 2026-07-15 — Pad 7U same-chip offset list comparison

- 用户提供“小米平板 7U 最新版本”vmlinux 符号表偏移清单；逐项与当前 Violin `src/targets/violin-v-oss/target.h` 对照，清单内核心 image-relative offsets 全部一致：`ASHMEM_FOPS=0x012c9df0`、`CONFIGFS_READ_ITER=0x00488978`、`CONFIGFS_BIN_WRITE_ITER=0x00488ea4`、`COPY_SPLICE_READ=0x0040d4ac`、`NOOP_LLSEEK=0x003c0380`、`INIT_TASK=0x020de280`、`ROOT_TASK_GROUP=0x022d4580`、`SELINUX_BLOB_SIZES=0x0164fb48`、`SECURITY_HOOK_HEADS=0x0164f410`、`KMALLOC_CACHES=0x0164ef50`、`ANON_PIPE_BUF_OPS=0x0114a288`、`SLIDE_NFULNL_LOGGER=0x020d2270`、`SLIDE_LOGGERS_0_1=0x020d21b8`、`SLIDE_SYSCTL_BOOTID=0x02336f58`，`KIMAGE_TEXT_BASE=0xffffffc080000000` 也一致。
- 关键差异/风险：用户补充的 `KERNEL_PHYS_LOAD=0x80000000/0x0` 不能直接替换本项目当前配置；Violin rooted `/proc/iomem` 与运行日志中仍使用 `P0_PHYS_OFFSET=0`、`P0_KERNEL_PHYS_LOAD=0x00210000`、delta `0x00210000`。这属于 physical alias/profile 层，不等同于 vmlinux symbol offset。
- 结论：该 Pad 7U 清单强烈说明同芯片/同 GKI build 的静态符号面与 Violin 一致，可作为交叉佐证；但不能证明目标当前 boot 的 canonical KASLR、Firefox 进程可读 tracefs、configfs/CFI 下游链或 root 已成功。后续若要使用 7U 成果，只能继承 image-relative offsets，不能继承 runtime `_text` 或物理加载假设。
- 修正 URL 启动命令：必须在设备 shell 中单引号包住完整 URL，否则 `&kbase=...` 被 shell 当作后台分隔符，导致 `CFI_KASLR_BASE` 缺失。带引号重启 configfs-only 诊断后 boot 仍未变化；本轮 UI crash-log 抓取未抽出阶段标记，暂不把它判为 configfs 成功，后续需先修复/等待结果页的应用内日志读取。
- 进一步证据链检查：执行 `firefox-tracefs-probe`（不加载 CVE payload）后 `pidof org.mozilla.firefox=13272`，说明本地页面、intent 和应用内 shell bridge 可正常存活。此前 `cfi-configfs-only` 启动后 Firefox 无进程，而 boot 未变；因此最强结论是其在应用/子进程结果回传前终止，不能用空 `diag=crash` 当作“未执行”。健康 Firefox 内单独访问 `diag=crash` 仍未从 UI 抽出历史标记，当前 private-log 回收链不可靠；下一版本需要把阶段心跳写入一个能在 app 进程终止后由 ADB 取回的受控位置，或改为每阶段单独的 non-exiting bridge acknowledgement。
- 纠正诊断回收结论：`crash_debug_log()` 已同时写 `/sdcard/Download/crash.txt`；ADB shell 可读，不能只依赖 Firefox 私有 `crash.txt`。configfs-only 实际日志确认外部 KASLR 成功应用到 fresh base `0xffffffd300200000`，页面已到 STEP2 page reclaim、STEP3 route，并在 FOPS route attempt 1-5 记录 consumer success；日志未出现 `cfi stage entered` 或 `CFI_CONFIGFS_ONLY_STOP`。因此当前阻断发生在 configfs-only gate 之前（route retry/进程终止），不是 pipe/physrw；后续阶段日志统一从 Download 文件 pull 回。
- 页面“无法连接”恢复：重建 `adb reverse tcp:18000 tcp:18000` 后，Firefox 实测可加载 `http://127.0.0.1:18000` 的 tracefs probe。截图还发现 root `index.html` 留有 Done alert，且 `exploit.html` standalone 分支仍有 confirm；现已全部替换为非阻塞页面状态。`rg` 确认 exploit-site HTML/JS 不再含 `alert(` 或 `confirm(`，并用唯一 run token 重新加载验证。
- 当前 boot `3c594ef3-1a2c-4ed1-ae0d-bdd1aa30def1` 重新由 CPU1 raw `worker_thread+0x9c` 记录推导 `_text=0xffffffe23ee00000`，trace 状态已恢复。configfs-only 使用该 fresh anchor 执行且 boot 不变，外部日志确认 `STEP1_EXTERNAL_KASLR` 消费了该值；随后仅到 `STEP1: slide OK`，未到 STEP2/FOPS/ashmem。故本轮 blocker 进一步前移到 `prepare_good_kernel_page(PAGE_PAYLOAD_FOPS)` 或其日志之后，不能把它归因于 ashmem/configfs；`CFI_OPEN_ASHMEM_FAIL` 增强尚未被实际触达。
- 更正上一条的阶段描述：完整 `crash.txt` 含 `STEP2: prepare_page`（page `0xffffff806d408000`）和 `STEP3: entering run_main_route_threads`；停止点在 `run_main_route_threads()` 内、首条 `FOPSROUTE_SETUP` 之前。因此当前最小 blocker 位于线程创建/等待或 `FUTEX_CMP_REQUEUE_PI` 前的 route 预备阶段，不是 page reclaim、ashmem 或 configfs。
- route-prep heartbeat run（asset SHA-256 `0E11272684EF62A759C84B48A1A36B98FFD5C13DE8C3DB6B036D696BAF20BFA5`）在同 boot 无重启下确认：waiter/owner/consumer 均创建、`ROUTE_PREP_READY` 成立、`FUTEX_CMP_REQUEUE_PI=-1/errno=35(EDEADLK)` 成立；但随后 `route_done` 持续为 0（至少 3.76s），所以从未进入 `do_pselect_fake_lock_route()`/FOPS setup。当前 blocker 精确为 requeue rollback 后 waiter/owner 线程未使 route_done 置位，而非 configfs stage。

## 2026-07-15 — 外部 Pad 7U log_success1.txt 复核

- 输入日志：`E:\ZEOON3\Pictures\Downloads\log_success1.txt`，SHA-256 97F7974517A635C63D72D14FAB602AF4A28B98E4093597D19511A48DBA425CE5。运行主体是 `uid=2000` / `u:r:shell:s0` / SELinux Enforcing，不是 root。
- `pselect ... calls=1 success=1` 仅表示 consumer 的用户态 `sched_setattr` 计数达标，不能等同 CFI、任意写或 root 成功。direct main route 连续 24 次均输出 `pselect cfi miss ... step=4 errno=0`。
- 当前源码 `src/fops.c` 中 `step=4` 精确对应：configfs 读回 fake fops 的 `llseek` slot 未得到预期 `text_addr(NOOP_LLSEEK)`；因此 CFI configfs/fake-fops 校验未通过，尚未进入后续 pipe/physrw/SELinux 写入阶段。
- 日志随后明确给出 `selinux enforce=1`、`direct SELinux write failed`；slide fallback 又读到非 canonical 值 `0xab420f3584b16325`，被 `slide bad leaked pointer` 拒绝。因此文件中的 `success=1` 不是 root success，完整链在 direct CFI 和 slide leak 两条路径上均失败。
- 该日志的 P0 profile 是 `phys_offset=kernel_phys_load=0x80000000, delta=0`，与当前 Violin 的 `P0_PHYS_OFFSET=0`、`P0_KERNEL_PHYS_LOAD=0x00210000` 不同；可参考其 image-relative symbol offsets 和失败签名，不能照搬 physical profile 或把该次运行时结论移植到 Violin。
- waiter-lifecycle run（asset SHA-256 `BD5F2CEA8D97C93BB8DF4B4E7A0100F0BCEE4B1B219363AD1DD93BB1819AE4C7`）确认 `WAITER_REQUEUE_WAIT_ENTER` 后无 `WAITER_REQUEUE_WAIT_RET`；controller 至少记录到 6.51 秒仍 `route_done=0`，而该 target 的 `ROUTE_WAIT_SECONDS=8`。因此当前现象是 waiter 未在 timeout 前返回或应用/子进程在其 8 秒 timeout 前终止；下一检查点应是页面 wrapper/command watchdog，而不是修改 futex payload timing。
- 进程检查显示 Firefox child shell 仍在运行；此前 14 秒后只记录 6.51 秒是采集时点相对 payload 进入时刻偏晚，不能据此判为 watchdog 终止。已延长等待并重新回收 waiter 生命周期日志（见 freshboot-3c594ef3/crash-waiter-lifecycle-final.txt）。
- `FOPSROUTE_CFI_DISPATCH/RESULT` 心跳版 asset（SHA-256 `A48A3E7F70EF0BAF75048A8A16CFEE27134748EF6D67C7547FC84B750910AF7E`）启动后 ADB 断开；设备恢复上线时 boot 已从 `3c594ef3-1a2c-4ed1-ae0d-bdd1aa30def1` 变为 `27b66c49-e0d5-48bc-afa3-2fbaf9f27cdd`，`/sdcard/Download/crash.txt` 不存在。此次 run 发生内核重启，因日志未持久化不能把崩溃位置归因于 dispatch 或 CFI 函数。旧 KASLR anchor 失效；停止同 boot 继续运行，后续只能先恢复新 boot 的 trace anchor，再依靠 mtdoops/oops 分区抓取重启证据或用不会触发 route 的静态/用户态检查。
- 重启后新 boot `27b66c49-e0d5-48bc-afa3-2fbaf9f27cdd` 的 tracefs raw CPU1 再次捕获 `worker_thread+0x9c=0xffffffdfc70d797c`，推导 fresh `_text=0xffffffdfc7000000`；采集位于 `analysis_outputs/post-reboot-27b66c49-20260715/`，trace enable/tracing_on 均已恢复。
- oops 证据路径已核验：`/dev/block/by-name/oops -> /dev/block/sdc79`，后者权限 `brw------- root:root`；非 root ADB shell 对 4 KiB 只读 `dd` 返回 Permission denied，未生成文件；`/sys/fs/pstore` 同样 Permission denied。因此必须在同 boot 的 rooted 设备上运行既有 `tools/collect-rooted-oops-partition.sh` 才能取到上轮重启的内核证据，普通 shell 不能绕过。
- 新增 Android 本地终端自提权、只读 oops 采集包 `tools/collect-current-boot-oops-local.sh` 与 `.zip`：默认输出 `/sdcard/Download/ionstack-oops-currentboot-<timestamp>.tar.gz`；脚本先以 `su` 重启自身，读取恰好 1048576-byte mtdoops record，短读/失败会删除无效 raw 并写 FAILED，成功则输出 raw/hash/strings/interesting lines/kallsyms。已通过 POSIX `sh -n`；不写 oops 分区，`kptr_restrict` 仅临时降低并恢复。

## 2026-07-16 — sameboot/currentboot 归档审计

- 使用 `minimal-run-and-audit` 的证据归一化流程，对 `E:\ZEOON3\Downloads\Compressed\currentboot.zip` 与 `E:\ZEOON3\Downloads\Compressed\sameboot.zip` 解包、计算外层 SHA-256，并逐项核验内部清单。
- 两包同属 root boot `ed0b4c66-b4d6-442b-a8ba-92f908275ee9`；已确认 `_text=0xffffffe1a5800000`、`init_cred=0xffffffe1a78f0548`、`init_cred` 相对偏移 `0x20f0548`、`init_task` 相对偏移 `0x20de280`。但 oracle 显示 `current_task_status=NEEDS_LKM_ORACLE`，未获得 current task/cred 运行时值。
- `currentboot` 正确读取 `/dev/block/sdc79` 的单条 1 MiB mtdoops 记录（`RESULT=OK`），但记录为 `Oops_Index: 209`、`REASON: Restart`、内嵌日期 `2026-07-08`，含电源键路径且无 panic/oops/CFI 证据；不可用作本轮重启归因。
- 实时 ADB 目标机 boot ID 为 `27b66c49-e0d5-48bc-afa3-2fbaf9f27cdd`，不同于 root 包 boot ID；root 包中的绝对符号地址不可复用到当前 USB 设备。
- 正式报告：`analysis_outputs\sameboot-currentboot-evidence-audit-20260716.md`；解包核验材料：`analysis_outputs\evidence-audit-20260716\`。

## 2026-07-18 stack_diag 自解压路径修复

- 现象：Android 本地运行 `stack_diag.sh` 时，第 18/22 行尝试写 `/kcore_read`、`/preload.so`，因根目录只读失败；随后 `FAIL: kcore_read`。
- 根因：2026-07-18 14:40 生成的 `tools/stack_diag.zip` 内脚本已把工作目录前缀丢失，实际内容是 `base64 -d > /kcore_read` 和 `> /preload.so`；不是 `/data/local/tmp` 权限问题。磁盘上的新版脚本虽已使用 `$D`，但 ZIP 仍是旧产物。
- 修复：`tools/stack_diag.sh` 固定并校验 `D=/data/local/tmp/stack_diag`，要求目录可创建且可写，所有内嵌工具输出/`chmod` 均使用带引号的 `"$D/..."`；重新生成 `tools/stack_diag.zip`。
- 验证：WSL `sh -n` 通过；重新读取 ZIP 内脚本确认写入目标为 `"$D/kcore_read"` 与 `"$D/preload.so"`。源脚本 SHA-256 `6B009ADE4C714B267E59FC321E133A2EB000776EE30315FE7D27221330F13960`；ZIP SHA-256 `34F49C50ED968D5012E3E0D1331F5F2E6D8D296F035F8C6613E56D7A7E084F32`。
- 后续：手机端必须删除旧解压脚本/ZIP并重新传输新版；若仍显示 `/kcore_read`，说明执行的仍是旧副本。

## 2026-07-18 stack_diag 重命名重打包

- 为避免手机端继续误执行旧同名文件，复制当前已修复脚本并重新打包为 `tools/stack_diag_fixed_20260718.sh` / `tools/stack_diag_fixed_20260718.zip`。
- ZIP 内唯一入口文件为 `stack_diag_fixed_20260718.sh`；已确认内嵌工具输出目标是 `"$D/kcore_read"` 和 `"$D/preload.so"`，不再是根目录绝对路径。
- WSL `sh -n` 通过。脚本 SHA-256 `6B009ADE4C714B267E59FC321E133A2EB000776EE30315FE7D27221330F13960`；ZIP SHA-256 `1BE4ED36964B26FA91C8BC5354D02F927CDDFFABF5D6A981244F58CB554E51C7`。

## 2026-07-18 stack_diag 设备直运行复核

- 在 USB 目标机 `03035440C1781540` 上直接执行新版脚本复现：设备当前 boot ID `c79163bc-d9f5-457a-a30f-0362d89db8ea`，运行身份 `uid=2000(shell)`、SELinux `u:r:shell:s0`、Enforcing，`su` 不可用。
- 结果：工作目录创建和两个内嵌 ELF 解压均成功（`kcore_read` 2,139,504 bytes、`preload.so` 175,504 bytes）；失败点是 `/proc/kallsyms` 对 shell 不可读，脚本退出码 1。此前 `/_kcore_read` 报错来自旧 ZIP；新版已不存在该路径问题。
- 对脚本增加直运行前置诊断：记录 uid/SELinux context；不可写 `kptr_restrict` 时记录 NOTE 而非制造 shell 重定向噪声；隐藏 kallsyms grep 权限错误并给出“需要 privileged device shell”；校验 `init_task`/`misc_fops` 符号和 kcore 读取长度。
- 新版 `stack_diag_fixed_20260718.sh` 与 ZIP 已重打包；`sh -n` 通过。脚本 SHA-256 `078AC8192815CD72702EB02A9897AC97E63E93B75109C41F919D57E3FDD069FE`；ZIP SHA-256 `14894DAD2D09E97CD4405AADD4B4B658416A39551A721725962B59676C25D2A0`。

## 2026-07-18 stack_diag MT 管理器特权兼容

- MT 管理器的执行包装只是 `exec sh <script>`，脚本不会凭空提权；它继承 MT 管理器当前 UID。
- 新增可选 `su` 自动重执行：非 root 时探测 PATH、`/data/adb/magisk/su`、KernelSU/APatch 及常见系统路径；只有 `su -c id` 明确返回 `uid=0` 才重执行，避免伪 su/递归。无可用 su 时继续当前 UID并记录 `no usable su found`。
- 在当前设备 ADB shell 实测仍为 uid 2000、无可用 su，因此按预期在 `/proc/kallsyms unavailable` 退出；内嵌 ELF 解压仍成功。MT 管理器若已获 root，日志应直接显示 `uid: 0`；若未获 root且设备无 su，只能先给 MT 管理器授予 root 或从 root 终端启动。
- 新版 `stack_diag_fixed_20260718.sh` / ZIP 已重打包；`sh -n` 通过。脚本 SHA-256 `509214B404A80E2F82228188E4FBF7ABB6CE867D1572BF4F7CA7677AAFF8453B`；ZIP SHA-256 `34A823399A52A451D9D98769043333730DAB26531B6D2DFC0286159F774D8E2B`。

## 2026-07-18 MT 管理器 root 运行结果与 kcore blocker

- 用户在 MT 管理器中运行 `stack_diag_fixed_20260718.sh`，截图确认 `uid: 0`、SELinux `u:r:magisk:s0`、`_text=0xffffffd5eda00000`；因此提权和 KASLR 读取均已成功，问题不再是打包路径或 MT 管理器 UID。
- 截图中的 warning 来自 `SELINUX_CONTEXT=$(cat /proc/self/attr/current)` 将 proc 输出中的 NUL 放入 shell command substitution；已改为 `tr -d '\000'`，并在设备 shell 回归中确认 warning 消失。
- `kcore_read` 的实现固定 `open("/proc/kcore", O_RDONLY)`；项目此前对该目标机的证据已确认 `/proc/kcore` 不存在。脚本新增 `/proc/kcore` 存在/可读预检，并保留 stderr 到 `kcore_read_init.err`，下一次运行会明确显示是 `does not exist`、`not readable` 或具体 kcore 错误，而不是笼统 `FAIL: kcore_read`。
- 最新 `stack_diag_fixed_20260718.sh` / ZIP 已重打包；`sh -n` 通过。脚本 SHA-256 `D1A8971253D627FFA81A938788D07E8E2B4D8D8C7EC74BD2863FE0614465415E`；ZIP SHA-256 `7DB2E51839E5468457EF80A4827582C90CA1AEBA4CF4CC14B3450BB4952C8EFE`。

## 2026-07-18 runtime kernel-stack analysis blocker

- 用户目标是：exploit/pselect 运行期间通过 `kcore_read` 读取内核栈，定位 `readfds` 指针，并与 `waiter->lock` 偏移对照。
- 当前证据链尚未满足第一步：MT 管理器终端已是 `uid=0`、`u:r:magisk:s0`，KASLR `_text` 可读；但 `kcore_read` 固定打开 `/proc/kcore`，该目标机此前已记录 `/proc/kcore` 不存在/不可用。因此不能声称已取得运行时栈、readfds 位置或 waiter lock 对照。
- 现有 `diagnose_stack_alignment.sh` 不能直接作为有效结果来源：含硬编码旧地址/旧 `_text` fallback，使用 `ps|grep` 竞态定位进程，抑制 kcore 错误，且没有同 boot guard 和可验证的 current-task/kernel-stack 定位。
- 后续若继续，只能先补齐同 boot 的 `/proc/kcore` 或授权只读 oracle/debug-kernel trace；再验证线程 TID、pselect 的 user `readfds` 地址、内核栈范围以及同 build 的 waiter 类型/字段偏移。缺少任一项时不输出偏移结论。

## 2026-07-18 /proc/kcore 配置结论

- MT 管理器截图确认新版运行环境为 root (`uid=0`, `u:r:magisk:s0`) 且 `_text=0xffffffd5eda00000`，所以 `FAIL: /proc/kcore does not exist` 不是权限/打包问题。
- 同 build 的静态内核配置 `analysis_outputs/e24/target-config.txt:6811` 明确为 `# CONFIG_PROC_KCORE is not set`；虽然存在 `CONFIG_ARCH_PROC_KCORE_TEXT=y`，但没有 `CONFIG_PROC_KCORE` 就不会创建 `/proc/kcore`。
- 结论：当前 `kcore_read` 路径在该生产内核上结构性不可用，脚本无法通过 chmod、Magisk context 或 shell 逻辑补出该节点。运行时内核栈/readfds/waiter->lock 分析必须改用 debug kernel/tracepoint/授权 LKM oracle 或离线同 build 内核映像分析。

## 2026-07-18 output-only 写入证据脚本

- 针对 `/proc/kcore` 在目标内核不存在，新增 `tools/stack_diag_output_20260718.sh` / `.zip`：仅解压 `preload.so`、读取当前 boot/KASLR、运行既有 payload，并从 `exploit.txt` 归类输出证据。
- 证据语义拆分为：`ROUTE_REACHED`（route/consumer marker）、`CFI_ROUTE_OK`（`FOPSROUTE_CFI_RESULT ok=1`）、`DIRECT_WRITE_ROUTE_OK`（direct-write probe 的 route signal）、`CRED_READBACK`（`STAGE2_VERIFY uid=0`）、`TARGET_SLOT_READBACK`（仅接受显式 `FOPS_WRITE_CONFIRMED`/`WRITE_READBACK_OK`）。最终明确输出 `TARGET_WRITE=UNKNOWN_NO_TARGET_READBACK`，不把 route 到达误报为目标槽位写入。
- ADB shell（非 root）回归：脚本正常解压 preload，按预期在 kallsyms 阶段退出；`sh -n` 通过。脚本 SHA-256 `D3C7D2DE0D6CF38B6841B5A6C98EC1251EA45127EF3EEE226D30A3C05DEF72FD`；ZIP SHA-256 `51EB1E4D6F9957D9427A14C341DDA158158D771A20193B6F3E8859D114E55B44`。

## 2026-07-18 output-only 脚本超时修复

- MT root 运行截图停在 `=== Run exploit (output-only evidence) ===`，原因是脚本先 `sleep 8` 后无条件 `wait $EXPID`；payload 内部 route/worker 可能不返回，导致 shell 永久等待且未归档当前输出。
- `stack_diag_output_20260718.sh` 已改为轮询 `kill -0`，默认最多等待 20 秒；超时先 TERM、再 KILL，并记录 `exploit timeout`、状态码 `124`，随后仍归档 `exploit.txt` marker 和证据分类。可通过 `EXP_TIMEOUT=<秒数>` 调整。
- 修复后 `sh -n` 通过；脚本 SHA-256 `5F18B09B05EE8B58C3CFE8ADA4EA16736E2D85F0002A85DF1922BBCBA91A7EE0`；ZIP SHA-256 `7B75184AD717F04DD7E993BBD24A7399706089C605CE0D59A367BE291346DCA1`。
- 为避免 MT 管理器继续执行旧同名文件，另存为 `tools/stack_diag_output_timeout_20260718.sh/.zip`；重命名 ZIP SHA-256 `2C932E2204F0054D0AE426F19D7AE9DFFDD7EB20C0D4651B013CD8E716A63C4E`，压缩包仅含该脚本。

## 2026-07-18 output-only evidence v2 审查与修复

- 两次 MT root 运行分别得到正常退出 0 和超时 124，但均显示所有 marker 为 0。审查确认这不能解释为 route 未执行：内嵌 payload 的 `fops_route_log()` 不写 stdout/stderr，而是追加到 `/data/data/org.mozilla.firefox/files/crash.txt` 与 `/sdcard/Download/crash.txt`；旧脚本只解析 `/data/local/tmp/stack_diag/exploit.txt`，因此结构性漏报。
- v2 在运行前记录 `/sdcard/Download/crash.txt` 字节数，运行后仅提取本轮追加 delta，与 `exploit.txt` 合并后解析；marker 正则不再要求行首匹配，并在无 marker 时直接显示 raw exploit tail。解析回归覆盖旧日志隔离、`FOPSROUTE_GO/RET` 与 `FOPSROUTE_CFI_RESULT ok=1`，结果 PASS。
- 同时修复：每轮清空 `diag.txt` 防止跨 boot 混证；超时终止 payload 的子进程树；恢复脚本改动前的 SELinux 与 `kptr_restrict`；校验 `EXP_TIMEOUT`；验证内嵌 preload 大小/SHA-256；拒绝空值/全零 `_text`；仅在明确 target readback marker 存在时输出 `TARGET_WRITE=CONFIRMED_BY_TARGET_READBACK`。
- 进程树终止回归（父 shell + sleep 子进程）PASS，`sh -n` PASS，ZIP 单文件与内嵌 ELF 校验通过。新交付 `tools/stack_diag_output_evidence_v2_20260718.sh/.zip`：脚本 SHA-256 `01103787A38292ECC266ED02156FCBAF34DA13D9C1993E9E2933D7AEC0C1DBD1`；ZIP SHA-256 `85EFCB893EDDBDCD00E6B7FDABE85EF489969FDA165AC1C2B4CABA3576B01778`；内嵌 preload 175,504 bytes，SHA-256 `F850DC1A0C06C71FA13FBA1E38CF465152381C7A61AF71819694501525201947`。

## 2026-07-18 GHOSTLOCK_VIOLIN_RESEARCH 方案审查

- 对 `exploit-repo/IonStack/CVE-2026-43499/exploit/GHOSTLOCK_VIOLIN_RESEARCH.md` 与 violin 源码交叉核验：方案暂不可执行，当前项目门禁仍只允许只读 canonical-pointer 审计和离线 rbtree/rt_mutex 对账，不得按文档第 14/16 节编译、安装、运行 payload 或关闭 SELinux。
- 已确认的硬阻塞：`PSELECT_ROUTE_NFDS=64` 且 ARM64 `words_per_set=1`，`prepare_pselect_fdsets()` 只会把 global word 0/1/2 分别放入三个 fd_set，其余 custom words（特别是 5/6/7/10/11）会被静默丢弃，不能实现文档声称的完整 waiter 覆写。
- 文档把 `cfi write errno=22` 和 boot_id 不变过度解释为“未发生写入”；两者只能表示该次 configfs transport 失败或未重启，不能替代目标槽位 readback、persistent oops/mtdoops 与同 boot 关联证据。
- 文档的 pselect/readfds 栈布局结论互相矛盾（0x20/sp+0x10 与 0x50/sp+0x40），且源码同时存在 pselect 与 poll 分支；后续必须固定源码入口、宏配置、构建命令、artifact SHA256，再给出一条经反汇编/运行时只读 oracle 证明的栈方程。
- `/proc/kcore` 在目标同 build 的 `target-config.txt` 中明确未启用；后续应改用离线同 build 映像、tracepoint、授权 debug kernel/LKM oracle 或持久化 oops 采集。

## 2026-07-18 ashmem fops 槽位与 fd_set word 语义复核

- 静态核验确认：`src/targets/violin-v-oss/target.h` 中 `ASHMEM_MISC_OFF` 指向 `ashmem_misc`，`ASHMEM_MISC_FOPS_OFF` 指向独立的 `misc_fops` 静态表；它不是 `ashmem_misc.fops` 槽位。
- 同 build `struct miscdevice` 在 `analysis_outputs/ota_full/kheaders/include/linux/miscdevice.h` 的字段顺序为 `minor/name/fops`，ARM64 下 `fops` 偏移为 `0x10`。Violin raw Image 在 `ashmem_misc + 0x10` 处的指针内容与 `ashmem_fops` 的 image-relative offset 相符，因此写入目标应单独定义为 `data_addr(ASHMEM_MISC) + 0x10`，原 `data_addr(ASHMEM_MISC_FOPS)` 目标错误。
- `fd_set` 语义需区分：`words[i].word` 是 waiter qword 索引；`set_idx` 才是三组 fd_set 的索引；`fd_set` 中的 value 是 64-bit bitmask，值为 `2` 完全可能（表示 bit 1/FD 1）。在 `nfds=64`、ARM64 `words_per_set=1` 时只有 global word 0/1/2 分别进入 in/out/ex，word 3 及以上会被当前 custom 分支忽略。
- 以上均为离线静态结论，未运行 payload。

## 2026-07-18 Violin rbtree→fops raw Image 静态模型更正

- 重新按同 build `boot.img.kernel` 的 image-relative offset 读取 `misc_fops` 与 `ashmem_misc`，确认 `misc_fops+0x00`、`+0x10`、`+0x18`、`+0x30`、`+0x40` 均为零；`ashmem_misc+0x10` 内容为 `&ashmem_fops`。因此“Violin misc_fops 所有字段非零”不成立。
- BTF `struct file_operations` 明确 `+0x30=iopoll`、`+0x40=poll`；文档把 `+0x30` 标成 poll 是字段映射错误。
- 依据同 build `rbtree.h`：NULL 搜索属于 `rb_add_cached()`，`rb_link_node()` 将 `&new_node` 写入选定 child link，`rb_insert_color_cached()` 只做平衡。当前默认伪节点在新 waiter 优先级低于 130 时会沿 `misc_fops-0x08` 走到 `misc_fops+0x00` NULL owner，候选写入是 stale waiter 地址，不是 `fake_fops`。
- 直接把 target 改为 `ashmem_misc+0x10` 后，该槽为非 NULL 的 `&ashmem_fops`，遍历会继续进入后续对象；不能把简单改址当作已完成 fops 劫持。
- 正式离线模型：`analysis_outputs/violin-rbtree-fops-static-model-20260718.md`；未构建、安装或运行 payload。
- 补充边界：`rtmutex.c::__waiter_prio()` 先调用 `trace_android_vh_rtmutex_waiter_prio()`，vendor hook 可能覆盖 waiter priority；因此模型中的 `new_prio=120` 只是默认 nice=0 候选，不能替代同 boot 优先级证据。
- 模型前置条件已补充：只有 `rt_mutex_adjust_prio_chain()` 走到 owner task 的 `rt_mutex_enqueue_pi()` 且 owner/root 仍对应 payload 的 `fake_task` 时，后续 `misc_fops`/ashmem 槽路径才会发生；不能把条件模型当作运行时已到达证据。
- 新增优先级分支：当前 `consumer_thread` 第一次 `sched_setattr` 使用 nice=19；Violin `rtmutex.c` 在 chain walk 中会先 `waiter_update_prio()` 再 `waiter_clone_prio()`，所以首个 pi-tree 候选通常为 priority 139，比较 `139 >= FAKE_WAITER_PRIO(130)` 后走 fake root 的 rb_right=0，而非 misc_fops。后续 nice=0 是否进入目标链，取决于 dequeue/requeue 状态。
- 补充 `rb_erase_cached` 条件模型：若首个 139 waiter 被插入 fake root 右叶、后续调整先删除该黑叶，sibling 会被解释为 `misc_fops-0x08`；其左 child 是 `noop_llseek`、右 child 是 `misc_fops+0x00=NULL`。raw Image 中 noop_llseek 首 qword color bit=0，可能走 color-flip 并上溯到 fake_fops，再撞到 fake_fops+0x10=NULL。此为离线损坏树风险路径，未运行验证。
- 进一步对账 `fake_lock.waiters` / `fake_task.pi_waiters`：两棵伪树都把根指向 `fake_w0`，而 `fake_w0.__rb_parent_color=fake_fops`、`fake_fops+0x08` 指向其 pi-tree entry；若首轮 139 保留伪 waiter 为 lock-top、后续 120 触发真实 waiter 接管，前置 `rb_erase_cached(fake_w0)` 可能先把 `fake_fops+0x08` 清零，再在损坏树上进入 `rb_is_red(NULL)`。该候选写入发生在 fake_fops payload，不是 misc_fops 或 ashmem fops 槽；仍属条件模型，未运行验证。
- 入口边界再次收紧：active 默认 FOPS route 实际调用 `poll()`，只有显式 `ROUTE_PSELECT_*` 宏分支才调用 `pselect()`；因此 target.h 的 pselect 栈方程不能直接套到默认 route。另确认 `pselect_custom_write=0` 时仍使用 `misc_fops-8`，custom fdset 在 `nfds=64`/`words_per_set=1` 下丢弃 word 3 及以上。下一步必须按 active 宏配置先重建 stale waiter 的 task/lock/tree/pi_tree 消费，再展开两次 sched_setattr 的 dequeue/requeue 状态机。
- 可达性限制：默认 FOPS payload 未启用 custom write 时将 `fake_w0->task=INIT_TASK`、`fake_task.pi_top_task=INIT_TASK`，不能直接假定 scheduler 会消费 `fake_task.pi_waiters`；同时 `fake_w0->lock=pselect_user_lock` 而不是 `fake_lock`。因此 fake_lock/fake_task 图必须等 stale waiter 身份、owner 与 lock 字段消费顺序闭合后才可升级为有效路径。

## 2026-07-18 Violin 设备连接与 tracefs 只读基线

- ADB 设备 `03035440C1781540` 已连接，product/model/device=`violin`/`25053RP5CC`/`violin`，kernel=`6.6.77-android15-8-g5770c661275f-abogki443185593-4k`，boot ID=`c79163bc-d9f5-457a-a30f-0362d89db8ea`。
- 当前身份为 `uid=2000(shell)`、`u:r:shell:s0`、SELinux `Enforcing`；`/proc/kcore` 不存在，`/proc/kallsyms` 对该 shell 不可读。
- tracefs 只读检查：`tracing_on=1`，`sched/sched_blocked_reason` 已启用，`trace_pipe_raw` 对 shell 可读；CPU0 stats 为 `entries=39980`、`overrun=15249335`、`dropped events=0`。本轮只读取 formatted snapshot，未读取 raw pipe，避免消费 ring buffer。
- 现有 trace 快照可见 `worker_thread+0x9c/0x334` 等符号化记录，但未用未解析地址推导新的 `_text`；trace ring 有大量 overrun，不能当作完整历史证据。正式基线：`analysis_outputs/violin-device-readonly-baseline-20260718.md`。
- 该结果只证明 shell/readtracefs 侧存在只读 trace 面，不证明 app payload 进程具备同权限，也不证明 payload 内 KASLR oracle 已建立；本轮未运行 payload。
- 非消费式 CPU0 formatted trace tail 已另存为 `analysis_outputs/violin-device-trace-snapshot-20260718.txt`，仅作当前 boot 的符号化样本，不作为完整历史或 `_text` 推导依据。
- 在记录前后 stats 后完成一次有界 `64 KiB` `trace_pipe_raw` 采集（该读取会消费 ring）：raw SHA-256=`0A84BFB09ACF2F7F9A7DED389D3104E52EA7E6A974C9CF540C9724EFC50E9215`。重复 `worker_thread+0x9c` caller=`0xffffffd6928d797c`，按同 build `worker_thread+0xd78e0` 推得当前 boot `c79163bc-d9f5-457a-a30f-0362d89db8ea` 的 `_text=0xffffffd692800000`。该地址不同于 2026-07-16 boot `ee24a224-a8a5-4c79-825b-638bded450e6` 的旧 `_text=0xffffffd5eda00000`，旧 base 不得复用。
- 由当前 boot `_text` 加 Violin 静态 offsets 得到离线模型地址：`misc_fops=0xffffffd693a69710`、`ashmem_misc=0xffffffd694a3b5d8`、`ashmem_misc+0x10=0xffffffd694a3b5e8`、`ashmem_fops=0xffffffd693ac9df0`。均未做 runtime readback，不能当作已验证写入目标。

## 2026-07-18 share-poc-XRing-O1 → Violin 移植审计

- 审计外部仓库 `wfqefwqf/share-poc-XRing-O1`：其 target 是 Jinghu (`OS3.0.301.0.WOXCNXM`)，不是当前 Violin (`OS3.0.303.0.WOTCNXM`)；P0 geometry 也不同，不能直接复制 `target.h` 或二进制。
- 仓库 `ASHMEM_MISC_FOPS_OFF=0x223b5e8` 恰好等于 Violin `ashmem_misc+0x10`，说明该名称实际代表 `miscdevice.fops` 指针槽；Violin 独立静态 `misc_fops` 仍是 `0x1269710`。这是可复用的目标语义，不能按符号名误解。
- 仓库的 pselect user-lock 布局把 word0 保持为零、word1-3 放 forged rt_mutex 字段，解决了 `nfds=64` 只扫描 word0 的约束；它是候选 route shape，不能替代 Violin 当前 active `poll()` 栈布局证明。
- 仓库 `main_cred.c` 的 `leak_task_struct()` 仍为 TODO 并返回 0；cred 直写路线未闭合。其文档同时承认 rb 写入值来自 `task->pi_blocked_on` waiter 的 pi-tree 地址，因此 `set_pselect_write(target,value)` 不能直接当作已证实的任意值写原语。
- 正式审计：`analysis_outputs/share-poc-xring-o1-violin-port-audit-20260718.md`；本轮未构建、安装或运行外部仓库 payload。
- 继续核对 checked commit `1a8877603edcaa726c1836687613ae768ea19ef8`：`common.h` 定义 `FAKE_WAITER_PI_TREE_PRIO=0x7fffffff`，但 `util.c` 实际在对应 offset 写入 `FAKE_WAITER_PRIO=130`；该宏未被使用，README 所述“强制走 right branch”与源码不一致。
- 离线重建 pselect/PI 链状态机：外部仓库的 `pselect_user_lock[0..3]` 仅在 `readfds == pselect_user_lock`、`nfds=64` 且 route 真正调用 `pselect()` 时成立；当前 Violin 默认 `do_pselect_fake_lock_route()` 实际把同一数组当 `pollfd` 传给 `poll(nfds=1)`，先将 word0 写成 `0xffffffffffffffff`，不能直接套用外部布局。
- 当前 Violin `prepare_pselect_fdsets()` 的 custom word map 只被显式 pselect probe/direct-write 分支消费；默认 poll 路径不消费它。且 custom write 关闭时 `fake_w0->task=INIT_TASK`、`fake_task.pi_top_task=INIT_TASK`，因此只移植 user-lock 形状仍不能证明 fake_task/pi_waiters 可达。
- 外部 `common.h` 对“fdset window 后放 lock fields”的注释与实际 `fops.c`（直接写 words 0--3 并传 `&pselect_user_lock`）不一致，已列为移植前必须解决的源码内契约冲突。详见 `analysis_outputs/share-poc-xring-o1-violin-port-audit-20260718.md` §6。
- 使用 codebase-memory MCP 完成 build/调用链核对：Violin target 目录无 target-local `fops.c`，Makefile 选择共享 `src/fops.c`；未提供任何 `ROUTE_*` / `DIRECT_WRITE_*` 编译宏时，`do_pselect_fake_lock_route()` 确定落入默认 `poll()` 分支。`run_exploit()` 默认不进 pselect probe，`waiter_thread()` 在 FUTEX_WAIT_REQUEUE_PI 返回后调用该 route。
- 因此下一步必须二选一：离线重建 Violin 专属 poll 栈/UAF 布局，或单独建模显式 pselect route 的外部 user-lock overlay；不能把两种布局混在同一 payload 模型中。

## 2026-07-18 Violin 默认 poll 路由栈/UAF 离线重建

- 从同 build `kernel_text_nonzero.objdump.S` 对账 `__arm64_sys_futex`、`do_futex`、`futex_wait_requeue_pi`、`__arm64_sys_poll`、`do_sys_poll`：令 syscall 前栈顶为 `T`，旧 `rt_waiter_base=T-0x200`，`waiter->lock=T-0x1a8`；后续 `do_sys_poll` local sp 为 `P0=T-0x4b0`，`pollfd` copy 在 `P0+0x7c`，`poll_wqueues` 在 `P0+0x170`。
- `waiter->lock` 的重叠位置是 `P0+0x308 = poll_wqueues+0x198`，不是用户 `pollfd` copy 区。`poll_initwait()`/`poll_get_entry()` 反汇编确认 `inline_entries` 从 `+0x30` 开始、stride `0x40`，所以该位置对应 `inline_entries[5].wait.entry.next`。
- `do_sys_poll` 先对 `poll_wqueues` 执行 `memset(...,0,0x270)`；当前源码固定 `fd=-1, events=0`，反汇编的负 fd 分支直接跳过 `fget`/`do_pollfd`，不会创建 `poll_table_entry`。因此该重叠字段在默认 route 中保持零值，`pselect_user_lock` 不会被送入 stale `waiter->lock`。
- 即使未来把 `fd` 换成合法文件，`__pollwait()`/`add_wait_queue()` 链接的也是内核 `wait_queue_head`，`wait.entry.next/prev` 是内核队列指针而非用户 VA；当前 `nfds=1,fd=-1` 更不会创建覆盖点所对应的 `inline_entries[5]`。
- 结论：默认 Violin `poll(fd=-1,nfds=1)` 与外部仓库 `pselect(readfds=user_lock,nfds=64)` 是两套不同状态机；把外部 word0..3 overlay 直接套入默认 route 不成立。正式离线记录：`analysis_outputs/violin-poll-stack-uaf-static-model-20260718.md`。本轮仍未构建、安装或运行 payload。
- 同文件进一步独立对账显式 `pselect()`：`__arm64_sys_pselect6=-0x90`、`core_sys_select=-0x1f0`，故 `Q0=T-0x280`；`nfds=64` 的三组 fd-set kernel copy 位于 `Q0+0x80/+0x88/+0x90`，而旧 `waiter->lock=T-0x1a8=Q0+0xd8` 落在 timeout scratch pair 末端、`poll_wqueues(Q0+0xe0)` 之前。当前同 build 方程没有证明 stale lock 指针等于 `pselect_user_lock` 用户 VA；旧 `sp+0x10/sp+0x40` 说法降级为未证实。
- 若增大 pselect `nfds` 让 copy 覆盖 `Q0+0xd8`，同 build 最早是 `nfds=256`，但该位置随即落入第三组 fd-set 的扫描窗口；用户 VA 会被解释为 FD bitmask，无法同时满足无 EBADF 与指针值条件。`nfds=64` 避开扫描却不覆盖该 slot。
- 研究结论收敛：下一步不是改 `ASHMEM` offset、`fd_set` value 或单独改 `nfds`，而是先离线找到能让 stale lock 读到同一用户 VA 的单一路由/调用序列；在该指针等式闭合前，不运行新 payload。

## 2026-07-18 share-poc-XRing-O1 最新提交离线复核

- 当前外部 HEAD 为 `fd7f733574965d36620d47e92c4d9e4b6d7cf50a`，相对已审计的
  `1a8877603edcaa726c1836687613ae768ea19ef8` 只新增 README、rb_insert/PI 链报告和
  反汇编文件；没有新的 C/H 逻辑、构建产物或 Violin 运行证据。
- 新反汇编支持“PI 链写入值是待插入 `pi_tree_entry` 的节点地址”，也支持
  `task->pi_blocked_on=waiter(+0x938)`、`waiter->lock(+0x58)` 和
  `owner==current` 跳过 `remove_waiter`。但这不等于任意写：红黑树的 root/child
  槽位仍由比较路径决定，`rb_erase` 只写替身/子节点或 NULL，均需合法树形状。
- 外部 README 的 pselect word0..3 overlay 仍未证明 stale `waiter->lock` 等于
  `&pselect_user_lock`。Violin 同 build 方程显示 `nfds=64` copy 在 `Q0+0x80/88/90`，
  stale lock 在 `Q0+0xd8` timeout scratch；且 Violin 默认入口是 `poll(fd=-1,nfds=1)`。
- 外部 target 是 Jinghu/KASLR=0；不能把绝对地址、vendor hook 或这套 pselect 路由
  直接迁移到当前 Violin。外部 `target.h` 还同时保留真实 waiter `+0x18` 与 fake
  waiter `+0x28` 两套宏，当前 `.c` 未引用旧宏，但后续 painting 前必须清理。
- 正式审计：`analysis_outputs/share-poc-xring-o1-update-audit-20260718.md`；本轮
  仍只做网络/文件/反汇编只读分析，未构建、安装或运行 payload。

## 2026-07-18 sched_blocked_reason KASLR 路线范围校正

- 这条路线在当前 Violin 上已经有同 boot 证据：ADB shell（uid=2000、`readtracefs`）
  可读取 `sched:sched_blocked_reason` raw event，并从 payload offset `16`、宽度 `8`
  的 `caller` 得到 canonical text 指针；用本地**精确匹配** vmlinux 的
  `worker_thread` image-relative offset 可推导该 boot 的 `_text`。
- 这不是“所有开启 tracefs 的 Linux 环境”都成立：`sched_blocked_reason` 是 Android
  common 扩展，且必须同时满足事件存在、enable/tracing_on 可写、raw trace 可读、
  产生 D-state wakeup 记录、读者与 payload 为同一权限域、以及本地 vmlinux/build
  fingerprint 对齐。上游 Linux 未必包含该 Android tracepoint。
- 文本 `trace`/`%pS` 只给符号化名称，不能单独当作数值 KASLR leak；数值地址来自
  raw record。当前 Firefox/untrusted_app（uid=10270）没有 `readtracefs`，不能把
  shell 的 leak 自动视为 payload 内 oracle；只能称为 shell-assisted same-boot
  handoff，且 reboot 后旧 base 立即失效。
- 当前阶段仍不启用/写入新 trace event、不运行 payload；后续只做离线 verifier：校验
  event ID/field offset、canonical range、symbol delta、boot_id 与 kernel fingerprint
  四项是否同时成立。

## 2026-07-18 历史“成功”口径复核

- “之前有成功”这一说法成立，但成功项必须限定为：在 Violin 指定 boot、ADB
  `shell`/`readtracefs` 权限域内，通过 `sched_blocked_reason` raw event 读取数值
  `caller`，并用同 build 的 `worker_thread` image-relative offset 推导该 boot 的
  canonical `_text`。
- 可复核数值链为：`caller=0xffffffd30a6d797c`，格式化记录对应
  `worker_thread+0x9c/0x334`，`worker_thread-_text=0xd78e0`，因此
  `_text=0xffffffd30a600000`。原始证据和离线解码器分别见
  `analysis_outputs/sched-blocked-reason-raw-cpu0-20260715.bin`、
  `analysis_outputs/sched-blocked-reason-kaslr-leak-20260715.md` 和
  `tools/parse_sched_blocked_reason_raw.py`。
- 该证据不等于 `/proc/kallsyms` 可读、不等于通用 Linux tracefs 都有该能力，
  也不等于 Firefox/app payload 可在进程内消费 oracle；Firefox 的 UID/domain
  无 `readtracefs`，raw pipe 访问已实际返回 `Permission denied`。
- 因此状态应写为：**same-boot shell KASLR leak：已证实；payload 内 oracle：未证实；
  fops/CFI 控制流：未闭合；root：未获得。** 旧对话中把其中任一中间证据写成
  “完整 KASLR bypass/root 成功”的说法均属过度结论，本条作为当前口径覆盖。
- 本条仅完善证据口径，未新增设备写入、payload 构建、安装或运行。

## 2026-07-18 sched_blocked_reason 离线 verifier

- 新增 `tools/verify_sched_blocked_reason_kaslr.py`，只读取归档 raw capture 和
  本地 `kallsyms.txt`，不连接 ADB/tracefs。
- 对 `analysis_outputs/sched-blocked-reason-raw-cpu0-20260715.bin` 完成五项核验：
  SHA-256、event ID 109/`caller` offset 16、`worker_thread-_text=0xd78e0`、
  caller 数值和派生 canonical `_text`，全部 PASS。
- 正式结果见 `analysis_outputs/sched-blocked-reason-kaslr-verifier-20260718.md`。
  该 verifier 只复现历史证据，不扩大 shell/readtracefs 的权限范围，也不把旧
  boot 基址视为当前 boot 有效。

## 2026-07-18 Violin 联机 tracefs oracle 复核

- 设备 `03035440C1781540` 在线，当前 boot 为
  `c79163bc-d9f5-457a-a30f-0362d89db8ea`；ADB shell 为 uid 2000、SELinux
  Enforcing、具备 `readtracefs`。
- 在事件原有 `enable=1`、`tracing_on=1` 状态下，仅读取一次有界 `64 KiB`
  CPU0 `trace_pipe_raw`，未写入 tracefs 节点；读取会消费对应 ring-buffer 样本。
- 新 raw 样本含 `caller=0xffffffd6928d797c`（`worker_thread+0x9c`），按同 build
  差值 `0xd78e0` 推得当前 boot `_text=0xffffffd692800000`；SHA-256 为
  `D344ED5D573D5FB3E8CE354D5AE75F4311AF9A86D80DCC28AFE185E2831232E1`。
- 事件和 tracing 状态在读取后仍为 `1`，boot_id 未变化；正式记录见
  `analysis_outputs/violin-live-trace-oracle-check-20260718.md`。
- 这轮只证明当前 shell/readtracefs 域的 fresh same-boot oracle，不证明 app
  域可读、任意写、CFI/fops 控制流或 root；未运行 exploit payload。
- 对该 64 KiB raw 样本做稳定性扫描：共识别 1818 个 event 候选，其中 690 个为
  精确 `worker_thread+0x9c` caller，全部推导同一 `_text=0xffffffd692800000`。
  这只说明当前 boot 的已知符号锚点稳定，不把其他模块/地址域 caller 当作同一
  kernel text base。

## 2026-07-18 trace_kaslr_leak native reader 修正与联机验证

- 发现旧 `tools/trace-kaslr-leak/trace_kaslr_leak.c` 把 `caller` 错读为 payload
  offset `24`，且 cleanup 无条件写 `enable=0`；这与 live format/离线 parser 的
  offset `16` 不一致。
- 已修正为对齐扫描 event ID 109、`pid+8`、`caller+16`；默认只读，不改变
  `enable`/`tracing_on`，仅显式 `--enable` 时临时修改并恢复原值。
- 使用 `bash tools/trace-kaslr-leak/compile.sh` 编译，AArch64 静态 ELF SHA-256：
  `2B33202758040FF7C7B0A1EF93907CC47BF99FCC69B4A0A8616936AB2C85D022`。
- 推送到在线设备并以 `-n 100 -t 2000` 运行，成功多次读到
  `caller=0xffffffd6928d797c`；运行后 `enable=1`、`tracing_on=1`、boot_id
  未变化。输出归档：`analysis_outputs/violin-live-tool-v2-20260718.txt`。

## 2026-07-18 Firefox 正确入口与 app-domain probe

- 首次浏览器白屏原因已定位：直接打开 `exploit.html`；它是无可视 body 的
  headless child。改用 `index.html?payload=firefox-tracefs-probe` 后页面正常显示
  完整结果。
- 当前 boot 的 Firefox probe 返回：`ls`/`head` 读取
  `/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw` 均 `Permission denied`，
  `FIREFOX_TRACEFS_RAW_READ_STATUS=1`，UID 10270，context
  `u:r:untrusted_app:s0:c14,c257,c512,c768`；JS bridge 本身正常完成（`[+] DONE`）。
- 截图证据：`analysis_outputs/firefox-tracefs-probe-live-20260718-index.png`，
  SHA-256=`2FD7AD03AD996AEBBE5F0E8FC9C701192F3865067C0518439E15D8597B3C6DAB`。
  boot_id、`enable`、`tracing_on` 未变化；app-domain oracle 门禁仍关闭。

## 2026-07-18 pselect-layout-only 纯用户态在线探针

- 使用正确父入口 `index.html?payload=pselect-layout-only` 运行
  `PSELECT_LAYOUT_ONLY_PROBE=1` 构建的诊断；源码路径为
  `exploit-repo/IonStack/CVE-2026-43499/exploit/src/main.c`，该分支只构造本地
  `fd_set` 并在 `PSELECT_LAYOUT_DONE` 前返回，不调用 `pselect()`/UAF 路由。
- 当前设备日志返回 `PSELECT_LAYOUT_DONE: ok=1 no_kernel_route=1`，并记录了
  `IN/OUT/EX` word 映射；日志归档为
  `analysis_outputs/pselect-layout-only-live-crash-20260718.txt`。
- boot_id 未变化，trace 状态未改变。该结果只闭合用户态 word mapping 和页面
  bridge，不升级为 kernel write 或 exploit 成功证据。

## 2026-07-18 pselect 栈方程与 live layout 交叉核验

- live `PSELECT_LAYOUT_ONLY_PROBE` 的 `IN/OUT/EX` word 输出与
  `prepare_pselect_fdsets()` 本地构造一致，确认 target/value/fake task/fake
  lock 的用户态排列没有实现层偏差。
- 该 probe 在 `PSELECT_LAYOUT_DONE` 前不调用 `pselect()`，因此没有验证 kernel
  fd-set copy，更没有验证 stale `waiter->lock` 指针等于用户锁 VA。
- 同 build 离线方程仍为：pselect copy 在 `Q0+0x80/+0x88/+0x90`，stale lock
  在 `Q0+0xd8`；当前“用户 overlay → stale lock”指针等式未闭合。正式补充见
  `analysis_outputs/violin-poll-stack-uaf-static-model-20260718.md` §6。

## 2026-07-18 当前最优路线决策

- **停止投入**：继续调整 `pselect` `nfds`、fd_set value、word offset，或把
  外部仓库的 user-lock overlay 直接套到 Violin 默认 `poll()`；同 build 栈方程
  已证明 stale `waiter->lock` 与用户 fd-set copy 没有闭合指针等式。
- **首选下一阶段**：以当前 boot 的 shell-assisted canonical base 为输入，
  单独验证 `cfi-configfs-only` 下游阶段；只观察 `CFGPROBE`、configfs write/read
  readback、boot_id 和持久化 crash 证据，不运行完整 root/CFI 链，不把 errno 或
  页面 `DONE` 当作目标槽位写入。
- **硬门禁**：测试前重新确认 boot_id 与 fresh `_text`；记录 artifact SHA-256；
  必须有目标 readback 或持久化 oops 才能判定写入；若仅得到 transport errno、
  reboot 或 `command_status=0`，结论只能是“下游阶段未证实”。
- **若该隔离阶段仍不能给出 readback**：当前 GhostLock/Violin fops 路线应标记
  为 blocked，转向离线评估其他已确认 vulnerable surface，而不是继续随机变更
  pselect/poll 布局。

## 2026-07-18 Dijun 同芯片工厂包选择性审计

- 对 `XIAOMI 15S Pro_KeepNV_dijun_factory_images_FACTORY-DIJUN_20250516.0.VODCNDM_15.0.tgz` 做只读选择性提取，包 SHA-256 为 `13FE90D0E25CED73424F3281626F0F570A7D8A9E39E75E363BA0685019BA1C40`；未刷机、未修改设备、未运行 payload。
- 选择性提取目录：`analysis_outputs/dijun-selective-20260718`；保留 boot/vendor_boot/init_boot/dtbo/vbmeta/GPT/sec_fdt_all 等小范围证据，未提取 `super.img`/`userdata.img`。
- Dijun `boot.img` 与现有 Violin boot 候选均为 Android Boot Image v4，外层 kernel payload 都以 `4d5a40fa` 开头，但大小分别为 36,039,168 与 36,456,960 字节、SHA-256 不同；这是 XRing 特有内层容器，现有脚本不能直接解包。
- Dijun payload 包含 `Linux version 6.6.30-android15-8-g8eff17a54aa9-abogki407711482-4k`，与 Violin 运行态 6.6.77 不同。因此 Dijun 只能作为同 SoC 启动链/DTB/分区/安全固件比较基线，不能直接迁移 Violin 的 KASLR、符号偏移、结构体布局或 exploit 偏移。
- 正式审计记录：`analysis_outputs/dijun-factory-selective-audit-20260718.md`。
- 后续只读解析补充：`init_boot.img` v4 的 2,507,126 字节 LZ4 ramdisk 可解压约 4.67 MiB；`vendor_boot.img` 首个 vendor ramdisk fragment 可由 `02 21 4c 18` 解压约 61.2 MiB，包含 `lib/modules/6.6.30-android15-8-4k/`、`xiaomi_touch_dijun.ko` 及多项 XRing/Xiaomi 模块。`dtbo.img` 为 8-entry 标准 DTBO，三个 vbmeta 均有 `AVB0` 头。
- 因此最优离线路线从“泛化找偏移”收敛为：先做 DTBO 八个 entry、vendor ramdisk 模块清单与 Violin 的差分；若 ABI/版本不一致则只保留比较结论，不迁移地址或 exploit 逻辑。
- 详细索引已落盘：`analysis_outputs/dijun-vendorboot-first-fragment-20260718.txt`（首个 CPIO 片段 79 entries，含 Dijun/XRing `.ko` 路径）和 `analysis_outputs/dijun-dtbo-index-20260718.txt`（8 个 DTBO entry 的大小、offset、id）。
- 已完成 Dijun 工厂包与现有 Violin OTA 分区的只读 boot 差分：两边 vendor_boot 首个 CPIO 分别解析出 34/39 个 `.ko`，同路径 31 个，但 31 个模块的大小或 SHA-256 全部不同；Dijun 独有 `xiaomi_touch_dijun.ko`/Synaptics 路线，Violin 独有 `xiaomi_touch_violin.ko`/键盘/hall/mi_power/io_monitor 路线。
- 两边 DTBO entry ID 集合相同（8 个），但每个 entry 的 size/offset 均不同，不能按 offset 迁移。详细差分：`analysis_outputs/dijun-violin-boot-diff-20260718.md`。
- 结论进一步收敛：Dijun 只保留同平台 ABI、设备树节点和启动链比较价值，不支持复用 Violin 的内核地址、模块地址、结构体布局或 exploit 参数。
## 2026-07-18 Dijun 包内工具兼容性

- 从工厂包选择性提取 `adb.exe`、`fastboot.exe`、`fdt-cli-v6.2.0(.exe)` 并仅运行版本/帮助查询；未连接设备执行写操作。
- `adb.exe`=`1.0.41 / 35.0.1-eng.jiangd.20240613.201152`，`fastboot.exe`=`35.0.2-eng.jiangd.00000000.000000`，可作为主机侧通用客户端用于查询和证据采集。
- `fdt-cli v6.2.0` 明确面向 FDT/BootROM/串口下载，加载 Dijun `sec_fdt_all.xml`；不能把该 XML/secure firmware 用于 Violin。
- 兼容性报告：`analysis_outputs/dijun-tools-compatibility-audit-20260718.md`。
## 2026-07-18 Dijun 工具只读联机可见性测试

- 使用 Dijun 包内 `adb.exe` 执行 `adb devices -l`：无 online adb 设备，因此未执行任何 shell 查询。
- 使用 Dijun `fdt-cli-v6.2.0.exe --list`：`connected serial ports:` 和 `connected fastboot devices:` 均为空，说明当前主机没有可供 FDT/fastboot 识别的端口。
- 系统 PATH 下的 `adb.cmd devices -l` 同样为空。
- 本次仅做设备枚举，没有运行 `-path`、`--load-ufs-para`、`flash`、`erase` 或任何写入操作；同 SoC 不能替代产品、分区和 secure firmware 匹配。

## 2026-07-18 Dijun / Violin DTBO 与公共 XRing 模块差分完成

- 设备当前已断开；本轮只读解析本地 DTBO/vendor ramdisk，未联机、未刷写、未安装或运行 payload/module。
- 八个 DTBO entry 的 ID 集合相同；Violin O81A PAD 对应 entry 7 (`0x09020101`)。归一化 `fragment@N` 后，entry 7 有 871 个新增键、151 个删除键和 1893 个值变化；面板命令/时序、GPIO/pinctrl、sensor phandle/fixup 均非同一配置。DTBO entry 不提供可直接复用的最终 `reserved-memory` 物理布局。
- 同路径公共模块 31 个，全部 ELF64 AArch64，但大小/SHA-256 全部不同；Dijun vermagic `6.6.30-android15-8-4k`，Violin `6.6.77-android15-8-4k`。canonical CPIO 复核后，定义符号集合差异仅剩 `minet.ko`（1/31）；9 个模块出现 `__export_symbol_` 字符串差异。旧 `xring_smartpa.ko` 解析记录已在后续错误审计中撤销。
- 详细报告：`analysis_outputs/dtbo-node-diff-20260718.md`、`analysis_outputs/module-interface-summary-20260718.md`；原始索引/审计：`analysis_outputs/dtbo-diff-20260718/`、`analysis_outputs/module-diff-20260718/`。
- 稳定结论：Dijun 工程包只能作同 SoC 功能/接口参考，不能移植 Violin DTBO、`.ko`、地址、偏移、结构体布局或 exploit 参数。

## 2026-07-18 Violin base DTB × DTBO entry 7 离线引用对账

- 解析 Violin `vendor_boot.img.dtb`：941 个节点、5466 个属性、592 个 `__symbols__` 标签；`/chosen` 的现有 bootargs 保持不变，`/reserved-memory` 有 46 个子节点。
- entry 7 共 106 个 fragment、113 个 `__fixups__` 标签；全部 fixup label 都能解析到该 base DTB，且目标路径存在。`chosen` 闭合到 `/chosen`，overlay 只增加 `bootargs_ext` 空格。
- 关键 memory-region 引用已闭合：`memdump_reserve`→`rsv_mem_log@43480000`（0x232）、`perf`→disabled `rsv_mem_perf`（0x243）、`wifi_mem`→`rsv_mem_wifi_reserve`（0x245）、`wifi_page_pool_mem`→`rsv_mem_wifi_page_pool`（0x246）。DTBO 内的 `0xffffffff` 只是待 fixup placeholder，不能直接当物理地址。
- 报告：`analysis_outputs/violin-base-dtb-entry7-audit-20260718.md`。本轮仍未生成可刷写 merged DTB、未联机、未刷写、未运行 payload。

## 2026-07-18 Violin entry 7 有效节点语义投影

- 使用 `tools/project_dtbo_overlay.py` 对 Violin base DTB + entry 7 做内存语义投影；不生成二进制 merged DTB，不联机、不刷写、不运行 payload。
- 106 个 fragment、113 个 fixup label、237 个 fixup location 全部解析成功；新增 2520 个节点、8711 个属性，覆盖 252 个 base 属性。
- 有效值已核对：`/chosen` 保留原 bootargs 并增加 `bootargs_ext`；O81A panel 为 4095 brightness、non-continuous、idle `0x2002`、lowpower `0x9d`、reset `[1,1,0,3,1,10]`、HS command；hall lid/table pin 为 4/10；keyboard default 为 GPIO 050/056，LS enable 为 GPIO 088。
- 报告：`analysis_outputs/violin-entry7-effective-projection-20260718.md`；JSON：`analysis_outputs/violin-base-dtb-entry7-projection-20260718.json`。

## 2026-07-18 Dijun / Violin entry 7 最终有效树对比

- 从 Dijun `vendor_boot.img` 的 v4 布局提取 base DTB（offset `0x1584000`、size `182478`），并使用与 Violin 相同的投影器复算 entry 7。
- Dijun 97 fragments/112 labels/219 locations 全部成功；Violin 106/113/237 全部成功。Dijun 最终 panel 为 2047 brightness、continuous、LP command、reset `[1,1,0,1,1,10]`；Violin 为 4095、non-continuous、HS command、reset `[1,1,0,3,1,10]`。
- Dijun 不存在 Violin 的 `/xiaomi_hall` 子树，keyboard GPIO 及 panel supply/GPIO phandle 不同；reserved-memory 范围近似但 phandle 不同，不能跨 build 复制。
- 报告：`analysis_outputs/dijun-violin-effective-entry7-diff-20260718.md`；Dijun DTB：`analysis_outputs/dijun-selective-20260718/images/vendor_boot_dtb_extracted.dtb`。

## 2026-07-18 既有 DTBO/模块分析错误审计与修正

- 复核 `project_dtbo_overlay.py` 时发现第一版 local phandle delta 写成 `max(base phandle)+1`；按 libfdt 应使用 `fdt_find_max_phandle(base)` 返回的最大值本身。已修正为 Dijun `596`、Violin `592`，并重跑两边 projection JSON；`__local_fixups__` location 分别为 394/409。
- 这项错误只污染此前 overlay-local phandle 的隐藏值；external symbol fixup、fragment/节点统计，以及 entry 7 面板时序、command mode、keyboard/hall 高层差异不变。旧临时 JSON 不再作为证据。
- 复核 Violin vendor ramdisk 原始 LZ4+CPIO 后，确认 `xring_smartpa.ko` 原始路径 SHA 为 `ca519d3b...`，而 module-diff 目录副本为 `bed0dc8f...`，是提取/复制产物错误，不是设备模块本身。canonical 对账后两边均有 294 个定义符号和 `depends=miev`，旧“Violin 0 symbols”结论撤销；符号差异汇总由 2/31 改为 1/31。
- 已更新 `module-interface-summary-20260718.md`、逐模块报告、manifest，并落盘 `analysis_outputs/module-diff-20260718/module-interface-correction-20260718.json`；错误副本保留为 `.invalid-extraction-20260718`。本轮继续只读，未联机、未刷写、未安装/加载模块、未运行 payload。

## 2026-07-19 Violin 重新联机只读基线

- ADB 已确认 serial `03035440C1781540`，设备 `violin/25053RP5CC`，Android 16，build `OS3.0.303.0.WOTCNXM`，kernel `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`。
- 当前 `boot_id=c79163bc-d9f5-457a-a30f-0362d89db8ea`，与 2026-07-18 基线一致；slot `_a`、verified boot `green`、flash locked=1。
- shell 仍为 uid 2000、`u:r:shell:s0`、含 `readtracefs`，SELinux Enforcing。`sched_blocked_reason` ID=109，caller offset=16/size=8；tracefs 当前已有 `enable=1`、`tracing_on=1`，本轮没有写状态。
- CPU0 stats 当前 `entries=39865`、`overrun=20238231`、`bytes=1441280`、`dropped events=0`。`per_cpu/cpu0/trace_pipe_raw` 可读，但本轮未读取，避免无明确授权地消费 ring buffer。
- 证据：`analysis_outputs/violin-device-connected-baseline-20260719.md` 及同名 `.txt`。下一步如需新 canonical record，必须单独做有界 raw 读取并记录消费副作用；旧 `_text` 地址不可跨 boot 复用。

## 2026-07-19 Violin 当前 boot sched_blocked_reason 有界 raw 对账

- 在记录 boot_id/CPU0 stats 后，从 `per_cpu/cpu0/trace_pipe_raw` 读取 64 KiB；raw SHA-256=`3D02D87142BA7AABF260FC938903CBDB83DAAA59F8DD96B8BD017C243692272C`，boot_id 仍为 `c79163bc-d9f5-457a-a30f-0362d89db8ea`。
- event ID=109，解析到 92 个唯一合法记录；精确命中 `caller=0xffffffd6928d797c` 共 14 条。按同 build `worker_thread-_text=0xd78e0`、caller=`worker_thread+0x9c`，得到当前 `_text=0xffffffd692800000`。
- 读取会消费 ring：CPU0 `entries 39825→38120`、`read events 6003→7811`；`enable=1`、`tracing_on=1` 前后未改变。两个错误命令产物已保留并标记，不纳入证据。
- 该结果仅证明 shell/readtracefs 域的当前 boot canonical record；不扩展 Firefox/app 权限，不证明 arbitrary write、fops/CFI 或 payload 链。证据：`analysis_outputs/violin-device-sched-blocked-raw-20260719.bin`、同名 `.md`、`*-raw-parse-20260719.txt`。

## 2026-07-19 Firefox/app 域 tracefs 权限复核

- 当前 `org.mozilla.firefox` PID `15438` 为 UID/GID `10270`，SELinux `u:r:untrusted_app:s0:c14,c257,c512,c768`，groups=`3003 9997 20270 50270 99909997`，不含 `readtracefs(3012)`，CapEff=0。
- `per_cpu/cpu0/trace_pipe_raw` 为 `0440 root:readtracefs`；因此 shell/readtracefs 的 canonical record 不能直接转移到 Firefox UID。`enable` 文件的 `0666` 不代表 app 能读 raw ring。
- `run-as org.mozilla.firefox` 仅返回 `package not debuggable`，未改变 app 状态。证据：`analysis_outputs/violin-firefox-tracefs-access-check-20260719.md`。

## 2026-07-19 Violin 字符设备只读清单

- 在同一在线 boot `c79163bc-d9f5-457a-a30f-0362d89db8ea` 上仅执行设备节点 metadata 清单：`id`、build/kernel、`ls -lZ`、过滤后的 `/dev`、`/proc/devices`；没有 `open`、`read`、`ioctl`、`write`、模块加载或 trace 状态修改。
- DAC 可见候选：`/dev/ashmem`、`/dev/mali0`、`/dev/camlog`、`/dev/hpc-rpmsg` 均为 `0666`，但 SELinux 类型分别为 `ashmem_device`、`gpu_device`、`camlog_device`、`npu_device`；这不等于 `untrusted_app` 可访问。
- `/dev/xring_*`/`xring_vpu_*` 为 `0660` 且受 `audio`/`camera` 组限制；`hpc-cdev`、`hpc-heap`、`hpc-mitee-crypto`、`ocm-buf` 与 `xring_*` dma-heap 主要为只读模式。未把权限元数据误判为可用 primitive。
- `/dev/mali0` 延续既有静态排除：`open()` 有固件/context 初始化，不作为 passive oracle；`camlog`、`hpc-rpmsg` 需先做 ABI/SELinux 静态审计，不能盲开节点。
- 证据：`analysis_outputs/violin-device-char-device-inventory-20260719.txt`、`analysis_outputs/violin-device-char-device-inventory-20260719.md`。下一步只做 `/dev/ashmem`、`/dev/camlog`、`/dev/hpc-rpmsg` 的离线 ABI/SELinux 对账，保持不运行 payload。

## 2026-07-19 `/dev/ashmem` 离线 ABI 审计

- 依据 matching GKI `ashmem.c`/UAPI 与 same-build `kallsyms.txt` 完成离线审计；设备节点未 open，未发 ioctl、mmap、read/write，未运行 payload。
- `ashmem_fops`、`ashmem_misc` 在 kallsyms 中均为 `d` 静态数据；源码明确 `ashmem_misc.fops=&ashmem_fops`。这只说明结构体/指针槽的静态布局，不能把它当作用户态指针输出。
- `open()` 分配 `struct ashmem_area` 并写 `file->private_data`；`mmap()` 创建 backing shmem 并修改 backing file fops。`GET_SIZE`/`GET_PROT_MASK`/`GET_PIN_STATUS` 是标量，`GET_NAME` 是有界字符串，`GET_FILE_ID` 仅返回 `i_ino`，没有 canonical kernel pointer；PIN/UNPIN/PURGE 是有状态操作。
- 结论：即使 `/dev/ashmem` DAC 为 `0666`，也不是 passive canonical-pointer leak 或通用写原语；Firefox `untrusted_app` 的 SELinux allow 仍未建立。报告：`analysis_outputs/ashmem-static-abi-audit-20260719.md`。

## 2026-07-19 当前 boot SELinux 节点权限对账

- 只读拉取当前 boot 的 `/system/etc/selinux/plat_sepolicy.cil`、`/vendor/etc/selinux/vendor_sepolicy.cil` 及 file_contexts；未打开任何设备节点，未发 ioctl/read/write。
- file_contexts 确认：`ashmem_device`/`ashmem_libcutils_device`、`camlog_device`、`npu_device`、`gpu_device`、`video_device` 与 XRing dma-heap 类型分别对应清单中的节点。
- 平台/厂商 CIL 没有直接的 `allow untrusted_app` 到 `camlog_device`、`npu_device`、`gpu_device`、`video_device` 或 XRing dma-heap；ashmem 只有属性规则与不匹配当前 Firefox 域的 `untrusted_app_25` 显式规则，不能把 DAC `0666` 当成 app 可达。
- 结论：当前 tracefs shell-only gate 之外，字符设备 app-domain gate 也未闭合；继续工作应做离线 CIL 属性解析/载体分析，不能用盲 open、ioctl 扫描或新 payload 代替权限证据。报告：`analysis_outputs/violin-live-sepolicy-device-node-audit-20260719.md`，原始拉取目录：`analysis_outputs/sepolicy-live-20260719/`。

## 2026-07-19 Dijun 工具包联机只读测试

- 使用 Dijun 包内 `platform-tools/adb.exe` 完成 `version`、`devices -l` 和只读 `getprop`：可识别当前 Violin `03035440C1781540`，设备/型号 `violin/25053RP5CC`，build `OS3.0.303.0.WOTCNXM`，slot `_a`，verified boot `green`。
- 使用包内 `fastboot.exe --version/devices`：客户端可运行，版本 `35.0.2-eng.jiangd.00000000.000000`；因设备仍在 Android/ADB 模式，fastboot 设备列表为空。
- 使用 `fdt-cli-v6.2.0.exe --help/--version/--list`：FDT v6.2.0 可运行，列表中 serial/fastboot 均为空；其内置 fastboot 为 `33.0.1-eng.jiangd.20230620.180441`。未传入 `sec_fdt_all.xml`、`-path`、`--load-ufs-para` 或 `--wait-for-com`。
- `FDTv6.2.0.exe.bat` 仅做静态读取，确认它会递归选择第一个 `fdt-cli*.exe` 后启动；未执行脚本。
- 结论：Dijun 包的通用 ADB/Fastboot 客户端可用于只读查询；FDT 主程序能启动但没有当前传输端口，不能据此证明 Dijun 刷写链适用于 Violin。证据：`analysis_outputs/dijun-tools-live-test-20260719.txt`、`analysis_outputs/dijun-tools-live-test-20260719.md`。

## 2026-07-19 SELinux CIL 属性解析纠错与最终权限结论

- 对当前 boot 的 `plat_sepolicy.cil`/`vendor_sepolicy.cil` 做了离线 S-expression 解析，展开 `typeattributeset` 的 `and/or/not`，再将 `allow/neverallow/dontaudit` 投影到 Firefox 实际主体 `untrusted_app`；解析器：`tools/parse_cil_permissions.py`。
- 纠正此前“没有直接 `allow untrusted_app` 即不可达”的不完整结论：`untrusted_app` 属于 `base_typeattr_257`，因此对实际标记为 `gpu_device` 的 `/dev/mali0` 有 `chr_file open/read/write/ioctl/map`；对 `dmabuf_system_heap_device`（`xring_cpa`、`xring_heap_drm`、`xring_isp_faceid`）有 `open/read/ioctl/map`，无 write。
- `/dev/ashmem` 的实际类型 `ashmem_device` 没有 `chr_file open`，并被 `base_typeattr_452` 的 `neverallow open` 阻断；但 boot-created `/dev/ashmem<boot_id>` 的 `ashmem_libcutils_device` 有 open/read/write/ioctl。两者都仍是有状态 ashmem ABI，未变成 pointer leak。
- `dmabuf_heap_device` 的 XRing 普通 heap 无字符设备 allow；`camlog_device`、`npu_device`、`hpc_aon_device`、`video_device`、`xring_audio_tool_device` 未解析到 app-domain 字符设备 allow，video 还有 `base_typeattr_272` 的 read/write `neverallow`。
- 因此上一份 `violin-live-sepolicy-device-node-audit-20260719.md` 的直接文本结论已标记 superseded；哈希路径映射也已纠正。最终报告：`analysis_outputs/violin-live-sepolicy-cil-resolution-20260719.md`，JSON：`analysis_outputs/violin-live-sepolicy-cil-resolution-20260719.json`。
- 权限修正不改变接口边界：mali0、DMA heap、ashmem alias 都是有状态接口，不能据此执行盲 open/ioctl 或新 payload；本轮仍未访问设备节点。

## 2026-07-19 XRing `xr_*` 节点补充审计

- 复核 file_contexts 后发现初始 `/dev` 清单过滤器漏掉了非 `xring_*` 命名的 XRing 节点；本轮仅做 metadata：`/dev/xr_dmabuf_helper`、`/dev/xr_meminfo`、`/dev/xr_cpnv`、`/dev/xr_cpufreq_qos`、`/dev/xr_perf_actuator`、`/dev/xr_compitable_enhance`，没有 open/read/ioctl/write。
- `/dev/xr_dmabuf_helper` 为 `0444 system:system`、类型 `xr_dmabuf_helper`；离线 CIL 解析没有 `untrusted_app` 的有效规则。匹配 `xr_heaps.ko` 的 `xr_dmabuf_helper_ioctl@0xd410` 接受 `0xc0305800..0xc0305806`，涉及 0x30-byte copy、dma_buf get/put、CPU/heap callback 与状态操作，不是 passive pointer query。
- `/dev/xr_meminfo` 同为只读但无 app CIL allow；`xr_cpnv`/`xr_cpufreq_qos` 为 root-only；`xr_perf_actuator` 为 root:system 0660；`xr_compitable_enhance` 无 app CIL allow。
- 初始 `violin-device-char-device-inventory-20260719.md` 的 `xr_*` 覆盖标记为 superseded，由 `analysis_outputs/violin-device-xr-node-metadata-20260719.txt`、`analysis_outputs/xr-dmabuf-helper-static-audit-20260719.md` 与 extra CIL JSON 补充。未访问节点，设备状态未改变。

## 2026-07-19 XRing system DMA-heap 离线 ABI 审计

- CIL 解析确认 `untrusted_app` 通过 `base_typeattr_257` 可访问 `dmabuf_system_heap_device`：`xring_cpa`、`xring_heap_drm`、`xring_isp_faceid` 具备 `open/read/ioctl/map`，无 write；普通 `dmabuf_heap_device` XRing heap 没有 app 字符设备 allow。
- matching GKI `dma-heap.c`/UAPI 只有 `DMA_HEAP_IOCTL_ALLOC`，24-byte 结构是 `len/fd/fd_flags/heap_flags`，返回整数 fd，不含 pointer-sized 字段；open 只把 heap 对象放入 `file->private_data`，ioctl 进入分配路径。
- matching `xr_heaps.ko` 的 `xr_cpa_heap_allocate@0xb1f4` 会分配 `0xdc0`-byte per-request state、锁 heap accounting、走 CMA/page-pool 分配和计数更新；这是有状态 allocator，不是 passive canonical leak。
- 本轮未打开任何 dma_heap、未分配/映射 buffer、未发 ioctl。报告：`analysis_outputs/xring-dma-heap-static-abi-audit-20260719.md`。

## 2026-07-19 `untrusted_app` 字符设备 CIL 穷举闭包

- 新增 `tools/enumerate_untrusted_app_char_devices.py`，对当前 boot 的 `plat_sepolicy.cil`、`vendor_sepolicy.cil` 做 `typeattributeset` 展开，并与两份 `/dev` file_contexts 合并；结果共 37 个带 `chr_file` 投影的 `/dev` 类型。
- 闭包没有新增 XRing 专用字符节点 app 入口。与当前研究链相关的 app 可达类型仍是 `gpu_device`（`/dev/mali0`）、`dmabuf_system_heap_device`（`xring_cpa`/`xring_heap_drm`/`xring_isp_faceid`）及 boot-created `ashmem_libcutils_device`；`/dev/ashmem` 的 `ashmem_device` 仍缺 `open` 并命中 `neverallow`。
- `/dev/camlog`、`/dev/hpc-rpmsg`/`npu_device`、`xr_*` helper 等没有 `untrusted_app` 字符设备投影；DAC 模式不构成 SELinux allow。报告：`analysis_outputs/violin-untrusted-app-char-device-closure-20260719.md`；JSON/原始文本同前缀。
- 该工具输出的是 raw allow/neverallow 投影，不替代策略编译器；本轮仍未打开节点、发 ioctl/read/write、改变 trace 状态或运行 payload。

## 2026-07-19 当前 boot 候选节点标签复核

- 对 `/dev/ashmem`、`/dev/ashmem<boot_id>`、`/dev/mali0` 及三个 XRing system dma-heap 仅执行 `ls -ldZ`；现场标签与离线 CIL 闭包完全一致。
- 关键修正：当前 `c79163bc-d9f5-457a-a30f-0362d89db8ea` 对应的 `/dev/ashmemc79163bc-d9f5-457a-a30f-0362d89db8ea` 是 `ashmem_libcutils_device`，而精确 `/dev/ashmem` 是 `ashmem_device`，不能混合分析。原始记录：`analysis_outputs/violin-live-cil-candidate-label-check-20260719.txt`；报告：同名 `.md`。
- 本轮没有打开节点、发 ioctl/read/write/mmap、改变 trace 状态或运行 payload。

## 2026-07-19 DMA heap 现场目录标签补充

- metadata-only `ls -lZ /dev/dma_heap` 确认 `system`、`system-uncached` 与 `xring_cpa`、`xring_heap_drm`、`xring_isp_faceid` 都是 `dmabuf_system_heap_device`；`xring_npu_dym`/`xring_tui_display`/`xring_tui_font` 是普通 `dmabuf_heap_device`。
- 因此 CIL 闭包的 app 可达 system-heap 集合应写成 5 个节点（两个 generic + 三个 XRing），但 ABI 结论不变：只有 stateful `DMA_HEAP_IOCTL_ALLOC`，不产生 passive canonical leak。原始记录：`analysis_outputs/violin-live-dma-heap-directory-metadata-20260719.txt`。
- 本轮未打开 dma_heap、未分配/映射 buffer、未发 ioctl/read/write，也未改变 trace 状态。

## 2026-07-19 tracefs `untrusted_app` CIL gate 闭合

- 用 `tools/parse_cil_permissions.py` 对 `debugfs_tracing`、`debugfs_tracing_debug`、`debugfs_trace_marker` 做属性展开；`plat_sepolicy.cil:329` 确认 `sched_blocked_reason` 归属 `debugfs_tracing`。
- `plat_sepolicy.cil:30609` 对 `untrusted_app_all -> debugfs_tracing` 的 file `neverallow` 覆盖 `open/read/write/ioctl` 等；`untrusted_app` 属于该属性。`domain -> debugfs_tracing` 仅有目录 `search`（`:14057`），不能推导文件读写。
- 因而 Firefox app 域的 tracefs gate 同时在 raw 读取和 event enable 写入两侧闭合；`dontaudit`（`:30648`）还会隐藏部分拒绝日志。报告：`analysis_outputs/violin-live-tracefs-cil-gate-20260719.md`，JSON/文本为 `violin-live-sepolicy-tracefs-resolution-20260719.*`。
- 最优路线改为确认是否存在既有 privileged/readtracefs broker；没有 broker 时冻结 app-domain tracefs 方案，不再扩大字符设备搜索。

## 2026-07-19 52pojie OnePlus GhostLock 文章复核

- 重新抓取并核对文章首帖：目标是 OnePlus 13T / Android 16 / kernel 6.6.89；首帖正文与 2026-07-14 抓取一致。作者明确记录完整链在 `slide_leak_kernel_base()` 因 UBSAN array-bounds/BRK/mrdump 重启，未完成 KASLR leak、fops、root。
- 文章对 Violin 的真正价值是 hardening/隐性 ABI 适配方法，以及 `ashmem_misc.fops` 指针槽语义；OnePlus 绝对地址、`PSELECT_WAITER_WORD_SHIFT=1`、KernelSnitch 候选不能迁移。
- Violin config 同样启用 UBSAN_TRAP/ARRAY_BOUNDS、PANIC_ON_OOPS、BUG_ON_DATA_CORRUPTION、CFI、KASLR；这与既有 `SLIDEC3` 崩溃相互印证，但不证明每个厂商 crash 分支相同。
- 详细对照：`analysis_outputs/52pojie-oneplus-ghostlock-violin-comparison-20260719.md`；本轮未构建、安装或运行文章 payload。

## 2026-07-19 `readtracefs` 进程主体验证

- metadata-only 扫描 `/proc/*/status` + `/proc/*/attr/current`，发现当前 boot 除 shell/adbd 外还有 `traced_probes`、`system_server`、`gpuservice`、`hal_camera_default`、`mobile_log_d` 持有 GID 3012。
- `traced_probes`（PID 1687）是唯一值得优先离线审计的 trace 相关 broker；其存在不证明 Firefox 可调用，也不证明会返回 `sched_blocked_reason` caller。
- 原始记录：`analysis_outputs/violin-readtracefs-principal-inventory-20260719.txt`；报告：同名 `.md`。未访问 tracefs、未执行 Binder transaction、未运行 payload。

## 2026-07-19 Perfetto/trace broker CIL 审计

- 离线投影确认 `appdomain` 可对 `traced` 执行 `unix_stream_socket connectto`，并可写 `traced_producer_socket`（`plat_sepolicy.cil:9456-9459`）；但没有 `traced_consumer_socket` allow，也没有 `perfetto_traces_data_file` 读取 allow。
- 因而这是 producer-side 入口，不是把 `sched_blocked_reason` raw/caller 返回给 Firefox 的 consumer relay；不能直接对 socket 发请求验证。
- 报告：`analysis_outputs/violin-trace-broker-cil-audit-20260719.md`。当前最优路径改为离线检查同 build Perfetto source/config 是否存在 app consumer relay；没有则冻结 Firefox tracefs 路线。
- 相关机器输出：`analysis_outputs/violin-trace-broker-cil-resolution-20260719.json` / `.txt`，共 20 条投影规则；补充覆盖 `traced_perf`/`traced_perf_socket`，但其 init 注释表明是 `/proc`/perf profiler，不是 ftrace consumer。
- `perfetto.rc` metadata-only 复核确认 `traced` 的 `traced_consumer`/`traced_producer` socket 均为独立对象且 DAC 0666；原始记录：`analysis_outputs/violin-perfetto-rc-metadata-20260719.txt`。SELinux consumer gate 仍未打开。
- `traced_relay` 仅做 producer 到 VM/host 的转发，与 `traced` 互斥；不是可供 Firefox 读取 event 的 relay。至此同 build Perfetto consumer-relay 检查闭合：Firefox tracefs oracle 路线冻结。
- 当前 boot metadata-only 状态：`persist.traced.enable=1`，`traced=running`、`traced_probes=running`，`traced_relay=stopped`、`traced_perf=stopped`；只有 `traced_consumer`/`traced_producer` socket 存在。证据：`analysis_outputs/violin-perfetto-live-state-20260719.txt`。

## 2026-07-19 52pojie 对照后的 Violin target baseline 复核

- 以 same-build rooted `kallsyms.txt`、`iomem.txt` 和 `target.h` 做只读基线核验；修正 `tools/audit_violin_kernel_baseline.py` 对 `/* symbol: name (annotation) */` 的解析，避免静默漏检带附加注释的符号宏。
- 复核共覆盖 27 个 symbol offset 与 `P0_PHYS_OFFSET`/`P0_KERNEL_PHYS_LOAD`，结果 `ok=true`、`mismatches=0`。此前漏检的 `ashmem_misc` 与 `sysctl_bootid` 现已显式通过：`0x223b5d8`、`0x2336f58`。
- 证据：`analysis_outputs/violin-target-baseline-audit-20260719.json`（SHA-256 `01D8DED9C7BC3A70490F4A09295876008D24D378F755B8F934956492E62F5DA6`）。脚本已通过 `python -m py_compile`。
- 结论：文章里的跨设备地址/shift 仍不可迁移；Violin 自身相对基线现在闭合，但 canonical base、stale waiter 消费和 app-domain broker 仍未闭合。本轮未联机写节点、未运行 payload。

## 2026-07-19 Violin ashmem fops 目标槽代码审计与修正

- 在 same-build offset baseline 核验后复查 active common source，确认 `src/util.c`、`src/main.c` 仍有把 `ASHMEM_MISC_FOPS`（静态 `struct file_operations`）当成可写/readback 槽位的旧引用；正确目标是 `data_addr(ASHMEM_MISC) + 0x10`，rb-tree parent/color 地址是该槽位减 `0x08`。
- 已修正 `src/util.c` 默认 pselect 写目标、FOPS fake parent、write_left 及注释；修正 `src/main.c` cfgprobe pre-hijack readback；`src/fops.c` 日志改为明确记录 `misc_fops_slot`。未改历史 `.bak-*` 或其他设备 target 目录。
- 语法验证通过：WSL `/usr/bin/clang -fsyntax-only` 对 `src/util.c`、`src/fops.c`、`src/main.c`、`src/slide.c` 全部通过。
- 审计报告：`analysis_outputs/violin-fops-target-slot-audit-20260719.md`。
- 该修正不等于 primitive/root 成功；本轮没有构建/安装/联机运行 payload，也没有访问设备节点或发 ioctl/read/write。

## 2026-07-19 active route selection 图谱审计

- 刷新 `codebase-memory-mcp` exploit 子仓库索引后，沿 `do_pselect_fake_lock_route()`、`prepare_pselect_fdsets()`、`prepare_skb_payload()` 和 `try_direct_configfs_kaslr_probe()` 做静态调用/分支复核。
- 确认 Violin 正常 `Makefile` 构建只传 `TARGET_CONFIG_H`，shared `src/fops.c` 的 `ROUTE_*`/`DIRECT_WRITE_*` 默认均为 0；默认执行 `poll((struct pollfd *)pselect_user_lock, 1, ...)`，不调用 `prepare_pselect_fdsets()`。
- 当前 active `common.h` 是 `PSELECT_ROUTE_NFDS=64`；历史 `nfds=320/words_per_set=5` 运行记录属于旧 binary/source snapshot，不能与当前路线混用。
- 结论：上一轮 fops 目标槽修正是必要条件但不是 route 成功证据。最优下一步是离线二选一：重建 Violin poll 栈帧，或显式 pselect 模型逐字节闭合；本轮不构建、不安装、不联机运行。
- 报告：`analysis_outputs/violin-active-route-selection-audit-20260719.md`。

## 2026-07-19 默认 poll 路由闭合审计

- 用 same-build `boot.img.kernel` 完成 PE `.text` 映射校验，并反汇编 `__arm64_sys_poll`、`do_sys_poll`、`poll_initwait`；确认 kallsyms 相对 `_text` 与 raw file offset 一致。
- `do_sys_poll` 在 `P0+0x170` 对 `poll_wqueues` 做 `memset(...,0,0x270)`；当前源码传入的 `pollfd.fd=-1` 在同 build `0x3e1b3c` 跳过 `do_pollfd`，因此不执行 `poll_wait()`/`poll_get_entry()`，没有 inline entry 被用户字节填充。
- stale `rt_mutex_waiter->lock` 位于 `P0+0x308 = poll_wqueues+0x198 = inline_entries[5].wait.entry.next`，来源是清零后的 kernel inline 区，不是 `pselect_user_lock`。模型 A 已闭合为默认 route 不可达，不能继续调参数或目标地址。
- 报告：`analysis_outputs/violin-poll-route-closure-20260719.md`；本轮只读离线分析，未访问设备节点、未构建/安装/运行 payload。

## 2026-07-19 显式 pselect 映射闭合审计

- 通过 codebase-memory 图谱复核 active `prepare_pselect_fdsets()`：当前 `PSELECT_ROUTE_NFDS=64`、`words_per_set=1` 时，custom waiter word 2..13 中只有 word2 的 value 落在 `ex[0]`，`write_target`、`fake_lock` 等关键字段全部被丢弃；`shift=1` 时全部丢弃。
- 离线映射器给出完整 overlay 所需最小 `nfds=257`（`words_per_set=5`）。但 same-build `core_sys_select` 的 stale `waiter->lock=Q0+0xd8` 在 `words_per_set>=4` 时进入第三组 fd-set copy window，会被解释为 fd 位图，不能同时保持锁指针语义。
- 产物：`tools/audit_violin_pselect_mapping.py`、`analysis_outputs/violin-pselect-mapping-audit-20260719.json`、`analysis_outputs/violin-pselect-mapping-closure-20260719.md`；脚本 `py_compile` 通过。
- 补充审计 `src/slide.c`：`SLIDE_PSELECT_NFDS` 直接绑定当前 `64`，slide waiter word 0..13 中仅 word 0..2 进入三组 fd_set，`pi_parent`/`task`/`lock` 等关键字段丢弃；旧 slide `nfds=320` 记录与 active source 不同配置。
- 结论：默认 poll、显式 pselect 和 slide pselect 三条现有 route 都未闭合；本轮未访问设备、未构建/安装/运行 payload。

## 2026-07-19 pselect copy-window 双重语义复核

- 复核 `core_sys_select` 的 `Q0+0xd8` stale-lock slot 与三组 fd-set 窗口：`nfds=64` 不覆盖；`nfds=257/320` 时精确落在 `ex[1]`，与 custom waiter word 11 `fake_lock` 同槽。
- 更正上一轮“被当作 fd bitmask 就不能作为锁指针”的过强结论：同一 qword 可先被 `do_select()` 读作位图、后被 stale waiter 读作指针；active custom `open_selected_fds()` 也会为置位 fd 做 dup2，不能仅凭 EBADF 关闭候选。
- same-build `core_sys_select` 的六 bitmap 布局（`in/out/ex` + `res_in/res_out/res_ex`）进一步确认：W=5 时 `Q0+0xd8=ex[1]` 是 input bitmap，普通 return copy-back 不会自动清零；独立 `remove_waiter()` 字节级审计已确认 pre-fix 逻辑不会清 `waiter->task->pi_blocked_on`，dangling waiter 与 `EDEADLK -> ETIMEDOUT` 相容。剩余未闭合项收敛为 scheduler 消费时的 waiter 指针/分支与伪树到达。旧 `nfds=257/320` 仍仅是静态候选，不能据此改 active `nfds` 或运行 payload。
- `tools/audit_violin_pselect_mapping.py` 增加 stale-lock 窗口对账并重生成 `analysis_outputs/violin-pselect-mapping-audit-20260719.json`；报告 `analysis_outputs/violin-pselect-mapping-closure-20260719.md` 同步更正。仅离线分析。

## 2026-07-19 alternate syscall stale-lock 审计

- `ppoll`（wrapper `0x80`）复用同一 `do_sys_poll`，用户 `pollfd` 走动态 copy，不是新的栈 overlay。
- `select` 与 `pselect6` 共用 `core_sys_select` 但 wrapper frame 不同，stale slot 方程不同，不能直接套旧 pselect word map。
- `epoll_wait/pwait/pwait2` 的 stale slot 在 `schedule_hrtimeout_range` 实现中分别落在无 usercopy 局部、保存的内核 `x21` 指针、stack-canary；`set_user_sigmask` 只 copy 8-byte 到自身 frame，未发现用户可控 stale-lock 来源。
- 报告：`analysis_outputs/violin-alternate-waiter-lock-route-audit-20260719.md`。`do_select` input/result bitmap 与 dangling-lifetime 已有证据，下一步只做 pselect 高 nfds 的 scheduler waiter 指针/分支/伪树离线对账。

## 2026-07-19 `nfds` source-drift 更正

- `exploit-repo` HEAD `1a10c4e` 的 `src/common.h` 是 `PSELECT_ROUTE_NFDS=320`、`CONSUMER_MAX_CALLS=1`；当前未提交 worktree 改成 `64`/`200`。因此 320 不是只能来自旧 artifact，必须标为 HEAD baseline；当前 active worktree 仍是 64。
- HEAD W=5 map 的 `ex[1]=fake_lock` 与 same-build `Q0+0xd8` stale slot 字节级重合，但只构成静态候选；默认 `ROUTE_*`=0 仍走 `poll(fd=-1,nfds=1)`，不应把 worktree 改回 320 或运行 payload。
- 报告：`analysis_outputs/violin-pselect-nfds-source-drift-audit-20260719.md`。保持 worktree 不动，先离线对账 scheduler consumer 的 waiter 指针/分支/伪树到达。
## 2026-07-19 scheduler consumer 分支静态对账

- 通过刷新后的 codebase-memory 图谱复核 active `consumer_thread()`、`run_main_route_threads()`、`prepare_pselect_fdsets()`、`prepare_skb_payload()`；确认默认 consumer 目标为 `waiter_tid`，交替 `sched_setattr(..., nice=19/0)`，而不是“未到 scheduler”的假设。
- same-build raw kernel 反汇编闭合 `rt_mutex_adjust_pi` 的前半段：读取 `task+0x938` 的 `pi_blocked_on`，非空后比较 waiter `+0x18` 与 task `+0x84`，再从 waiter `+0x58` 取 lock 调 `rt_mutex_adjust_prio_chain`。W=5 候选中 `ex[1]=fake_lock` 与 stale slot `Q0+0xd8` 重合，但后续 chain 分支仍未闭合。
- 本轮只读、未构建、未安装、未打开设备节点、未运行新 payload。报告：`analysis_outputs/violin-scheduler-consumer-branch-audit-20260719.md`。

## 2026-07-19 `task_to_waiter_node` 静态解释更正

- 复核 matching 6.6 `rtmutex.c` 与 same-build raw disasm：`task_to_waiter_node()` 使用 `__waiter_prio(task)`/deadline，不是把 `task->pi_waiters` 强转后把 `task+0x938` 当 prio。旧研究段落 13.3/13.4 已标记为过时并追加更正。
- 由此 `tree.prio=0` 与非 RT `SCHED_BATCH` task 的默认 waiter prio 静态上不相等；`orig_waiter=NULL` 的 chain 入口应继续按 `detect_deadlock=false`、`top_waiter=NULL` 模型对账。
- 下一步是离线模拟第一次 `rb_erase_cached/rb_add_cached` 的每个 parent/left/right/root 写入，再核对 fake owner 第二轮的 lock-change 退出；未运行 payload。

## 2026-07-19 rbtree 首轮重排离线模拟

- 新增 `tools/audit_violin_rtmutex_rbtree.py`，对 W=5 候选的 stale tree、`fake_w0` 和 `fake_lock` cached root/leftmost 做首轮 `rb_erase_cached`/`rb_add_cached` 符号化模拟；仅离线，不构建/安装/联机运行。
- `fake_fops` + `shape=1` 的 root 替换不会更新 cached leftmost（仍为 `fake_w0`），首轮 `waiter == rt_mutex_top_waiter(lock)` 不成立，`rt_mutex_dequeue_pi` 目标写入分支未达；`shape=0` 进入 `write_target` 未知解引用。
- 任意内核值仍为 unknown，模型结果不能当作成功 primitive。详细报告：`analysis_outputs/violin-rtmutex-rbtree-requeue-audit-20260719.md`；JSON：`analysis_outputs/violin-rtmutex-rbtree-requeue-audit-20260719.json`。
- 下一步：用 same-build raw/inlined rbtree 代码复核颜色修复、parent/color 写入和 stale root/leftmost 实际身份；保持 `nfds` 与 active worktree 不变。

## 2026-07-19 same-build rbtree raw 语义对账

- 从本地 same-build kernel image 提取 `rb_erase_cached@0x128074`、`rb_erase@0x102da44` 和 `__rb_erase_color@0x102d654`；确认 `rb_erase_cached` 只有在待删 node 等于 cached `rb_leftmost` 时才回写 leftmost。
- `rt_mutex_adjust_prio_chain@0x1052868` 在 `0x1052a88` 调 `rb_erase_cached`，随后 `0x1052ac8` 进入按 prio 选择左右子树的 inline reinsert。该 raw 语义支持模型中的 leftmost 阻断，但 fake root 的实际字段仍需逐项闭合。
- 产物：`analysis_outputs/rb_erase-and-color-20260719.disasm.txt`、`analysis_outputs/rb_erase-20260719.disasm.txt`；仅离线读取 kernel image。

## 2026-07-19 runtime FOPS route 输出诊断

- 运行输出的 `ROUTE_REACHED=1`、`consumer success=105` 只证明 scheduler consumer 分支被执行；`FOPSROUTE_CFI_RESULT ok=0 step=1 errno=22` 证明 CFI 首个 configfs 写阶段失败，不证明 fops 劫持或 rb_insert 写入。
- matching ashmem `ashmem_fops` 没有 `.write`/`.write_iter`，未劫持时 `pwrite()` 的 `-EINVAL` 应归因于 VFS 无写回调；`asma->size==0` 仅对应 `ashmem_read_iter` 的 EOF。不能把它写成 `ashmem_write_iter` 检查 size。
- `CFGPROBE_MISS` 因所有 pre-hijack 读均 EOF，不能确认 `misc_fops` 字段无 NULL；本次也没有读出 `ashmem_misc+0x10` 槽值。详细诊断：`analysis_outputs/violin-runtime-fops-route-diagnosis-20260719.md`。
- 当前 active worktree 默认 `ROUTE_*`=0，实际入口是 `poll(fd=-1,nfds=1)`；本次 runtime 不能套用 W=5 显式 pselect 字段映射。

## 2026-07-19 same-build `misc_fops` NULL 字段更正

- 直接读取 matching `boot.img.kernel`：`misc_fops@0x1269710` 的 `poll(+0x40)=0`，`read/write/read_iter/write_iter` 也全为 0；此前“Violin 所有字段非零、无 NULL 插入点”结论错误。
- `ashmem_misc+0x10` raw 值为 `0xffffffc0812c9df0`，与 `ashmem_fops@0x12c9df0` 对齐，确认 fops 劫持目标仍应是该指针槽，而不是静态 `misc_fops` 对象。
- 详细报告：`analysis_outputs/violin-fops-raw-null-fields-audit-20260719.md`。下一步转向实际 stale waiter/tree root 身份和插入父节点对账，不再以“无 NULL file_operations”作为阻断假设。

## 2026-07-19 active priority-tree 分支对账

- 运行 `tools/audit_violin_priority_tree_branches.py` 并通过 `py_compile`；输出
  `analysis_outputs/violin-priority-tree-branch-audit-20260719.json`。
- 当前 source 默认目标是 `ashmem_misc+0x10` 槽、值为 `fake_fops`，不是静态
  `misc_fops` 对象。以 `fake_w0` prio 130 为根时，nice 19/prio 139 走右支且
  leftmost 不变；nice 0/prio 120 走左支且 leftmost 只有在 stale waiter 真正
  到达伪树时才可能变化。
- 两条 `rb_link_node` 分支都写 `&stale_waiter` 而不是 `fake_fops`，所以尚未
  形成直接 fops 槽写入证据。该结果不覆盖颜色旋转、完整 erase/reinsert 或
  stale owner/task 身份；默认 route 仍是 `poll(fd=-1,nfds=1)`。
- 本轮保持只读，未改 `nfds`，未构建、安装或运行新 payload。下一步是 same-build
  `rb_erase_cached` 到 inline reinsert 的完整字段转移表。

## 2026-07-19 rt_mutex 全首轮 transition 更正

- 新增 `tools/audit_violin_rtmutex_full_transition.py` 并通过 `py_compile`；输出
  `analysis_outputs/violin-rtmutex-full-transition-audit-20260719.json`。
- 真实顺序不是“stale 作为 fake_w0 子节点被重排”：W=5 候选中 stale tree 的
  parent/left/right 均为 NULL，第一次 `rb_erase_cached` 直接清空 fake_lock
  root；随后 `rt_mutex_enqueue` 将 stale 设为 root/leftmost，因此 owner branch
  的 `waiter == top_waiter` 在 139/120 两个候选都成立。
- `rt_mutex_dequeue_pi(fake_task,fake_w0)` 的 raw one-child 写入为
  `[ashmem_misc+0x10-8] = fake_fops`，fops 指针槽 `ashmem_misc+0x10` 未改变。
  后续 pi enqueue 静态经过 `ashmem_misc+0x10-8 -> ashmem_fops -> noop_llseek`，
  link/旋转结果未知；不能报告为 target write。
- 报告：`analysis_outputs/violin-rtmutex-full-transition-audit-20260719.md`。
  当前 active route 仍是 poll/nfds=64，本轮只读，未改参数、未运行 payload。

## 2026-07-19 raw-text traversal 收敛

- 更新 full-transition 核验器：same-build `noop_llseek+0x18` 的 synthetic prio
  为负数，nice 19/0 候选都选择右 child `0xd503233fe61887de`，静态上在
  `rb_link_node`/`rb_insert_color` 前遇到非 canonical text qword。
- 因而本候选不是“已写入 target”或“旋转 unknown”，而是“到达非 canonical
  pointer、link 未执行”。报告与 JSON 已同步更新；active route 仍是 poll/nfds=64，
  本轮只读未运行 payload。

## 2026-07-19 第二轮 fake_w0->lock scheduler/PI 对账

- 新增 `tools/audit_violin_second_chain_user_lock.py`，并生成
  `analysis_outputs/violin-second-chain-user-lock-audit-20260719.json`、
  `analysis_outputs/violin-second-chain-user-lock-audit-20260719.md`。
- 读取 `kernel-src-wsl/common-gki/init/init_task.c` 与同 build
  `analysis_outputs/ota_full/boot_parse/boot.img.kernel`：`init_task` 的
  `prio/static_prio/normal_prio` 均为 `120`，与 payload `fake_task` 的
  `prio/normal_prio=120` 对齐。
- `rt_mutex_adjust_prio()` 的 donor 是 `stale->task=INIT_TASK`。因此
  `rt_mutex_setprio(fake_task, INIT_TASK)` 在 vendor force-update 未置位时
  early-return；但 chain walk 继续，读取 `fake_task->pi_blocked_on=fake_w0`，
  令第二轮 `next_lock=fake_w0->lock`。
- `fake_w0->lock` 当前硬编码为用户态 `pselect_user_lock`。即便把第一轮
  `rt_mutex_enqueue_pi()` 假设为可达，第二轮的 [4]-[5] 也会对该用户 VA 执行
  `raw_spin_trylock(&lock->wait_lock)`；没有有效内核 rt_mutex 对象，故不能继续
  到第二轮 requeue 或推导 target write。
- 严格 W=5 模型仍在第一轮 `noop_llseek` 的非 canonical child 停止；active route
  仍为 poll/nfds=64。本轮只读，未改参数、未构建/安装/运行 payload。

## 2026-07-19 `rt_mutex_force_update` hook 分支闭合

- 新增 `tools/audit_violin_rtmutex_force_update_hook.py`，生成
  `analysis_outputs/violin-rtmutex-force-update-hook-audit-20260719.json` 与报告。
- common-GKI 中只有 hook 声明、导出和 `rt_mutex_setprio()` 调用，没有 vendor callback
  注册实现；同 build `kallsyms.txt` 的 tracepoint/iterator 符号只证明基础设施存在，
  不能证明 runtime callback list 为空。
- `update=0`：保留前一轮结论，early-return 后 chain walk 继续并对用户态
  `pselect_user_lock` 执行 `raw_spin_trylock`。
- `update=1`：先进入 `__task_rq_lock(fake_task)`、rq/sched-class 路径；当前 fake page
  没有完整 CPU/rq、on-rq/state、sched entity、DL/RT 子结构和 task 生命周期证明，
  因而不能闭合到第二轮。
- 结论：vendor hook 分支不会修复现有路径；active route 仍为 poll/nfds=64，本轮只读，
  未改参数、未构建/安装/运行 payload。

## 2026-07-19 HEAD / active route 状态混用纠正

- 新增 `tools/audit_violin_route_state_split.py`，生成
  `analysis_outputs/violin-route-state-split-audit-20260719.json` 与报告。
- 发现上一份第二轮报告把当前 worktree 的 user-lock 字段误套到 HEAD W=5；报告已标记
  `superseded`。HEAD 实际为 `nfds=320`、pselect、`fake_w0->lock=fake_lock`；当前
  worktree 为 `nfds=64`、poll，stale lock 来自 poll 栈，fake_w0 lock 才是 user VA。
- HEAD 条件第二轮重新收敛为 fake_lock kernel-page dequeue/requeue：先清 root、更新
  fake_w0 prio=120、重新入 root/leftmost，下一轮因 prio 相等停止；第二轮本身无
  target-slot 写入。当前 active route 第一轮 lock identity 未闭合，不可套用该模型。
- 本轮只读，未改 exploit source、未构建/安装/运行 payload。

## 2026-07-19 PI-chain 入口门禁再纠正

- 新增 tools/audit_violin_pi_chain_entry.py，生成
  analysis_outputs/violin-pi-chain-entry-audit-20260719.json 与报告；只读
  对账 task_blocks_on_rt_mutex() 的 chain-entry 条件。
- HEAD W=5 FOPS payload 把 fake_task->pi_blocked_on 置 NULL，且 FOPS 分支把
  pi_waiters 置 NULL；因此 HEAD 不会进入 rt_mutex_adjust_prio_chain()，
  之前 full-transition 对 HEAD 的 PI-tree 过程只能算不可达条件模型。
- 当前 worktree 把 blocked_on 改为 fake_w0，但 fake_w0->lock 为用户态
  pselect_user_lock，active route 又是 poll(fd=-1,nfds=1)；静态非 NULL 不等于
  kernel 可解引用，也不等于 stale waiter->lock 地址一致。
- analysis_outputs/violin-rtmutex-full-transition-audit-20260719.md 已添加
  SUPERSEDED 标记。__rb_change_child() 的正确分支写的是
  fake_fops->rb_right = ashmem_misc+0x08，不是把 pi root 改成 target-8 或直接
  向 target-8 写 fake_fops。
- 当前门禁：先离线闭合 owner / stale waiter / next_lock 三者地址等式与
  raw_spin_trylock 可访问性；不改 nfds、不改 fd_set word、不构建/安装/运行 payload。

## 2026-07-19 pselect 256-fd kernel-lock overlay 候选

- 默认 poll route 已闭合为 stale lock 读取 zeroed poll_wqueues。新增
  tools/audit_violin_pselect256_kernel_lock.py，输出
  analysis_outputs/violin-pselect256-kernel-lock-audit-20260719.json 与报告。
- same-build core_sys_select：Q0=T-0x280，stale waiter base=Q0+0x80，
  waiter->lock=Q0+0xd8；nfds=256 时 3 组各复制 4 qword，exceptfds[3] 覆盖
  waiter->lock (+0x58)，可静态设置 kernel-page fake_lock。
- 该候选只关闭 user-VA lock 这一项，不代表 fd-mask readiness、stale task/lock
  identity、PI-tree parent/color 或 target-slot write 已成立。
- 下一步是离线 256-fd fd-mask/readiness 状态机，核对 open_selected_fds 的复制
  以及 ready 状态；不改 payload、不构建/安装/联机测试。
- 注意：当前 prepare_pselect_fdsets() 不是 256-fd 映射；只改 NFDS 会丢弃 in[4] 并错位 pi/task/lock，必须先做独立 word table。

## 2026-07-19 pselect 256-fd fd-mask/readiness 状态机

- 新增 tools/audit_violin_pselect256_fdmask_state.py，生成
  analysis_outputs/violin-pselect256-fdmask-state-20260719.json 与报告；通过
  py_compile 和 JSON 解析。
- 在 256-fd 独立 12-word 候选字段表下，原始 `out[0]=0x43434343` 置位 fd 1，
  当前 open_selected_fds 只重绑定 fd 3..255，因此 stdout/终端可能使 writefds
  提前 ready；原始常量不能进入后续 PI 模型。`ex[0]=130` 也置位 fd 1，进一步说明
  fd 0..2 的低位不能无条件带入。
- 低位清零画像（out[0]=0x43434340、ex[0]=128、in[3]=0x42424240）使所有
  set fd 落在 3..255，但 `prio 130 -> 128` 会改变 PI-tree 排序，只能作为离线
  诊断，不能视为 payload 修复。
- 这些 profile 不是当前 prepare_pselect_fdsets() 的布局；只改 NFDS 仍会错位，
  必须先独立建模 12-word 字段表。当前仍只读，不改 source、不构建/安装/联机。

## 2026-07-19 pselect 256-fd PI identity / second-lock gate

- 新增 tools/audit_violin_pselect256_pi_identity.py，生成
  analysis_outputs/violin-pselect256-pi-identity-20260719.json 与报告；通过
  py_compile 和 JSON 解析。
- 256-fd 独立字段表的 ex[3] 可把 stale waiter->lock 设为 kernel-page
  fake_lock，关闭原 stale lock 的 user-VA 阻断。
- 但当前 payload 仍写 `fake_w0->lock=pselect_user_lock`，因此
  fake_task->pi_blocked_on=fake_w0 后，rt_mutex_adjust_prio_chain 的
  next_lock 仍是 user VA；[5] raw_spin_trylock 不能作为有效 kernel lock 消费。
- 原始 prio=130 与低位清零诊断 prio=128 都在同一第二锁地址空间门槛处停止；128
  只可用于离线比较，不能直接替换 payload。因 `rt_mutex_adjust_pi()` 传入
  `orig_lock=NULL`，同一 `fake_lock` 不能自动归类为 `[6] same-orig-lock`
  deadlock；还需独立核对 `rt_mutex_owner(lock)==top_task` 等 chain 条件。本轮
  继续只读，不构建/安装/联机。

## 2026-07-19 pselect 256-fd second-lock transition matrix

- 新增 tools/audit_violin_pselect256_second_lock.py，生成
  analysis_outputs/violin-pselect256-second-lock-20260719.json 与报告；通过
  py_compile 和 JSON 解析。
- 矩阵结果：当前 fake_w0->lock=user VA 在 rt_mutex_adjust_prio_chain [5]
  阻断；假设改成同一 fake_lock 会在 [6] `lock == orig_lock` 触发
  `-EDEADLK`；只有不同的 kernel rt_mutex 才有继续可能，但必须补齐 owner、
  waiters、wait_lock 生命周期模型。
- 因此 256-fd overlay 只关闭 stale/original lock 地址空间问题，不能声称达到
  PI requeue 或目标写入。最优下一步是离线搜索第二个有效 kernel rt_mutex；找不到
  就停止该分支，不做联机测试。

## 2026-07-19 second rt_mutex inventory gate

- 新增 tools/audit_violin_second_rtmutex_inventory.py，生成
  analysis_outputs/violin-second-rtmutex-inventory-20260719.json 与报告；通过
  py_compile 和 JSON 解析。
- common-GKI 源码中的 11 个 `DEFINE_RT_MUTEX` 测试对象全部未出现在同 build
  kallsyms data/BSS；目标 config 同时关闭 `CONFIG_DEBUG_LOCKING_API_SELFTESTS`
  与 `CONFIG_LOCK_TORTURE_TEST`。
- `port_mutex`、`ts_report_mutex` 只是名称命中，不能证明是 `struct rt_mutex`。
- 当前没有稳定符号化的第二个静态 rt_mutex；pselect-256 只能确认 stale lock
  overlay，不能闭合 second-lock/PI requeue/target write。除非出现新的离线
  DWARF/BTF/合法 lock 地址证据，否则停止该分支，不联机测试。

## 2026-07-19 pipe_buffer / anon_pipe_buf_ops 独立写入原语离线审计

- 新增 `tools/audit_violin_pipe_buffer_primitive.py`，输出
  `analysis_outputs/violin-pipe-buffer-primitive-audit-20260719.json` 和报告；
  `py_compile`、JSON 解析均通过。
- 布局/符号静态通过：`struct pipe_buffer` 与 `user_pipe_buffer` 为 `0x28`，
  字段偏移一致；Violin `anon_pipe_buf_ops` offset `0x114a288` 已由同 build
  kallsyms/offset report 复核；ops 无 `confirm`，NULL confirm 在 helper 中返回 0。
- 发现 `pipe_phys_write_data()` 允许整页长度，但 `pipe_write()` 对整页令
  `chars=0`，因此会走新 buffer 分配而不是 forged buffer；当前可靠的单页写只应
  接受 `0 < len < PAGE_SIZE`。零长度写会假成功但不写目标。
- pipe physrw 的元数据读写依赖 ConfigFS/ashmem fops primitive，不是独立
  arbitrary write。候选页 gate 还存在 normal-2k 放行、缺少 `PAGE_TYPE_SLAB`
  硬 gate、`KMALLOC_CACHE_TYPES=4` 超出本 build 三行 cache enum 等问题。
- 本轮保持只读门禁，不改 source、不构建/安装、不联机；先完成离线门禁修订再考虑
  后续单变量验证。
- 补充核对：Violin direct-map/VMEMMAP 计算未回绕（`VMEMMAP_END=0xfffffffe40000000`），
  240 个 reclaim marker 到 `len-1` 的索引映射静态自洽；这些只是二级路径前提，
  不改变其对 ConfigFS/fops primitive 的依赖。

## 2026-07-19 pipe 写调用方契约闭合

- 基于 codebase-memory graph 追踪 active `src/pipe.c` / `src/root.c`，新增
  `tools/audit_violin_pipe_write_callers.py` 及 JSON/Markdown 结果。
- 共 12 个实际写调用，全部静态解析，最大长度 40 bytes；当前调用方没有传入
  `0` 或 `PAGE_SIZE`，因此未触发整页 merge 边界。
- API 本身仍需独立拒绝 `len==0` 与 `len>=PAGE_SIZE`；下一步优先形成离线 gate
  修订，不改 source、不构建、不联机。

## 2026-07-19 rb_set_parent_color → fops 中继桥离线审计

- 新增 `tools/audit_violin_rbset_fops_bridge.py`，输出对应 JSON/Markdown；
  `py_compile`、JSON 解析通过。
- `rb_set_parent_color()` 的第一个实参才是写入地址，第二个实参只是 parent
  value；`fake_parent=ashmem_misc+0x10` 不能单独把写入导向 fops 槽。
- `ashmem_misc+0x10` 在 `miscdevice` 中是 `fops` 字段；作为 rb_node 解释时，
  `+0x08/+0x10` 会落到 live `list.next/list.prev`，必须证明旋转期间的所有访问安全。
- 临时 fops=`fake_w0+0x28` 失败：waiter pi_tree 节点的字段会把 `.read`/`.write`/
  `.read_iter`/`.write_iter` 解析成 target-8、prio=130、deadline=0、task 指针。
  `configfs_write_once()` 走 `pwrite()`，`vfs_write()` 先检查 `.write`，llseek
  为空不能绕过错误间接调用。
- 当前状态 `RBSET-INTERIM-FOPS-INVALID`；后续门禁是完整的 `__rb_insert` 地址/颜色/
  子指针状态表，未闭合前不改 payload、不构建、不联机。

## 2026-07-19 same-build raw rb 对象图再校正

- 新增 `tools/audit_violin_raw_rb_object_graph.py`，输出对应 JSON/Markdown；
  `py_compile`、JSON 解析通过。
- same-build raw image 显示 `misc_fops`/`ashmem_fops` 都有 NULL 槽，否定“Violin
  无 NULL 插入点”这一旧根因；此前 runtime EOF 不能证明静态 fops 字段全非零。
- 目标槽 `ashmem_misc+0x10` 的内容是 `ashmem_fops`。当前 `target-8` 的
  `rb_right` 解引用该内容指针，进入 `ashmem_fops` 对象，而不是把槽地址作为
  rb_node；静态 fops 的 NULL 插入点因此仍不等于目标槽写入。
- 目标槽作为 rb_node 时，`+0x08/+0x10` 是 post-`misc_register` 的 list.next/prev；
  `INIT_LIST_HEAD` + `list_add` 已证明两个 child 运行时非 NULL，镜像零值只是
  注册前状态。当前仍是对象图未闭合，下一步枚举其余可达
  `rb_set_parent_color` 第一实参；当前已知 destination 集合不含
  `ashmem_misc+0x10`。不改 payload、不构建、不联机。

## 2026-07-19 rb_erase / rb_replace 目标槽目的地审计

- 新增 `tools/audit_violin_rb_erase_target_destinations.py` 及对应 JSON/Markdown；
  `py_compile` 与 JSON 解析通过。
- 当前图中 `W=fake_w0.pi_tree` 的 `rb_parent=F=fake_fops`、
  `rb_left=N=T-8`、`rb_right=NULL`。若 cached leftmost 指向 W，
  `rb_erase_cached` 会先把它更新为 `rb_next(W)=ashmem_fops`；随后 `rb_erase(W)` 只会写 `F.rb_right=N`，
  并把 `N.__rb_parent_color` 设为 `F`；不会写真实 fops 槽 `T=ashmem_misc+0x10`，
  也不会更新 root（parent 非 NULL）。
- 只有抽象条件 `parent=N` 且 victim=`N.rb_right=ashmem_fops` 才可能通过
  `__rb_change_child` 覆盖 T，但未证明 `rb_parent(ashmem_fops)=N`，且当前
  rtmutex 调用图没有 `rb_replace_node`。结论为
  `RB-ERASE-FOPS-SLOT-NOT-CLOSED`；本轮只读，不改 payload、不构建、不联机。

## 2026-07-19 codebase graph relay dependency复核

- codebase-memory index ready（4218 nodes / 15631 edges）；`kernel_write_data()`
  仅包装 `configfs_write_once()`，最终调用 `pwrite()`（`src/util.c:926-943,
  995-997`）。
- `pipe_phys_write()`（`src/pipe.c:517-543`）对 pipe_buffer 的读/改/恢复均依赖
  `kernel_read_data/kernel_write_data`，普通 pipe `write()` 只是最后触发 forged
  buffer 的动作，不是第一写入原语。
- active `run_main_route_threads()`（`src/main.c:624-679`）只做 PI route 和可选
  pipe page 准备，不能绕过 fops/ConfigFS。当前分支应停止，下一步仅做新的
  kernel write sink/目标离线枚举，不改 payload、不构建、不联机。
- codebase-memory 对 active `src/{util,pipe,fops,root,main}.c` 枚举
  `pwrite/process_vm_writev/vmsplice/copy_file_range/sendfile/writev`，唯一命中为
  `src/util.c:941` 的 `pwrite`；未发现独立第二写入 sink。

## 2026-07-19 alternate file_operations slot inventory

- 新增 `tools/audit_violin_alternate_fops_slots.py` 及 JSON/Markdown；
  `py_compile`、JSON 解析均通过。
- 同 build `misc_fops`/`ashmem_fops` 共 46 个 NULL qword 字段（44 个 pointer/callback，2 个 `mmap_supported_flags` scalar），当前图唯一交集为
  `ashmem_fops.read`（`A+0x10`）。但 `rb_link_node` 写入新 waiter rb_node
  地址，不是可调用函数；`misc_fops` NULL 槽也无当前图可达 parent。
- 结论 `NO-USABLE-ALTERNATE-FOPS-SLOT`。停止静态 fops NULL 分支，下一步只读
  搜索新的 kernel-object writable field；不改 payload、不构建、不联机。




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

## 2026-07-19 rb_erase direct fops-slot equation correction

- 新增 `tools/audit_violin_rb_erase_direct_fops_write.py`，离线读取 active
  payload 与同 build rbtree/rtmutex/misc/fs 源码，输出 JSON/Markdown，并通过
  `py_compile` 与 JSON 解析。
- 该审计把 active default 与 custom shape-1 分开：`main.c` 不调用
  `set_pselect_write()`，因此当前默认仍是 shape 0（`W.parent=F, W.left=N,
  W.right=NULL`），其 erase 只写 `F.rb_right=N`、T 不变；shape-1 只是未启用候选。
  custom shape-1 的字段为 `T=ashmem_misc+0x10`、`N=T-8`、`W=fake_w0+0x28`、
  `F=fake_fops`，且 `W.parent=N, W.left=NULL, W.right=F`。
  `rb_erase_cached(W)` 的一子节点分支调用 `__rb_change_child(W,F,N,root)`；
  因 `N.rb_left` 是 live `miscdevice.list.next` 而不是 W，else 分支写
  `N.rb_right=F`，即 **T 直接变为 F**。
- 同一分支会将 `F.__rb_parent_color` 写成 N，别名 fake fops `owner=N`；
  root 仍为 W、leftmost 变为 F，后续 `rb_add_cached` 树状态不合法性待离线建模。
  `misc_open/fops_get` 的 owner pin 也使当前 route 后 fresh-open 顺序未闭合。
- `rt_mutex_adjust_pi()` 传入 `orig_lock=NULL`，因此“fake_lock 必然命中
  `lock==orig_lock`”已从 blocker 中删除；其它 deadlock/owner/route 条件仍未闭合。
- 结论：active default 仍为 `T-NOT-REACHED`；仅 custom shape-1 的目标槽写入方程
  标记 `SYMBOLICALLY-CLOSED`，不标记 payload 成功；
  下一步只做 erase 后树状态机和 pre-open/owner-repair 设计，不改 fd-set、不构建、不联机。

## 2026-07-22 rb_erase post-write state closure

- 新增 `tools/audit_violin_rb_erase_postwrite_state.py` 及 JSON/Markdown；
  通过 `py_compile`、JSON 解析和 evidence null 检查。
- 对 active/default 与 custom shape-1 分别建模：active shape 0 的 erase 只写
  `fake_fops.rb_right=N`，所以 `ashmem_misc+0x10` 仍未触达。
- custom shape-1 的目标方程可成立，但 erase 后 cached tree 保留 stale root W、
  leftmost F，`RB_CLEAR_NODE(W)` 后存在自父平衡或 W↔F 循环；没有安全 consumer
  状态。并且 child-parent copy 将 `fake_fops.owner` 改成 N，route 后 fresh-open
  必须先证明 `fops_get/try_module_get` 对该 module-shaped 地址的实际结果，当前未闭合。
- 结论：active `T-NOT-REACHED`；custom `SYMBOLICALLY-CLOSED` 但不可消费。
  下一步改为离线搜索独立 owner 修复/写入 sink 或新的 kernel-object consumer，
  不启用 shape-1、不改 fd-set、不构建、不联机。

## 2026-07-22 owner/open gate correction and same-waiter cycle closure

- `tools/audit_violin_fake_fops_owner_module_shape.py` 已通过运行和
  `py_compile`。同 build BTF/raw image 显示 `struct module.state=+0x0`、
  `refcnt=+0x5c0`；N=`ashmem_misc+0x08` 的 raw 值为
  `state=0x815eb0c9`、`refcnt=0x1a4`，且 `CONFIG_MODULE_UNLOAD=y`。
- `try_module_get()` 没有 module-registry membership check，所以
  `fake_fops.owner=N` 是 raw-image 上的 **likely pass + adjacent refcnt side effect**，
  不是必然 fault；副作用落在 `dev_attr_recovery+0x8`。runtime 初始化仍未验证。
- `audit_violin_rb_erase_postwrite_state.py` 进一步把 consumer 身份分支闭合：若
  `prerequeue_top_waiter == waiter == fake_w0`，erase 后同一 W 被重新 enqueue，
  clone 后 W.prio=120、F.prio=0，`rb_add_cached` 在 `W -> F -> W` 间循环；若身份
  不等，目标槽写入方程也不会发生。
- 状态仍为 active `T-NOT-REACHED`，custom 只保留条件目标方程；本轮不启用
  shape-1、不改 fd-set、不构建、不联机。

## 2026-07-22 active poll-route lock-source closure

- 新增 `tools/audit_violin_poll_route_lock_source.py` 及 JSON/Markdown，已通过
  `py_compile` 与 JSON 校验。
- active route 使用 `poll((struct pollfd *)pselect_user_lock, 1, ...)`，并把
  `fd=-1` 写入唯一 pollfd。same-build `do_pollfd()` 在 `fd < 0` 直接跳到 `out`，
  不执行 `fdget/vfs_poll`，所以没有 `poll_wait`/`poll_table_entry` 注册。
- `poll_initwait` 的 `inline_index=0/table=NULL` 与 `poll_schedule_timeout` 的睡眠
  不会把 user VA 复制到 `rt_mutex_waiter.lock`。结论：active poll 到
  `fake_w0->lock=pselect_user_lock` 为 **NO-SOURCE-EDGE**，不是已验证 overlay。
- pselect overlay 与当前 poll 日志继续分离；下一步仅做 offline poll-stack/UAF
  反汇编核对，找不到独立边就归档该 PI 映射，不联机改参数。

## 2026-07-22 second-kernel-lock inventory

- 新增 `tools/audit_violin_second_kernel_lock_inventory.py` 和 JSON/Markdown，
  已通过 `py_compile`、raw-word 与 JSON 校验。
- `rcu_state.node[0..2].boost_mtx` 虽为合法 `struct rt_mutex` 布局，但 raw image
  全零、owner/waiters 为空，源码也明确其只作 RCU priority-boost side effect。
- `console_mutex`、`tty_mutex` 是非-RT `struct mutex` 布局，不能当作
  `rt_mutex_base`；`futex_pi_state.pi_mutex` 没有独立稳定地址/生命周期。
- 未找到闭合的 distinct second lock。`fake_lock` 仍是唯一受控候选；
  `orig_lock=NULL` 仅修正 same-lock 解释，不闭合 owner/top-task/requeue 条件。

## 2026-07-22 corrected pselect-256 second-lock matrix

- 新增 `tools/audit_violin_pselect256_second_lock_correction.py` 及
  `analysis_outputs/violin-pselect256-second-lock-correction-20260722.{json,md}`；
  运行、`py_compile` 均通过。
- 旧报告中 `same_fake_lock -> STOP_[6]_SAME_ORIG_LOCK_DEADLOCK` 已撤销：
  `rt_mutex_adjust_pi()` 的 `orig_lock` 为 NULL，same fake_lock 只能标为
  `CHECK_[6]_OWNER_TOP_TASK; ORIG_LOCK_NULL`，还需 owner/top-task、requeue、
  cached-tree、生命周期证明。
- 当前 fake waiter lock 仍为 user VA，仍在 `[5]` 阻断；distinct second lock
  仍未闭合。全程离线，不改 payload、不联机。

## 2026-07-22 pipe first-stage circularity closure

- 新增 `tools/audit_violin_pipe_first_stage_circularity.py` 及对应 JSON/Markdown；
  运行、`py_compile`、JSON 检查通过。
- `pipe_phys_write_data()` 的 found-buffer 路径通过 `pipe_phys_write()` 用
  `kernel_write_data()` 改写/恢复 buffer；unfound-buffer 路径通过
  `forge_pipe_buffers_on_page()` 逐项调用同一写原语。`install_pipe_physrw()` 在
  physrw 检查前也先写 proof data。
- `kernel_write_data()` → `configfs_write_once()`，所以 pipe 不是独立第一阶段写入，
  结论为 **NO-INDEPENDENT-FIRST-STAGE-WRITE**；保留为 fops/ConfigFS 后的二级
  transport。继续只做有界离线 sink inventory，不运行 payload。

## 2026-07-22 bounded core kernel-write sink inventory

- 新增 `tools/audit_violin_kernel_write_sink_inventory.py` 和对应 JSON/Markdown；
  使用 codebase-memory `search_code` 枚举核心 `src/*.c` write-like syscall，再只读
  对账关键函数；运行、`py_compile`、JSON 校验通过。
- 结果为 **NO-NEW-INDEPENDENT-KERNEL-WRITE-SINK**：ConfigFS/`pwrite` 仍是唯一
  arbitrary target/value transport（受 fops 门控）；pipe downstream/circular；
  pselect 同一 rb anchor；ashmem-name/perf/sendmsg/page shaping 是 setup/leak/
  allocation；SELinux/su/wallpaper/log 是 post-credential 或 userspace side effect。
- 范围只覆盖核心 `src/*.c`，未把重复 target variants 计为新路径；本轮不构建、不改
  payload、不联机。下一步改为归档已知分支，除非出现可独立闭合的
  object/callback/destination/value 四元组。

## 2026-07-22 active Violin artifact scope correction

- 新增 `tools/audit_violin_active_artifact_scope.py` 及对应 JSON/Markdown；运行、
  `py_compile`、JSON 校验通过。
- `Makefile` 默认项目是 `blazer-CP2A.260605.012`；只有显式
  `PROJECT=violin-v-oss` 才是 Violin source selection。该选择仅覆盖
  `src/targets/violin-v-oss/slide.c` 与 `target.h`，其余 `main/util/fops/pipe` 仍用
  核心 `src/*.c`。
- Violin 专用 `slide.c` 的写调用只是 crash log 与 child-pipe report，未发现新的
  arbitrary kernel-write syscall。因此核心 sink inventory 对显式 Violin 选择有效，
  但 binary/hash 证据必须记录 project 和 source map；默认 blazer artifact 不得当作
  Violin 证据。本轮仍不构建、不联机。

## 2026-07-22 binary/hash provenance audit

- 新增 `tools/audit_violin_binary_provenance.py` 及对应 JSON/Markdown 产物；审计仅
  读取历史 hash、文件大小和日志映射，未构建、未运行、未联机。
- stable0、E20、caimanwords、route-only、slide-only 与显式
  `build/violin-v-oss/bin/preload.so` 的 SHA256 均命中历史记录；CFI ConfigFS 同一路径
  复用了两个历史 hash，必须以 hash 加 run log 消歧。
- `exploit-site/preload.so`、`preload-a358fbf.so` 当前 hash 无 source-map/run-log
  映射，标记为 **CURRENT_HASH_UNMAPPED**；不能当作 Violin 证据。后续 artifact 证据
  必须同时给出 hash、`PROJECT=violin-v-oss` source map 和对应 run log。

## 2026-07-22 strict provenance manifest

- 新增 `tools/build_violin_provenance_manifest.py` 与对应 JSON/Markdown；从 hash audit
  派生严格证据清单，未移动、重建或执行 artifact。
- 强制字段为 `SHA256 + PROJECT=violin-v-oss + source map + run log`。本轮清单共 9
  个文件：6 个 hash 命中但字段不全，1 个路径复用且字段不全，2 个通用文件逻辑隔离，
  `accepted_complete=0`。
- 下一步只从现有离线日志补齐缺失字段；在四元组闭合前不把任何文件当作新的 Violin
  runtime 证据，仍不构建、不联机。

## 2026-07-22 provenance recovery audit

- 新增 `tools/audit_violin_provenance_recovery.py` 及对应产物；仅读取既有 build script
  和日志引用，未执行任何脚本。
- 9 个条目中 7 个 run-log/embedded-artifact 引用已能离线复核；CFI ConfigFS、
  route-only 另外有可复核 source script。两者均是显式
  `TARGET_CONFIG_H=targets/violin-v-oss/target.h`，但没有 `PROJECT=violin-v-oss` 变量
  记录，CFI 路径同时存在 hash 复用。stable0/E20/caimanwords/slide-only 仍没有与
  具体 source script 的一对一链接。
- 因此完整证据仍为 0；2 个通用文件保持逻辑隔离，其余仅为部分 provenance。下一步
  继续补现有记录，不以 recovered script 触发新 payload。

## 2026-07-22 transcript provenance audit

- 新增 `tools/audit_violin_transcript_provenance.py` 及对应产物；只读扫描用户提供的
  Claude JSONL，未重放其中命令。
- JSONL 中可见大量通用 `make PROJECT=violin-v-oss` 记录，但 stable0、E20、
  caimanwords、slide-only 均没有与文件名同时出现的结构化 build record，不能由转录
  将 hash 绑定到具体 source map。
- 结论仍是完整 provenance 为 0；不构建、不运行、不联机。

## 2026-07-22 corrected primary fops gate

- 新增 `tools/audit_violin_primary_fops_gate.py` 及
  `analysis_outputs/violin-primary-fops-gate-20260722.{json,md}`；工具已通过
  `py_compile`、执行和断言校验，`runtime_allowed=false`。
- raw image 直接证明旧的“Violin `misc_fops` 所有字段非零”说法错误：
  `misc_fops.owner=0`、`misc_fops.poll=0`。该旧根因解释已 superseded。
- `ashmem_misc+0x10` 才是实际 fops 指针槽，raw 值为
  `IMAGE_BASE+ASHMEM_FOPS_OFF`；静态 `misc_fops` 地址不能当作指针槽。
- 默认 shape-0 仍只建模到 `[ashmem_misc+0x08]` 和 `[fake_fops+0x08]` 的写，
  不写 `T=ashmem_misc+0x10`。shape-1 的分支条件已由
  `misc_register()`/`__rb_change_child()` 修正为 `N.rb_left!=W`；list invariant 支持
  该条件，仍需 PI dequeue identity 到达 erase。
- 当前 active poll 使用 `fd=-1`，早退于 `do_pollfd()`，所以用户态
  `pselect_user_lock` 到 `fake_w0->lock` 仍为 **NO-SOURCE-EDGE**。
- 结论：**ACTIVE_PRIMARY_FOPS_WRITE_NOT_CLOSED**；下一步仅保留一个离线
  pselect/custom-shape 状态表门，或在其前置关系无法证明时归档该 anchor。

## 2026-07-22 bounded pselect/custom-shape state table

- 新增 `tools/audit_violin_pselect_custom_shape_state.py` 及对应 JSON/Markdown；
  已通过 `py_compile`、执行和字段断言，`runtime_allowed=false`。
- 四情形离线矩阵已固定：active poll 无用户锁 source edge；nfds=64 丢 target/fake_lock；
  hypothetical nfds>=257 shape-0 只可能修 stale lock，`fake_w0->lock` 仍 user VA；
  shape-1 的 T:=F 仍依赖 erase/PI dequeue identity，且 post-erase `W→F→W` 与
  `F.owner:=N` 的 owner/open gate 未闭合。
- raw 预注册 `N.rb_left=0`、`N.rb_right=&ashmem_fops` 加上 list invariant 支持
  `N.rb_left!=W`。结论：**PSELECT_CUSTOM_SHAPE_STATE_NOT_CLOSED**。
- 只保留四项离线闭合门（PI dequeue identity、kernel second lock、terminating rb_add、
  owner-repair/transport）；本轮不改 fd-set、不启用 shape1、不构建、不联机。

## 2026-07-22 rb/PI anchor archive

- 生成 `analysis_outputs/violin-rb-pi-anchor-archive-20260722.md`，将当前 rb/PI
  分支标记为 `FROZEN_NO_RUNTIME_BRANCH`，不是永久性漏洞结论。
- 关闭条件固定为四项离线证据同时成立：PI dequeue identity、kernel second lock、
  terminating post-erase rb_add、owner-repair/transport 顺序。此前 pselect/poll、shape0/
  shape1、历史 hash/runtime 证据均不能替代。

## 2026-07-22 shape-1 predecessor branch correction

- 新增 `tools/audit_violin_misc_list_predecessor.py` 及对应产物，已通过
  `py_compile`、源码字段断言和 raw 地址校验。
- 纠正前一轮错误：`__rb_change_child()` 的右写分支要求 `N.rb_left != W`，不是
  `N.rb_left == W`。`misc_register()` 的 list invariant 使该条件在当前无先前 list
  corruption 模型下成立，因此 shape-1 的 predecessor gate 为
  `CLOSED_UNDER_CURRENT_LIST_INVARIANT`。
- shape-1 的目标方程现在应写成：PI dequeue identity 到达 erase
  → `N.rb_left!=W` → `N.rb_right:=F` → `ashmem_misc.fops:=F`。完整链路仍被
  `fake_w0->lock`、post-erase `W→F→W` 和 owner/transport 门阻断；本轮不运行 payload。

## 2026-07-22 PI dequeue/top-waiter identity audit

- 新增 `tools/audit_violin_pi_dequeue_identity.py` 及对应 JSON/Markdown 产物；已通过
  `py_compile`、执行、JSON 校验，未构建、未改 fd-set、未联机。
- 对账结果：`prerequeue_top_waiter` 的源头是
  `rt_mutex_top_waiter(lock)`，消费点是 `rt_mutex_dequeue_pi(task, ...)`；它不是
  `task->pi_blocked_on` 的别名。`futex_wait_requeue_pi()` 传入的是栈对象 `&rt_waiter`，
  `futex_requeue()` 再把该对象传给 `rt_mutex_start_proxy_lock()`。
- active `poll(fd=-1,nfds=1)` 没有把实际 chain task/lock/waiter 绑定到
  `fake_task/fake_lock/fake_w0` 的 source edge，判定为
  **PI_IDENTITY_NOT_CLOSED_ACTIVE_POLL**。shape-1 目标式仅在 synthetic chain 已进入
  时条件性成立；`fake_w0->lock` 仍为 user VA，second-lock/lifetime 仍阻断。
- 下一步继续只读：若不能离线证明完整 pointer identity、canonical second lock、
  terminating post-erase `rb_add` 与 owner/transport repair，则维持 rb/PI archive，
  不运行新 payload。

## 2026-07-22 full synthetic-chain closure audit

- 新增 `tools/audit_violin_full_synthetic_chain_closure.py` 与
  `analysis_outputs/violin-full-synthetic-chain-closure-20260722.{json,md}`；
  只读汇总 synthetic chain、second-lock、终止性、owner/transport 四个 gate，
  `runtime_allowed=false`。
- payload shape 本身齐全，但 active `poll(fd=-1,nfds=1)` 没有 source edge 进入
  `fake_task/fake_lock/fake_w0`，且 `prerequeue_top_waiter` 来自真实
  `rt_mutex_top_waiter(lock)`；因此 synthetic entry 未闭合。
- `fake_w0->lock` 仍为 user VA；内核 chain 会对 `lock->wait_lock` trylock，既有
  second-kernel-lock inventory 也没有找到独立、稳定、owner 已闭合的 canonical RT lock。
- shape-1 的 T:=F 仅条件性成立；post-erase stale `rb_root=W`/`leftmost=F` 导致同 waiter
  `W→F→W` 循环，`rb_add_cached` 不遇 NULL，终止性未闭合。
- 初始 fops transport 的 owner=0/read_iter/write_iter ConfigFS、llseek/text refresh 和
  owner clear 均被源码证实，但 refresh/pipe 是首次写入之后的下游；shape-1 owner=N
  不是合法 module 指针，pipe 也没有独立 first-stage sink。
- 总结：**`FULL_SYNTHETIC_CHAIN_NOT_CLOSED`**；维持 rb/PI frozen branch，不改
  `fd_set`/`nfds`，不构建、不联机、不运行新 payload。

## 2026-07-22 independent sink closure

- 新增 `tools/audit_violin_independent_sink_closure.py` 与
  `analysis_outputs/violin-independent-sink-closure-20260722.{json,md}`；已通过
  `py_compile`、执行和 JSON 断言，未构建、未联机。
- 显式 Violin source map 只替换 `slide.c/target.h`；target slide 没有 arbitrary
  kernel-write syscall。active core 的唯一 `pwrite()` 是 fops-gated ConfigFS；
  sendmsg/ioctl/setsockopt 是 setup，pipe write 是 ConfigFS 下游。
- 对候选 `splice/vmsplice/tee/process_vm_writev/copy_file_range/madvise/ptrace/bpf`
  做了 callsite 扫描，全部为 0；结论：**`NO_NEW_INDEPENDENT_KERNEL_WRITE_SINK`**。
- 因此下一步不是重开 payload，而是归档已知 rb/PI/pipe/syscall 分支；除非发现独立
  kernel object + callback + destination + value 的离线闭合证据。

## 2026-07-22 same-build kernel sink candidate closure

- 新增 `tools/audit_violin_kernel_sink_candidates.py` 及
  `analysis_outputs/violin-kernel-sink-candidates-20260722.{json,md}`；已通过
  `py_compile`、执行和 JSON 断言，未构建、未安装、未联机。
- `CONFIG_DEVMEM=n` 关闭 `/dev/mem` 直接物理写；Binder/BPF/UFFD/TUN/VHOST/ashmem
  的 user-copy 只落到各自 allocator/object/mm/skb/guest-memory 语义，未闭合任意
  kernel destination 的新首写原语。`CONFIG_VHOST_NET=n`，当前仅有通用 vhost/vsock。
- `CONFIG_IO_URING=y` 但 source snapshot 缺 `io_uring/io_uring.c` 与 `fs/io_uring.c`；
  `CONFIG_KVM=y` 但缺 `virt/kvm/kvm_main.c` common core。两者标记为
  **`OPEN_SOURCE_SNAPSHOT_GAP`**，不能错误解释为“没有 sink”。
- 总判定为 **`NO_NEW_INDEPENDENT_SINK_CLOSED_SOURCE_GAPS_REMAIN`**；下一步只补齐
  exact common-kernel source 或匹配 vmlinux/disassembly，再继续离线闭合这两个缺口。

## 2026-07-22 raw sink-gap inventory correction

- 新增 `tools/audit_violin_raw_sink_gap_inventory.py` 与
  `analysis_outputs/violin-raw-sink-gap-inventory-20260722.{json,md}`；已通过
  `py_compile`、执行和字段断言，未构建、未安装、未联机。
- `analysis_outputs/ota_full/boot_parse/boot.img.kernel`（36,456,960 bytes，SHA256
  `9552098B7FADBB2F6375252F69A47DC132AB36CEC3290F5219C8103DCE064D33`）的 raw symbols
  已证明 io_uring 与 KVM common implementation 实际存在；之前 source-gap 不是实现
  不存在的证据。
- bounded ARM64 disassembly：io_uring setup/create、registered user buffers、read/write
  的目的地保持 ring/user-buffer/opened-file 语义；KVM VM ioctl/set-memory-region/write-
  guest 保持 memslot/guest-memory/vCPU state 语义；没有新的 generic arbitrary host write。
- `io_uring_cmd` driver callback 与 arm64 KVM 专用 ioctl 仍是开放的定点审计边界；判定为
  **`RAW_ARTIFACT_PRESENT_GENERIC_PATHS_NOT_ARBITRARY_DRIVER_OR_ARCH_REVIEW_OPEN`**。

## 2026-07-22 raw driver/arch sink boundary

- 新增 `tools/audit_violin_raw_driver_arch_sinks.py` 及
  `analysis_outputs/violin-raw-driver-arch-sinks-20260722.{json,md}`；已通过
  `py_compile`、执行、raw SHA256 与 JSON 断言，未构建、未安装、未联机。
- 定点反汇编确认 generic `io_uring_cmd` 在 `file->f_op` 上执行间接 callback；已列出的
  ublk/NVMe callbacks 分别落到 ublk 对象状态和 `nvme_map_user_request`/block device I/O，
  没有用户选择的 host-kernel destination。arm64 KVM vCPU/VM ioctl、MTE tags、pKVM info
  和 timer offset 只落到固定 KVM/guest state 或 usercopy。
- 进一步按 raw dispatcher 使用的 `+0xf8/+0x100` 槽扫描 static fops，解析出 8 条已知
  callback 记录（`null_fops`、ublk control/channel、NVMe device/namespace 及 iopoll）；
  module alias relocation delta 为 `0x2307200000`。这不是对动态或未列 module callback 的
  whole-kernel absence 证明。
- 目标符号全部存在；本轮 verdict 为
  **`TARGETED_DRIVER_ARCH_CALLBACKS_NO_ARBITRARY_KERNEL_DESTINATION; GENERIC_IO_URING_CMD_DISPATCH_REMAINS_OPEN`**。
- 这仍不是未列出模块/未来 callback 的全内核负证据；继续保持 frozen offline-only，不改
  `fd_set`/`nfds`，不运行 payload。

## 2026-07-22 device identity/log preflight

- `adb devices -l` 确认 `03035440C1781540` 在线且为 `violin`；只读 fingerprint、kernel、
  boot_id、SELinux 与 shell groups 均已保存到
  `analysis_outputs/device-readonly-20260722/device-fingerprint.txt`。
- 设备已有 `/sdcard/Download/crash.txt` 仅包含 2026-07-18 `PSELECT_LAYOUT_*` 探针，已
  拉取到 `analysis_outputs/device-readonly-20260722/crash.txt`；不是本轮 raw sink 审计的新
  证据。
- 已保存当前全量 logcat `analysis_outputs/device-readonly-20260722/logcat-all.txt`，SHA256
  `2DA28BBA1FACD91A3BA6E828D43ED27304CBC0691EDAF4971D9EDBDC6649AB81`；shell `dmesg` 仍为
  `Permission denied`。
- 现有 `build/violin-v-oss/bin/preload.so` 为 2026-07-18 旧 full-route binary，而
  `src/main.c/fops.c/util.c` 在 2026-07-19 更新；本机未找到 Android NDK。结论：不推送旧
  binary；若要联机，先构建 `CFGPROBE_ONLY_DIAG=1` stop-only 版本，仅收集 CFGPROBE 日志。

## 2026-07-22 NDK diagnostic build and device run

- 使用用户提供的 `E:\workspace\projects\xiaomi-root\ndk`（Android NDK r29，
  `29.0.14206865`）构建 `PROJECT=violin-v-oss` 的隔离 stop-only 版本，编译宏为
  `CFGPROBE_ONLY_DIAG=1`；输出没有覆盖 `build/violin-v-oss/bin/preload.so`。
- 产物：`exploit-repo/IonStack/CVE-2026-43499/exploit/build/violin-v-oss-diag-20260722/bin/preload.so`，
  173,536 bytes，SHA256 `cb71799ce82f3ae8a62b1226c7fc332a7ec54d9746d4679e463ff0d481c84662`。
  构建清单：`analysis_outputs/device-diag-build-20260722/build-manifest.txt`。
- 在线设备 `03035440C1781540` 已完成 push，远端文件为
  `/data/local/tmp/ionstack-violin-diag-20260722/preload.so`；远端 sha256 与本地一致。
  以 `LD_PRELOAD=<remote> /system/bin/toybox id` 触发一次，返回进程仍为
  `uid=2000(shell)`，宿主命令退出 0。
- 新日志：`analysis_outputs/device-diag-run-20260722/crash.txt`，SHA256
  `7006eb965db4df72ca6cfb84ad6508416eee6db87df7e4a506068f236fa0a6e4`。日志完整包含
  `STEP0` → `CFGPROBE_START` → pre-hijack `rd=0/EOF` → `CFGPROBE1 rd=0 errno=0` →
  `CFGPROBE_MISS` → `CFGPROBE_STOP_AFTER_PROBE` → `CFGPROBE_ONLY_DIAG_STOP`；没有进入
  `STEP3`、`ROUTE_PREP_*`、`FOPSROUTE_*`、PI 或 pipe 阶段。
- boot_id 前后均为 `c79163bc-d9f5-457a-a30f-0362d89db8ea`，没有重启。结果确认当前
  源码在目标 boot 上能安全执行 pre-hijack probe；由于 stop-only 编译开关跳过后续 route，本轮未测试 fops 劫持/ConfigFS R/W，不能
  把该轮写成完整链成功。


## 2026-07-22 route-only scheduler/consumer diagnostic

- 为验证当前源码的 scheduler/PI consumer handoff，又以 NDK r29 构建隔离版本，宏为
  `DIRECT_WRITE_ROUTE_ONLY_PROBE=1`；该分支不调用 `set_pselect_write()`、不准备 fake kernel page，
  fops route 使用安全 fd_set/timerfd，仅测 route handoff。
- 产物：`exploit-repo/IonStack/CVE-2026-43499/exploit/build/violin-v-oss-route-diag-20260722/bin/preload.so`，
  170,248 bytes，SHA256 `8363b56a0fae924be5af710d9906f9b6e116d8ea0b6461422e379d0915eaf8fb`；清单：
  `analysis_outputs/device-route-diag-build-20260722/build-manifest.txt`。
- 已推送并以 shell `LD_PRELOAD` 运行；新日志：
  `analysis_outputs/device-route-diag-run-20260722/crash.txt`，SHA256
  `0616c41602c201af4464a21a6fe1cea42a4d6bd9456f17a6a4d65468f88a6bfa`。
- 关键证据：`ROUTE_PREP_REQUEUE ret=1 errno=0`；`ROUTE_ONLY_RET ret=0 errno=0 calls=200 success=200`；
  `ROUTE_ONLY_PROBE_DONE changed=0 route_done=1 ... cfi_step=0 errno=0`。运行前后 boot_id 均为
  `c79163bc-d9f5-457a-a30f-0362d89db8ea`，shell 仍 uid 2000，未重启。
- 结论：当前源码的普通 futex requeue、waiter handoff、consumer `sched_setattr` 循环和安全
  pselect/timerfd route 均可重复执行；这只闭合 scheduler/consumer transport 层，不证明 fake lock、
  rb_insert、fops 劫持、CFI ConfigFS R/W、pipe physrw 或 root。下一轮不能把 `calls=200` 当作
  kernel write 成功。

## 2026-07-22 CFI transport errno isolation

- 为定位旧 full-route `FOPSROUTE_CFI_RESULT step=1 errno=22`，在 `src/main.c` 增加默认关闭的
  `CFI_TRANSPORT_ONLY_DIAG=1` 分支。该分支只执行 `ASHMEM_SET_NAME` blob 设置和随后一次
  `pwrite()`，不创建 fake page、不调用 `set_pselect_write()`、不启动 scheduler route，也不写
  任意 kernel address。
- NDK r29 构建产物：`exploit-repo/IonStack/CVE-2026-43499/exploit/build/violin-v-oss-cfi-transport-diag-20260722/bin/preload.so`，
  SHA256 `916c683bf5789bfed6380bb5c5efd6ed17fadb66c782ecc189e283a3e990ec09`；清单：
  `analysis_outputs/device-cfi-transport-build-20260722/build-manifest.txt`。
- 设备日志：`analysis_outputs/device-cfi-transport-run-20260722/crash.txt`，SHA256
  `7e3282c8987dc1c3833b940b7ee8f8db22370045bd754b3f57dfff4f7730bfbd`。
- 关键证据：`CFI_TRANSPORT_SET_NAME ret=0 errno=0`，随后
  `CFI_TRANSPORT_PWRITE ret=-1 errno=22 payload_len=35`；`CFI_TRANSPORT_ONLY_DONE` 重复确认
  同一结果。boot_id 前后仍为 `c79163bc-d9f5-457a-a30f-0362d89db8ea`，设备未重启。
- 结论：旧 step 1 的 `EINVAL` 已精确归因到 **pre-hijack ashmem fd 的 pwrite 阶段**，不是
  `ASHMEM_SET_NAME` blob 设置失败。它仍不能单独区分 VFS 缺少 write_iter 与 ashmem size gate，
  但确认在 fops route 未将 fd 切到 `configfs_bin_write_iter` 前，ConfigFS 写入不可能成功；下一步
  应针对 fops slot 写入/readback 做独立闭合，不再重复调整 `fd_set`/`nfds`。

### 2026-07-22 offline fops/chain gate re-audit

重新执行 `audit_violin_primary_fops_gate.py` 和 `audit_violin_full_synthetic_chain_closure.py`。
raw image 对账确认目标是 `ashmem_misc+0x10`，其初值为 `&ashmem_fops`；`misc_fops.owner` 与
`poll` 为 NULL，因此旧的“无 NULL 字段”根因说法已 superseded。当前 active route 仍是
`poll(fd=-1,nfds=1)`，未闭合 `pselect_user_lock → fake_lock`，完整 synthetic chain 仍未闭合。
审计同时保留四个阻塞点：user-VA second lock、shape-1 后续 `W→F→W` 非终止循环、`owner=N`
module 身份未证实、无独立 first-stage pipe sink。下一步只做离线 pointer/lifetime/termination
状态表；不再修改 fd_set/nfds，不重跑 full-route。

### 2026-07-22 pointer/lifetime synthetic-chain state table

新增 `tools/audit_violin_pointer_lifetime_state_table.py`，离线生成
`analysis_outputs/violin-pointer-lifetime-state-table-20260722.{json,md}`。S0-S6 状态表确认：
payload shape 和普通 requeue transport 存在，但 active poll 没有 fake-lock edge，second lock
仍是 user VA，shape-1 目标和 owner/transport 仅条件成立，post-erase 会出现 `W→F→W` 循环。
verdict 仍为 `FULL_SYNTHETIC_CHAIN_NOT_CLOSED`；不运行 shape-1/full-route。

### 2026-07-22 expanded same-build second-lock inventory

为排除“另找一个静态 kernel `rt_mutex` 作为第二把锁”的误判，扩展并重跑
`tools/audit_violin_second_kernel_lock_inventory.py`。输入保持同一 build 的
`kallsyms.txt`、`analysis_outputs/ota_full/boot_parse/boot.img.kernel`、BTF 和
`kernel-src-wsl/common-gki`；本轮 `runtime_allowed=false`，没有构建、推送或联机运行。

- raw image 内 212 个名字包含 `mutex` 的 data symbols 全部符合普通 `struct mutex`
  初始化形状：`owner@+0=0`、`wait_lock@+0x8=0`、`wait_list@+0x10/+0x18` 自链；因此
  `console_mutex`、`tty_mutex`、`port_mutex`、`misc_mtx`、`ashmem_mutex` 等不能按
  `rt_mutex_base` 解读。之前把 `port_mutex` 读成 `po_rt_mutex` 的说法已更正。
- common-gki 中可见的 11 个 `DEFINE_RT_MUTEX` 测试对象（locktorture/locking-selftest）
  均不出现在该 exact build 的 kallsyms；唯一名字匹配的
  `rt_mutex_adjust_prio_chain.prev_max` 在 raw built-in image 外，是函数局部 scalar，
  不是锁对象。
- `rcu_state.node[0..2].boost_mtx` 的布局仍合法，但 raw `owner/waiters` 全零，且源码
  注释明确只用于 RCU priority-boost side effect，不提供稳定的第二 owner chain。

机器可读结果：`analysis_outputs/violin-second-kernel-lock-inventory-20260722.json` 中
`closed_distinct_second_lock=false`；下一步不得把普通 mutex、RCU boost 或 `fd_set/nfds`
调参当作修复。若无法离线闭合独立 lock 的 owner/waiters/lifetime，应归档 second-lock
分支并寻找独立首写 sink。

随后重跑 `tools/audit_violin_pointer_lifetime_state_table.py`，把该 negative inventory
回灌 S3；状态表仍为 `FULL_SYNTHETIC_CHAIN_NOT_CLOSED`，但 S3 的 blocker 现在有同一份
212-symbol raw 证据，不再只是“没有找到候选”的文字判断。

### 2026-07-22 read-only io_uring callback reachability

在不触碰 payload 的前提下，对已连接 Violin 做设备只读面核对，日志：
`analysis_outputs/device-readonly-uring-surface-20260722/inventory.txt`，SHA256
`81832E9C6F8664C7A2992FF0725A7E739F2EAB6CF52FD2FB57C257503A9A1DD7`。

- 设备身份是 `uid=2000(shell)`、SELinux Enforcing，boot_id 仍为
  `c79163bc-d9f5-457a-a30f-0362d89db8ea`。
- `/dev/ublk-control` 存在但为 `root:root 0600`、`ublk_control_device` label，shell 对它的
  read/write 测试均失败；`/dev/nvme0`、`/dev/kvm` 不存在；`/proc/modules` 没有对应模块。
- 结合 raw static fops callback inventory，当前 shell 可达的已知 `uring_cmd` 路径不产生
  arbitrary kernel-write sink；记录为 `CURRENT_SHELL_NO_REACHABLE_IO_URING_WRITE_SINK`。
  该结论只针对当前身份/设备状态，不能替代对 generic `io_uring_cmd` 全部特权 callback 的
  全局闭合。

### 2026-07-22 supplied artifact consistency

对用户提供的三份 ZIP 与四份 loose 采集文件做离线一致性审计，工具为
`tools/audit_violin_artifact_consistency.py`，报告为
`analysis_outputs/violin-artifact-consistency-20260722.{json,md}`；没有构建、推送或运行 payload。

- 三份 `kallsyms` 的绝对基址不同，但 `100433` 个唯一公共 in-image 符号的相对偏移完全一致；
  `anon_pipe_buf_ops +0x114a288`、`misc_fops +0x1269710`、`ashmem_fops +0x12c9df0`、
  `ashmem_misc +0x223b5d8` 等核心锚点一致。11 个非核心差异均为末端 vendor/`a` 数据符号。
- fingerprint 相同，且 `uname` 与 `version` release 均为 `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`；cmdline 仅在 `bootinfo.pdreason=0x0/0x3` 上不同。artifact boot_id
  `2988e1dc-3130-4ba7-9985-74a91a2296cd`、`46b498dc-6a0c-4d36-b6b1-9c85da32a7fc` 与现有设备
  只读记录 `c79163bc-d9f5-457a-a30f-0362d89db8ea` 不同，绝对 KASLR 地址不可跨快照复用。
- `ionstack-current-ktext` 清单 4/4 通过；`1.zip` 为 33/35 通过，失败为自引用清单项和
  `collector.log`。其 tombstone/filtered log 均不是 GHOSTLOCK 成功证据。

结论：`SAME_BUILD_OFFSETS_CONFIRMED_SNAPSHOT_BASES_NOT_INTERCHANGEABLE`；下一步只允许同 boot
KASLR leak 与 target readback 对账，不能把历史绝对地址直接带入新运行。

### 2026-07-22 `sched_blocked_reason` / fake-lock claim cross-check

新增离线报告 `analysis_outputs/violin-sched-blocked-fake-lock-claim-audit-20260722.md`。

- `sched_blocked_reason` 的 `__get_wchan()` raw KASLR oracle 以及 D-state wakeup 触发条件
  已由 common-gki source 对上；范围只能写成同 build、同 boot、具备 tracefs/raw-read 条件的
  shell oracle，不能泛化为所有 tracefs 环境，也不能当作 write/root 证据。
- `task+0x938 -> pi_blocked_on`、`waiter+0x58 -> lock` offsets 对，但当前 active route
  仍是 `poll(fd=-1,nfds=1)`，没有 `pselect_user_lock -> fake_lock` 的已证实数据边；W=5
  pselect 是显式 HEAD/诊断分支，不能与 poll route 混用。
- `rt_mutex_adjust_prio_chain()` 对 `waiter->lock` 直接 `raw_spin_trylock`；Violin exact
  build 启用 `CONFIG_ARM64_PAN` 与 `CONFIG_ARM64_SW_TTBR0_PAN`，所以第二轮 user-VA lock
  不是已闭合的 kernel `rt_mutex_base`。PI traversal 也不等于 SELinux write。
- raw `brk #0x800` 先由 waiter `lock` 与当前 lock 不一致的分支跳入，吻合内联
  `rt_mutex_top_waiter()` 的 `BUG_ON(w->lock != lock)`；common `rt_mutex_setprio()` 只有
  idle 分支 `WARN_ON(p->pi_blocked_on)`，不存在“非空即 BRK”的通用条件；“前 16 轮安全”
  未证实。
- fd 0-2 覆盖、consumer warm-up、`punch_consume_go` 过早清零均为分支特定时序问题：
  custom dup2 会覆盖 0-2，default 已跳过；default poll 在返回后等待 consumer，显式
  pselect probe 才会立即清零。最终 verdict 仍为 `FULL_SYNTHETIC_CHAIN_NOT_CLOSED`，
  本轮没有构建、安装、联机或运行新 payload。

下一步决策：先闭合 `analysis_outputs/violin-provenance-manifest-20260722.md` 的 artifact
provenance（当前 accepted complete tuples=0），把 `PROJECT=violin-v-oss`、source map、
preload hash 与 run log 绑定；然后冻结当前 poll baseline，离线补齐 active route、
second-lock owner/lifetime、终止性和 fops readback 四项门禁。当前 second-lock inventory
为 negative，若没有新 canonical kernel lock 证据就归档该 fops/PI anchor，转向独立首写
sink。门禁闭合前不再调 `fd_set`/`nfds`/consumer 次数，也不运行 full-route；设备侧最多做
带 stop gate 的 `boot_id/KASLR/target-readback` 只读诊断。

### 2026-07-22 active route-state alignment

为开始下一轮实施前固定 artifact 边界，新增 `tools/audit_violin_active_route_state.py`，并
完成 `py_compile=0` 与离线执行。报告：
`analysis_outputs/violin-active-route-state-20260722.{json,md}`。

- `cfgprobe_diag`（`CFGPROBE_ONLY_DIAG=1`）、`route_only_diag`
  （`DIRECT_WRITE_ROUTE_ONLY_PROBE=1`）和 `cfi_transport_diag`
  （`CFI_TRANSPORT_ONLY_DIAG=1`）三组均通过 `PROJECT=violin-v-oss`、ELF hash/size、run
  hash、`run_exit=0`、同 boot_id 和 crash marker 对账；对应 SHA256 分别为
  `cb71799ce82f3ae8a62b1226c7fc332a7ec54d9746d4679e463ff0d481c84662`、
  `8363b56a0fae924be5af710d9906f9b6e116d8ea0b6461422e379d0915eaf8fb`、
  `916c683bf5789bfed6380bb5c5efd6ed17fadb66c782ecc189e283a3e990ec09`。
- marker 对账只证明三个诊断分支分别停在 cfgprobe、safe route handoff、ConfigFS
  name/pwrite；没有 fops slot readback、kernel write、cred 或 SELinux 证据。
- 未带 2026-07-22 tuple 的 `build/violin-v-oss/bin/preload.so` 已因旧于当前 source 且
  可能包含 full-route marker 被隔离，禁止复用。
- 本轮没有 ADB 设备（`adb devices -l` 为空），因此没有新的在线动作。设备恢复后先做
  `boot_id/KASLR/target readback` 只读对账，再决定是否进入下一道单变量诊断；不直接运行
  full-route。

### 2026-07-22 provenance correction

将 build manifest 的 source hash block 纳入严格检查后，修正“当前 diagnostic tuple 已完整”
的过宽结论；`analysis_outputs/violin-current-diag-tuples-20260722.{json,md}` 和
`analysis_outputs/violin-active-route-state-20260722.{json,md}` 现明确为
`all_diagnostic_tuples_complete=false`。

- `cfgprobe_diag` 的 `src/main.c` manifest hash 是
  `ac509d7786173ccfc4c80f7ae0f43811da0e96f74d0c800b8fd18bddb392b6d5`，当前 source 为
  `9984a41b58383605913f7f79e4e207fe3b0d39fafc1e49cc34250d6b7b365f85`，因此 source stale。
- `route_only_diag` 没有 source hash block；`cfi_transport_diag` 仅记录 `main.c`，其余
  tracked source 缺失。三组 hash/size/run/boot/marker 仍能和各自 manifest 对上，但不能
  升级成 current-source complete tuple。
- 修正后的最优下一步是使用同一 `PROJECT=violin-v-oss` source map 重新构建诊断产物、补齐
  8 个 tracked source hash 和 run manifest；设备恢复前不把现有 artifact 当作新 payload。

### 2026-07-22 fresh source-bound diagnostic builds

使用 WSL NDK r29 执行 `tools/build_violin_fresh_diag_tuples.sh`，再用
`tools/record_violin_fresh_diag_builds.py` 记录 build-only provenance。编译命令未调用 ADB，
未安装、未运行 payload；`py_compile=0`，三个 ELF 均为 Android arm64 shared object。

- cfgprobe：`ed918dfabf61c5c53e7b1bfe5a99bc946dc77385939458ee1d38ababc6adb2e8`，173328 bytes；
- route-only：`81e17de80d9f6720e28e3886abb5bdd17a9d62ac2ab56382699ddbd1cb63c099`，170032 bytes；
- cfi-transport：`f833c5a9f33b2f6d07a11f9ba65148b8bc5081638e343d5d7169f81eff703cf6`，171704 bytes。

每个 build manifest 都包含 8 个 tracked source SHA256、显式 `PROJECT=violin-v-oss`、宏和
输出 hash/size；JSON 为 `analysis_outputs/violin-fresh-diag-builds-20260722.json`。当前仍
没有设备 run manifest，下一步只需同 hash/同 boot 做最小诊断，不得把 build-only 证据升级为
fops、kernel write 或 root 证据。

### 17.69 Interrupted-run recovery log analysis（2026-07-23）

恢复附件已保存为 `analysis_outputs/ionstack-recovery-20260723/`：原始 `run.log` 26599 bytes，SHA256
`7aee1c46dcaabd82df976fa46ad1dddf91874d95e65a91904093b8ad25949c4f`；`summary.json` 保存逐项计数，
`report.md` 保存证据边界和下一步。`result` 只有 gate bypass、CPU=9/consumer=2、preload pid=10616
以及 pselect 入口，`result.done` 缺失。单独的 `crash.txt` 块含 16 次完整 slide 尝试和第 17 次开始，
pselect/consumer marker 可见，但每次 `SLIDER2_BAD` 后均 `no stext`。其 STEP0 pid=17785 与 result pid
不同，且缺 selected binary/hash/source/run manifest，因此只能作为 unbound instrumented trace，不能算已发布
r4 的设备证明。`SLIDER2_BAD=0xa84effde6235b8d2` 与 trace 中 boot_id 前 16 个 hex 字符 little-endian 完全
相同，确定 oracle 仍读普通 boot_id 文本；无 KASLR、fops、pipe、cred、SELinux 或 root 证据。当前 boot_id
已改变，确认发生重启/掉电，但 boot reason/pstore/last_kmsg 未提供原因。下一步离线绑定 binary/source 并做
单次、可停止的 slide target/readback 审计，不再直接重复 20 次循环。

补充：该 unbound `crash.txt` 同时打印 `sysctl_bootid_direct=0xffffffbffa756f58` 与
`SLIDE2 bootid_data=0xffffff8002546f58`（差 `0x3ff8210000`），应先完成 direct-map/P0-alias 地址域对账。

### 17.70 Linuxoid upstream generator audit（2026-07-23）

已核对 Linuxoid-cn 仓库 `main=a4106311a6035ce0a7831860a255a4ded310bfcc` 与
`secret=e03994331634f8c03ed1df51a4e9fc551ef8e5f1`；generator 和核心 C 源 hash 相同，main 仅有 README
示例变更。`generate_target.py` 能从 boot.img 的 IKCONFIG/kallsyms/BTF 和反汇编推导 target.h，补足
pselect/futex、nf logger、boot_id.data 等硬编码 offset；但 profile 仍要求两个 p0 地址，detect_offset.py
只读 root `/proc/iomem`，没有 XBL/DTB 解析。

使用现有 Violin `boot.img`（100663296 bytes，SHA256
`140f57f5aeb591913aeaa5e554e2dd7ec32d6c8b197f86f39f06d8fbdb13573`）和 profile 0x0/0x210000 运行失败：
`IKCONFIG 标记不唯一或顺序错误: starts=[], ends=[]`。因此当前 boot 无法直接生成 target.h。上游 slide.c
仍解析普通 boot_id 文本为“泄漏指针”，没有修复 `SLIDER2_BAD`；release 资产没有 violin。完整命令和日志
见 `analysis_outputs/linuxoid-cve-2026-43499-upstream-20260723/`。

### 17.71 7sp screenshot functional evidence（2026-07-23）

用户截图已保存到 `analysis_outputs/7sp-local-run-evidence-20260723/`。截图显示 `p.so` 的 permissive-only
结果（getenforce=Permissive、enforcing=0），以及干净重启后 `r.so` 的 direct-root 结果（got_root=1、
uid/euid=0、root proof 内容 root、属主 root:root）。附件三个 ELF hash 已复核并写入该目录 manifest。
截图没有 boot_id、device fingerprint、run id、artifact/source hash，且没有 r2.so 证据；所以这是两次功能
结果证据，不是完整 provenance/可复现性证明。下一次只跑 hash 绑定的 r.so，并把 run tuple 写入日志。

### 17.72 XBL/DTB mem-label profile audit（2026-07-23）

用户提出的 NOMAP/Kernel 节点提取法在原理上正确。已核对 popsicle 的实现：扫描 `xbl_config` 中所有
`FDT_MAGIC`，严格验证 FDT header、结构块/字符串块边界、token 闭合、父节点 cell 数和 `reg` 完整性，
再要求同一 DTB 中唯一的 `/memorymap/` `NOMAP`/`Kernel` pair；最终计算
`phys_offset = NOMAP.base & -0x40000000`、`kernel_phys_load = Kernel.base`，并检查 4K 对齐、冲突 map、
Kernel 区域是否容纳 boot Image。`xbl_config` 不是 `dtbo.img` 的同义词，不能只把任意 DTB 代入 profile。

已对 Dijun factory tgz 做只读扫描：归档中相关文件为 `dtbo.img`（8 个有效 DTB）、`sec_dtb.img`、
`sec_uefi.img`、`sec_xloader.img`、`sec_xloader_usb.img`；它们均未出现 `NOMAP`、`Kernel` 或 `mem-label`
字符串，归档名中也没有独立 `xbl_config`。这只说明当前候选文件未命中，不能排除 xbl_config 嵌入
sec_xloader/UEFI 或需从设备分区 dump；结果见 `analysis_outputs/dijun-xbl-dtb-scan-20260723/`。

`Dere3046/xbl-dtb` 可用于快速枚举，但解析校验较轻，不能直接替代严格生成器。XBL profile 只能补齐
物理地址输入，不能解决 Violin 当前 `SLIDER2_BAD`/readback 阻塞，也不能单独证明后续 fops、pipe 或 root。

### 17.73 Violin p.so browser-stage failure（2026-07-23）

设备重新连接后只做了只读对账：serial `03035440C1781540`、Violin fingerprint、Firefox `151.0`、
`boot_id=b27dcce4-4ba1-413f-a8ff-d9b1ab9fe14a`，SELinux=`Enforcing`。实时 Pages `p.so` 为
83632 bytes，SHA256 与附件 `edd44e0c17781f0d63935dc1938b81fdcdc981f7221392117effb54e26e6cc81`
一致。

用户日志中的三个 iframe 都在 JS 阶段得到 `typedWord=carrierWord=0x7ff8000000000000`。
按 IEEE-754 解释这是 quiet NaN；它不满足当前页面的 canonical user-pointer 条件，说明 typed/carrier
泄漏没有建立。没有出现 AAW/AAR/ADDROF/RW64/MPROTECT 或 native preload marker，故本轮尚未进入
`p.so` 内核路径，不能归因于 KASLR/fops，也不能升级为 permissive/root 失败。

报告：`analysis_outputs/violin-p-js-failure-20260723/{manifest.json,report.md}`。下一步先做 JS-only
gate probe，绑定 Firefox build、页面版本和失败码；不原样重试 p.so。


### 17.74 In-place cred patch isolated build and target-base provenance（2026-07-23）

- 本轮没有推送设备、没有 Pages 发布、没有运行 payload；只在 `session-20260723-cred-patch/build-so/` 做隔离源码构建和静态核验。项目级同 boot 只读门禁继续有效。
- 已确认附件 `r.so` 的 `run_exploit` 反汇编直接编码 `PER_CPU_OFFSET=0xffffffc0820cb658`、`ENTRY_TASK=0xffffffc082096328`、`INIT_CRED=0xffffffc0820f0548`，因此其 image base 是 `0xffffffc080000000`。当前 exploit/旧 target 文档中的 `0xffffffc008000000` 不可直接用于复现该预编译 r 产物；这解释了新编译产物与 r.so 不能按“同源码/同 target”看待，并是 pselect 超时排查的首个构建来源差异。
- 在 `build-so/source/` 使用 external Linuxoid snapshot commit `e03994331634f8c03ed1df51a4e9fc551ef8e5f1` 的 direct 架构实现候选：shape-0 读取 `task->real_cred`/`task->cred`，只 patch 指针指向的 cred 对象；每个对象写 `+8,+16,+24,+32` 的零 uid/gid qword、`+40` 的零 securebits qword、`+48,+56,+64,+72,+80` 的 `CAP_FULL`。不改 cred pointer slots、不改 `cred+128` security、不改 kernel `selinux_enforcing`，也不读取/写入 `/sys/fs/selinux/load`。
- `/tmp/ndk` API35 clang 构建通过。未修改 direct baseline：88528 bytes，SHA256 `72fddecfa550b4e34450cdfdfc2eff4a7f56e2b866ef720cd4e66d17fbb4cce2`；in-place 候选：89800 bytes，SHA256 `31997ea1ff19ce6b831cbf0f4c73a041a5458e9a5ead080b238a09b3e1185920`。两者均为 AArch64 DYN；候选静态检查到 `direct_cred_patch_inplace`/`direct_read_qword_retry`，且无 policy reload/followup helper 和 `/sys/fs/selinux/load` 字符串。
- 证据文件：`session-20260723-cred-patch/build-so/BUILD-MANIFEST.md`、`build-so/source/src/main.c`、`build-so/source/src/target.h`。候选没有 runtime proof，下一步不能把 build hash 或候选 `root_ok` 判定升级为设备 root。


### 17.75 Online r1p dump cleanup exposed SELinux/framework failure; cred-only patch（2026-07-23）

- 按用户授权在设备 `03035440C1781540` 上推送并核对 `r1p.so`：86464 bytes，SHA256 `DE94AE077660A7C926A7B22B5754C6AA592ABAE7FBE83E17E98444AE1A03A1AB`。设备初始 `boot_id=159283d4-29f1-47a6-af57-6e434bc0e06b`、`getenforce=1`；`/data/local/tmp/dump` 已存在但 shell 无权访问，`rm -rf` 返回 `Permission denied`。
- 一次预载尝试使设备进入异常态并重新出现：随后 `boot_id=40b8bc02-80ff-ffff-888b-3f0280ffffff`、`getenforce=Permissive`、shell `context=?`；`service list` 为 `Found 0 services`，`dumpsys SurfaceFlinger` 为 `Can't find service: SurfaceFlinger`，进程列表中只可见 `adbd`。因此黑屏不是单纯 UI 亮度问题，而是 framework/SELinux/内核状态被破坏；`sys.boot_completed=1` 不能作为健康证明。普通 `adb reboot` 和 `setprop sys.powerctl reboot,userrequested` 均因当前 shell 权限/异常态失败，需设备实体/fastboot/recovery 重启后再做 runtime 验证。
- dump 清理已完成：删除 `/data/local/tmp/dump` 和同轮产生的 `/data/local/tmp/zump`，再创建 `/data/local/tmp/dump` 的 0 字节、`----------` 文件 guard；设备当前 `df -k /data/local/tmp` 为 503803840 total、111122576 available、78% used，后续不能再让 exploit 创建 dump 目录。
- 反汇编定位到 `r1p.so` `run_exploit+0x4dc`（VA `0xf8f8`，文件偏移 `0xb8f8`）调用 `direct_trigger_write64`，其前置 target 为 `SELINUX_ENFORCING=0xffffffc082315f68`；这正是运行后 `getenforce=Permissive` 的直接证据。另两处字符串 patch 仍为 `/data/local/tmp/zump` 与 `/sys/fs/selinux/zzzz`。
- 已生成并推送 `r1p-cred-only.so`：只把 `0xb8f8` 的 `bl direct_trigger_write64` 改为 `mov w0,wzr`，跳过 `selinux_enforcing` 写入；保留 cred 路径、dump guard 和 policy-reload 路径 patch。产物 86464 bytes，SHA256 `3F59E5D825D3145E66E95B95E9294606CD02225454DD4B717554F3FEA9A5E02B`，设备路径 `/data/local/tmp/r1p-cred-only.so`，远端 hash/size 已核对一致。
- `r1p-cred-only.so` 目前只有静态/推送证据，尚无“Enforcing 下仍可 root 且 framework 存活”的 runtime proof；session handoff 中已知“只跳过 selinux_zero、仍替换整个 cred 指针”可能失去可用 root。因此最终方案仍应优先修复 `build-so` 的 in-place cred patch/pselect，而不是把本次 binary patch 当成完成。


### 17.76 Cred-only safe run：Enforcing/framework 保持，root 阶段仍失败（2026-07-23）

- 在 clean boot `boot_id=85cc2589-0274-4fe6-894d-84ada0eedc58`、`getenforce=Enforcing` 上运行 `/data/local/tmp/r1p-cred-only-safe.so`（86464 bytes，SHA256 `F5AF873B3758A6156F28B66384A166C97E080473821CE958C30EB1EFE4B1CCFD`）。该变体同时将目录与镜像格式串改为只读无效路径 `/proc/no_such`、`/proc/no_such/%s.img`，不依赖 dump guard。
- native 输出成功到 `slide-kaslr-ok`、`direct-percpu`、`direct-entry`，并明确打印 `direct pre-cred selinux preserved enforcing=1`；之后对 `task->real_cred` 与 `task->cred` 槽做整指针写入，进程以 `adb_exit=255` 结束，未产生 uid/gid=0 或 `root_proof`。这证明 SELinux 写入是可移除的，但整 cred 指针路径仍不是可用 root。
- 运行后立即核对：`getenforce=Enforcing`、`service list=439`、`SurfaceFlinger` 存在、window focus 为 Launcher，未复现此前 framework 黑屏；随后主动 `adb reboot`，最终 clean boot 为 `boot_id=50c73656-3757-48a2-aaca-87475ba345a0`、`getenforce=Enforcing`、`service list=438`，`df` 可用 `189507496 KiB`（63% used）。
- 当前结论：黑屏链路已定位并由 cred-only safe 变体规避；“root 成功且不黑屏”尚未闭环。下一步只应修复 `build-so` in-place cred/pselect 失败，不应再运行会替换整个 `task->cred` 指针的 r1p 变体。

### 17.77 In-place candidate CPU-mask run：仍在 sched_setattr 前重启（2026-07-23）

- 将 `build-so/source` 的 consumer 选择恢复为“当前 caller affinity 中除 direct CPU 外的第一个 online CPU”，不再硬编码 CPU1；用 `taskset 3fc` 模拟 app/browser 常见的 `2-9` mask。构建命令为 `make clean preload NDK_ROOT=/tmp/ndk SKIP_CHALLENGE_GATE=1`，产物 87296 bytes，SHA256 `82ED208C88157A49031CC26C3520B1C188C922EFE4AF5B94275005E0AD2921C6`，设备路径 `/data/local/tmp/inplace-preload-cpu2.so`。
- 运行 marker 为 `direct_cpu=9`、`consumer_cpu=2`、`enforce=1`，随后到 `slide consumer before sched ... alive_ret=0`；没有 `slide consumer sched`、pselect return、cred 或 root marker，设备随即重启。故该失败发生在 scheduler/pselect route，早于 cred/SELinux 阶段，不能继续归因于 SELinux。
- 重启恢复后再次核对：`boot_id=61077774-2417-476d-8a66-1cb98ed4e7c8`、`getenforce=Enforcing`、`sys.boot_completed=1`、service count=438、`/data/user/0` 63% used / 189517652 KiB available。完整记录：`analysis_outputs/7sp-inplace-cpu2-run-20260723/report.md`。
- 当前门禁：SELinux/dump 黑屏防护保持有效；`root_proof=false`。下一步只做离线 pselect/scheduler 对齐，禁止继续运行 old r1p whole-cred-pointer 变体。


### 17.60 Stage-2 root_stage wiring and 7sp artifact audit（2026-07-22）

用户指出第一阶段 permissive 不能替代第二阶段 root_stage。已在当前 Violin source 中将 root 阶段显式接入 `try_cfi_stage -> install_child_root -> install_pipe_physrw -> root_stage -> install_android_root`，并给 `root_stage` 加 transport proof gate（cache、read/write、read64/write64）与失败 child 回收。旧的 ConfigFS partial fake-cred 路径由 `LEGACY_CONFIGFS_CRED_STAGE=0` 默认关闭，避免错误的半成品 cred 覆盖新的 root path。

离线审计脚本 `tools/audit_violin_root_stage_reachability.py` 已通过 `py_compile` 并生成 `analysis_outputs/violin-root-stage-reachability-20260722.{json,md}`；call graph verdict 为 `ROOT_STAGE_CALL_GRAPH_CONNECTED_LEGACY_PARTIAL_CRED_DISABLED`，但 `runtime_proof=false`。build-only 产物 SHA256 为 `da44ed17e16190e5fc99320666fe8b3fab9577589d62b0a25fba5abdb0b95a82`（176184 bytes），manifest 为 `analysis_outputs/violin-root-stage-build-20260722/build-manifest.txt`。

附件 `7sp_permissive和root.zip` 的 `p.so/r.so/r2.so` 均为 AArch64；静态 marker 分别对应 permissive-only、direct-root、direct-root+reboot。三者没有 source/run manifest，不能证明设备上成功；r2 含 reboot 字符串，不作为首选。当前仍没有设备 run tuple，下一步必须在设备恢复后按 hash 做同 boot 只读对账，再决定最小在线诊断。

- 额外修正 `spawn_root_child()`：父进程关闭 ready-pipe 写端后立即把槽位置 `-1`，避免后续失败清理因 fd 号复用误关其他描述符；修正后重新 build，产物 hash 已更新。

### 17.61 7sp variants published（2026-07-22）

按用户要求，将 `7sp_permissive和root.zip` 的 `p.so/r.so/r2.so` 发布到 `liang1228/ionstack-violin` 的 `master`，commit `0b56a19447d0d683470cbc8ab16c18b846db993e`。`exploit.html` 新增 `payload=p/r/r2` 映射，并新增 `7sp-root-variants-20260722.md` 记录 hash/尺寸与截图证据边界。

GitHub Pages API 状态为 `built`，页面为 `https://liang1228.github.io/ionstack-violin/`；raw 和 Pages 下载的三个二进制 hash/size 均与本地一致。截图可证明一次 direct-root（uid/euid/gid/egid=0、`got_root=1`、`whoami=root`），但没有文件名/source hash/boot_id，不能据此证明三个文件都可用。

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

### 17.65 `r3.so` published to the new Pages selector（2026-07-22）

- 已将 CPU-affinity 修复候选作为独立 `r3.so` 发布，不覆盖 `r.so`/`r2.so`；`exploit.html` 新增 `?payload=r3` 映射。
- Git commit：`7449577d850732d973ce79028cee386c1e270450`，已推送到 `liang1228/ionstack-violin` 的 `master`。
- 本地、raw GitHub 和 GitHub Pages 下载均为 89264 bytes，SHA256 均为 `657bdb47745c59cb8157ad7afbf2dd7b8f7b34487040406764e1a0b9c33f6744`；Pages `exploit.html` 的 r3 selector 和脚本语法复核通过。
- 新运行入口：`https://liang1228.github.io/ionstack-violin/?payload=r3&run=violin-r3-20260722-01`。采集入口仍用对应 `?diag=crash&run=...`。
- 该发布只证明页面/文件 provenance 与静态构建，不证明设备上的 KASLR、PI、fops、pipe physrw 或 root；首次运行需保留完整 `runtime performance cpu`、`consumer_cpu/shared`、`slide`、`direct-*`/`ROOT_STAGE-*` marker。
- 发布复核清单：`analysis_outputs/ionstack-violin-publish-20260722/publish-r3-manifest-20260722.txt`。

### 17.66 `r3.so` online run reached only the Challenge Gate; `r4.so` build candidate (2026-07-22)

- Violin run `run=mrw8pc555d278ze1kdp` selected `r3.so` size 89264. Browser-side `AAW/AAR/ADDROF/RW64/MPROTECT_READY` all passed and the prior `sched_setaffinity(EINVAL)` marker did not recur.
- Native output stopped at `[Challenge] vw8e0d5ki964toad` / `[Signature] Enter value:`. Because `exploit.html` starts `LD_PRELOAD=$file /system/bin/sh` without stdin signature, the constructor returned before `preload starting`; `command_status=0` means shell exit only, not exploit/root success.
- Full log/report: `analysis_outputs/ionstack-violin-r3-challenge-gate-20260722/{run.log,report.md}`. No `runtime performance`, `slide`, `direct-*`, `ROOT_STAGE-*`, KASLR, PI, fops, pipe, cred or SELinux proof exists for this run.
- Built independent `r4.so` from the r3 CPU-affinity source with only `IONSTACK_SKIP_CHALLENGE_GATE=1`; runtime marker is `[Challenge] disabled_for_violin_test`. Artifact is 86224 bytes, SHA256 `151208b0c6e06d721f11dca558359cc87bb90c2decb8025f9f1c22a163a49c92`; manifest: `analysis_outputs/violin-r4-gate-bypass-20260722/build-manifest.txt`. Static AArch64 ELF verification passed; `runtime_proof=false`.
- r3/r2/r remain unchanged. Next online run must use the new `?payload=r4` selector and preserve the first native markers; do not interpret the gate-bypass build or `command_status=0` as root evidence.

### 17.67 `r4.so` published and Pages live verification (2026-07-22)

- `r4.so` was published independently; `r3.so`, `r2.so`, `r.so` and `p.so` were not overwritten. Commit `00bd272` on `liang1228/ionstack-violin` adds `r4.so`, the `?payload=r4` selector and the variant note.
- Local, raw GitHub and GitHub Pages downloads all returned 86224 bytes with SHA256 `151208b0c6e06d721f11dca558359cc87bb90c2decb8025f9f1c22a163a49c92`; Pages selector/script check passed. Manifest: `analysis_outputs/ionstack-violin-publish-20260722/publish-r4-manifest-20260722.txt`.
- Run URL: `https://liang1228.github.io/ionstack-violin/?payload=r4&run=violin-r4-20260722-01`; capture URL: `https://liang1228.github.io/ionstack-violin/?diag=crash&run=violin-r4-20260722-01`.
- This publication proves only asset provenance and static build. `r4` has no device runtime/root proof; the first useful markers are `[Challenge] disabled_for_violin_test`, `preload starting`, `runtime performance`, `slide`, `direct-*`, `ROOT_STAGE-*`, and final uid/SELinux/transport evidence.

### 17.68 Read-only interrupted-run recovery page (2026-07-22)

- 用户反馈 r4 运行中设备关机，浏览器端无法保存最后一段日志。页面已有 localStorage/webhook，但最后 native 输出可能在父页面收到前丢失。
- `exploit.html` 新增 `?diag=recover`，只读读取 `/data/data/org.mozilla.firefox/files/result`、`result.done`、`crash.txt`、当前 `boot_id`、`uptime`，以及 `sys.boot.reason`、`ro.boot.bootreason`、`/sys/fs/pstore` 列表和 `/proc/last_kmsg`；不会下载/执行 payload，也不会删除结果文件。
- 页面修复已推送：commits `1dd1ac6`、`06d3f7f`；最终 Pages HTML 已复核包含 recovery 分支和 reboot-reason commands。
- 设备重新开机后先打开 `https://liang1228.github.io/ionstack-violin/?diag=recover&run=violin-r4-recover-20260722-01`，下载完整输出；再视结果决定是否运行 r4。若结果文件均为 `__MISSING__`，本次 native 日志无法从设备文件恢复，只能记录为 power-loss/no-runtime-proof。

### 17.78 jinghu v13 设备前置核对与放置（2026-07-28）

- 用户提供的 `E:\ZEOON3\Downloads\preload_jinghu_v13.so` 与交付 ZIP 的 `SHA256SUMS.txt` 一致：6,901,024 bytes，SHA256 `4c202c6545e42afbc287ec392de20c01b35c3595ed9db0ac59d148394e839e8b`。已保留原文件，并生成同 hash 的 `E:\ZEOON3\Downloads\preload.so`。
- 已将该副本推送到当前 ADB 设备 `0401481180981540` 的 `/storage/emulated/0/preload.so`；远端大小与 SHA256 均复核一致。
- 当前连接设备只读身份为 `violin` / `Xiaomi/violin/violin:15/AP3A.240905.015.A2/OS2.0.217.0.VOTCNXM:user/release-keys`，内核 `6.6.77-android15-8-g561b227c0e7d-abogki425270610-4k`，boot ID `816974bf-f24b-4551-aad8-9398a984590d`，SELinux `Enforcing`。
- v13 交付包明确要求 `jinghu` 精确内核 `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`；当前设备的设备代号与内核编译号均不匹配，不能把本 SO 作为当前设备的可验证运行候选。
- 当前设备未安装 `moe.shizuku.privileged.api` 或 `in.sunilpaulmathew.ashell`，本机 Downloads 也没有对应 APK；本轮未进行 Shizuku 授权或 `LD_PRELOAD` 执行。
- 下一步门槛：连接精确的 `jinghu` 设备，并在同一次干净启动中复核 `uname -r` 与交付包完全一致、安装并启动 Shizuku/aShell 后，才可按交付说明运行一次并记录 `ko/ksud` 输出。

### 17.79 安装 Shizuku 13.6.0（2026-07-28）

- 用户提供的 `E:\ZEOON3\Downloads\Compressed\shizuku-v13.6.0.r1086.2650830c-release.apk` 已核验：2,571,773 bytes，SHA256 `6e273ab0e991c4e79bc8b1bbb9b9dd739ccac1a8712a541a214078886b7b790f`。
- 已通过 ADB 安装到设备 `0401481180981540`；包名 `moe.shizuku.privileged.api`，versionName `13.6.0.r1086.2650830c`，versionCode `1086`，远端 APK 路径已由 `pm path` 复核。
- 当前设备仍未安装 `in.sunilpaulmathew.ashell`，因此尚未进行 Shizuku 服务授权或 aShell 执行；jinghu/violin 内核不匹配门禁仍有效。

### 17.80 jinghu v13 Shizuku/aShell 单次实跑结果（2026-07-28）

- 已按用户授权安装并启动 Shizuku：`E:\ZEOON3\Downloads\Compressed\shizuku-v13.6.0.r1086.2650830c-release.apk`，2,571,773 bytes，SHA256 `6e273ab0e991c4e79bc8b1bbb9b9dd739ccac1a8712a541a214078886b7b790f`；Shizuku 服务通过 ADB 运行，aShell You 已获授权，Shizuku 页面显示已授权 1 个应用。
- 已安装并使用 `E:\ZEOON3\Downloads\Compressed\aShellYou-v7.4.0-fdroid-release.apk`，11,490,894 bytes，SHA256 `0ff9a694fcdb2dafd5661cac285a49b4541c7b33bc38e8e1aebaffa5a48e34b2`；aShell 当前模式为 `Shizuku`。
- 通过 aShell/Shizuku 执行 `cp /storage/emulated/0/preload.so /data/local/tmp/preload.so`，远端文件为 6,901,024 bytes，SHA256 `4c202c6545e42afbc287ec392de20c01b35c3595ed9db0ac59d148394e839e8b`，与 `E:\ZEOON3\Downloads\preload_jinghu_v13.so` / `E:\ZEOON3\Downloads\preload.so` 一致。
- 已单次执行 `LD_PRELOAD=/data/local/tmp/preload.so /system/bin/true`。native 输出确认已加载并进入 slide 阶段：`preload starting`、`runtime performance`、`startup`、`slide attempt 1`、`pselect returned ret=5 errno=0 calls=1 sched_ok=1`；最后输出为 `slide bad leaked pointer=51454bf2bf746981`。
- 本次没有出现 `ko=1 ksud=1`，因此不能判定成功；没有重复执行。执行前后 `boot_id` 均为 `816974bf-f24b-4551-aad8-9398a984590d`，设备保持在线，`getenforce=Enforcing`、`sys.boot_completed=1`、service count=417、SurfaceFlinger PID=1477，未发生重启或框架异常。
- 当前运行设备仍是 `violin`，内核 `6.6.77-android15-8-g561b227c0e7d-abogki425270610-4k`；交付包要求的 `jinghu` 内核为 `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`。本次证据证明“payload 已加载但在 slide 阶段失败”，不证明该 SO 在精确 `jinghu` 设备上的结果。原始 aShell UI XML 与报告见 `analysis_outputs/jinghu-v13-shizuku-ashell-run-20260728/`。

### 17.81 系统更新后 jinghu v13 精确内核单次复测（2026-07-28）

- 系统更新后设备已从旧的 `g561...abogki425270610-4k` 切换为 README 要求的精确内核 `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`；fingerprint 为 `Xiaomi/violin/violin:16/BP2A.250605.031.A3/OS3.0.303.0.WOTCNXM:user/release-keys`，兼容性门禁通过。
- 在同一干净启动中，使用已核验的 `preload.so`（6,901,024 bytes，SHA256 `4c202c6545e42afbc287ec392de20c01b35c3595ed9db0ac59d148394e839e8b`）通过 Shizuku/aShell 单次执行 `LD_PRELOAD=/data/local/tmp/preload.so /system/bin/true`。
- native 输出进入 pselect slide：`slide child pid=21605 uid=2000 direct_cpu=9`、`pselect returned ret=5 errno=0 calls=1 sched_ok=1`；未看到 `ko=1 ksud=1`，随后 ADB 暂时断开并发生重启。重启后的 `boot_id=6e4a8933-049a-44ec-ba8b-654ef6e9f9cc`，boot reason=`reboot,ap_s_coldboot,na`。
- 重启恢复后系统正常：`sys.boot_completed=1`、`getenforce=Enforcing`、service count=438、SurfaceFlinger PID=1553，精确内核仍在。重新安装交付包内 KernelSU Manager（APK SHA256 `1417081413bf7ab1de8e440ecbcb62685037c8f28f048f0f8b79e305b31ab916`，v3.2.5 / versionCode 32525）后，Manager 页面显示 `未安装`；没有可见独立 `ksud` 进程或 KSU 模块标记。
- 结论：系统更新解决了前一轮的内核不匹配，但本次单次运行没有形成 `ko=1 ksud=1` 或 Manager 已安装证据，不能判定 v13 安装成功；未再次运行 SO。详细证据：`analysis_outputs/jinghu-v13-shizuku-ashell-run-20260728/report-system-update.md` 与 `run-output-exact-kernel.txt`。

### 17.82 继续尝试：精确内核下进入 direct stage 但未获得 root（2026-07-28）

- 在上一次恢复后的干净启动 `boot_id=6e4a8933-049a-44ec-ba8b-654ef6e9f9cc` 中，确认内核仍为 README 精确要求的 `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`，按用户要求再次执行一次；此前输入法导致的错误 copy 记录均未执行 payload，正确 copy 的 hash 已复核。
- 本次 native 比上次深入：完成 `slide-kaslr-ok`，随后进入 `direct_root_enter`、entry_task oracle、real_cred 写入和 follow-up；但最终报告为 `direct credential result uid=2000 euid=2000 ... selinux=1->0`，汇总为 `direct-root-summary root=0 id=1 su=0/1 daemon=-1 ksu=0`。没有 `ko=1 ksud=1`，uid/euid 仍为 2000，不能判定 root 或 KernelSU 安装成功。
- 运行结束后设备处于 `getenforce=Permissive`，`boot_id` 显示为 payload 影响后的异常值 `40b8bc02-80ff-ffff-888b-3f0280ffffff`；已保存 aShell XML，随后执行一次正常 ADB 重启恢复干净状态。恢复后 `boot_id=563e7fc1-93d2-4efb-923c-eb18904ec667`、boot reason=`reboot,shell`、精确内核仍在、`getenforce=Enforcing`、`sys.boot_completed=1`、service count=437、SurfaceFlinger PID=1557。
- 重启后 KernelSU Manager v3.2.5 / versionCode 32525 仍显示 `未安装`，没有独立 `ksud` 进程；Shizuku 已重新启动。未再运行 payload。证据见 `analysis_outputs/jinghu-v13-shizuku-ashell-run-20260728/report-continuation-run.md`、`run-output-continuation-extracted.txt`。
