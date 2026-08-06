<div align="center">

# ⚡ IonStack Violin

**CVE-2026-43499 (GhostLock) 内核提权研究 — Xiaomi Pad 7S Pro**

**CVE-2026-43499 (GhostLock) Kernel Privilege Escalation Research — Xiaomi Pad 7S Pro**

---

![Target](https://img.shields.io/badge/Target-Xiaomi%20Pad%207S%20Pro-ff6900?logo=xiaomi)
![CVE](https://img.shields.io/badge/CVE--2026--43499-critical)
![Kernel](https://img.shields.io/badge/Kernel-6.6.77--android15--8-blue)
![Android](https://img.shields.io/badge/Android-16%20(HyperOS%203.0)-green?logo=android)
![Status](https://img.shields.io/badge/Status-Research%20in%20Progress-yellow)

</div>

---

## 📖 项目简介 / Overview

### 中文

本项目是对 **CVE-2026-43499**（代号 GhostLock / IonStack）在 **小米平板7S Pro**（代号 `violin`，内核 `6.6.77-android15-8`，HyperOS 3.0 / Android 16）上的完整提权链研究。

研究目标是在授权测试设备上评估该漏洞的本地提权可行性，复现完整攻击链，并据此修复产品漏洞。

**当前状态：CVE 触发已确认，KASLR 泄漏路径已在 shell 域建立，但完整浏览器内提权链尚未闭合。**

### English

This project is a full-chain kernel privilege escalation research of **CVE-2026-43499** (codename GhostLock / IonStack) on the **Xiaomi Pad 7S Pro** (codename `violin`, kernel `6.6.77-android15-8`, HyperOS 3.0 / Android 16).

The goal is to evaluate the local privilege escalation feasibility on authorized test devices, reproduce the full attack chain, and use the findings to fix product vulnerabilities.

**Current status: CVE trigger confirmed, KASLR leak path established in shell domain, but the full in-browser privilege escalation chain is not yet closed.**

---

## 🔬 研究思路 / Research Approach

### 总体架构 / Overall Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     IonStack 利用链总览                              │
│                     IonStack Exploit Chain Overview                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ① CVE 触发          ② UAF 利用           ③ KASLR 泄漏             │
│  CVE Trigger    →    UAF Exploit      →   KASLR Leak               │
│                                                                     │
│  futex requeue       stale waiter         sched_blocked_reason      │
│  EDEADLK rollback    stack overlap        tracefs raw event         │
│                                                                     │
│  ④ 任意写原语         ⑤ 凭据修补           ⑥ Root                   │
│  Write Primitive  →  Cred Patch       →   Root                     │
│                                                                     │
│  pselect fdset       in-place uid=0       SELinux Enforcing         │
│  rbtree overlap      caps=FULL            framework alive           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

### 阶段一：CVE 触发 / Phase 1: CVE Trigger

**中文：**

CVE-2026-43499 的核心是 Linux 内核 futex 子系统中 `FUTEX_CMP_REQUEUE_PI` 的一个缺陷。当 requeue 操作检测到死锁条件时，`remove_waiter()` 函数存在 **UAF（Use-After-Free）**：它清零了错误任务的 `pi_blocked_on` 字段，导致一个 `rt_mutex_waiter` 结构体在被释放后仍可通过 `task->pi_blocked_on` 悬空指针访问。

**触发条件：**
- 使用 `FUTEX_CMP_REQUEUE_PI` 触发死锁回滚（返回 `-1`，`errno=EDEADLK`）
- 随后 waiter 超时返回 `ETIMEDOUT`
- 此时 stale waiter 指针仍然存活（`pi_blocked_on` 未被正确清理）

**English:**

CVE-2026-43499 stems from a flaw in the Linux kernel's futex subsystem in `FUTEX_CMP_REQUEUE_PI`. When a requeue operation detects a deadlock condition, the `remove_waiter()` function has a **Use-After-Free**: it clears the wrong task's `pi_blocked_on` field, leaving an `rt_mutex_waiter` struct accessible via a dangling pointer after deallocation.

**Trigger conditions:**
- `FUTEX_CMP_REQUEUE_PI` deadlock rollback (`ret=-1`, `errno=EDEADLK`)
- Subsequent waiter timeout (`ETIMEDOUT`)
- Stale waiter pointer survives (`pi_blocked_on` not properly cleaned)

---

### 阶段二：栈帧重叠 / Phase 2: Stack Overlap

**中文：**

研究的关键发现是 futex waiter 的栈帧位置与 `pselect()`/`poll()` 系统调用的 fdset 缓冲区在内核栈上存在重叠：

- futex waiter 位于 syscall 栈 `sp-0x200`
- `pselect` 的三组 fd_set（in/out/ex）也从同一区域复制
- 通过精心构造 `nfds` 参数，可以将 waiter 的字段（`tree`、`pi_parent`、`task`、`lock`）映射到 fd_set 的特定 word

**关键约束：**
- `PSELECT_WAITER_WORD_SHIFT=0`（已由原厂内核反汇编确认）
- `shift=1` 是错误方法，会导致 waiter 整体错 8 字节并引发 panic

**English:**

A key finding is that the futex waiter's stack frame overlaps with the `pselect()`/`poll()` syscall fdset buffers on the kernel stack:

- Futex waiter is at syscall stack `sp-0x200`
- `pselect`'s three fd_set groups (in/out/ex) are copied from the same region
- By carefully crafting the `nfds` parameter, waiter fields (`tree`, `pi_parent`, `task`, `lock`) can be mapped to specific fd_set words

**Key constraints:**
- `PSELECT_WAITER_WORD_SHIFT=0` (confirmed by factory kernel disassembly)
- `shift=1` is incorrect — causes 8-byte misalignment and kernel panic

---

### 阶段三：KASLR 泄漏 / Phase 3: KASLR Leak

**中文：**

内核地址空间布局随机化（KASLR）是利用链的核心障碍。研究发现了一条通过 `sched_blocked_reason` tracefs 原始事件泄漏 canonical `_text` 地址的路径：

1. **ADB shell 域**：`shell` 用户（uid=2000）属于 `readtracefs` 组，可以读取 `/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw`
2. **事件解析**：`sched_blocked_reason`（ID=109）的 `caller` 字段位于 payload offset 16，宽度 8 字节
3. **地址推导**：`caller - (worker_thread - _text) - 0x9c` = 当前 boot 的 `_text` canonical 地址

**重要限制：**
- Firefox app 进程（UID 10270, `u:r:untrusted_app:s0`）没有 `readtracefs` 权限
- 该泄漏仅在 ADB shell 域可用，不可直接作为浏览器 payload 的 oracle
- canonical 地址每次 boot 都会改变，不可跨 boot 复用

**English:**

Kernel Address Space Layout Randomization (KASLR) is the core barrier of the exploit chain. A path was found to leak the canonical `_text` address through `sched_blocked_reason` tracefs raw events:

1. **ADB shell domain**: The `shell` user (uid=2000) belongs to the `readtracefs` group and can read `/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw`
2. **Event parsing**: `sched_blocked_reason` (ID=109) has a `caller` field at payload offset 16, width 8 bytes
3. **Address derivation**: `caller - (worker_thread - _text) - 0x9c` = current boot's canonical `_text` address

**Critical limitations:**
- Firefox app process (UID 10270, `u:r:untrusted_app:s0`) lacks `readtracefs` permission
- This leak is only available in ADB shell domain, cannot serve as an in-browser payload oracle
- Canonical addresses change every boot — cannot be reused across reboots

---

### 阶段四：写原语研究 / Phase 4: Write Primitive Research

**中文：**

研究了多种将 UAF 转化为内核任意写原语的路径：

| 路线 | 方法 | 状态 |
|------|------|------|
| **Direct pselect** | 通过 pselect fdset 覆写 waiter 字段 | post-copy barrier 下 oracle=0，语义阻断 |
| **rt_mutex PI chain** | 利用 `rt_mutex_adjust_prio_chain` 的 rbtree 操作 | 第一轮 `noop_llseek` 后离开受控页，未闭合 |
| **fops 劫持** | 通过 rbtree 操作覆写 `ashmem_misc.fops` 指针槽 | `ROUTE_REACHED=1` 但 CFI 写入失败 |
| **P0/direct-map** | 利用 direct-map 数据页 | P0 指针不是 canonical text，不能用于 fops/CFI |
| **Bad Epoll (CVE-2026-46242)** | `ep_remove()` UAF + 320-byte cross-cache | 静态漏洞已确认，ARM64 exploit 未建立 |
| **256-fd pselect** | 扩展 nfds 使 waiter->lock 落入 kernel-page | fd-mask readiness 状态机待建模 |

**English:**

Multiple paths were researched to convert the UAF into a kernel arbitrary write primitive:

| Route | Method | Status |
|-------|--------|--------|
| **Direct pselect** | Overwrite waiter fields via pselect fdset | oracle=0 post-copy barrier, semantically blocked |
| **rt_mutex PI chain** | Leverage `rt_mutex_adjust_prio_chain` rbtree ops | First round exits controlled page at `noop_llseek`, not closed |
| **fops hijack** | Overwrite `ashmem_misc.fops` pointer slot via rbtree | `ROUTE_REACHED=1` but CFI write failed |
| **P0/direct-map** | Use direct-map data pages | P0 pointer is not canonical text, cannot use for fops/CFI |
| **Bad Epoll (CVE-2026-46242)** | `ep_remove()` UAF + 320-byte cross-cache | Static vuln confirmed, ARM64 exploit not established |
| **256-fd pselect** | Extend nfds so waiter->lock lands in kernel-page | fd-mask readiness state machine not yet modeled |

---

### 阶段五：原地凭据修补 / Phase 5: In-Place Cred Patch

**中文：**

传统提权方法（替换 `task->cred` 为 `init_cred`）会导致 SELinux context 变为 `kernel`，触发 zygote/system_server 崩溃（黑屏）。

**原地修补方案**（不杀 framework）：

不替换 cred 指针，只修改 cred 结构体内的字段：

| 偏移 | 字段 | 写入值 |
|------|------|--------|
| +8 | uid + gid | 0x0 |
| +16 | suid + sgid | 0x0 |
| +24 | euid + egid | 0x0 |
| +32 | fsuid + fsgid | 0x0 |
| +40 | securebits | 0x0 |
| +48~80 | capability × 5 | `0x000001ffffffffff` (CAP_FULL) |

**关键设计：**
- `cred + 128`（security pointer）**不修改** → SELinux SID 保持 `shell`
- `selinux_enforcing` **不修改** → 保持 `1`（Enforcing）
- `task->cred` / `task->real_cred` 指针 **不变**

**预期结果：** `uid=0(root) context=u:r:shell:s0`，framework 不受影响。

**English:**

The traditional approach (replacing `task->cred` with `init_cred`) changes the SELinux context to `kernel`, crashing zygote/system_server (black screen).

**In-place patch approach** (framework stays alive):

Instead of replacing the cred pointer, modify fields within the cred struct:

| Offset | Field | Value |
|--------|-------|-------|
| +8 | uid + gid | 0x0 |
| +16 | suid + sgid | 0x0 |
| +24 | euid + egid | 0x0 |
| +32 | fsuid + fsgid | 0x0 |
| +40 | securebits | 0x0 |
| +48~80 | capability × 5 | `0x000001ffffffffff` (CAP_FULL) |

**Key design:**
- `cred + 128` (security pointer) is **NOT modified** → SELinux SID stays `shell`
- `selinux_enforcing` is **NOT modified** → stays `1` (Enforcing)
- `task->cred` / `task->real_cred` pointers are **unchanged**

**Expected result:** `uid=0(root) context=u:r:shell:s0`, framework unaffected.

---

### 阶段六：安全审计 / Phase 6: Security Audits

**中文：**

研究过程中对设备攻击面进行了系统性审计：

**字符设备审计：**
- `/dev/mali0` — `open()` 有固件初始化，非被动 oracle（已排除）
- `/dev/ashmem` — `open()` 被 SELinux `neverallow` 阻断（已排除）
- `/dev/camlog` — `read()` 会消费 FIFO 记录（已排除）
- `/dev/hpc-*` — 全部有状态操作，无被动查询（已排除）
- `/dev/xr_*` — 无 `untrusted_app` CIL 投影（已排除）

**SELinux CIL 权限分析：**
- `untrusted_app` 仅对 `gpu_device`（mali0）和 `dmabuf_system_heap_device`（XRing heap）有字符设备访问权
- tracefs `sched_blocked_reason` 对 app 域有 `neverallow` 阻断
- 无 `readtracefs` 的 privileged broker 可供 app 调用

**English:**

Systematic attack surface auditing was performed during research:

**Character device audit:**
- `/dev/mali0` — `open()` has firmware init, not a passive oracle (excluded)
- `/dev/ashmem` — `open()` blocked by SELinux `neverallow` (excluded)
- `/dev/camlog` — `read()` consumes FIFO records (excluded)
- `/dev/hpc-*` — all stateful, no passive queries (excluded)
- `/dev/xr_*` — no `untrusted_app` CIL projection (excluded)

**SELinux CIL permission analysis:**
- `untrusted_app` only has char device access to `gpu_device` (mali0) and `dmabuf_system_heap_device` (XRing heaps)
- tracefs `sched_blocked_reason` has `neverallow` for app domain
- No `readtracefs` privileged broker available for app invocation

---

## 🧪 实验变体 / Experimental Variants

**中文：**

研究过程中构建了大量实验变体（E1–E24+），每个变体仅修改一个变量：

| 实验 | 假设 | 结果 |
|------|------|------|
| E1 | rb_parent_color 设置 RB_RED 触发重平衡 | 无重启，boot_id 未变 |
| E2 | 修改 CMP_REQUEUE_PI 比较值 | 待验证 |
| E3 | lock owner 字段 | 待验证 |
| E5 | 修正 pselect 布局 | 待验证 |
| E19 | 上游完整链 | 已证伪，不重跑 |
| E20 | exact stack offset 0 | 设备重启，已证伪 |
| E21–E23 | watchdog 观测变体 | 全部重启，已排除 |
| E24 | wake_state=0 | 重启，非根因修复 |

**English:**

Numerous experimental variants (E1–E24+) were built, each modifying only one variable:

| Experiment | Hypothesis | Result |
|------------|-----------|--------|
| E1 | Set RB_RED on rb_parent_color to trigger rebalance | No reboot, boot_id unchanged |
| E2 | Modify CMP_REQUEUE_PI comparison value | Pending verification |
| E3 | Lock owner field | Pending verification |
| E5 | Fix pselect layout | Pending verification |
| E19 | Upstream full chain | Disproven, do not re-run |
| E20 | Exact stack offset 0 | Device rebooted, disproven |
| E21–E23 | Watchdog observation variants | All reboot, excluded |
| E24 | wake_state=0 | Reboot, not root cause fix |

---

## 🚫 已排除的路径 / Excluded Paths

**中文：**

以下路径经严格验证后已确认不可行，不得重试：

1. **P0/direct-map 地址当作 KASLR text** — `0xffffff80...` 不是 canonical `0xffffffe3...`/`0xffffffd3...`
2. **跨 boot 复用 canonical 地址** — KASLR 每次 boot 改变
3. **E21–E24 watchdog 变体** — 全部导致重启
4. **`ret=0` 判定 requeue 成功** — 只有 `EDEADLK` 才表示 UAF rollback
5. **普通 shell 读 `/proc/kallsyms`** — 被 SELinux 拒绝，零地址不等于可用地址
6. **shift=1 waiter 偏移** — 导致 8 字节错位和 panic
7. **公开 Linux LPE 路线** — `CONFIG_CRYPTO_USER_API_AEAD`、`AF_RXRPC`、`USER_NS` 均未启用

**English:**

The following paths have been rigorously verified as infeasible and must not be retried:

1. **P0/direct-map address as KASLR text** — `0xffffff80...` is not canonical `0xffffffe3...`/`0xffffffd3...`
2. **Reusing canonical addresses across boots** — KASLR changes every boot
3. **E21–E24 watchdog variants** — all cause reboots
4. **`ret=0` as requeue success** — only `EDEADLK` indicates UAF rollback
5. **Plain shell reading `/proc/kallsyms`** — denied by SELinux, zero addresses are not usable
6. **shift=1 waiter offset** — causes 8-byte misalignment and panic
7. **Public Linux LPE routes** — `CONFIG_CRYPTO_USER_API_AEAD`, `AF_RXRPC`, `USER_NS` all disabled

---

## 📊 证据状态矩阵 / Evidence Status Matrix

| 阶段 / Stage | 状态 / Status | 证据 / Evidence |
|---|---|---|
| CVE trigger (EDEADLK) | ✅ 已证实 | `CMP_REQUEUE_PI=-1/errno=35` |
| Stack overlap (shift=0) | ✅ 已证实 | 原厂 kernel 反汇编确认 |
| tracefs KASLR leak (shell) | ✅ 已证实 | `caller=0xffffffd30a6d797c` → `_text` |
| tracefs KASLR leak (Firefox) | ❌ 不可用 | SELinux `neverallow` on `untrusted_app` |
| pselect write primitive | ❌ oracle=0 | post-copy barrier 下未建立 |
| rt_mutex PI chain | ❌ 未闭合 | `noop_llseek` 后离开受控页 |
| fops hijack (CFI) | ❌ 写入失败 | `CFI_RESULT ok=0 step=1 errno=22` |
| In-place cred patch | 🔨 build-only | 无设备 runtime proof |
| 完整 ARM64 root | ❌ 未获得 | — |

---

## 🛠️ 技术栈 / Tech Stack

| 类别 / Category | 技术 / Technology |
|---|---|
| 目标设备 / Target | Xiaomi Pad 7S Pro (`violin`), 25053RP5CC |
| 固件 / Firmware | HyperOS 3.0 (`OS3.0.303.0.WOTCNXM`), Android 16 |
| 内核 / Kernel | `6.6.77-android15-8-g5770c661275f`, ARM64 |
| 浏览器 / Browser | Firefox for Android 151.0 |
| 构建 / Build | Android NDK r29, API 35, AArch64 |
| 上游参考 / Upstream | `NebuSec/CyberMeowfia` (IonStack) |
| 分析工具 / Analysis | Python 离线核验器, raw kernel 反汇编, BTF 解析, SELinux CIL 解析 |

---

## 📂 项目结构 / Project Structure

```
ionstack-violin/
├── index.html                              # 启动器 — ANSI 终端 UI、重试逻辑、参数路由
│                                           # Launcher — ANSI terminal UI, retry logic, param routing
├── exploit.html                            # CVE-2026-43499 核心触发 + payload 加载器
│                                           # Core CVE-2026-43499 trigger + payload loader
├── diag.html                               # 诊断 / 断电恢复页面
│                                           # Diagnostic / power-loss recovery page
├── ansi.js                                 # 轻量 ANSI 转义码渲染器
│                                           # Lightweight ANSI escape renderer
├── run-rooted-e24-live-capture.sh          # root 设备内核日志实时捕获脚本
│                                           # Rooted device live kernel log capture
├── collect-rooted-panic-evidence.sh        # 重启后证据收集脚本
│                                           # Post-reboot evidence collector
└── README.md                               # 本文件 / This file
```

---

## 📋 设备信息 / Device Info

```
设备代号:    violin (Xiaomi Pad 7S Pro)
型号:        25053RP5CC
固件:        OS3.0.303.0.WOTCNXM
Android:     16
内核:        6.6.77-android15-8-g5770c661275f-abogki443185593-4k
SPL:         2026-05-01
Verified Boot: green
```

---

## ⚠️ 免责声明 / Disclaimer

**中文：**

本项目仅用于**授权安全研究和教育目的**。所有测试均在作者拥有并明确授权的设备上进行。作者不对任何滥用行为负责。请勿在未经授权的设备上使用本项目的任何内容。

**English:**

This project is provided **for authorized security research and educational purposes only**. All testing was performed on devices owned and explicitly authorized by the author. The authors are not responsible for any misuse. Do not use any content from this project on unauthorized devices.

---

<div align="center">

**⚡ IonStack — 内核提权研究，浏览器交付**

**⚡ IonStack — Kernel Privilege Escalation Research, Browser-Delivered**

</div>
