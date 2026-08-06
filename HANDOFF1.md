# Violin 内核异常复现与证据采集交接（HANDOFF1）

> **读者**：完全没有本项目上下文的新会话。
>
> **先做什么**：读本文、`E:\workspace\projects\xiaomi-root\03-dev-log.md` 最后 200 行、以及 `E:\workspace\projects\xiaomi-root\analysis_outputs\sameboot-currentboot-evidence-audit-20260716.md`。先检查实时 boot ID；没有同 boot 证据时，不运行任何历史 payload 或以旧绝对地址继续测试。
>
> **范围**：本文件仅记录授权环境中的异常复现、崩溃归因和防御性证据采集。不要将历史实验代码、内核对象伪造、调度/PI 时序、地址或写入原语用于提权、绕过 SELinux 或写入内核状态。

---

## 1. 一句话状态

项目在 Xiaomi Pad 7S Pro（`violin`，Android 16 / OS3.0.303.0.WOTCNXM / Linux 6.6.77）上做内核异常复现与根因证据采集。用户态载荷链曾触发设备重启；**尚无 root 成功证据**。目前最重要的进展是：已验证 root 设备同一次 boot 的符号包与 oops 分区读取包匹配，但它们与当前 USB 测试机的 boot 不同；而现有 oops 内容又是历史正常 Restart，不能解释本轮重启。

当前工作应转为：**在每次受控运行后，获取目标同 boot 的完整、可归因的崩溃记录与只读运行时元数据**，而不是继续扩大触发强度。

---

## 2. 环境与当前设备状态

| 项目 | 值 / 说明 |
| --- | --- |
| 工作目录 | `E:\workspace\projects\xiaomi-root` |
| USB ADB serial | `03035440C1781540` |
| 当前 ADB 身份 | `uid=2000(shell)`、`u:r:shell:s0`、SELinux Enforcing |
| 当前 USB boot ID（2026-07-16 实测） | `27b66c49-e0d5-48bc-afa3-2fbaf9f27cdd` |
| 当前 build fingerprint | `Xiaomi/violin/violin:16/BP2A.250605.031.A3/OS3.0.303.0.WOTCNXM:user/release-keys` |
| 主研究源码 | `E:\workspace\projects\xiaomi-root\exploit-repo\IonStack\CVE-2026-43499\exploit` |
| 测试页面 | `E:\workspace\projects\xiaomi-root\exploit-site` |
| 分析输出 | `E:\workspace\projects\xiaomi-root\analysis_outputs` |
| 项目日志 | `E:\workspace\projects\xiaomi-root\03-dev-log.md` |

**每次会话开头必须重新读取：**

```powershell
$adb = 'C:\Users\zeooon3\AppData\Local\Android\Sdk\platform-tools\adb.exe'
& $adb devices
& $adb -s 03035440C1781540 shell 'id; getenforce; cat /proc/sys/kernel/random/boot_id; getprop ro.build.fingerprint'
```

任何绝对内核地址都只在产生它的 **完全相同 boot ID** 内有效。

---

## 3. 已完成且已核验的事实

### 3.1 基础复现与历史现象

- 用户态 Firefox/native 测试链可运行；历史载荷曾使设备重启。
- 最近一次已记录的目标机重启前后 boot ID 变化为：
  - 旧：`3c594ef3-1a2c-4ed1-ae0d-bdd1aa30def1`
  - 重启后：`27b66c49-e0d5-48bc-afa3-2fbaf9f27cdd`
- 当次缺少持久化 crash log，不能将重启归因到某个具体内核函数、调度分派或 CFI 检查。
- 历史 scheduler/consumer 假设已被负面证据削弱：trace 仅观察到 owner 自身优先级变化，未得到可解释的 waiter/link 传播。不要通过增加线程、调用次数或链长度来“硬撞”。

### 3.2 目标机当前 boot 的只读 trace anchor

目标机在 `27b66c49-e0d5-48bc-afa3-2fbaf9f27cdd` boot 上曾从 tracefs raw CPU1 记录得到 `worker_thread+0x9c=0xffffffdfc70d797c`，推导 `_text=0xffffffdfc7000000`。材料在：

`E:\workspace\projects\xiaomi-root\analysis_outputs\post-reboot-27b66c49-20260715\`

此值必须在下一次运行前重新核验 boot ID；boot 改变即失效。

### 3.3 root 同 boot 归档已通过完整性校验

用户提供的两个包：

| 包 | 外层 SHA-256 | 核验结果 |
| --- | --- | --- |
| `E:\ZEOON3\Downloads\Compressed\currentboot.zip` | `5ce3787b6f01eac0bd5817a92763c5dcc61b68536efb3c193daa7c57d751c776` | 13 个非自指内部文件匹配；单条 mtdoops 读取有效。 |
| `E:\ZEOON3\Downloads\Compressed\sameboot.zip` | `ba4227f252999a347c98b70aebf60b22283299a8097f3a87e025c1d35c082d4a` | 清单 5 项全部匹配。 |

两包的 root boot ID 都是：

```text
ed0b4c66-b4d6-442b-a8ba-92f908275ee9
```

在这个 **root boot** 中，已核验：

| 项目 | 值 |
| --- | --- |
| `_text` / `CFI_KASLR_BASE` | `0xffffffe1a5800000` |
| `init_cred` | `0xffffffe1a78f0548` |
| `init_cred - _text` | `0x20f0548` |
| `init_task - _text` | `0x20de280` |
| `task_struct.cred / real_cred` 静态偏移 | `0x820 / 0x818` |
| current task oracle | 未取得：`NEEDS_LKM_ORACLE` |

结论：这证明了该 root 设备内的同 boot 符号一致性，**不**证明其地址可用于 USB 测试机。当前 USB boot 是 `27b66c49-...`，与该 root boot 不同。

正式审计：
`E:\workspace\projects\xiaomi-root\analysis_outputs\sameboot-currentboot-evidence-audit-20260716.md`

解包副本：
`E:\workspace\projects\xiaomi-root\analysis_outputs\evidence-audit-20260716\`

### 3.4 mtdoops 采集能力与当前限制

- rooted 采集器从 `/dev/block/sdc79` 成功读取了精确 `1,048,576` 字节，`RESULT=OK`。
- 当前读取的是 `Oops_Index: 209`，`REASON: Restart`，内嵌时间 `2026-07-08 12:04:46`。
- 内容含电源键事件，未包含 `Call trace`、`Unable to handle`、`Kernel panic`、`BUG:`、`Oops:` 或 CFI 错误。
- 因此它是历史正常 Restart 记录，**不是**最近一轮测试的崩溃证据。
- 当前 collector 只读取一个 1 MiB record；它没有枚举整个 oops 分区，可能错过更新的槽位。

已有 Android 本地终端采集脚本：

`E:\workspace\projects\xiaomi-root\tools\collect-current-boot-oops-local.sh`

其 ZIP 已在 `tools` 下生成。它会自提权到 `su` 并只读采集；普通 ADB shell 没有 `/dev/block/sdc79` 或 `/sys/fs/pstore` 的读取权限。

---

## 4. 当前卡点

### 主 blocker：没有针对“发生重启的同一 boot”的可归因证据

1. 触发后设备会 reboot，所有旧绝对地址失效。
2. 当前 root 归档与 USB 目标机 boot 不同，不能作为目标机运行时地址来源。
3. 已采集的 mtdoops 是历史 restart，不是刚刚那次异常；单槽读取不足以排除其他槽中存在新记录。
4. root 同 boot oracle 仍未报告 current task 类运行时元数据，只提供了全局符号。
5. 现有普通 shell 访问受限，无法读取 oops/pstore 原始证据。

因此，当前不是“继续调参”的问题，而是要补齐**运行前关联信息 + 运行后完整崩溃证据**的闭环。

---

## 5. 下一步计划（只做证据与防御验证）

### 步骤 1：建立每轮运行的最小证据包

每次受控测试前后保存：

- boot ID；
- build fingerprint；
- 测试时间、唯一 run ID、载荷文件 SHA-256；
- 测试结果（正常返回、应用崩溃、ADB 断开、是否 reboot）；
- reboot 后立即获取的完整 oops/mtdoops 槽位扫描与 pstore（存在时）。

**通过标准**：能把一条崩溃记录唯一对应到某一个 run ID 和 boot ID，而不是仅知道“设备曾重启”。

### 步骤 2：改进 rooted oops 采集的覆盖范围

在授权 root 设备上，把单记录采集扩展为只读的全分区/全槽枚举：

- 先读取块设备总大小；
- 按配置的 1 MiB record size 顺序读取每个槽；
- 对每槽保存 hash、可打印文本、header/index/reason/time；
- 仅选择与当前测试时间和 run ID 关联的最新记录作分析；
- 不向 oops 分区写入任何字节。

完成后以一个归档交付，并记录采集前后 boot ID。

### 步骤 3：补 root oracle 的只读运行时观测

若有授权且同 boot 的调试/root 环境，仅记录必要的运行时诊断字段（oracle 输出、boot ID、模块/内核 build 标识）；禁止让 oracle 修改 credential、SELinux、task 或锁状态。目标是确认观测链是否完整，而不是使用它改变权限。

### 步骤 4：做内核防御回归

在调试内核上启用 KASAN/KFENCE，并围绕 futex、pselect、rt_mutex/PI 生命周期路径做受控负向测试：

- 检测 waiter 的 lock/owner 指针是否越出可信内核对象范围；
- 检测 pselect 栈数据是否能影响 waiter 生命周期字段；
- 覆盖优先级变更与 `pi_blocked_on` 的检查分支；
- 收集 call trace 和 sanitizer 报告。

这一步的交付物应是修复建议、回归测试结果和崩溃日志，不是权限变化。

---

## 6. 绝对不要再踩的坑

1. **不要宣称已 root。** 当前没有 root 成功证据。
2. **不要复用旧 boot 的绝对内核地址。** 每次重启都必须先核对 boot ID。
3. **不要把 root 同 build/sameboot 包误当作当前 USB 设备 sameboot。** 2026-07-16 已实测两者 boot ID 不同。
4. **不要把单条 mtdoops 成功读取误认为抓到了本轮崩溃。** 必须比对 record index、内嵌时间、run ID 与 boot ID。
5. **不要只读第一个/固定一个 mtdoops 槽位。** 要扫描全部槽位或明确证明记录选择策略正确。
6. **不要在普通 ADB shell 上反复尝试读取 oops/pstore。** 已证实权限拒绝；使用授权 root 设备的只读采集器。
7. **不要在测试前触发依赖 syscall 栈帧的消费者/后台工作。** 这会制造未初始化状态与不可归因崩溃；所有受控触发必须有明确同步和完成确认。
8. **不要过早清除同步标志。** 先确认消费者已完成，再收尾；否则会得到“未触发”的假阴性。
9. **不要让 fd 重定向覆盖标准输入/输出/错误（0–2）。** 这会吞掉 printf/诊断日志，导致错误归因。
10. **不要将 `FUTEX_CMP_REQUEUE_PI ret=0` 当 rollback 成功。** 历史成功判据是 `ret=-1` 且 `errno=EDEADLK`。
11. **不要恢复历史 `PSELECT_WAITER_WORD_SHIFT=1` 配置。** 离线验证结论为 `0`；历史 shift=1 导致字段整体错位并伴随崩溃。
12. **不要再通过扩大 scheduler consumer/calls/chain 轰路径。** 该假设已有负面 trace 证据。
13. **不要把 kprobe 注册成功当作 KASLR 地址正确。** 注册与 raw 地址泄漏是不同问题。
14. **不要把 ConfigFS/ashmem pre-hijack 的 EOF 解释为可用的读取 primitive。** 该路径已有 EOF 证据。
15. **不要 `git add -A`。** 源码/站点目录含大量实验产物、build 与备份文件；逐文件 stage。

---

## 7. 关键文件与材料索引

| 用途 | 路径 |
| --- | --- |
| 本交接 | `E:\workspace\projects\xiaomi-root\HANDOFF1.md` |
| 最新开发日志 | `E:\workspace\projects\xiaomi-root\03-dev-log.md` |
| sameboot/currentboot 正式审计 | `E:\workspace\projects\xiaomi-root\analysis_outputs\sameboot-currentboot-evidence-audit-20260716.md` |
| 归档解包材料 | `E:\workspace\projects\xiaomi-root\analysis_outputs\evidence-audit-20260716\` |
| 当前 USB boot trace anchor | `E:\workspace\projects\xiaomi-root\analysis_outputs\post-reboot-27b66c49-20260715\` |
| rooted oops 本地采集脚本 | `E:\workspace\projects\xiaomi-root\tools\collect-current-boot-oops-local.sh` |
| 旧 scheduler/CFI 报告 | `E:\workspace\projects\xiaomi-root\analysis_outputs\sched-wchan-run-20260713\REPORT.md` |
| 主源码（仅供防御审计） | `E:\workspace\projects\xiaomi-root\exploit-repo\IonStack\CVE-2026-43499\exploit` |
| 测试页面（仅供受控复现） | `E:\workspace\projects\xiaomi-root\exploit-site` |

---

## 8. 新会话开始清单

1. 读本文件、`03-dev-log.md` 最新条目、sameboot/currentboot 审计报告。
2. 运行只读 ADB 状态命令，记录当前 boot ID。
3. 比较当前 boot ID 与任意计划使用的证据包 boot ID；不一致则仅保留相对偏移/离线资料。
4. 检查是否有新的、带 run ID 的 root oops/pstore 全槽归档。
5. 若没有，优先完成全槽只读采集工具和一次空载/正常重启对照采集。
6. 若有崩溃记录，先做归因报告（时间、boot、trace、sanitizer、最小复现条件），再决定是否需要防御补丁/回归用例。
7. 每次有稳定结论时，追加到 `03-dev-log.md` 并同步更新本文件的“一句话状态”和“当前卡点”。

---

## 9. 更新记录

- **2026-07-16**：重写为 newcomer-ready 基线；纳入 `currentboot.zip` / `sameboot.zip` 完整性核验、root/USB boot 不一致结论、历史 mtdoops record 结论，以及证据采集优先的后续计划。
