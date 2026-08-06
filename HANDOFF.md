# Violin / CVE-2026-43499（IonStack）交接文档

> 本文写给没有任何上下文的新会话。先读本文，再读 `03-dev-log.md` 的最新条目；不要直接运行任何网页 payload。

## 1. 任务与边界

- 目标：在**授权测试设备** Xiaomi Pad 7S Pro `violin` 上，评估/复现 Linux `CVE-2026-43499`（GhostLock / IonStack）的本地提权链，最终获得可验证 root，并据此修复产品漏洞。
- 当前目标设备：ADB serial `03035440C1781540`，未 root。
- 另有同版本 root 设备，可在其本地 MT 管理器终端运行脚本收集证据。
- 内核/固件：`6.6.77-android15-8-g5770c661275f-abogki443185593-4k`，`OS3.0.303.0.WOTCNXM`，Android 16。
- 上游参考仓库：`exploit-repo/IonStack`，remote 为 `https://github.com/NebuSec/CyberMeowfia.git`，当前公开基线 commit `1a10c4e`。

## 2. 当前结论：**尚未 root，不要宣称完整利用成功**

已稳定触发 CVE 的 UAF rollback，但完整 ARM64/violin root 链尚未建立。此前“缺少经验证的 canonical KASLR 指针泄漏”的表述已被 2026-07-15 的 tracefs 证据取代：在指定 boot 上，ADB shell/readtracefs 域已经从 `sched_blocked_reason` raw event 恢复出 canonical `caller` 并推导同 boot `_text`。这只证明 **shell 域的 same-boot KASLR oracle**，不证明 Firefox/app payload 可以读取该 oracle，也不证明 fops/CFI 写入、控制流劫持或 root 已完成。P0/direct-map 的 data-only 路线仍不以 canonical text 为前置，但其 Violin 调度对象形状尚未安全可用。

### 2.1 证据状态矩阵

| 阶段 | 状态 | 当前证据/限制 |
| --- | --- | --- |
| `sched_blocked_reason` raw → same-boot canonical `_text` | **已证实** | ADB `shell` + `readtracefs`；只对该 boot 有效 |
| Firefox/app 进程内直接读取 trace oracle | **未证实/当前不可用** | UID 10270 无 `readtracefs`，raw pipe 实测 `Permission denied` |
| KASLR base 注入到下游测试参数 | **已做过一次 shell-assisted 试验** | 注入后设备重启，未获得 root；重启后旧 base 失效 |
| fops/CFI 任意写与控制流劫持 | **未闭合** | 缺少目标槽位 readback 和完整下游链证据 |
| 完整 ARM64 root | **未获得** | 不得将中间 leak 证据写成 root 成功 |

## 3. 已完成且可复用的证据

### 3.1 CVE trigger 与 stack overlap

- 正确 requeue 调用使用 `FUTEX_CMP_REQUEUE_PI`；`ret=-1` 且 `errno=EDEADLK` 才是 rollback 成功，`ret=0` 不是成功。
- E20 私有日志：`analysis_outputs/e20/private-crash-from-local-diag.txt`。
- 已确认序列：`SLIDEC2_UAF_PRIMED` → `SLIDEW4` → `SLIDEP2` → `SLIDECONS0`。
- 原厂 kernel 反汇编证明 futex waiter 与 pselect fdset 目标位置同为 syscall stack `sp-0x200`，故 `PSELECT_WAITER_WORD_SHIFT=0`。
- `shift=1` 是旧错法，会使 waiter 整体错 8 字节并造成 panic/重启；绝不能恢复。

### 3.2 结构/符号/物理布局已核实

- BTF：`analysis_outputs/btf-layouts-rooted-device.txt`。
  - `rt_mutex_waiter`：tree `0x00`、pi_tree `0x28`、task `0x50`、lock `0x58`、wake_state `0x60`、ww_ctx `0x68`。
  - `task_struct.pi_lock/pi_waiters/pi_top_task/pi_blocked_on`：`0x90c/0x920/0x930/0x938`。
- 25 个 header symbol offset 已和有效 rooted kallsyms 精确一致：`analysis_outputs/e24/symbol-offset-audit.txt`。
- `/proc/iomem` 证明 `_text` physical load 是 `0x00210000`；P0/direct-map alias 的数值本身无误：`analysis_outputs/e24/p0-direct-map-audit.txt`。
- 已验证根机证据工作目录：`violin-kernel-evidence-work/violin-kernel-evidence-work/`，其中含 BTF、`proc/iomem`、有效 `proc/kallsyms`。

### 3.3 已明确排除的错误路径

- E21/E22/E23 watchdog 观测变体、E24 wake_state=0 都在 `SLIDECONS0` 后重启；不要再运行。
- `wake_state=0` 不是根因修复，不能避开 RB tree 数据破坏。
- 当前 `slide` boot-id 算法把 P0/direct-map `SLIDE_LOGGERS_0_1` 写入 boot-id；读回后仍是 `0xffffff80...`，不是 canonical `0xffffffd3...` text 地址。它不能作为 fops/CFI KASLR 地址，但可作为 direct-data 路线的地址域候选，不能据此跳过调度结构验证。
- 推导见 `analysis_outputs/e24/slide-kaslr-address-domain-audit.md`：P0 leak 减 offset 后仍处 P0，不能得到 KASLR slide。
- 已在 `src/slide.c` 加了 `SLIDER2_BAD_DOMAIN` 门禁，拒绝把 P0 指针误当 `stext`。
- 普通 shell 的 `/proc/kallsyms`、`/proc/iomem`、`/proc/vmallocinfo` 均被 SELinux 拒绝；trace kprobe event 无法 enable；simpleperf system-wide 要 root，per-process clock event 不可用。

## 4. 当前代码与重要路径

- 主源码：`exploit-repo/IonStack/CVE-2026-43499/exploit/src/`。
- violin 配置：`src/targets/violin-v-oss/target.h`。
- 当前真实使用的 slide 源：`src/slide.c`（不是 `src/targets/violin-v-oss/slide.c`）。
- Web 发布目录：`exploit-site/`；GitHub Pages repo remote 为 `https://github.com/liang1228/ionstack-violin.git`。
- E20 binary SHA256：`82010A66D2A0B15CDB6E4A580697F0E633CC8EF022FB234DA7E6D72448CCE92B`。
- E24 binary SHA256：`DEA0E08C39BC3C524D8B7A7BDCA7F1DC9B9977904CEEE9F51ED5C6829F89D91C`；已证伪，不得重跑。

## 5. Root 设备最新收集包

### 5.1 `violin-kernel-info2.zip`（本轮有效 canonical 证据）

- 已解包到 `analysis_outputs/violin-kernel-info2/violin-kernel-info/`，原包 SHA-256：`94999DC250D1E653B8324974D8A1D8289F283ED0D3C99F0869E0D490D42273B5`。
- 与目标同为 `violin` / `OS3.0.303.0.WOTCNXM` / `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`；本包 kallsyms 含非零 canonical 地址：`_text=0xffffffe387200000`、`loggers=0xffffffe3892d21b8`、`sysctl_bootid=0xffffffe389536f58`。
- 与先前有效 root boot 的 `_text=0xffffffd365e00000` 相差 `0x1021400000`，再次实证 canonical KASLR 地址每次 boot 改变；**绝不可直接填到未 root 设备 payload。**
- cmdline 启用 `block2mtd ... /dev/block/by-name/oops`、`mtdoops.record_size=1048576`、`mtdoops.dump_oops=1`、`printk.always_kmsg_dump=1`。重启后的首选 crash 证据是原始 `oops` 分区，而不是 pstore。
- 新增只读重启后收集脚本：`tools/collect-rooted-oops-partition.sh`。它先解析 `/dev/block/by-name/oops` 到真实 block device，再强校验 `dd` 退出码和读取长度必须恰为 `1048576` bytes；失败会写 `EVIDENCE_STATUS.txt=FAILED` 并删除可能的零字节/截断 raw 文件，绝不把无效输出伪装为证据。通过才生成 raw、hash、字符串、关键行和 `.tar.gz`；不会写分区或改变日志设置。

- 用户提供：`ionstack-canonical-surface-20260712-172004.zip`。
- 已解包：`analysis_outputs/rooted-canonical-surface-20260712-172004/ionstack-canonical-surface-20260712-172004/`。
- 它确认 root/Magisk 和同 build，提供 iomem、模块清单、字符设备 ACL；`mali_kbase` 已加载，`/dev/mali0` 对 shell 可访问。
- **限制：**该次脚本处在 `u:r:magisk:s0`，`/proc/kallsyms` 和 `/sys/module/*/sections/*` 都是零地址，不能用于 canonical runtime 地址；部分 GPU/trace/kcore 文件也未输出。不要把它与先前有效 kallsyms 混用。
- 修正后的收集脚本：`tools/collect-rooted-canonical-leak-surface.sh`。必须传 `.sh`，不是旧的 `.sh.txt`。其运行会逐步打印 `[ionstack] collecting ...`。

## 6. 当前卡点与下一步计划

### 卡点

同 boot canonical 地址的 shell 侧获取已成立，不再是当前唯一卡点；但该能力尚未进入 Firefox/app payload 的执行域。fops/CFI 路线仍需独立证明 payload 如何获得同 boot base、目标槽位是否真的写入、以及 CFI/configfs/pipe 后续链是否闭合。P0 可控页只能承载数据，不是可执行 canonical kernel text；ARM64 CFI 也不能把 P0 数据页当回调代码。direct-data 路线则先需证明同 build rbtree/rt_mutex 形状不会破坏 live kernel state。

### 下一步（严格按顺序）

1. 对目标上普通 shell 可打开的字符设备作**只读、结构化 ioctl 返回审计**，优先 `/dev/mali0`、ashmem 和 XRing 已公开节点；这是补充独立对象/目标元数据的审计，不再把它表述为 canonical-leak 前置，禁止盲写/fuzz。
2. direct-data 方向先离线对账每个 `rb_erase_cached` 写入、parent-color、fake lock/task 与 wake 分支；没有证明写目标安全前，不得再运行 rbtree shape。
3. 对已有 shell-side canonical 候选，必须用离线 verifier 复核 event ID、字段偏移、canonical range、symbol delta、boot_id 和 kernel fingerprint；不得把旧 boot 的 base 直接复用到新 boot。
4. 只有相应路线的 leak/调度门禁成立后，才重新评估 constrained write；最后才做 ARM64 CFI/回调链或任何 credential 写入。每一阶段单独留日志和可重复验证。

## 7. 绝对不要再踩的坑

1. 不要把 P0/direct-map `0xffffff80...` 当作 KASLR text 指针。
2. 不要把 root 设备另一次 boot 的 canonical 地址硬编码到未 root 目标；KASLR 每次 boot 改变。
3. 不要运行 E21/E22/E23/E24，也不要扫描 pselect shift=1。
4. 不要因为 `ret=0` 判定 `CMP_REQUEUE_PI` 成功；只有 `EDEADLK` 表示已获得该 UAF rollback。
5. 不要以普通 ADB shell 读取被 SELinux 禁止的 `/proc/kallsyms`/iomem 后把失败输出误作零地址。
6. Magisk `uid=0` 不必然具备 `CAP_SYSLOG`：新 root 归档中全零 kallsyms 即是证据；先检查实际内容再使用。
7. 不要直接 `git add -A` 于 `exploit-site`，其中有大量实验产物和历史临时文件。
8. 不要用当前残缺的 `E:\workspace\projects\xiaomi-root\ndk` 链接 Android 产物；其 clang 是 stub。现阶段只可用 host clang 做 `-fsyntax-only`，或恢复完整 NDK 后再链接。

## 8. 验证与日志约定

- 每次源码改动至少运行：
  ```sh
  clang -fsyntax-only -Isrc -Isrc/targets/violin-v-oss \
    '-DTARGET_CONFIG_H="targets/violin-v-oss/target.h"' src/slide.c
  ```
- 所有稳定结论追加到 `03-dev-log.md`；分析输出放入 `analysis_outputs/<experiment>/`。
- 不要在没有新静态模型与独立证据的情况下重启目标设备。

## 9. 2026-07-13 交接整合状态

- `HANDOFF1.md` 已降级为历史 APK 交接，不得按其中的“立即行动”直接安装或运行 payload；完整差异和证据见 `analysis_outputs/handoff-reconciliation-2026-07-13.md`。
- 构建源码必须按**实际入口**记录：`ndk_build.sh` 直接编译 `src/slide.c`，而 `make PROJECT=violin-v-oss` 通过 `Makefile` 的 `pick_src` 优先编译 `src/targets/violin-v-oss/slide.c`。不能把任一文件称为不带构建命令的唯一有效实现；每个二进制须记录命令、源选择和 SHA256。
- direct-data 试探的补充结果：`analysis_outputs/violin-popsicle-direct/build/bin/preload.so`（SHA-256 `005E585C4C6F7A121F92A211706A31FCD21E3C761A22A34D226895820E95436B`）在 boot `d933bd9e-797a-421d-8473-998e50cbd938` 止于 consumer 进入 `sched_setattr` 前后并导致重启；没有达到 `direct-probe-ok`，没有执行 direct read 后的 credential 路径。新 boot 为 `02dbe33b-7783-40c1-8bc2-62103a98f1df`。详见 `analysis_outputs/violin-popsicle-direct/STATIC_RECONCILIATION_2026-07-13.md`。**不得重跑该 binary 或同一 rbtree shape。**
- direct shape-0 的实际写入已还原：one-child helper 会写 `Q+8` 或 `Q+16`，并写 `boot_id_data+0`。不能把它泛称只读。范围必须区分：当前运行时 CPU=9、`possible=0-9` 时，首次 `Q=__per_cpu_offset[9]` 的相邻写落在已分配但非 possible CPU 10/11 slot，可作**仅一次、早退**的 direct-route 验证；第二次 `Q=entry_task[9]` 的相邻写落在 `overflow_stack` 邻域，严禁执行。候选仅可用 `IONSTACK_P0_SEED_PROBE_ONLY=1` 与 `IONSTACK_DIRECT_PROBE_ONLY=1`，在首笔 per-CPU read 后退出，不进入 entry-task/credential 路径。详见 `analysis_outputs/violin-popsicle-direct/DIRECT_STAGE_PRECONDITION_AUDIT_2026-07-13.md`。
- 已运行上述 first-stage P0-seed probe（SHA-256 `855F77BDF2D0696D67B1B62CB6FC65187F402E132CF51EED7990297647EA167B`）：无重启、boot ID/UID/SELinux 不变，且 `pselect ret=4/calls=1/success=1`；但 boot-id oracle 保留运行前 UUID 的原始 16 bytes，未得到 expected sidecar，故 direct overwrite/read primitive 尚未建立。不得推进 entry-task。记录：`analysis_outputs/violin-popsicle-direct/P0_SEED_PERCPU_PROBE_2026-07-13.md`。
- `x-spy/CVE-2026-43499-popsicle` 已完整拉到本地并审计到 HEAD `98cf38fcf6f2e3f508979d6ad46abffb1837a246`；完整来源、历史、模块和 Violin 差异见 `analysis_outputs/popsicle-source-audit-20260713.md`。仅允许按该报告做 single-variable first-stage 对账；initial source 的 timing 与 latest source 的 `ww_ctx` 省略是独立候选，不能同时改。
- 已以 initial source 的首档 50ms 做过 single-variable first-stage timing 回归（SHA-256 `CB6CEFCEA2023728C8DB688184035D78475F03680BE7E4F0C0F7469DC7C43C58`）：`ret=5/calls=1/success=1` 但 oracle 仍为 0，且设备状态不变。停止 timing sweep；若继续只允许独立的 `ww_ctx` 字段对账，不得叠加 timing 或进入 entry-task。日志：`analysis_outputs/violin-p0-seed-delay50k-probe-20260713.txt`。
- 已独立验证 `ww_ctx` word13=0（SHA-256 `69979EFFC6B70BC3AFB795EFD7004C4D78357F13988B16326A488338622B06D5`），结果仍为 `ret=4/calls=1/success=1/oracle=0` 且设备状态不变。停止 current direct shape-0 的原样、timing 与 word13 变体；下一研究分支改为 initial release 中被删除的 TMP_PAGE/pipe primitive，先静态审计，不上机。日志：`analysis_outputs/violin-p0-seed-wwctx0-probe-20260713.txt`。
- 已对 Popsicle HEAD `generate_target.py` 的 `derive_pselect_layout()` 在 Violin OTA 原始 boot image 上独立复算：pselect word0 与 futex waiter 都是 syscall stack `sp-0x200`，严格结果仍为 `PSELECT_WAITER_WORD_SHIFT=0`；原始输出、可复跑驱动及适配边界见 `analysis_outputs/violin-popsicle-direct/popsicle-pselect-layout-violin-20260713.json` 和 `POPSICLE_PSELECT_LAYOUT_RECONCILIATION_2026-07-13.md`。这排除 shift 计算错误；`shift=1` 继续禁止。Popsicle 的 `ret/calls/success` 仅是 route 的用户态计数条件，不验证 boot-id 写入；`oracle=0` 仍表示 primitive 未建立。继续前只能离线重建 waiter 的实际消费/生命周期，禁止因本结果重跑。
- 新增 `analysis_outputs/violin-popsicle-direct/CVE_TRIGGER_GATE_AUDIT_2026-07-13.md`：Popsicle current direct source 丢弃 `FUTEX_WAIT_REQUEUE_PI` 与 `FUTEX_CMP_REQUEUE_PI` 的 return/errno，而 `ret/calls/success` 即使在普通 `sched_setattr(nice=19)` 成功时也可成立。此前 P0 logs 没记录 required `CMP_REQUEUE_PI=-1/errno=EDEADLK`，所以不能证明 CVE rollback/UAF 曾激活。下一候选只能是无 pselect/page/scheduler/写入的 trigger-only 诊断，先记录两个 futex 的精确返回；EDEADLK 以外一律停止，不得进入 direct shape。
- trigger-only 诊断已完成一次（binary SHA-256 `00E0576A983E8393C8565089F691DF5E308132F3C1F716302CD0B9516D497BA3`）：`CMP_REQUEUE_PI=-1/errno=35(EDEADLK)`，waiter 随后在配置 timeout 以 `-1/110(ETIMEDOUT)` 返回。该 run 明确不调用 pselect、page/spray、scheduler consumer、boot-id、direct read、credential 或 SELinux 路径；设备保持同一 boot `02dbe33b-7783-40c1-8bc2-62103a98f1df`、shell、Enforcing。日志 `analysis_outputs/violin-trigger-only-probe-20260713.txt`。因此 CVE rollback 已被独立确认，历史 `oracle=0` 的根因收窄为 timeout 后的 pselect stack placement / forged-waiter consumption；禁止把 trigger-only 成功称为 read 或 root。
- 新增 `PSELECT_READINESS_AND_TRACE_AUDIT_2026-07-13.md`：完全 userspace-only 的相同 fdset control 阻塞约 5006ms 后 `ret=0`，证明历史 direct `ret=4/5` 不是原始 fdset 自发 ready，而依赖 consumer/scheduler 一侧。随后唯一的 first-stage trace（仅添加 fdset/耗时日志，SHA-256 `710B37BD...E25B8F8A`）在打印 pselect before fdsets 后重启；没有 pselect-after、boot-id oracle、entry-task 或 credential 输出。boot 从 `02dbe...` 变为 `e8a179...`，恢复 shell/Enforcing。日志 `analysis_outputs/violin-p0-pselect-trace-probe-20260713.txt`。**自此禁止 current direct shape、timing、word13 和 trace 任何变体；只允许离线 waiter-consumption 重建与同 build root crash 证据恢复。**
- `CONSUMER_ORDERING_RACE_AUDIT_2026-07-13.md` 已闭合 direct 的关键实现缺口：`punch_consume_go` 在 `pselect()` 前设置，而 consumer 无“fdset 已复制到 kernel stack”的确认便可 `sched_setattr`；trace 的打印恰扩大该窗口并重启。原始 fdset control 会阻塞 5 秒，但 consumer active 时才出现 `ret=4/5`，所以当前最强解释是 consumer 与 pselect stack-copy 的无序竞争，而非 shift/三 fdset layout 错误。50ms 固定 delay 不是 stack-copy barrier。没有可验证的 post-copy 同步机制前，禁止任何 timing sweep 或 current shape 复跑。
- 已找到并验证 post-copy barrier：同一进程可读 waiter `/proc/self/task/<tid>/wchan=do_select`，而 exact `core_sys_select` 显示此时三组 fdset 已复制。一次受限 P0 first-stage run（SHA-256 `FAB1CCFA...BF4084CC`）确实先观察到 `do_select`，随后 consumer `sched_setattr` 成功、pselect `ret=5`，但 boot-id oracle 仍为 0、无重启、无 entry-task/credential。详见 `POSTCOPY_BARRIER_RESULT_2026-07-13.md` 和 `violin-p0-wchan-barrier-probe-20260713.txt`。因此 current direct oracle 失败不再可归因于 pre-copy race 或三 fdset layout；剩余前提是 scheduler 时真实 `pi_blocked_on` waiter 的寿命/身份或更早的精确 rt-mutex exit。**禁止再运行该 shape；仅离线分析。**
- `FUTEX_WAITER_LIFETIME_RECONCILIATION_2026-07-13.md` 将 observed `CMP_REQUEUE_PI=EDEADLK` + waiter `WAIT_REQUEUE_PI=ETIMEDOUT` 与 Android15-6.6 requeue state machine 和 Violin exact `futex_wait_requeue_pi` 反汇编对齐：deadlock rollback 后 timeout 的正常路径会 teardown waiter，而不是保持 `task->pi_blocked_on` 供返回用户态后的 sched_setattr 消费。post-copy barrier 下 oracle 仍为 0 正与此吻合。结论：EDEADLK 不是本机 direct primitive 成功条件；没有能跨过 ETIMEDOUT cleanup 的独立 lifetime-break 证据前，当前 direct-data route 在 rbtree 前即被语义阻断，不得再尝试。

### 9.1 2026-07-13 waiter-lifetime 结论更正（以本节为准）

- 上一条“`EDEADLK + ETIMEDOUT` 代表正常 teardown、语义阻断”的结论已**撤回**；它遗漏 CVE-2026-43499 的 `remove_waiter()` 本体缺陷。
- 已保存上游修复 `analysis_outputs/references/CVE-2026-43499-fix-3bfdc639.patch`，并在 Violin raw `boot.img.kernel` 对 runtime `remove_waiter=0xffffffe3882520f0`（image offset `0x10520f0`）逐指令核验：`mrs sp_el0` 后在 `[current + 0x938]` 清零，即清错任务的 `pi_blocked_on`；没有在同一 lock/clear 序列用 `[waiter+0x50]` 的 `waiter->task`。目标是 CVE 修复前逻辑。
- 所以 target 实测 `CMP_REQUEUE_PI=-1/EDEADLK` 后 waiter `ETIMEDOUT` **与 stale `waiter->task->pi_blocked_on` 存活相容**，不能再把它当成 no-UAF 证据。更新后的完整对账见 `analysis_outputs/violin-popsicle-direct/FUTEX_WAITER_LIFETIME_RECONCILIATION_2026-07-13.md`。
- 这只恢复“CVE stale-pointer 前提已静态成立”的事实；post-copy barrier 的 oracle=0 仍是当前 forged direct shape 的真实负结果。下一步仍仅限离线重建 `sched_setattr -> rt_mutex_adjust_pi` 对该 stale waiter 的准确身份/分支；**不恢复任何 current direct shape 上机运行**。
- `SCHED_STALE_WAITER_PATH_AUDIT_2026-07-13.md` 已将此下一步完成到可验证边界：Violin `sched_setattr@0xf2e68` 以 PI flag 进入 `__sched_setscheduler`，并在 `0xf37bc` 调 `rt_mutex_adjust_pi@0x10526c8`；后者读取 `task->pi_blocked_on@0x938`、`waiter+0x18` priority 和 `waiter+0x58` lock。candidate 的 `nice=19` 与 `FAKE_WAITER_PRIO=130` 构成非相等优先级，不能用“不是 PI API / 静态 no-op”解释 oracle=0。余下未证实事实仅为 scheduler 当刻 stale pointer 的精确值/分支，仍无上机授权。
- 当前 boot `e8a179a4-3225-4e3c-92c1-dd2a10860e8a` 已完成一次**纯读** trace-buffer canonical-pointer 审计：`tracing_on=0`，`trace` 与 `per_cpu/cpu0/trace` 均 `entries=0/0`，旧 BCC kprobe event 在重启后已不存在；`current_tracer` 被拒绝。故本次 boot 没有可消费的 `__probe_ip` canonical record。详细输出与写入边界：`analysis_outputs/trace-buffer-readonly-canonical-audit-20260713.md`。不得因该负结果尝试 enable/create event。
- `/dev/hpc-cdev` 已完成**精确 ABI 后的单命令**只读审计：同 OTA `hpc_cdev.ko` 的 `0xc0085802` 仅回传 `{tsens_id, temperature}` 两个 `int32`；target 返回 `id=0,temp=41000`，无 reboot、boot/UID/SELinux 不变，远端临时 probe 已删除。`0x5800` 是 `hdev_boot()`，绝不能测试；不允许 ioctl-number scan。故该节点不是 canonical pointer leak。完整反汇编/运行证据：`analysis_outputs/hpc-cdev-readonly-audit-20260713.md`，source `tools/hpc_cdev_readonly_probe.c`。
- 同一 HPC 族的 `/dev/hpc-rpmsg` 已由 OTA `hpc_rpmsg.ko` 静态排除：`open()` 会分配 per-file object 并 `rpmsg_create_ept()`，`read()` 会消费/释放 queue payload 或阻塞，不能称为被动只读面；本轮未打开该节点。理由已写入 `hpc-cdev-readonly-audit-20260713.md`，不得为“看看是否泄漏”而触发它。
- `/dev/ocm-buf` 虽 mode 为 world-readable，但同 OTA `xring-ocm.ko` 的全部 ioctl 都有副作用：`0xc0044f02` 调 regulator/clock-rate control，`0xc0084f01` 进行 OCM allocation + IDR state。没有 passive query；未对目标 open/ioctl。静态排除证据：`analysis_outputs/ocm-buf-static-exclusion-20260713.md`。
- `/dev/io_monitor` 的 `open()` 是空操作，但 exact `io_monitor.ko` 的 `read()` 会分配 4MiB 临时 buffer，并把全局 `io_monitor_enabled` 先写 0、完成后写 1；这不是 passive read。它仅格式化 I/O counters/timestamps；未在 target 读取。静态排除：`analysis_outputs/io-monitor-static-exclusion-20260713.md`。
- `/dev/camlog` 虽可由 shell 打开，但 exact `cameralog.ko` 的 `cameralog_read()` 先以 `__kfifo_out(..., 0x408)` 从共享 FIFO 出队一条日志，再 copy-to-user；read 本身会消费记录。其 ioctl 也含 logger-state 写入/出队分支，未找到有明确结构、无副作用的地址查询 ABI。本轮未对 target open/read/ioctl；静态排除：`analysis_outputs/camlog-static-exclusion-20260713.md`。
- 当前 boot 的标准 address surface 已纯读复核：`/proc/kallsyms`、`/proc/vmallocinfo`、`/proc/iomem` 和五个已加载模块的 `sections/.text` 均被拒绝；`/proc/modules` 虽可读但 load-address 字段全部是 `0x0000000000000000`。这只是地址隐藏，绝非可用的零地址。详见 `analysis_outputs/standard-canonical-surface-readonly-audit-20260713.md`；不得为突破该负结果改变 SELinux/trace/module 状态。
- `/dev/timestamp` 已按 matching `xr_timestamp.ko` 的精确 ABI 审计：仅 `0x80086b00/0x80086b01` 两个 `_IOR`，各回传一个 MMIO counter/换算时间 `u64`，没有地址字段。最小 `O_RDONLY` probe 在 shell 域即 `EPERM`，故 ioctl 未发送；boot/UID/SELinux 不变、远端 binary 已删除。排除记录：`analysis_outputs/timestamp-readonly-audit-20260713/TIMESTAMP_READONLY_AUDIT.md`。
- `/dev/hpc-heap` 已由 matching `hpc_mem.ko` 静态排除：`open()` 就分配并挂入约 3520-byte per-file controller state；首个 ioctl `0x80045800` 沿 heap/DMA-buf/IOMMU allocation 路径改变状态。没有 passive query，本轮未在 target open/ioctl。证据：`analysis_outputs/hpc-heap-static-exclusion-20260713.md`。
- `/dev/hpc-mitee-crypto` 的 matching `hpc_mitee_crypto.ko` 虽有空 `open()`，但唯一 `0xc0885800` ioctl 处理 0x88-byte secure model-key request/return；它不是 kernel-object address query，且会进入 key-service 路径。本轮未打开或 ioctl；不得用于 scan/探测。静态排除：`analysis_outputs/hpc-mitee-crypto-static-exclusion-20260713.md`。
- Popsicle 附带的 `kernelsnitch` 已对 Violin 重新判定：ARM 默认仅穷举 `0xffffff800...` 起的 64GiB P0/direct-map `mm_struct` 域，不会得到 canonical KASLR text；默认执行还会映射 64GiB、创建 4096 个阻塞 futex waiter、以 20 threads 做大规模穷举。历史 P0 first-stage 的 `prepare_kernel_page()` 已间接成功产出 P0 `workspace=` slab base（当前 boot post-copy 为 `0xffffff801dc28000`），但这只验证 prepare anchor，不验证 pselect overwrite，且不改变地址域结论。BTF 的 `mm_struct` payload 为 `0x4c0`，rooted same-build slabinfo 的 cache stride 为 `0x500`，故 candidate `MM_STRUCT_SZ=0x500` 已核验正确；target 无 `mte` CPU feature。不得把它当作 fops/CFI leak 或重启 direct route 的理由。详见 `analysis_outputs/kernelsnitch-violin-feasibility-audit-20260713.md`。
- 已以 upstream HEAD `98cf38fc...` 完整 diff 关闭 candidate source-drift 疑点：除 Violin `target.h` 和已记录的 trigger-only/post-copy barrier/probe gate/word13/日志外，`pipe.c`、`util.c`、`slide.c`、`offset.h`、Kernelsnitch 等均未变。故 P0 oracle=0 不能归因于未记录的本地核心实现漂移；仍只可离线定位 target-specific stale waiter 消费，不恢复 shape。证据：`analysis_outputs/popsicle-violin-source-drift-closure-20260713.md`。
- 对 Popsicle initial `28f5d45` 的补充复核亦排除“退回旧版即可改变 first-stage grooming”：default `clone_memfd` guard-mm 保活、pre/spray/post count、`0x500` stride、order-3 slab、4 次 skb reclaim 和 fops waiter core 布局与 latest direct chain 等价；initial 大量额外代码是 primitive 成功后的 configfs/pipe/root 处理。TMP_PAGE/pipe 仍不是当前 P0 oracle=0 的绕过。完整对照并入 `analysis_outputs/popsicle-violin-source-drift-closure-20260713.md`。
- `KSULaoderv2_decompiled` 已核对：它依赖正在运行且已授权的 Shizuku，实际只是 Android `shell` 域 delegation，不含 kernel bootstrap。target 虽安装 KernelSU Manager 与 Shizuku，Shizuku server 也确以 `shell` 运行，但未见 `ksud`/kernelsu daemon；不能作为当前无 root 的替代路线。本轮未调用 `su` 或 loader injection。详见 `analysis_outputs/ksu-loader-shizuku-bootstrap-audit-20260713.md`。
- `sysctl_bootid` 的“双地址”疑点已静态闭合：rooted same-build kallsyms 将它标成 BSS `b`，且 Android15/6.6 source 定义为 `static u8 sysctl_bootid[UUID_SIZE]`；`random_table[]` 的 ctl_table entry 是另一个无符号表对象，`.data` 才指向该 buffer。因此 `SLIDE_RANDOM_BOOT_ID_DATA_OFF` 与历史名 `SLIDE_SYSCTL_BOOTID_OFF` 原本相同不是遗漏，而是同一 16-byte boot-ID data buffer 的重复命名；后者已改为带注释的 compatibility alias，数值不变。此项**不**推翻 P0 oracle=0，也不授权 direct shape 复跑。完整证据：`analysis_outputs/sysctl-bootid-symbol-reconciliation-20260713.md`。
- `/dev/mali0` 已从 canonical audit 候选中静态排除：matching `mali_kbase.ko` 的 `kbase_open()` 会先调 `kbase_device_firmware_init_once()`，然后分配 `0xcc0` bytes 的 file-private GPU context、写 `private_data`；不能把其 version ioctl 视为 passive read。`kbase_ioctl()` 中可辨认的 `0xc0048000` 仅四字节 protocol version copy-in/out，不是 pointer 输出；其余是 GPU state/memory/queue 类 command。本轮未在 target open 或 ioctl。详见 `analysis_outputs/mali0-static-exclusion-20260713.md`。
- `/dev/npu_freq_qos_min` 与 `/dev/npu_freq_qos_max` 也已静态排除：matching `npu_freq_qos.ko` 的任一 `open()` 都会分配 `0xdc0` bytes 并调用 `freq_qos_add_request`（min=0 或 max=`INT_MAX`）；read 虽只输出 4-byte scalar，却必须先创建该 QoS request，write 更会 `freq_qos_update_request`。本轮未对 target open/read/write。详见 `analysis_outputs/npu-freq-qos-static-exclusion-20260713.md`。
- `/dev/tango32` 已静态排除：matching `tango32.ko` 只有二进制翻译控制 ioctl；其看似 output-only 的 `0x800474a0` 仅回传常量 2，`0x800874a5` 仅回传两个 32-bit word（current-task field 的低 32 bits 和常量 12），不存在完整 canonical pointer。其余 ioctl 会修改 current thread translator 状态或操作 caller fd/directory，不能作为 passive query。本轮未发送 ioctl。详见 `analysis_outputs/tango32-static-exclusion-20260713.md`。
- 已对 2026 年公开 Linux LPE 路线做配置级筛选：`CONFIG_CRYPTO_USER_API_AEAD`、`CONFIG_AF_RXRPC`、`CONFIG_NF_TABLES`、`CONFIG_USER_NS` 都未设置；live shell 亦 `CapEff=0`/Enforcing。故 Copy Fail、Dirty Frag 的 RxRPC path、CVE-2026-23111 与发布的 Fragnesia user+net namespace path 均不在本 target 的可执行条件内；`CONFIG_XFRM_ESP=y` 单独不足以推导 Fragnesia 可达。未创建 namespace 或运行 payload。详见 `analysis_outputs/public-lpe-route-config-triage-20260713.md`。
- 同一 public-LPE triage 已补充 CVE-2026-46333：对 `/system`、`/system_ext`、`/product`、`/vendor`、`/odm`、`/apex` 的 metadata-only setuid/setgid/file-capability scan 均为空，未发现可承载公开 `ssh-keysign`/setuid-exit-race 路线的 Android privileged-transition binary。此为 carrier 缺失结论，不宣称内核是否已修复；未执行 `pidfd_getfd` 或任何 race。详见同一报告。
- CVE-2025-48595（A-430889718）已完成版本与 framework 调用链对账：target 的只读 pulled `/system/lib64/libsqlite.so` 是 SQLite `3.44.3`（SHA-256 `12C3DA1C8A261541A648C77F41C0A7BDE4BC0B0DFA72F1C0F912D59AA2E3F89E`），而官方修复在 2026-06-01 的 3.44.5 更新中规范化 `setupLookaside()` 的 `sz/cnt` 后再做乘法；target SPL 为 2026-05-01。因此仅“version-vulnerable candidate”成立。AOSP Framework 的 public `SQLiteDatabase.OpenParams.Builder.setLookasideConfig()` 会在**调用 app 自己的进程**传入该 JNI/`sqlite3_db_config` 路径；尚未找到 untrusted app 可控制的 privileged-service carrier，不能把该结果称为 root 或 LPE 已实现。`HORKimhab/CVE-2025-48595` 本地 clone 没有实现代码，不可作为来源。完整边界：`analysis_outputs/cve-2025-48595-violin-feasibility-20260713.md`。本轮未构建、安装或运行 trigger；下一步仍仅限静态 carrier/权限可达性审计。
- 上述 SQLite carrier 审计已扩大并得到负结果：AOSP `frameworks/base` 的 `core/services/packages` 没有 API 实现和测试之外的 `.setLookasideConfig()` 调用；target 上对 framework/vendor/APEX JAR 及全部 preinstalled APK 的 `classes*.dex` 只读字符串审计中，只有 `/system/framework/framework.jar` 命中 API 名，APK 无命中。该结果排除普通直接 Java-bytecode privileged caller，但不排除 reflection/native/dynamic code，故仍不能把 CVE 当作 root route。命令边界和限制已加入 `analysis_outputs/cve-2025-48595-violin-feasibility-20260713.md`；未启动 app、未安装 APK、未运行 trigger。
- 同一 SQLite audit 还以只读二进制字符串扫描 `/system`、`/system_ext`、`/product`、`/vendor`、`/odm`、`/apex` 的 `.so`：`sqlite3_db_config` 仅出现在 `/system/lib{,64}/libsqlite.so` 和预期的 Framework JNI `/system/lib{,64}/libandroid_runtime.so`，没有 vendor/product native direct importer。它进一步收窄 native carrier，但不排除静态链接/反射/动态代码；仍不是 root 证据。
- 当前 Popsicle working tree 的 EDEADLK 后续链已静态复核：`exploit/src/slide.c` 的本地未提交 E25 instrumentation 会在 `CMP_REQUEUE_PI=-1/EDEADLK` 时置 `slide_uaf_primed=1` 和 `slide_consume_stop=1`，而 consumer 在 `sched_setattr_tid()` 前检查该两 flag 并以 `SLIDECONS_SKIP` 退出。因此**按当前 working tree 构建**只能证明 trigger，永远不会消费该 stale waiter；不能把它的 EDEADLK 输出当作 pselect/rbtree primitive。此 gate 并非 upstream `1a10c4e...`，也不得反向篡改历史 binary 的证据。未修改源码或构建；完整静态审计：`analysis_outputs/popsicle-uaf-consumer-gate-audit-20260713.md`。direct shape 继续禁止运行。
- 上述 gate 已与历史 direct binary source snapshot 对账：`analysis_outputs/violin-popsicle-direct/src/slide.c` 没有 E25 gate，consumer 无条件进入 `sched_setattr_tid()`，且 `CMP_REQUEUE_PI` 的第四参数为 `(void *)1`；它正是已有 post-copy barrier `sched_setattr` 成功但 oracle=0 的负结果所对应的路径。当前 tree 除 gate 外还把该参数改为 `(void *)0`，与自己“requeue=1”的注释不符。故不能把历史 oracle=0 归因于后来加入的 gate；当前 tree 也不是历史 binary 的忠实复现。详见同一 audit；不构建/运行任何变体。
- 新发现的候选为 Bad Epoll / CVE-2026-46242：Violin matching raw kernel 的 exact `ep_remove()`（image `0x427dec`）仍直接取 `epi->ffd.file`、在 `file->f_lock` 后才检查 dying，缺少 upstream `a6dc643c693` 的 `epi_fget()` pin；且 `ep_clear_and_put` terminal path 仍 `bl kfree@0x311774`，没有 CVE-2026-43074 `07712db8` 引入的 RCU-deferred eventpoll free。`CONFIG_EPOLL=1`，公开 trigger 不要求 capability/user namespace。因此 static vulnerable condition 已被 raw binary 证实。公开完整 exploit 只覆盖 x86-64 kernelCTF 6.12/COS，Android/ARM64 exploit 尚未发布；不能直接拷贝或称已 root。下一阶段仅限 ARM64/Violin 离线 port-feasibility/mitigation audit，仍不得构建、安装或运行新 payload。完整证据：`analysis_outputs/bad-epoll-violin-static-audit-20260713.md`。
- Bad Epoll port audit 的第一批 target 差异已实测：live `/proc/slabinfo` 的 `filp` 是 320-byte、25 objects/2 pages，不是公开 source 仅支持的 192/256 geometry；same config 还启用 `SLUB_DEBUG`、freelist hardened/random。raw `ep_remove` 进一步显示 active randomized `struct file` 的 `f_lock=+0x10`、`f_ep=+0xe0`，禁止套用公开 x86 field constants。目标同时 `RANDOMIZE_BASE`、`CFI_CLANG`、SCS、ARM64 kernel PAC，且当前仍无 same-boot canonical leak；公开的 `rdtscp` prefetch KASLR leak 与 x86 f_op->poll ROP/JOP 不能直接移植。UAF 状态未被否定，但 320-byte cross-cache、canonical leak、file/inode exact offsets、CFI/PAC-compatible elevation 都尚未建立。完整更新已并入 `analysis_outputs/bad-epoll-violin-static-audit-20260713.md`；只读 metadata 外未操作设备。
- Bad Epoll 的 matching raw `boot.img.kernel` 内嵌 BTF 已解析并关闭 fdinfo 字段未知：`struct file` 为 `0x108`，`f_inode=0xb8`、`f_op=0xc0`、`private_data=0xd8`，`inode.i_sb=0x28`/`i_ino=0x40`，`super_block.s_dev=0x10`；这些是 target-build BTF，不是套用公共 x86 layout。由此 constrained `ino` read 的 guard 精确为 `A-0x18`。在冻结的 same-build P0 profile 下，`A=P0(init_task)+comm(0x830)=0xffffff80022eeab0` 时 guard 正好是 `init_task.real_cred@+0x818`，可作为**条件性的 data-only fdinfo bootstrap 模型**（预期读出 `swapper/`），不需要先得到 canonical text。它仍依赖未建立的 320-byte cross-cache，且 `real_cred` 未从本 boot 读取；不是 runtime AAR、canonical leak、写原语或 root。详见 `analysis_outputs/bad-epoll-violin-fdinfo-bootstrap-audit-20260713.md`；未 build/install/run。

## 10. 2026-07-15 — sched_blocked_reason tracefs KASLR leak (new active evidence)

- On the current unrooted target boot `9668d46b-4917-4ae2-b717-dab05eef25be`, ADB `shell` (`uid=2000`, SELinux Enforcing, gid `readtracefs`) can enable `sched:sched_blocked_reason` and `tracing_on`; both nodes are `0666` in this tracefs mount. A bounded two-second test restored both to `0`, did not reboot, and collected 336 formatted records plus a 4096-byte CPU0 raw trace capture.
- The exact live format is `ID=109`, `caller` at event-payload offset `16`, width `8`. Raw record `pid=25045` gives `caller=0xffffffd30a6d797c`; its formatted twin is `worker_thread+0x9c/0x334`. Same-build static arithmetic `worker_thread-_text=0xd78e0` derives **current `_text=0xffffffd30a600000`**. This is a same-boot canonical text base, not P0/direct-map.
- Evidence: `analysis_outputs/sched-blocked-reason-kaslr-leak-20260715.md`, raw `analysis_outputs/sched-blocked-reason-raw-cpu0-20260715.bin`, offline decoder `tools/parse_sched_blocked_reason_raw.py`. Run the decoder with `--symbol-offset 0xd797c`.
- Offline five-check verifier `tools/verify_sched_blocked_reason_kaslr.py` revalidated the archived hash, event/field layout, symbol delta, caller value, and derived `_text`; result: `analysis_outputs/sched-blocked-reason-kaslr-verifier-20260718.md`.
- Fresh online shell check on boot `c79163bc-d9f5-457a-a30f-0362d89db8ea` read a bounded 64 KiB CPU0 raw sample (SHA-256 `D344ED5D573D5FB3E8CE354D5AE75F4311AF9A86D80DCC28AFE185E2831232E1`) and reproduced `worker_thread+0x9c` → `_text=0xffffffd692800000`; details: `analysis_outputs/violin-live-trace-oracle-check-20260718.md`. The read consumed ring-buffer data but did not write tracefs state or run a payload.
- Corrected native reader `tools/trace-kaslr-leak/trace_kaslr_leak.c` now uses caller offset `16` and preserves tracefs state by default; its AArch64 ELF (`SHA-256 2B33202758040FF7C7B0A1EF93907CC47BF99FCC69B4A0A8616936AB2C85D022`) ran online for 100 events and reproduced the same anchor. Output: `analysis_outputs/violin-live-tool-v2-20260718.txt`.
- Firefox online probe must use the parent `index.html`, not the headless `exploit.html` child. The corrected current-boot probe completed and visibly returned `FIREFOX_TRACEFS_RAW_READ_STATUS=1` with `Permission denied`, UID 10270/untrusted_app; screenshot: `analysis_outputs/firefox-tracefs-probe-live-20260718-index.png`. This reconfirms the app-domain gate is closed.
- The `index.html?payload=pselect-layout-only` userspace-only probe returned `PSELECT_LAYOUT_DONE: ok=1 no_kernel_route=1` with the expected IN/OUT/EX word mapping; evidence: `analysis_outputs/pselect-layout-only-live-crash-20260718.txt`. It did not call the kernel route or change boot state.
- Scope gate remains: this leak is proven only in ADB shell's tracefs principal. The existing browser/app payload UID has not been shown to be `readtracefs` or to own tracefs write access. Do not wire the base into that payload as an in-process oracle without separately proving that execution-domain equivalence or an authorized same-boot handoff.
- Firefox-domain gate closed: active `org.mozilla.firefox` is UID 10270 in `u:r:untrusted_app:s0`, no `readtracefs` supplementary group; `trace_pipe_raw` is `0440 root:readtracefs`. The sched trace raw-pointer leak cannot be read from the current Firefox payload process. Keep it classified as an ADB-shell-only same-boot oracle.
- Firefox in-process confirmation now supersedes inference: explicit Firefox page command bridge returned `Permission denied` for both `ls` and `head` on `/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw` (`FIREFOX_TRACEFS_RAW_READ_STATUS=1`, uid=10270, `u:r:untrusted_app:s0`). This trace oracle remains unavailable to Firefox even though ADB shell can use it.
- Shell-assisted `cfi-stage` was run once with the verified same-boot tracefs `_text=0xffffffd30a600000` via Firefox `kbase` parameter. It rebooted before root; new boot `c1d5962f-411e-4596-93c8-9fb54957e003`, shell UID and SELinux unchanged. This validates only base injection; the active blocker moves downstream to CFI/configfs/pipe. Do not re-run current full artifact; fresh trace base is mandatory after reboot and any next action must isolate its downstream fault.

## 11. 2026-07-18 Dijun / Violin DTBO 与公共 XRing 模块差分（离线完成）

- 设备仍断开；本项只读取本地工厂包/OTA 分区，未联机、未刷写、未安装或运行 payload/module。
- 两边 DTBO 均解析为 8 个标准 entry，ID 集合相同；Violin O81A PAD 对应 entry 7，ID `0x09020101`。`fragment@N` 编号在构建间移动，已按 `fragment@#` 归一化后比较。
- entry 7 共享 `dsi_panel_o81a_0a_dualdsi_dsc_lcd_video` 与 `xiaomi-touch-violin`，但面板亮度/时序/命令模式、hall GPIO、keyboard pin、sensor-pu/pd、fixup target 均存在差异；DTBO entry 中没有可直接迁移的 `reserved-memory` 物理布局，`memory-region` 多为占位 phandle。
- vendor ramdisk 按同路径匹配出 31 个公共 `.ko`；全部 ELF64 AArch64，但 31/31 大小或 SHA-256 不同。Dijun vermagic 为 `6.6.30-android15-8-4k`，Violin 为 `6.6.77-android15-8-4k`。经 §15 canonical CPIO 复核后，定义符号集合差异仅剩 `minet.ko`（1/31）；9 个模块有 `__export_symbol_` 字符串差异。旧的 `xring_smartpa.ko` “无 `.modinfo`/0 symbols”记录已撤销。
- 结论：Dijun 仅可作为同 SoC 的节点/功能/接口线索，不能移植 DTBO、模块、地址、偏移、结构体布局或 exploit 参数；后续接口核验必须以 Violin same-build artifact 为准。
- 详细报告：`analysis_outputs/dtbo-node-diff-20260718.md`、`analysis_outputs/module-interface-summary-20260718.md`；原始证据：`analysis_outputs/dtbo-diff-20260718/`、`analysis_outputs/module-diff-20260718/`。

## 12. 2026-07-18 Violin base DTB × entry 7 引用闭合

- 离线解析 `analysis_outputs/ota_full/boot_parse/vendor_boot.img.dtb`：941 个节点、5466 个属性、592 个 `__symbols__` 标签；`/reserved-memory` 有 46 个子节点。
- Violin entry 7 有 106 个 fragment（13 个 `target-path`、93 个 symbol-target），113 个 `__fixups__` 标签全部能在该 base DTB 的 `__symbols__` 中解析，引用路径存在。
- `chosen` fixup 闭合到 base `/chosen`；overlay 只增加 `bootargs_ext` 空格，不替换 base `bootargs`。关键 reserved-memory 引用闭合为：`memdump_reserve -> rsv_mem_log@43480000 (phandle 0x232, 10 MiB)`、`perf -> disabled rsv_mem_perf (0x243)`、`wifi_mem -> rsv_mem_wifi_reserve (0x245, 0x1b00000)`、`wifi_page_pool_mem -> rsv_mem_wifi_page_pool (0x246, 0x5400000)`。
- 这只证明 Violin 自己的 base DTB 与 entry 7 在 symbol/fixup 层自洽；未生成可刷写 merged DTB，未刷写设备。详细记录：`analysis_outputs/violin-base-dtb-entry7-audit-20260718.md`。

## 13. 2026-07-18 Violin entry 7 有效节点语义投影

- 新增只读投影工具 `tools/project_dtbo_overlay.py`，将 Violin base DTB 与 entry 7 在内存中按 fragment target 合并，仅输出 JSON 语义，不生成可刷写 DTB。
- 106 个 fragment（13 个 `target-path`、93 个 symbol-target）、113 个 fixup label、237 个 fixup location 全部闭合；投影新增 2520 个节点、8711 个属性，覆盖 252 个 base 属性。
- 最终 `/chosen` 保留原 bootargs，仅增加 `bootargs_ext=" "`；O81A 面板最终为亮度 4095、`non_continuous`、idle `0x2002`、lowpower `0x9d`、reset `[1,1,0,3,1,10]`，default on/off command 为 HS mode（1079/42 bytes）。
- 最终 hall pin 为 lid=4、table=10；keyboard default 为 `PAD_GPIO_050/PAD_GPIO_056`，LS enable 为 `PAD_GPIO_088`。关键 reserved-memory 引用仍落到 Violin base phandle `0x232/0x243/0x245/0x246`。
- 报告：`analysis_outputs/violin-entry7-effective-projection-20260718.md`；JSON：`analysis_outputs/violin-base-dtb-entry7-projection-20260718.json`。该投影不是 merged DTB，不能用于刷写或推导 kernel 地址。

## 14. 2026-07-18 Dijun / Violin entry 7 最终有效树对比

- 从 Dijun v4 `vendor_boot.img` 离线提取 base DTB：offset `0x1584000`、size `182478`、SHA-256 `991f99d159324aa6925dba2399fdbccf552e72c6eddcac92c181109293073fc9`。
- 用同一语义投影器对 Dijun entry 7 复算：97 fragments、112 fixup labels、219 locations，全部成功；与 Violin 的 106/113/237 形成可比基线。
- 最终有效差异确认：Dijun panel brightness 2047、continuous、idle/lowpower=0、reset `[1,1,0,1,1,10]`、LP commands 176/24 bytes；Violin 为 4095、non_continuous、`0x2002/0x9d`、reset `[1,1,0,3,1,10]`、HS commands 1079/42 bytes。Dijun 无 Violin 的 `/xiaomi_hall` 子树，keyboard GPIO 也不同。
- reserved-memory 物理范围基线相近但 phandle 不同（Dijun `0x236/0x247/0x249/0x24a`，Violin `0x232/0x243/0x245/0x246`），禁止跨 build 复用。
- 报告：`analysis_outputs/dijun-violin-effective-entry7-diff-20260718.md`；Dijun base DTB：`analysis_outputs/dijun-selective-20260718/images/vendor_boot_dtb_extracted.dtb`。

## 15. 2026-07-18 既有 DTBO/模块分析错误审计与修正

- 审计发现投影器 `tools/project_dtbo_overlay.py` 的第一版把 overlay-local phandle delta 写成 `base_max + 1`；libfdt 实际使用 base tree 的最大 phandle 作为 delta。已改为 `delta=base_max`，并按 `__local_fixups__` 重新生成 Dijun/Violin 两份 JSON。此前临时投影中只涉及 overlay-local phandle 的值作废；external fixup、fragment 统计、面板/键盘/hall 高层差异未受影响。
- 纠正后的 local-fixup 对账：Dijun `base_max=596, delta=596, node phandle=820, locations=394`；Violin `base_max=592, delta=592, node phandle=851, locations=409`。证据：`analysis_outputs/dijun-base-dtb-entry7-projection-20260718.json`、`analysis_outputs/violin-base-dtb-entry7-projection-20260718.json`。
- 审计发现模块差分中的 Violin `xring_smartpa.ko` 副本 SHA `bed0dc8f...` 与原始 vendor ramdisk CPIO 同路径文件不一致，导致 section table、`.modinfo` 和符号解析为 0。canonical SHA 为 `ca519d3b...`；纠正后 Dijun/Violin 均为 294 个定义符号、均含 `depends=miev`，差异仅为 build/vermagic。错误副本已保留为 `.invalid-extraction-20260718`。
- 因此旧的“Violin smartpa 无 `.modinfo`/0 symbols”和“符号集合差异 2/31”结论撤销；修正后符号集合差异为 1/31（仅 `minet.ko`）。机器证据：`analysis_outputs/module-diff-20260718/module-interface-correction-20260718.json`；总审计报告已同步修订。
- 当前仍保持离线门禁：未连接设备、未刷写、未安装/加载模块、未运行 payload。完整错误审计记录：`analysis_outputs/previous-analysis-error-audit-20260718.md`。

## 16. 2026-07-19 当前 Violin boot 的 sched_blocked_reason 只读复核

- 设备已重新联机：serial `03035440C1781540`；当前 `boot_id=c79163bc-d9f5-457a-a30f-0362d89db8ea`，kernel `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`。
- 在不改 `enable`/`tracing_on` 的前提下，从 CPU0 `trace_pipe_raw` 有界读取 64 KiB；event 109 解析到 92 个唯一合法记录，精确命中 `caller=0xffffffd6928d797c` 14 条。
- 结合同 build `worker_thread-_text=0xd78e0` 与 caller `+0x9c`，当前 boot `_text=0xffffffd692800000`。raw SHA-256=`3D02D87142BA7AABF260FC938903CBDB83DAAA59F8DD96B8BD017C243692272C`。
- 该读取消费 CPU0 ring（entries `39825→38120`，read events `6003→7811`），但 `enable=1`、`tracing_on=1` 未改变。证据：`analysis_outputs/violin-device-sched-blocked-raw-20260719.bin` 及同名报告。
- 这只证明 ADB shell/readtracefs 域的同 boot canonical record；Firefox/app 域权限、arbitrary write、fops/CFI 和 payload 链仍未证明。不得把该 `_text` 地址跨 boot 硬编码。
- 当前 Firefox PID `15438` 为 UID `10270`、`u:r:untrusted_app:s0:c14,c257,c512,c768`，不含 `readtracefs`；`trace_pipe_raw` 是 `0440 root:readtracefs`。因此 shell 侧 `_text=0xffffffd692800000` 不能直接视为 Firefox payload 的 oracle。详细权限证据：`analysis_outputs/violin-firefox-tracefs-access-check-20260719.md`。

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

- `tools/enumerate_untrusted_app_char_devices.py` 已对当前 boot 的两份 CIL 与两份 `/dev` file_contexts 做属性展开闭包，共 37 个带 `chr_file` 投影的类型；输出：`analysis_outputs/violin-untrusted-app-char-device-closure-20260719.md`、`.json`、`.txt`。
- 没有发现新的 XRing 专用字符节点 app 入口。可达类型仅保留：`gpu_device` 的 `/dev/mali0`（open/read/write/ioctl/map）、`dmabuf_system_heap_device` 的三个 XRing system heap（open/read/ioctl/map、无 write）、以及 boot-created `ashmem_libcutils_device`；精确 `/dev/ashmem` 的 `open` 被 `neverallow` 阻断。
- `camlog_device`、`npu_device`、`video_device`、`xr_*` helper 等没有 `untrusted_app` 的有效字符设备投影。报告是 raw policy projection，不替代 `secilc`/`checkpolicy`；本轮仍未打开设备节点、发 ioctl/read/write 或运行 payload。

## 2026-07-19 当前 boot 候选节点标签复核

- 只读 `ls -ldZ` 已核对 `/dev/ashmem`、boot-created `/dev/ashmemc79163bc-d9f5-457a-a30f-0362d89db8ea`、`/dev/mali0` 与三个 XRing system dma-heap；现场 type 与离线 CIL 闭包一致。
- 不得把两个 ashmem 节点合并：精确 `/dev/ashmem`=`ashmem_device`（无 `open`，命中 `neverallow`），boot alias=`ashmem_libcutils_device`（有 open/read/write/ioctl/map 投影）。原始记录：`analysis_outputs/violin-live-cil-candidate-label-check-20260719.txt`；报告：同名 `.md`。
- 本轮仍未打开节点、发 ioctl/read/write/mmap、改变 trace 状态或运行 payload。

## 2026-07-19 DMA heap 现场目录标签补充

- `ls -lZ /dev/dma_heap` 现场确认 `system`、`system-uncached` 与三个 XRing heap 均为 `dmabuf_system_heap_device`，而 `xring_npu_dym`/`xring_tui_*` 为普通 `dmabuf_heap_device`。
- 研究矩阵中的 app 可达 system-heap 集合应包含 5 个节点；同一 `DMA_HEAP_IOCTL_ALLOC` ABI/有状态 allocator 结论适用于它们，未产生 passive canonical leak。原始记录：`analysis_outputs/violin-live-dma-heap-directory-metadata-20260719.txt`。
- 本轮仍未打开 dma_heap、分配/映射 buffer、发 ioctl/read/write 或改变 trace 状态。

## 2026-07-19 tracefs `untrusted_app` CIL gate 闭合

- `plat_sepolicy.cil:329` 将 `sched_blocked_reason` event 归为 `debugfs_tracing`；`untrusted_app` 通过 `untrusted_app_all` 命中 `:30609` 的 file `neverallow`，包含 `open/read/write/ioctl`。`domain -> debugfs_tracing` 在 `:14057` 只有目录 `search`。
- 结论：Firefox app 域既不能读 `trace_pipe_raw`，也不能把 `enable` 的 DAC `0666` 当作可写；`:30648` 的 `dontaudit` 可能隐藏拒绝。shell/readtracefs 侧的 `_text` 不可直接交给 Firefox payload。
- 报告：`analysis_outputs/violin-live-tracefs-cil-gate-20260719.md`；解析输出：`analysis_outputs/violin-live-sepolicy-tracefs-resolution-20260719.json` / `.txt`。
- 当前最优下一步是只读确认是否存在既有 privileged/readtracefs broker；若不存在，冻结 app-domain tracefs 路线，不再扩大字符设备搜索。

## 2026-07-19 52pojie OnePlus GhostLock 文章复核

- 文章目标为 OnePlus 13T / kernel 6.6.89，作者自己记录 full chain 在 slide 阶段因 UBSAN array-bounds → BRK → mrdump 重启，未完成 leak/fops/root；不是成功 root 证据。
- 对 Violin 可复用的只有 hardening/隐性 ABI 审计方法与 `ashmem_misc.fops` 指针槽语义。OnePlus 绝对地址、`shift=1` 和 KernelSnitch 方向均不可直接迁移；Violin static audit 已得 `shift=0`。
- 文章复核报告：`analysis_outputs/52pojie-oneplus-ghostlock-violin-comparison-20260719.md`。不因文章的“编译成功”描述重跑 full payload。

## 2026-07-19 `readtracefs` 进程主体验证

- 只读扫描当前 boot 的进程状态发现：除 shell/adbd 外，`traced_probes`、`system_server`、`gpuservice`、`hal_camera_default`、`mobile_log_d` 持有 GID 3012。
- `traced_probes`（PID 1687）是下一步唯一优先的离线对象；先审计其 Perfetto/Binder/socket 接口和 app 调用权限，不能因为持有 `readtracefs` 就直接联机调用。
- 证据：`analysis_outputs/violin-readtracefs-principal-inventory-20260719.md` / `.txt`。本轮没有访问 tracefs、执行 Binder transaction 或运行 payload。

## 2026-07-19 Perfetto/trace broker CIL 审计

- `appdomain` 仅获得到 `traced` 的 producer-side 连接/写入（`plat_sepolicy.cil:9456-9459`）；没有 `traced_consumer_socket` 或 `perfetto_traces_data_file` 读取 allow。
- 因此 `traced_probes` 虽然持有 `readtracefs`，也不能据此推导 Firefox 能消费 `sched_blocked_reason` caller；不要直接联机发 socket 请求。
- 详细报告：`analysis_outputs/violin-trace-broker-cil-audit-20260719.md`。下一步仅离线检查同 build Perfetto relay 配置/source，确认是否存在专门的 app consumer path。
- 机器输出：`analysis_outputs/violin-trace-broker-cil-resolution-20260719.json` / `.txt`；同时覆盖 `traced_perf`/`traced_perf_socket`，其服务语义是 `/proc`/perf profiler，不是 ftrace consumer。
- `perfetto.rc` metadata-only 证据：`analysis_outputs/violin-perfetto-rc-metadata-20260719.txt`；`traced_consumer`/`traced_producer` 虽为 0666，SELinux consumer allow 仍缺失。
- `traced_relay` 只转发 producer 数据到 VM/host，与 `traced` 互斥，不能作为 Firefox consumer relay。至此同 build consumer-relay 离线检查完成；Firefox tracefs oracle 路线冻结。
- 当前 boot 只运行 `traced`/`traced_probes`；`traced_relay`、`traced_perf` 均 stopped，socket 只有 `traced_consumer`/`traced_producer`。证据：`analysis_outputs/violin-perfetto-live-state-20260719.txt`。

## 2026-07-19 同 build target baseline 核验闭合

- 离线核验器 `tools/audit_violin_kernel_baseline.py` 已修正注释解析：现在能识别 `/* symbol: ashmem_misc (miscdevice struct) */`、`/* symbol: sysctl_bootid ctl_table */` 这类带附加说明的 symbol 注释；此前版本会静默漏检这两项。
- 用 `target.h` + `analysis_outputs/violin-kernel-info2/violin-kernel-info/{kallsyms,iomem}.txt` 重跑：27 个 symbol offset、2 个 physical-layout 字段全部匹配（`ok=true`, `mismatches=0`）。
- 重点确认：`ASHMEM_MISC_OFF=0x223b5d8` 是 same-build `ashmem_misc` 相对 `_text` 偏移；fops 劫持语义仍应指向 `ashmem_misc + 0x10` 的 `miscdevice.fops` 槽，而不是 `misc_fops` 静态结构体本体。
- 产物：`analysis_outputs/violin-target-baseline-audit-20260719.json`，SHA-256 `01D8DED9C7BC3A70490F4A09295876008D24D378F755B8F934956492E62F5DA6`；脚本 `python -m py_compile` 通过。
- 该核验只闭合静态相对偏移/物理布局，不提供当前 boot canonical base，也不授权联机 payload 或任何新写入实验。

## 2026-07-19 ashmem fops 目标语义代码修正

- active common source 的旧引用已纠正：`ASHMEM_MISC_FOPS` 只代表静态 `struct file_operations` 对象；Violin fops 劫持目标统一为 `ashmem_misc + 0x10` 的 `miscdevice.fops` 指针槽，rb parent/color 为槽位减 `0x08`。
- 已同步修正 `src/util.c`（默认 pselect target、fake parent、write_left）、`src/main.c`（cfgprobe readback）和 `src/fops.c`（诊断变量/日志）；历史 `.bak-*` 与其他设备 target 目录未改。
- WSL `/usr/bin/clang -fsyntax-only` 对 Violin target 的四个 active C 源通过；报告：`analysis_outputs/violin-fops-target-slot-audit-20260719.md`。
- 仅完成静态代码修正，不代表已建立 write primitive 或 root；仍禁止以此恢复 full payload 运行。

## 2026-07-19 active route selection 结论

- 已用刷新后的 codebase-memory 图谱核对 active common source：Violin 默认构建不消费 `prepare_pselect_fdsets()`，而是进入 `poll((struct pollfd *)pselect_user_lock, 1, ...)`。
- `PSELECT_ROUTE_NFDS=64` 是当前 source 值；此前 `nfds=320/words_per_set=5` 的日志来自旧 artifact，不能当作当前 route 证据。
- `ashmem_misc + 0x10` 槽位修正仍保留，但不能解除 poll/pselect route mismatch。下一步先离线选择模型 A（poll 栈帧）或模型 B（pselect 64-fd overlay），未闭合前禁止联机运行。
- 详细报告：`analysis_outputs/violin-active-route-selection-audit-20260719.md`。

## 2026-07-19 默认 poll 路由闭合

- 对 same-build raw kernel 完成 PE section 映射和 `__arm64_sys_poll`/`do_sys_poll`/`poll_initwait` 反汇编复核；raw `.text` VA/raw 均从 `0x10000` 起，符号到文件 offset 对齐已确认。
- 当前默认 `poll(fd=-1, nfds=1)` 在 `do_sys_poll` 中先对 `P0+0x170` 的 `poll_wqueues` 清零；fd<0 分支在 `0x3e1b3c` 跳过 `do_pollfd`，不会创建 `poll_table_entry`。
- stale waiter 的 `lock` 重叠到 `poll_wqueues + 0x198`，即 `inline_entries[5].wait.entry.next`，该 qword 来源是清零后的内核 inline 区，不是 `pselect_user_lock` 用户字节。模型 A 已闭合为默认 route 不可达，不能再靠调 `nfds`、fd-set word 或 fops 目标修复。
- 详细报告：`analysis_outputs/violin-poll-route-closure-20260719.md`；反汇编证据：`analysis_outputs/poll_initwait-20260719.disasm.txt`、`analysis_outputs/do_poll_wrapper-20260719.disasm.txt`、`analysis_outputs/do_sys_poll-20260719.disasm.txt`。
- 下一步仅保留独立的显式 pselect 变体离线审计；不得与默认 poll 方程混用，也不得构建、安装或联机运行新 payload。

## 2026-07-19 显式 pselect 映射阻断

- active `src/fops.c` 的 custom waiter words 为 2..13；当前 `PSELECT_ROUTE_NFDS=64` 使 `words_per_set=1`，Violin `shift=0` 下 `write_target`、`fake_lock` 等关键字段全部被丢弃，只有 word2 的 value 落到 `ex[0]`，不形成有效 target/value 对。
- 要承载全部 waiter words 至少需要 `words_per_set=5`，即 `nfds>=257`；但 same-build `core_sys_select` 的 stale `waiter->lock=Q0+0xd8` 在 `words_per_set>=4` 时进入第三组 fd-set copy window，会被当作 fd bitmask，不能同时作为用户锁指针。
- 离线核验器：`tools/audit_violin_pselect_mapping.py`；输出：`analysis_outputs/violin-pselect-mapping-audit-20260719.json`；详细报告：`analysis_outputs/violin-pselect-mapping-closure-20260719.md`。
- `src/slide.c` 也把 `SLIDE_PSELECT_NFDS` 绑定到同一 `64`，其 waiter word 0..13 只有 tree word 0..2 分别落到 `in[0]`/`out[0]`/`ex[0]`，`pi_parent`、`task`、`lock` 等 word 3..13 全部丢弃；slide route 不能与旧 `nfds=320` 日志混用。
- 结论：默认 poll、显式 pselect 和 slide pselect 三条现有路线均未闭合；下一步不再调 word/nfds/目标地址，除非发现能改变 stale-lock 来源的全新调用序列。不得构建、安装或运行新 payload。

## 2026-07-19 显式 pselect copy-window 复核（更正上一条的过强表述）

- 对 `Q0+0xd8` 与三组 fd-set 的连续 copy window 做了离线逐窗口计算：当前 `nfds=64` 确实不覆盖 stale-lock slot；`nfds=257/320`（`words_per_set=5`）时该 slot 恰为 `ex[1]`，而 custom word 11 `fake_lock` 也映射到 `ex[1]`。
- 因而“该 qword 会被 `do_select()` 当作 fd bitmask 读取”不能单独推出“不能再作为 stale lock 指针”；同一 qword 存在双重语义候选。active custom `open_selected_fds()` 还会把已置位 fd 绑定到同一高位 read fd，不能再用“必然 EBADF”作硬阻断。
- 这只把旧 `nfds=257/320` 降级为**待复核的静态候选**，不代表路线成功：same-build `core_sys_select` 的六 bitmap 布局表明 `Q0+0xd8`（W=5 时 `ex[1]`）属于 input bitmap，不是 `res_*`，普通 return copy-back 不会自动清零；独立 `remove_waiter()` 审计还确认 pre-fix 逻辑不会清 `waiter->task->pi_blocked_on`，因此 dangling waiter 与 `EDEADLK -> ETIMEDOUT` 相容。剩余硬问题收敛为 scheduler 消费时的精确 waiter 指针/分支及伪树到达。当前默认入口仍是 `poll(fd=-1,nfds=1)`，未改变 active source，也未运行 payload。
- 映射器已补充 `configured/comparison_stale_lock_copy_windows` 字段；报告 `analysis_outputs/violin-pselect-mapping-closure-20260719.md` 已同步更正。JSON 已重生成，脚本 `py_compile` 通过。

## 2026-07-19 alternate syscall stale-lock 审计

- `ppoll` wrapper（`0x80`）随后调用同一 `do_sys_poll`；用户 `pollfd` 复制到动态缓冲，不提供新的 stale-lock 栈字节来源，已排除为独立模型。
- `select` 与 `pselect6` 共用 `core_sys_select`，但 wrapper frame 不同（`0x80` vs `0x90`），其 stale slot 方程不同，不能直接复用 pselect word map。
- `epoll_wait/pwait/pwait2` 虽都有 `do_epoll_wait -> schedule_hrtimeout_range`，stale slot 分别落在无 usercopy 的实现局部、保存的内核 `x21` 指针、stack-canary 槽；`set_user_sigmask` 的 8-byte copy 不覆盖该 slot，暂排除为更优 user overlay route。
- 详细离线记录：`analysis_outputs/violin-alternate-waiter-lock-route-audit-20260719.md`。`do_select` input/result bitmap 与 dangling-lifetime 已有静态证据；下一步只做 pselect 高 nfds 候选的 scheduler waiter 指针/分支/伪树离线对账。

## 2026-07-19 `nfds` source-drift 更正

- `exploit-repo` HEAD `1a10c4e` 的 `src/common.h` 本来就是 `PSELECT_ROUTE_NFDS=320`、`CONSUMER_MAX_CALLS=1`；当前未提交 worktree 改成 `64`/`200`，并带有 backup-v1 注释。此前把 320 一概写成“旧 artifact”不准确，后续必须显式区分 HEAD baseline 与 active worktree。
- HEAD 的 W=5 custom map 将 `fake_lock` 放到 `ex[1]`，与 same-build `Q0+0xd8` stale slot 字节级重合；这只是静态候选，不改变当前默认 `ROUTE_*`=0 的 `poll(fd=-1,nfds=1)` 入口，也不授权把 worktree 改回 320 或运行 payload。
- 详细矩阵：`analysis_outputs/violin-pselect-nfds-source-drift-audit-20260719.md`。下一步先做 HEAD(320)/worktree(64) 的 scheduler consumer 分支对账，保持 worktree 不动。

## 2026-07-19 scheduler consumer 分支静态对账

- `consumer_thread()` 默认对 `waiter_tid` 交替调用 `sched_setattr_tid(..., nice=19/0)`；same-build `sched_setattr -> __sched_setscheduler` 会进入 PI-enabled 的 `rt_mutex_adjust_pi` 路径。
- `rt_mutex_adjust_pi@0x10526c8` 先读 `task->pi_blocked_on`（`+0x938`）；NULL 直接返回，不进入 chain。非空时比较 `waiter->prio(+0x18)` / `task->prio(+0x84)`，随后从 `waiter->lock(+0x58)` 调 `rt_mutex_adjust_prio_chain@0x1052868`。
- W=5 pselect 候选的 `ex[1]=fake_lock` 与 stale slot `Q0+0xd8` 字节级重合；这仍只证明 copy-window 候选，未证明 scheduler 时 stale waiter 身份、owner/top-waiter 分支或伪树到达。
- 详细报告：`analysis_outputs/violin-scheduler-consumer-branch-audit-20260719.md`。下一步继续做 `rt_mutex_adjust_prio_chain` 全分支与 fake page 字段的离线矩阵，不改 `nfds`、不构建/安装/运行新 payload。

## 2026-07-19 `task_to_waiter_node` 解释更正

- 旧研究段落把 `task_to_waiter_node(task)` 解释成 `&task->pi_waiters` 强转，并把 `task+0x938` 当作 prio；这与 matching 6.6 实现不符。该 helper 使用 `__waiter_prio(task)` 与 `task->dl.deadline`，same-build 反汇编也显示比较源是 `task+0x84`。
- 因此不能再用“prio 等于 `pi_blocked_on` 指针”解释 `rt_mutex_adjust_pi` 提前返回。W=5 候选的 `tree.prio=0` 与非 RT task 的默认 waiter prio 静态上不相等，chain 入口仍是候选路径。
- `orig_waiter=NULL` 使 chain 的 `detect_deadlock=false`、初始 `top_waiter=NULL`；下一步聚焦第一次 `rb_erase_cached/rb_add_cached` 的树形写入模拟，以及 fake owner 第二轮的 `next_lock != waiter->lock` 退出。
- 更正已写入 `exploit-repo/IonStack/CVE-2026-43499/exploit/GHOSTLOCK_VIOLIN_RESEARCH.md:13.7` 与 scheduler branch audit；不改变只读门禁。

## 2026-07-19 rbtree 首轮重排离线模拟

- 对 W=5 pselect 候选的第一次 `rb_erase_cached`/`rb_add_cached` 做了符号化模拟；脚本只建模 root、cached `rb_leftmost` 和首轮遍历，不实现完整颜色修复，不访问设备、不运行 payload。
- 默认 `write_value=fake_fops`、`shape=1`：stale root 被替换为 `fake_fops`，但 cached leftmost 保持 `fake_w0`；因此 `waiter == rt_mutex_top_waiter(lock)` 不成立，首轮 `rt_mutex_dequeue_pi` 目标写入分支未到达。`shape=0` 会继续解引用未建模的 `write_target`。
- 任意内核值分支保持 unknown；模型中 stale 成为 top 只表示字段恰好满足时的可能性，不能当作 primitive 证据。
- 产物：`tools/audit_violin_rtmutex_rbtree.py`、`analysis_outputs/violin-rtmutex-rbtree-requeue-audit-20260719.json`、`analysis_outputs/violin-rtmutex-rbtree-requeue-audit-20260719.md`；`py_compile` 已通过。
- 这只是候选阻断，下一步应把模型与 same-build `rb_erase_cached`/`rb_add_cached` 内联反汇编、颜色修复以及真实 stale root/leftmost 身份逐写入对账；不改 `nfds`，不恢复 payload。
- same-build raw 已补证：`rb_erase_cached@0x128074` 先比较 cached `rb_leftmost`，仅相等时更新；`rt_mutex_adjust_prio_chain@0x1052868` 在 `0x1052a88` 调用，`0x1052ac8` 开始 inline reinsert。反汇编：`analysis_outputs/rb_erase-and-color-20260719.disasm.txt`、`analysis_outputs/rb_erase-20260719.disasm.txt`。

## 2026-07-19 runtime FOPS route 输出诊断

- 新日志证明 `ROUTE_REACHED=1`、consumer `105/105`，但只说明 scheduler route 到达；`FOPSROUTE_CFI_RESULT ok=0 step=1 errno=22` 才是首个失败边界，不能把 `success=105` 解释成 fops hijack 成功。
- matching ashmem 源的原始 `ashmem_fops` 没有 `.write`/`.write_iter`；因此未劫持时 `configfs_write_once()` 的 `pwrite()` 返回 `-EINVAL`，不是 `ashmem_write_iter` 的 `asma->size==0` 检查。`asma->size==0` 只解释 pre-hijack `pread()` 的 EOF。
- 本次 `CFGPROBE_MISS` 的所有读均为 EOF，不能证明 Violin `misc_fops` 字段全非零，也不能证明 rb_insert 已遍历到静态 fops；正确目标仍是 `ashmem_misc + 0x10` 指针槽。
- 当前 active worktree 默认 `ROUTE_*`=0，实际入口是 `poll(fd=-1,nfds=1)`；本次输出不能套用 W=5 显式 pselect 的 fd-set 字段映射，后者只能独立作为离线候选。
- same-build raw image 已直接复核：`misc_fops@0x1269710` 的 `poll(+0x40)=0`，`read/write/read_iter/write_iter` 也为 0；“Violin misc_fops 所有字段非零、无 NULL 插入点”被否定。`ashmem_misc+0x10` 的值为 `ashmem_fops` 地址，槽位语义仍正确。报告：`analysis_outputs/violin-fops-raw-null-fields-audit-20260719.md`。
- 诊断报告：`analysis_outputs/violin-runtime-fops-route-diagnosis-20260719.md`。下一步补齐 `cfi write ret`/`try_set_ashmem_name_blob` 失败点，并把 active poll 与 W=5 pselect 候选分开做静态树对账；不改 `nfds`、不运行 payload。

## 2026-07-19 active priority-tree 分支对账

- 新增离线核验器 `tools/audit_violin_priority_tree_branches.py`，并生成
  `analysis_outputs/violin-priority-tree-branch-audit-20260719.json` 与报告
  `analysis_outputs/violin-priority-tree-branch-audit-20260719.md`。
- active worktree 默认 payload 的实际语义是 `write_target=ashmem_misc+0x10`、
  `write_value=fake_fops`、`fake_w0.pi_tree.prio=130`；旧报告中把默认
  `write_left` 写成 `misc_fops-8` 的段落已不再代表当前 source，历史记录保留但
  必须以本条和 active `src/util.c` 为准。
- 首次 `rb_add_cached` 的条件矩阵：`nice=19`（prio 139）走
  `fake_w0.rb_right`，cached leftmost 保持 `fake_w0`；`nice=0`（prio 120）走
  `fake_w0.rb_left`，cached leftmost 可能变为 stale waiter。两条分支的
  `rb_link_node` 都只写入 `&stale_waiter`，不直接写 fops 槽。
- 该矩阵未建模颜色旋转、完整 erase/reinsert、stale waiter 的 task/owner/tree
  身份；当前入口仍是 `poll(fd=-1,nfds=1)`，不是 W=5 pselect。下一步只做
  same-build `rb_erase_cached`/inline reinsert 的全状态离线对账，不改 `nfds`，
  不构建、安装或运行新 payload。

## 2026-07-19 rt_mutex 全首轮 transition 更正

- 新增 `tools/audit_violin_rtmutex_full_transition.py`，输出
  `analysis_outputs/violin-rtmutex-full-transition-audit-20260719.json` 与报告
  `analysis_outputs/violin-rtmutex-full-transition-audit-20260719.md`。
- 按 matching 6.6 `rt_mutex_adjust_prio_chain()` 的真实顺序，W=5 候选首先把
  NULL-parent/NULL-child stale waiter 当作 `lock.waiters` 根删除，清空 root；随后
  `rt_mutex_enqueue()` 将 stale 重新放为 root/leftmost。此前“stale 是 fake_w0
  子节点”的简化模型已由本条 supersede。
- owner PI 树删除 `fake_w0.pi_tree` 时，raw `rb_erase_cached` 的直接写入是
  `[ashmem_misc+0x10-8] = fake_fops`，即 `miscdevice.name` 槽；
  `ashmem_misc+0x10` fops 槽仍为 `ashmem_fops`。后续 pi enqueue 从
  `ashmem_misc+0x10-8 -> ashmem_fops -> noop_llseek` 离开受控页，旋转结果保持
  unknown。
- 第二轮若消费 `fake_w0->lock`，当前 payload 给的是用户态
  `pselect_user_lock`，不是已证实的内核 rt_mutex。默认 active route 仍为
  `poll(fd=-1,nfds=1)`；本条只读、未改 `nfds`、未构建/安装/运行新 payload。

## 2026-07-19 raw-text traversal 收敛

- full transition 模型继续对账 same-build `noop_llseek` 原始 qword：其
  `+0x18` 作为 synthetic prio 是负数，139/120 两个候选均走右支；右 child
  为原始 qword `0xd503233fe61887de`，不是 canonical kernel pointer。
- 因此 `rt_mutex_enqueue_pi()` 在静态模型中于 `noop_llseek` 后到达非 canonical
  指针，尚未执行 `rb_link_node`/`rb_insert_color`，没有 target-slot 写入。
- 这比“离开受控页后完全 unknown”更精确，但仍仅适用于 HEAD W=5 pselect 候选；
  active worktree 仍为 poll/nfds=64。本轮未改 source 参数，未构建、安装或运行 payload。

## 2026-07-19 第二轮 fake_w0->lock scheduler/PI 对账

- 新增 `tools/audit_violin_second_chain_user_lock.py`，输出
  `analysis_outputs/violin-second-chain-user-lock-audit-20260719.json` 与报告
  `analysis_outputs/violin-second-chain-user-lock-audit-20260719.md`。
- 同 build `init_task` 的 `prio/static_prio/normal_prio` 已由源码和 raw image
  双重核对为 `120`；payload 的 `fake_task.prio/normal_prio` 也是 `120`，
  `fake_w0->task=INIT_TASK`。因此 owner 分支调用 `rt_mutex_setprio(fake_task,
  INIT_TASK)` 时，若 vendor `force_update` hook 不置 `update=1`，满足
  `pi_top_task`、effective prio 与当前 prio 均不变的 early-return 条件。
- 该 early return 只跳过 rq/scheduler 重排，不终止 `rt_mutex_adjust_prio_chain()`；
  owner 分支仍读取 `fake_task->pi_blocked_on=fake_w0`，把下一轮的
  `next_lock` 设为 `fake_w0->lock`。
- 条件假设第一轮 PI enqueue 已越过 `noop_llseek` 非 canonical qword 后，第二轮
  的前置比较可通过，但 [5] 会执行
  `raw_spin_trylock(&pselect_user_lock->wait_lock)`。这是用户 VA，不是已证明的
  内核 `rt_mutex_base`；因此第二轮在 lock 类型边界停止，不能作为有效 PI 消费或
  写入原语。
- 严格路径仍在第一轮 `noop_llseek+0x08` 停止，所以第二轮不可达；active worktree
  仍是 `poll(fd=-1,nfds=1)`，本轮只读，未改参数、未构建/安装/运行 payload。

## 2026-07-19 `rt_mutex_force_update` hook 分支闭合

- 新增 `tools/audit_violin_rtmutex_force_update_hook.py`，输出
  `analysis_outputs/violin-rtmutex-force-update-hook-audit-20260719.json` 与报告
  `analysis_outputs/violin-rtmutex-force-update-hook-audit-20260719.md`。
- common-GKI 源树只声明/导出并调用 `android_rvh_rtmutex_force_update`、
  `android_rvh_rtmutex_prepare_setprio`，没有 vendor callback 注册实现；同 build
  `kallsyms.txt` 有 tracepoint/iterator 符号，但不能据此证明 callback list 为空。
  因此 `update=0` 只能作为基础分支假设，不能称为 runtime 已证实。
- `update=0` 分支仍是 `rt_mutex_setprio()` early-return 后继续 chain walk，下一步对
  `pselect_user_lock` 用户 VA 执行 `raw_spin_trylock`；`update=1` 则先把伪造
  `fake_task` 送入 `__task_rq_lock`、rq 和 sched-class 路径，当前 payload 未提供可验证
  的 CPU/rq、on-rq/state、sched entity、DL/RT 子结构与生命周期字段。
- 所以无论 hook 分支取值如何，都没有闭合到有效第二轮 PI 消费：关闭 hook 保留用户
  VA lock 阻断，强制更新则先遇到未建模的伪造 task scheduler 消费。active route 仍是
  `poll(fd=-1,nfds=1)`；本轮只读，未改参数、未构建/安装/运行 payload。

## 2026-07-19 HEAD / active route 状态混用纠正

- 新增 `tools/audit_violin_route_state_split.py`，输出
  `analysis_outputs/violin-route-state-split-audit-20260719.json` 与报告。
- 发现上一份 `violin-second-chain-user-lock-audit-20260719.md` 标记为 HEAD W=5，
  但采用了当前 worktree 的 `fake_w0->lock=pselect_user_lock`；该报告已加
  `superseded` 标记，不能继续作为 HEAD 结论。
- 正确状态矩阵：HEAD=`nfds=320`、显式 pselect、`fake_w0->lock=fake_lock`、stale
  `ex[1]=fake_lock`；当前 worktree=`nfds=64`、默认 poll、stale lock 来自
  `poll_wqueues+0x198`，`fake_w0->lock` 才是 user VA。两者不可混用。
- HEAD 条件第二轮应改为 fake_lock kernel-page 模型：第二轮可先完成
  `raw_spin_trylock`、fake_w0 的 dequeue/requeue，随后 prio 120 相等时停止；该段
  本身没有 target-slot 写入。未闭合仍是第一轮 stale PI enqueue 越过 non-canonical
  child 后的具体 parent/color 状态。
- 当前 active route 在第一轮 lock identity 就未闭合，不能套用 HEAD 第二轮模型。本轮
  只读，未改 exploit source、未构建/安装/运行 payload。

## 2026-07-19 PI-chain 入口门禁再纠正（当前有效）

- 新增 tools/audit_violin_pi_chain_entry.py，生成
  analysis_outputs/violin-pi-chain-entry-audit-20260719.json 与报告。
- matching 6.6 task_blocks_on_rt_mutex() 的门禁是
  owner->pi_blocked_on != NULL 且 next_lock != NULL；否则在调用
  rt_mutex_adjust_prio_chain() 前直接返回。
- HEAD W=5 FOPS 分支写入 fake_task->pi_blocked_on=NULL、
  fake_task->pi_waiters=NULL；此前把 HEAD 直接推进到 fake_w0.pi_tree 的
  full-transition 模型是不可达条件，不能作为 HEAD 结论。
- 当前工作树虽写入 fake_task->pi_blocked_on=fake_w0，但
  fake_w0->lock=pselect_user_lock 是用户 VA，且 active 默认入口仍为
  poll(fd=-1,nfds=1)；这只让入口静态非 NULL，没有证明 kernel lock 解引用或
  stale waiter 与其地址相等。
- analysis_outputs/violin-rtmutex-full-transition-audit-20260719.md 已标记
  SUPERSEDED：其中 root 替换为 target-8 并向 target-8 写 fake_fops 错误；
  正确的 __rb_change_child() 分支写的是 fake_fops->rb_right，且只有
  chain-entry 门禁打开后才有意义。
- 下一步固定为离线闭合 owner / stale waiter / next_lock 地址等式及
  raw_spin_trylock 可访问性；在此之前不改 nfds、fd_set word，不运行新 payload。

## 2026-07-19 pselect 256-fd kernel-lock overlay 候选

- 默认 poll 路由已闭合为 stale lock 读取 zeroed poll_wqueues；新增离线候选
  tools/audit_violin_pselect256_kernel_lock.py，生成
  analysis_outputs/violin-pselect256-kernel-lock-audit-20260719.json 与报告。
- 同 build core_sys_select 方程：Q0=T-0x280，stale waiter base=Q0+0x80，
  waiter->lock=Q0+0xd8。nfds=256 时每组复制 4 words，exceptfds[3] 正好覆盖
  waiter->lock (+0x58)；可静态尝试放入 kernel-page fake_lock，而不是 user VA。
- 该候选绕过当前 pselect_user_lock 的地址空间阻断，但还没有闭合 fd-mask
  readiness、stale task/lock identity、PI-tree parent/color 或 target-slot 写入。
- 下一步只做离线 256-fd fd-mask/readiness 状态机，核对 open_selected_fds 对
  所有置位 fd 的复制和 ready 状态；不改 payload、不构建/安装、不联机测试。
- 注意：当前 prepare_pselect_fdsets() 的数组不是 256-fd 映射；只改 NFDS 会丢弃 in[4] 并错位 pi/task/lock 字段，必须先做独立 word table。

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
  只可用于离线比较，不能直接替换 payload。`rt_mutex_adjust_pi()` 传入
  `orig_lock=NULL`，所以把同一 `fake_lock` 直接标成必然 `[6] same-orig-lock`
  deadlock 是错误的；仍需单独核对 `rt_mutex_owner(lock)==top_task` 和其它
  chain 条件。本轮继续只读，不构建/安装/联机。

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

- 新增 `tools/audit_violin_pipe_buffer_primitive.py`，生成
  `analysis_outputs/violin-pipe-buffer-primitive-audit-20260719.json` 与报告
  `analysis_outputs/violin-pipe-buffer-primitive-audit-20260719.md`；已通过
  `py_compile` 与 JSON 解析。
- 静态通过：Violin `user_pipe_buffer` 与同 build `struct pipe_buffer` 都是
  `0x28` 字节，字段偏移 `0x00/0x08/0x0c/0x10/0x18/0x20` 一致；
  `ANON_PIPE_BUF_OPS_OFF=0x114a288` 与 kallsyms/offset report 一致；
  `anon_pipe_buf_ops` 没有 `confirm`，`pipe_buf_confirm()` 对 NULL confirm 返回 0。
- 关键边界 bug：`pipe_phys_write_data()` guard 允许 `len == PAGE_SIZE`，但
  `pipe_write()` 的 `chars = total_len & (PAGE_SIZE-1)` 在整页时为 0，跳过
  forged-buffer merge 并分配新 buffer；因此单页 arbitrary write 的静态契约只能是
  `0 < len < PAGE_SIZE`。`len == 0` 也会被 wrapper 报告为成功但不触碰目标。
- pipe path 不是独立原语：save/forge/restore 通过 `kernel_read_data()`/
  `kernel_write_data()`，而 util 层直接委托 ConfigFS/ashmem primitive；不能用
  pipe physrw 证明 fops→ConfigFS 第一阶段已成功。
- cache gate 偏宽：pipe ring `kcalloc()` 使用 `GFP_KERNEL_ACCOUNT`，目标 config
  有 `CONFIG_MEMCG_KMEM=y`，但代码同时接受 normal-2k 和 cgroup-2k；且读取
  `page_type` 后没有硬性要求 `PAGE_TYPE_SLAB`。`KMALLOC_CACHE_TYPES=4` 也比本
  build normal/reclaim/cgroup 三行的实际枚举大，bulk read 会越过声明数组范围。
- 当前仍只读：不改 payload、不构建/安装、不联机测试。下一步先离线收紧长度
  契约、cgroup cache gate、slab page-type gate，再重新复审依赖链。
- `DIRECT_MAP_BASE..END` 与 `STRUCT_PAGE_SIZE` 计算得到有效的
  `VMEMMAP_END=0xfffffffe40000000`，未发生 64 位回绕；marker `len=1..240` 与
  `pipebuf_pipe_idx=len-1` 在源码层面自洽，但前提仍是 ConfigFS 元数据读已成立。

## 2026-07-19 pipe 写调用方契约闭合

- 新增 `tools/audit_violin_pipe_write_callers.py`，生成
  `analysis_outputs/violin-pipe-write-callers-20260719.json` 与报告；通过
  `py_compile` 和 JSON 解析。
- 通过 codebase-memory graph 追踪 active `src/pipe.c` / `src/root.c` 调用链后，
  共闭合 12 个实际写调用；长度全部静态解析成功，最大 40 bytes，没有当前调用方
  使用 `0`、`PAGE_SIZE` 或更大长度。
- 这只证明当前调用方不会触发整页写边界 bug，不解除 API 入口 gate；下一步仍应把
  `pipe_phys_write_data()` 契约固定为 `0 < len < PAGE_SIZE`，并收紧 cgroup cache
  与 `PAGE_TYPE_SLAB` gate。当前不改 source、不构建/安装、不联机。

## 2026-07-19 rb_set_parent_color → fops 中继桥离线审计

- 新增 `tools/audit_violin_rbset_fops_bridge.py`，生成
  `analysis_outputs/violin-rbset-fops-bridge-audit-20260719.json` 与
  `analysis_outputs/violin-rbset-fops-bridge-audit-20260719.md`；已通过
  `py_compile` 与 JSON 解析。
- 语义纠正：`rb_set_parent_color(rb, p, color)` 的写入目的地是**第一个参数**
  `rb`，写入值是 `p | color`。因此把 `fake_parent` 设为
  `ashmem_misc + 0x10` 只改变 value，不会选择 fops 槽作为 destination；当前
  尚未证明任何可达 `__rb_insert` 状态会令第一个参数恰好等于该槽。
- `ashmem_misc + 0x10` 是 `miscdevice.fops`，若被当作 `rb_node`，其
  `+0x08/+0x10` 实际别名 `miscdevice.list.next/list.prev`，不是独立 rb 子指针；
  对其做旋转/子树更新必须另行闭合 list 生命周期与写安全性。
- 临时把 fops 指针写成 `new_waiter = fake_w0 + 0x28` 不可用：该地址是
  `rt_mutex_waiter.pi_tree` 的 rb_node。按当前布局，fops `.read` 映射到
  `rb_left=(target-8)`，`.write` 映射到 `pi_tree.prio=130`，`.read_iter`
  映射到 `pi_tree.deadline=0`，`.write_iter` 映射到 `waiter_task`；而
  `configfs_write_once()` 使用 `pwrite()`，VFS 先取 `.write`，不会因为
  `.llseek==NULL` 而跳过间接调用。
- 结论标记：`RBSET-INTERIM-FOPS-INVALID`。下一步只能离线构造一份完整
  `__rb_insert` 状态表，证明 destination、value、miscdevice list 别名读写及
  可用的直接/中继 fops 四项同时成立；在此之前不改 fd-set、不构建、不联机。

## 2026-07-19 same-build raw rb 对象图再校正

- 新增 `tools/audit_violin_raw_rb_object_graph.py`，生成
  `analysis_outputs/violin-raw-rb-object-graph-20260719.json` 与
  `analysis_outputs/violin-raw-rb-object-graph-20260719.md`；已通过
  `py_compile` 与 JSON 解析。
- 重要更正：同 build `boot.img.kernel` 已直接否定“Violin `misc_fops` 所有
  字段非零”。`misc_fops` 的 `llseek` 非零，但 read/write/read_iter/write_iter
  与 poll 相关槽均有 NULL；`ashmem_fops` 也存在 NULL 槽。此前以“无 NULL”作为
  根因的结论不可再使用。
- 但 NULL 静态槽不等于目标槽写入：当前锚点 `ashmem_misc+0x08` 的
  `rb_right` 读取的是 `ashmem_misc+0x10` 的**内容**（`ashmem_fops` 地址），
  不是 fops 槽地址本身；遍历会进入静态 `ashmem_fops` 对象，而不会自动把
  `ashmem_misc+0x10` 作为 `rb_set_parent_color` 的第一个实参。
- `ashmem_misc+0x10` 若被解释为 rb_node，其 `rb_right/rb_left` 是运行时
  `miscdevice.list.next/prev`；镜像中的零值不能替代 `misc_register()` 后的链表状态。
- 当前结论改为：`RBSET-INTERIM-FOPS-INVALID` 仍成立，但阻塞原因是
  **对象图/目标地址不闭合**，不再是“Violin 没有 NULL 字段”。
  `misc_register()` 的 `INIT_LIST_HEAD`/`list_add` 已足以证明 fops 槽作为 rb_node
  时两个 child 运行时均非 NULL；下一步只需枚举其余可达
  `rb_set_parent_color` destination。当前已知 destination 集合只含 fake_w0.pi_tree
  child、`ashmem_fops+0x10`、`ashmem_misc+0x08`、fake_fops.owner 及可能的其它
  list node，尚不含 `ashmem_misc+0x10`。若无第一实参等于该槽，应放弃该锚点并换
  写入位置。保持不改
  payload、不构建、不联机。

## 2026-07-19 rb_erase / rb_replace 目标槽目的地审计

- 新增 `tools/audit_violin_rb_erase_target_destinations.py`，生成
  `analysis_outputs/violin-rb-erase-target-destinations-20260719.json` 与
  `analysis_outputs/violin-rb-erase-target-destinations-20260719.md`；已通过
  `py_compile` 和 JSON 解析。
- 用 `T=ashmem_misc+0x10`（真实 fops 槽）、`N=T-0x08`（name 字段）、
  `W=fake_w0+0x28`、`F=fake_fops` 建模当前 FOPS payload。`rb_erase(W)` 的
  cached leftmost 若指向 W，会先被 `rb_next(W)` 更新为 `ashmem_fops`；一子节点路径是
  `__rb_change_child(W,N,F,root)`，直接写
  `F.rb_right`，随后把 `N.__rb_parent_color` 设为 `F`；因为 parent 非 NULL，
  不会更新 `root.rb_node`，也不会写 T。
- 抽象上只有条件路径能命中 T：必须存在 `parent=N` 且 victim 正好是
  `N.rb_right=A=ashmem_fops`，让 `__rb_change_child()` 写 `N.rb_right`。
  当前图没有证明 `rb_parent(A)=N` 或存在该 victim/parent 对；`rtmutex.c`
  当前使用的是 `rb_erase_cached`，没有 `rb_replace_node` 调用。
- 结论：`RB-ERASE-FOPS-SLOT-NOT-CLOSED`。当前 blocker 已从“NULL 插入点
  不存在”进一步收紧为“erase/replace 目标槽条件图未闭合”。未证明条件路径前，
  不改 fd-set、不调整 pselect、不构建、不联机；若下一轮仍无法闭合，应放弃
  该 anchor，改选其他写入原语/目标。

## 2026-07-19 codebase graph relay dependency复核

- codebase-memory index 状态为 ready（4218 nodes / 15631 edges）。通过
  `get_code_snippet` 复核 `src/util.c:995-997`：`kernel_write_data()` 只是
  `configfs_write_once()` 的薄包装；`src/util.c:926-943` 的最终 sink 是
  `pwrite()`。
- 同图复核 `src/pipe.c:517-543`：`pipe_phys_write()` 先调用
  `kernel_read_data()`，再调用 `kernel_write_data()` 修改 pipe_buffer，最后
  才执行普通 `write(pipefd[1], ...)` 并恢复 metadata。因此 pipe_buffer 不是
  独立于 ConfigFS/fops 的第一写入原语。
- `src/main.c:624-679` 的 active route 只负责 FUTEX/PI 线程和可选 pipe page
  准备，不会绕过 fops/ConfigFS 直接完成 arbitrary write。
- 最优下一步：停止当前 `ashmem_misc+0x10` rb anchor 与 pipe relay 分支，
  只读枚举新的 kernel write sink/合法目标；在出现独立 sink 前不改 fd-set、
  不构建、不联机。
- 进一步用 codebase-memory `search_code` 在 active `src/util.c`、`src/pipe.c`、
  `src/fops.c`、`src/root.c`、`src/main.c` 枚举 `pwrite/process_vm_writev/
  vmsplice/copy_file_range/sendfile/writev`，唯一命中是 `src/util.c:941`
  的 `pwrite`；未发现第二个独立 arbitrary-write syscall sink。

## 2026-07-19 alternate file_operations slot inventory

- 新增 `tools/audit_violin_alternate_fops_slots.py`，生成
  `analysis_outputs/violin-alternate-fops-slot-audit-20260719.json` 与
  `analysis_outputs/violin-alternate-fops-slot-audit-20260719.md`；通过
  `py_compile` 和 JSON 解析。
- 同 build raw image 中 `misc_fops`/`ashmem_fops` 共发现 46 个 NULL qword 字段（其中 44 个是 pointer/callback，2 个是 `mmap_supported_flags` scalar）；当前
  对象图唯一有意义的交集是 `ashmem_fops.read`（`A+0x10`），因为
  `ashmem_misc+0x08` 的 `rb_right` 内容指向 A，且 A 的 left 为 NULL。
- 该交集仍不可用：`rb_link_node()` 写入的是新 waiter 的 rb_node 地址，不是
  `fake_fops` 或 CONFIGFS 函数；`rb_set_parent_color()` 也只产生 node/parent
  地址。`misc_fops` NULL 槽没有当前图的可达 parent。结论：
  `NO-USABLE-ALTERNATE-FOPS-SLOT`。
- 下一步转向更宽的 kernel-object inventory：寻找既能从真实 rb/PI 图到达、又能
  接受已证明 callable/pointer 值的字段；不改 fd-set、不构建、不联机。




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

- 新增 `tools/audit_violin_rb_erase_direct_fops_write.py`，生成
  `analysis_outputs/violin-rb-erase-direct-fops-write-20260719.json` 与
  `analysis_outputs/violin-rb-erase-direct-fops-write-20260719.md`；已通过
  `py_compile` 与 JSON 解析。
- 该审计保留并细化本文件前面“默认 W.parent=F、W.left=N、W.right=NULL、T 不变”
  的结论，同时单独审计未启用的 custom shape-1 候选。`main.c` 明确不调用
  `set_pselect_write()`，所以当前默认运行仍是 shape 0；shape-1 不是 active route。
  custom shape-1 的实际字段才是：
  `T=ashmem_misc+0x10`、`N=T-0x08`、`W=fake_w0+0x28`、`F=fake_fops`，
  `W.__rb_parent_color=N`、`W.rb_left=NULL`、`W.rb_right=F`。
- 若确实到达 `rt_mutex_dequeue_pi(fake_task, fake_w0)`，一子节点路径调用
  `__rb_change_child(W,F,N,root)`。运行时 `N.rb_left` 是
  `miscdevice.list.next`，不是 W，于是 helper 的 else 分支写
  `N.rb_right=F`；该地址正好别名真实槽 T，故符号上得到
  **`ashmem_misc.fops := fake_fops`**。
- 同一步还写 `F.__rb_parent_color=N`，因此 fake fops 的 `owner` 字段变为 N；
  parent 非 NULL，`fake_task.pi_waiters.rb_root` 仍是 W，而 cached leftmost
  已变为 F。后续 `rb_add_cached()`/旋转及 fresh-open 的 `fops_get(owner)`
  尚未闭合，不能把目标槽方程等同于整条链成功。
- `rt_mutex_adjust_pi()` 的 chain-walk 参数 `orig_lock` 明确为 NULL；旧的
  “fake_lock 一定命中 lock==orig_lock”阻断说法已修正，但 owner/top-task、
  stale root 和 route lock 映射仍是独立门槛。
- 当前状态：active default 为 `T-NOT-REACHED`；只有未启用的 custom shape-1
  标记 `direct_fops_slot_equation=SYMBOLICALLY-CLOSED`；
  `pi_chain_reachability/post_write_tree/fresh_open_owner/current_payload_success`
  均未闭合。最优下一步是离线完成 erase 后 `rb_add_cached`/`rb_insert_color`
  状态机及 pre-open transport/owner-repair 顺序；不改 payload、不联机。

## 2026-07-22 rb_erase post-write state closure

- 新增 `tools/audit_violin_rb_erase_postwrite_state.py`，生成
  `analysis_outputs/violin-rb-erase-postwrite-state-20260722.json` 与
  `analysis_outputs/violin-rb-erase-postwrite-state-20260722.md`；已通过
  `py_compile`、JSON 解析和 evidence null 检查。
- 状态表确认 active default 是 shape 0：`W.parent=F, W.left=N,
  W.right=NULL`，`rb_erase_cached(W)` 只写 `F.rb_right=N`，真实槽 T 不变，结论
  为 **ACTIVE-T-NOT-REACHED**。
- 未启用 custom shape-1 虽然符号上能通过 `N.rb_right` 写 T，但 erase 后
  `rb_root` 仍为 W、leftmost 为 F，`RB_CLEAR_NODE(W)` 使 W 自指；后续
  `rb_add_cached()` 要么进入自父平衡，要么在 W↔F 间循环，未证明能安全返回用户态。
- 同时 `F.__rb_parent_color=N` 会使 `fake_fops.owner=N`；而当前
  `try_cfi_stage()` 在 route 后才 `open_ashmem_device()`，`misc_open/fops_get`
  会先对该任意 module-shaped 地址做 `try_module_get`。其返回值/副作用尚需
  结合实际 module 布局与镜像字节证明，因此 custom 分支的 transport 顺序未闭合，
  但不能直接断言必然 fault。
- 最优下一步：不要启用 shape-1 或重复联机。先离线寻找独立 owner 修复/写入 sink
  或不同的 kernel-object consumer；若无闭合证据，则将当前 rb anchor 归档为不可行。

## 2026-07-22 owner/open gate correction and same-waiter cycle closure

- 新增并验证 `tools/audit_violin_fake_fops_owner_module_shape.py`，读取同 build
  `boot.img.kernel` 的嵌入 BTF、kernel config 与 raw image：`struct module` 为
  `0x600`，`state=+0x0`、`refcnt=+0x5c0`；N=`ashmem_misc+0x08` 的 raw bytes 为
  `state=0x815eb0c9`、`refcnt=0x1a4`，`CONFIG_MODULE_UNLOAD=y`。
- 因 `try_module_get()` 只检查 `module_is_live()` 与 `atomic_inc_not_zero()`，不检查
  module registry，`fake_fops.owner=N` 不能再标为“必然 fault”；raw-image 预测是
  **likely-pass-with-adjacent-refcnt-side-effect**，副作用别名为
  `dev_attr_recovery+0x8`。这仍不是运行时证明。
- 修订 `tools/audit_violin_rb_erase_postwrite_state.py`：custom shape-1 若实际消费的
  `prerequeue_top_waiter` 与 `waiter` 都是 payload 设置的 `fake_w0`，erase 后会重新
  enqueue W；`waiter_clone_prio` 后 W.prio=120、F.prio（fake_fops.write）=0，
  `rb_add_cached` 沿 `W.rb_right=F -> F.rb_right=W` 无限循环，未到达 NULL/link 或
  `rb_insert_color`。若 top-waiter 身份不相等，pi-tree erase 及 `T:=F` 方程反而不发生。
- 因而当前最优下一步仍是离线寻找独立写入/owner 修复 sink 或保持合法树状态的其他
  consumer；不启用 shape-1，不改 fd-set，不构建、不联机。

## 2026-07-22 active poll-route lock-source closure

- 新增 `tools/audit_violin_poll_route_lock_source.py`，生成
  `analysis_outputs/violin-poll-route-lock-source-audit-20260722.{json,md}`；已通过
  `py_compile` 与 JSON 校验。
- 当前 worktree 的 active route 只把 `pselect_user_lock` 当作 `pollfd` 数组，且
  `pfd[0].fd=-1`。同 build `fs/select.c:do_pollfd()` 在 `fd < 0` 立即 `goto out`，
  早于 `fdget()`/`vfs_poll()`；因此不会进入 `f_op->poll/poll_wait`，不会登记
  `poll_table_entry`。
- `poll_initwait()` 只初始化 `poll_wqueues` 控制字段并把 `inline_index=0`、
  `table=NULL`；后续 `poll_schedule_timeout()` 可能让当前线程睡眠，但没有把用户
  指针复制到 `rt_mutex_waiter.lock`。结论为 **active poll → fake_w0.lock
  NO-SOURCE-EDGE**，`fd=-1` wait registration 为 **CLOSED-NO-WAIT-ENTRY**。
- 因此历史 pselect overlay 证据不能与当前 poll runtime 日志混用。最优下一步只剩
  离线同 build 反汇编寻找独立 poll-stack/UAF 边；若不存在，归档当前
  `pselect_user_lock` PI 映射并转向其它 sink。

## 2026-07-22 second-kernel-lock inventory

- 新增 `tools/audit_violin_second_kernel_lock_inventory.py`，生成
  `analysis_outputs/violin-second-kernel-lock-inventory-20260722.{json,md}`；已通过
  `py_compile`、raw-word 读取和 JSON 校验。
- `rcu_state.node[0..2].boost_mtx` 的 BTF 布局确实是合法 `struct rt_mutex`，但
  raw image 的 0x20 字节全零（owner/waiters 均为空），且源码注明只作 RCU
  priority-boost side effect，不是可复用的 owner-bearing lock。
- `console_mutex`/`tty_mutex` 是 BTF `struct mutex` 的非-RT 布局（size 0x30），
  与 `rt_mutex_base`（wait_lock +0、waiters +8、owner +0x18）不兼容；
  `futex_pi_state.pi_mutex` 是动态、route-owned，不能作为独立稳定地址。
- 结论：没有闭合的 distinct second lock。`fake_lock` 仍是唯一受控 kernel-page
  候选；`orig_lock=NULL` 只撤销“same-lock 必然 [6]”的错误说法，不能替代
  owner/top-task/requeue/lifetime 证明。不要把 console/tty/RCU 锁写入 payload。

## 2026-07-22 corrected pselect-256 second-lock matrix

- 新增 `tools/audit_violin_pselect256_second_lock_correction.py`，生成
  `analysis_outputs/violin-pselect256-second-lock-correction-20260722.{json,md}`；
  已通过运行、`py_compile` 和输出核对。
- 该修正保留旧报告文件不变，但撤销其中“same fake_lock 必然在 [6] 因
  `lock==orig_lock` 停止”的过强结论：同 build `rt_mutex_adjust_pi()` 传入的
  `orig_lock` 是 NULL，所以 same fake_lock 只能进入
  `CHECK_[6]_OWNER_TOP_TASK; ORIG_LOCK_NULL`，仍需证明 owner/top-task、requeue、
  cached-tree 与生命周期条件。
- 当前 payload 的 `fake_w0->lock` 仍是 user VA，离线矩阵仍在 `[5]` 阻断；distinct
  kernel lock 仍需要 owner/waiters/lifetime/consumer 的完整模型。
- 最优下一步：不把旧的 same-orig-lock blocker 当作事实；继续离线做一次有界 sink/
  consumer 选择，若没有闭合地址和值方程，则归档 rb/PI anchor，不改 payload、不联机。

## 2026-07-22 pipe first-stage circularity closure

- 新增 `tools/audit_violin_pipe_first_stage_circularity.py`，生成
  `analysis_outputs/violin-pipe-first-stage-circularity-20260722.{json,md}`；已通过
  运行、`py_compile`、JSON 检查。
- `pipe_phys_write_data()` 虽有直接 `write()`，但 found-buffer 分支的
  `pipe_phys_write()` 会先用 `kernel_write_data()` 改写/恢复 pipe buffer；未找到
  buffer 的分支则调用 `forge_pipe_buffers_on_page()`，该函数同样逐项调用
  `kernel_write_data()`。`install_pipe_physrw()` 还在宣称 physrw 前先做 proof write。
- 同 build `kernel_write_data()` 只是 `configfs_write_once()` 的封装，因此结论是
  **NO-INDEPENDENT-FIRST-STAGE-WRITE**：pipe_buffer/anon_pipe_buf_ops 只能作为
  fops→ConfigFS 之后的二级 transport，不能替代当前第一写入 sink。
- 最优下一步：不再把 pipe 提升为第一阶段；归档 rb/PI 与 pipe anchor，继续一次有界
  离线 distinct-kernel-write-sink inventory；无地址和值方程则停止该分支。

## 2026-07-22 bounded core kernel-write sink inventory

- 新增 `tools/audit_violin_kernel_write_sink_inventory.py`，生成
  `analysis_outputs/violin-kernel-write-sink-inventory-20260722.{json,md}`；通过
  codebase-memory `search_code` 枚举核心 `src/*.c` 的 write-like syscall 函数，随后
  只读核对关键函数源码；已通过运行、`py_compile` 和 JSON 校验。
- 清点结果：ConfigFS/`pwrite` 是唯一已有的 arbitrary target/value transport，且
  受 ashmem fops 劫持门控；pipe 是 downstream/circular，pselect 是同一 rb anchor；
  `ASHMEM_SET_NAME`、perf、`sendmsg` 和页面塑形仅是 setup/leak/allocation；SELinux、
  su、wallpaper 与日志写入是 post-credential 或 userspace side effect。
- 结论：**NO-NEW-INDEPENDENT-KERNEL-WRITE-SINK**。该清点范围为核心 `src/*.c`，不
  把重复 target variant 当作新路径；全程不构建、不改 payload、不联机。
- 最优下一步：归档 rb/PI、pipe 和核心 syscall 分支；只有发现独立 kernel object、
  callback、destination、write value 四项均可离线闭合时，才开启新的研究分支。

## 2026-07-22 active Violin artifact scope correction

- 新增 `tools/audit_violin_active_artifact_scope.py`，生成
  `analysis_outputs/violin-active-artifact-scope-20260722.{json,md}`；已通过运行、
  `py_compile` 和 JSON 校验。
- `Makefile` 默认 `PROJECT=blazer-CP2A.260605.012`，因此不带参数的 `make` 不是
  Violin artifact。Violin 必须显式使用 `PROJECT=violin-v-oss`。
- 在该显式选择下，`pick_src` 只覆盖 `src/targets/violin-v-oss/slide.c` 与
  `target.h`；`main.c/util.c/fops.c/pipe.c` 仍来自核心 `src/*.c`。Violin 专用
  `slide.c` 的 write 调用仅为 crash log 和 child-pipe report，没有任意 kernel-write
  syscall。
- 因此核心 sink inventory 对 Violin 源码选择仍有效，但任何 binary/hash 证据必须
  同时记录 `PROJECT=violin-v-oss` 和 source map；不能把默认 blazer 构建当作 Violin
  证据。全程不构建、不联机。
- 最优下一步：停止 sink 猜测，先对历史 binary/哈希做 source-map provenance 对账；
  provenance 不一致的 artifact 直接降级为无效证据。

## 2026-07-22 binary/hash provenance audit

- 新增 `tools/audit_violin_binary_provenance.py`，生成
  `analysis_outputs/violin-binary-provenance-20260722.{json,md}`；仅读取历史日志、
  文件大小和 SHA256，不构建、不运行、不联机。
- 已记录的命名 Violin artifact（stable0、E20、caimanwords、route-only、slide-only
  及当前 `build/violin-v-oss/bin/preload.so`）均能与文件 SHA256 对上；CFI ConfigFS
  路径存在两个历史 hash，不能仅凭路径归属某一次运行。
- `exploit-site/preload.so` 与 `preload-a358fbf.so` 的当前 hash 未在历史记录中找到
  对应 source-map/run-log，状态为 **CURRENT_HASH_UNMAPPED**，不得作为 Violin 证据。
- 结论：hash 命中只能证明字节一致，不能替代 `PROJECT=violin-v-oss`、source map
  和对应 run log 的三元 provenance。后续只允许使用三项齐全的 artifact；未映射文件
  先隔离，避免把默认 blazer 或路径复用误当作 Violin 结果。

## 2026-07-22 strict provenance manifest

- 新增 `tools/build_violin_provenance_manifest.py`，生成
  `analysis_outputs/violin-provenance-manifest-20260722.{json,md}`；该清单消费前一轮
  hash 审计，只做离线字段归类，不移动、重建或执行任何 artifact。
- 清单强制要求四元证据：`SHA256`、`PROJECT=violin-v-oss`、selected source map、
  corresponding run log。当前 9 个文件中：6 个为 hash 命中但 provenance 不完整，1 个
  为路径复用且 provenance 不完整，2 个通用文件逻辑隔离；**accepted_complete=0**。
- 结论：所有历史结果暂只能作为部分证据，不能把 hash 命中直接升级为 Violin runtime
  结论。下一步只补齐已有离线记录中的 project/source-map/run-log 字段，缺字段时保持
  只读门禁。

## 2026-07-22 provenance recovery audit

- 新增 `tools/audit_violin_provenance_recovery.py`，生成
  `analysis_outputs/violin-provenance-recovery-20260722.{json,md}`；只读取已有 build
  script 与 `03-dev-log.md`，不执行脚本。
- 回收确认：9 个条目中已有 7 个可复核 run-log/embedded-artifact 引用；只有 CFI
  ConfigFS 与 route-only 还各有可复核的 source script。两份脚本都硬编码
  `TARGET_CONFIG_H=targets/violin-v-oss/target.h`，没有记录 `PROJECT=violin-v-oss`
  变量；CFI 路径还被两个 hash 复用。stable0/E20/caimanwords/slide-only 的 hash
  仍没有与具体 source script 建立一对一链接。
- 因此仍为 `accepted_complete=0`：2 个通用当前文件继续逻辑隔离，其余 hash 命中项
  只能算部分 provenance。下一步只能补齐已有记录，不能借 recovered script 开新运行。

## 2026-07-22 transcript provenance audit

- 新增 `tools/audit_violin_transcript_provenance.py`，生成
  `analysis_outputs/violin-transcript-provenance-20260722.{json,md}`；只读解析用户提供
  的 Claude JSONL，不重放其中命令。
- 转录中存在大量通用 `make PROJECT=violin-v-oss` 讨论/命令，但没有任何一条同时绑定
  stable0、E20、caimanwords 或 slide-only 文件名的结构化 build record；四项均为
  `NO_ARTIFACT_SPECIFIC_BUILD_RECORD`。
- 因此 transcript 不能补齐 hash→source 一对一关系；完整 provenance 仍为 0，继续
  只读门禁。

## 2026-07-22 corrected primary fops gate

- 新增并验证 `tools/audit_violin_primary_fops_gate.py`，生成
  `analysis_outputs/violin-primary-fops-gate-20260722.{json,md}`；仅对显式 Violin
  source、同 build raw kernel image 和既有调用模型做离线对账。
- 旧的“Violin `misc_fops` 所有字段非零、因此 rb_insert 无 NULL 插入点”结论已被
  raw image 直接否定：`misc_fops.owner=0`，`misc_fops.poll=0`，并且多个其它字段
  也是 NULL。该旧结论标记为 **superseded**，不得继续作为失败根因。
- 正确的 fops 指针槽是 `ashmem_misc + 0x10`，raw 值为
  `&ashmem_fops`（`0xffffffc0812c9df0`）；`misc_fops` 静态表地址不能替代该槽位。
- 当前 worktree 的默认 route 仍是 `poll(fd=-1,nfds=1)`。`pselect_user_lock` 被当作
  `pollfd` 用户缓冲区，但 `fd=-1` 在 `do_pollfd()` 早退，不进入 `vfs_poll/poll_wait`；
  因而 `fake_w0->lock=pselect_user_lock` 仍为 **NO-SOURCE-EDGE**。
- 默认 shape-0 的离线 `rb_erase` 模型只产生
  `[ashmem_misc+0x08]=fake_fops` 与 `[fake_fops+0x08]=ashmem_misc+0x08` 两个写，
  不触达 fops 槽 `T=ashmem_misc+0x10`。custom shape-1 的实际分支条件已由
  `misc_register()`/`__rb_change_child()` 对账修正：要求 `N.rb_left!=W`，随后写
  `N.rb_right=T`；当前 list invariant 支持该条件，但仍需 PI dequeue identity 到达 erase。
- 本轮校验结果：`source_checks=5/5`、`raw_checks=3/3`，结论仍为
  **ACTIVE_PRIMARY_FOPS_WRITE_NOT_CLOSED**。不构建、不改 fd-set、不联机。

## 2026-07-22 bounded pselect/custom-shape state table

- 新增并验证 `tools/audit_violin_pselect_custom_shape_state.py`，生成
  `analysis_outputs/violin-pselect-custom-shape-state-20260722.{json,md}`；
  `runtime_allowed=false`，只消费现有 source/raw/report，不改变 `nfds` 或 shape。
- 状态表分离四个情形：
  - active `poll(fd=-1)`：stale lock 无 `pselect_user_lock` source edge，shape-0 的 T 不到达；
  - hypothetical `pselect nfds=64`：target/fake_lock/剩余 waiter words 被丢弃；
  - hypothetical `pselect nfds>=257` + shape-0：stale lock 可由独立 12-word 表供给，
    但 `fake_w0->lock` 仍是 user VA，且 shape-0 仍不写 T；
  - hypothetical `nfds>=257` + shape-1：T:=F 仍需 PI dequeue identity 到达 pi-tree erase，
    erase 后同 waiter `W→F→W` 不终止，且 F.owner:=N 的 fresh-open/owner-repair 未闭合。
- raw 预注册 `N.rb_left=0`、`N.rb_right=&ashmem_fops` 加上 `misc_register()` list invariant
  支持 `N.rb_left!=W`；总判定仍为 **PSELECT_CUSTOM_SHAPE_STATE_NOT_CLOSED**。
- 下一步只保留离线证据门：PI dequeue identity、`fake_w0->lock` 的 kernel 地址、
  可终止的 post-erase `rb_add`、以及 owner-repair/transport 顺序四项必须同时闭合；否则归档。
  不构建、不联机、不改 fd-set。

## 2026-07-22 rb/PI anchor archive

- 生成 `analysis_outputs/violin-rb-pi-anchor-archive-20260722.md`，状态为
  `FROZEN_NO_RUNTIME_BRANCH`。这不是 root/利用失败的永久结论，而是当前证据门下
  对 rb/PI 分支的运行冻结。
- 归档理由：active poll 没有用户锁 source edge；shape-0 不写 T；pselect>=257
  只是未接入的假设映射且 fake_w0.lock 仍 user VA；shape-1 的目标方程、post-erase
  终止性和 owner/transport 顺序均未闭合。
- 只有 PI dequeue identity、kernel second-lock、terminating rb_add、owner-repair/
  transport 四项离线证据同时出现时才重新打开；否则不使用历史 runtime/hash-only
  artifact，不构建、不联机。

## 2026-07-22 shape-1 predecessor branch correction

- 新增并验证 `tools/audit_violin_misc_list_predecessor.py`，生成
  `analysis_outputs/violin-misc-list-predecessor-20260722.{json,md}`；该审计读取
  same-build `misc_register()`、`list_add()`、`__rb_change_child()` 源码和 raw image。
- 发现并撤销前一轮“shape-1 要求 `N.rb_left==W`/predecessor child 等于 W”的说法。
  `__rb_change_child()` 的真实条件是：`N.rb_left==W` 写 `N.rb_left`，否则写
  `N.rb_right`。shape-1 要把 `T` 写成 `F`，需要的是 **`N.rb_left!=W`**。
- `misc_register()` 先 `INIT_LIST_HEAD(&misc->list)`，再
  `list_add(&misc->list,&misc_list)`；因此 `N.rb_left` 是 `misc_list.next`（空表头或
  现有 miscdevice list 节点），不是 payload 页中的 `W`。在无先前 list corruption
  的当前模型下，predecessor branch 已闭合，shape-1 的 `T:=F` 只剩 PI dequeue/top-waiter
  identity 这一到达门。
- 仍未闭合：active poll 的 stale-lock source、`fake_w0->lock` kernel second lock、
  shape-1 erase 后 `W→F→W` 终止性、`F.owner:=N` 的 owner/transport 修复。
- 旧 child-link blocker 已标记 **SUPERSEDED**；不启用 shape1、不改 fd-set、不构建、不联机。

## 2026-07-22 PI dequeue/top-waiter identity audit

- 新增并验证 `tools/audit_violin_pi_dequeue_identity.py`，生成
  `analysis_outputs/violin-pi-dequeue-identity-20260722.{json,md}`；工具只读核对
  `futex/requeue.c`、`rtmutex.c`、`rtmutex_api.c`、当前 `main/fops/util` 与已有审计，
  已通过 `py_compile`、执行和 JSON 校验，`runtime_allowed=false`。
- 关键更正：`prerequeue_top_waiter` 来自
  `rt_mutex_top_waiter(lock)`（随后传给 `rt_mutex_dequeue_pi(task, ...)`），不是由
  `task->pi_blocked_on` 单独推导。`futex_wait_requeue_pi()` 的初始 waiter 是栈上的
  `&rt_waiter`，requeue 直接把它传给 `rt_mutex_start_proxy_lock()`；这不能自动等价于
  payload 页的 `fake_w0`。
- 当前 active route 是 `FUTEX_CMP_REQUEUE_PI` 后的 `poll(fd=-1,nfds=1)`；没有证据把
  实际 chain 的 task/lock/waiter 绑定为 `fake_task/fake_lock/fake_w0`，因此 verdict 为
  **PI_IDENTITY_NOT_CLOSED_ACTIVE_POLL**，shape-1 的 `T:=F` 只能记为
  `CONDITIONAL_ON_SYNTHETIC_CHAIN_ENTRY`。
- 即使假设离线模型先进入 `fake_lock`，shape-1 的 predecessor 分支确实可把
  `T=ashmem_misc+0x10` 改为 `fake_fops`；但现有 `fake_w0->lock` 仍是用户态
  `pselect_user_lock`，下一轮 `raw_spin_trylock()` 的 second lock/lifetime 未闭合。
- 结论：继续保持 `FROZEN_NO_RUNTIME_BRANCH`；不改 `nfds`、不启用 shape-1、不构建、
  不联机。只有完整 synthetic chain identity、canonical second lock、终止性和
  owner/transport 四项同时有离线证据时才重新打开。

## 2026-07-22 full synthetic-chain closure audit

- 新增并验证 `tools/audit_violin_full_synthetic_chain_closure.py`，生成
  `analysis_outputs/violin-full-synthetic-chain-closure-20260722.{json,md}`；工具只读
  对账 exploit source、same-build rtmutex/rbtree source、raw-image 报告和既有审计，
  `runtime_allowed=false`，已通过 `py_compile`、执行和 JSON 读取校验。
- **Synthetic chain：** payload 的 `fake_task/fake_lock/fake_w0` 字段确实完整存在；
  但 active `FUTEX_CMP_REQUEUE_PI → poll(fd=-1,nfds=1)` 没有把真实 chain 的
  task/lock/waiter 绑定到这三个对象的 source edge，`prerequeue_top_waiter` 仍需从
  实际 `rt_mutex_top_waiter(lock)` 证明，结论为 `SHAPE_PRESENT_ENTRY_NOT_PROVEN`。
- **Kernel second-lock：** `rt_mutex_adjust_pi()`/`rt_mutex_adjust_prio_chain()` 会
  读取 `waiter->lock` 后访问 `lock->wait_lock`；当前 `fake_w0->lock` 明确是
  `pselect_user_lock` 用户 VA。RCU boost mutex 没有稳定 owner，console/tty 是
  非 RT mutex 布局，动态 futex PI lock 没有独立生命周期；结论为
  `NO_CANONICAL_KERNEL_SECOND_LOCK`。
- **终止性：** shape-1 的 predecessor 方程仍可在 PI identity 已到达时把
  `T=ashmem_misc+0x10` 改成 `fake_fops`，但 erase 后 stale root/leftmost 与同 waiter
  enqueue 沿 `W→F→W`，`rb_add_cached` 找不到 NULL，不能安全返回；结论为
  `NON_TERMINATING_CONDITIONAL_SHAPE1`。
- **Owner/transport：** 初始 `fake_fops.owner=0`，read/write_iter 已指向 ConfigFS；
  llseek 修复、text refresh 和最终 owner clear 均有代码，但它们都依赖首次 fops/ConfigFS
  写入；shape-1 后 owner=N 不是已验证的合法 module 指针，pipe forge/restore 也委托
  同一 `kernel_write_data→ConfigFS`，没有独立 first-stage sink。结论为
  `STRUCTURAL_ONLY_FOPS_GATED`。
- 四门总判定：**`FULL_SYNTHETIC_CHAIN_NOT_CLOSED`**。不改变 `fd_set`/`nfds`，不启用
  shape-1，不构建、不联机；只有四项同时有新的离线闭合证据才重新打开 rb/PI anchor。

## 2026-07-22 independent sink closure

- 新增并验证 `tools/audit_violin_independent_sink_closure.py`，生成
  `analysis_outputs/violin-independent-sink-closure-20260722.{json,md}`；只扫描显式
  `PROJECT=violin-v-oss` 的 active source map，`runtime_allowed=false`。
- Makefile/source map 已确认：Violin 只 override `slide.c`/`target.h`，核心
  `main.c/util.c/fops.c/pipe.c` 仍来自 `src/*.c`；target `slide.c` 只有日志和 child-pipe
  `write()`，没有 arbitrary kernel-write syscall。
- active source 中唯一 `pwrite()` 是 ConfigFS transport；`sendmsg/ioctl/setsockopt` 是
  页面、ashmem、perf、socket setup；pipe direct write 仍依赖 ConfigFS 的
  `kernel_write_data()`。`splice/vmsplice/tee/process_vm_writev/copy_file_range/madvise/
  ptrace/bpf` 均无调用点。
- 结论：**`NO_NEW_INDEPENDENT_KERNEL_WRITE_SINK`**。当前 rb/PI、pipe、syscall 分支归档；
  只有新的 offline 证据同时给出独立 kernel object、callback、destination、value，才重新评估。

## 2026-07-22 same-build kernel sink candidate closure

- 新增并验证 `tools/audit_violin_kernel_sink_candidates.py`，生成
  `analysis_outputs/violin-kernel-sink-candidates-20260722.{json,md}`；仅核对
  `kernel-src-wsl/common-gki` 与记录的同 build config，`runtime_allowed=false`。
- `/dev/mem` 的直接物理写路径被 `CONFIG_DEVMEM=n` 关闭；Binder、BPF、UFFD、TUN、
  VHOST、ashmem 的 user-copy 目标分别落在 allocator-owned buffer、map/object、当前
  `mm`、skb、guest/IOTLB 或 ashmem object，没有接受任意 kernel address 的首写接口。
- `CONFIG_VHOST_NET=n`；`CONFIG_VHOST_VSOCK=y` 仍只暴露 vhost 状态/guest memory 语义。
- 不能把 source snapshot 缺失当作负证据：`CONFIG_IO_URING=y` 但缺少
  `io_uring/io_uring.c`/`fs/io_uring.c`，`CONFIG_KVM=y` 但缺少 `virt/kvm/kvm_main.c`；
  这两个候选保持 **`OPEN_SOURCE_SNAPSHOT_GAP`**，尚未完成 whole-kernel sink absence。
- 本轮总判定：**`NO_NEW_INDEPENDENT_SINK_CLOSED_SOURCE_GAPS_REMAIN`**。下一步是取得
  exact Violin common-kernel source 或匹配 vmlinux/disassembly，补齐 io_uring/KVM 的
  destination/value 对账；不据此重开 rb/PI anchor。

## 2026-07-22 raw sink-gap inventory correction

- 新增并验证 `tools/audit_violin_raw_sink_gap_inventory.py`，生成
  `analysis_outputs/violin-raw-sink-gap-inventory-20260722.{json,md}`；使用匹配 OTA
  `boot.img.kernel` 和 rooted kallsyms 做 bounded ARM64 disassembly，未构建、未联机。
- 重要更正：前节的 `OPEN_SOURCE_SNAPSHOT_GAP` 只表示 checked-in `common-gki` 缺目录，
  不能解释为目标内核没有实现。匹配 raw kernel 为 36,456,960 bytes，SHA256
  `9552098B7FADBB2F6375252F69A47DC132AB36CEC3290F5219C8103DCE064D33`，已同时定位
  io_uring setup/enter/register、buffer registration、read/write，以及 KVM VM ioctl、
  set-memory-region、write-guest、device ioctl 符号。
- bounded disassembly 显示：io_uring generic path 只处理 ring/registered user buffers/
  opened-file operations；KVM generic path 只处理 memslot/guest memory/vCPU state，均未
  发现 user-supplied arbitrary host-kernel destination。
- 尚未闭合的只是专用分支：`io_uring_cmd` 的 file-specific `uring_cmd` callback，以及
  arm64 KVM 专用 ioctl handler；总判定为
  **`RAW_ARTIFACT_PRESENT_GENERIC_PATHS_NOT_ARBITRARY_DRIVER_OR_ARCH_REVIEW_OPEN`**。
- 因此下一步应继续对同一 raw image 做 driver/arch 定点反汇编，而不是补造缺失 source、
  改 payload 或恢复 rb/PI runtime branch。

## 2026-07-22 raw driver/arch sink boundary

- 新增并验证 `tools/audit_violin_raw_driver_arch_sinks.py`，生成
  `analysis_outputs/violin-raw-driver-arch-sinks-20260722.{json,md}`；使用同一匹配
  raw kernel/kallsyms，`runtime_allowed=false`，已通过 `py_compile`、执行和 JSON 断言。
- 定点核对 generic `io_uring_cmd`、ublk/NVMe callbacks 及 arm64 KVM 专用 ioctl：
  `io_uring_cmd` 的 `blr x8` 确认是 `file->f_op->uring_cmd` 间接分发；ublk 只操作
  request/device state，NVMe 最终经 `nvme_map_user_request`/block request 做设备 I/O，
  KVM 只围绕 vCPU/VM、guest memslot/MTE tags 和计时字段操作，未发现新的任意 host-kernel
  destination。
- raw static fops 的 dispatcher `+0xf8/+0x100` 槽又解析出 8 条已知 callback 记录：
  `null_fops`、`ublk_ctl_fops`、`ublk_ch_fops`、`nvme_dev_fops`、
  `nvme_ns_chr_fops`、`nvme_ns_head_chr_fops`（含 `uring_cmd_iopoll`）；module alias
  relocation delta 为 `0x2307200000`。这只扩大已列静态表的证据，不等于动态/未列模块全闭合。
- 目标符号全部在匹配 raw image 中存在；结论为
  **`TARGETED_DRIVER_ARCH_CALLBACKS_NO_ARBITRARY_KERNEL_DESTINATION; GENERIC_IO_URING_CMD_DISPATCH_REMAINS_OPEN`**。
- 这不是 whole-kernel absence 证明：未列出的 loadable module/future callback 仍在边界外。
  维持 `FROZEN_NO_RUNTIME_BRANCH`；不改 `fd_set`/`nfds`，不构建、不安装、不联机、不运行
  新 payload。

## 2026-07-22 device identity/log preflight

- 已只读确认设备 `03035440C1781540` 在线，product/device 为 `violin`，fingerprint
  `Xiaomi/violin/violin:16/BP2A.250605.031.A3/OS3.0.303.0.WOTCNXM:user/release-keys`，
  kernel 为 `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`，SELinux Enforcing，
  shell 具有 `readtracefs`。当前 boot_id 为 `c79163bc-d9f5-457a-a30f-0362d89db8ea`。
- 设备现存 `/sdcard/Download/crash.txt` 只有 2026-07-18 的 `PSELECT_LAYOUT_*` 安全布局
  探针；已拉取到 `analysis_outputs/device-readonly-20260722/`。未发现本轮 raw sink 审计对应
  的新运行日志。
- 已保存当前全量 logcat 到 `analysis_outputs/device-readonly-20260722/logcat-all.txt`
  （SHA256 `2DA28BBA1FACD91A3BA6E828D43ED27304CBC0691EDAF4971D9EDBDC6649AB81`）；shell 读取
  `dmesg` 被 `Permission denied`，不能把它当 kernel crash 证据。
- 当前 `build/violin-v-oss/bin/preload.so` 是 2026-07-18 旧 full-route binary，早于
  2026-07-19 的 `main.c/fops.c/util.c`；本机未发现可用 Android NDK。因此不能把旧 binary
  冒充当前源码验证，也不应直接推送旧 full route。下一次联机测试应先生成
  `CFGPROBE_ONLY_DIAG=1` 停止版，再单独收集日志，不进入 rb/PI/pipe stage。

## 2026-07-22 NDK diagnostic build and device run

- 用户提供并核实 `E:\workspace\projects\xiaomi-root\ndk` 为 Android NDK r29
  (`Pkg.Revision = 29.0.14206865`)；使用 `PROJECT=violin-v-oss` 与
  `-DCFGPROBE_ONLY_DIAG=1` 重新构建隔离产物，未覆盖旧 full-route binary。
- 当前 diagnostic `preload.so`：
  `exploit-repo/IonStack/CVE-2026-43499/exploit/build/violin-v-oss-diag-20260722/bin/preload.so`，
  大小 173,536 bytes，SHA256
  `cb71799ce82f3ae8a62b1226c7fc332a7ec54d9746d4679e463ff0d481c84662`；构建来源和源码哈希
  记录在 `analysis_outputs/device-diag-build-20260722/build-manifest.txt`。
- 已推送到设备 `/data/local/tmp/ionstack-violin-diag-20260722/preload.so`，远端
  `sha256sum` 与本地完全一致。通过 shell `LD_PRELOAD` 只触发 stop-only constructor，日志已拉取到
  `analysis_outputs/device-diag-run-20260722/crash.txt`，SHA256
  `7006eb965db4df72ca6cfb84ad6508416eee6db87df7e4a506068f236fa0a6e4`。
- 运行证据：`STEP0`、`CFGPROBE_START`、`CFGPROBE_STOP_AFTER_PROBE`、
  `CFGPROBE_ONLY_DIAG_STOP` 均出现；`CFGPROBE_MISS`、`CFGPROBE1 rd=0 errno=0`，且没有
  `STEP3`、`ROUTE_PREP_*`、`FOPSROUTE_*` 或 PI/pipe 阶段。boot_id 运行前后仍为
  `c79163bc-d9f5-457a-a30f-0362d89db8ea`，设备未重启。
- 该轮只证明当前源码/当前 boot 的 pre-hijack CFGPROBE 路径可执行并在 probe 后停止；没有证明
  fops 劫持、任意 kernel write、CFI 或 root。下一步仍应围绕离线 sink/目标槽位证据，不得把该
  diagnostic run 当成完整利用成功。


## 2026-07-22 route-only scheduler/consumer diagnostic

- 以用户提供 NDK r29 构建隔离版本 `DIRECT_WRITE_ROUTE_ONLY_PROBE=1`。该分支明确不调用
  `set_pselect_write()`，不准备 fake kernel page，只用安全 fd_set/timerfd 测量 scheduler/consumer
  handoff；产物 SHA256 为
  `8363b56a0fae924be5af710d9906f9b6e116d8ea0b6461422e379d0915eaf8fb`，清单在
  `analysis_outputs/device-route-diag-build-20260722/build-manifest.txt`。
- 设备远端为 `/data/local/tmp/ionstack-violin-route-diag-20260722/preload.so`；运行日志在
  `analysis_outputs/device-route-diag-run-20260722/crash.txt`，SHA256
  `0616c41602c201af4464a21a6fe1cea42a4d6bd9456f17a6a4d65468f88a6bfa`。
- 证据：`ROUTE_PREP_REQUEUE: ret=1 errno=0`、`ROUTE_ONLY_RET: ret=0 errno=0 calls=200 success=200`、
  `ROUTE_ONLY_PROBE_DONE: ... changed=0 route_done=1 ... cfi_step=0 errno=0`；boot_id 前后不变，
  shell uid 仍为 2000。说明普通 requeue/consumer/safe pselect route 当前可执行。
- 这不是 fops 或写入证据：因为 route-only 分支没有 fake page 和 pselect write，未调用 ConfigFS CFI、
  rb_insert 或 pipe physrw；完整利用仍未闭合。

## 2026-07-22 CFI transport errno isolation

- 新增默认关闭的 `CFI_TRANSPORT_ONLY_DIAG=1` 构建分支，仅执行 `ASHMEM_SET_NAME` blob 设置与
  一次 `pwrite()`；不创建 fake page、不调用 `set_pselect_write()`、不启动 route、不写任意
  kernel address。artifact SHA256 为
  `916c683bf5789bfed6380bb5c5efd6ed17fadb66c782ecc189e283a3e990ec09`，构建清单：
  `analysis_outputs/device-cfi-transport-build-20260722/build-manifest.txt`。
- 运行日志 `analysis_outputs/device-cfi-transport-run-20260722/crash.txt`（SHA256
  `7e3282c8987dc1c3833b940b7ee8f8db22370045bd754b3f57dfff4f7730bfbd`）显示：
  `CFI_TRANSPORT_SET_NAME: ret=0 errno=0`；`CFI_TRANSPORT_PWRITE: ret=-1 errno=22`。
- 这把旧 full-route `step=1 errno=22` 的失败边界收窄为 pre-hijack ashmem `pwrite`，不是
  name/blob 设置失败；但仍不能把它写成 fops slot 已写入。下一步只需闭合 fops slot 的写入与
  readback，不能再通过调 `fd_set`/`nfds` 推断 ConfigFS transport 已建立。


## 2026-07-22 offline fops/chain gate re-audit

- 重新执行 `tools/audit_violin_primary_fops_gate.py` 与
  `tools/audit_violin_full_synthetic_chain_closure.py`；均为
  `runtime_allowed=false`，未构建、未安装、未联机、未运行新 payload。
- 同一匹配 raw image 的离线 image-coordinate 中，目标槽为 `ashmem_misc + 0x10 =`
  `0xffffffc08223b5e8`（运行时地址由 KASLR slide 决定；本轮设备日志为
  `0xffffff800244b5e8`），当前值确实是 `&ashmem_fops = 0xffffffc0812c9df0`；
  `misc_fops.owner` 与 `misc_fops.poll` 均为 NULL。此前“Violin 的 misc_fops 没有 NULL
  字段”的结论已被 raw image 证据否定，不能再作为 `errno=22` 根因。
- 当前 worktree 的 active route 仍是 `run_main_route_threads()` →
  `FUTEX_CMP_REQUEUE_PI` → `poll(fd=-1,nfds=1)`；没有已证明的
  `pselect_user_lock → fake_lock` 边，故 `fake_task/fake_lock/fake_w0` 的 PI 身份未闭合。
- 完整 synthetic-chain verdict 仍为 `FULL_SYNTHETIC_CHAIN_NOT_CLOSED`：第二轮
  `fake_w0->lock` 是用户 VA；shape-1 的 `T:=fake_fops` 只是条件等式；同 waiter 的后续
  `rb_add` 会走 `W→F→W` 循环且无 userspace return；`owner=N` 不是已验证 module pointer；
  没有独立 first-stage pipe sink。

### 下一道门

停止继续调 `fd_set`/`nfds`，也不要直接重跑 full-route。下一步只做一项离线闭合：把实际
`rt_mutex_adjust_prio_chain` 的 task/lock/waiter 指针身份、一个 canonical kernel second-lock、
shape-1 `rb_erase → rb_add` 的终止性以及 fake_fops owner/transport 修复写成同一张状态表；若
不能同时闭合，就放弃该 fops anchor，转向新的独立首写 sink。任何启用 shape-1 的联机运行都
需先单独授权并设置可检测的 stop/reboot 条件。



## 2026-07-22 pointer/lifetime synthetic-chain state table

- 新增并运行 `tools/audit_violin_pointer_lifetime_state_table.py`，生成：
  `analysis_outputs/violin-pointer-lifetime-state-table-20260722.json` 和
  `analysis_outputs/violin-pointer-lifetime-state-table-20260722.md`；`py_compile=0`，
  `runtime_allowed=false`，没有构建、安装、联机或运行 payload。
- 状态表把链拆成 S0-S6：S0 只有 payload shape；S1 只有普通 futex/requeue transport；S2
  active poll 没有 fake-lock edge；S3 `fake_w0->lock` 仍是 user VA；S4 shape-1 只是条件目标；
  S5 同 waiter 的 `rb_add` 是 `W→F→W` 非终止；S6 owner/transport 没有独立首写。
- 机器可读 verdict：`FULL_SYNTHETIC_CHAIN_NOT_CLOSED`；下一道门是同时闭合 S2-S6，
  否则放弃当前 fops anchor，不启用 shape-1 或重跑 full-route。

## 2026-07-22 expanded same-build second-lock inventory

- 在同一份 `kallsyms.txt`、raw built-in image、BTF 和 common-gki source 上复核第二轮
  `rt_mutex` 候选；工具为 `tools/audit_violin_second_kernel_lock_inventory.py`，输出为
  `analysis_outputs/violin-second-kernel-lock-inventory-20260722.{json,md}`。本轮仍是离线
  审计，`runtime_allowed=false`，没有构建、安装或运行 payload。
- 扩展扫描到 212 个位于 raw image 内、名字包含 `mutex` 的 data symbols；每个首部都符合
  BTF `struct mutex` 的 `owner@+0 / wait_lock@+0x8 / wait_list self@+0x10,+0x18` 形状，
  没有一个符合 `rt_mutex_base` 的 `waiters.rb_root@+0x8 / leftmost@+0x10 / owner@+0x18`
  形状。`port_mutex` 只是同一类普通 mutex，并非此前误读的 `po_rt_mutex`。
- source 中 `locktorture.c` 与 `locking-selftest.c` 的 11 个 `DEFINE_RT_MUTEX` 名称均不在
  该 exact build 的 kallsyms 中；唯一名字匹配项 `rt_mutex_adjust_prio_chain.prev_max`
  在 raw built-in image 外且是函数局部 scalar，不是 lock object。RCU 的三个
  `boost_mtx` 仍为合法布局但 raw owner/waiters 全零，source 明确其用途仅是 priority-boost
  side effect，不构成稳定第二 owner chain。
- 结论不变但证据更强：`closed_distinct_second_lock=false`。不得把 `port_mutex`、
  `console_mutex`、`tty_mutex`、RCU boost mutex 或 `fd_set/nfds` 调整当作修复；若不能离线
  闭合独立 lock 的 owner/waiters/lifetime，就应归档 second-lock 分支并转向独立首写 sink。

- 已将该结果回灌 `tools/audit_violin_pointer_lifetime_state_table.py` 并重生成同名
  `analysis_outputs/violin-pointer-lifetime-state-table-20260722.{json,md}`；S3 现在明确记录
  `212` 个 named mutex 全为普通 `struct mutex`，且 `second_lock_inventory_closed=false`。

## 2026-07-22 read-only io_uring callback reachability

- 仅做设备只读面核对，记录在 `analysis_outputs/device-readonly-uring-surface-20260722/inventory.txt`
  （SHA256 `81832E9C6F8664C7A2992FF0725A7E739F2EAB6CF52FD2FB57C257503A9A1DD7`）；没有构建、
  推送或运行 payload。当前 uid 是 `2000(shell)`，SELinux 为 Enforcing，boot_id 未变。
- 既有 raw callback inventory 显示已知静态 `uring_cmd` fops 只有 null/ublk/NVMe 这组；设备
  上 `/dev/ublk-control` 为 `root:root 0600`、`u:object_r:ublk_control_device:s0`，shell 的
  `test -r`/`test -w` 均失败；`/dev/nvme0` 和 `/dev/kvm` 不存在，`/proc/modules` 没有
  对应可加载模块记录。
- 因此对当前 shell 身份，已知 callback 没有可达的 arbitrary-write sink；这只能形成
  `CURRENT_SHELL_NO_REACHABLE_IO_URING_WRITE_SINK`，不能把 generic `io_uring_cmd` 对所有
  特权/未来 driver callback 全局宣称已闭合。

## 2026-07-22 supplied artifact consistency

- 针对用户提供的 `ionstack-current-ktext.zip`、`violin-kernel-info2.zip`、`1.zip`、`kallsyms.txt`、`iomem.txt`、`slabinfo.txt`、`cmdline.txt`，新增离线工具 `tools/audit_violin_artifact_consistency.py`，生成
  `analysis_outputs/violin-artifact-consistency-20260722.json`（SHA256
  `a1760438ae8c62fb585d3592cd5c2ea54d83442de9258008668ac295e41880a4`）和
  `analysis_outputs/violin-artifact-consistency-20260722.md`（SHA256
  `00a22a4b50743ac8e01ff97ee6b819045adec706dd310e528312ddc1c3507eca`）。工具只读归档、校验哈希和相对符号，不构建、安装、联机或运行 payload。
- 三份 Violin `kallsyms` 的绝对 `_text` 分别为 loose=`0xffffffd365e00000`、current-ktext=`0xffffffe7ca400000`、kernel-info2=`0xffffffe387200000`；在同一 raw image 长度范围内有 `100433` 个唯一公共符号的相对偏移完全一致。核心锚点也全部一致：`anon_pipe_buf_ops +0x114a288`、`misc_fops +0x1269710`、`ashmem_fops +0x12c9df0`、`ashmem_misc +0x223b5d8`、`rcu_state +0x216acc0`、`misc_mtx +0x21f8c50`、`ashmem_mutex +0x223b540`、`security_hook_heads +0x164f410`。剩余 11 个差异集中在末端 vendor/`a` 类数据符号，不影响上述核心锚点。
- `violin-kernel-info2` 与 `1.zip` 的 build fingerprint 完全一致，且 `uname`/`version` release 均为 `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`，说明它们属于同一 kernel build 家族；`cmdline` 只在 `bootinfo.pdreason` 上出现 `0x0`/`0x3` 差异，属于不同启动快照。`ionstack-current-ktext` 的 boot_id 为 `2988e1dc-3130-4ba7-9985-74a91a2296cd`，`1.zip` 的 boot_id 为 `46b498dc-6a0c-4d36-b6b1-9c85da32a7fc`；现有设备只读记录的 boot_id 为 `c79163bc-d9f5-457a-a30f-0362d89db8ea`，三者不可混用。所有绝对 KASLR 地址只能作为各自快照历史值，当前计算必须重新取得同一 boot 的 leak 并核对 boot_id。
- `ionstack-current-ktext` 内部清单 4/4 通过；`1.zip` 清单 35 项中 33 项通过，两个不通过项是自引用 `SHA256SUMS.txt` 占位项和 `collector.log` 摘要不匹配。因此 `1.zip` 不能作为“整包完整校验通过”的证据。
- `1.zip` 的 tombstone 进程属于 dex2oat、SecurityCenter 和 `com.xiaomi.mirror`，过滤后的 `relevant-kernel-log.txt` 没有 `FOPSROUTE`/`CFGPROBE`/`GHOSTLOCK` 等实际利用标记；它只能作为历史崩溃上下文，不能证明 GHOSTLOCK 成功。
- 机器结论：`SAME_BUILD_OFFSETS_CONFIRMED_SNAPSHOT_BASES_NOT_INTERCHANGEABLE`。当前下一道门是同一启动实例的 KASLR leak/target readback 对账，不是重跑 full-route，也不是继续调整 `fd_set`/`nfds`。

## 2026-07-22 `sched_blocked_reason` / fake-lock claim cross-check

- 离线核对报告：`analysis_outputs/violin-sched-blocked-fake-lock-claim-audit-20260722.md`。
  `sched_blocked_reason` 的 `__get_wchan()` 同 boot KASLR oracle 与 D-state 触发条件已由
  `sched.h:493-512`、`sched/core.c:4355-4356` 证实，但不能泛化为所有 tracefs 环境，
  也不能把 oracle 当成 write/root 证据。
- 同 build raw offset `task+0x938 -> pi_blocked_on`、`waiter+0x58 -> lock` 是正确的，
  但当前 active worktree route 仍是 `poll(fd=-1,nfds=1)`，没有已证明的
  `pselect_user_lock -> fake_lock` 边；W=5/pselect 只属于显式 HEAD/诊断分支。
- `rt_mutex_adjust_prio_chain()` 对 `waiter->lock` 直接执行
  `raw_spin_trylock(&lock->wait_lock)`；exact build 启用 `CONFIG_ARM64_PAN` 和
  `CONFIG_ARM64_SW_TTBR0_PAN`，所以 `fake_w0->lock` 的 user VA 不能视为可消费的
  kernel `rt_mutex_base`。第二轮 PI/SELinux write 仍未闭合。
- raw `brk #0x800` 主要由 `waiter->lock` 与当前 lock 不一致的分支进入，吻合内联
  `rt_mutex_top_waiter()` 的 `BUG_ON(w->lock != lock)`；common source 的
  `rt_mutex_setprio()` 只有 idle 分支 `WARN_ON(p->pi_blocked_on)`，没有“非空即 BRK”。
  “前 16 轮一定安全”尚无证据。
- fd 0-2 覆盖、consumer warm-up、`punch_consume_go` 清零过早均为分支/时序风险：custom
  dup2 分支会覆盖 0-2，default 已跳过；default route 在 poll 返回后等待约 300 ms，
  显式 pselect probe 才是立即清零的分支。机器结论保持
  `FULL_SYNTHETIC_CHAIN_NOT_CLOSED`；本轮未构建、未安装、未联机、未运行新 payload。

### Recommended next action

1. **先闭合 artifact provenance**：当前 `analysis_outputs/violin-provenance-manifest-20260722.md`
   的 accepted complete tuples 为 `0`；必须把 `PROJECT=violin-v-oss`、实际 source map、
   preload SHA256 和对应 run log 绑定起来。现有四个 Violin build 目录不能凭文件名互换。
2. **冻结当前 poll baseline**：在 provenance 闭合后记录 active target、编译宏、构建产物
   hash、同 boot `boot_id` 与 KASLR 相对偏移；禁止把 W=5/pselect HEAD 状态混进 poll 日志。
3. **只做离线闭合表**：逐项填写 active route → fake-lock edge、kernel second-lock 的
   owner/waiters/lifetime、`rb_erase → rb_add` 终止性、fops slot readback。任一项为否，
   不启动 full-route。
4. **若 second-lock 仍无 canonical kernel 候选**（当前 inventory 已为否），关闭当前
   fops/PI anchor，转向独立首写 sink 的可达性审计；不要继续调 `fd_set`、`nfds` 或 consumer
   次数。
5. 只有上述门全部为真后，才做一次带 stop/reboot gate 的最小设备诊断；诊断先验证
   `boot_id/KASLR/target readback`，不直接执行 root/SELinux 写入路径。

## 2026-07-22 active route-state alignment

- 已新增并执行 `tools/audit_violin_active_route_state.py`；`py_compile=0`，审计只读取现有
  source、ELF、build/run manifest 与 crash log，不构建、不安装、不调用 ADB、不执行 payload。
- 三个 2026-07-22 诊断 tuple 均通过 selector、preload SHA256/size、run hash、`run_exit=0`、
  同 boot_id 与运行时 marker 对账：
  `cfgprobe_diag=cb71799ce82f3ae8a62b1226c7fc332a7ec54d9746d4679e463ff0d481c84662`，
  `route_only_diag=8363b56a0fae924be5af710d9906f9b6e116d8ea0b6461422e379d0915eaf8fb`，
  `cfi_transport_diag=916c683bf5789bfed6380bb5c5efd6ed17fadb66c782ecc189e283a3e990ec09`。
- 运行时边界已经按日志闭合：`cfgprobe_diag` 只到 `CFGPROBE_ONLY_DIAG_STOP`；
  `route_only_diag` 只验证 `ROUTE_ONLY_*` consumer/timerfd handoff；
  `cfi_transport_diag` 只到 `CFI_TRANSPORT_SET_NAME/PWRITE`。三者都不是 fops 劫持、
  arbitrary kernel write、cred 或 SELinux 证据。
- `build/violin-v-oss/bin/preload.so`（SHA256
  `f850dc1a0c06c71fa13fba1e38cf465152381c7a61af71819694501525201947`，175504 bytes）没有
  对应的 2026-07-22 tuple，且早于当前 source，已标记 **quarantine**，不能作为当前 Violin
  运行产物。
- 当前 source selector 明确为 `PROJECT=violin-v-oss`：只有 `src/targets/violin-v-oss/target.h`
  与 `slide.c` 覆盖，`main/util/fops/pipe/root/preload` 使用 root `src/`。未显式传
  `PROJECT` 的 `make` 不得作为 Violin 证据。
- 新报告：`analysis_outputs/violin-active-route-state-20260722.{json,md}`。
- 当前再次查询 `adb devices -l` 无设备；设备重新连接后，下一动作应先做同 boot 的只读
  `boot_id/KASLR/target readback` 对账，并沿用上述三类已证明 provenance 的诊断产物；
  不得把旧 full-route ELF 直接推送。

## 2026-07-22 provenance correction

- 随后把 build manifest 的 source hash block 纳入严格检查，修正了“当前 diag tuple 已完整”
  的过宽表述；报告已重生成为 `all_diagnostic_tuples_complete=false`。
- `cfgprobe_diag` 的 `src/main.c` manifest hash 为旧值
  `ac509d7786173ccfc4c80f7ae0f43811da0e96f74d0c800b8fd18bddb392b6d5`，与当前 source
  `9984a41b58383605913f7f79e4e207fe3b0d39fafc1e49cc34250d6b7b365f85` 不同；
  `route_only_diag` 完全没有 source hash block；`cfi_transport_diag` 只记录了当前
  `main.c`，缺少其余 tracked source。三组 artifact 只能称为“与各自 manifest/hash/marker
  一致的历史诊断产物”，不能称为 current-source complete tuple。
- 严格报告：`analysis_outputs/violin-current-diag-tuples-20260722.{json,md}` 与
  `analysis_outputs/violin-active-route-state-20260722.{json,md}`。在设备恢复前，不应重用
  这些 artifact 作为当前 source 的新 payload；应先用同一 source map 重新构建并生成完整
  source-hash tuple，再进行任何在线诊断。

## 2026-07-22 fresh source-bound diagnostic builds

- 已实际用 WSL NDK r29 编译脚本
  `tools/build_violin_fresh_diag_tuples.sh`；只生成本地 ELF，不调用 ADB、不安装、不运行。
- `tools/record_violin_fresh_diag_builds.py` 已生成每组完整 8-file source hash manifest：
  `analysis_outputs/violin-fresh-diag-builds-20260722.json` 及
  `analysis_outputs/fresh-{cfgprobe_diag,route_only_diag,cfi_transport_diag}-build-20260722/build-manifest.txt`。
- 新鲜产物（均 `PROJECT=violin-v-oss`、Android arm64、NDK r29）为：
  `cfgprobe=ed918dfabf61c5c53e7b1bfe5a99bc946dc77385939458ee1d38ababc6adb2e8`（173328 bytes），
  `route-only=81e17de80d9f6720e28e3886abb5bdd17a9d62ac2ab56382699ddbd1cb63c099`（170032 bytes），
  `cfi-transport=f833c5a9f33b2f6d07a11f9ba65148b8bc5081638e343d5d7169f81eff703cf6`（171704 bytes）。
- 这三组目前只有 **build** tuple，没有 device run tuple；下一道门是设备连接后以相同 hash
  做一次最小、可停止的只读诊断并记录 `boot_id`，不能把 build 成功写成 route/fops 成功。



## 2026-07-22 Stage-2 root_stage wiring and supplied 7sp artifacts

- 针对“第一阶段 SELinux permissive 不等于 root”的问题，当前 Violin source 已把 Stage 2 拆成显式链：`try_cfi_stage -> install_child_root -> install_pipe_physrw -> root_stage -> install_android_root`。`root_stage()` 只有在 `pipe_cache_gate_ok`、32-bit read/write 和 64-bit read/write 五项 transport proof 全部为真时才进入 credential/SELinux 操作；失败会回收等待中的 root child。
- 旧的 ConfigFS partial fake-cred 实验仍保留在 `fops.c`，但默认 `LEGACY_CONFIGFS_CRED_STAGE=0`，不会和新的 pipe-physrw root stage 叠加执行。当前 source/build 仍不构成 fops hijack、pipe physrw 或 root 的运行证明。
- 新增静态审计：`tools/audit_violin_root_stage_reachability.py`，报告 `analysis_outputs/violin-root-stage-reachability-20260722.{json,md}`。call graph 已闭合，verdict 为 `ROOT_STAGE_CALL_GRAPH_CONNECTED_LEGACY_PARTIAL_CRED_DISABLED`；该 verdict 仅表示源码连线和门禁存在，`runtime_proof=false`。
- 新 build-only 产物：`exploit-repo/IonStack/CVE-2026-43499/exploit/build/violin-v-oss-root-stage-20260722/bin/preload.so`，176184 bytes，SHA256 `da44ed17e16190e5fc99320666fe8b3fab9577589d62b0a25fba5abdb0b95a82`。完整 source hash 与编译宏见 `analysis_outputs/violin-root-stage-build-20260722/build-manifest.txt`；构建使用 NDK r29 WSL 镜像，未产生设备 run manifest。
- 用户附件 `7sp_permissive和root.zip` 解包后的三个 ELF 均为 AArch64：`p.so`（83632，`edd44e0c17781f0d63935dc1938b81fdcdc981f7221392117effb54e26e6cc81`）只有 permissive marker；`r.so`（86464，`ed07f6901eacd13577e77f09a7eebce5609e62b5b602bbefa10d09fdd4ca152e`）含 direct-root marker；`r2.so`（86664，`f4ddca29b1b86c6d119ecdf1d10b4337842739479c50e4c2e19d39808631af76`）额外含 reboot marker。附件没有 source map、运行日志或同 boot provenance，因此这些只能作为功能字符串线索，不能写成成功证据；`r2.so` 不应作为首个在线候选。
- 当前机器仍无 ADB 设备；下一次设备恢复后只把上述 hash 绑定的产物用于可停止诊断，先记录同 boot `boot_id/KASLR/target readback`，再观察 `ROOT_STAGE_ENTER/RESULT`、transport proof、child uid/gid 和 SELinux readback。不能把源码 call graph 或附件 marker 升级成 root 成功。

- 额外修正 root child ready-pipe 的 parent-side fd 状态：关闭写端后立即置为 `-1`，避免失败清理路径因 fd number 被复用而关闭无关描述符。

## 2026-07-22 7sp variants published to ionstack-violin

- 用户明确要求将三个附件变体上传到 `liang1228/ionstack-violin`。已在 `master` 提交 `0b56a19447d0d683470cbc8ab16c18b846db993e`，只包含 `p.so`、`r.so`、`r2.so`、`7sp-root-variants-20260722.md` 和 `exploit.html` 的 payload selector。
- GitHub Pages 已返回 `built`：`https://liang1228.github.io/ionstack-violin/`。可用 `?payload=p`、`?payload=r`、`?payload=r2` 选择三个文件。
- 已通过 raw 与 Pages 下载复核，三个文件的 size/SHA256 与本地完全一致；完整记录见 `analysis_outputs/ionstack-violin-publish-20260722/publish-manifest.txt`。
- 截图中的 `uid/euid/gid/egid=0`、`got_root=1`、`whoami=root` 可以证明某次 direct-root 运行成功，但未标注具体文件、source hash 或 boot_id，因此不能回溯为三个文件都已证明可用。

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

### 17.69 Interrupted-run recovery log analysis (2026-07-23)

- 用户提供的恢复日志已原样保存为 `analysis_outputs/ionstack-recovery-20260723/run.log`，大小 26599 bytes，SHA256 `7aee1c46dcaabd82df976fa46ad1dddf91874d95e65a91904093b8ad25949c4f`；机器可读统计为 `summary.json`，结论报告为 `report.md`。
- `result` 块只有 gate bypass、preload pid=10616、`cpu=9`/`consumer_cpu=2`/`shared=0` 和 `slide attempt 1 uses pselect`，随后截断；`result.done` 缺失，因此没有当前 run 的 KASLR/fops/pipe/cred/root 证明。
- `crash.txt` 块另含 16 个完整 instrumented slide attempts 和第 17 次开始：pselect ret=6 共 11 次、ret=0 共 5 次，`sched_ok=1`；但每次均为 `SLIDER2_BAD`，随后 `SLIDE4_CHILD_FAIL ... no stext`。该块的 STEP0 pid=17785 与 result 的 preload pid=10616 不同，且没有 selected filename/size/SHA/source commit/run manifest，不能严格绑定到已发布 `r4.so`。发布的 r4（86224 bytes，SHA256 `151208b0c6e06d721f11dca558359cc87bb90c2decb8025f9f1c22a163a49c92`）没有这些详细 `SLIDE1`/`SLIDER2_BAD` 字符串。
- `SLIDER2_BAD` 是确定性的假泄漏：`d2b83562-deff-4ea8...` 的前 16 个 hex 字符按 little-endian 恰好得到 `0xa84effde6235b8d2`，`hi=0xa84e`；因此 oracle 仍返回普通 boot_id 文本，没有得到 canonical kernel pointer，也没有 KASLR slide。当前恢复 boot_id 为 `d95f31f1-0838-402c-a84f-f114f06e7465`，与 trace 不同，确认发生了重启/掉电；boot reason 为空、pstore 被拒绝、last_kmsg 缺失，原因未知。
- 同一 unbound `crash.txt` 还打印了 `sysctl_bootid_direct=0xffffffbffa756f58`，而 `SLIDE2 bootid_data=0xffffff8002546f58`，相差 `0x3ff8210000`；下一轮离线审计必须先核对 direct-map/P0-alias 转换，不能把两个地址当成同一目标。
- 最优下一步是离线先绑定详细 marker 对应的实际 binary/source，给单次 slide attempt 增加 selected artifact + boot_id + target/readback manifest，核对 `SLIDE_RANDOM_BOOT_ID_DATA`/`SLIDE_NFULNL_LOGGER` 和 pselect stack-copy shape；在同一 artifact/boot tuple 出现 `SLIDER3_OK` 前，不再运行 20 次循环，也不进入 fops/pipe/cred/SELinux/root stage。

### 17.70 Linuxoid upstream generator audit (2026-07-23)

- 已离线拉取 `Linuxoid-cn/CVE-2026-43499-Poc-Analysis`：`main=a4106311a6035ce0a7831860a255a4ded310bfcc`，`secret=e03994331634f8c03ed1df51a4e9fc551ef8e5f1`。两个分支的 generator 和核心 C 源 hash 相同；这次不是新的 Violin exploit 修复。
- 上游 `generate_target.py` 是通用 `boot.img + profile.json -> target.h` 生成器，会用 IKCONFIG/kallsyms/BTF/反汇编推导 pselect/futex 布局、nf logger 槽和 `boot_id.data` 候选；但 `detect_offset.py` 仍只读取 root `/proc/iomem`，没有实现 XBL/DTB mem-label 扫描。XBL 得到的 p0 两个地址只能手工填 profile。
- 用当前 `E:\workspace\projects\xiaomi-root\boot.img`（100663296 bytes，SHA256 `140f57f5aeb591913aeaa5e554e2dd7ec32d6c8b197f86f39f06d8fbdb13573`）和已有 profile（0x0/0x210000）离线运行 generator，失败于 `IKCONFIG 标记不唯一或顺序错误: starts=[], ends=[]`；boot.img 与解压 kernel 均无 `IKCFG_ST/IKCFG_ED`，未生成 target.h。日志在 `analysis_outputs/linuxoid-cve-2026-43499-upstream-20260723/`。
- 上游 `slide.c` 仍将 `/proc/sys/kernel/random/boot_id` 前 16 个 hex 当作泄漏指针，因此没有修复本项目已确认的 `SLIDER2_BAD` 假泄漏。上游 release 也没有 violin 资产；其它机型 `.so` 不得直接测试 Violin。
- 下一步保持现有 Violin target，不在线替换；先找同 build 的 IKCONFIG+BTF+kallsyms kernel blob，或离线移植 generator 的结构校验逻辑，再验证 `SLIDE_RANDOM_BOOT_ID_DATA` 的地址域和 readback。

### 17.71 7sp screenshot functional evidence (2026-07-23)

- 用户提供截图已保存为 `analysis_outputs/7sp-local-run-evidence-20260723/evidence.jpg`；截图明确显示 `p.so` 一次 permissive-only（`getenforce -> Permissive`、`enforcing=0`）和 `r.so` 一次 direct-root（`got_root=1`、`uid=0/euid=0`、root proof 内容为 `root`、属主 `root:root`）。
- 本地附件 `E:\ZEOON3\Downloads\7sp_permissive和root.zip` 的 hash 已复核：`p.so` 83632 bytes `edd44e0c17781f0d63935dc1938b81fdcdc981f7221392117effb54e26e6cc81`；`r.so` 86464 bytes `ed07f6901eacd13577e77f09a7eebce5609e62b5b602bbefa10d09fdd4ca152e`；`r2.so` 86664 bytes `f4ddca29b1b86c6d119ecdf1d10b4337842739479c50e4c2e19d39808631af76`。
- 证据仍缺 device fingerprint、boot_id、run id、artifact SHA/source commit 和完整原始日志；因此可升级为“一次 p.so permissive + 一次 r.so root 的功能证据”，不能升级为三个文件均可复现或当前 Violin build 的 provenance proof。截图没有 `r2.so` 证据。
- 下次复现优先只运行 hash 绑定的 `r.so`，在日志首行记录 filename/size/SHA256/device fingerprint/boot_id/source manifest，并保存 root proof 文件 hash；不要把 p.so permissive 当 root stage，也不要优先运行未绑定的 r2.so。详细报告见 `analysis_outputs/7sp-local-run-evidence-20260723/report.md`。

### 17.72 XBL/DTB mem-label profile audit（2026-07-23）

- 用户提出的 Qualcomm 启动链方法在原理上成立：扫描 `xbl_config` 中全部 `FDT_MAGIC`，解析 FDT token 和父节点 `#address-cells/#size-cells`，在 `/memorymap/` 下提取唯一 `mem-label=NOMAP` 与 `mem-label=Kernel`；`p0_phys_offset = NOMAP.base & -0x40000000`，`p0_kernel_phys_load = Kernel.base`。上游 popsicle 的 `generate_target.py` 已实现完整 header/边界/token/对齐/冲突校验，并把这两个值接入 target profile；其 CLI 要求 `--boot` 与 `--xbl-config` 两个普通文件，不能把 `dtbo.img` 直接当作 xbl_config。
- 已对 Dijun 工程包（9.268 GB，SHA256 `13fe90d0e25ced73424f3281626f0f570a7d8a9e39e75e363ba0685019ba1c40`）离线扫描归档中命名为 `dtbo.img`、`sec_dtb.img`、`sec_uefi.img`、`sec_xloader.img`、`sec_xloader_usb.img` 的文件。`dtbo.img` 含 8 个可解析 DTB，但五个文件均没有 `NOMAP`/`Kernel`/`mem-label` 字符串；归档目录也没有名为 `xbl_config` 的分区镜像。当前只能判定“候选文件中未找到目标节点”，不能判定启动链中不存在嵌入式 xbl_config；后续应从 GPT/分区表或设备实际 `xbl_config` dump 定位输入。
- 扫描产物与每个文件 hash 在 `analysis_outputs/dijun-xbl-dtb-scan-20260723/{manifest.json,report.md}`。使用的是 popsicle parser（source SHA256 `61322dda51a4831e133f4b004fc64269ef5fefe71e49deda6f0bf577567a6423`），未运行 payload。
- `Dere3046/xbl-dtb` 适合初筛/列出节点，但其轻量解析器不能替代严格 profile 生成器；使用前必须复核 `reg` cell 数、FDT block bounds、节点闭合、唯一 pair、4K/1GiB 对齐和 `Kernel.size >= boot Image size`。XBL 只解决物理 profile 输入，不会修复当前 `SLIDER2_BAD` 假泄漏或证明 Violin root。

### 17.73 Violin p.so browser-stage failure（2026-07-23）

- 设备已连接：serial `03035440C1781540`，fingerprint `Xiaomi/violin/violin:16/BP2A.250605.031.A3/OS3.0.303.0.WOTCNXM:user/release-keys`，Firefox `151.0`，当前 `boot_id=b27dcce4-4ba1-413f-a8ff-d9b1ab9fe14a`，SELinux 为 `Enforcing`。
- 实时 Pages `p.so` 已下载复核为 83632 bytes，SHA256 `edd44e0c17781f0d63935dc1938b81fdcdc981f7221392117effb54e26e6cc81`，与附件一致。
- 用户日志的三个 iframe 尝试均得到 `typedWord=0x7ff8000000000000`、`carrierWord=0x7ff8000000000000`。该值是 IEEE-754 quiet NaN，不是用户态指针；它在浏览器页的 `isLikelyUserPtr()` 检查前就已失败，故没有 `AAW/AAR/ADDROF/RW64/MPROTECT` 或 native `preload` marker。
- 判定为 `JS_PRIMITIVE_FAIL_BEFORE_AAW`，不是内核 slide/fops/root 失败；本轮没有执行到 `p.so` native 阶段。不要继续原样重试，也不要把这次日志写成 Permissive/root 证据。
- ADB shell 只能读取 property/boot_id；`/proc/cmdline`、`/proc/iomem`、`xloader_a`、`uefi_a` 均拒绝读取，且没有 `xbl_config` by-name 项。完整 tuple 与报告见 `analysis_outputs/violin-p-js-failure-20260723/`。
- 最小下一步是先加一个不进入 native 的 JS gate probe，记录精确失败码、`typeof`、NaN bit pattern、Firefox build 与 iframe 状态；只有四个泄漏值都成为 canonical user pointers 后，才恢复 native payload 测试。

### 17.74 In-place cred patch isolated candidate（2026-07-23）

- 本轮只做离线隔离构建和静态检查；没有设备推送、Pages 发布或 payload 运行。17.73 的 `JS_PRIMITIVE_FAIL_BEFORE_AAW` 门禁仍然有效。
- 附件 `r.so` 的反汇编立即数绑定了 `KIMAGE_TEXT_BASE=0xffffffc080000000`：`PER_CPU_OFFSET=0xffffffc0820cb658`、`ENTRY_TASK=0xffffffc082096328`、`INIT_CRED=0xffffffc0820f0548`。旧 Violin target 中的 `0xffffffc008000000` 与该预编译 artifact 不一致；不能用旧 base 判断新 build 与 r.so 的运行等价。
- 在 `session-20260723-cred-patch/build-so/source/` 的 direct Linuxoid 隔离副本中实现 in-place patch：shape-0 读两个 cred 指针，只写 pointed cred 对象的 `+8,+16,+24,+32` 零 qword、`+40` 零 securebits、`+48,+56,+64,+72,+80` CAP_FULL；不写 pointer slots、`cred+128 security`、kernel `selinux_enforcing`，不做 policy reload。
- 候选 `inplace-preload.so`：89800 bytes，SHA256 `31997ea1ff19ce6b831cbf0f4c73a041a5458e9a5ead080b238a09b3e1185920`。AArch64 DYN 静态检查通过；候选不含 `/sys/fs/selinux/load` 和已删除的 policy-reload/followup helper。未修改同 base baseline 为 88528 bytes，SHA256 `72fddecfa550b4e34450cdfdfc2eff4a7f56e2b866ef720cd4e66d17fbb4cce2`。
- 该候选仍是 build-only artifact，不能升级为 root 或保留 shell SELinux context 的 runtime proof。详情：`session-20260723-cred-patch/build-so/BUILD-MANIFEST.md`、`03-dev-log.md:3273-3285`。

### 17.75 当前设备黑屏/SELinux 运行态与 cred-only 候选（2026-07-23）

- 本轮已获用户授权在线推送。`r1p.so` 已推送到 `/data/local/tmp/r1p.so` 并核对为 86464 bytes、SHA256 `DE94AE077660A7C926A7B22B5754C6AA592ABAE7FBE83E17E98444AE1A03A1AB`；`/data/local/tmp/dump` 已清空并替换为 0 字节 `000` 权限 guard，当前约 111122576 KiB 可用。
- 运行 r1p 后设备进入异常态：`boot_id=40b8bc02-80ff-ffff-888b-3f0280ffffff`、`getenforce=Permissive`、shell `context=?`；`service list` 无服务，`SurfaceFlinger` 不存在，黑屏是 framework/内核运行态损坏，不是普通屏幕唤醒问题。当前 `sys.boot_completed=1` 不可信；需要先通过实体/fastboot/recovery 重启恢复干净 boot，暂不重复运行旧 r1p。
- 反汇编证据：r1p 文件偏移 `0xb8f8`（VA `0xf8f8`）调用 direct write，将 `SELINUX_ENFORCING`（`0xffffffc082315f68`）写为 0。已生成 `session-20260723-cred-patch\r1p-cred-only.so`，只将该调用改为 `mov w0,wzr`，同时保留 `zump`/`zzzz` 两处防护；SHA256 `3F59E5D825D3145E66E95B95E9294606CD02225454DD4B717554F3FEA9A5E02B`，设备路径 `/data/local/tmp/r1p-cred-only.so`。
- 该 binary patch 只证明“删除 SELinux 写入”的静态差异和在线 hash，尚未证明 Enforcing 下 root/framework 双成功；已知 init_cred 整指针路径在不做 selinux_zero 时可能卡住。后续应恢复 clean boot 后先按 hash 运行一次最小命令；若 root 不成立，回到 `build-so` 的 in-place cred/pselect 修复，不再扩大 SELinux 改动。

### 17.76 Cred-only safe run 结果（2026-07-23）

- clean boot 上运行 `/data/local/tmp/r1p-cred-only-safe.so`（86464 bytes，SHA256 `F5AF873B3758A6156F28B66384A166C97E080473821CE958C30EB1EFE4B1CCFD`）后，native 输出确认 `direct pre-cred selinux preserved enforcing=1`，并进入 `task->real_cred`/`task->cred` 整指针写入；最终 `adb_exit=255`，无 root proof。
- 运行后 `getenforce=Enforcing`、`service list=439`、`SurfaceFlinger` 存在、Launcher 获得焦点；主动重启后最终 clean boot `boot_id=50c73656-3757-48a2-aaca-87475ba345a0`、`getenforce=Enforcing`、`service list=438`，63% used、约 189507496 KiB 可用。故 SELinux/黑屏链路已规避，但 root 阶段未成功。
- 下一步基线固定为 `build-so` in-place cred/pselect 修复；不要再运行会替换整个 `task->cred` 指针的 r1p/r1p-cred-only 变体。

### 17.77 In-place candidate CPU-mask run 结果（2026-07-23）

- 当前 `build-so/source` 已恢复为按 caller 的 allowed/online mask 选择 consumer CPU；以 `taskset 3fc` 运行时选中 `direct_cpu=9`、`consumer_cpu=2`。候选 `/data/local/tmp/inplace-preload-cpu2.so` 为 87296 bytes，SHA256 `82ED208C88157A49031CC26C3520B1C188C922EFE4AF5B94275005E0AD2921C6`。
- 输出止于 `slide consumer before sched ... alive_ret=0`，没有 `sched` 返回、pselect return、cred 或 root proof，设备随后重启。该失败发生在 cred/SELinux 之前，不是 SELinux 黑屏证据。
- 恢复后 clean boot 为 `boot_id=61077774-2417-476d-8a66-1cb98ed4e7c8`、`getenforce=Enforcing`、`sys.boot_completed=1`、service count=438。报告：`analysis_outputs/7sp-inplace-cpu2-run-20260723/report.md`。下一步只修 pselect/scheduler route；SELinux/dump 保护不得回退。

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
