# 戒指 v20 攻击性 QA 规则

> 这不是开发说明，也不是功能验收清单。目标是主动让应用失败，找出崩溃、假成功、卡死、状态锁死、数据耗尽和用户误操作路径。QA 发现问题后应先保留证据，不得用“看起来成功”替代复现结论。

## 1. 范围与判定方式

目标包：`com.zeoon3.jinghu`  
当前版本：`1.2.1-v20` / versionCode `6`  
代码根：`E:\workspace\projects\xiaomi-root\session-20260723-cred-patch\jinghu-shizuku-app`

攻击面：

- Activity 生命周期、旋转、后台、进程被回收、重复点击。
- Shizuku 未安装、未激活、未授权、权限撤销、UserService 慢启动和 Binder 死亡。
- 系统文档提供器返回空文件、错误 MIME、超大文件、阻塞流、异常 `InputStream` 和畸形 ELF。
- 自定义 SO 输出刷屏、输出超长单行、异常退出、fork 子进程、修改远端文件。
- 低磁盘、低内存、无网络、DNS 失败、framework 不完整、设备重启。
- Manager 复选框、切换内置/自定义 SO、过期预检状态等用户误操作。

状态标签：

- `STATIC_CONFIRMED`：源码链路已证明，尚未在当前设备实际触发。
- `RUNTIME_CONFIRMED`：设备或测试夹具已触发并保存 logcat/应用日志。
- `RUNTIME_PENDING`：当前设备或 Shizuku 状态不满足，禁止写成“已通过”。

严重级别：

- **P0**：用户看到成功但实际失败、执行了未确认的 payload、完整性被绕过。
- **P1**：崩溃、OOM、ANR、永久卡死、同一启动周期不可恢复、后台中断后状态错误。
- **P2**：可恢复但会误导用户、安装错组件、日志不可用、无处理器时点击崩溃。
- **P3**：纯视觉或低影响体验问题。

## 2. 当前已发现的攻击点

### QA-001 — P0：任意输出可伪造 `RUN_FINISHED=1`

状态：`STATIC_CONFIRMED`  
证据：

- `app/src/main/java/com/zeoon3/jinghu/JinghuViewModel.java:239-245` 用
  `result.contains("RUN_FINISHED=1")` 判定成功。
- `app/src/main/java/com/zeoon3/jinghu/JinghuRunner.java:64-66` 的 `contains()` 只是对完整输出做字符串包含判断，不是最后一条机器行解析。
- `app/src/main/java/com/zeoon3/jinghu/JinghuRunner.java:311-317` 才输出真正的最终 `RUN_FINISHED=0/1`。

攻击步骤：

1. 使用测试夹具 SO 在 stdout 写入一行 `RUN_FINISHED=1`。
2. 让最终门禁输出 `RUN_FINISHED=0` 或让 payload 非零退出。
3. 点击执行，观察 UI、run log 和 `RUN_STATUS`。

失败判定：只要应用把该次运行标为成功，或日志出现成功文案，即失败。必须只接受带随机 nonce 的最终记录，并校验唯一、最后、完整的状态行。

### QA-002 — P0：网络和 framework 检查只打印，不参与成功条件

状态：`STATIC_CONFIRMED`  
证据：`app/src/main/java/com/zeoon3/jinghu/JinghuRunner.java:284-310` 只执行并打印 `SERVICES`、`SURFACEFLINGER`、IP ping、DNS ping、`BOOT_ID_AFTER`；`311-317` 的最终条件只检查 `PAYLOAD_EXIT`、Enforcing、sysfs enforce、KernelSU 和 `uid=0`。

攻击步骤：

1. 测试夹具让 IP ping、DNS ping 失败，或让 service 数量为 0、SurfaceFlinger 不存在。
2. 同时让现有 root/SELinux 条件满足。
3. 检查是否仍出现 `RUN_FINISHED=1` 和成功文案。

失败判定：任何一个 README 所承诺的网络或 framework 健康项失败时，必须是 `RUN_FINISHED=0`。当前 README 第 12 行声称“全部通过才输出”，与源码门禁不一致。

### QA-003 — P1：marker 在 payload 启动前创建，失败后锁死整次 boot

状态：`STATIC_CONFIRMED`  
证据：`JinghuRunner.java:279-286` 先 `touch "$MARKER"`，之后才执行 `LD_PRELOAD=... /system/bin/true`。`DeviceSnapshot.canRun()` 会拒绝 `MARKER=1`。

攻击步骤：

1. 运行到 `MARKER_CREATED=1` 后立即 force-stop App、杀掉 UserService、让 shell 超时，或让测试 SO 崩溃。
2. 不重启设备，重新打开 App 并预检。
3. 尝试重新执行同一个 payload。

失败判定：如果 UI 没有明确显示“本 boot 已消耗，不可重试，需重启/人工恢复”，或者失败前置状态没有留在日志中，属于 P1。不能把“无条件禁止重试”伪装成普通门禁失败。

### QA-004 — P1：180 秒任务没有前台执行保障，后台/进程回收会中断

状态：`STATIC_CONFIRMED`  
证据：`JinghuViewModel.java:194-253` 把运行放入普通 `Executor`；`JinghuRunner.java:43` 的运行超时为 180 秒；工程没有前台服务或 WorkManager 任务承载 payload。

攻击步骤：

1. 启动一个持续 30-180 秒的测试夹具。
2. 按 Home、锁屏、从最近任务划掉 App、执行 `am force-stop`，分别测试。
3. 重新打开 App，检查 active journal、run log、marker 和按钮状态。

失败判定：不能出现 UI 显示空闲但后台仍执行、journal 未标记中断、marker 已存在却没有可解释状态，或 App 回来后永久 busy。进程死亡和设备重启必须分别可诊断。

### QA-005 — P1：UserService 绑定超时会污染客户端状态

状态：`STATIC_CONFIRMED`  
证据：`ShizukuUserServiceClient.java:153-190`。`latch.await(12s)` 超时直接抛出异常，但没有把 `bindingRequested` 重置为 `false`；之后 `requireService()` 会重复等待同一个未完成 latch。

攻击步骤：

1. 让 UserService 启动时间超过 12 秒，或在 bind 后杀掉 Binder。
2. 等第一次操作报 `connection timed out`。
3. 在同一 App 进程内连续点“刷新”“安装 Manager”“更换 SO”或重试预检。

失败判定：后续每次都固定等待约 12 秒，直到强杀 App 才恢复，即失败。超时必须清理绑定状态并允许下一次重新 bind。

### QA-006 — P1：自定义 SO 导入没有应用侧大小上限，且 ELF 校验过弱

状态：`STATIC_CONFIRMED`  
证据：

- `JinghuRunner.java:113-180` 持续读取 `InputStream` 到私有文件，没有大小上限、剩余空间预检、取消和进度。
- `JinghuRunner.java:391-399` 只验证 ELF magic、ELF64、小端和 `EM_AARCH64=183`，不验证 `ET_DYN`、program header、loadable segment 或可加载 SO 结构。
- 文件选择器在 `MainActivity.java:235-241` 接受 `*/*`。
- UserService 虽有 64 MiB 远端上限（`JinghuUserService.java:28,64-118`），但这不能阻止本地导入先耗尽空间。

攻击步骤：

1. 选择 64 MiB 以上的 AArch64 文件、稀疏/不断增长的 Provider 文件、错误 MIME 文件。
2. 选择返回阻塞 `read()`、重复返回 0、截断 ELF、AArch64 ET_EXEC 或伪造头部的测试 Provider。
3. 观察 UI 是否长时间无响应、私有目录是否持续增长、是否能取消并恢复到原 SO。

失败判定：导入过程无上限、无取消、读阻塞后不能返回错误，或不合法的 ET_EXEC 被当成可运行 SO，均为 P1。

### QA-007 — P1：输出可导致 OOM、ANR、管道阻塞和 App 杀进程

状态：`STATIC_CONFIRMED`  
证据：

- `JinghuUserService.java:120-159` 对远端 stdout 没有字节上限。
- `ShizukuUserServiceClient.java:91-111,205-224` 把所有行放入无上限 `List<String>`；`BufferedReader.readLine()` 对无换行超长行也无上限。
- `JinghuViewModel.java:359-382` 虽将 UI 文本截到 24000 字符，但每行仍写入磁盘、复制字符串并触发一次 LiveData 发布。

攻击步骤：

1. 测试 SO 连续输出 100 MB、多行高频输出，或输出一条 50 MB 且不换行的行。
2. 持续 30 秒后观察内存、帧率、logcat、Binder/pipe 是否阻塞。
3. 在刷屏中杀掉 App，再检查 marker 和日志是否可恢复。

失败判定：出现 OOM、ANR、主线程明显卡顿、UserService 无法退出、日志只写了一半但 UI 报成功，均为 P1。必须同时限制字节数、行数、单行长度、日志空间和 UI 更新频率。

### QA-008 — P1：复制后到执行前存在远端 SO TOCTOU

状态：`STATIC_CONFIRMED`  
证据：`JinghuViewModel.java:211-220` 只在复制后检查 UserService 回传的 hash；`JinghuRunner.java:279-281` 执行前只打印 `sha256sum`，没有与期望 hash 比较。

攻击步骤：

1. 用 UserService 测试替身在 copy 成功后、`LD_PRELOAD` 前替换固定远端路径文件。
2. 让替换文件仍是 AArch64 SO，但 hash 不同。
3. 观察 App 是否继续执行并记录成功。

失败判定：执行前没有再次对“期望 hash == 当前远端 hash”做硬校验，即失败。不能只把 hash 写进日志当成完整性保护。

### QA-009 — P2：运行日志无轮转、无保留上限，低磁盘下会失去证据

状态：`STATIC_CONFIRMED`  
证据：`RunLogStore.java:66-101,199-208` 对日志持续 append；`130-152` 的 `readLatestLogs(32000)` 只限制显示，不限制磁盘；没有单文件、总目录和保留天数上限。

攻击步骤：

1. 重复执行导入失败、预检、UI 事件和高频输出夹具数百次。
2. 将应用私有空间压到低磁盘，再点击“已保存日志”。
3. 检查写失败是否被静默吞掉、active journal 是否仍可恢复。

失败判定：日志可以无限增长、写满后只显示“成功”、或历史日志因低磁盘无法保存，均为 P2；QA 必须记录日志目录大小和写失败证据。

### QA-010 — P2：Manager 检查与实际安装目标不可信，且安装选项没有进入最终确认

状态：`STATIC_CONFIRMED`  
证据：

- `JinghuRunner.java:206-222` 输出的 `MANAGER_PACKAGE` 实际查询的是 `com.zeoon3.jinghu`，不是 KernelSU Manager 包。
- `JinghuRunner.java:242-245` 只执行 `pm install -r`；`JinghuViewModel.java:167-192,300-320` 没有安装后包名、版本和签名的后置核验。
- `MainActivity.java:263-280` 的确认弹窗只展示 payload、hash、kernel，不展示 `installManagerCheck.isChecked()` 的“将安装/不安装 Manager”结果。

攻击步骤：

1. 保持“安装 Manager”默认勾选，直接点击执行并确认；再取消勾选重复测试。
2. 在设备没有预装 Manager、已有其他版本或远端文件被替换的情况下分别测试。
3. 查看确认弹窗、安装后包信息和日志。

失败判定：用户无法在最后一步看到安装状态，或 exit code 为 0 但无法证明目标包/版本/签名正确，均为 P2。

### QA-011 — P2：UserService 超时不会可靠清理子进程和读写线程

状态：`STATIC_CONFIRMED`  
证据：`JinghuUserService.java:120-159` 只销毁 shell 进程；没有进程组清理；读线程最多 join 5 秒后 interrupt。`ShizukuUserServiceClient.java:226-257` 对阻塞 Provider 线程也只是 interrupt。

攻击步骤：

1. 测试 SO fork 一个长驻子进程并保持 stdout/FD 打开。
2. 让主 shell 超时或断开 Binder。
3. 检查残留进程、FD、线程和下一次运行是否受影响。

失败判定：主 shell 已结束但子进程/线程继续存活，或下一次操作被旧管道拖住，即失败。

### QA-012 — P2：预检失败仍被解析成普通快照，诊断状态不诚实

状态：`STATIC_CONFIRMED`  
证据：`JinghuViewModel.java:151-165` 无论 `ShellResult.exitCode`、超时与否都执行 `DeviceSnapshot.from(result.text())`；`DeviceSnapshot.java:28-37` 对重复 key 采用后者覆盖。

攻击步骤：

1. 让预检命令超时、只返回半截字段、返回重复 `KERNEL/ENFORCE/MARKER`。
2. 观察 UI 是否显示“未知/不满足”还是仍像一次正常预检。
3. 检查运行按钮是否能因半截或重复输出被错误启用。

失败判定：预检失败没有独立的“预检失败”状态，或重复门禁字段未拒绝，均为 P2。运行门禁必须绑定一次完整、成功、未过期的预检快照。

### QA-013 — P2：没有可用分享处理器时，分享日志可能直接崩溃

状态：`RUNTIME_PENDING`  
证据：`MainActivity.java:294-299` 直接 `startActivity(Intent.createChooser(...))`，没有捕获 `ActivityNotFoundException`。

攻击步骤：

1. 在没有邮件/分享目标的模拟器或精简系统中打开“已保存日志”。
2. 点击“分享”。
3. 读取 logcat 是否出现 `FATAL EXCEPTION`。

失败判定：任何 `ActivityNotFoundException` 或对话框消失后 App 退出，均为 P2；没有分享目标时应回退到复制文本或明确提示。

## 3. 用户误操作攻击矩阵

以下操作都必须在中文 UI 下逐项执行，不能用“用户应该知道”作为通过理由：

| 操作 | 必须看到的保护 | 失败信号 |
|---|---|---|
| Shizuku 未安装/未激活时点授权 | 跳官方激活页或明确安装提示，返回后状态刷新 | 按钮无反应、误进入 payload、回到 App 仍显示旧状态 |
| Shizuku 授权后立即点刷新/运行 | 只允许一次任务，按钮 busy 状态清楚 | 重复 bind、重复 shell、两个 run journal |
| “更换 SO”选普通文件/超大文件/取消选择 | 明确错误、可取消、内置 SO 不丢失 | 卡住、覆盖旧 SO、私有空间持续增长 |
| 自定义 SO 与内置 v20 来回切换 | 当前名称、hash、模式和执行按钮同步 | UI 显示 v20 但执行旧 selected-payload |
| Manager 勾选/取消后点击运行 | 确认弹窗再次显示安装状态 | 未提醒即安装或用户以为不会安装 |
| 预检过程中旋转、Home、锁屏、划掉任务 | 任务状态、journal、恢复文案一致 | 永久 busy、marker 消耗但显示未执行 |
| 设备重启后打开 App | 运行日志出现 `INTERRUPTED` / boot recovery，并说明能否重试 | 日志丢失、显示成功、按钮状态与 marker 矛盾 |
| 无网络、DNS 失败、framework 不完整 | 成功条件明确失败，不接受只打印探测结果 | 日志写成功、UI 写成功 |
| 打开历史日志并分享 | 低磁盘、超长单行和无分享器都不崩 | OOM、ANR、`ActivityNotFoundException` |

## 4. 自动化/夹具要求

常规 QA 不直接运行真实 v20 payload；用可控的 UserService/SO 夹具验证状态机和资源上限。夹具至少覆盖：

1. 正常退出、非零退出、超时、提前断 Binder、重启前后半截输出。
2. stdout：0 行、1 行、10 万行、100 MB、50 MB 无换行单行、包含伪造 `RUN_FINISHED=1`。
3. Provider：空流、64 MiB 边界、超过边界、阻塞 read、异常 read、重复返回 0、错误 ELF、ET_EXEC、错误架构。
4. 远端：copy 后替换文件、权限错误、低磁盘、rename 失败、残留 `.part-*`。
5. 生命周期：旋转、后台、force-stop、进程被杀、Binder death、设备重启。

每个 case 必须保存：

- 时间、设备 serial、App versionCode/versionName、当前 boot ID。
- Shizuku 状态、payload 名称和 SHA-256、是否勾选 Manager。
- App 的 `files/run-logs/`、`app-events.log`、关键 `logcat` 和最终 UI 状态。
- 失败发生前最后一条阶段标记；不能只保存最后一句“失败”。

## 5. 成功门禁（没有全部满足就判失败）

- `RUN_FINISHED=1` 必须是唯一、最后、带 nonce 的最终状态行；不能用 substring 判断。
- 网络、DNS、framework/SurfaceFlinger、前后 boot ID、payload 退出码、SELinux、KernelSU、root 身份必须全部有明确的 `*_OK=1` 证据并进入硬门禁。
- marker 的创建、payload 启动和完成状态必须是可恢复状态机；进程死亡、超时和重启不能制造不可解释的永久锁死。
- 所有输入、输出、单行、线程、进程和日志目录都必须有上限；超限要可见失败、可取消、可恢复。
- 每次 bind 超时后下一次操作必须能重新 bind；Binder death 不能污染后续操作。
- 运行前后都要对远端 SO 做期望 SHA-256 校验，且安装 Manager 后验证包名、版本和签名。
- 最终确认必须重复显示 payload 模式、hash、精确 kernel、marker 规则和 Manager 安装状态。
- P0 为 0；P1 未关闭或没有明确接受记录时不得发布；P2 至少有可见错误和恢复路径。

## 6. 本轮证据基线

已执行：

- `:app:testDebugUnitTest`：5/5 通过；现有唯一测试文件为 `DeviceSnapshotTest.java`，覆盖的是快照门禁，不覆盖 UserService、输入、输出、生命周期、日志和 Activity。
- `:app:lintDebug`：`No issues found.`
- 设备只读启动冒烟：serial `0401481180981540`、`sys.boot_completed=1`、`Enforcing`、精确 v20 内核；已启动 `com.zeoon3.jinghu/.MainActivity`，未发现本轮新增 `FATAL EXCEPTION`。
- 本轮没有点击执行按钮，也没有运行真实 v20 payload；上面列出的 P0/P1 运行项因此仍按源码证据标记，不得写成“已在真机复现”。

结论：构建、Lint 和 5 个快照单测通过，只能证明编译与基础门禁解析没有失败；不能覆盖本文件列出的高风险攻击面。
