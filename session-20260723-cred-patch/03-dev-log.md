# 技术日志：Xiaomi Pad 7S Pro (violin) KernelSU Root

> 日期：2026-07-23 ~ 2026-07-28
> 设备：Xiaomi Pad 7S Pro (violin / 25053RP5CC)
> 内核：6.6.77-android15-8-g5770c661275f-abogki443185593-4k
> 固件：HyperOS OS3.0.303.0.WOTCNXM (Android 16)

---

## 一、目标

在 Xiaomi Pad 7S Pro 上实现 root，要求：
- SELinux Enforcing 下持久 root
- Framework（zygote/system_server）正常运行
- 应用可正常打开
- 不重启设备

---

## 二、exploit 原理

基于 CVE-2026-43499 的 pselect write 原语：

1. **KASLR 泄漏**：通过 `sched_blocked_reason` trace event + boot_id sidecar 泄漏内核绝对地址
2. **pselect 写入**：利用 `rt_mutex_adjust_prio_chain` 的 PI chain walk，在 fd_set overlay 中伪造 `rt_mutex_waiter` 结构体，通过 `rb_insert_color`/`rb_erase` 实现任意 8 字节内核内存写入
3. **kCFI 绕过**：pselect 通过 rb-tree 数据结构操作写入，不走间接函数调用，天然绕过 kCFI

---

## 三、已验证可用方案

### 最终方案：preload_jinghu_v13.so + KernelSU

```bash
# 一键提权 + 加载 KernelSU ko
LD_PRELOAD=/data/local/tmp/preload_jinghu.so /system/bin/true

# 恢复 Enforcing
su -c 'echo 1 > /sys/fs/selinux/enforce'

# 随时 root
su -c id
# → uid=0(root) gid=0(root) context=u:r:ksu:s0
```

**验证结果：**
| 项目 | 状态 |
|------|------|
| SELinux | Enforcing ✅ |
| Root | `uid=0 context=u:r:ksu:s0` ✅ |
| Framework | 437-439 services ✅ |
| Settings | 79ms ✅ |
| Camera | 140ms ✅ |
| Contacts | 274ms ✅ |
| KernelSU 模块 | `kernelsu 176128 1` ✅ |
| 存储 | 不受影响 ✅ |

### 之前的可用方案：preload_archive.so + su daemon（Permissive）

```bash
# 一键 root（Permissive）
LD_PRELOAD=/data/local/tmp/preload_archive.so sh -c '
  setsid /data/local/tmp/su --daemon </dev/null >/dev/null 2>&1 &
'

# 持久 root
su -c id
# → uid=0(root) context=u:r:kernel:s0
```

**限制**：SELinux Permissive（policy 完整但非 Enforcing）。

---

## 四、根因分析

### 4.1 selinux_state 被 8 字节 write 溢出破坏

`selinux_enforcing` 实际是 `selinux_state` 结构体的 `enforcing` 字段（bool, 1 字节）。pselect write64 写 8 字节到 `selinux_state+0`，覆盖了：

```
+0: bool enforcing      ← 写入点（1字节有效）
+1: bool initialized    ← 被清零！
+2: bool policycap[0]   ← 被清零！
+3: bool policycap[1]   ← 被清零！
+4: bool policycap[2]   ← 被清零！
+5: bool android_netlink ← 被清零！
```

`initialized=0` 导致 SELinux 子系统认为未初始化，`policycap` 清零导致所有策略能力失效。

### 4.2 kCFI 阻止 fops hijack

```
CONFIG_CFI_CLANG=y
CONFIG_CFI_PERMISSIVE is not set
```

kCFI 强制执行，阻止 `file_operations->write_iter` 间接调用替换。pipe-based root_stage（需要 fops hijack）在 violin 上无法打通。

### 4.3 rebuild SO 的 pselect 不工作

pselect 机制对二进制布局极度敏感。原始 preload.so（85KB）工作正常，任何重建（即使 224 字节差异）都会破坏 pselect 的栈帧对齐，导致写入超时。

### 4.4 kernel:s0 context 在 Enforcing 下的限制

exploit 的 init_cred 替换给进程 `kernel:s0` context。在 Enforcing 下：
- su daemon 的 socket 连接被阻止
- 文件操作被 SELinux 限制
- 进程无法正常 exec 用户态程序

KernelSU 的 `ksu:s0` context 解决了这个问题。

---

## 五、踩坑记录

| # | 问题 | 根因 | 教训 |
|---|------|------|------|
| 1 | NOP cbz 指令导致崩溃 | ARM64 条件分支后的 cleanup 代码依赖正确控制流 | 不要 NOP 条件分支，用字符串 patch |
| 2 | PSELECT_ROUTE_NFDS=64 导致超时 | 通用 common.h 和 target 专用 common.h 不一致 | violin 必须用 320 |
| 3 | make clean 清掉 KernelSU 占位文件 | clean 目标删除 build/embed/ | 每次 clean 后重建占位文件 |
| 4 | git checkout 丢失修改 | 无 commit 的 repo 回退到 staged 版本 | 修改前先 git stash |
| 5 | insmod "Exec format error" | ko 的 ELF section 与设备内核不兼容（.hyp.*、.BTF 等） | ko 必须用相同内核版本编译 |
| 6 | vermagic 不匹配 | ko 给 6.6.127 编译，设备是 6.6.77 | vermagic 必须完全匹配 |
| 7 | __versions CRC 不匹配 | ko 缺少 CRC 或 CRC 值错误 | 需要 Module.symvers |
| 8 | ksud late-load 崩溃 | kernelsu.ko 版本不兼容 | 用匹配的 ko |
| 9 | WSL 编译内核卡死 | WSL 文件系统 IO 慢 + make 进程爆炸 | 用 Linux 原生环境或 Docker |
| 10 | su daemon 被 Enforcing 杀死 | kernel:s0 context 无效 | 需要 KernelSU 的 ksu:s0 context |

---

## 六、关键文件

| 文件 | 说明 |
|------|------|
| `preload_jinghu_v13.so` (6.9MB) | **最终方案**：一键 root + KernelSU ko 加载 |
| `preload_archive.so` (84KB) | PoC 预编译版，无 dump/policy_reload/reboot |
| `preload_patched.so` (85KB) | 用户下载版 + 字符串 patch |
| `kernelsu_mi_ready.ko` (250KB) | jinghu 设备的 KernelSU ko（vermagic 不匹配 violin） |
| `kernelsu_jinghu_32525_v13.ko` (3.4MB) | **最终 ko**：匹配 6.6.77 内核，__versions 完整 |
| `ksud_32525_v13` (3.3MB) | KernelSU daemon |
| `su_real` (15KB) | 嵌入式 su daemon（Permissive 下使用） |
| `ksu.sh` | 一键提权脚本 |
| `force_insmod2` | 强制 insmod 工具（finit_module + IGNORE_VERMAGIC） |

---

## 七、exploit 输出解读

```
[+] slide-kaslr-ok              ← KASLR 泄漏成功
[+] direct-r64-oracle           ← shape-0 read 验证通过
[+] direct-w64[N]               ← shape-1 write 成功
[+] direct-entry                ← entry_task 泄漏成功
[+] direct-step install_real_cred    ← 写 init_cred 到 real_cred
[+] direct-step install_cred_then_selinux_zero ← 写 init_cred 到 cred + selinux_zero
[+] direct credential result uid=0   ← root 成功
[+] embedded su daemon ready    ← su daemon 启动
[+] direct-root-summary         ← 最终结果
[+] ksu-auto ko=1 ksud=1 loaded=1 ← KernelSU 加载成功（jinghu 版）
```

---

## 八、下一步

1. **自动化**：已完成基于 Shizuku 的一键 App，详见第九节
2. **Enforcing + root 稳定性**：验证长期运行下 KernelSU 模块的稳定性
3. **LSPosed 集成**：在 Enforcing + root 下测试 Xposed 模块
4. **OTA 更新防护**：已禁用自动更新，防止内核变更导致 root 丢失

---

## 九、2026-07-28 Shizuku App v13 自动化

已在 `session-20260723-cred-patch/jinghu-shizuku-app` 完成独立 Android App：

- applicationId：`com.zeoon3.jinghu`；versionName：`1.0.0-v13`。
- 所有设备命令均通过 Shizuku shell 执行，不调用宿主机 adb，也不开放自由命令输入。
- 内置并校验 `preload_jinghu_v13.so`，SHA256：`4c202c6545e42afbc287ec392de20c01b35c3595ed9db0ac59d148394e839e8b`；可选内置 KernelSU Manager 32525 APK。
- App 门禁固定要求精确 kernel `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`、SELinux `Enforcing`、`boot_completed=1`、当前 boot 未执行 marker、`kernelsu` 未加载；同一 boot 的重复执行由远端 marker 再次拒绝。
- 修复 Shizuku `ShizukuRemoteProcess` 的等待兼容性：使用其 `waitForTimeout`，并在 `exitValue()` 尚不可用时回退到阻塞等待。

### 实机验收

- 设备：serial `0401481180981540`，product `violin`，model `25053RP5CC`。
- 已通过 Shizuku 连接和 App 授权；实机只读门禁结果：精确 kernel、`Enforcing`、`boot_completed=1`、`KernelSU module=0`、`marker=0`，App 显示“设备门禁：通过，可执行一次”，`preflight exit=0`。
- APK 已重新安装并启动验证；`assembleDebug` 和 `lintDebug` 均通过。
- 初始验收阶段没有点击“执行 v13”，没有执行 payload，也没有安装 Manager。

### 人工点击后的日志复核

- 用户随后手动点击了“执行 v13（一次）”。日志显示流程停在 payload 写入/校验阶段：`APP_ERROR=IllegalArgumentException: process hasn't exited`，随后报告远端哈希校验失败。
- 该次流程没有进入 payload：当前 boot 的 marker 仍为 `0`，设备仍为 `Enforcing`，没有形成完成标记；之后刷新门禁已读到 payload 远端哈希与交付物一致：`4c202c6545e42afbc287ec392de20c01b35c3595ed9db0ac59d148394e839e8b`。
- 根因是上一轮修复只覆盖了普通 `execute()`，`copyAsset()` 仍使用 Java `Process.waitFor(timeout, unit)`；已补齐为 Shizuku `waitForTimeout`，重新 `assembleDebug`、`lintDebug` 并安装新 APK。
- 当前新 APK SHA256：`d107e3fd2fd2b37fece003c7f8e381efb50ca70d282d8b2c3c16cee275d9e68b`。未自动重试 payload，需人工确认后再点击一次。

---

## 十、2026-07-28 KernelSU 与网络故障日志

### KSU 状态

- `/data/local/tmp/ksu_auto.log`：`ksud insmod st=0 loaded=1`、`exec self-test passed`、`module_loaded=1`。
- `/proc/modules`：`kernelsu ... Live`；`ksud debug info` 显示 version `32525`、`lkm=true`、`late_load=true`、runtime mode `late-load`。
- 因此 KernelSU 模块本身已成功加载；这不是“模块没加载”的问题。

### 网络故障证据

- Wi-Fi 仍连接在 `wlan0`，有地址 `222.16.24.148/25`、默认路由和 DNS；故障不是断 Wi-Fi 或 DHCP。
- `ping 1.1.1.1` 返回 `Connection refused`。
- `logcat/dmesg` 持续出现：`avc: denied { send } ... scontext=u:r:netd:s0 ... tcontext=u:object_r:unlabeled:s0 tclass=packet permissive=0`，同时 shell、platform_app、untrusted_app、system_app 的网络包也被拒绝。

### 根因结论

payload 日志明确记录：`direct credential result ... selinux=1->0 policy_reload=0`，之后只执行了 `SELINUX_RESTORE ... ENFORCE=Enforcing`。结合本文件第四节的结构说明，直接阶段对 `selinux_state` 做 8 字节写，除了 `enforcing` 外还破坏了 `initialized` 和策略能力字段；恢复一个字节为 Enforcing 不会恢复整个 SELinux 状态。因此网络包被标为 `unlabeled` 并被 Enforcing 拒绝，应用层统一显示“网络异常”。

结论：本次网络故障由 v13 payload 的 SELinux 状态破坏引起，不是 KernelSU `insmod` 失败，也不是 Wi-Fi 配置问题。当前 boot 不应继续重复执行；恢复设备应先重启，后续方案必须改为不破坏 `selinux_state` 的 payload。

---

## 十一、2026-07-28 v19 Enforcing + Network Complete App 封装

- 用户提供的 v19 成品 SO 已替换进 `jinghu-shizuku-app`：
  `preload_jinghu_v19_enforcing_network_complete.so`。
- v19 SO SHA-256：
  `3b46a9a3b027e2460ed9ffa3ca48344e966d87a2e36fd9f8b69859a13be1908e`；大小 `7007256` 字节。
- App 执行链已从旧版 `CVE_NO_PERMISSIVE=1` 改为 v19 交付命令：
  `LD_PRELOAD=/data/local/tmp/preload_jinghu_v19_enforcing_network_complete.so /system/bin/true`。
- boot marker 已切换为 `.jinghu-v19-<boot_id>`，避免与 v13 旧流程混用。
- 完成条件增加真实 `Enforcing`、`/sys/fs/selinux/enforce=1`、KernelSU、`su uid=0`、IP ping 和 DNS ping 校验；全部通过才输出 `RUN_FINISHED=1`。
- UI 已重做为深色验证头部、状态卡片、执行配置卡片、主执行按钮和深色日志面板。
- `assembleDebug` 与 `lintDebug` 均通过。
- APK：`jinghu-shizuku-app/app/build/outputs/apk/debug/app-debug.apk`；SHA-256：
  `7a964f3795f4405ec036d16389602779ba4adbaaaeda21b3ca124d90746f9c77`。
- 便于直接分发的副本：`jinghu-shizuku-app/jinghu-enforcing-v19-shizuku-debug.apk`，SHA-256 相同。
- 本轮构建完成，但设备在前序实验重启后暂时未重新连上 adb，因此未进行新 APK 的实机安装和 UI 截图验收。

---

## 十二、2026-07-29 aShellYou 风格 UI、持久化错误日志与可更换 SO

用户要求“像素级模仿 aShellYou 界面、自动保存出错 log、支持更换 so”，本轮在 `session-20260723-cred-patch/jinghu-shizuku-app` 完成：

- UI 从上一版深色验证面板改为 aShellYou 参考的 Material You 方向：暖白画布、顶部五个圆形快捷按钮、超大黑色标题、右侧 Root 胶囊、浅绿色圆角描边卡片、亮绿色主按钮和青色 Output 面板。
- 新增 `RunLogStore`：每次 payload 运行先写入 `active-run.properties` 和独立 `.log`，运行中的 shell 输出实时追加；成功/失败会落盘状态，App 进程重启时自动恢复未完成 journal。
- 新增 `BootReceiver`：收到 `BOOT_COMPLETED` 后检查 active journal，把重启中断记录追加为 `BOOT_RECEIVER_RECOVERY=1`、`RUN_STATUS=INTERRUPTED`，并在 Saved logs 中可查看/分享。
- 非运行阶段的 App 错误和门禁事件写入 `files/run-logs/app-events.log`，避免只显示在临时 UI 中。
- 新增 Change SO：系统文件选择器导入后校验 arm64 ELF 头和 SHA-256，保存为应用私有目录的 `selected-payload.so`；重启 App 后仍保留，可随时恢复内置 v19 SO。运行前再次计算本地 SHA，写入固定远端路径后再校验远端 SHA。
- 自定义 SO 不改变设备安全门禁：仍要求精确 kernel、Enforcing、boot_completed=1、当前 boot 未执行 marker、KernelSU 未加载；v19 内置 SO 仍使用不带旧版环境变量的固定 `LD_PRELOAD` 命令。
- `assembleDebug` 与 `lintDebug` 均通过。新 APK：
  `session-20260723-cred-patch/jinghu-shizuku-app/app/build/outputs/apk/debug/app-debug.apk`
  SHA-256：`a174da42043b38f7a1b1b46d2538feed41052a3eee00e08af27e11cff4a620d5`。
- 已静态核对 APK 内置资产：v19 SO 大小 `7007256` 字节、SHA-256 `3b46a9a3b027e2460ed9ffa3ca48344e966d87a2e36fd9f8b69859a13be1908e`；Manager 大小 `9083665` 字节、SHA-256 `1417081413bf7ab1de8e440ecbcb62685037c8f28f048f0f8b79e305b31ab916`。
- 当前 `adb devices -l` 仍无设备，因此本轮未宣称实机安装、重启广播和 UI 截图验收；剩余实机验收项是导入自定义 SO、点击失败后查看 Saved logs、重启后确认 `BOOT_RECEIVER_RECOVERY=1`。

---

## 十三、2026-07-29 Shizuku 未激活时跳转官方激活引导

- 修复授权按钮在 Shizuku 未运行时被禁用的问题；现在按钮会显示 `Activate Shizuku` 并可直接点击。
- 未激活时先尝试打开已安装 Shizuku 的官方主页/激活页；Shizuku 已激活但未授权时，仍进入原有 `Shizuku.requestPermission()` 授权流程。
- 如果设备没有安装 Shizuku 或无法解析应用入口，则自动打开官方网页引导 `https://shizuku.rikka.app/guide/setup/`，没有浏览器时显示安装提示。
- 顶部 Shizuku 快捷按钮也统一走同一套激活引导逻辑，状态回到本 App 后由 `onResume` 自动刷新。
- `assembleDebug`、`lintDebug` 通过。为便于覆盖安装，版本提升到 `1.0.1-v19` / versionCode `3`；最新 APK SHA-256：`af70fad85f937739887f8ad1a1ff771740968998b1ce43ca37c91cea2354ede4`。

---

## 十四、2026-07-29 v20、Android 规范化、“戒指”命名与莫奈取色

### v20 交付物绑定

- 用户提供 `preload_jinghu_v20_final_optimization.so`，大小 `7022496` 字节，SHA-256：
  `016477c1b9ae3cdc15f2b5b68bc51d69614aca994847cf80f2970ebdb7007463`。
- 该 SO 与 `jinghu_ksu_32525_v20_20260729.zip` 内版本一致；App 资产名、远端路径和执行命令均已切换为 v20。
- KernelSU Manager 32525 大小 `9083665` 字节，SHA-256：
  `1417081413bf7ab1de8e440ecbcb62685037c8f28f048f0f8b79e305b31ab916`。
- boot marker 更新为 `/data/local/tmp/.jinghu-v20-<boot_id>`；精确内核门禁继续固定为：
  `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`。
- 最终 APK 中只存在 v20 SO 和 Manager 两项资产，未发现 v19 资产。

### Android 架构规范化

- 工程改为 AndroidX + Material 3 XML，启用 ViewBinding，并由 `JinghuViewModel` 管理 UI 状态和后台任务。
- 移除废弃的 `Shizuku.newProcess()` 调用，新增 `IJinghuUserService.aidl`、`JinghuUserService` 和 `ShizukuUserServiceClient`，使用 Shizuku 官方 UserService 架构。
- SO 通过 `ParcelFileDescriptor` 传入 UserService；远端采用临时文件、`fsync`、SHA-256 回传和原子替换，避免 shell 管道复制大文件的不完整状态。
- 保留 `RunLogStore`、`BootReceiver` 和 `app-events.log`：运行中输出实时落盘，App/设备重启后自动把未完成任务标记为 `INTERRUPTED`。
- 支持系统文档选择器导入 arm64 ELF SO，并持久保存到应用私有目录；恢复内置 v20 不改变原有设备门禁。
- 新增 `DeviceSnapshotTest` 共 5 项，覆盖内核、SELinux、启动完成、KernelSU 和 boot marker 门禁。
- 新增 Android 工程 `.gitignore`，排除 Gradle/IDE 中间产物、本地配置和签名文件，便于该子项目后续独立版本管理。当前 codebase-memory 以外层 workspace 为 Git 根，仍会发现子项目 `build/`；这是索引器根目录行为，不影响 App 构建。

### 名称、中文和图标

- 应用展示名与主页面标题统一改为“戒指”，保持 applicationId `com.zeoon3.jinghu` 不变以支持覆盖升级。
- 可见操作文案已中文化；Shizuku、UserService、KernelSU、SELinux、SO 和 SHA-256 作为技术名称保留。
- 启动器图标改为 Adaptive Icon 钻戒造型，并提供 Android 13+ monochrome 图标；实机桌面已显示新的绿色钻戒图标。
- 版本提升为 versionCode `6`、versionName `1.2.1-v20`。

### Material You 与实机验收

- 新增 `JinghuApplication` 并在 Application 启动时调用：
  `DynamicColors.applyToActivitiesIfAvailable(this)`。
- 主题为 `Theme.Material3.DayNight.NoActionBar`；布局与 drawable 全部使用 Material 3 语义色，亮色/暗色资源只作为不支持 Dynamic Color 时的 fallback。
- 当前设备系统 Monet 色值包含 `system_accent1_100=#ffe5deff`、`system_accent1_500=#ff7770ab`；实机界面已跟随为紫色主按钮、快捷按钮和容器色，而不是原先固定绿色。
- Edge-to-edge 通过 WindowInsets 为状态栏、导航栏和 display cutout 设置内边距；横屏 3200x2136 顶部/下半页截图均无系统栏重叠、文字裁切或控件溢出。
- 实机：serial `0401481180981540`，型号 `25053RP5CC`，Android 16；最终 APK 覆盖安装成功，系统包信息显示名称“戒指”、versionCode `6`、versionName `1.2.1-v20`。
- 当前状态为 `Enforcing`、`kernelsu` 已加载、Shizuku 未激活；UI 中“激活 Shizuku”可点击，v20 执行按钮为 `enabled=false`。本轮未点击执行按钮、未运行 payload。
- 自动日志目录可读，保留历史运行日志和 `app-events.log`。

### 最终验证与产物

- `:app:assembleDebug`、`:app:testDebugUnitTest`、`:app:lintDebug` 全部通过；测试 `5/5`，Lint 输出 `No issues found.`。
- 最终 APK 大小 `32389173` 字节，SHA-256：
  `42522ef3ed0a08ffc4873ff952f10f5d12bf67d7538239171674cae60b3af2f3`。
- 项目分发副本：`jinghu-shizuku-app/ring-v20-shizuku-debug.apk`。
- 下载目录副本：`E:\ZEOON3\Downloads\戒指-v20-shizuku-debug.apk`。
- 截图证据：
  - `app/build/outputs/screenshots/ring-v20-final-top.png`
  - `app/build/outputs/screenshots/ring-v20-final-lower.png`
  - `app/build/outputs/screenshots/ring-launcher.png`

## 十五、2026-07-29 攻击性 QA 审计

- 按用户要求新增：
  `jinghu-shizuku-app/QA_RULES.md`。
- 本次只做攻击性 QA 审计，没有修改 App 实现；文档记录了 13 个源码证据级攻击点，覆盖 P0 假成功、P1 OOM/ANR/卡死/同一 boot 锁死、输入 Provider、Shizuku UserService、远端 SO 完整性、日志耗尽和用户误操作。
- 最高风险证据：
  - `JinghuViewModel` 用 substring 搜索 `RUN_FINISHED=1`，任意自定义 SO 输出该文本即可污染成功判断。
  - `JinghuRunner` 打印 IP/DNS/framework 探测结果，但最终成功条件没有引用这些结果。
  - boot marker 在 `LD_PRELOAD` 之前创建，任务中断后当前 boot 无法重试。
  - `ShizukuUserServiceClient` 的 12 秒 bind 超时路径没有清除 `bindingRequested`，可能污染同一进程的后续操作。
- 验证：`:app:testDebugUnitTest` 5/5 通过；`:app:lintDebug` 输出 `No issues found.`；设备只读启动冒烟成功，包版本 `1.2.1-v20`，未点击执行按钮、未运行真实 v20 payload，因此运行类攻击点仍按 `STATIC_CONFIRMED/RUNTIME_PENDING` 区分，不宣称真机复现。
