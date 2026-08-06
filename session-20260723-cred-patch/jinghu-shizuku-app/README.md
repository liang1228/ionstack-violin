# 戒指 v20 Shizuku App

“戒指”是 `jinghu_ksu_32525_v20_20260729` 的本地 Android App 封装。应用保留稳定包名 `com.zeoon3.jinghu`，通过 Shizuku 官方 UserService 执行固定流程，不调用主机端 `adb`，也不提供自由命令输入。

## 主要能力

- Shizuku 未激活时，“激活 Shizuku”会打开已安装的 Shizuku 官方页面；未安装时回退到官方网页引导。
- 使用 AIDL + Shizuku UserService，SO 通过 `ParcelFileDescriptor` 流式传输到远端临时文件，经 `fsync`、SHA-256 校验和原子替换后才允许使用。
- 内置 v20 最终优化版 SO 与 KernelSU Manager 32525，写入设备前后均校验 SHA-256。
- 执行前严格检查精确内核、SELinux、`sys.boot_completed`、KernelSU 模块和当前启动周期标记。
- 标记路径为 `/data/local/tmp/.jinghu-v20-<boot_id>`，同一启动周期无法重复执行。
- 完成后核验真实 Enforcing、sysfs enforce、KernelSU、`su` root、IP ping 和 DNS ping；全部通过才输出 `RUN_FINISHED=1`。
- 每次执行都会在应用私有目录 `files/run-logs/` 建立实时 journal；进程退出、App 重启或设备重启后，未完成任务会自动记录为 `INTERRUPTED`。
- “已保存日志”支持查看与分享历史日志，非载荷阶段的错误和 UI 事件写入 `app-events.log`。
- “更换 SO”支持导入 arm64 ELF `.so` 并持久保存；可随时恢复内置 v20 SO，设备安全门禁不会因自定义 SO 而放宽。

## Android 与界面

- AndroidX、Material 3、ViewBinding、ViewModel、LiveData。
- 应用名和页面标题均为“戒指”。
- 启动器使用 Adaptive Icon 戒指图标，并提供 Android 13+ monochrome 主题图标。
- `DynamicColors.applyToActivitiesIfAvailable()` 在 Android 12+ 使用系统莫奈壁纸取色；旧系统使用亮色/暗色 fallback 主题。
- Edge-to-edge 系统栏使用 WindowInsets 处理，不让内容进入状态栏或显示缺口。
- 界面采用中文文案，保留 Shizuku、KernelSU、SELinux、SO、SHA-256 等必要技术名称。

## 构建与检查

```powershell
$env:JAVA_HOME = 'C:\Users\zeooon3\AndroidStudioProjects\.jdks\jdk-21.0.11+10'
.\gradlew.bat :app:assembleDebug :app:testDebugUnitTest :app:lintDebug
```

- versionCode：`6`
- versionName：`1.2.1-v20`
- APK：`app\build\outputs\apk\debug\app-debug.apk`
- 分发副本：`ring-v20-shizuku-debug.apk`
- APK 大小：`32389173` 字节
- APK SHA-256：`42522ef3ed0a08ffc4873ff952f10f5d12bf67d7538239171674cae60b3af2f3`
- 单元测试：`5` 项通过
- Android Lint：`No issues found.`

## 交付物绑定

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `app/src/main/assets/preload_jinghu_v20_final_optimization.so` | 7022496 | `016477c1b9ae3cdc15f2b5b68bc51d69614aca994847cf80f2970ebdb7007463` |
| `app/src/main/assets/KernelSU_v3.2.5_32525-release.apk` | 9083665 | `1417081413bf7ab1de8e440ecbcb62685037c8f28f048f0f8b79e305b31ab916` |

APK 中不存在 v19 SO 资产。目标内核必须精确等于：

```text
6.6.77-android15-8-g5770c661275f-abogki443185593-4k
```

## 2026-07-29 实机验收

- 设备：Xiaomi Pad 7S Pro，型号 `25053RP5CC`，Android 16。
- 最新 APK 已覆盖安装，系统包信息显示应用名“戒指”、versionCode `6`、versionName `1.2.1-v20`。
- 当前设备为 `Enforcing`，但 `kernelsu` 已加载且 Shizuku 未激活，因此执行按钮保持禁用；本轮未运行 payload。
- 当前系统 Monet 主色为紫色，应用主按钮和容器已跟随壁纸色；亮色上下页、系统栏、中文长文案均无重叠或裁切。
- 截图：`app/build/outputs/screenshots/ring-v20-final-top.png`、`ring-v20-final-lower.png`、`ring-launcher.png`。
