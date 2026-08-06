# Violin Root Injector

CVE-2026-43499 (IonStack) exploit 的 Android APK 封装，面向 Xiaomi Pad 7S Pro (violin)。

## 构建

### 1. 编译 preload.so (WSL)

```bash
cd /mnt/e/workspace/projects/xiaomi-root/exploit-repo/IonStack/CVE-2026-43499/exploit
make PROJECT=violin-v-oss
cp build/violin-v-oss/bin/preload.so /mnt/e/workspace/projects/xiaomi-root/violin-injector/app/src/main/assets/
```

### 2. Android Studio 构建 APK

1. 打开 Android Studio → File → Open → 选择 `violin-injector/` 目录
2. 等待 Gradle Sync 完成
3. Build → Make Project
4. APK 产出: `app/build/outputs/apk/debug/app-debug.apk`

### 3. 安装到设备

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

## 使用

### 前提

1. 设备已安装 [Shizuku](https://shizuku.rikka.app/)
2. Shizuku 已通过 ADB 或无线调试激活
3. 设备为 Xiaomi Pad 7S Pro (violin), 固件 OS3.0.303.0.WOTCNXM

### 操作

1. 打开 Violin Root app
2. 点击「一键执行」
3. 等待 exploit 运行（可能需要 30 秒）
4. 如果成功，设备将获得 root 权限

### 手动步骤

1. **复制到内部存储** — 从 APK assets 提取 preload.so
2. **获取 Shizuku 权限** — 授权 Shizuku shell 访问
3. **复制到 /data/local/tmp** — 通过 Shizuku 复制并设置可执行权限
4. **LD_PRELOAD 激活** — 注入 exploit 到目标进程

## 技术原理

APK 通过 Shizuku 获得 ADB shell 级别的权限，然后：

1. 将编译好的 `preload.so` (CVE-2026-43499 exploit) 复制到 `/data/local/tmp/`
2. 设置 `LD_PRELOAD` 环境变量指向该 .so 文件
3. 通过 Shizuku 执行目标命令，触发 exploit 的构造函数
4. exploit 执行完整的 root 链：KASLR leak → fops hijack → pipe physrw → cred patch

## 文件结构

```
violin-injector/
├── app/src/main/
│   ├── kotlin/com/violin/injector/
│   │   ├── MainActivity.kt        # 主界面
│   │   ├── SettingsActivity.kt     # 设置
│   │   ├── ShizukuManager.kt      # Shizuku API 封装
│   │   ├── ConfigManager.kt       # 配置管理
│   │   ├── CommandPreset.kt       # 命令预设
│   │   └── BootReceiver.kt        # 开机自启
│   ├── assets/preload.so           # 编译好的 exploit
│   └── res/                        # 布局和资源
├── build.gradle.kts
└── settings.gradle.kts
```
