# Violin 一次性内核证据清单

## A. 同固件、已 root 设备（可提供静态基线）

### MT 管理器本地运行

将脚本放在任意目录，例如 `/sdcard/Download/collect-rooted-baseline.sh`，然后在 MT 管理器 Root 终端运行：

```sh
su -c 'sh /sdcard/Download/collect-rooted-baseline.sh'
```

运行完成后，以下两个文件会直接生成在脚本所在目录：

```text
violin-kernel-evidence.tar.gz
violin-kernel-evidence.tar.gz.sha256
```

运行：

```powershell
powershell -ExecutionPolicy Bypass -File E:\workspace\projects\xiaomi-root\tools\pull-kernel-evidence.ps1
```

脚本会采集：

- 完整 build fingerprint、增量版本、安全补丁、slot、VBMeta digest
- `/sys/kernel/btf/vmlinux` 和模块 BTF
- `/proc/config.gz`、`kallsyms`、`cmdline`、`bootconfig`
- `iomem`、`slabinfo`、`vmallocinfo`、`zoneinfo`
- `/sys/kernel/kheaders.tar.xz`
- SELinux binary policy
- device tree
- `/vendor_dlkm`、`/system_dlkm`、`/vendor` 内核模块
- 当前 slot 的 `boot/init_boot/vendor_boot/vendor_kernel_boot/dtbo/vbmeta*`
- SHA-256 清单

只有 fingerprint、kernel release、VBMeta digest 均匹配时，才把这台设备的 BTF、偏移和分区镜像用于目标设备。

## B. 发生 E19 panic 的目标设备（不可由另一台替代）

必须从发生崩溃的设备采集：

- `/sys/fs/pstore/*`
- vendor ramoops / `last_kmsg`（若存在）
- panic 后的 boot_id
- E19 用户态 `crash.txt`

如果目标设备暂时不能 root，先不要再次运行会 panic 的实验；pstore 可能被后续 panic 覆盖。

## C. 建议额外提供

- 已 root 设备上执行 E19 前后的完整 `dmesg`
- 同版本设备的 `/proc/<waiter_tid>/stack`、`sched`、`status`、`wchan`（root 才能完整读取）
- 若已安装 Magisk：Magisk 版本、内核是否被修补、原厂 boot 与当前 boot 的 SHA-256；偏移分析优先使用原厂镜像
- 对两台设备分别保存 `getprop`，用于确认是否真的是完全相同构建

## D. 已有，无需重复

- full OTA
- 原厂 `boot.img`
- OTA kheaders
- 解压后的 ARM64 kernel binary
- 完整 kallsyms（仍建议脚本再采一份，以便绑定 fingerprint 和哈希）
- cmdline、iomem、slabinfo
