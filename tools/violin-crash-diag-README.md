# violin crash 诊断 — 操作步骤

## 前提
- 已 root 的 Xiaomi Pad 7S Pro (violin)
- zip 解压到手机任意目录（比如 /sdcard/Download/）

## 步骤

### 1. 给权限
```sh
chmod 755 kcore_read
```

### 2. 获取 root
```sh
su
```
手机弹授权提示 → 点允许。确认 `id` 显示 `uid=0(root)`。

### 3. 运行脚本
```sh
sh violin-crash-diag.sh
```
脚本会自动采集符号、运行 exploit、采集 dmesg。
**设备可能黑屏重启，正常现象。**

### 4. 拉结果
脚本结束后（或设备重启后），把这几个文件发回来：
- `diag.txt` — 最重要，含 call trace
- `crash_trace.txt` — crash 关键信息
- `exploit_output.txt` — exploit 输出

这三个文件和脚本在同一个目录下。

## 如果 crash 太快来不及保存

开两个终端窗口：

窗口 1：
```sh
su
dmesg -w > dmesg_live.txt
```

窗口 2：
```sh
su
sh violin-crash-diag.sh
```

设备 crash 重启后，把 `dmesg_live.txt` 也发回来。
