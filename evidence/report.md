# 7sp p.so / r.so 本机运行证据审计（2026-07-23）

截图文件已原样保存为 `evidence.jpg`。截图明确显示：

- `p.so`：`getenforce` 从 enforcing 变为 `Permissive`，并有 `selinux zero result: enforcing=0`。这证明一次 permissive-only 结果。
- `r.so`（干净重启后）：日志出现 `got_root=1`、`uid=0`、`euid=0`，并且 `/data/local/tmp/root_proof` 内容为 `root`、属主 `root:root`。这证明一次 direct-root 结果。
- `r2.so`：截图没有对应证据。

本地附件 `7sp_permissive和root.zip` 的三个 ELF 已按 hash 复核：

| 文件 | 大小 | SHA256 | 截图结论 |
|---|---:|---|---|
| p.so | 83632 | `edd44e0c17781f0d63935dc1938b81fdcdc981f7221392117effb54e26e6cc81` | permissive-only |
| r.so | 86464 | `ed07f6901eacd13577e77f09a7eebce5609e62b5b602bbefa10d09fdd4ca152e` | direct-root claim |
| r2.so | 86664 | `f4ddca29b1b86c6d119ecdf1d10b4337842739479c50e4c2e19d39808631af76` | no screenshot evidence |

## 证据边界

截图没有包含设备 fingerprint、boot_id、运行 ID、文件 SHA256、source commit 或完整原始日志。因此可以把它升级为“至少一次本机 p.so permissive、至少一次本机 r.so root 的功能证据”，但不能证明：

1. 三个文件都已验证；
2. 截图中的 r.so 一定等于附件中 hash 的 r.so；
3. 结果可在当前 Violin/当前 build 稳定复现；
4. KASLR leak、fops/pipe physrw、cred 替换和 SELinux 写入链每一段都已成功。

## 下一步

保留当前附件不变。下次复现只运行 `r.so`，并在同一日志开头记录 selected filename、size、SHA256、device fingerprint、boot_id 和 source/build manifest；保留完整 stdout/stderr 和 root proof 文件 hash。不要把 p.so 的 permissive 结果当成 root stage 成功，也不要运行未绑定 provenance 的 `r2.so`。
