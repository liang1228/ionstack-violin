# 2026-07-23 in-place cred patch build manifest

## Scope

This directory contains an isolated static build only. No device push, browser/Pages publication, or payload execution was performed in this run.

## Source provenance

- Direct source snapshot: `E:\workspace\projects\xiaomi-root\analysis_outputs\external-linuxoid-cve-20260722-v2\source`
- Source repository commit: `e03994331634f8c03ed1df51a4e9fc551ef8e5f1`
- Patched source copy: `source/`
- Unmodified source copy: `source-unmodified/`
- Patched `source/src/main.c`: SHA256 `047b55c97dcfc93f6aa9d2c700e486da05592ee046d24ace94ea1ae0fd8b70e7`
- Target header: copied from `analysis_outputs/violin-popsicle-direct/src/target.h` and corrected from `0xffffffc008000000` to the `r.so`-confirmed `0xffffffc080000000` image base.
- NDK: `/tmp/ndk`, Android API 35 clang

## Build command

```bash
cd /mnt/e/workspace/projects/xiaomi-root/session-20260723-cred-patch/build-so/source
make clean preload NDK_ROOT=/tmp/ndk
```

## Artifacts

| File | Bytes | SHA256 |
|---|---:|---|
| `unmodified-correct-base.so` | 88528 | `72fddecfa550b4e34450cdfdfc2eff4a7f56e2b866ef720cd4e66d17fbb4cce2` |
| `inplace-preload.so` | 89800 | `31997ea1ff19ce6b831cbf0f4c73a041a5458e9a5ead080b238a09b3e1185920` |
| reference `r.so` | 86464 | `ed07f6901eacd13577e77f09a7eebce5609e62b5b602bbefa10d09fdd4ca152e` |
| reference `r2.so` | 86664 | `f4ddca29b1b86c6d119ecdf1d10b4337842739479c50e4c2e19d39808631af76` |

## Static checks

- Candidate is AArch64 `DYN`, with 10 program headers and 28 sections.
- `direct_cred_patch_inplace` and `direct_read_qword_retry` are present.
- The patch table has qword writes at `cred+8,+16,+24,+32` (zero), `+40` (zero), and `+48,+56,+64,+72,+80` (`CAP_FULL`).
- The candidate code path does not write the task cred pointer slots, does not reference the `SELINUX_ENFORCING` target, does not reference `/sys/fs/selinux/load`, and does not contain the removed policy-reload/followup helper symbols.
- The candidate's final condition requires all uid/gid values to be zero and SELinux enforce state to remain `1`.

## Open gate

Static build success is not runtime proof. The next online run, if explicitly authorized by the active project gate, must bind filename, size/SHA256, target base, boot_id, pselect/shape-0 markers, cred pointers, uid/gid, and `getenforce` in one same-boot manifest.
