<div align="center">

# ⚡ IonStack Violin

**CVE-2026-43499 Kernel Privilege Escalation Research — Xiaomi Pad 7S Pro**

---

![Target](https://img.shields.io/badge/Target-Xiaomi%20Pad%207S%20Pro-ff6900?logo=xiaomi)
![CVE](https://img.shields.io/badge/CVE--2026--43499-critical)
![Kernel](https://img.shields.io/badge/Kernel-6.6.77--android15--8-blue)
![Android](https://img.shields.io/badge/Android-16%20(HyperOS%203.0)-green?logo=android)
![Status](https://img.shields.io/badge/Status-Root%20Achieved-green)

[中文](README.md)

</div>

---

## Overview

This project is a full-chain kernel privilege escalation research of **CVE-2026-43499** (codename GhostLock / IonStack) on the **Xiaomi Pad 7S Pro** (codename `violin`).

- **Target devices:** Xiaomi Pad 7S Pro / Xiaomi Pad 7 Ultra / Xiaomi 15S Pro
- **Kernel:** `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`
- **Android:** 16 (HyperOS 3.0, `OS3.0.303.0.WOTCNXM`)
- **Goal:** Evaluate exploit feasibility, achieve full root, install KernelSU + LSPosed

**Current status: Root successfully achieved, KernelSU + LSPosed fully operational.**

---

## Root Evidence

![KernelSU Root](evidence/ksu-root-success.jpg)

Ring app showing ROOT acquired (enforcement mode), KernelSU Manager v3.2.5 working [jailbreak mode], running in LKM mode, LSPosed activated (API 102). Device: Xiaomi Pad 7S Pro 12.5, kernel `6.6.77-android15-8`, HyperOS 3.0 (`OS3.0.303.0.WOTCNXM`)

---

## One-Shot Root Tool (jinghu loader)

A one-shot root loader based on CVE-2026-43499, achieving kernel privilege escalation from userspace via `LD_PRELOAD` and automatically installing KernelSU.

### Usage

```sh
# 1. Push loader to device
adb push preload_jinghu_v20_final_optimization.so /data/local/tmp/

# 2. Reboot and wait for boot to complete
adb shell getprop sys.boot_completed  # should return 1

# 3. Verify kernel version
adb shell uname -r
# Expected: 6.6.77-android15-8-g5770c661275f-abogki443185593-4k

# 4. Verify clean baseline
adb shell getenforce        # Enforcing
adb shell su -c id          # should NOT return root

# 5. Execute (once per boot only)
adb shell LD_PRELOAD=/data/local/tmp/preload_jinghu_v20_final_optimization.so /system/bin/true
```

### Seven-Stage Execution Flow

| Stage | Name | Duration | Description |
|-------|------|----------|-------------|
| 1/7 | Environment check | ~0.002s | Validate `boot_completed`, `enforcing`, `kernelsu_loaded` |
| 2/7 | Save boot ID | ~0.001s | Record and verify boot ID |
| 3/7 | Locate kernel | ~39s | KASLR leak, derive `_text` base address |
| 4/7 | Acquire root | ~61s | CVE trigger → direct root (`init_cred`) |
| 5/7 | Restore boot ID | ~0.001s | Bind mount restore original boot ID |
| 6/7 | Load KernelSU | ~0.4s | insmod KO + start ksud |
| 7/7 | Final verification | ~5s | Verify root/SELinux/network, cleanup temp files |
| | **Total** | **~106s** | |

### Expected Results

- `su -c id` → `uid=0(root) context=u:r:ksu:s0`
- SELinux stays Enforcing (brief Permissive bootstrap, restored after)
- KernelSU 32525 / UAPI 2 / LKM / late-load
- LSPosed activated, ReZygisk running
- IP and DNS connectivity normal
- Temp files cleaned up

### Supported Devices

| Device | Codename | Kernel |
|--------|----------|--------|
| Xiaomi Pad 7 Ultra | jinghu | `6.6.77-android15-8-g5770c661275f-abogki443185593-4k` |
| Xiaomi Pad 7S Pro | violin | Same |
| Xiaomi 15S Pro | dijun | Same |

---

## Research Approach

### Overall Flow

```
CVE Trigger → UAF Exploitation → Address Leak → Write Primitive → Cred Patch → Root → KernelSU
```

### Phase 1: Vulnerability Trigger

CVE-2026-43499 stems from a flaw in the Linux kernel futex subsystem's `FUTEX_CMP_REQUEUE_PI` path. The kernel's cleanup logic operates on an incorrect waiter struct, leaving a freed kernel object accessible via a dangling pointer.

### Phase 2: Stack Space Overlap

The waiter struct on the kernel stack overlaps with userspace buffers. Using `pselect` with `nfds=320` and `shift=0` offset, the waiter's `tree`, `pi_parent`, `task`, and `lock` fields are mapped to user-controllable fdset word positions.

### Phase 3: KASLR Leak

The canonical `_text` base address is leaked through `sched_blocked_reason` tracefs raw events. The loader's slide route automates KASLR bypass — no manual address input required.

### Phase 4: Write Primitive

Through pselect syscall buffer overwrite and rt_mutex PI chain operations, an arbitrary kernel write primitive is established. The direct write route uses a three-step `per_cpu_offset` → `entry_task` → `cred` write sequence.

### Phase 5: Credential Patch

`init_cred` replaces `task->cred`, while `selinux_enforcing` is zeroed via the pselect primitive. KernelSU completes its domain transition during the brief Permissive window before Enforcing is restored.

### Phase 6: KernelSU Installation

After root, the loader automatically:
1. Deploys ksud to KernelSU manager directory
2. Deploys kernelsu .ko to `/data/local/tmp/`
3. Calls ksud for late-load insmod
4. Verifies KSU version, module list, network connectivity

---

## Evidence Status

| Stage | Status | Notes |
|-------|--------|-------|
| CVE trigger | ✅ Confirmed | `CMP_REQUEUE_PI=-1/errno=EDEADLK` |
| Stack overlap | ✅ Confirmed | `shift=0, nfds=320` factory kernel verified |
| KASLR leak | ✅ Implemented | Slide route automated bypass |
| Write primitive | ✅ Implemented | Direct write three-step cred patch |
| Credential patch | ✅ Implemented | `init_cred` + `selinux_enforcing=0` |
| KernelSU | ✅ Implemented | v32525 UAPI2 LKM late-load |
| LSPosed | ✅ Implemented | v2.1.1 API 102 |

---

## Tech Stack

| Category | Details |
|----------|---------|
| Target devices | Xiaomi Pad 7S Pro (`violin`), Pad 7 Ultra (`jinghu`), 15S Pro (`dijun`) |
| Firmware | HyperOS 3.0 (`OS3.0.303.0.WOTCNXM`), Android 16 |
| Kernel | `6.6.77-android15-8-g5770c661275f-abogki443185593-4k`, ARM64 |
| CVE | CVE-2026-43499 (GhostLock / IonStack) |
| Root method | `LD_PRELOAD` loader SO → kernel privesc → auto KernelSU install |
| Build tools | Android NDK r29, API 35 |
| Analysis tools | Python offline verifiers, kernel disassembly, BTF parsing, SELinux CIL analysis |

---

## Project Structure

```
ionstack-violin/
├── evidence/                           # Success screenshots and kernel info
├── exploit-site/                       # Browser-based exploit pages (HTML/JS)
├── tools/                              # Python offline audit/verification tools (~50)
├── violin-injector/                    # Android injector app source
├── session-20260723-cred-patch/        # In-place cred patch experiment source
├── ionstack-current-ktext/             # Rooted device kernel symbol dump
├── index.html                          # Launcher — terminal UI, retry logic
├── exploit.html                        # CVE trigger + payload loader
├── diag.html                           # Diagnostic / power-loss recovery
├── ansi.js                             # ANSI renderer
├── run-rooted-e24-live-capture.sh      # Kernel log capture script
├── collect-rooted-panic-evidence.sh    # Post-reboot evidence collector
└── README_EN.md                        # This file
```

---

## Disclaimer

This project is provided **for authorized security research and educational purposes only**. All testing was performed on devices owned and explicitly authorized by the author. The authors are not responsible for any misuse.

---

<div align="center">

**⚡ IonStack — Kernel Privilege Escalation Research, Browser-Delivered**

</div>
