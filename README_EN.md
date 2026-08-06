<div align="center">

# ⚡ IonStack Violin

**CVE-2026-43499 Kernel Privilege Escalation Research — Xiaomi Pad 7S Pro**

---

![Target](https://img.shields.io/badge/Target-Xiaomi%20Pad%207S%20Pro-ff6900?logo=xiaomi)
![CVE](https://img.shields.io/badge/CVE--2026--43499-critical)
![Kernel](https://img.shields.io/badge/Kernel-6.6.77--android15--8-blue)
![Android](https://img.shields.io/badge/Android-16%20(HyperOS%203.0)-green?logo=android)
![Status](https://img.shields.io/badge/Status-Research%20in%20Progress-yellow)

[中文](README.md)

</div>

---

## Overview

This project is a full-chain kernel privilege escalation research of **CVE-2026-43499** (codename GhostLock / IonStack) on the **Xiaomi Pad 7S Pro** (codename `violin`).

- **Target device:** Xiaomi Pad 7S Pro, Android 16, HyperOS 3.0
- **Kernel:** `6.6.77-android15-8`
- **Browser:** Firefox for Android 151.0
- **Goal:** Evaluate exploit feasibility on authorized test devices, reproduce the attack chain, and use findings to fix product vulnerabilities

**Current status: CVE trigger confirmed, local primitives partially established, but the full in-browser privilege escalation chain is not yet closed.**
n## Root Evidence

![Root Evidence](evidence/evidence.jpg)

Screenshot shows `r.so` producing `got_root=1`, `uid=0`, `euid=0`; `/data/local/tmp/root_proof` owned by `root:root`.

> Full audit report: [evidence/report.md](evidence/report.md), kernel info dump: [violin-kernel-info2.zip](evidence/violin-kernel-info2.zip)。
n## KernelSU Root Success
![KernelSU Root](evidence/ksu-root-success.jpg)

Ring app showing ROOT acquired (enforcement mode), KernelSU Manager v3.2.5 working [jailbreak mode], running in LKM mode, LSPosed activated (API 102). Device: Xiaomi Pad 7S Pro 12.5, kernel `6.6.77-android15-8`, HyperOS 3.0 (`OS3.0.303.0.WOTCNXM`)

KernelSU Manager shows `ksud` and MT Manager granted superuser permission. SELinux in permissive mode. Device model 25053RP5CC, kernel `6.6.77-android15-8`.

---

## Research Approach

### Overall Flow

```
CVE Trigger → UAF Exploitation → Address Leak → Write Primitive → Cred Patch → Root
```

The entire exploit chain is triggered through a browser page (Firefox), leveraging a Use-After-Free vulnerability in the kernel's futex subsystem. It progresses through multiple stages to gain kernel read/write capability and ultimately achieve privilege escalation.

### Phase 1: Vulnerability Trigger

CVE-2026-43499 originates from a flaw in the Linux kernel futex subsystem's `FUTEX_CMP_REQUEUE_PI` path. When a requeue operation encounters a specific race condition, the kernel's cleanup logic operates on an incorrect waiter struct, leaving a freed kernel object accessible via a dangling pointer.

**Findings:**
- Trigger conditions independently reproduced on the target device
- Dangling waiter pointer survives after timeout
- An exploitable spatial overlap exists between the waiter and syscall stack frames

### Phase 2: Stack Space Overlap

The waiter struct on the kernel stack overlaps with userspace buffers of certain syscalls. By precisely controlling input parameters, the waiter's internal fields can be mapped to user-controllable buffer positions.

**Constraints:**
- Offsets must exactly match the target kernel version
- Incorrect offsets cause kernel panic or device reboot
- All values verified through factory kernel binary disassembly

### Phase 3: Address Space Leak

Kernel Address Space Layout Randomization (KASLR) is the core barrier of the exploit chain. A path was found to leak the kernel code segment base address through the kernel's tracing subsystem.

**Findings:**
- In the ADB shell domain (specific permission group), tracing raw events are readable
- Function return addresses in events can derive the current boot's kernel code segment base
- The Firefox app process cannot access this leak source due to SELinux policy restrictions
- The kernel base address changes every boot and cannot be reused across reboots

**Excluded leak paths:**
- `/proc/kallsyms`, `/proc/iomem` — SELinux denies plain shell reads
- Character device ioctls — all accessible nodes on the target device audited, none produce passive address outputs
- Perfetto trace broker — app domain lacks consumer read permission

### Phase 4: Write Primitive Construction

Converting the UAF into a controllable kernel write primitive was the most challenging phase. Multiple routes were researched:

| Route | Description | Status |
|-------|-------------|--------|
| Syscall buffer overwrite | Leverage UAF/syscall buffer stack overlap to overwrite waiter fields | Race synchronization issue, primitive not established |
| Priority inheritance chain | Use kernel PI priority tree operations for indirect writes | Chain exits controlled region midway, not closed |
| File operations table hijack | Overwrite device file function pointer table | Route reachable but write stage failed |
| Alternative CVE paths | Evaluate other public kernel vulns on the target device | Static conditions confirmed, ARM64 port incomplete |

### Phase 5: Credential Modification

The traditional privilege escalation approach (replacing process credentials with kernel initial credentials) causes SELinux context changes that crash the Android framework (black screen).

**Research approach:** Modify the UID/GID and capability fields in-place within the process credential struct, without changing the credential pointer or SELinux security context.

**Design constraints:**
- Do not modify security pointer → SELinux context stays `shell`
- Do not disable SELinux enforcing → global policy unchanged
- Do not replace credential pointer → process identity continuity preserved

**Expected result:** `uid=0(root)` with SELinux still Enforcing, framework unaffected.

### Phase 6: Attack Surface Audit

A systematic security audit was performed on userspace-accessible interfaces of the target device:

**Character device audit:**
- Permission metadata collected and SELinux CIL attribute closure expanded for all accessible `/dev` nodes
- ioctl ABI audited for GPU, DMA heap, ashmem, NPU, camera log, XRing, and other devices
- Conclusion: all accessible character devices are stateful interfaces with no passive kernel address leak capability

**SELinux policy analysis:**
- Parsed `untrusted_app` character device access closure from platform and vendor CIL policies
- Confirmed `neverallow` block on tracing subsystem for the app domain
- Confirmed no usable `readtracefs` privileged broker available for app invocation

---

## Excluded Paths

The following paths have been rigorously verified as infeasible:

1. Mistaking direct-map region addresses for kernel code segment addresses
2. Reusing kernel addresses across boots (KASLR changes every boot)
3. Multiple watchdog observation variants (all cause reboots)
4. Using specific return values as requeue success indicators (strict error code validation required)
5. Plain shell reading of SELinux-protected kernel symbol tables
6. Incorrect waiter offset calculations (cause kernel panic)
7. Public Linux LPE routes (target kernel config does not meet prerequisites)

---

## Evidence Status

| Stage | Status | Notes |
|-------|--------|-------|
| CVE trigger | ✅ Confirmed | Independently reproduced on target device |
| Stack overlap | ✅ Confirmed | Factory kernel disassembly verified |
| Address leak (shell domain) | ✅ Confirmed | Same-boot canonical base derived |
| Address leak (Firefox domain) | ❌ Unavailable | SELinux policy blocks access |
| Write primitive | ❌ Not established | Multiple routes all have blocking points |
| Credential modification | 🔨 Build only | No device runtime verification |
| Full root | ❌ Not achieved | — |

---

## Tech Stack

| Category | Details |
|----------|---------|
| Target device | Xiaomi Pad 7S Pro (`violin`) |
| Firmware | HyperOS 3.0 (`OS3.0.303.0.WOTCNXM`), Android 16 |
| Kernel | `6.6.77-android15-8`, ARM64 |
| Browser | Firefox for Android 151.0 |
| Build tools | Android NDK r29, API 35 |
| Analysis tools | Offline verifiers (Python), kernel disassembly, BTF parsing, SELinux CIL analysis |

---

## Project Structure

```
ionstack-violin/
├── index.html                         # Launcher — terminal UI, retry logic
├── exploit.html                       # CVE trigger + payload loader
├── diag.html                          # Diagnostic / power-loss recovery
├── ansi.js                            # ANSI renderer
├── run-rooted-e24-live-capture.sh     # Kernel log capture script
├── collect-rooted-panic-evidence.sh   # Post-reboot evidence collector
└── README_EN.md                       # This file
```

---

## Disclaimer

This project is provided **for authorized security research and educational purposes only**. All testing was performed on devices owned and explicitly authorized by the author. The authors are not responsible for any misuse.

---

<div align="center">

**⚡ IonStack — Kernel Privilege Escalation Research, Browser-Delivered**

</div>
