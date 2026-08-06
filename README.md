<div align="center">

# ⚡ IonStack Violin

**A browser-based Android kernel exploit for Xiaomi Violin (Mi 17) and Google Frankel (Pixel).**

[![Target](https://img.shields.io/badge/Target-Xiaomi%20Violin%20(Mi%2017)-ff6900?logo=xiaomi)]()
[![Android](https://img.shields.io/badge/Android-16%20%7C%2017-green?logo=android)]()
[![CVE](https://img.shields.io/badge/CVE--2026--43499-red)]()
[![Firefox](https://img.shields.io/badge/Firefox-151.0-orange?logo=firefox-browser)]()

</div>

---

## Overview

IonStack Violin is a **zero-interaction, browser-only kernel exploit** that achieves root on targeted Android devices through a vulnerability in the kernel's ion stack subsystem. The entire exploit chain runs inside Firefox for Android — no ADB, no app install, no bootloader unlock required.

**For authorized security research and educational purposes only.**

## Supported Devices

| Device | Codename | Android | Build Fingerprint | Status |
|--------|----------|---------|-------------------|--------|
| Xiaomi 17 | `violin` | 16 | `Xiaomi/violin/violin:16/BP2A.250605.031.A3/OS3.0.303.0.WOTCNXM:user/release-keys` | ✅ Primary target |
| Google Pixel | `frankel` | 17 | `google/frankel/frankel:17/CP2A.260605.012/15430684:user/release-keys` | ✅ Supported |

## How It Works

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  index.html  │────▶│ exploit.html │────▶│  preload.so  │────▶│  Kernel R/W  │
│  (launcher)  │     │  (trigger)   │     │  (payload)   │     │   (root)     │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
   3 attempts          CVE-2026-           Shared library       uid=0, root
   w/ timeout          43499 trigger       via LD_PRELOAD       shell achieved
```

1. **`index.html`** — Launcher page with ANSI terminal UI, retry logic (up to 3 attempts), and wake-lock management
2. **`exploit.html`** — Core exploit that triggers the kernel vulnerability, loads the selected payload `.so`, and orchestrates privilege escalation
3. **`preload.so`** — Compiled native payload injected into Firefox's process to achieve kernel-level code execution

## Payload Variants

Select a variant via the `?payload=` query parameter:

```
https://liang1228.github.io/ionstack-violin/index.html?payload=r
```

| Payload | File | Purpose |
|---------|------|---------|
| `p` | `p.so` | Permissive SELinux marker only |
| `r` | `r.so` | Direct root markers (`uid/euid=0`) |
| `r2` | `r2.so` | Root markers + reboot marker |
| `r3` | `r3.so` | Root + CPU-affinity fix (avoids app-cpuset failure on CPU 9) |
| `r4` | `r4.so` | Root + CPU-affinity fix + challenge gate disabled for browser testing |
| `e20` | `preload-local-violin-e20-exact-stack0.so` | E20 variant — exact stack offset 0 |
| `e24` | `preload-local-violin-e24-wake0.so` | E24 variant — wake offset 0 |
| `cfi` | `preload-local-violin-cfi-stage-only.so` | CFI bypass stage-only |
| `perf` | `preload-local-violin-perf-leak.so` | Performance counter leak variant |
| `sched` | `preload-local-violin-sched-wchan.so` | Scheduler wchan variant |
| `stable` | `preload-local-violin-stable0-faketask-khdrpi.so` | Stable variant with fake task + KHDRPI |

## Diagnostic & Recovery

| Parameter | Description |
|-----------|-------------|
| `?diag=recover` | Read-only collector — retrieves result files after a power-loss or crash without executing any payload |
| `?kbase=0x...` | Supply a known kernel base address to skip KASLR |

## Shell Scripts (for rooted devices)

These scripts run on-device via `adb shell` or a root terminal:

| Script | Purpose |
|--------|---------|
| `run-rooted-e24-live-capture.sh` | Launch E24 reproduction with live `dmesg` and kernel logcat capture |
| `collect-rooted-panic-evidence.sh` | Post-reboot evidence collector — grabs pstore, tombstones, boot_id, and uptime |

## Project Structure

```
ionstack-violin/
├── index.html                              # Launcher — ANSI UI, retry logic, parameter routing
├── exploit.html                            # Core CVE-2026-43499 exploit + payload loader
├── diag.html                               # Diagnostic / power-loss recovery page
├── ansi.js                                 # Lightweight ANSI escape code renderer
├── preload.so                              # Default payload (primary)
├── preload-a358fbf.so                      # Payload build variant (commit hash tagged)
├── preload-d6b5303.so                      # Payload build variant (commit hash tagged)
├── preload-local-violin-cfi-stage-only.so  # CFI bypass stage
├── preload-local-violin-e20-exact-stack0.so
├── preload-local-violin-e24-wake0.so
├── preload-local-violin-perf-leak.so
├── preload-local-violin-sched-wchan.so
├── preload-local-violin-stable0-faketask-khdrpi.so
├── p.so                                    # Permissive-only payload
├── r.so                                    # Direct-root payload
├── r2.so                                   # Root + reboot payload
├── r3.so                                   # Root + CPU-affinity fix
├── r4.so                                   # Root + CPU-affinity + skip challenge gate
├── run-rooted-e24-live-capture.sh          # Live kernel capture script
├── collect-rooted-panic-evidence.sh        # Post-reboot evidence collector
└── 7sp-root-variants-20260722.md           # Build manifest & SHA-256 checksums
```

## Usage

### Quick Start

Serve the repo via GitHub Pages or any static server, then open in **Firefox 151.0** on the target device:

```
https://liang1228.github.io/ionstack-violin/index.html
```

### With a Specific Payload

```
https://liang1228.github.io/ionstack-violin/index.html?payload=r
```

### Power-Loss Recovery

After a crash or unexpected reboot:

```
https://liang1228.github.io/ionstack-violin/index.html?diag=recover
```

### Live Kernel Capture (on rooted device)

```sh
adb push run-rooted-e24-live-capture.sh /data/local/tmp/
adb shell su -c "sh /data/local/tmp/run-rooted-e24-live-capture.sh"
```

## Build Info

| Item | Value |
|------|-------|
| NDK | r29 |
| Target API | 35 |
| Platform | ARM64 (AArch64) |
| Build date | 2026-07-22 |

SHA-256 checksums for all payloads are documented in [`7sp-root-variants-20260722.md`](7sp-root-variants-20260722.md).

## Acknowledgments

- Exploit by **N3bunuSec**
- "Exploit made with love"

## Disclaimer

This project is provided **as-is for authorized security research and educational purposes only**. The authors are not responsible for any misuse. Use only on devices you own and have explicit permission to test.

---

<div align="center">

**⚡ IonStack — kernel exploitation, browser-delivered**

</div>
