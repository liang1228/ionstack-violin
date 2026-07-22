# 7sp root-stage variants (2026-07-22)

The three shared objects are exposed by `exploit.html` through the `payload` query parameter:

- `?payload=p` -> `p.so` (permissive marker only)
- `?payload=r` -> `r.so` (direct-root markers)
- `?payload=r2` -> `r2.so` (direct-root markers plus a reboot marker)

SHA-256 and sizes:

| file | bytes | SHA-256 |
|---|---:|---|
| `p.so` | 83632 | `edd44e0c17781f0d63935dc1938b81fdcdc981f7221392117effb54e26e6cc81` |
| `r.so` | 86464 | `ed07f6901eacd13577e77f09a7eebce5609e62b5b602bbefa10d09fdd4ca152e` |
| `r2.so` | 86664 | `f4ddca29b1b86c6d119ecdf1d10b4337842739479c50e4c2e19d39808631af76` |

The screenshot evidence supplied separately proves a direct-root run (`uid/euid/gid/egid=0`, `got_root=1`, `whoami=root`), but does not identify which binary or provide the matching boot/source manifest. Treat the query variants as separate candidates and preserve the complete output log for each run.

## CPU-affinity fix candidate: `r3.so`

- `?payload=r3` -> `r3.so`
- Purpose: preserve `r.so` and avoid the Violin app-cpuset failure observed when the runtime selected CPU 9 but the old build pinned `CORE=0`.
- Build source: external Linuxoid snapshot plus runtime CPU selection fix; target config bound to the current Violin target header.
- Build: Android API 35, workspace NDK r29.
- Size: `89264` bytes.
- SHA-256: `657bdb47745c59cb8157ad7afbf2dd7b8f7b34487040406764e1a0b9c33f6744`.
- Evidence boundary: build/static only; no device run or root proof yet. `r.so` and `r2.so` remain unchanged.

## Challenge-gate test candidate: `r4.so`

- `?payload=r4` -> `r4.so`
- Purpose: retain the r3 CPU-affinity fix while compiling out only the source-level Challenge Gate for the Violin browser test; no KASLR/PI/fops/pipe/cred logic was changed.
- Trigger: r3 loaded correctly but stopped at `[Signature] Enter value:` because the page command does not provide stdin.
- Build macro: `IONSTACK_SKIP_CHALLENGE_GATE=1`.
- Runtime marker: `[Challenge] disabled_for_violin_test` before `preload starting`.
- Android API 35, workspace NDK r29; size `86224` bytes.
- SHA-256: `151208b0c6e06d721f11dca558359cc87bb90c2decb8025f9f1c22a163a49c92`.
- Evidence boundary: static build only before first run; `r3.so` and prior variants remain unchanged.
