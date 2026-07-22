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
