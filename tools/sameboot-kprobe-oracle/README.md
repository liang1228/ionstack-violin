# Same-boot kprobe oracle

Use only on the rooted same-boot device and build the module against that exact
kernel output tree.  The module is read-only and emits `/proc/ionstack_oracle`.

It records, for the selected `target_tgid`:

- `do_select()`'s three kernel `fd_set` copy starts (`in/out/ex`) after all
  `get_fd_set()` calls have completed, plus five words from each copy;
- `rt_mutex_dequeue_pi(task, waiter)`'s actual waiter pointer and all fields
  relevant to the PI RB-tree mutation;
- signed `waiter - fdset_{in,out,ex}` deltas and the configured shift's
  byte expectation.

`rt_mutex_dequeue_pi` is `__always_inline` in some production builds.  The
module never substitutes a nearby symbol: its proc output says `unavailable`
and gives the registration errno if that exact symbol is absent.  `do_select`
must be present or module loading fails, because without it the fd-set claim is
not meaningful.

Build:

```sh
KDIR=/absolute/path/to/exact/kernel/out ./build-module.sh
```

On device, load before the target run and pull the proc output only after the
run has reached its observation point:

```sh
PSELECT_WAITER_WORD_SHIFT=0 ./load-and-collect.sh \
  /data/local/tmp/ionstack_kprobe_oracle.ko <target-tgid>
```

The existing `../collect-sameboot-root-oracle.sh` already captures
`/proc/ionstack_oracle` into `current-oracle.raw` and includes it in its tarball.
