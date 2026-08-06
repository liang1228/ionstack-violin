#!/usr/bin/env python3
"""
Fix R_AARCH64_PREL32 (type 275) relocation overflow in a kernel module (.ko).

When the kernel text base is >2GB away from the referenced symbol,
PREL32 cannot encode the offset. This script converts those relocations
to R_AARCH64_ABS64 (type 274) which uses a full 64-bit absolute address.

ELF64 RELA entry layout (24 bytes):
  r_offset : uint64  (offset in section to patch)
  r_info   : uint64  (sym_idx << 32 | type)
  r_addend : int64   (signed addend)

PREL32 formula:  S + A - P  (truncated to 32-bit signed)
ABS64 formula:   S + A      (full 64-bit)

Converting: only the type field in r_info changes (275 -> 274).
The addend (A) stays the same because the kernel loader will apply
the correct formula for each type independently.
"""

import struct
import sys
import shutil

R_AARCH64_PREL32 = 275
R_AARCH64_ABS64 = 274

ELF_RELA_SIZE = 24  # 8 + 8 + 8

def main():
    input_path = r"E:\ZEOON3\Downloads\kernelsu_signed.ko"
    output_path = r"E:\ZEOON3\Downloads\kernelsu_fixed.ko"

    # Copy to output first so we work on the copy
    shutil.copy2(input_path, output_path)

    with open(output_path, "r+b") as f:
        # Read ELF header to verify it's ELF64
        f.seek(0)
        ident = f.read(16)
        if ident[:4] != b'\x7fELF':
            print("ERROR: Not an ELF file")
            sys.exit(1)
        ei_class = ident[4]  # 1=32-bit, 2=64-bit
        ei_data = ident[5]   # 1=LE, 2=BE
        if ei_class != 2:
            print("ERROR: Not ELF64")
            sys.exit(1)
        if ei_data != 1:
            print("ERROR: Not little-endian")
            sys.exit(1)

        # Read ELF64 header
        # e_shoff (section header offset) at offset 40
        # e_shentsize at offset 58
        # e_shnum at offset 60
        # e_shstrndx at offset 62
        f.seek(40)
        e_shoff = struct.unpack("<Q", f.read(8))[0]
        f.seek(58)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", f.read(6))

        if e_shentsize != 64:
            print(f"ERROR: Unexpected section header size {e_shentsize}")
            sys.exit(1)

        # Read section header string table to identify sections
        shstrtab_off = e_shoff + e_shstrndx * 64
        f.seek(shstrtab_off + 24)  # sh_offset field
        strtab_file_off = struct.unpack("<Q", f.read(8))[0]

        def read_section_name(sh_idx):
            f.seek(e_shoff + sh_idx * 64)  # sh_name is first field (uint32)
            name_off = struct.unpack("<I", f.read(4))[0]
            f.seek(strtab_file_off + name_off)
            name = b""
            while True:
                c = f.read(1)
                if c == b'\x00' or not c:
                    break
                name += c
            return name.decode("utf-8", errors="replace")

        # Find all RELA sections and patch type 275 -> 274
        patched_count = 0
        total_rela_count = 0

        for i in range(e_shnum):
            f.seek(e_shoff + i * 64)
            section_data = f.read(64)
            sh_name = struct.unpack("<I", section_data[0:4])[0]
            sh_type = struct.unpack("<I", section_data[4:8])[0]
            sh_offset = struct.unpack("<Q", section_data[24:32])[0]
            sh_size = struct.unpack("<Q", section_data[32:40])[0]

            # SHT_RELA = 4
            if sh_type != 4:
                continue

            section_name = read_section_name(i)
            num_rela = sh_size // ELF_RELA_SIZE
            total_rela_count += num_rela

            print(f"Section [{i}] '{section_name}': {num_rela} RELA entries at offset 0x{sh_offset:x}")

            # Scan all RELA entries in this section
            for j in range(num_rela):
                entry_off = sh_offset + j * ELF_RELA_SIZE
                f.seek(entry_off)
                r_offset, r_info, r_addend = struct.unpack("<QQq", f.read(ELF_RELA_SIZE))

                reloc_type = r_info & 0xffffffff

                if reloc_type == R_AARCH64_PREL32:
                    # Patch: change type to R_AARCH64_ABS64 (274)
                    new_r_info = (r_info & ~0xffffffff) | R_AARCH64_ABS64
                    f.seek(entry_off + 8)  # r_info is at offset 8 within the entry
                    f.write(struct.pack("<Q", new_r_info))
                    patched_count += 1

        print(f"\nTotal RELA entries scanned: {total_rela_count}")
        print(f"R_AARCH64_PREL32 (type 275) relocations patched to R_AARCH64_ABS64 (type 274): {patched_count}")
        print(f"Output written to: {output_path}")

        if patched_count == 0:
            print("WARNING: No PREL32 relocations found to patch.")


if __name__ == "__main__":
    main()
