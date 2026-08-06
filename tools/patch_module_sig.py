#!/usr/bin/env python3
"""
In-place patch: rename .llvm_addrsig -> .module_sig and overwrite its content
with a valid module_signature struct. No offset shifting needed.
"""
import struct, sys

def patch(input_path, output_path):
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]

    # Read shstrtab
    sh = e_shoff + e_shstrndx * e_shentsize
    shstrtab_off = struct.unpack_from('<Q', data, sh + 0x18)[0]
    shstrtab_size = struct.unpack_from('<Q', data, sh + 0x20)[0]
    shstrtab = data[shstrtab_off:shstrtab_off + shstrtab_size]

    # Find .llvm_addrsig
    for i in range(e_shnum):
        sh_i = e_shoff + i * e_shentsize
        name_idx = struct.unpack_from('<I', data, sh_i)[0]
        nend = shstrtab.index(b'\x00', name_idx)
        name = shstrtab[name_idx:nend].decode('ascii', errors='replace')
        if name == '.llvm_addrsig':
            sh_offset = struct.unpack_from('<Q', data, sh_i + 0x18)[0]
            sh_size = struct.unpack_from('<Q', data, sh_i + 0x20)[0]
            print(f"[{i}] .llvm_addrsig at 0x{sh_offset:x} size={sh_size}")

            # 1. Rename in shstrtab (in-place, same-length pad)
            old_name = b'.llvm_addrsig\x00'  # 14 bytes
            new_name = b'.module_sig\x00\x00\x00'  # 14 bytes (padded)
            assert len(old_name) == len(new_name), f"{len(old_name)} != {len(new_name)}"
            abs_name_off = shstrtab_off + name_idx
            data[abs_name_off:abs_name_off + len(old_name)] = new_name

            # 2. Change section type: SHT_LLVM_ADDRSIG (0x6fff4c03) -> SHT_PROGBITS (1)
            struct.pack_into('<I', data, sh_i + 4, 1)

            # 3. Clear flags (remove SHF_EXCLUDE 0x80000000)
            struct.pack_into('<Q', data, sh_i + 0x08, 0)

            # 4. Overwrite section content with valid module_signature + PKCS#7
            # Build minimal PKCS#7 ContentInfo
            pkcs7 = bytes([
                0x30, 0x03,  # SEQUENCE len=3
                0x06, 0x01,  # OID len=1
                0x00,        # dummy
            ])
            # struct module_signature trailer (12 bytes header + pkcs7 data)
            sig = bytes(8) + struct.pack('>I', len(pkcs7)) + pkcs7
            if len(sig) > sh_size:
                print(f"WARNING: sig data ({len(sig)}) > section size ({sh_size})")
                sig = sig[:sh_size]
            else:
                # Pad to fill section (kernel reads sh_size bytes)
                sig = sig + b'\x00' * (sh_size - len(sig))

            data[sh_offset:sh_offset + sh_size] = sig
            print(f"  Content overwritten with {len(sig)} bytes of signature data")

            with open(output_path, 'wb') as f:
                f.write(data)
            print(f"Output: {output_path} ({len(data)} bytes)")
            return

    print("ERROR: .llvm_addrsig not found")
    sys.exit(1)

if __name__ == '__main__':
    patch(
        sys.argv[1] if len(sys.argv) > 1 else 'E:/ZEOON3/Downloads/kernelsu_mi_ready.ko',
        sys.argv[2] if len(sys.argv) > 2 else 'E:/ZEOON3/Downloads/kernelsu_signed.ko'
    )
