import struct, sys

def get_code_and_syms(filename, sym_name):
    with open(filename, 'rb') as f:
        data = f.read()
    if data[:4] != b'\x7fELF' or data[4] != 2:
        return None, None, {}
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]
    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    shstr = data[struct.unpack_from('<Q', data, shstr_hdr + 0x18)[0]:]
    text_off = text_addr = symtab_off = symtab_sz = strtab_off = strtab_sz = 0
    for i in range(e_shnum):
        h = e_shoff + i * e_shentsize
        t = struct.unpack_from('<I', data, h + 4)[0]
        nm_idx = struct.unpack_from('<I', data, h)[0]
        n = shstr.find(0, nm_idx)
        nm = shstr[nm_idx:n].decode('ascii', 'replace') if n > 0 else ''
        if nm == '.text':
            text_off = struct.unpack_from('<Q', data, h + 0x18)[0]
            text_addr = struct.unpack_from('<Q', data, h + 0x10)[0]
        if t == 2:
            symtab_off = struct.unpack_from('<Q', data, h + 0x18)[0]
            symtab_sz = struct.unpack_from('<Q', data, h + 0x20)[0]
            lk = struct.unpack_from('<I', data, h + 0x28)[0]
            sh = e_shoff + lk * e_shentsize
            strtab_off = struct.unpack_from('<Q', data, sh + 0x18)[0]
            strtab_sz = struct.unpack_from('<Q', data, sh + 0x20)[0]
    if not symtab_off:
        return None, None, {}
    st = data[strtab_off:strtab_off + strtab_sz]
    result_code = None
    result_addr = None
    all_syms = {}
    for i in range(symtab_sz // 24):
        s = data[symtab_off + i * 24:symtab_off + (i + 1) * 24]
        sn = struct.unpack_from('<I', s, 0)[0]
        info = s[4]
        val = struct.unpack_from('<Q', s, 8)[0]
        sz = struct.unpack_from('<Q', s, 16)[0]
        ne = st.find(0, sn)
        if ne < 0:
            continue
        nm = st[sn:ne].decode('ascii', 'replace')
        if (info & 0xf) == 2:
            all_syms[val] = nm
            if nm == sym_name and sz > 0:
                code_off = text_off + (val - text_addr)
                result_addr = val
                result_code = data[code_off:code_off + sz]
    return result_addr, result_code, all_syms

CONDS = ['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv']

def decode(insn, pc, syms):
    if (insn & 0xffc00000) == 0xa9800000:
        rt = insn & 31; rt2 = (insn >> 10) & 31
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 128
        l = (insn >> 22) & 1
        return ('ldp' if l else 'stp') + ' x{}, x{}, [sp, #{}]!'.format(rt, rt2, imm7*8)
    if (insn & 0xffc00000) == 0xa9400000:
        rt = insn & 31; rt2 = (insn >> 10) & 31
        imm7 = (insn >> 15) & 0x7f
        if imm7 & 0x40: imm7 -= 128
        l = (insn >> 22) & 1; rn = (insn >> 5) & 31
        return ('ldp' if l else 'stp') + ' x{}, x{}, [x{}, #{}]'.format(rt, rt2, rn, imm7*8)
    if (insn & 0x9f000000) == 0x90000000:
        rd = insn & 31
        immhi = (insn >> 5) & 0x7ffff; immlo = (insn >> 29) & 3
        imm = (immhi << 2) | immlo
        if imm & 0x100000: imm -= 0x200000
        page = (pc & ~0xfff) + (imm << 12)
        return 'adrp x{}, 0x{:x}'.format(rd, page)
    if (insn & 0xff800000) == 0x91000000:
        rd = insn & 31; rn = (insn >> 5) & 31
        imm12 = (insn >> 10) & 0xfff
        if (insn >> 22) & 1: imm12 <<= 12
        r = 'sp' if rn == 31 else 'x{}'.format(rn)
        return 'add x{}, {}, #0x{:x}'.format(rd, r, imm12)
    if (insn & 0xff800000) == 0xd1000000:
        rd = insn & 31; rn = (insn >> 5) & 31
        imm12 = (insn >> 10) & 0xfff
        if (insn >> 22) & 1: imm12 <<= 12
        r = 'sp' if rn == 31 else 'x{}'.format(rn)
        return 'sub x{}, {}, #0x{:x}'.format(rd, r, imm12)
    if (insn & 0xffc00000) == 0xf9000000:
        rt = insn & 31; rn = (insn >> 5) & 31; imm = (insn >> 10) & 0xfff
        return 'str x{}, [x{}, #0x{:x}]'.format(rt, rn, imm*8)
    if (insn & 0xffc00000) == 0xf9400000:
        rt = insn & 31; rn = (insn >> 5) & 31; imm = (insn >> 10) & 0xfff
        return 'ldr x{}, [x{}, #0x{:x}]'.format(rt, rn, imm*8)
    if (insn & 0xffc00000) == 0xb9000000:
        rt = insn & 31; rn = (insn >> 5) & 31; imm = (insn >> 10) & 0xfff
        return 'str w{}, [x{}, #0x{:x}]'.format(rt, rn, imm*4)
    if (insn & 0xffc00000) == 0xb9400000:
        rt = insn & 31; rn = (insn >> 5) & 31; imm = (insn >> 10) & 0xfff
        return 'ldr w{}, [x{}, #0x{:x}]'.format(rt, rn, imm*4)
    if (insn & 0xfc000000) == 0x14000000:
        imm = insn & 0x3ffffff
        if imm & 0x2000000: imm -= 0x4000000
        t = pc + imm * 4; nm = syms.get(t, '')
        return 'b 0x{:x}{}'.format(t, '  ;' + nm if nm else '')
    if (insn & 0xfc000000) == 0x94000000:
        imm = insn & 0x3ffffff
        if imm & 0x2000000: imm -= 0x4000000
        t = pc + imm * 4; nm = syms.get(t, '')
        return 'bl 0x{:x}{}'.format(t, '  ;' + nm if nm else '')
    if (insn & 0xff000000) == 0x34000000:
        rt = insn & 31; imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        return 'cbz w{}, 0x{:x}'.format(rt, pc + imm19 * 4)
    if (insn & 0xff000000) == 0x35000000:
        rt = insn & 31; imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        return 'cbnz w{}, 0x{:x}'.format(rt, pc + imm19 * 4)
    if (insn & 0xff000000) == 0xb4000000:
        rt = insn & 31; imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        return 'cbz x{}, 0x{:x}'.format(rt, pc + imm19 * 4)
    if (insn & 0xff000000) == 0xb5000000:
        rt = insn & 31; imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        return 'cbnz x{}, 0x{:x}'.format(rt, pc + imm19 * 4)
    if (insn & 0xffe00000) == 0x54000000:
        cond = insn & 0xf; imm19 = (insn >> 5) & 0x7ffff
        if imm19 & 0x40000: imm19 -= 0x80000
        return 'b.{} 0x{:x}'.format(CONDS[cond], pc + imm19 * 4)
    if (insn & 0xffe0001f) == 0xeb000000:
        rn = (insn >> 5) & 31; rm = (insn >> 16) & 31
        return 'cmp x{}, x{}'.format(rn, rm)
    if (insn & 0xff00001f) == 0xf1000000:
        rn = (insn >> 5) & 31; imm = (insn >> 10) & 0xfff
        return 'cmp x{}, #0x{:x}'.format(rn, imm)
    if (insn & 0xff00001f) == 0x71000000:
        rn = (insn >> 5) & 31; imm = (insn >> 10) & 0xfff
        return 'cmp w{}, #0x{:x}'.format(rn, imm)
    if (insn & 0xffe00c00) == 0x1a800400:
        rd = insn & 31; rn = (insn >> 5) & 31; rm = (insn >> 16) & 31
        c = (insn >> 12) & 0xf
        if rn == 31 and rm == 31:
            return 'cset w{}, {}'.format(rd, CONDS[c ^ 1])
        return 'csinc w{}, w{}, w{}, {}'.format(rd, rn, rm, CONDS[c])
    if (insn & 0xffe00c00) == 0x9a800400:
        rd = insn & 31; rn = (insn >> 5) & 31; rm = (insn >> 16) & 31
        c = (insn >> 12) & 0xf
        if rn == 31 and rm == 31:
            return 'cset x{}, {}'.format(rd, CONDS[c ^ 1])
        return 'csinc x{}, x{}, x{}, {}'.format(rd, rn, rm, CONDS[c])
    if (insn & 0xffe00c00) == 0x9a800000:
        rd = insn & 31; rn = (insn >> 5) & 31; rm = (insn >> 16) & 31
        c = (insn >> 12) & 0xf
        return 'csel x{}, x{}, x{}, {}'.format(rd, rn, rm, CONDS[c])
    if (insn & 0xffe00c00) == 0x1a800000:
        rd = insn & 31; rn = (insn >> 5) & 31; rm = (insn >> 16) & 31
        c = (insn >> 12) & 0xf
        return 'csel w{}, w{}, w{}, {}'.format(rd, rn, rm, CONDS[c])
    if (insn & 0xffe003e0) == 0xaa0003e0:
        rd = insn & 31; rm = (insn >> 16) & 31
        return 'mov x{}, x{}'.format(rd, rm)
    if (insn & 0xffe00000) == 0x2a000000:
        rd = insn & 31; rm = (insn >> 16) & 31
        return 'mov w{}, w{}'.format(rd, rm)
    if (insn & 0xff800000) == 0x52800000:
        rd = insn & 31; imm = (insn >> 5) & 0xffff
        return 'mov w{}, #0x{:x}'.format(rd, imm)
    if (insn & 0xffc00000) == 0xd2800000:
        rd = insn & 31; imm = (insn >> 5) & 0xffff; hw = (insn >> 21) & 3
        return 'movz x{}, #0x{:x}, lsl #{}'.format(rd, imm, hw*16)
    if (insn & 0xffc00000) == 0xf2800000:
        rd = insn & 31; imm = (insn >> 5) & 0xffff; hw = (insn >> 21) & 3
        return 'movk x{}, #0x{:x}, lsl #{}'.format(rd, imm, hw*16)
    if (insn & 0xffc00000) == 0x72800000:
        rd = insn & 31; imm = (insn >> 5) & 0xffff; hw = (insn >> 21) & 3
        return 'movk w{}, #0x{:x}, lsl #{}'.format(rd, imm, hw*16)
    if (insn & 0xfffffc1f) == 0xd63f0000:
        rn = (insn >> 5) & 31
        return 'blr x{}'.format(rn)
    if insn == 0xd65f03c0:
        return 'ret'
    if insn == 0xd503201f:
        return 'nop'
    if (insn & 0xffc00000) == 0x39000000:
        rt = insn & 31; rn = (insn >> 5) & 31; imm = (insn >> 10) & 0xfff
        return 'strb w{}, [x{}, #0x{:x}]'.format(rt, rn, imm)
    if (insn & 0xffc00000) == 0x39400000:
        rt = insn & 31; rn = (insn >> 5) & 31; imm = (insn >> 10) & 0xfff
        return 'ldrb w{}, [x{}, #0x{:x}]'.format(rt, rn, imm)
    return '.inst 0x{:08x}'.format(insn)

if len(sys.argv) < 3:
    print('Usage: disasm.py <elf> <symbol>')
    sys.exit(1)

addr, code, syms = get_code_and_syms(sys.argv[1], sys.argv[2])
if code:
    print('{}: 0x{:08x} size={}'.format(sys.argv[2], addr, len(code)))
    print()
    for i in range(0, len(code), 4):
        insn = struct.unpack_from('<I', code, i)[0]
        pc = addr + i
        d = decode(insn, pc, syms)
        print('  {:08x}: {}'.format(pc, d))
else:
    print('Symbol not found:', sys.argv[2])
