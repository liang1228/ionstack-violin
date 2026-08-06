#!/usr/bin/env python3
"""Minimal raw-BTF struct/union layout dumper (no bpftool dependency)."""
import argparse
import struct
from pathlib import Path

KIND = {1:'INT',2:'PTR',3:'ARRAY',4:'STRUCT',5:'UNION',6:'ENUM',7:'FWD',8:'TYPEDEF',
        9:'VOLATILE',10:'CONST',11:'RESTRICT',12:'FUNC',13:'FUNC_PROTO',14:'VAR',
        15:'DATASEC',16:'FLOAT',17:'DECL_TAG',18:'TYPE_TAG',19:'ENUM64'}

def cstr(blob, off):
    end = blob.find(b'\0', off)
    return blob[off:end].decode('utf-8', 'replace') if off < len(blob) else ''

def parse(path):
    b = Path(path).read_bytes()
    magic, ver, flags, hlen, toff, tlen, soff, slen = struct.unpack_from('<HBBIIIII', b, 0)
    if magic != 0xEB9F: raise SystemExit(f'bad BTF magic: 0x{magic:04x}')
    types_blob = b[hlen+toff:hlen+toff+tlen]
    strings = b[hlen+soff:hlen+soff+slen]
    types = [None]
    p = 0
    while p < len(types_blob):
        start = p
        name_off, info, size_type = struct.unpack_from('<III', types_blob, p); p += 12
        vlen, kind, kflag = info & 0xffff, (info >> 24) & 0x1f, bool(info >> 31)
        extra = None
        if kind == 1: extra = types_blob[p:p+4]; p += 4
        elif kind == 3: extra = types_blob[p:p+12]; p += 12
        elif kind in (4,5): extra = types_blob[p:p+12*vlen]; p += 12*vlen
        elif kind == 6: extra = types_blob[p:p+8*vlen]; p += 8*vlen
        elif kind == 13: extra = types_blob[p:p+8*vlen]; p += 8*vlen
        elif kind == 14: extra = types_blob[p:p+4]; p += 4
        elif kind == 15: extra = types_blob[p:p+12*vlen]; p += 12*vlen
        elif kind == 17: extra = types_blob[p:p+4]; p += 4
        elif kind == 19: extra = types_blob[p:p+12*vlen]; p += 12*vlen
        types.append({'name':cstr(strings,name_off),'kind':kind,'kind_name':KIND.get(kind,str(kind)),
                      'vlen':vlen,'kflag':kflag,'size_type':size_type,'extra':extra,'start':start})
    return types, strings

def typename(types, tid, seen=None):
    if tid == 0: return 'void'
    if tid >= len(types): return f'<bad:{tid}>'
    t=types[tid]; n=t['name']; k=t['kind']
    if k == 2: return typename(types,t['size_type'])+' *'
    if k in (8,9,10,11,18): return n or typename(types,t['size_type'])
    if k in (4,5,7): return f"{t['kind_name'].lower()} {n}".strip()
    return n or t['kind_name'].lower()

def dump(types, strings, wanted):
    found=0
    for tid,t in enumerate(types):
        if not t or t['kind'] not in (4,5) or t['name'] not in wanted: continue
        found += 1
        print(f"\n[{tid}] {t['kind_name'].lower()} {t['name']} size=0x{t['size_type']:x} ({t['size_type']})")
        for i in range(t['vlen']):
            no, mt, off = struct.unpack_from('<III', t['extra'], i*12)
            bits = off & 0xffffff if t['kflag'] else off
            width = off >> 24 if t['kflag'] else 0
            suffix=f' bitfield={width}' if width else ''
            print(f"  +0x{bits//8:04x} bit={bits%8}: {typename(types,mt)} {cstr(strings,no)}{suffix}")
    if not found: raise SystemExit('none of the requested structs/unions were found')

if __name__ == '__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('btf'); ap.add_argument('names',nargs='+')
    a=ap.parse_args(); dump(*parse(a.btf), set(a.names))
