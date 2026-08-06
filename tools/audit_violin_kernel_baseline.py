#!/usr/bin/env python3
"""Read-only violin target.h, kallsyms, and iomem consistency auditor.

This tool intentionally performs no ADB, shell, or device operation.  It turns
existing evidence into a machine-readable audit and rejects a target offset that
does not agree with the supplied rooted-kernel symbols and physical layout.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


DEFINE_RE = re.compile(
    r"^\s*#define\s+(?P<name>[A-Z][A-Z0-9_]*)\s+(?P<value>[^/\n]+?)"
    # Keep accepting annotations after the symbol name, e.g.
    # ``/* symbol: ashmem_misc (miscdevice struct) */``.  The previous
    # pattern silently dropped that define, so ASHMEM_MISC_OFF was never
    # checked against same-build kallsyms.
    r"\s*(?:/\*\s*symbol:\s*(?P<symbol>[^*\s(]+)(?:[^*]*)\*/)?\s*$"
)
KALLSYMS_RE = re.compile(r"^(?P<address>[0-9a-fA-F]{16})\s+\S\s+(?P<name>\S+)(?:\s+\[.*\])?$")
IOMEM_RE = re.compile(r"^\s*(?P<start>[0-9a-fA-F]+)-(?P<end>[0-9a-fA-F]+)\s*:\s*(?P<name>.+?)\s*$")
GIB = 1 << 30


def parse_defines(text: str) -> tuple[dict[str, int], dict[str, str]]:
    raw: dict[str, str] = {}
    symbols: dict[str, str] = {}
    for line in text.splitlines():
        match = DEFINE_RE.match(line)
        if not match:
            continue
        raw[match["name"]] = match["value"].strip()
        if match["symbol"]:
            symbols[match["name"]] = match["symbol"]

    resolved: dict[str, int] = {}

    def resolve(name: str, stack: set[str]) -> int:
        if name in resolved:
            return resolved[name]
        if name in stack or name not in raw:
            raise ValueError(f"cannot resolve macro {name}")
        value = raw[name].replace("ULL", "").replace("UL", "").strip()
        if re.fullmatch(r"0x[0-9a-fA-F]+|[0-9]+", value):
            result = int(value, 0)
        elif re.fullmatch(r"[A-Z][A-Z0-9_]*", value):
            result = resolve(value, stack | {name})
        else:
            raise ValueError(f"unsupported macro expression for {name}: {raw[name]!r}")
        resolved[name] = result
        return result

    for name in raw:
        try:
            resolve(name, set())
        except ValueError:
            continue
    return resolved, symbols


def parse_kallsyms(text: str) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in text.splitlines():
        match = KALLSYMS_RE.match(line.strip())
        if not match or " [" in line:
            continue
        symbols.setdefault(match["name"], int(match["address"], 16))
    return symbols


def parse_iomem(text: str) -> list[tuple[int, int, str]]:
    ranges = []
    for line in text.splitlines():
        match = IOMEM_RE.match(line)
        if match:
            ranges.append((int(match["start"], 16), int(match["end"], 16) + 1, match["name"]))
    return ranges


def audit_texts(target_text: str, kallsyms_text: str, iomem_text: str) -> dict[str, Any]:
    defines, macro_symbols = parse_defines(target_text)
    kallsyms = parse_kallsyms(kallsyms_text)
    ranges = parse_iomem(iomem_text)
    findings: list[dict[str, Any]] = []
    mismatches = 0

    text_base = kallsyms.get("_text")
    if text_base is None:
        findings.append({"kind": "error", "check": "_text", "detail": "missing non-module _text"})
        mismatches += 1
    else:
        for macro, symbol in sorted(macro_symbols.items()):
            if not macro.endswith("_OFF") or macro not in defines:
                continue
            address = kallsyms.get(symbol)
            if address is None:
                findings.append({"kind": "missing", "macro": macro, "symbol": symbol})
                continue
            actual = address - text_base
            expected = defines[macro]
            matched = actual == expected
            findings.append({
                "kind": "symbol_offset", "macro": macro, "symbol": symbol,
                "expected": f"0x{expected:x}", "actual": f"0x{actual:x}", "match": matched,
            })
            mismatches += int(not matched)

    system_ram = [item for item in ranges if item[2] == "System RAM"]
    kernel_code = [item for item in ranges if item[2] == "Kernel code"]
    if len(system_ram) != 0 and len(kernel_code) == 1:
        first_ram = min(item[0] for item in system_ram)
        expected_phys_offset = first_ram & -GIB
        # Violin's existing target names this field P0_KERNEL_PHYS_LOAD and
        # defines it as the /proc/iomem "Kernel code" start (0x00210000).
        # Do not import popsicle's _stext-to-_text subtraction convention:
        # these profiles use different field semantics.
        expected_kernel_load = kernel_code[0][0]
        for macro, actual in (("P0_PHYS_OFFSET", expected_phys_offset), ("P0_KERNEL_PHYS_LOAD", expected_kernel_load)):
            if macro not in defines:
                findings.append({"kind": "missing", "macro": macro})
                continue
            matched = defines[macro] == actual
            findings.append({"kind": "physical_layout", "macro": macro,
                             "expected": f"0x{defines[macro]:x}", "actual": f"0x{actual:x}", "match": matched})
            mismatches += int(not matched)
    else:
        findings.append({"kind": "error", "check": "iomem", "detail": "need System RAM and exactly one Kernel code range"})
        mismatches += 1

    checked_offsets = sum(1 for item in findings if item["kind"] == "symbol_offset")
    return {
        "ok": mismatches == 0,
        "summary": {"checked_symbol_offsets": checked_offsets, "mismatches": mismatches},
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--kallsyms", required=True, type=Path)
    parser.add_argument("--iomem", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="write JSON report")
    args = parser.parse_args()
    report = audit_texts(args.target.read_text(encoding="utf-8"), args.kallsyms.read_text(encoding="utf-8"), args.iomem.read_text(encoding="utf-8"))
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
