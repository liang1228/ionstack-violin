#!/usr/bin/env python3
"""Offline inventory of possible second rt_mutex objects for Violin.

This is an evidence triage pass: it compares source-level DEFINE_RT_MUTEX
objects against the same-build kallsyms data/bss symbols. It does not infer
that a missing symbol is impossible (LTO/localization/dynamic allocation can
hide objects), and it performs no device or payload operation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "kernel-src-wsl/common-gki"
KALLSYMS = ROOT / "analysis_outputs/evidence-audit-20260716/sameboot/ionstack-sameboot-oracle/kallsyms.txt"
CONFIG = ROOT / "analysis_outputs/e24/target-config.txt"

DECL_RE = re.compile(r"(?:static\s+)?DEFINE_RT_MUTEX\(([^)]+)\)")
SYM_RE = re.compile(r"^([0-9a-f]+)\s+([dDbB])\s+(.+)$")


def collect_source_objects() -> list[dict]:
    rows = []
    for path in SOURCE_ROOT.rglob("*.c"):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            match = DECL_RE.search(line)
            if match:
                rows.append({
                    "name": match.group(1).strip(),
                    "file": str(path.relative_to(ROOT)).replace("\\", "/"),
                    "line": line_no,
                    "kind": "DEFINE_RT_MUTEX",
                })
    return rows


def collect_symbols() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for line in KALLSYMS.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = SYM_RE.match(line)
        if not match:
            continue
        address, sym_type, name = match.groups()
        if sym_type not in "dDbB":
            continue
        out.setdefault(name, []).append({
            "address": "0x" + address,
            "type": sym_type,
            "name": name,
        })
    return out


def collect_config() -> dict[str, str]:
    wanted = {
        "CONFIG_DEBUG_LOCKING_API_SELFTESTS",
        "CONFIG_LOCK_TORTURE_TEST",
    }
    result = {}
    for line in CONFIG.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("# ") and line.endswith(" is not set"):
            key = line[2:-len(" is not set")]
            if key in wanted:
                result[key] = "not set"
        elif "=" in line:
            key, value = line.split("=", 1)
            if key in wanted:
                result[key] = value
    return result


def main() -> None:
    source_objects = collect_source_objects()
    symbols = collect_symbols()
    config = collect_config()
    matches = []
    missing = []
    for row in source_objects:
        found = symbols.get(row["name"], [])
        item = {**row, "kallsyms": found}
        (matches if found else missing).append(item)

    explicit_rt_data = [
        item for name, rows in symbols.items()
        if re.search(r"(?i)(rt_mutex|rtmutex)", name)
        for item in rows
        if not re.search(r"(?i)(__trace|__tpstrtab|__SCK__|adjust_prio_chain)", name)
    ]

    result = {
        "scope": "offline second rt_mutex inventory; source and same-build kallsyms only",
        "inputs": {
            "source_root": str(SOURCE_ROOT),
            "kallsyms": str(KALLSYMS),
            "config": str(CONFIG),
        },
        "source_define_rt_mutex_objects": source_objects,
        "source_objects_found_in_kallsyms": matches,
        "source_objects_missing_from_kallsyms": missing,
        "rtmutex_named_data_symbols_after_trace_filter": explicit_rt_data,
        "relevant_config": config,
        "decision": {
            "static_named_candidate_count": len(matches),
            "source_declarations_not_exposed_as_data_symbols": len(missing),
            "selftest_and_locktorture_enabled": any(value not in {"not set", "0", "n"} for value in config.values()),
            "result": "no obvious static named second rt_mutex in same-build kallsyms" if not matches else "named candidates require byte/layout verification",
            "limitations": [
                "anonymous/LTO-local objects may not retain source names",
                "struct rt_mutex fields embedded in dynamic objects are not enumerated",
                "a symbol name alone does not prove owner/waiters/wait_lock state",
            ],
            "next_gate": "only investigate dynamic or embedded rt_mutex candidates if a runtime-free byte/layout source can identify owner and waiter state; otherwise stop the pselect-256 branch",
        },
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
