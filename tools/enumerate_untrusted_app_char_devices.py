#!/usr/bin/env python3
"""Enumerate all device types reachable by untrusted_app from CIL text.

This is an offline complement to parse_cil_permissions.py.  It does not query
or modify a device and deliberately reports raw allow/neverallow projections;
it is not a replacement for the platform policy compiler.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from parse_cil_permissions import Policy, parse_forms  # noqa: E402


def context_paths(path: Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = defaultdict(list)
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("/dev/"):
            continue
        match = re.match(r"^(\S+)\s+u:object_r:([^:]+):s0", line)
        if match:
            out[match.group(2)].append(match.group(1))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", action="append", required=True, type=Path)
    ap.add_argument("--contexts", action="append", required=True, type=Path)
    ap.add_argument("--subject", default="untrusted_app")
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()

    policies: list[tuple[Path, Policy]] = []
    all_types: set[str] = set()
    for path in args.policy:
        policy = Policy(parse_forms(path.read_text(encoding="utf-8", errors="replace")))
        policies.append((path, policy))
        all_types |= policy.types

    paths_by_type: dict[str, list[str]] = defaultdict(list)
    for path in args.contexts:
        for typ, paths in context_paths(path).items():
            paths_by_type[typ].extend(paths)

    rows: dict[str, dict[str, object]] = {}
    for path, policy in policies:
        for rule in policy.matching_rules(args.subject, all_types):
            if "chr_file" not in rule["classes"]:
                continue
            for target in rule["matched_targets"]:
                row = rows.setdefault(
                    target,
                    {
                        "type": target,
                        "paths": sorted(set(paths_by_type.get(target, []))),
                        "allow": defaultdict(set),
                        "neverallow": defaultdict(set),
                        "sources": [],
                    },
                )
                kind = rule["kind"]
                if kind in ("allow", "neverallow"):
                    for cls, perms in rule["classes"].items():
                        row[kind][cls].update(perms)
                    row["sources"].append(
                        {
                            "policy": str(path),
                            "kind": kind,
                            "source": rule["source"],
                            "target": rule["target"],
                            "classes": rule["classes"],
                        }
                    )

    output = []
    interesting = {"open", "read", "write", "ioctl", "map"}
    for target, row in sorted(rows.items()):
        if not row["paths"]:
            continue
        allow = {cls: sorted(perms) for cls, perms in row["allow"].items()}
        neverallow = {cls: sorted(perms) for cls, perms in row["neverallow"].items()}
        perms = set(allow.get("chr_file", [])) | set(neverallow.get("chr_file", []))
        if not perms & interesting:
            continue
        output.append(
            {
                "type": target,
                "paths": row["paths"],
                "allow": allow,
                "neverallow": neverallow,
                "sources": row["sources"],
            }
        )

    result = {
        "subject": args.subject,
        "policy_files": [str(p) for p, _ in policies],
        "context_files": [str(p) for p in args.contexts],
        "device_types_with_char_rules": output,
    }
    args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
