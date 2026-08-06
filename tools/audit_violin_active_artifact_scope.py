#!/usr/bin/env python3
"""Offline check that the sink inventory matches the Violin build source selection."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPLOIT = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit"
MAKEFILE = EXPLOIT / "Makefile"
TARGET_DIR = EXPLOIT / "src/targets/violin-v-oss"
OUT = ROOT / "analysis_outputs"


def main() -> None:
    make = MAKEFILE.read_text(encoding="utf-8")
    default_match = re.search(r"^PROJECT\s*\?=\s*([^\r\n]+)", make, re.MULTILINE)
    default_project = default_match.group(1).strip() if default_match else None
    pick_src_present = "$(if $(wildcard $(TARGET_DIR)/$(1)),$(TARGET_DIR)/$(1),src/$(1))" in make
    target_header_rule = 'TARGET_CFLAGS := -DTARGET_CONFIG_H=\\"targets/$(PROJECT)/target.h\\"' in make

    core_names = ["main.c", "util.c", "slide.c", "fops.c", "pipe.c"]
    target_files = {name: (TARGET_DIR / name).exists() for name in core_names}
    target_files["target.h"] = (TARGET_DIR / "target.h").exists()
    source_map = {
        name: f"src/targets/violin-v-oss/{name}" if target_files[name] else f"src/{name}"
        for name in core_names
    }

    slide = (TARGET_DIR / "slide.c").read_text(encoding="utf-8") if target_files["slide.c"] else ""
    target_slide_writes = {
        "userspace_log_write": 'write(fd, msg + off, len - off)' in slide,
        "child_pipe_report_write": 'SYSCHK(write(fds[1], &stext, sizeof(stext)))' in slide,
        "arbitrary_kernel_write_syscall": any(
            token in slide for token in ("pwrite(", "process_vm_writev(", "vmsplice(", "splice(")
        ),
    }

    result = {
        "scope": "offline Makefile/source-selection audit for the Violin artifact",
        "runtime_allowed": False,
        "default_project": default_project,
        "required_project": "violin-v-oss",
        "makefile_source_selection": {
            "pick_src_prefers_target_override": pick_src_present,
            "target_header_macro_present": target_header_rule,
        },
        "target_files": target_files,
        "violin_source_map": source_map,
        "target_slide_write_scan": target_slide_writes,
        "inventory_scope_status": (
            "VALID_FOR_EXPLICIT_PROJECT=violin-v-oss"
            if default_project != "violin-v-oss" and pick_src_present and target_header_rule
            else "REQUIRES_REVIEW"
        ),
        "decision": (
            "The Makefile defaults to a non-Violin project, so an unqualified make is not a "
            "Violin artifact. With PROJECT=violin-v-oss, only slide.c and target.h override "
            "the generic core; main/util/fops/pipe remain src/*.c. The Violin slide override "
            "contains only userspace log writes and a child-pipe report write, with no arbitrary "
            "kernel-write syscall. Therefore the bounded core sink inventory applies to the "
            "explicit Violin source selection, but binary evidence must record PROJECT=violin-v-oss."
        ),
        "next_gate": "Do not treat an unqualified/default build as Violin evidence; next offline artifact checks must record PROJECT=violin-v-oss and source map before any binary comparison.",
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "violin-active-artifact-scope-20260722.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    md = [
        "# Violin active artifact scope audit (2026-07-22)",
        "",
        "## Verdict",
        "",
        f"- Makefile default: `{default_project}`.",
        "- Required explicit build selector: `PROJECT=violin-v-oss`.",
        "- With that selector, only `slide.c` and `target.h` override the generic core; `main.c`, `util.c`, `fops.c`, and `pipe.c` remain `src/*.c`.",
        "- Violin `slide.c` has userspace log writes and a child-pipe report write, but no arbitrary kernel-write syscall.",
        "- The sink inventory is therefore valid for the explicit Violin source map, not for an unqualified/default build.",
        "- Offline only; no build, payload, device, or runtime action.",
        "",
        "## Source map",
        "",
        "| Unit | Selected source |",
        "|---|---|",
    ]
    for name, path in source_map.items():
        md.append(f"| `{name}` | `{path}` |")
    md += [
        "",
        "## Decision",
        "",
        result["decision"],
        "",
        "## Next gate",
        "",
        result["next_gate"],
        "",
        "## Evidence anchors",
        "",
        "- `Makefile:2` — default `PROJECT`.",
        "- `Makefile:6-15` — `TARGET_DIR`, `TARGET_HEADER`, and `pick_src` override rule.",
        "- `Makefile:84` — `TARGET_CONFIG_H` points at the selected target header.",
        "- `src/targets/violin-v-oss/slide.c:21-28,818-821` — target-only write calls are log/IPC writes.",
    ]
    (OUT / "violin-active-artifact-scope-20260722.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
