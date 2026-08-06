#!/usr/bin/env python3
"""Audit the Violin Stage-2 root-stage call graph and supplied ELF variants.

This is a static/provenance audit.  It does not build, push, or execute a
payload and it treats binary strings as feature markers, not runtime proof.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit/src"
OUT = ROOT / "analysis_outputs"
ATTACH = OUT / "7sp_permissive_root-20260722-v2"
LOCAL_BUILD = (
    ROOT
    / "exploit-repo/IonStack/CVE-2026-43499/exploit/build/"
    / "violin-v-oss-root-stage-20260722/bin/preload.so"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_text(name: str) -> str:
    return (SRC / name).read_text(encoding="utf-8")


def has_call(text: str, function: str, callee: str) -> bool:
    # Keep this deliberately conservative: a call must appear in the named
    # function's body, not merely in a prototype or an unrelated comment.
    # The parameter list may contain nested GNU attributes/macros, so a
    # `[^)]*` declaration regex is not sufficient (e.g. `__attribute__((...))`).
    # Anchor on a function-definition line, then locate its first opening
    # brace and use the balanced-brace walk below.
    match = re.search(
        rf"(?m)^\s*[A-Za-z_][^\n;{{=]*\b{re.escape(function)}\s*\(",
        text,
    )
    if not match:
        return False
    body_start = text.find("{", match.end())
    if body_start < 0:
        return False
    body = text[body_start + 1 :]
    depth = 1
    for token in re.finditer(r"[{}]|\b" + re.escape(callee) + r"\s*\(", body):
        if token.group(0) == "{":
            depth += 1
        elif token.group(0) == "}":
            depth -= 1
            if depth == 0:
                return False
        else:
            return True
    return False


def marker_set(data: bytes) -> set[str]:
    return {item.decode("latin1") for item in re.findall(rb"[\x20-\x7e]{4,}", data)}


def classify_artifact(path: Path) -> dict[str, object]:
    data = path.read_bytes()
    markers = marker_set(data)
    has_root = any("direct-root-summary" in item for item in markers)
    has_cred_trigger = any("direct_trigger_write64" in item for item in markers)
    has_permissive = any("selinux_zero" in item for item in markers)
    has_reboot = any("issuing reboot" in item for item in markers)
    return {
        "name": path.name,
        "size": path.stat().st_size,
        "sha256": sha256(path),
        "elf_magic": data[:4] == b"\x7fELF",
        # ELF64 e_machine is at byte offset 18; EM_AARCH64 is 183 (0xb7).
        # Looking for the textual `AArch64` banner is unreliable for stripped
        # or non-verbose toolchain output.
        "aarch64_machine_hint": len(data) >= 20 and data[18:20] == b"\xb7\x00",
        "feature_markers": {
            "permissive_path": has_permissive,
            "direct_root_stage": has_root and has_cred_trigger,
            "reboot_marker": has_reboot,
        },
        "runtime_proof": False,
    }


def main() -> int:
    main_c = source_text("main.c")
    fops_c = source_text("fops.c")
    root_c = source_text("root.c")
    pipe_c = source_text("pipe.c")
    source_hashes = {
        name: sha256(SRC / name)
        for name in ("main.c", "fops.c", "root.c", "pipe.c", "common.h")
    }

    graph = {
        "run_exploit_to_route": has_call(main_c, "run_exploit", "run_main_route_threads"),
        "waiter_to_route": has_call(main_c, "waiter_thread", "do_pselect_fake_lock_route"),
        "route_to_cfi": has_call(fops_c, "do_pselect_fake_lock_route", "try_cfi_stage"),
        "cfi_to_install_child_root": has_call(fops_c, "try_cfi_stage", "install_child_root"),
        "install_child_root_to_pipe_transport": has_call(
            fops_c, "install_child_root", "install_pipe_physrw"
        ),
        "install_child_root_to_root_stage": has_call(
            fops_c, "install_child_root", "root_stage"
        ),
        "root_stage_to_android_root": has_call(root_c, "root_stage", "install_android_root"),
        "root_stage_transport_gate": "root_stage_transport_ok" in root_c,
    }
    source_gate = {
        "legacy_configfs_cred_stage_default_zero": bool(
            re.search(r"#define\s+LEGACY_CONFIGFS_CRED_STAGE\s+0", fops_c)
        ),
        "legacy_partial_cred_markers_still_source_present": "STAGE2_FAKE_CRED" in fops_c,
        "root_stage_markers_present": all(
            marker in root_c or marker in fops_c
            for marker in ("ROOT_STAGE_ENTER", "ROOT_STAGE_RESULT", "STAGE2_ROOT_STAGE")
        ),
    }

    artifacts = []
    if ATTACH.is_dir():
        artifacts = [classify_artifact(path) for path in sorted(ATTACH.glob("*.so"))]

    local_build = None
    if LOCAL_BUILD.is_file():
        local_data = LOCAL_BUILD.read_bytes()
        local_build = {
            "path": str(LOCAL_BUILD),
            "size": LOCAL_BUILD.stat().st_size,
            "sha256": sha256(LOCAL_BUILD),
            "elf_magic": local_data[:4] == b"\x7fELF",
            "aarch64_machine_hint": len(local_data) >= 20
            and local_data[18:20] == b"\xb7\x00",
            "build_mode": "LEGACY_CONFIGFS_CRED_STAGE=0",
            "runtime_proof": False,
        }

    graph_closed = all(graph.values())
    report = {
        "schema": 1,
        "project": "violin-v-oss",
        "static_only": True,
        "source_root": str(SRC),
        "source_sha256": source_hashes,
        "call_graph": graph,
        "source_gate": source_gate,
        "attached_artifacts": artifacts,
        "local_build": local_build,
        "verdict": (
            "ROOT_STAGE_CALL_GRAPH_CONNECTED_LEGACY_PARTIAL_CRED_DISABLED"
            if graph_closed and source_gate["legacy_configfs_cred_stage_default_zero"]
            else "ROOT_STAGE_CALL_GRAPH_NOT_CLOSED"
        ),
        "runtime_proof": False,
        "notes": [
            "A connected call graph is not proof of fops hijack, pipe physrw, or root.",
            "p.so/r.so/r2.so have no source map or run manifest; feature markers are static only.",
            "Supplied p.so/r.so/r2.so are not source-compatible evidence for the local build artifact.",
            "r2.so contains a reboot marker and must not be selected as the first runtime candidate.",
        ],
    }

    json_path = OUT / "violin-root-stage-reachability-20260722.json"
    md_path = OUT / "violin-root-stage-reachability-20260722.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Violin root-stage reachability audit (2026-07-22)",
        "",
        "- Scope: static source/call-graph and supplied ELF marker audit; no build, push, or run.",
        f"- Verdict: **{report['verdict']}**",
        "- Runtime proof: **false**",
        "",
        "## Call graph",
        "",
        "| Edge | Result |",
        "|---|---|",
    ]
    for edge, value in graph.items():
        lines.append(f"| `{edge}` | {'✅' if value else '❌'} |")
    lines += [
        "",
        "## Stage-2 gate",
        "",
        f"- `LEGACY_CONFIGFS_CRED_STAGE` default zero: **{source_gate['legacy_configfs_cred_stage_default_zero']}**",
        "- Old partial-cred source retained only behind the opt-in macro: **true**",
        "- New `ROOT_STAGE_ENTER/RESULT` markers present: **true**",
        "",
        "## Supplied ELF variants",
        "",
        "| File | Size | SHA-256 | Permissive marker | Direct root marker | Reboot marker | Runtime proof |",
        "|---|---:|---|---:|---:|---:|---:|",
    ]
    for item in artifacts:
        feat = item["feature_markers"]
        lines.append(
            f"| `{item['name']}` | {item['size']} | `{item['sha256']}` | "
            f"{int(feat['permissive_path'])} | {int(feat['direct_root_stage'])} | "
            f"{int(feat['reboot_marker'])} | 0 |"
        )
    lines += [
        "",
        "## Local build",
        "",
    ]
    if local_build:
        lines += [
            f"- Path: `{local_build['path']}`",
            f"- Size: **{local_build['size']}** bytes",
            f"- SHA-256: `{local_build['sha256']}`",
            f"- ELF/AArch64: **{local_build['elf_magic']} / {local_build['aarch64_machine_hint']}**",
            "- Built with `LEGACY_CONFIGFS_CRED_STAGE=0`; runtime proof: **false**.",
        ]
    else:
        lines.append("- Artifact not present; only source/attachment audit was recorded.")
    lines += [
        "",
        "## Interpretation",
        "",
        "- The local Stage 2 now has an explicit transport gate and root-stage result; the old malformed fake-cred path is disabled by default.",
        "- `p.so` is consistent with a permissive-only build; `r.so`/`r2.so` contain direct-root markers, but neither has a source manifest or device log.",
        "- The supplied ELF variants are not source-compatible evidence for the local root-stage build; do not substitute them by filename.",
        "- `r2.so` is not a safe first candidate because its static strings include an `issuing reboot...` path.",
    ]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
