#!/usr/bin/env python3
"""Offline closure check for whether pipe physrw is an independent first sink."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit/src"
OUT = ROOT / "analysis_outputs"


def main() -> None:
    pipe = (SRC / "pipe.c").read_text(encoding="utf-8")
    util = (SRC / "util.c").read_text(encoding="utf-8")

    evidence = {
        "pipe_phys_write_data_direct_write": "write(pipe_fds_reclaim[pipebuf_pipe_idx][1], data, len)" in pipe,
        "pipe_phys_write_data_found_buffer_branch": "return pipe_phys_write(fd, pipefd, pipebuf_addr, direct_addr, data, len);" in pipe,
        "pipe_phys_write_branch_rewrites_pipe_buffer_via_kernel_write": "kernel_write_data(fd, buf_addr, &pb, sizeof(pb))" in pipe,
        "pipe_phys_write_restores_pipe_buffer_via_kernel_write": "kernel_write_data(fd, buf_addr, &saved, sizeof(saved))" in pipe,
        "pipe_phys_write_unfound_buffer_branch_uses_forge": "forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 1);" in pipe,
        "forge_pipe_buffers_uses_kernel_write": "kernel_write_data(fd, base + off, &pb, sizeof(pb))" in pipe,
        "install_proof_write_precedes_phys_write": "kernel_write_data(fd, proof_addr, seed, sizeof(seed))" in pipe,
        "kernel_write_delegates_configfs": "return configfs_write_once(fd, target, data, len);" in util,
    }
    checks = {
        "found_buffer_path_circular": evidence["pipe_phys_write_data_found_buffer_branch"] and evidence["pipe_phys_write_branch_rewrites_pipe_buffer_via_kernel_write"],
        "unfound_buffer_path_circular": evidence["pipe_phys_write_unfound_buffer_branch_uses_forge"] and evidence["forge_pipe_buffers_uses_kernel_write"],
        "install_proof_depends_on_existing_write": evidence["install_proof_write_precedes_phys_write"] and evidence["kernel_write_delegates_configfs"],
    }
    result = {
        "scope": "offline pipe_buffer/anon_pipe_buf_ops first-stage sink audit",
        "runtime_allowed": False,
        "evidence": evidence,
        "checks": checks,
        "verdict": "NO_INDEPENDENT_FIRST_STAGE_WRITE" if all(checks.values()) else "REQUIRES_MANUAL_REVIEW",
        "decision": (
            "pipe_phys_write_data() does issue a direct write, but both setup branches are circular: "
            "a found pipe buffer is forged/restored through kernel_write_data(), while an unfound "
            "buffer calls forge_pipe_buffers_on_page(), which also uses kernel_write_data(). "
            "install_pipe_physrw() additionally performs a proof write before claiming physrw. "
            "kernel_write_data() delegates to ConfigFS, so pipe is a secondary transport after "
            "the existing fops/ConfigFS write primitive, not a replacement for the first sink."
        ),
        "next_gate": "Do not promote pipe_buffer to the first-stage branch; archive it and search a distinct kernel write sink offline.",
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "violin-pipe-first-stage-circularity-20260722.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    md = [
        "# Violin pipe first-stage circularity audit (2026-07-22)",
        "",
        "## Verdict",
        "",
        f"- **{result['verdict']}**",
        "- `pipe_phys_write_data()` has a direct `write()` sink, but does not independently establish the forged pipe-buffer state.",
        "- Found-buffer path: `pipe_phys_write()` rewrites and restores the pipe buffer through `kernel_write_data()`.",
        "- Unfound-buffer path: `forge_pipe_buffers_on_page()` writes every forged buffer through `kernel_write_data()`.",
        "- `install_pipe_physrw()` performs a proof `kernel_write_data()` before the physrw read/write checks.",
        "- `kernel_write_data()` delegates to `configfs_write_once()`, so the pipe path is downstream of ConfigFS/fops.",
        "- Offline only; no build, payload, device, or runtime action.",
        "",
        "## Decision",
        "",
        result["decision"],
        "",
        "## Next gate",
        "",
        result["next_gate"],
        "",
        "## Source anchors",
        "",
        "- `src/pipe.c:517-542` — `pipe_phys_write()` setup/restore writes.",
        "- `src/pipe.c:545-557` — `forge_pipe_buffers_on_page()` setup writes.",
        "- `src/pipe.c:579-597` — direct write dispatch.",
        "- `src/pipe.c:646-656` — proof write before physrw checks.",
        "- `src/util.c:995-996` — `kernel_write_data()` → `configfs_write_once()`.",
    ]
    (OUT / "violin-pipe-first-stage-circularity-20260722.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
