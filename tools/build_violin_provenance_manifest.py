#!/usr/bin/env python3
"""Build a strict, offline provenance manifest for Violin artifact evidence.

This consumes the bounded SHA256 audit and deliberately does not move, execute,
or rebuild any artifact.  A hash match is not accepted as complete evidence
unless project selection, source map, and a run-log reference are all explicit.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "analysis_outputs/violin-binary-provenance-20260722.json"
OUT = ROOT / "analysis_outputs"


def metadata(path: str, status: str) -> dict[str, str]:
    """Return conservative provenance labels; never infer a complete source map."""

    if status == "CURRENT_HASH_UNMAPPED":
        return {
            "project_status": "UNMAPPED",
            "source_map_status": "UNMAPPED",
            "run_log_status": "UNMAPPED",
            "evidence_status": "QUARANTINED_UNMAPPED",
        }

    if path.endswith("build/violin-v-oss/bin/preload.so"):
        return {
            "project_status": "PATH_CONFIRMED_PROJECT",
            "source_map_status": "PARTIAL_COMMAND_NOT_RECORDED",
            "run_log_status": "REFERENCED_NOT_SELF_CONTAINED",
            "evidence_status": "HASH_MATCH_PROVENANCE_INCOMPLETE",
        }

    if path.endswith("preload-local-violin-cfi-configfs-only.so"):
        return {
            "project_status": "FILENAME_LABEL_ONLY",
            "source_map_status": "PARTIAL_COMMAND_NOT_RECORDED",
            "run_log_status": "REQUIRES_HASH_AND_RUN_SECTION",
            "evidence_status": "HASH_MATCH_PATH_REUSED_PROVENANCE_INCOMPLETE",
        }

    return {
        "project_status": "FILENAME_LABEL_ONLY",
        "source_map_status": "PARTIAL_COMMAND_NOT_RECORDED",
        "run_log_status": "REFERENCED_NOT_SELF_CONTAINED",
        "evidence_status": "HASH_MATCH_PROVENANCE_INCOMPLETE",
    }


def main() -> None:
    audit = json.loads(INPUT.read_text(encoding="utf-8"))
    rows = []
    for row in audit["artifacts"]:
        row = dict(row)
        row.update(metadata(row["path"], row["status"]))
        row["required_project"] = audit["required_project"]
        row["required_fields"] = [
            "current_sha256",
            "required_project",
            "source_map_status=COMPLETE",
            "run_log_status=COMPLETE",
        ]
        rows.append(row)

    summary = {
        "total": len(rows),
        "quarantined_unmapped": sum(
            row["evidence_status"] == "QUARANTINED_UNMAPPED" for row in rows
        ),
        "hash_match_provenance_incomplete": sum(
            row["evidence_status"] == "HASH_MATCH_PROVENANCE_INCOMPLETE" for row in rows
        ),
        "hash_match_path_reused_provenance_incomplete": sum(
            row["evidence_status"]
            == "HASH_MATCH_PATH_REUSED_PROVENANCE_INCOMPLETE"
            for row in rows
        ),
        "accepted_complete": sum(
            row["source_map_status"] == "COMPLETE"
            and row["run_log_status"] == "COMPLETE"
            for row in rows
        ),
    }
    result = {
        "scope": "strict offline evidence manifest derived from the bounded hash audit",
        "runtime_allowed": False,
        "required_project": audit["required_project"],
        "required_provenance": ["SHA256", "PROJECT=violin-v-oss", "source map", "run log"],
        "summary": summary,
        "artifacts": rows,
        "decision": (
            "No artifact is promoted to complete evidence until the source-selection command "
            "and the corresponding run log are explicit. Unmapped generic files are logically "
            "quarantined; no file is moved or modified."
        ),
        "next_gate": (
            "Recover missing PROJECT/source-map and run-log references from existing offline "
            "records; do not run, rebuild, or connect a payload while any required field is absent."
        ),
    }

    OUT.mkdir(exist_ok=True)
    (OUT / "violin-provenance-manifest-20260722.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    md = [
        "# Violin strict provenance manifest (2026-07-22)",
        "",
        "This is a derived, read-only manifest. It does not move, rebuild, execute, or upload any artifact.",
        "",
        "## Required evidence tuple",
        "",
        "`SHA256 + PROJECT=violin-v-oss + selected source map + corresponding run log`",
        "",
        "## Summary",
        "",
        f"- Total artifacts: **{summary['total']}**",
        f"- Hash-match but incomplete provenance: **{summary['hash_match_provenance_incomplete']}**",
        f"- Hash-match path reused and incomplete: **{summary['hash_match_path_reused_provenance_incomplete']}**",
        f"- Logically quarantined unmapped: **{summary['quarantined_unmapped']}**",
        f"- Accepted complete tuples: **{summary['accepted_complete']}**",
        "",
        "## Matrix",
        "",
        "| Artifact | Hash status | Project | Source map | Run log | Evidence status |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        md.append(
            f"| `{row['path']}` | `{row['status']}` | `{row['project_status']}` | "
            f"`{row['source_map_status']}` | `{row['run_log_status']}` | "
            f"`{row['evidence_status']}` |"
        )
    md += [
        "",
        "## Decision",
        "",
        result["decision"],
        "",
        "## Next gate",
        "",
        result["next_gate"],
    ]
    (OUT / "violin-provenance-manifest-20260722.md").write_text(
        "\n".join(md) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
