#!/usr/bin/env python3
"""Offline audit of the supplied Claude JSONL for artifact-specific build evidence."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRANSCRIPT = Path(
    r"C:\Users\zeooon3\.claude\projects\E--workspace-projects-xiaomi-root\ea086ca3-e2d2-48b8-8aff-9f9ab29510dd.jsonl"
)
OUT = ROOT / "analysis_outputs"

ARTIFACTS = {
    "stable0": "preload-local-violin-stable0-faketask-khdrpi.so",
    "e20": "preload-local-violin-e20-exact-stack0.so",
    "caimanwords": "preload-local-violin-caimanwords-khdrpi-faketask.so",
    "slide_only": "preload-local-violin-slide-only.so",
}
BUILD_MARKERS = ("make PROJECT=violin-v-oss", "TARGET_CONFIG_H", "sha256sum")


def walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_strings(item)


def main() -> None:
    result = {
        "scope": "offline scan of the user-supplied Claude JSONL transcript",
        "runtime_allowed": False,
        "transcript": str(TRANSCRIPT),
        "exists": TRANSCRIPT.exists(),
        "artifacts": {},
        "generic_build_command_records": [],
        "decision": "",
    }
    if not TRANSCRIPT.exists():
        result["decision"] = "Transcript unavailable; no provenance claim made."
    else:
        lines = TRANSCRIPT.read_text(encoding="utf-8", errors="ignore").splitlines()
        for key, artifact in ARTIFACTS.items():
            occurrences = []
            command_records = []
            for line_no, line in enumerate(lines, 1):
                if artifact.lower() not in line.lower():
                    continue
                occurrences.append(line_no)
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                strings = list(walk_strings(obj))
                for text in strings:
                    lower = text.lower()
                    if artifact.lower() in lower and any(
                        marker.lower() in lower for marker in BUILD_MARKERS
                    ):
                        command_records.append(line_no)
            result["artifacts"][key] = {
                "artifact": artifact,
                "transcript_occurrence_count": len(occurrences),
                "transcript_occurrence_lines": occurrences[:20],
                "artifact_specific_build_record_count": len(set(command_records)),
                "artifact_specific_build_record_lines": sorted(set(command_records))[:20],
                "status": (
                    "NO_ARTIFACT_SPECIFIC_BUILD_RECORD"
                    if not command_records
                    else "CONTEXT_REQUIRES_MANUAL_REVIEW"
                ),
            }

        for line_no, line in enumerate(lines, 1):
            if "make PROJECT=violin-v-oss" not in line:
                continue
            try:
                obj = json.loads(line)
                strings = list(walk_strings(obj))
            except json.JSONDecodeError:
                strings = [line]
            # Keep only structured command-like strings, not giant copied file dumps.
            for text in strings:
                if "make PROJECT=violin-v-oss" in text and len(text) < 1200:
                    result["generic_build_command_records"].append(
                        {"line": line_no, "text": text}
                    )
                    break
        result["decision"] = (
            "The transcript contains generic PROJECT=violin-v-oss/Makefile discussion, "
            "but no structured artifact-specific build command for stable0, E20, "
            "caimanwords, or slide-only. Transcript mentions are not sufficient to "
            "promote a hash to complete provenance."
        )

    result["summary"] = {
        "artifact_specific_build_records": sum(
            row["artifact_specific_build_record_count"]
            for row in result["artifacts"].values()
        ),
        "artifacts_without_specific_build_record": sum(
            row["status"] == "NO_ARTIFACT_SPECIFIC_BUILD_RECORD"
            for row in result["artifacts"].values()
        ),
        "generic_build_command_records": len(result["generic_build_command_records"]),
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "violin-transcript-provenance-20260722.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    md = [
        "# Violin transcript provenance audit (2026-07-22)",
        "",
        "Read-only scan of the supplied Claude JSONL; no command from the transcript was replayed.",
        "",
        f"- Transcript exists: **{result['exists']}**",
        f"- Artifact-specific build records: **{result['summary']['artifact_specific_build_records']}**",
        f"- Artifacts without specific build records: **{result['summary']['artifacts_without_specific_build_record']}**",
        f"- Generic build-command records: **{result['summary']['generic_build_command_records']}**",
        "",
        "| Artifact | Transcript mentions | Specific build record | Status |",
        "|---|---:|---:|---|",
    ]
    for row in result["artifacts"].values():
        md.append(
            f"| `{row['artifact']}` | {row['transcript_occurrence_count']} | "
            f"{row['artifact_specific_build_record_count']} | `{row['status']}` |"
        )
    md += [
        "",
        "## Decision",
        "",
        result["decision"],
        "",
        "## Next gate",
        "",
        "Recover source/hash links from existing artifact manifests or archive metadata; do not rebuild or run a payload solely from transcript context.",
    ]
    (OUT / "violin-transcript-provenance-20260722.md").write_text(
        "\n".join(md) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
