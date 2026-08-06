#!/usr/bin/env python3
"""Recover explicit offline source/run references for the strict Violin manifest.

The audit only reads existing scripts and logs.  It never executes a build script,
loads a library, talks to a device, or changes an artifact.
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "analysis_outputs/violin-provenance-manifest-20260722.json"
OUT = ROOT / "analysis_outputs"
DEVLOG = ROOT / "03-dev-log.md"


RECOVERY = {
    "exploit-site/preload-local-violin-cfi-configfs-only.so": {
        "source_records": [
            "analysis_outputs/build-violin-cfi-configfs-only-20260715.sh"
        ],
        "source_needles": [
            "-DTARGET_CONFIG_H='\"targets/violin-v-oss/target.h\"'",
            "src/main.c src/preload.c src/slide.c",
            "src/fops.c src/pipe.c src/root.c src/util.c",
        ],
        "run_records": ["03-dev-log.md:1752", "03-dev-log.md:1777"],
        "run_needles": [
            "preload-local-violin-cfi-configfs-only.so",
            "A48A3E7F70EF0BAF75048A8A16CFEE27134748EF6D67C7547FC84B750910AF7E",
        ],
        "project_status": "TARGET_HEADER_ONLY_NOT_PROJECT_VAR",
        "source_status": "RECOVERED_EXPLICIT_SCRIPT",
        "run_status": "RECOVERED_BUT_PATH_REUSED",
    },
    "exploit-site/preload-local-violin-route-only-probe.so": {
        "source_records": [
            "analysis_outputs/build-violin-route-only-probe-20260714.sh"
        ],
        "source_needles": [
            "-DTARGET_CONFIG_H='\"targets/violin-v-oss/target.h\"'",
            "src/main.c src/preload.c src/slide.c",
            "src/fops.c src/pipe.c src/root.c src/util.c",
        ],
        "run_records": ["03-dev-log.md:1638-1643"],
        "run_needles": [
            "preload-local-violin-route-only-probe.so",
            "CF80CC26686FA604778F9A899A3F9F29EE397E3EAC6FC39C3BABDDB1979D8969",
            "ROUTE_ONLY_PROBE_START",
        ],
        "project_status": "TARGET_HEADER_ONLY_NOT_PROJECT_VAR",
        "source_status": "RECOVERED_EXPLICIT_SCRIPT",
        "run_status": "RECOVERED_EXPLICIT_LOG",
    },
}


RUN_RECOVERY = {
    "exploit-repo/IonStack/CVE-2026-43499/exploit/build/violin-v-oss/bin/preload.so": {
        "run_records": ["03-dev-log.md:1856"],
        "run_needles": [
            "175,504 bytes",
            "F850DC1A0C06C71FA13FBA1E38CF465152381C7A61AF71819694501525201947",
        ],
        "run_status": "RECOVERED_EMBEDDED_ARTIFACT_RECORD",
    },
    "exploit-site/preload-local-violin-stable0-faketask-khdrpi.so": {
        "run_records": [
            "03-dev-log.md:46-57",
            "analysis_outputs/device-exec-20260713-135823/served-payload-sha256.txt",
        ],
        "run_needles": [
            "stable0-faketask-khdrpi",
            "272FB4FB7E96075DD8AE6DA9E4CE08F227CD55DF2DBA0084AE6A499E4AB0BF5A",
        ],
        "run_status": "RECOVERED_EXPLICIT_LOG",
    },
    "exploit-site/preload-local-violin-e20-exact-stack0.so": {
        "run_records": [
            "03-dev-log.md:682-685",
            "03-dev-log.md:717-720",
            "analysis_outputs/browser_logs/2026-07-12/ionstack-log-1783788433342.txt",
        ],
        "run_needles": [
            "preload-local-violin-e20-exact-stack0.so",
            "82010A66D2A0B15CDB6E4A580697F0E633CC8EF022FB234DA7E6D72448CCE92B",
            "kernel_file=preload-local-violin-e20-exact-stack0.so",
        ],
        "run_status": "RECOVERED_EXPLICIT_LOG",
    },
    "exploit-site/preload-local-violin-caimanwords-khdrpi-faketask.so": {
        "run_records": ["03-dev-log.md:46-48", "analysis_outputs/bootimg/local_http_server.err.log"],
        "run_needles": [
            "caimanwords-khdrpi-faketask",
            "E737AB30F94607C8CCAE465DF1ADC71D19D8604D84DE49906CB32A93F58AC0A9",
            "会 reboot",
        ],
        "run_status": "RECOVERED_EXPLICIT_LOG",
    },
    "exploit-site/preload-local-violin-slide-only.so": {
        "run_records": [
            "03-dev-log.md:1377-1384",
            "analysis_outputs/slide-only-20260714/SUMMARY.md",
        ],
        "run_needles": [
            "preload-local-violin-slide-only.so",
            "DD7DDB2A10C31D775C1C220421ED30C739A0F32FE9A9EEB76AF5EB71738480D7",
            "SLIDE_ONLY_DIAG=1",
        ],
        "run_status": "RECOVERED_EXPLICIT_LOG",
    },
}


def has_needles(path: Path, needles: list[str]) -> bool:
    text = path.read_text(encoding="utf-8")
    return all(needle in text for needle in needles)


def main() -> None:
    manifest = json.loads(INPUT.read_text(encoding="utf-8"))
    devlog = DEVLOG.read_text(encoding="utf-8")
    rows = []
    for base in manifest["artifacts"]:
        row = {
            "path": base["path"],
            "hash_status": base["status"],
            "current_sha256": base["current_sha256"],
            "evidence_status_before_recovery": base["evidence_status"],
            "project_status": base["project_status"],
            "source_status": base["source_map_status"],
            "run_status": base["run_log_status"],
            "source_records": [],
            "run_records": [],
            "source_records_verified": False,
            "run_records_verified": False,
        }
        recovered = RECOVERY.get(base["path"])
        if recovered:
            source_records = recovered.get("source_records", [])
            source_needles = recovered.get("source_needles", [])
            run_records = recovered.get("run_records", [])
            run_needles = recovered.get("run_needles", [])
            source_ok = all(
                (ROOT / rel).exists()
                and has_needles(ROOT / rel, source_needles)
                for rel in source_records
            ) and bool(source_records)
            run_ok = all(needle in devlog for needle in run_needles) and bool(run_records)
            row.update(
                {
                    "project_status": recovered.get("project_status", row["project_status"]),
                    "source_status": recovered.get("source_status", row["source_status"])
                    if source_ok
                    else row["source_status"],
                    "run_status": recovered.get("run_status", row["run_status"])
                    if run_ok
                    else row["run_status"],
                    "source_records": source_records,
                    "run_records": run_records,
                    "source_records_verified": source_ok,
                    "run_records_verified": run_ok,
                }
            )
        run_recovered = RUN_RECOVERY.get(base["path"])
        if run_recovered:
            run_ok = all(needle in devlog for needle in run_recovered["run_needles"])
            row.update(
                {
                    "run_status": run_recovered["run_status"] if run_ok else row["run_status"],
                    "run_records": run_recovered["run_records"],
                    "run_records_verified": run_ok,
                }
            )
        if row["hash_status"] == "CURRENT_HASH_UNMAPPED":
            row["evidence_status_after_recovery"] = "QUARANTINED_UNMAPPED"
        elif (
            row["hash_status"] in {"HASH_MATCH", "HASH_MATCH_BUT_PATH_REUSED"}
            and row["project_status"] == "PROJECT_EXPLICIT"
            and row["source_status"] == "RECOVERED_EXPLICIT_SCRIPT"
            and row["run_status"] == "RECOVERED_EXPLICIT_LOG"
        ):
            row["evidence_status_after_recovery"] = "ACCEPTED_COMPLETE"
        elif row["hash_status"] == "HASH_MATCH_BUT_PATH_REUSED":
            row["evidence_status_after_recovery"] = "HASH_MATCH_PATH_REUSED_INCOMPLETE"
        else:
            row["evidence_status_after_recovery"] = "HASH_MATCH_INCOMPLETE"
        rows.append(row)

    summary = {
        "total": len(rows),
        "source_record_recovered": sum(
            row["source_status"] == "RECOVERED_EXPLICIT_SCRIPT" for row in rows
        ),
        "run_record_recovered": sum(
            row["run_status"]
            in {
                "RECOVERED_EXPLICIT_LOG",
                "RECOVERED_BUT_PATH_REUSED",
                "RECOVERED_EMBEDDED_ARTIFACT_RECORD",
            }
            for row in rows
        ),
        "accepted_complete": sum(
            row["evidence_status_after_recovery"] == "ACCEPTED_COMPLETE" for row in rows
        ),
        "quarantined_unmapped": sum(
            row["evidence_status_after_recovery"] == "QUARANTINED_UNMAPPED" for row in rows
        ),
    }
    result = {
        "scope": "bounded recovery of existing source scripts and run-log references",
        "runtime_allowed": False,
        "required_project": manifest["required_project"],
        "summary": summary,
        "artifacts": rows,
        "decision": (
            "Route-only and CFI source scripts plus their log references are recoverable, "
            "but both hard-code TARGET_CONFIG_H rather than recording PROJECT=violin-v-oss; "
            "CFI also reuses a path. No item is promoted to complete evidence."
        ),
        "next_gate": (
            "Only fill the missing project/source-map/run-log metadata from existing records; "
            "do not execute the recovered scripts or use them to justify a new payload run."
        ),
    }

    OUT.mkdir(exist_ok=True)
    (OUT / "violin-provenance-recovery-20260722.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    md = [
        "# Violin provenance recovery audit (2026-07-22)",
        "",
        "Read-only recovery of existing build scripts and log references; no script was executed.",
        "",
        "## Summary",
        "",
        f"- Source records recovered: **{summary['source_record_recovered']}**",
        f"- Run records recovered: **{summary['run_record_recovered']}**",
        f"- Accepted complete tuples: **{summary['accepted_complete']}**",
        f"- Quarantined unmapped: **{summary['quarantined_unmapped']}**",
        "",
        "## Recovered records",
        "",
        "| Artifact | Source records | Run records | Project status | Source status | Run status | Final status |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        md.append(
            f"| `{row['path']}` | `{'; '.join(row['source_records']) or 'none'}` | "
            f"`{'; '.join(row['run_records']) or 'none'}` | `{row['project_status']}` | "
            f"`{row['source_status']}` | `{row['run_status']}` | "
            f"`{row['evidence_status_after_recovery']}` |"
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
    (OUT / "violin-provenance-recovery-20260722.md").write_text(
        "\n".join(md) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
