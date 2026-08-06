#!/usr/bin/env python3
"""Offline hash/path/source-map provenance audit for selected Violin artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "analysis_outputs"


ARTIFACTS = [
    {
        "path": "exploit-repo/IonStack/CVE-2026-43499/exploit/build/violin-v-oss/bin/preload.so",
        "recorded_hashes": ["F850DC1A0C06C71FA13FBA1E38CF465152381C7A61AF71819694501525201947"],
        "record_ref": "03-dev-log.md:1856 (embedded preload in stack_diag_output_evidence_v2)",
        "source_map": "PROJECT=violin-v-oss required; direct build command not recorded beside this hash",
    },
    {
        "path": "exploit-site/preload-local-violin-stable0-faketask-khdrpi.so",
        "recorded_hashes": ["272FB4FB7E96075DD8AE6DA9E4CE08F227CD55DF2DBA0084AE6A499E4AB0BF5A"],
        "record_ref": "03-dev-log.md:45-57",
        "source_map": "Violin artifact name; explicit source command not recorded in the same entry",
    },
    {
        "path": "exploit-site/preload-local-violin-e20-exact-stack0.so",
        "recorded_hashes": ["82010A66D2A0B15CDB6E4A580697F0E633CC8EF022FB234DA7E6D72448CCE92B"],
        "record_ref": "03-dev-log.md:682-694",
        "source_map": "Violin artifact name; source-map command must be retained separately",
    },
    {
        "path": "exploit-site/preload-local-violin-caimanwords-khdrpi-faketask.so",
        "recorded_hashes": ["E737AB30F94607C8CCAE465DF1ADC71D19D8604D84DE49906CB32A93F58AC0A9"],
        "record_ref": "03-dev-log.md:45-48",
        "source_map": "Artifact is explicitly marked caimanwords; not a default Violin baseline",
    },
    {
        "path": "exploit-site/preload-local-violin-cfi-configfs-only.so",
        "recorded_hashes": [
            "C9B81F9EF0A804BA0EE0D9D53D1BEAF43BBBE4923798085D3E85B44F88F5D088",
            "A48A3E7F70EF0BAF75048A8A16CFEE27134748EF6D67C7547FC84B750910AF7E",
        ],
        "record_ref": "03-dev-log.md:1752 and 1777",
        "source_map": "Same path was reused; hash and run section are mandatory to identify the version",
    },
    {
        "path": "exploit-site/preload-local-violin-route-only-probe.so",
        "recorded_hashes": ["CF80CC26686FA604778F9A899A3F9F29EE397E3EAC6FC39C3BABDDB1979D8969"],
        "record_ref": "03-dev-log.md:1638-1641",
        "source_map": "Violin route-only diagnostic; build script is separately recorded",
    },
    {
        "path": "exploit-site/preload-local-violin-slide-only.so",
        "recorded_hashes": ["DD7DDB2A10C31D775C1C220421ED30C739A0F32FE9A9EEB76AF5EB71738480D7"],
        "record_ref": "03-dev-log.md:1377-1380",
        "source_map": "Violin slide-only diagnostic; build selector not repeated in entry",
    },
    {
        "path": "exploit-site/preload.so",
        "recorded_hashes": [],
        "record_ref": "no exact current-file hash record found",
        "source_map": "unmapped current generic filename",
    },
    {
        "path": "exploit-site/preload-a358fbf.so",
        "recorded_hashes": [],
        "record_ref": "03-dev-log.md:708 records size only for a stale browser run",
        "source_map": "unmapped stale browser filename",
    },
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def main() -> None:
    rows = []
    for item in ARTIFACTS:
        path = ROOT / item["path"]
        exists = path.exists()
        current_hash = sha256(path) if exists else None
        recorded = [h.upper() for h in item["recorded_hashes"]]
        if not exists:
            status = "MISSING_CURRENT_FILE"
        elif not recorded:
            status = "CURRENT_HASH_UNMAPPED"
        elif current_hash in recorded and len(recorded) > 1:
            status = "HASH_MATCH_BUT_PATH_REUSED"
        elif current_hash in recorded:
            status = "HASH_MATCH"
        else:
            status = "HASH_MISMATCH"
        rows.append({
            "path": item["path"],
            "exists": exists,
            "size": path.stat().st_size if exists else None,
            "current_sha256": current_hash,
            "recorded_sha256": recorded,
            "status": status,
            "record_ref": item["record_ref"],
            "source_map": item["source_map"],
        })

    result = {
        "scope": "bounded current-file/hash audit for high-signal Violin artifacts",
        "runtime_allowed": False,
        "required_project": "PROJECT=violin-v-oss",
        "artifacts": rows,
        "summary": {
            "hash_match": sum(r["status"] == "HASH_MATCH" for r in rows),
            "hash_match_path_reused": sum(r["status"] == "HASH_MATCH_BUT_PATH_REUSED" for r in rows),
            "unmapped": sum(r["status"] == "CURRENT_HASH_UNMAPPED" for r in rows),
            "mismatch": sum(r["status"] == "HASH_MISMATCH" for r in rows),
        },
        "decision": (
            "Several named Violin artifacts match their recorded hashes. The CFI ConfigFS "
            "filename was reused across at least two hashes, so path-only references are unsafe. "
            "Generic current preload.so/preload-a358fbf.so files have no exact current hash record "
            "and cannot be used as provenance anchors. Even hash matches retain only partial source "
            "provenance unless PROJECT=violin-v-oss and the selected source map are recorded."
        ),
        "next_gate": "Use only hash-matched artifacts with an explicit source-map record; quarantine unmapped generic files and disambiguate reused paths by hash plus run log.",
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "violin-binary-provenance-20260722.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    md = [
        "# Violin binary provenance audit (2026-07-22)",
        "",
        "## Scope",
        "",
        "Bounded audit of selected current `.so` files, recorded SHA256 values, and source-map notes. No build or execution was performed.",
        "",
        "## Verdict",
        "",
        "- Named stable0/E20/route-only/slide-only artifacts match their recorded hashes.",
        "- `preload-local-violin-cfi-configfs-only.so` is a reused path with two recorded hashes; path alone is invalid provenance.",
        "- Current generic `exploit-site/preload.so` and `preload-a358fbf.so` have no exact current hash record and are unmapped.",
        "- Hash match does not replace the required `PROJECT=violin-v-oss` source-map record.",
        "- Offline only; no payload, build, device, or runtime action.",
        "",
        "## Matrix",
        "",
        "| Artifact | Current SHA256 | Status |",
        "|---|---|---|",
    ]
    for row in rows:
        md.append(f"| `{row['path']}` | `{row['current_sha256'] or 'MISSING'}` | `{row['status']}` |")
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
        "## Source-selection rule",
        "",
        "All Violin binary comparisons must carry `PROJECT=violin-v-oss` plus the Makefile `pick_src` source map. The default Makefile project is blazer and is not acceptable as Violin provenance.",
    ]
    (OUT / "violin-binary-provenance-20260722.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
