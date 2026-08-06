#!/usr/bin/env python3
"""Verify existing Violin diagnostic artifact tuples without building or running anything.

The audit only reads build/run manifests and local artifacts.  It deliberately does not
talk to ADB, execute a payload, or promote a diagnostic artifact to exploit evidence.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLOIT = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit"
OUT = ROOT / "analysis_outputs"

CASES = [
    {
        "name": "diag",
        "build_manifest": ROOT / "analysis_outputs/device-diag-build-20260722/build-manifest.txt",
        "run_manifest": ROOT / "analysis_outputs/device-diag-run-20260722/run-manifest.txt",
    },
    {
        "name": "route_diag",
        "build_manifest": ROOT / "analysis_outputs/device-route-diag-build-20260722/build-manifest.txt",
        "run_manifest": ROOT / "analysis_outputs/device-route-diag-run-20260722/run-manifest.txt",
    },
    {
        "name": "cfi_transport_diag",
        "build_manifest": ROOT / "analysis_outputs/device-cfi-transport-build-20260722/build-manifest.txt",
        "run_manifest": ROOT / "analysis_outputs/device-cfi-transport-run-20260722/run-manifest.txt",
    },
]

CORE_SOURCES = [
    "src/main.c",
    "src/util.c",
    "src/fops.c",
    "src/pipe.c",
    "src/root.c",
    "src/preload.c",
    "src/su_blob.S",
    "src/wallpaper_blob.S",
]

TRACKED_SOURCE_MAP = [
    "src/main.c",
    "src/util.c",
    "src/fops.c",
    "src/pipe.c",
    "src/root.c",
    "src/preload.c",
    "src/targets/violin-v-oss/slide.c",
    "src/targets/violin-v-oss/target.h",
]


def parse_manifest(path: Path) -> dict[str, str | list[str]]:
    result: dict[str, str | list[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key == "compile_define":
            result.setdefault(key, [])
            assert isinstance(result[key], list)
            result[key].append(value)
        else:
            result[key] = value
    return result


def parse_source_hashes(path: Path) -> dict[str, str]:
    """Parse the optional indented source hash block from a build manifest."""
    result: dict[str, str] = {}
    in_block = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "source_hashes:":
            in_block = True
            continue
        if in_block and line.startswith("  "):
            fields = line.strip().rsplit(None, 1)
            if len(fields) == 2 and len(fields[1]) == 64:
                raw_path, digest = fields
                marker = "exploit-repo/IonStack/CVE-2026-43499/exploit/"
                normalized = raw_path.replace("\\", "/")
                if marker in normalized:
                    normalized = normalized.split(marker, 1)[1]
                result[normalized] = digest.lower()
            continue
        if in_block and line and not line.startswith("  "):
            in_block = False
        if line.startswith("main_c_sha256="):
            result["src/main.c"] = line.split("=", 1)[1].strip().lower()
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_map() -> list[dict[str, str | bool]]:
    target_dir = EXPLOIT / "src/targets/violin-v-oss"
    entries: list[dict[str, str | bool]] = []
    for rel in CORE_SOURCES:
        path = EXPLOIT / rel
        entries.append(
            {
                "path": rel,
                "selection": "fallback-src" if not (target_dir / Path(rel).name).exists() else "target-override",
                "exists": path.exists(),
                "sha256": sha256(path) if path.exists() else "",
            }
        )
    for rel in ["src/targets/violin-v-oss/target.h", "src/targets/violin-v-oss/slide.c"]:
        path = EXPLOIT / rel
        entries.append(
            {
                "path": rel,
                "selection": "target-override",
                "exists": path.exists(),
                "sha256": sha256(path) if path.exists() else "",
            }
        )
    return entries


def verify_case(case: dict[str, Path], sources: list[dict[str, str | bool]]) -> dict:
    build_path = case["build_manifest"]
    run_path = case["run_manifest"]
    build = parse_manifest(build_path)
    run = parse_manifest(run_path)
    manifest_source_hashes = parse_source_hashes(build_path)
    current_source_hashes = {
        str(row["path"]): str(row["sha256"]).lower()
        for row in sources
        if row["path"] in TRACKED_SOURCE_MAP
    }
    source_hashes_missing = [
        rel for rel in TRACKED_SOURCE_MAP if rel not in manifest_source_hashes
    ]
    source_hashes_mismatched = [
        rel
        for rel in TRACKED_SOURCE_MAP
        if rel in manifest_source_hashes
        and manifest_source_hashes[rel] != current_source_hashes.get(rel, "")
    ]
    output = Path(str(build.get("output", "")))
    output_ok = output.exists()
    actual_hash = sha256(output) if output_ok else ""
    actual_size = output.stat().st_size if output_ok else -1
    expected_hash = str(build.get("preload_sha256", "")).lower()
    expected_size = int(str(build.get("preload_size", "-1")))
    run_hash = str(run.get("preload_sha256", "")).lower()
    compile_defines = build.get("compile_define", [])
    if isinstance(compile_defines, str):
        compile_defines = [compile_defines]
    checks = {
        "build_manifest_exists": build_path.exists(),
        "run_manifest_exists": run_path.exists(),
        "project_explicit": build.get("project") == "violin-v-oss",
        "target_explicit": build.get("target") == "Android arm64-v8a",
        "output_exists": output_ok,
        "hash_matches_build": output_ok and actual_hash == expected_hash,
        "size_matches_build": output_ok and actual_size == expected_size,
        "run_hash_matches_build": run_hash == expected_hash,
        "run_exit_zero": run.get("run_exit") == "0",
        "boot_id_stable": bool(run.get("boot_id_before")) and run.get("boot_id_before") == run.get("boot_id_after"),
        "compile_define_recorded": bool(compile_defines),
        "remote_hash_recorded": bool(run_hash),
        "source_hashes_complete": not source_hashes_missing,
        "source_hashes_match_current": not source_hashes_mismatched,
    }
    # This is diagnostic provenance only.  It is not a claim that the route or write primitive works.
    return {
        "name": case["name"],
        "build_manifest": str(build_path.relative_to(ROOT)),
        "run_manifest": str(run_path.relative_to(ROOT)),
        "project": build.get("project"),
        "compile_defines": compile_defines,
        "output": str(output),
        "preload_sha256": actual_hash,
        "preload_size": actual_size,
        "run_boot_id": run.get("boot_id_before"),
        "device": run.get("device"),
        "source_selection": "Makefile PROJECT=violin-v-oss; target.h/slide.c override; remaining sources fallback to src/",
        "manifest_source_hashes": manifest_source_hashes,
        "source_hashes_missing": source_hashes_missing,
        "source_hashes_mismatched": source_hashes_mismatched,
        "source_map": sources,
        "checks": checks,
        "all_checks_pass": all(checks.values()) and all(bool(row["exists"]) for row in sources),
        "evidence_scope": "existing diagnostic artifact provenance only",
        "runtime_allowed": False,
    }


def main() -> None:
    sources = source_map()
    cases = [verify_case(case, sources) for case in CASES]
    result = {
        "scope": "read-only verification of existing Violin diagnostic build/run tuples",
        "runtime_allowed": False,
        "source_map_rule": "Makefile PROJECT=violin-v-oss; target-specific files override root src files",
        "cases": cases,
        "all_diagnostic_tuples_complete": all(case["all_checks_pass"] for case in cases),
        "decision": (
            "A diagnostic tuple is current-source provenance-complete only when all checks pass, "
            "including the full tracked source-hash map. Missing or stale source hashes keep the "
            "artifact historical-only. This does not promote any artifact to full-route, fops-hijack, "
            "root, or SELinux-write evidence."
        ),
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "violin-current-diag-tuples-20260722.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# Violin current diagnostic tuple audit (2026-07-22)",
        "",
        "Read-only verification; no build, ADB, payload execution, or artifact mutation.",
        "",
        f"- All diagnostic tuples complete: **{result['all_diagnostic_tuples_complete']}**",
        "- Source rule: `Makefile PROJECT=violin-v-oss`; `target.h`/`slide.c` override, remaining sources fallback to `src/`.",
        "",
        "| Case | Project | Defines | SHA256 | Boot stable | Source bound | All checks |",
        "|---|---|---|---|---|---|---|",
    ]
    for case in cases:
        checks = case["checks"]
        lines.append(
            f"| `{case['name']}` | `{case['project']}` | `{'; '.join(case['compile_defines'])}` | "
            f"`{case['preload_sha256']}` | `{checks['boot_id_stable']}` | "
            f"`{checks['source_hashes_complete'] and checks['source_hashes_match_current']}` | "
            f"`{case['all_checks_pass']}` |"
        )
    lines += [
        "",
        "## Decision",
        "",
        result["decision"],
    ]
    (OUT / "violin-current-diag-tuples-20260722.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
