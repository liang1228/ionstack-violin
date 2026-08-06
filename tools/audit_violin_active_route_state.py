#!/usr/bin/env python3
"""Audit the route state of existing Violin diagnostic artifacts.

This is a provenance/selector check only.  It reads source, build manifests, run
manifests, and local ELF bytes; it never builds, calls ADB, installs an artifact,
or executes a payload.
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
        "name": "cfgprobe_diag",
        "build": ROOT / "analysis_outputs/device-diag-build-20260722/build-manifest.txt",
        "run": ROOT / "analysis_outputs/device-diag-run-20260722/run-manifest.txt",
        "expected_define": "CFGPROBE_ONLY_DIAG=1",
        "expected_markers": ["CFGPROBE_START", "CFGPROBE_ONLY_DIAG_STOP"],
        "forbidden_markers": ["STEP3: entering run_main_route_threads", "FOPSROUTE_GO", "TARGET_WRITE"],
        "route_class": "pre-hijack cfgprobe only",
    },
    {
        "name": "route_only_diag",
        "build": ROOT / "analysis_outputs/device-route-diag-build-20260722/build-manifest.txt",
        "run": ROOT / "analysis_outputs/device-route-diag-run-20260722/run-manifest.txt",
        "expected_define": "DIRECT_WRITE_ROUTE_ONLY_PROBE=1",
        "expected_markers": ["ROUTE_ONLY_PROBE_START", "ROUTE_ONLY_PROBE_DONE"],
        "forbidden_markers": ["CFGPROBE_START", "FOPSROUTE_CFI_DISPATCH", "TARGET_WRITE"],
        "route_class": "safe consumer/timerfd route handoff only",
    },
    {
        "name": "cfi_transport_diag",
        "build": ROOT / "analysis_outputs/device-cfi-transport-build-20260722/build-manifest.txt",
        "run": ROOT / "analysis_outputs/device-cfi-transport-run-20260722/run-manifest.txt",
        "expected_define": "CFI_TRANSPORT_ONLY_DIAG=1",
        "expected_markers": [
            "CFI_TRANSPORT_ONLY_START",
            "CFI_TRANSPORT_SET_NAME",
            "CFI_TRANSPORT_PWRITE",
        ],
        "forbidden_markers": ["STEP3: entering run_main_route_threads", "FOPSROUTE_GO", "TARGET_WRITE"],
        "route_class": "ConfigFS name/pwrite transport only",
    },
]

SOURCE_FILES = [
    EXPLOIT / "src/main.c",
    EXPLOIT / "src/util.c",
    EXPLOIT / "src/fops.c",
    EXPLOIT / "src/pipe.c",
    EXPLOIT / "src/root.c",
    EXPLOIT / "src/preload.c",
    EXPLOIT / "src/targets/violin-v-oss/target.h",
    EXPLOIT / "src/targets/violin-v-oss/slide.c",
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


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_manifest(path: Path) -> dict[str, list[str] | str]:
    result: dict[str, list[str] | str] = {}
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
                normalized = raw_path.replace("\\", "/")
                marker = "exploit-repo/IonStack/CVE-2026-43499/exploit/"
                if marker in normalized:
                    normalized = normalized.split(marker, 1)[1]
                result[normalized] = digest.lower()
            continue
        if in_block and line and not line.startswith("  "):
            in_block = False
        if line.startswith("main_c_sha256="):
            result["src/main.c"] = line.split("=", 1)[1].strip().lower()
    return result


def marker_present(data: bytes, marker: str) -> bool:
    return marker.encode("ascii") in data


def check_case(case: dict) -> dict:
    build_path = case["build"]
    run_path = case["run"]
    build = parse_manifest(build_path)
    run = parse_manifest(run_path)
    manifest_source_hashes = parse_source_hashes(build_path)
    current_source_hashes = {
        str(path.relative_to(EXPLOIT)).replace("\\", "/"): sha256(path)
        for path in SOURCE_FILES
        if path.exists()
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
    data = output.read_bytes() if output.exists() else b""
    crash_path = run_path.parent / "crash.txt"
    crash = crash_path.read_text(encoding="utf-8", errors="replace") if crash_path.exists() else ""
    defines = build.get("compile_define", [])
    if isinstance(defines, str):
        defines = [defines]
    expected_hash = str(build.get("preload_sha256", "")).lower()
    actual_hash = sha256(output) if output.exists() else ""
    run_hash = str(run.get("preload_sha256", "")).lower()
    # Compile-time dead branches can leave marker strings in an ELF.  Runtime
    # reachability is therefore checked against the captured crash/log text,
    # not against the binary's string table.
    expected_markers = {m: m in crash for m in case["expected_markers"]}
    forbidden_markers = {m: m in crash for m in case["forbidden_markers"]}
    checks = {
        "build_manifest_exists": build_path.exists(),
        "run_manifest_exists": run_path.exists(),
        "project_explicit": build.get("project") == "violin-v-oss",
        "define_matches_case": case["expected_define"] in defines,
        "output_exists": output.exists(),
        "hash_matches_build": bool(actual_hash) and actual_hash == expected_hash,
        "run_hash_matches_build": run_hash == expected_hash,
        "run_exit_zero": run.get("run_exit") == "0",
        "boot_id_stable": bool(run.get("boot_id_before")) and run.get("boot_id_before") == run.get("boot_id_after"),
        "expected_markers_present": all(expected_markers.values()),
        "forbidden_markers_absent": not any(forbidden_markers.values()),
        "source_hashes_complete": not source_hashes_missing,
        "source_hashes_match_current": not source_hashes_mismatched,
    }
    return {
        "name": case["name"],
        "route_class": case["route_class"],
        "compile_defines": defines,
        "build_manifest": str(build_path.relative_to(ROOT)),
        "run_manifest": str(run_path.relative_to(ROOT)),
        "crash_log": str(crash_path.relative_to(ROOT)),
        "manifest_source_hashes": manifest_source_hashes,
        "source_hashes_missing": source_hashes_missing,
        "source_hashes_mismatched": source_hashes_mismatched,
        "output": str(output),
        "preload_sha256": actual_hash,
        "preload_size": output.stat().st_size if output.exists() else -1,
        "device": run.get("device"),
        "boot_id": run.get("boot_id_before"),
        "expected_markers": expected_markers,
        "forbidden_markers": forbidden_markers,
        "checks": checks,
        "all_checks_pass": all(checks.values()),
        "current_source_bound": checks["source_hashes_complete"] and checks["source_hashes_match_current"],
        "full_route_or_write_claim": False,
        "evidence_scope": "diagnostic route provenance only",
    }


def inspect_stable_artifact() -> dict:
    output = EXPLOIT / "build/violin-v-oss/bin/preload.so"
    data = output.read_bytes() if output.exists() else b""
    source_mtime = max(path.stat().st_mtime for path in SOURCE_FILES if path.exists())
    artifact_mtime = output.stat().st_mtime if output.exists() else 0
    return {
        "path": str(output),
        "exists": output.exists(),
        "sha256": sha256(output) if output.exists() else "",
        "size": output.stat().st_size if output.exists() else -1,
        "artifact_mtime": artifact_mtime,
        "current_source_max_mtime": source_mtime,
        "older_than_current_source": bool(output.exists() and artifact_mtime < source_mtime),
        "looks_like_full_route": any(
            marker_present(data, marker)
            for marker in ("FOPSROUTE_GO", "STEP3: entering run_main_route_threads", "pipe-physrw-summary")
        ),
        "quarantine": True,
        "reason": "no 2026-07-22 build/run tuple; artifact predates current source and must not be reused",
    }


def main() -> None:
    source_map = [
        {
            "path": str(path.relative_to(EXPLOIT)),
            "exists": path.exists(),
            "sha256": sha256(path) if path.exists() else "",
        }
        for path in SOURCE_FILES
    ]
    cases = [check_case(case) for case in CASES]
    result = {
        "scope": "offline active route-state alignment for existing Violin artifacts",
        "runtime_allowed": False,
        "source_selection": "PROJECT=violin-v-oss; target.h/slide.c override; remaining core files fallback to src/",
        "source_map": source_map,
        "cases": cases,
        "stable_default_artifact": inspect_stable_artifact(),
        "all_diagnostic_cases_pass": all(case["all_checks_pass"] for case in cases),
        "decision": (
            "The three 2026-07-22 artifacts are selector-, hash-, and marker-consistent with their "
            "recorded manifests, but none is bound to the complete current source map: cfgprobe has a "
            "stale main.c hash, route-only has no source hash block, and CFI transport records only "
            "main.c. They therefore remain historical diagnostic artifacts. They do not exercise the "
            "full route, fops hijack, kernel write, credential, or SELinux path. The unqualified "
            "build/violin-v-oss artifact is quarantined because it has no matching tuple and is older "
            "than the current source."
        ),
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "violin-active-route-state-20260722.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# Violin active route-state alignment (2026-07-22)",
        "",
        "Offline only: no build, ADB, installation, or payload execution.",
        "",
        f"- All diagnostic cases pass: **{result['all_diagnostic_cases_pass']}**",
        "- Source selector: `PROJECT=violin-v-oss`; `target.h`/`slide.c` override; remaining core files use root `src/`.",
        "",
        "## Diagnostic cases",
        "",
        "| Case | Route class | Define | SHA256 | Boot stable | Source bound | Full-route/write claim |",
        "|---|---|---|---|---|---|---|",
    ]
    for case in cases:
        checks = case["checks"]
        lines.append(
            f"| `{case['name']}` | {case['route_class']} | `{'; '.join(case['compile_defines'])}` | "
            f"`{case['preload_sha256']}` | `{checks['boot_id_stable']}` | "
            f"`{case['current_source_bound']}` | `False` |"
        )
    stable = result["stable_default_artifact"]
    lines += [
        "",
        "## Quarantined unqualified artifact",
        "",
        f"- `{stable['path']}`: SHA256 `{stable['sha256']}`, size `{stable['size']}`.",
        f"- Older than current source: **{stable['older_than_current_source']}**.",
        f"- Looks like full-route binary by marker scan: **{stable['looks_like_full_route']}**.",
        "- Decision: **quarantine**; do not use it for current Violin evidence.",
        "",
        "## Decision",
        "",
        result["decision"],
    ]
    (OUT / "violin-active-route-state-20260722.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
