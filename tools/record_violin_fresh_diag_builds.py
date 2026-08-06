#!/usr/bin/env python3
"""Record complete source-bound manifests for freshly built Violin diagnostics.

The build itself is intentionally performed outside this script.  This recorder
only hashes the selected source map and local ELF outputs; it never calls ADB or
executes an artifact.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLOIT = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit"
OUT = ROOT / "analysis_outputs"

SOURCE_FILES = [
    EXPLOIT / "src/main.c",
    EXPLOIT / "src/util.c",
    EXPLOIT / "src/fops.c",
    EXPLOIT / "src/pipe.c",
    EXPLOIT / "src/root.c",
    EXPLOIT / "src/preload.c",
    EXPLOIT / "src/targets/violin-v-oss/slide.c",
    EXPLOIT / "src/targets/violin-v-oss/target.h",
]

CASES = [
    {
        "name": "cfgprobe_diag",
        "outdir": "violin-v-oss-fresh-cfgprobe-20260722",
        "defines": ["CFGPROBE_ONLY_DIAG=1"],
        "strings_assert": "CFGPROBE_START,CFGPROBE_ONLY_DIAG_STOP",
    },
    {
        "name": "route_only_diag",
        "outdir": "violin-v-oss-fresh-route-20260722",
        "defines": [
            "DIRECT_WRITE_ROUTE_ONLY_PROBE=1",
            "CFGPROBE_ONLY_DIAG=0",
            "PSELECT_CFI_ROUTE_ATTEMPTS=1",
        ],
        "strings_assert": "ROUTE_ONLY_PROBE_START,ROUTE_ONLY_RET",
    },
    {
        "name": "cfi_transport_diag",
        "outdir": "violin-v-oss-fresh-cfi-20260722",
        "defines": ["CFI_TRANSPORT_ONLY_DIAG=1"],
        "strings_assert": "CFI_TRANSPORT_ONLY_START,CFI_TRANSPORT_SET_NAME,CFI_TRANSPORT_PWRITE",
    },
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def elf_description(path: Path) -> str:
    wsl_path = str(path).replace("E:\\", "/mnt/e/").replace("\\", "/")
    try:
        return subprocess.run(
            ["wsl.exe", "-e", "bash", "-lc", f"file {wsl_path}"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "ELF description unavailable; hash/size remain authoritative"


def main() -> None:
    source_hashes = {
        str(path.relative_to(EXPLOIT)).replace("\\", "/"): sha256(path)
        for path in SOURCE_FILES
    }
    results = []
    for case in CASES:
        output = EXPLOIT / "build" / case["outdir"] / "bin/preload.so"
        if not output.exists():
            raise SystemExit(f"missing build output: {output}")
        manifest_dir = OUT / f"fresh-{case['name']}-build-20260722"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        manifest = [
            "build_date=2026-07-22",
            "project=violin-v-oss",
            "target=Android arm64-v8a",
            "ndk_root=E:\\workspace\\projects\\xiaomi-root\\ndk",
            "ndk_revision=29.0.14206865",
        ]
        manifest.extend(f"compile_define={define}" for define in case["defines"])
        manifest += [
            f"output={output}",
            f"preload_sha256={sha256(output)}",
            f"preload_size={output.stat().st_size}",
            f"elf={elf_description(output)}",
            f"strings_assert={case['strings_assert']}",
            "source_hashes:",
        ]
        manifest.extend(f"  exploit-repo\\IonStack\\CVE-2026-43499\\exploit\\{rel} {digest}" for rel, digest in source_hashes.items())
        manifest += [
            "build_scope=source-bound diagnostic build only; no device run manifest yet",
            "runtime_allowed=false",
            "",
        ]
        path = manifest_dir / "build-manifest.txt"
        path.write_text("\n".join(manifest), encoding="utf-8")
        results.append(
            {
                "name": case["name"],
                "build_manifest": str(path.relative_to(ROOT)),
                "output": str(output),
                "preload_sha256": sha256(output),
                "preload_size": output.stat().st_size,
                "source_hashes": source_hashes,
                "runtime_allowed": False,
                "run_manifest": None,
            }
        )
    result = {
        "scope": "fresh local source-bound Violin diagnostic build manifests",
        "runtime_allowed": False,
        "cases": results,
        "all_build_outputs_present": True,
        "next_gate": "device run manifest with same preload hash and same boot_id",
    }
    (OUT / "violin-fresh-diag-builds-20260722.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
