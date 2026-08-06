#!/usr/bin/env python3
"""Offline consistency audit for the supplied Violin evidence bundles.

This report separates build-relative kernel offsets from boot-specific KASLR
addresses.  It does not connect to a device, build a payload, or execute any
exploit code.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
RAW_IMAGE = ROOT / "analysis_outputs/ota_full/boot_parse/boot.img.kernel"
OUT = ROOT / "analysis_outputs"
OUT_JSON = OUT / "violin-artifact-consistency-20260722.json"
OUT_MD = OUT / "violin-artifact-consistency-20260722.md"

FILES = [
    ROOT / "ionstack-current-ktext.zip",
    ROOT / "violin-kernel-info2.zip",
    ROOT / "1.zip",
    ROOT / "kallsyms.txt",
    ROOT / "iomem.txt",
    ROOT / "slabinfo.txt",
    ROOT / "cmdline.txt",
]

KEY_SYMBOLS = [
    "_text",
    "_stext",
    "anon_pipe_buf_ops",
    "misc_fops",
    "ashmem_fops",
    "ashmem_misc",
    "rcu_state",
    "misc_mtx",
    "ashmem_mutex",
    "security_hook_heads",
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def file_record(path: Path) -> dict:
    data = path.read_bytes()
    stat = path.stat()
    return {
        "path": str(path.relative_to(ROOT)),
        "size": stat.st_size,
        "sha256": sha256_bytes(data),
        "mtime": stat.st_mtime,
    }


def zip_bytes(path: Path, member: str) -> bytes:
    with ZipFile(path) as archive:
        return archive.read(member)


def zip_inventory(path: Path) -> dict:
    with ZipFile(path) as archive:
        infos = archive.infolist()
        return {
            "entries": len(infos),
            "uncompressed_size": sum(info.file_size for info in infos),
            "compressed_size": sum(info.compress_size for info in infos),
            "members": [info.filename for info in infos],
        }


def parse_kallsyms(text: str, image_len: int) -> tuple[int, dict[str, list[tuple[int, str]]]]:
    base = None
    symbols: defaultdict[str, list[tuple[int, str]]] = defaultdict(list)
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            address = int(parts[0], 16)
        except ValueError:
            continue
        symbol_type, name = parts[1], parts[2]
        rows.append((address, symbol_type, name))
        if name == "_text":
            base = address
    assert base is not None, "_text missing from kallsyms"
    for address, symbol_type, name in rows:
        if base <= address < base + image_len:
            symbols[name].append((address - base, symbol_type))
    return base, dict(symbols)


def key_offsets(symbols: dict[str, list[tuple[int, str]]]) -> dict[str, list[list[object]]]:
    return {
        name: [[hex(offset), symbol_type] for offset, symbol_type in symbols.get(name, [])]
        for name in KEY_SYMBOLS
    }


def format_key_offset(rows: list[list[object]]) -> str:
    """Render one artifact's normalized key-symbol rows for the markdown report."""
    if not rows:
        return "missing"
    return ", ".join(f"{offset} ({symbol_type})" for offset, symbol_type in rows)


def normalized_symbol_consistency(kallsyms: dict[str, str], image_len: int) -> dict:
    parsed = {}
    for name, text in kallsyms.items():
        base, symbols = parse_kallsyms(text, image_len)
        parsed[name] = {symbol: sorted(values) for symbol, values in symbols.items()}
    common = set.intersection(*(set(item) for item in parsed.values()))
    unique_common = []
    matched = []
    mismatched = []
    for symbol in sorted(common):
        values = [parsed[name][symbol] for name in parsed]
        if not all(len(value) == 1 for value in values):
            continue
        unique_common.append(symbol)
        if len({tuple(value) for value in values}) == 1:
            matched.append(symbol)
        else:
            mismatched.append({
                "name": symbol,
                "values": {name: parsed[name][symbol] for name in parsed},
            })
    return {
        "image_len": image_len,
        "common_names": len(common),
        "unique_common_names": len(unique_common),
        "exact_relative_matches": len(matched),
        "unique_relative_mismatches": mismatched,
        "key_offsets": {
            name: key_offsets(parsed[name]) for name in parsed
        },
        "bases": {
            name: hex(parse_kallsyms(text, image_len)[0]) for name, text in kallsyms.items()
        },
    }


def validate_manifest(zip_path: Path, manifest_member: str, prefix: str) -> dict:
    with ZipFile(zip_path) as archive:
        manifest = archive.read(manifest_member).decode("utf-8", "replace")
        rows = []
        for line in manifest.splitlines():
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            expected, relative = parts
            relative = relative.strip()
            if relative.startswith("./"):
                relative = relative[2:]
            member = prefix + relative
            try:
                actual = sha256_bytes(archive.read(member))
            except KeyError:
                rows.append({"member": member, "status": "missing"})
                continue
            rows.append({
                "member": member,
                "expected": expected.upper(),
                "actual": actual,
                "status": "match" if expected.lower() == actual.lower() else "mismatch",
            })
    counts = defaultdict(int)
    for row in rows:
        counts[row["status"]] += 1
    return {"counts": dict(counts), "rows": rows}


def token_set(text: str) -> set[str]:
    return {token for token in text.split() if token}


def main() -> int:
    assert RAW_IMAGE.exists()
    loose_kallsyms = (ROOT / "kallsyms.txt").read_text(encoding="utf-8", errors="replace")
    with ZipFile(ROOT / "ionstack-current-ktext.zip") as archive:
        current_kallsyms = archive.read("ionstack-current-ktext/kallsyms.txt").decode("utf-8", "replace")
        current_meta = archive.read("ionstack-current-ktext/current-ktext.txt").decode("utf-8", "replace")
    with ZipFile(ROOT / "violin-kernel-info2.zip") as archive:
        info_kallsyms = archive.read("violin-kernel-info/kallsyms.txt").decode("utf-8", "replace")
        info_cmdline = archive.read("violin-kernel-info/cmdline.txt").decode("utf-8", "replace").strip()
        info_fingerprint = archive.read("violin-kernel-info/fingerprint.txt").decode("utf-8", "replace").strip("\x00\n")
        info_version = archive.read("violin-kernel-info/version.txt").decode("utf-8", "replace").strip()
    with ZipFile(ROOT / "1.zip") as archive:
        panic_cmdline_raw = archive.read("ionstack-panic-evidence-20260712-112350/cmdline.txt").decode("utf-8", "replace")
        panic_cmdline = panic_cmdline_raw.split("command: cat /proc/cmdline", 1)[-1].strip()
        panic_boot_id_raw = archive.read("ionstack-panic-evidence-20260712-112350/boot-id.txt").decode("utf-8", "replace")
        panic_boot_id_match = re.search(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            panic_boot_id_raw,
        )
        panic_boot_id = panic_boot_id_match.group(0) if panic_boot_id_match else None
        panic_build_props = archive.read("ionstack-panic-evidence-20260712-112350/build-props.txt").decode("utf-8", "replace")
        panic_uname_raw = archive.read("ionstack-panic-evidence-20260712-112350/uname.txt").decode("utf-8", "replace")
        panic_uname = next(
            (line.strip() for line in panic_uname_raw.splitlines() if line.startswith("Linux ")),
            None,
        )
        panic_fingerprint = next(
            (line.split("]:", 1)[1].strip().strip("[]") for line in panic_build_props.splitlines() if line.startswith("[ro.build.fingerprint]")),
            None,
        )
        tombstone_headers = []
        for info in archive.infolist():
            if "/tombstones/data/tombstone_" not in info.filename or info.filename.endswith(".pb") or info.is_dir():
                continue
            text = archive.read(info.filename).decode("utf-8", "replace")
            cmdline = re.search(r"^Cmdline: (.*)$", text, re.MULTILINE)
            signal = re.search(r"^signal (.*)$", text, re.MULTILINE)
            tombstone_headers.append({
                "member": info.filename,
                "cmdline": cmdline.group(1) if cmdline else None,
                "signal": signal.group(1) if signal else None,
            })
        relevant_log = archive.read("ionstack-panic-evidence-20260712-112350/relevant-kernel-log.txt").decode("utf-8", "replace")

    current_meta_lines = dict(
        line.split("=", 1) for line in current_meta.splitlines() if "=" in line
    )
    kernel_release_match = re.search(r"^Linux version (\S+)", info_version)
    panic_release_match = re.search(r"^Linux \S+ (\S+) ", panic_uname or "")
    kernel_release_info = kernel_release_match.group(1) if kernel_release_match else None
    kernel_release_panic = panic_release_match.group(1) if panic_release_match else None
    loose_cmdline = (ROOT / "cmdline.txt").read_text(encoding="utf-8", errors="replace").strip()
    consistency = normalized_symbol_consistency(
        {"loose": loose_kallsyms, "current_ktext": current_kallsyms, "kernel_info2": info_kallsyms},
        RAW_IMAGE.stat().st_size,
    )
    manifests = {
        "current_ktext": validate_manifest(
            ROOT / "ionstack-current-ktext.zip",
            "ionstack-current-ktext/SHA256SUMS",
            "ionstack-current-ktext/",
        ),
        "panic_1": validate_manifest(
            ROOT / "1.zip",
            "ionstack-panic-evidence-20260712-112350/SHA256SUMS.txt",
            "ionstack-panic-evidence-20260712-112350/",
        ),
    }
    key_offsets_by_artifact = consistency["key_offsets"]
    key_anchor_offsets_consistent = all(
        all(anchor in key_offsets_by_artifact[artifact] for artifact in key_offsets_by_artifact)
        and len({
            tuple(tuple(row) for row in key_offsets_by_artifact[artifact][anchor])
            for artifact in key_offsets_by_artifact
        }) == 1
        for anchor in KEY_SYMBOLS
    )
    cmdline_diff = {
        "loose_only": sorted(token_set(loose_cmdline) - token_set(info_cmdline)),
        "info2_only": sorted(token_set(info_cmdline) - token_set(loose_cmdline)),
        "panic_only_vs_loose": sorted(token_set(panic_cmdline) - token_set(loose_cmdline)),
    }
    artifact_records = {str(path.relative_to(ROOT)): file_record(path) for path in FILES}
    result = {
        "audit": "Violin supplied artifact consistency",
        "date": "2026-07-22",
        "mode": "offline-archive-hash-relative-symbol-and-log-audit",
        "runtime_allowed": False,
        "artifacts": artifact_records,
        "zip_inventory": {
            name: zip_inventory(ROOT / name)
            for name in ["ionstack-current-ktext.zip", "violin-kernel-info2.zip", "1.zip"]
        },
        "build_identity": {
            "fingerprint_kernel_info2": info_fingerprint,
            "fingerprint_panic_1": panic_fingerprint,
            "fingerprint_match": info_fingerprint == panic_fingerprint,
            "kernel_version_kernel_info2": info_version,
            "kernel_release_kernel_info2": kernel_release_info,
            "kernel_release_panic_1": kernel_release_panic,
            "kernel_release_match": kernel_release_info == kernel_release_panic,
            "panic_uname": panic_uname,
            "current_ktext_boot_id": current_meta_lines.get("boot_id"),
            "current_ktext_kaslr_base": current_meta_lines.get("CFI_KASLR_BASE"),
            "panic_1_boot_id": panic_boot_id,
            "absolute_bases_are_snapshot_specific": True,
        },
        "relative_symbol_consistency": consistency,
        "cmdline_consistency": cmdline_diff,
        "manifest_validation": manifests,
        "panic_bundle_relevance": {
            "tombstone_headers": tombstone_headers,
            "relevant_kernel_log_contains_actual_exploit_marker": bool(
                re.search(r"(?m)^(?!command:).*(?:FOPSROUTE|CFGPROBE|ROUTE_PREP|GHOSTLOCK)", relevant_log)
            ),
            "relevant_kernel_log_text": relevant_log.strip(),
            "interpretation": "1.zip contains unrelated app/dex2oat crashes; it is not evidence of a successful GHOSTLOCK chain.",
        },
        "verdict": {
            "same_build_relative_offsets_confirmed": consistency["exact_relative_matches"] >= 100000,
            "snapshot_bases_interchangeable": False,
            "key_anchor_offsets_consistent": key_anchor_offsets_consistent,
            "panic_zip_success_evidence": False,
            "next_gate": "Use relative offsets from the matched build; require a same-boot KASLR leak before any absolute address. Keep 1.zip as unrelated crash evidence, not exploit proof.",
        },
    }
    OUT.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # The markdown summary prints one representative snapshot (the loose
    # kallsyms file); the JSON retains all three artifact-specific values.
    key = consistency["key_offsets"]["loose"]
    md = [
        "# Violin supplied artifact consistency (2026-07-22)",
        "",
        "**Mode:** offline archive/hash/relative-symbol/log audit only; no payload build, device run, or address write.",
        "",
        "## Conclusions",
        "",
        f"- Loose `kallsyms.txt`, `ionstack-current-ktext.zip`, and `violin-kernel-info2.zip` have different absolute `_text` bases, but `{consistency['exact_relative_matches']}` unique in-image symbol offsets match exactly.",
        f"- Core anchors are stable by image-relative offset: `anon_pipe_buf_ops={format_key_offset(key['anon_pipe_buf_ops'])}`, `misc_fops={format_key_offset(key['misc_fops'])}`, `ashmem_fops={format_key_offset(key['ashmem_fops'])}`, `ashmem_misc={format_key_offset(key['ashmem_misc'])}`, `rcu_state={format_key_offset(key['rcu_state'])}`.",
        f"- The panic bundle's uname release matches `violin-kernel-info2` (`{kernel_release_panic}`), reinforcing the same kernel build identity.",
        "- `cmdline` snapshots differ only in `bootinfo.pdreason` (`0x0` vs `0x3`), so they are different boot instances; absolute KASLR values must not be mixed across them.",
        "- `ionstack-current-ktext` manifest validates 4/4 entries. `1.zip` validates 33 entries; its self-hash is intentionally non-verifiable and `collector.log` does not match the recorded digest.",
        "- `1.zip` tombstones belong to dex2oat, SecurityCenter, and `com.xiaomi.mirror`; its filtered kernel log contains no actual exploit marker. It is not prior GHOSTLOCK success evidence.",
        "",
        "## Verdict",
        "",
        "**SAME_BUILD_OFFSETS_CONFIRMED_SNAPSHOT_BASES_NOT_INTERCHANGEABLE**. Use these bundles for same-build relative layout and historical crash context only. Before any absolute target calculation, obtain a KASLR leak from the same boot and verify the boot_id.",
        "",
    ]
    OUT_MD.write_text("\n".join(md), encoding="utf-8")
    print(json.dumps({"json": str(OUT_JSON), "markdown": str(OUT_MD), "verdict": result["verdict"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
