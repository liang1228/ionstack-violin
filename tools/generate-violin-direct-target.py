#!/usr/bin/env python3
"""Run popsicle's strict target generator with violin's kallsyms prefix.

Violin's Image starts `_text`, `_stext`, `__irqentry_text_start`; the upstream
generator only recognizes the popsicle-specific `_text`, `__pi__text`, `_stext`
prefix.  The rest of its boot-image, IKCONFIG, and full-table validation remains
unchanged.
"""

from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path


REFERENCE = (
    Path(__file__).parents[1]
    / "analysis_outputs"
    / "references"
    / "CVE-2026-43499-popsicle"
    / "generate_target.py"
)
spec = importlib.util.spec_from_file_location("popsicle_target_generator", REFERENCE)
if spec is None or spec.loader is None:
    raise RuntimeError(f"cannot load reference generator: {REFERENCE}")
generator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = generator
spec.loader.exec_module(generator)


def locate_violin_u32_offset_table(data, names, token_index_off, image_size):
    prefix = [name for _, name in names[:3]]
    if prefix != ["_text", "_stext", "__irqentry_text_start"]:
        generator.fail(f"violin kallsyms prefix mismatch: {names[:3]!r}")
    signature = struct.pack("<III", 0, 0x10000, 0x10000)
    table_bytes = len(names) * 4
    candidates = []
    pos = token_index_off + 512
    while True:
        pos = data.find(signature, pos)
        if pos < 0:
            break
        if pos & 3 or pos + table_bytes > len(data):
            pos += 1
            continue
        values = struct.unpack_from(f"<{len(names)}I", data, pos)
        if (
            values[-1] == image_size
            and not any(value > image_size for value in values)
            and all(values[i] <= values[i + 1] for i in range(len(values) - 1))
        ):
            candidates.append((pos, values))
        pos += 4
    if len(candidates) != 1:
        generator.fail(
            "violin u32 base-relative kallsyms table candidates: "
            + repr([hex(offset) for offset, _ in candidates])
        )
    return candidates[0]


generator.locate_u32_offset_table = locate_violin_u32_offset_table

if __name__ == "__main__":
    raise SystemExit(generator.main())
