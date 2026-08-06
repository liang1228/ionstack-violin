#!/usr/bin/env python3
"""Build a bounded offline state table for Violin pselect/custom-shape paths.

This tool only reconciles existing source, same-build image, and prior offline
audit outputs.  It does not build, install, connect to a device, change fd-set
constants, or execute a payload.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLOIT = ROOT / "exploit-repo/IonStack/CVE-2026-43499/exploit"
SRC_UTIL = EXPLOIT / "src/util.c"
SRC_FOPS = EXPLOIT / "src/fops.c"
SRC_MAIN = EXPLOIT / "src/main.c"
IMAGE = ROOT / "analysis_outputs/ota_full/boot_parse/boot.img.kernel"
MAPPING = ROOT / "analysis_outputs/violin-pselect-mapping-audit-20260719.json"
RB = ROOT / "analysis_outputs/violin-rb-erase-postwrite-state-20260722.json"
PRIMARY = ROOT / "analysis_outputs/violin-primary-fops-gate-20260722.json"
OUT = ROOT / "analysis_outputs"

IMAGE_BASE = 0xFFFFFFC080000000
ASHMEM_FOPS_OFF = 0x12C9DF0
ASHMEM_MISC_OFF = 0x223B5D8


def qword(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    util = SRC_UTIL.read_text(encoding="utf-8")
    fops = SRC_FOPS.read_text(encoding="utf-8")
    main_c = SRC_MAIN.read_text(encoding="utf-8")
    image = IMAGE.read_bytes()
    mapping = load(MAPPING)
    rb = load(RB)
    primary = load(PRIMARY)

    target = IMAGE_BASE + ASHMEM_MISC_OFF + 0x10
    predecessor = target - 8
    ashmem_fops = IMAGE_BASE + ASHMEM_FOPS_OFF
    raw_predecessor_left = qword(image, ASHMEM_MISC_OFF + 0x18)
    raw_predecessor_right = qword(image, ASHMEM_MISC_OFF + 0x10)

    source_checks = {
        "active_poll_fd_minus_one": "pfd[0] = -1" in fops,
        "active_poll_call": "poll((struct pollfd *)pselect_user_lock, 1" in fops,
        "fake_w0_lock_is_user_pointer":
            "FAKE_WAITER_LOCK_OFF, (uint64_t)(uintptr_t)pselect_user_lock" in util,
        "shape1_parent_predecessor": "fake_parent = write_target - 8" in util,
        "shape1_writes_target_value_pair":
            "write_pc = write_target - 8" in util and
            "write_right = write_value" in util and
            "write_left = 0" in util,
        # Activation is recorded from the existing main-path audit; this
        # source check only confirms that the normal route and explicit probe
        # entry points coexist, rather than treating a probe call as active.
        "normal_route_and_probe_entry_points_present": (
            "run_main_route_threads();" in main_c and
            "DIRECT_WRITE_ONLY_DIAG" in main_c and
            "PSELECT_LAYOUT_ONLY_PROBE" in main_c
        ),
    }

    mapping64 = mapping["violin_shift_0"]
    mapping257 = mapping["comparison_stale_lock_copy_windows"]["257"]
    mapping_checks = {
        "configured_nfds_64": mapping["configured_nfds"] == 64,
        "nfds64_target_dropped": mapping64["write_target_survives"] is False,
        "nfds64_fake_lock_dropped": any(
            row["name"] == "fake_lock" and row["destination"].startswith("dropped")
            for row in mapping64["rows"]
        ),
        "minimum_nfds_257": mapping["violin_shift_0"]["minimum_nfds_for_all_words"] == 257,
        "nfds257_stale_lock_in_input": mapping257["stale_lock_copy_overlap"] is True,
        "nfds257_stale_lock_not_result": mapping257["stale_lock_in_result_copy"] is False,
    }

    raw_checks = {
        "target_slot_points_to_ashmem_fops": raw_predecessor_right == ashmem_fops,
        "predecessor_left_not_fake_w0": raw_predecessor_left == 0,
        "predecessor_right_is_table_value": raw_predecessor_right == ashmem_fops,
        "primary_gate_raw_checks_pass": all(primary["raw_checks"].values()),
    }

    cases = [
        {
            "case": "active_poll_shape0",
            "activation": "default run_main_route_threads path",
            "stale_lock_source": "zeroed kernel poll_wqueues; fd=-1 skips do_pollfd/vfs_poll/poll_wait",
            "stale_lock_gate": "NO-SOURCE-EDGE",
            "pselect_overlay": "not used",
            "rb_target": "T-NOT-REACHED (default shape0 erase writes F.rb_right=N)",
            "owner_gate": "not reached",
            "verdict": "STOP_ACTIVE_ROUTE",
        },
        {
            "case": "hypothetical_pselect64_shape0",
            "activation": "custom pselect branch with current PSELECT_ROUTE_NFDS=64",
            "stale_lock_source": "waiter lock lies outside the copied fd-set window",
            "stale_lock_gate": "BLOCKED_MAPPING",
            "pselect_overlay": "write_value survives in ex[0], target/fake_lock and remaining waiter words drop",
            "rb_target": "NOT-REACHED",
            "owner_gate": "not reached",
            "verdict": "STOP_NFDS64_MAPPING",
        },
        {
            "case": "hypothetical_pselect257_shape0",
            "activation": "independent 12-word field table, not current builder",
            "stale_lock_source": "ex[1] input word can carry stale waiter->lock; it is not in result copy",
            "stale_lock_gate": "CONDITIONAL_FAKE_LOCK",
            "pselect_overlay": "stale lock can be fake_lock, but fake_w0->lock remains user VA",
            "rb_target": "T-NOT-REACHED (shape0)",
            "owner_gate": "not reached",
            "verdict": "STOP_SECOND_LOCK_USER_VA",
        },
        {
            "case": "hypothetical_pselect257_shape1",
            "activation": "explicit custom shape1 plus independent 12-word pselect table",
            "stale_lock_source": "ex[1] input word can carry stale waiter->lock",
            "stale_lock_gate": "CONDITIONAL_FAKE_LOCK",
            "pselect_overlay": "fake_w0->lock is still pselect_user_lock; next lock is not a kernel rt_mutex",
            "rb_target": "CONDITIONAL T:=F after pi-tree erase and PI dequeue identity",
            "predecessor_gate": "CLOSED under misc_register list invariant: N.rb_left=misc_list.next != W, so right-child arm writes T",
            "rb_post_state": "root remains W, leftmost becomes F, RB_CLEAR_NODE(W); same-waiter enqueue follows W->F->W",
            "owner_gate": "F.owner:=N; fresh open/try_module_get and owner repair remain runtime-uncLOSED",
            "verdict": "STOP_TARGET_CONDITIONAL_AND_CONSUMER_BROKEN",
        },
    ]

    result = {
        "audit": "Violin bounded pselect/custom-shape state table",
        "date": "2026-07-22",
        "mode": "offline-source-image-and-existing-audit-only",
        "runtime_allowed": False,
        "sources": {
            "util_c": str(SRC_UTIL),
            "fops_c": str(SRC_FOPS),
            "main_c": str(SRC_MAIN),
            "mapping": str(MAPPING),
            "rb_postwrite": str(RB),
            "primary_gate": str(PRIMARY),
            "raw_image": str(IMAGE),
        },
        "address_state": {
            "target_T": hex(target),
            "predecessor_N": hex(predecessor),
            "ashmem_fops": hex(ashmem_fops),
            "raw_N_rb_left": hex(raw_predecessor_left),
            "raw_N_rb_right": hex(raw_predecessor_right),
        },
        "source_checks": source_checks,
        "mapping_checks": mapping_checks,
        "raw_checks": raw_checks,
        "cases": cases,
        "cross_case_conclusion": {
            "active_route": "poll fd=-1 has no user-lock source edge",
            "pselect64": "deterministically incomplete mapping",
            "pselect257": "only a hypothetical stale-lock overlay; second lock and readiness remain separate gates",
            "shape1": "predecessor branch is structurally supported; PI dequeue identity, post-erase consumer, and owner repair remain unclosed",
            "primary_verdict": "PSELECT_CUSTOM_SHAPE_STATE_NOT_CLOSED",
        },
        "next_gate": (
            "Do not change nfds, enable shape1, rebuild, or run a device test.  Keep this branch "
            "archived unless a new offline proof supplies (1) PI dequeue/top-waiter identity, "
            "(2) a kernel address for fake_w0->lock, (3) a terminating post-erase rb_add state, "
            "and (4) a valid owner-repair/transport ordering."
        ),
    }
    OUT.mkdir(exist_ok=True)
    out_json = OUT / "violin-pselect-custom-shape-state-20260722.json"
    out_md = OUT / "violin-pselect-custom-shape-state-20260722.md"
    out_json.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    md = [
        "# Violin bounded pselect/custom-shape state table (2026-07-22)",
        "",
        "Offline source/raw-image/existing-report reconciliation only; no build, install, fd-set change, device connection, or payload execution.",
        "",
        "## Address facts",
        "",
        f"- `T=ashmem_misc+0x10` = `{hex(target)}`; `N=T-0x08` = `{hex(predecessor)}`.",
        f"- Raw `N.rb_left=0`, `N.rb_right=&ashmem_fops` = `{hex(ashmem_fops)}`; after `misc_register()`, `N.rb_left` aliases `misc_list.next`, not payload-page `W` under the current no-corruption model.",
        "",
        "## State table",
        "",
        "| Case | Stale-lock source | Target/erase state | Owner/transport | Verdict |",
        "| --- | --- | --- | --- | --- |",
    ]
    for c in cases:
        md.append(
            f"| `{c['case']}` | {c['stale_lock_gate']} — {c['stale_lock_source']} | "
            f"{c['rb_target']} | {c.get('owner_gate', '—')} | **{c['verdict']}** |"
        )
    md += [
        "",
        "## Explicit blockers",
        "",
        "1. Current poll route never sources `fake_w0->lock` from `pselect_user_lock`.",
        "2. Current `nfds=64` custom mapping drops target, fake lock, task, and tail words; `nfds>=257` is only a hypothetical field-table condition.",
        "3. Shape-1 reaches `T:=F` when the PI erase is reached: `N.rb_left != W` selects the right-child arm, and the misc list invariant supports that branch.",
        "4. After the conditional erase, the same-waiter enqueue has a `W→F→W` non-terminating traversal; `F.owner:=N` also leaves fresh-open/owner repair unresolved.",
        "",
        "## Verdict",
        "",
        "**PSELECT_CUSTOM_SHAPE_STATE_NOT_CLOSED**. Keep the active poll route frozen and do not turn the hypothetical pselect/shape-1 rows into runtime instructions.",
        "",
        "## Next gate",
        "",
        result["next_gate"],
    ]
    out_md.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
