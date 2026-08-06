#!/usr/bin/env python3
"""Offline state transition model for the first rt_mutex chain step.

The model follows the matching 6.6 rtmutex/rbtree source and the same-build
raw layout.  It is deliberately symbolic: it does not open a device, build a
payload, access adb, or execute kernel-facing code.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List


NULL = "NULL"
TARGET_MINUS_8 = "ashmem_misc+0x10-8"
TARGET_SLOT = "ashmem_misc+0x10"
FAKE_LOCK = "fake_lock"
FAKE_W0 = "fake_w0"
FAKE_W0_PI = "fake_w0.pi_tree"
FAKE_TASK = "fake_task"
FAKE_FOPS = "fake_fops"
STALE = "stale_waiter"
ASHMEM_FOPS = "ashmem_fops"
NOOP_LLSEEK = "noop_llseek"
USER_LOCK = "pselect_user_lock (user VA)"
NOOP_RAW_RIGHT = "raw_text_qword(noop+0x08)=0xd503233fe61887de"


@dataclass
class RbNode:
    parent: str = NULL
    right: str = NULL
    left: str = NULL
    prio: int | str = 0
    deadline: int | str = 0
    color: str = "black"


@dataclass
class Tree:
    root: str = NULL
    leftmost: str = NULL
    nodes: Dict[str, RbNode] = field(default_factory=dict)


def make_state(task_prio: int) -> tuple[Tree, Tree, Dict[str, RbNode], List[str]]:
    """Build the W=5 pselect candidate from active source/raw field meanings."""
    nodes = {
        # First lock waiter tree: pselect word 0..2 make the stale tree node
        # parent/children NULL.  word 3/4 are overwritten by waiter_update_prio.
        STALE: RbNode(parent=NULL, right=NULL, left=NULL,
                      prio=0x42424242, deadline=0x43434343),
        FAKE_W0: RbNode(parent=NULL, right=NULL, left=NULL, prio=130,
                        deadline=0),
        # FOPS payload fake_w0.pi_tree: parent=color=fake_fops, right=NULL,
        # left=target-8.  This is the node removed from fake_task.pi_waiters.
        FAKE_W0_PI: RbNode(parent=FAKE_FOPS, right=NULL,
                           left=TARGET_MINUS_8, prio=130, deadline=0),
        # Raw fake_fops qwords: owner=0, llseek=fake_w0.pi_tree, read=0,
        # write=0, read_iter=configfs_read_iter.  Interpreted as rb_node /
        # rt_waiter_node fields this gives a black synthetic node with prio 0.
        FAKE_FOPS: RbNode(parent=NULL, right=FAKE_W0_PI, left=NULL,
                          prio=0, deadline="configfs_read_iter"),
        # ashmem_misc+0x08 after rb_erase writes fake_fops to the name slot.
        # Its rb_right is the fops pointer slot, whose raw value is ashmem_fops.
        TARGET_MINUS_8: RbNode(parent=FAKE_FOPS, right=ASHMEM_FOPS,
                               left=NULL, prio=0, deadline=0),
        # Same-build raw ashmem_fops: write(+0x18)=NULL => prio 0; llseek(+0x08)
        # is a text address, so the next traversal leaves the controlled model.
        ASHMEM_FOPS: RbNode(parent=NULL, right=NOOP_LLSEEK, left=NULL,
                            prio=0, deadline="ashmem_read_iter"),
        # Same-build raw bytes at noop_llseek.  The qword at +0x18 is the
        # synthetic prio field and is negative as a signed 32-bit value; the
        # right child at +0x08 is a non-canonical instruction qword.
        NOOP_LLSEEK: RbNode(parent="raw_text_qword(noop+0x00), black",
                            right=NOOP_RAW_RIGHT,
                            left="raw_text_qword(noop+0x10)",
                            prio=-1459464202,
                            deadline="raw_text_qword(noop+0x20)"),
    }
    lock_tree = Tree(root=FAKE_W0, leftmost=FAKE_W0,
                     nodes={STALE: nodes[STALE], FAKE_W0: nodes[FAKE_W0]})
    pi_tree = Tree(root=FAKE_W0_PI, leftmost=FAKE_W0_PI,
                   nodes={FAKE_W0_PI: nodes[FAKE_W0_PI]})
    events = [f"candidate_task_prio={task_prio}"]
    return lock_tree, pi_tree, nodes, events


def erase_stale_lock_waiter(lock: Tree, events: List[str]) -> None:
    """Exact first branch for stale tree parent=NULL, children=NULL."""
    node = lock.nodes[STALE]
    if lock.leftmost == STALE:
        events.append("lock.leftmost=rb_next(stale) [not expected: stale != fake_w0]")
        lock.leftmost = NULL
    # Matching rb_erase sees parent=0 and no children, then writes root=NULL.
    if node.parent == NULL and node.left == NULL and node.right == NULL:
        lock.root = NULL
        events.append("rb_erase_cached(lock.waiters, stale): lock.root=NULL")
    else:
        events.append("rb_erase_cached(lock.waiters, stale): shape not modeled")


def enqueue_stale_lock_waiter(lock: Tree, task_prio: int, events: List[str]) -> None:
    node = lock.nodes[STALE]
    node.parent = NULL
    node.left = NULL
    node.right = NULL
    node.prio = task_prio
    node.deadline = "task->dl.deadline"
    lock.root = STALE
    lock.leftmost = STALE
    events.extend([
        "waiter_update_prio(stale, task): stale.tree.prio=task->prio",
        "rb_add_cached(lock.waiters, stale): root=stale, leftmost=stale",
    ])


def erase_fake_w0_pi(pi: Tree, nodes: Dict[str, RbNode], events: List[str]) -> None:
    """Model the write-relevant rb_erase_cached(fake_w0.pi_tree)."""
    node = nodes[FAKE_W0_PI]
    if pi.leftmost == FAKE_W0_PI:
        # rb_next(fake_w0.pi_tree): fake_fops->right points to the node and
        # fake_fops has NULL parent, so the cached leftmost becomes NULL.
        pi.leftmost = NULL
        events.append("rb_erase_cached(fake_task.pi_waiters, fake_w0): leftmost=NULL")
    if node.parent == FAKE_FOPS and node.right == NULL and node.left == TARGET_MINUS_8:
        # rb_erase's one-child branch: root is replaced by left and the child
        # parent/color is written.  This is ashmem_misc+0x08, not +0x10.
        pi.root = TARGET_MINUS_8
        nodes[TARGET_MINUS_8].parent = FAKE_FOPS
        events.extend([
            "rb_erase(fake_w0.pi_tree): pi_root=ashmem_misc+0x10-8",
            "WRITE [ashmem_misc+0x10-8] = fake_fops",
            "TARGET_SLOT ashmem_misc+0x10 remains ashmem_fops",
        ])
        node.parent = FAKE_W0_PI
        node.left = NULL
        node.right = NULL
    else:
        events.append("rb_erase(fake_w0.pi_tree): unexpected shape")


def enqueue_stale_pi(pi: Tree, nodes: Dict[str, RbNode], task_prio: int,
                     events: List[str]) -> dict:
    """Follow rb_add_cached until it reaches an uncontrolled text node."""
    node = nodes[STALE]
    node.prio = task_prio
    node.deadline = 0
    cursor = pi.root
    hops = []
    while cursor != NULL:
        if cursor not in nodes:
            hops.append({"node": cursor, "result": "UNKNOWN_TEXT_OR_UNMAPPED"})
            events.append(f"pi rb_add traversal leaves model at {cursor}")
            return {
                "hops": hops,
                "link": "UNKNOWN",
                "target_slot_written": "UNKNOWN_AFTER_ROTATION",
                "status": "unknown_after_static_fops",
            }
        current_name = cursor
        current = nodes[cursor]
        if isinstance(current.prio, str):
            hops.append({"node": current_name, "prio": current.prio,
                         "branch": "UNKNOWN"})
            events.append(f"pi rb_add compares against symbolic-prio node {cursor}")
            return {
                "hops": hops,
                "link": "UNKNOWN",
                "target_slot_written": "UNKNOWN_AFTER_ROTATION",
                "status": "unknown_symbolic_prio",
            }
        if node.prio < current.prio:
            branch = "left"
            cursor = current.left
        else:
            branch = "right"
            cursor = current.right
        hops.append({"node": current_name,
                     "prio": current.prio, "branch": branch,
                     "next": cursor})
        if current_name == NOOP_LLSEEK and cursor == NOOP_RAW_RIGHT:
            events.append("noop_llseek raw +0x18 prio is negative; right child is non-canonical text qword")
            return {
                "hops": hops,
                "link": "NOT_REACHED",
                "target_slot_written": False,
                "status": "noncanonical_text_pointer_before_link",
            }
    events.append("rb_link_node(stale.pi_tree): link location is after uncontrolled traversal")
    return {
        "hops": hops,
        "link": "UNKNOWN",
        "target_slot_written": False,
        "status": "unknown_link_location",
    }


def run(task_prio: int) -> dict:
    lock, pi, nodes, events = make_state(task_prio)
    before = {
        "lock_root": lock.root,
        "lock_leftmost": lock.leftmost,
        "pi_root": pi.root,
        "pi_leftmost": pi.leftmost,
        "target_slot": "ashmem_fops",
    }
    erase_stale_lock_waiter(lock, events)
    enqueue_stale_lock_waiter(lock, task_prio, events)
    prerequeue_top = FAKE_W0
    owner_branch = lock.leftmost == STALE
    if owner_branch:
        events.append("waiter == rt_mutex_top_waiter(lock): true")
        erase_fake_w0_pi(pi, nodes, events)
        events.append("waiter_clone_prio(stale, fake_task)")
        pi_result = enqueue_stale_pi(pi, nodes, task_prio, events)
    else:
        events.append("waiter == rt_mutex_top_waiter(lock): false")
        pi_result = {"status": "owner_pi_branch_not_reached"}
    return {
        "task_prio": task_prio,
        "before": before,
        "after_lock_requeue": {
            "lock_root": lock.root,
            "lock_leftmost": lock.leftmost,
            "prerequeue_top": prerequeue_top,
            "owner_branch": owner_branch,
        },
        "after_pi_dequeue": {
            "pi_root": pi.root,
            "pi_leftmost": pi.leftmost,
            "target_slot": "ashmem_fops",
        },
        "pi_enqueue": pi_result,
        "events": events,
        "second_chain_lock": USER_LOCK,
        "second_chain_status": (
            "next rt_mutex_adjust_prio on fake_w0 would consume a user VA as lock"
            if owner_branch else "not reached"
        ),
    }


def main() -> None:
    print(json.dumps({
        "scope": "HEAD W=5 pselect candidate only; active worktree remains poll/nfds=64",
        "task_prio_candidates": {
            "nice19": run(139),
            "nice0": run(120),
        },
        "hard_limitations": [
            "rb_insert_color is not reached in the static non-canonical branch",
            "vendor scheduler hooks and exact stale waiter lifetime are not modeled",
            "default active route is poll(fd=-1,nfds=1), so this is not runtime evidence",
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
