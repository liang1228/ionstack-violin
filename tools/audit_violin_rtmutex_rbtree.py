#!/usr/bin/env python3
"""Offline model of the first rt_mutex rbtree requeue step.

This intentionally models symbolic addresses only.  It does not open a device,
build a payload, talk to adb, or execute any kernel-facing code.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, Optional


NULL = "NULL"
VALUE = "write_value"
TARGET = "write_target"
FAKE_FOPS = "fake_fops"
FAKE_W0 = "fake_w0"
FAKE_W0_PI = "fake_w0.pi_tree"
STALE = "stale_waiter.tree"


@dataclass
class Node:
    parent: str = NULL
    right: str = NULL
    left: str = NULL
    prio: int = 0
    deadline: str = "0"


@dataclass
class CachedTree:
    root: str
    leftmost: str
    nodes: Dict[str, Node] = field(default_factory=dict)


def build(shape: int, value_ref: str) -> CachedTree:
    # prepare_skb_payload(): fake_lock->waiters points at fake_w0 and uses it
    # as rb_leftmost.  The pselect W=5 overlay starts at the stale waiter's
    # tree node, i.e. in[0..4].
    stale = Node(
        parent=NULL,
        right=NULL,
        left=value_ref,
        prio=0,
        deadline=TARGET,
    )
    fake_w0 = Node(parent="1", right=NULL, left=NULL, prio=130, deadline="0")
    # The first four file_operations qwords are owner/llseek/read/write.  When
    # the stale node is treated as the tree root's child, these are the fields
    # rb_add_cached() reads from fake_fops as a synthetic rt_waiter_node.
    fake_fops = Node(
        parent=NULL,
        right=FAKE_W0_PI,
        left=NULL,
        prio=0,
        deadline="configfs_read_iter",
    )
    fake_w0_pi = Node(
        parent=(TARGET + "-8") if shape == 1 else "write_value",
        right=value_ref,
        left=NULL if shape == 1 else TARGET,
        prio=130,
        deadline="0",
    )
    return CachedTree(
        root=FAKE_W0,
        leftmost=FAKE_W0,
        nodes={
            STALE: stale,
            FAKE_W0: fake_w0,
            FAKE_FOPS: fake_fops,
            FAKE_W0_PI: fake_w0_pi,
        },
    )


def erase_cached(tree: CachedTree, node_name: str) -> list[str]:
    """Model the root/leftmost effects relevant before color repair."""
    node = tree.nodes[node_name]
    events = []
    if tree.leftmost == node_name:
        tree.leftmost = NULL
        events.append("leftmost=rb_next(stale)")

    # rb_erase() sees parent=NULL and one child (write_value).  The kernel
    # helper writes the child parent/color and replaces root with that child.
    if node.parent == NULL:
        if node.left != NULL and node.right == NULL:
            tree.root = node.left
            events.append("root=stale.left(write_value)")
        elif node.right != NULL and node.left == NULL:
            tree.root = node.right
            events.append("root=stale.right")
        elif node.left == NULL and node.right == NULL:
            tree.root = NULL
            events.append("root=NULL")
        else:
            events.append("two-child-erase-requires-successor")
    else:
        events.append("non-root-erase-not-modeled")
    return events


def add_cached(tree: CachedTree, node_name: str) -> list[str]:
    node = tree.nodes[node_name]
    events = []
    cursor = tree.root
    parent: Optional[str] = None
    leftmost = True
    hops = []
    while cursor != NULL:
        parent = cursor
        parent_node = tree.nodes.get(cursor)
        if parent_node is None:
            events.append(f"DEREF_UNKNOWN:{cursor}")
            break
        # rt_waiter_node_less(): prio 0 is not less than a non-RT fake node;
        # no deadline comparison is needed for these non-RT priorities.
        if node.prio < parent_node.prio:
            hops.append(f"{cursor}.left")
            cursor = parent_node.left
        else:
            hops.append(f"{cursor}.right")
            cursor = parent_node.right
            leftmost = False
    if parent is not None and cursor == NULL:
        events.append(f"link:{parent}->{node_name}:{'left' if hops[-1].endswith('.left') else 'right'}")
    if leftmost:
        tree.leftmost = node_name
        events.append("leftmost=stale")
    return events


def run(shape: int, value_ref: str) -> dict:
    tree = build(shape, value_ref)
    before_root, before_leftmost = tree.root, tree.leftmost
    erase_events = erase_cached(tree, STALE)
    after_erase_root, after_erase_leftmost = tree.root, tree.leftmost
    add_events = add_cached(tree, STALE)
    # rt_mutex_adjust_prio_chain() compares waiter with top_waiter and then
    # chooses dequeue_pi only if it is the cached leftmost node.
    prerequeue_top = FAKE_W0
    top_after = tree.leftmost
    return {
        "shape": shape,
        "value_ref": value_ref,
        "before": {"root": before_root, "leftmost": before_leftmost},
        "erase": erase_events,
        "after_erase": {"root": after_erase_root, "leftmost": after_erase_leftmost},
        "add": add_events,
        "after_add": {"root": tree.root, "leftmost": tree.leftmost},
        "prerequeue_top_waiter": prerequeue_top,
        "top_waiter_after_requeue": top_after,
        "stale_is_top_after_requeue": top_after == STALE,
        "pi_tree_dequeue_branch": top_after == STALE,
        "interpretation": (
            "first tree requeue leaves cached leftmost at fake_w0; "
            "the rt_mutex_dequeue_pi branch is not reached"
            if top_after != STALE
            else "stale waiter becomes cached top; pi_tree dequeue branch is reachable"
        ),
    }


def main() -> None:
    print(json.dumps({
        "fake_fops_value": {"shape0": run(0, FAKE_FOPS), "shape1": run(1, FAKE_FOPS)},
        "arbitrary_kernel_value": {"shape0": run(0, "arbitrary_kernel_value"), "shape1": run(1, "arbitrary_kernel_value")},
    }, indent=2))


if __name__ == "__main__":
    main()
