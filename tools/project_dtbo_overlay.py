#!/usr/bin/env python3
"""Project a DTBO overlay onto a base DTB without writing a binary DTB.

This is intentionally a read-only semantic projection for audit reports.  It
resolves external symbol fixups, applies fragment properties/nodes to an
in-memory tree, and emits selected effective nodes.  It does not implement
libfdt's binary packing or claim that the JSON projection is flashable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from copy import deepcopy
from pathlib import Path


class Fdt:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if len(self.data) < 40 or self.data[:4] != b"\xd0\x0d\xfe\xed":
            raise ValueError(f"not an FDT: {path}")
        _, total, off_struct, off_strings, _, _, _, _, size_strings, size_struct = struct.unpack_from(
            ">10I", self.data, 0
        )
        if total > len(self.data):
            raise ValueError(f"truncated FDT: {path}")
        struct_data = self.data[off_struct : off_struct + size_struct]
        strings = self.data[off_strings : off_strings + size_strings]
        self.nodes: dict[str, dict] = {}
        stack: list[str] = []

        def string_at(off: int) -> str:
            end = strings.find(b"\0", off)
            if end < 0:
                raise ValueError("unterminated FDT string")
            return strings[off:end].decode("utf-8", "replace")

        pos = 0
        while pos + 4 <= len(struct_data):
            token = struct.unpack_from(">I", struct_data, pos)[0]
            pos += 4
            if token == 1:  # FDT_BEGIN_NODE
                end = struct_data.find(b"\0", pos)
                if end < 0:
                    raise ValueError("unterminated node name")
                name = struct_data[pos:end].decode("utf-8", "replace")
                pos = (end + 4) & ~3
                stack.append(name)
                path_name = "/" + "/".join(x for x in stack if x)
                if path_name == "//":
                    path_name = "/"
                self.nodes.setdefault(path_name, {"props": {}})
            elif token == 2:  # FDT_END_NODE
                if not stack:
                    raise ValueError("unbalanced FDT_END_NODE")
                stack.pop()
            elif token == 3:  # FDT_PROP
                length, nameoff = struct.unpack_from(">II", struct_data, pos)
                pos += 8
                raw = bytes(struct_data[pos : pos + length])
                pos = (pos + length + 3) & ~3
                path_name = "/" + "/".join(x for x in stack if x)
                if path_name == "//":
                    path_name = "/"
                self.nodes.setdefault(path_name, {"props": {}})["props"][string_at(nameoff)] = raw
            elif token == 4:  # FDT_NOP
                continue
            elif token == 9:  # FDT_END
                break
            else:
                raise ValueError(f"unknown FDT token {token} at {pos:#x}")
        self.total_size = total
        self.sha256 = hashlib.sha256(self.data[:total]).hexdigest()

    def prop(self, path: str, name: str) -> bytes | None:
        return self.nodes.get(path, {}).get("props", {}).get(name)


def split_strings(raw: bytes) -> list[str]:
    return [x.decode("utf-8", "replace") for x in raw.split(b"\0") if x]


def u32s(raw: bytes) -> list[int] | None:
    if len(raw) % 4:
        return None
    return list(struct.unpack(">" + "I" * (len(raw) // 4), raw))


def display(raw: bytes) -> object:
    if not raw:
        return True
    # DT cells/phandles start with a zero byte; they are numeric, not C strings
    # (for example <0x45> would otherwise be rendered as the ASCII "E").
    if len(raw) % 4 == 0 and raw and raw[0] == 0:
        vals = u32s(raw)
        return [f"0x{x:x}" for x in vals] if vals is not None else True
    if b"\0" in raw and all(c == 0 or 32 <= c < 127 or c in (9, 10, 13) for c in raw):
        vals = split_strings(raw)
        return vals[0] if len(vals) == 1 else vals
    vals = u32s(raw)
    if vals is not None:
        return [f"0x{x:x}" for x in vals]
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def base_symbols(base: Fdt) -> dict[str, str]:
    return {
        name: raw.rstrip(b"\0").decode("utf-8", "replace")
        for name, raw in base.nodes.get("/__symbols__", {}).get("props", {}).items()
    }


def phandle_map(base: Fdt) -> dict[int, str]:
    out: dict[int, str] = {}
    for path, node in base.nodes.items():
        for prop_name in ("phandle", "linux,phandle"):
            raw = node["props"].get(prop_name)
            vals = u32s(raw) if raw is not None else None
            if vals:
                out[vals[0]] = path
    return out


def apply_u32_fixup(tree: Fdt, location: str, value: int) -> bool:
    try:
        path, prop_name, offset = location.rsplit(":", 2)
        offset = int(offset)
    except ValueError:
        return False
    raw = tree.prop(path, prop_name)
    if raw is None or offset + 4 > len(raw):
        return False
    patched = bytearray(raw)
    struct.pack_into(">I", patched, offset, value)
    tree.nodes[path]["props"][prop_name] = bytes(patched)
    return True


def resolve_external_fixups(base: Fdt, overlay: Fdt) -> dict:
    symbols = base_symbols(base)
    handles = phandle_map(base)
    fixup_props = overlay.nodes.get("/__fixups__", {}).get("props", {})
    resolved = 0
    missing_symbols: list[str] = []
    failed_locations: list[str] = []
    for label, raw in fixup_props.items():
        target_path = symbols.get(label)
        if target_path is None:
            missing_symbols.append(label)
            continue
        target_handle = None
        for handle, path in handles.items():
            if path == target_path:
                target_handle = handle
                break
        if target_handle is None:
            failed_locations.append(f"{label}:no-phandle:{target_path}")
            continue
        for location in split_strings(raw):
            if apply_u32_fixup(overlay, location, target_handle):
                resolved += 1
            else:
                failed_locations.append(location)
    return {
        "symbol_count": len(symbols),
        "fixup_label_count": len(fixup_props),
        "resolved_location_count": resolved,
        "missing_symbols": sorted(missing_symbols),
        "failed_locations": sorted(failed_locations),
    }


def rebase_local_fixups(base: Fdt, overlay: Fdt) -> dict:
    """Apply the DTBO local-phandle delta in memory.

    libfdt offsets overlay-local phandles by the base tree's maximum phandle.
    The `__local_fixups__` tree contains byte offsets into overlay properties
    that reference those local phandles.  Leaving these values at their
    original small integers produces a structurally plausible but semantically
    wrong projection (notably pinctrl and internal node links).
    """
    base_handles = phandle_map(base)
    base_max = max(base_handles, default=0)
    # This is the libfdt fdt_find_max_phandle() result, not max+1.  Overlay
    # phandles are non-zero, so adding the base maximum maps overlay value 1
    # to max+1 without colliding with any base phandle.
    delta = base_max
    rebased_nodes = 0
    rebased_locations = 0

    # Rebase each overlay node's own phandle first.  Metadata trees are not
    # part of the applied overlay and must not be changed.
    for path, node in overlay.nodes.items():
        if path.startswith(("/__fixups__", "/__local_fixups__", "/__symbols__")):
            continue
        changed = False
        for prop_name in ("phandle", "linux,phandle"):
            raw = node["props"].get(prop_name)
            vals = u32s(raw) if raw is not None else None
            if not vals:
                continue
            patched = bytearray(raw)
            for i, value in enumerate(vals):
                struct.pack_into(">I", patched, i * 4, value + delta)
            node["props"][prop_name] = bytes(patched)
            changed = True
        if changed:
            rebased_nodes += 1

    # Apply byte offsets from the mirror __local_fixups__ tree.
    prefix = "/__local_fixups__"
    for fixup_path, fixup_node in overlay.nodes.items():
        if not fixup_path.startswith(prefix):
            continue
        target_path = fixup_path[len(prefix) :] or "/"
        target_node = overlay.nodes.get(target_path)
        if target_node is None:
            continue
        for prop_name, offset_raw in fixup_node["props"].items():
            offsets = u32s(offset_raw) or []
            raw = target_node["props"].get(prop_name)
            if raw is None:
                continue
            patched = bytearray(raw)
            for offset in offsets:
                if offset + 4 > len(patched):
                    continue
                value = struct.unpack_from(">I", patched, offset)[0]
                struct.pack_into(">I", patched, offset, value + delta)
                rebased_locations += 1
            target_node["props"][prop_name] = bytes(patched)
    return {
        "base_max_phandle": base_max,
        "local_phandle_delta": delta,
        "rebased_node_phandles": rebased_nodes,
        "rebased_location_count": rebased_locations,
    }


def child_paths(tree: Fdt, prefix: str) -> list[str]:
    return [p for p in tree.nodes if p.startswith(prefix + "/")]


def fragment_target(overlay: Fdt, fragment: str, phandles: dict[int, str]) -> tuple[str | None, str]:
    direct = overlay.prop(fragment, "target-path")
    if direct:
        return direct.rstrip(b"\0").decode("utf-8", "replace"), "target-path"
    raw = overlay.prop(fragment, "target")
    vals = u32s(raw) if raw is not None else None
    if vals and vals[0] in phandles:
        return phandles[vals[0]], "symbol-target"
    return None, "unresolved-target"


def merge_projection(base: Fdt, overlay: Fdt) -> dict:
    # Copy only ordinary nodes; metadata nodes are used for resolution, not merged.
    merged = {p: {"props": dict(n["props"])} for p, n in base.nodes.items()}
    base_handles = phandle_map(base)
    fragments = sorted(
        p for p in overlay.nodes if p.startswith("/fragment@") and p.count("/") == 1
    )
    stats = {
        "fragment_count": len(fragments),
        "target_path_count": 0,
        "symbol_target_count": 0,
        "unresolved_target_fragments": [],
        "nodes_added": 0,
        "properties_added": 0,
        "properties_overridden": 0,
    }
    for fragment in fragments:
        target, kind = fragment_target(overlay, fragment, base_handles)
        if target is None:
            stats["unresolved_target_fragments"].append(fragment)
            continue
        stats["target_path_count" if kind == "target-path" else "symbol_target_count"] += 1
        overlay_root = fragment + "/__overlay__"
        if overlay_root not in overlay.nodes:
            continue
        for source in [overlay_root] + child_paths(overlay, overlay_root):
            rel = source[len(overlay_root) :]
            dest = target + rel if target != "/" else rel or "/"
            if dest == "":
                dest = "/"
            if dest not in merged:
                merged[dest] = {"props": {}}
                stats["nodes_added"] += 1
            for name, raw in overlay.nodes[source]["props"].items():
                if name in ("target", "target-path"):
                    continue
                if name in merged[dest]["props"]:
                    stats["properties_overridden"] += 1
                else:
                    stats["properties_added"] += 1
                merged[dest]["props"][name] = raw
    return {"tree": merged, "stats": stats}


def selected_projection(merged: dict, patterns: list[str]) -> dict:
    selected: dict[str, dict] = {}
    for path, node in merged.items():
        if any(pattern in path for pattern in patterns):
            selected[path] = {
                name: display(raw) for name, raw in sorted(node["props"].items())
            }
    return selected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", type=Path, required=True)
    ap.add_argument("--overlay", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    base = Fdt(args.base)
    overlay = Fdt(args.overlay)
    fixups = resolve_external_fixups(base, overlay)
    local_fixups = rebase_local_fixups(base, overlay)
    projection = merge_projection(base, overlay)
    patterns = [
        "/chosen",
        "dsi_panel_o81a_0a_dualdsi_dsc_lcd_video",
        "xiaomi_touch",
        "xiaomi_keyboard",
        "xiaomi_hall",
        "/reserved-memory/",
    ]
    result = {
        "base": {"path": str(args.base), "sha256": base.sha256, "node_count": len(base.nodes)},
        "overlay": {"path": str(args.overlay), "sha256": overlay.sha256, "node_count": len(overlay.nodes)},
        "external_fixups": fixups,
        "local_fixups": local_fixups,
        "merge": projection["stats"],
        "selected_effective_nodes": selected_projection(projection["tree"], patterns),
        "note": "semantic projection only; not a packed or flashable merged DTB",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in ("external_fixups", "local_fixups", "merge")}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
