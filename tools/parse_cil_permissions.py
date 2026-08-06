#!/usr/bin/env python3
"""Resolve a small, auditable subset of Android SELinux CIL offline.

This intentionally does not load or modify policy on a device.  It expands
typeattributeset expressions (including and/or/not) and projects allow,
neverallow, and dontaudit rules onto one subject type and selected target
types.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

Atom = str
SExpr = Atom | list["SExpr"]


def tokenize(text: str) -> list[str]:
    # CIL comments are line comments beginning with ';'.  Quoted strings are
    # retained as one token; the policy files used here do not need unescaping.
    lines = []
    for line in text.splitlines():
        if ";" in line:
            line = line.split(";", 1)[0]
        lines.append(line)
    return re.findall(r'"(?:\\.|[^"\\])*"|[()]|[^\s()]+', "\n".join(lines))


def parse_forms(text: str) -> list[SExpr]:
    tokens = tokenize(text)
    pos = 0

    def parse_one() -> SExpr:
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError("unexpected end of CIL")
        tok = tokens[pos]
        pos += 1
        if tok != "(":
            if tok == ")":
                raise ValueError("unexpected )")
            return tok
        out: list[SExpr] = []
        while pos < len(tokens) and tokens[pos] != ")":
            out.append(parse_one())
        if pos >= len(tokens):
            raise ValueError("unterminated CIL form")
        pos += 1
        return out

    forms: list[SExpr] = []
    while pos < len(tokens):
        forms.append(parse_one())
    return forms


class Policy:
    def __init__(self, forms: list[SExpr]):
        self.forms = forms
        self.types: set[str] = set()
        self.attributes: set[str] = set()
        self.exprs: dict[str, list[SExpr]] = defaultdict(list)
        self._cache: dict[str, set[str]] = {}
        self._collect_declarations()
        self.universe = set(self.types)

    def _collect_declarations(self) -> None:
        for form in self.forms:
            if not isinstance(form, list) or not form:
                continue
            head = form[0]
            if head == "type" and len(form) >= 2 and isinstance(form[1], str):
                self.types.add(form[1])
            elif head == "typeattribute" and len(form) >= 2 and isinstance(form[1], str):
                self.attributes.add(form[1])
            elif head == "typeattributeset" and len(form) >= 3 and isinstance(form[1], str):
                self.attributes.add(form[1])
                if len(form) == 3:
                    self.exprs[form[1]].append(form[2])
                else:
                    self.exprs[form[1]].append(form[2:])

    def eval_symbol(self, symbol: str, stack: frozenset[str] = frozenset()) -> set[str]:
        if symbol not in self.exprs:
            return {symbol}
        if symbol in self._cache:
            return set(self._cache[symbol])
        if symbol in stack:
            return set()
        result: set[str] = set()
        next_stack = stack | {symbol}
        for expr in self.exprs[symbol]:
            result |= self.eval_expr(expr, next_stack)
        self._cache[symbol] = set(result)
        return result

    def eval_expr(self, expr: SExpr, stack: frozenset[str] = frozenset()) -> set[str]:
        if isinstance(expr, str):
            return self.eval_symbol(expr, stack)
        if not expr:
            return set()
        op = expr[0] if isinstance(expr[0], str) else None
        children = expr[1:] if op in {"and", "or", "not"} else expr
        if op == "and":
            values = [self.eval_expr(x, stack) for x in children]
            return set.intersection(*values) if values else set()
        if op == "or":
            out: set[str] = set()
            for child in children:
                out |= self.eval_expr(child, stack)
            return out
        if op == "not":
            excluded: set[str] = set()
            for child in children:
                excluded |= self.eval_expr(child, stack)
            return self.universe - excluded
        out: set[str] = set()
        for child in expr:
            out |= self.eval_expr(child, stack)
        return out

    def resolve(self, symbol: str) -> set[str]:
        return self.eval_symbol(symbol)

    def subject_memberships(self, subject: str) -> list[dict[str, Any]]:
        rows = []
        for attr in sorted(self.attributes | set(self.exprs)):
            members = self.resolve(attr)
            if subject in members:
                rows.append({"attribute": attr, "size": len(members)})
        return rows

    def matching_rules(self, subject: str, targets: set[str]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for form in self.forms:
            if not isinstance(form, list) or len(form) < 4:
                continue
            kind = form[0]
            if kind not in {"allow", "neverallow", "dontaudit"}:
                continue
            if not isinstance(form[1], str) or not isinstance(form[2], str):
                continue
            source_set = self.resolve(form[1])
            target_set = self.resolve(form[2])
            matched_targets = sorted(target_set & targets)
            if subject not in source_set or not matched_targets:
                continue
            classes: dict[str, list[str]] = {}
            for clause in form[3:]:
                if not isinstance(clause, list) or not clause or not isinstance(clause[0], str):
                    continue
                cls = clause[0]
                perms: list[str] = []
                for item in clause[1:]:
                    if isinstance(item, str):
                        perms.append(item)
                    elif isinstance(item, list):
                        perms.extend(x for x in item if isinstance(x, str))
                classes[cls] = sorted(set(perms))
            out.append(
                {
                    "kind": kind,
                    "source": form[1],
                    "source_size": len(source_set),
                    "target": form[2],
                    "matched_targets": matched_targets,
                    "classes": classes,
                }
            )
        return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", action="append", required=True, type=Path)
    parser.add_argument("--subject", default="untrusted_app")
    parser.add_argument(
        "--target",
        action="append",
        required=True,
        help="target type to resolve; repeat for multiple types",
    )
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    all_rules: list[dict[str, Any]] = []
    policy_meta = []
    memberships: dict[str, list[dict[str, Any]]] = {}
    for path in args.policy:
        text = path.read_text(encoding="utf-8", errors="replace")
        forms = parse_forms(text)
        policy = Policy(forms)
        policy_meta.append(
            {
                "path": str(path),
                "sha256": hashlib.sha256(text.encode()).hexdigest().upper(),
                "forms": len(forms),
                "types": len(policy.types),
                "attributes": len(policy.attributes | set(policy.exprs)),
            }
        )
        memberships[str(path)] = policy.subject_memberships(args.subject)
        all_rules.extend(
            [{"policy": str(path), **rule} for rule in policy.matching_rules(args.subject, set(args.target))]
        )

    effective: dict[str, dict[str, dict[str, set[str]]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(set))
    )
    for rule in all_rules:
        for target in rule["matched_targets"]:
            for cls, perms in rule["classes"].items():
                effective[target][rule["kind"]][cls].update(perms)

    result = {
        "subject": args.subject,
        "targets": args.target,
        "policies": policy_meta,
        "subject_memberships": memberships,
        "matching_rules": all_rules,
        "effective": {
            target: {
                kind: {cls: sorted(perms) for cls, perms in classes.items()}
                for kind, classes in kinds.items()
            }
            for target, kinds in effective.items()
        },
    }
    if args.json:
        args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
