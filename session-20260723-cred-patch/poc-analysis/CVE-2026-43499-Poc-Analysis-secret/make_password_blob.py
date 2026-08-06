#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

CHALLENGE_ALPHABET = set("abcdefghijklmnopqrstuvwxyz0123456789")
CHALLENGE_LEN = 16
FNV_OFFSET = 1469598103934665603
FNV_PRIME = 1099511628211


def parse_int(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must not be a boolean")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        result = int(value, 0)
    else:
        raise ValueError(f"{name} must be an integer or 0x... string")
    if result <= 0:
        raise ValueError(f"{name} must be positive")
    return result


def load_private_key(path: Path) -> tuple[int, int, int]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    key = raw.get("rsa_private_key")
    if not isinstance(key, dict):
        raise ValueError("JSON must contain object field rsa_private_key")
    n = parse_int(key.get("n"), "rsa_private_key.n")
    e = parse_int(key.get("e"), "rsa_private_key.e")
    d = parse_int(key.get("d"), "rsa_private_key.d")
    if pow(pow(123456789, d, n), e, n) != 123456789:
        raise ValueError("private key self-check failed")
    return n, e, d


def challenge_hash(challenge: str, modulus: int) -> int:
    h = FNV_OFFSET
    for ch in challenge.encode("ascii"):
        h ^= ch
        h = (h * FNV_PRIME) & 0xffffffffffffffff
    return h % modulus


def validate_challenge(challenge: str) -> None:
    if len(challenge) != CHALLENGE_LEN:
        raise ValueError(f"challenge must be exactly {CHALLENGE_LEN} characters")
    bad = sorted(set(challenge) - CHALLENGE_ALPHABET)
    if bad:
        raise ValueError("challenge contains invalid characters: " + "".join(bad))


def make_signature(challenge: str, key_path: Path) -> int:
    validate_challenge(challenge)
    n, _, d = load_private_key(key_path)
    digest = challenge_hash(challenge, n)
    return pow(digest, d, n)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate the preload signature for a displayed challenge.",
    )
    parser.add_argument("challenge", help="challenge printed by preload.so")
    parser.add_argument(
        "--key",
        type=Path,
        default=Path(__file__).with_name("private_key.json"),
        help="private key JSON path",
    )
    args = parser.parse_args()

    signature = make_signature(args.challenge.strip(), args.key)
    print(f"0x{signature:016x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
