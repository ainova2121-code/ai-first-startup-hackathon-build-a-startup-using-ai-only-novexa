"""Hashing primitives for the audit ledger: canonical encoding, event hashes, a Merkle tree.

The tree follows RFC 6962 (leaf = H(0x00 || h), node = H(0x01 || l || r), split at the largest
power of two below n), so a single event can be proven part of a sealed root with a short
inclusion path (verified per RFC 9162 §2.1.3) without revealing the rest of the log.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "0" * 64
MAX_PROOF_DEPTH = 64  # a tree of 2**64 leaves; anything longer is hostile input


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def event_hash(prev: str, core: dict) -> str:
    return hashlib.sha256(prev.encode() + canonical(core)).hexdigest()


def _leaf(hash_hex: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(hash_hex)).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly below n (n > 1)."""
    return 1 << ((n - 1).bit_length() - 1)


def _tree_hash(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return _node(_tree_hash(leaves[:k]), _tree_hash(leaves[k:]))


def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return GENESIS
    return _tree_hash([_leaf(h) for h in hashes]).hex()


def inclusion_path(hashes: list[str], index: int) -> list[str]:
    """The sibling hashes that tie leaf ``index`` to the root of ``hashes``."""
    if not 0 <= index < len(hashes):
        raise IndexError("leaf index outside the tree")
    return [p.hex() for p in _path(index, [_leaf(h) for h in hashes])]


def _path(index: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return _path(index, leaves[:k]) + [_tree_hash(leaves[k:])]
    return _path(index - k, leaves[k:]) + [_tree_hash(leaves[:k])]


def verify_inclusion(leaf_hash: str, index: int, size: int, path: list[str], root: str) -> bool:
    try:
        if not 0 <= index < size or len(path) > MAX_PROOF_DEPTH:
            return False
        fn, sn, current = index, size - 1, _leaf(leaf_hash)
        for sibling in (bytes.fromhex(p) for p in path):
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                current = _node(sibling, current)
                while not fn & 1 and fn != 0:
                    fn, sn = fn >> 1, sn >> 1
            else:
                current = _node(current, sibling)
            fn, sn = fn >> 1, sn >> 1
        return sn == 0 and current.hex() == root
    except (ValueError, TypeError):
        return False
