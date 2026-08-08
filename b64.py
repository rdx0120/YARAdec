"""
Recovers the plaintext behind a ``base64`` / ``base64wide`` string modifier.

YARA expands ``$s = "text" base64`` into three encodings -- the string
prefixed with 0, 1 and 2 NUL bytes -- and keeps only the base64 characters
that are fully determined by the plaintext, discarding the leading and
trailing characters that depend on surrounding data. The compiled rules
therefore contain three partial encodings and no copy of the plaintext.

The expansion is:

    pad      = b"\\x00" * i                      for i in (0, 1, 2)
    encoded  = b64encode(pad + s)  (no "=" padding)
    leading  = (0, 2, 3)[i]                     characters to drop in front
    determined = len(pad + s) * 8 // 6          characters that are fully
                                                determined by the input
    permutation = encoded[leading:determined]

This module inverts that. Because the tail of the plaintext is only partially
represented, the last one or two bytes are recovered by search rather than
arithmetic -- but every candidate is then re-expanded and compared against
*all* observed permutations. A candidate is returned only on an exact match,
so this never guesses: it either proves the plaintext or reports failure.
"""

from __future__ import annotations

import base64
from typing import Iterable, Optional

_LEADING = (0, 2, 3)


def expand(plaintext: bytes) -> list[str]:
    """Reproduce YARA's three base64 permutations for ``plaintext``."""
    out: list[str] = []
    for i in range(3):
        padded = b"\x00" * i + plaintext
        encoded = base64.b64encode(padded).decode("ascii").rstrip("=")
        determined = len(padded) * 8 // 6
        out.append(encoded[_LEADING[i] : determined])
    return out


def _decode_prefix(permutation: str) -> bytes:
    """Decode the fully-determined leading bytes of the i=0 permutation."""
    usable = len(permutation) - (len(permutation) % 4)
    if usable == 0:
        return b""
    return base64.b64decode(permutation[:usable] + "=" * ((4 - usable % 4) % 4))


def recover(permutations: Iterable[str], max_tail: int = 2) -> Optional[bytes]:
    """
    Recover the plaintext from observed permutations, or None.

    ``permutations`` need not be in YARA's order and need not be complete;
    every one supplied must match for a candidate to be accepted.
    """
    observed = set(permutations)
    if not observed:
        return None

    # The i=0 permutation is the one that is a prefix of b64encode(plaintext).
    candidates_seed: list[bytes] = []
    for perm in observed:
        try:
            candidates_seed.append(_decode_prefix(perm))
        except Exception:
            continue
    if not candidates_seed:
        return None

    for seed in candidates_seed:
        for tail_len in range(0, max_tail + 1):
            for tail in _tails(tail_len):
                candidate = seed + tail
                if not candidate:
                    continue
                produced = set(expand(candidate))
                if observed <= produced:
                    return candidate
    return None


def _tails(n: int) -> Iterable[bytes]:
    if n == 0:
        yield b""
        return
    if n == 1:
        for a in range(256):
            yield bytes((a,))
        return
    for a in range(256):
        for b in range(256):
            yield bytes((a, b))
