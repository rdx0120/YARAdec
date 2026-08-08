#!/usr/bin/env python3
"""
Round-trip verification: compile -> decompile -> recompile -> compare.

This is the only check that really matters. A decompiler can produce
plausible-looking source that is subtly wrong, and eyeballing the output will
not catch it. So for each rule file we:

  1. compile it with the real YARA,
  2. decompile the result with yaradec,
  3. recompile the decompiled source with the real YARA, and
  4. scan a corpus of test buffers with both rule sets and assert that
     *exactly the same rules fire on exactly the same inputs*.

Step 4 is what makes this meaningful. Steps 1-3 only prove the output parses;
step 4 proves it means the same thing.

Usage:  python tools/roundtrip.py rules1.yar rules2.yar ...
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import yara
except ImportError:  # pragma: no cover
    print("roundtrip: yara-python is required (pip install yara-python)")
    raise SystemExit(2)

from yaradec.decompile import decompile  # noqa: E402

#: Buffers chosen to exercise the patterns in the test corpus.
CORPUS: dict[str, bytes] = {
    "empty": b"",
    "mz": b"MZ\x90\x00\x03\x00\x00\x00" + b"A" * 64,
    "mz_wild": b"MZ\x90\x00\x03\xff\x00\x00" + b"B" * 64,
    "text": b"the quick brown fox",
    "alpha": b"alpha bravo charlie",
    "alpha_only": b"alpha",
    "malicious": b"malicious_string here",
    "malicious_upper": b"MALICIOUS_STRING here",
    "wide": "malicious_string".encode("utf-16le"),
    "regex": b"evil1234regex and evil42regex",
    "b64": b"YjY0bW and I2NG1l",
    "b64_plain": b"b64me",
    "xored": b"xored",
    "fullword": b"fullword_hit ",
    "fullword_embedded": b"xxfullword_hitxx",
    "needle": b"needle needle needle",
    "nops": b"\x90\x90\x90\x90" + b"C" * 200,
    "helper": b"helper",
    "mixed": (
        b"MZ\x90\x00\x03\x11\x00\x00 malicious_string helper "
        b"evil99regex b64me xored fullword_hit needle"
    ),
}


def scan_matches(rules, data: bytes) -> set[str]:
    return {m.rule for m in rules.match(data=data)}


def check(path: Path) -> bool:
    print(f"\n=== {path.name} ===")
    original = yara.compile(filepath=str(path))

    with tempfile.TemporaryDirectory() as tmp:
        compiled_path = Path(tmp) / "rules.yarc"
        original.save(str(compiled_path))

        result = decompile(compiled_path)

        rules_total = len(result.compiled.rules)
        conds = result.conditions_recovered
        print(f"  rules:      {rules_total}")
        print(f"  conditions: {conds}/{rules_total} reconstructed")
        for w in result.warnings:
            print(f"  warning:    {w}")

        if conds < rules_total:
            print("  FAIL: not every condition was reconstructed")
            return False

        src_path = Path(tmp) / "decompiled.yar"
        src_path.write_text(result.source)

        try:
            recompiled = yara.compile(filepath=str(src_path))
        except yara.Error as exc:
            print(f"  FAIL: decompiled source does not compile: {exc}")
            for i, line in enumerate(result.source.splitlines(), 1):
                print(f"    {i:3d} | {line}")
            return False

    ok = True
    for name, data in CORPUS.items():
        before = scan_matches(original, data)
        after = scan_matches(recompiled, data)
        if before != after:
            ok = False
            print(
                f"  FAIL: behaviour differs on {name!r}: "
                f"original={sorted(before)} recompiled={sorted(after)}"
            )
    if ok:
        print(f"  OK: identical matches across {len(CORPUS)} test buffers")
    return ok


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    failures = 0
    for arg in argv:
        if not check(Path(arg)):
            failures += 1
    print()
    if failures:
        print(f"{failures} file(s) FAILED round-trip")
        return 1
    print(f"all {len(argv)} file(s) round-tripped successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
