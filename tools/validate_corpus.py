#!/usr/bin/env python3
"""
Validate yaradec against a corpus of real YARA rule files.

For every rule file it can compile, this:

  1. compiles it with the installed YARA,
  2. decompiles the compiled rules with yaradec,
  3. recompiles the decompiled source, and
  4. scans a set of test buffers with BOTH the original and the recompiled
     rules, asserting the same rules fire on the same inputs.

Step 3 only proves the output parses. Step 4 proves it means the same thing --
that is the check that actually matters.

The test buffers are built from each rule's own literal strings, so rules
genuinely fire and the comparison is meaningful rather than everything simply
not matching an empty buffer.

Usage:
    python tools/validate_corpus.py /path/to/rules

    # e.g. after: git clone https://github.com/Yara-Rules/rules.git
    python tools/validate_corpus.py ./rules

Prints a summary you can paste straight into the README. Exit code is 0 only
if there are no crashes, no recompile failures, and no behavioural mismatches.
"""

from __future__ import annotations

import random
import sys
import tempfile
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import yara
except ImportError:
    print("This script needs yara-python:  pip install yara-python")
    raise SystemExit(2)

from yaradec.constants import StringFlags  # noqa: E402
from yaradec.decompile import decompile  # noqa: E402

warnings.filterwarnings("ignore")
random.seed(1337)  # deterministic buffers, so runs are reproducible


def scan(rules, data: bytes) -> set[str]:
    return {m.rule for m in rules.match(data=data)}


def buffers_for(strings: list[bytes]) -> list[bytes]:
    """Build test buffers out of a rule set's own literal strings."""
    usable = [s for s in strings if 3 <= len(s) <= 200]
    random.shuffle(usable)
    out = [b"", b"MZ\x90\x00" + bytes(random.getrandbits(8) for _ in range(256))]
    for i in range(0, min(len(usable), 120), 4):
        chunk = usable[i : i + 4]
        out.append(b"\x00".join(chunk))
        out.append(b"MZ\x90\x00" + b" ".join(chunk) + b"\x00" * 8)
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2

    root = Path(argv[0])
    if not root.exists():
        print(f"path not found: {root}")
        return 2

    files = sorted(root.rglob("*.yar")) + sorted(root.rglob("*.yara"))
    if not files:
        print(f"no .yar/.yara files found under {root}")
        return 2

    total = dict(
        files=0,
        skipped=0,
        rules=0,
        strings=0,
        conditions=0,
        recompile_ok=0,
        recompile_fail=0,
        crash=0,
        buffers=0,
        mismatch=0,
        files_with_mismatch=0,
    )
    recompile_failures: list[str] = []
    mismatches: list[str] = []

    for f in files:
        try:
            original = yara.compile(filepath=str(f))
        except Exception:
            total["skipped"] += 1  # rule needs external vars / modules we lack
            continue

        total["files"] += 1
        with tempfile.TemporaryDirectory() as tmp:
            compiled = Path(tmp) / "r.yarc"
            original.save(str(compiled))

            try:
                result = decompile(compiled)
            except Exception as exc:
                total["crash"] += 1
                print(f"  CRASH  {f.name}: {type(exc).__name__}: {exc}")
                continue

            total["rules"] += len(result.compiled.rules)
            total["strings"] += len(result.compiled.strings)
            total["conditions"] += result.conditions_recovered

            src = Path(tmp) / "d.yar"
            src.write_text(result.source)
            try:
                recompiled = yara.compile(filepath=str(src))
                total["recompile_ok"] += 1
            except Exception as exc:
                total["recompile_fail"] += 1
                recompile_failures.append(f"{f.name}: {exc}")
                continue

            literals = [
                s.data
                for s in result.compiled.strings
                if (s.flags & StringFlags.LITERAL) and s.data
            ]
            file_bad = False
            for buf in buffers_for(literals):
                total["buffers"] += 1
                before = scan(original, buf)
                after = scan(recompiled, buf)
                if before != after:
                    total["mismatch"] += 1
                    if not file_bad:
                        mismatches.append(
                            f"{f.name}: {sorted(before ^ after)[:4]}"
                        )
                        file_bad = True
            if file_bad:
                total["files_with_mismatch"] += 1

    _report(total, recompile_failures, mismatches)

    clean = (
        total["crash"] == 0
        and total["recompile_fail"] == 0
        and total["mismatch"] == 0
        and total["conditions"] == total["rules"]
    )
    return 0 if clean else 1


def _report(total, recompile_failures, mismatches) -> None:
    print()
    print("=" * 60)
    print("  yaradec corpus validation")
    print("=" * 60)
    print(f"  files compiled & tested   {total['files']}")
    print(f"  files skipped (need ext.) {total['skipped']}")
    print(f"  rules parsed              {total['rules']}")
    print(f"  strings parsed            {total['strings']}")
    cond_pct = (
        100 * total["conditions"] / total["rules"] if total["rules"] else 0
    )
    print(
        f"  conditions reconstructed  {total['conditions']} / {total['rules']}"
        f"  ({cond_pct:.1f}%)"
    )
    print(f"  crashes                   {total['crash']}")
    print(
        f"  files recompiled          {total['recompile_ok']} / "
        f"{total['recompile_ok'] + total['recompile_fail']}"
    )
    print(
        f"  scan buffers compared     {total['buffers']}"
    )
    print(f"  behavioural mismatches    {total['mismatch']}")
    print("=" * 60)

    if recompile_failures:
        print("\nRecompile failures:")
        for line in recompile_failures[:20]:
            print(f"  {line}")
    if mismatches:
        print("\nBehavioural mismatches:")
        for line in mismatches[:20]:
            print(f"  {line}")

    if not recompile_failures and not mismatches and total["crash"] == 0:
        print("\nAll clean. These numbers are safe to cite.")
    else:
        print("\nNot clean -- investigate the failures above before citing.")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
