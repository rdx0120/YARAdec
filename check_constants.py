#!/usr/bin/env python3
"""
Verify yaradec's opcode operand table against a checked-out YARA source tree.

Usage:  python tools/check_constants.py /path/to/yara

The operand widths in constants.py are the single most fragile thing in this
project: a wrong width desynchronises the whole disassembly downstream of the
bad instruction and produces confident nonsense. Rather than trust that the
table is still correct on a new YARA release, this script re-derives it from
``libyara/exec.c`` and diffs.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from yaradec.constants import OPERANDS, SUPPORTED_ARENA_VERSIONS  # noqa: E402

_SIZE = {
    "uint8_t": "u8", "uint16_t": "u16", "uint32_t": "u32",
    "uint64_t": "u64", "int32_t": "u32",
}


def derive(exec_c: str) -> dict[str, str]:
    """Re-derive operand widths, honouring C fall-through case groups."""
    toks = [(m.start(), m.end(), m.group(1))
            for m in re.finditer(r"case (OP_[A-Z0-9_]+):", exec_c)]
    out: dict[str, str] = {}
    i = 0
    while i < len(toks):
        # Gather consecutive labels with nothing but whitespace between them;
        # they all share the body that follows the last one.
        j = i
        while (j + 1 < len(toks)
               and not exec_c[toks[j][1]:toks[j + 1][0]].strip()):
            j += 1
        group = [toks[k][2] for k in range(i, j + 1)]
        body_end = toks[j + 1][0] if j + 1 < len(toks) else len(exec_c)
        body = exec_c[toks[j][1]:body_end]

        adv = re.findall(r"ip \+= sizeof\(([a-z0-9_]+)\)", body)
        jmp = "jmp_if(" in body
        if adv or jmp:
            if jmp and adv:
                kind = "jmp+" + _SIZE[adv[0]]
            elif jmp:
                kind = "jmp"
            else:
                kind = _SIZE[adv[0]]
            for label in group:
                out[label[3:]] = kind
        i = j + 1
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    root = Path(sys.argv[1])
    exec_c = (root / "libyara" / "exec.c").read_text()
    arena_h = (root / "libyara" / "include" / "yara" / "arena.h").read_text()

    m = re.search(r"#define YR_ARENA_FILE_VERSION (\d+)", arena_h)
    version = int(m.group(1)) if m else None
    problems = 0

    if version not in SUPPORTED_ARENA_VERSIONS:
        print(f"FAIL arena version: tree says {version}, "
              f"we support {sorted(SUPPORTED_ARENA_VERSIONS)}")
        problems += 1
    else:
        print(f"ok   arena file version {version}")

    derived = derive(exec_c)
    ours = {op.name: kind for op, kind in OPERANDS.items()}
    # Opcodes marked "Not used" in exec.h never appear in exec.c.
    ignore = {"JUNDEF", "JNUNDEF_P"}

    for name in sorted(set(ours) | set(derived)):
        if name in ignore:
            continue
        a, b = ours.get(name), derived.get(name)
        if a != b:
            print(f"FAIL {name}: ours={a!r} yara={b!r}")
            problems += 1

    if problems:
        print(f"\n{problems} mismatch(es). Update yaradec/constants.py.")
        return 1
    print(f"ok   {len(derived)} opcode operand widths match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
