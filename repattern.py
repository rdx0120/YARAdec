"""
Reconstructs hex strings and regular expressions from YARA's RE bytecode.

The original yaradec listed "Regex are not extracted" and "FAST_EXP_REGEXP
with wildcards or placeholders are not extracted" as limitations. This module
closes both.

Two facts drive the design:

1. ``YR_STRING.string`` is NULL for every non-literal pattern in a saved
   arena. The compiled regexp program is reachable only through the
   Aho-Corasick match lists (``YR_AC_MATCH.forward_code``), which is why
   :mod:`yaradec.acmatch` exists at all.

2. The RE code section holds a run of independent programs, each terminated
   by ``RE_OPCODE_MATCH``. YARA emits a *forward* and a *backward* program per
   pattern, and one such pair per base64 permutation. Segmenting the section
   by linear disassembly and then locating the segment that contains a
   string's ``forward_code`` offset is what ties a program back to its string.

Instruction widths (libyara/re.c @ v4.5.8):

    ANY, MATCH, WORD_CHAR, DIGIT, boundaries, ...   1
    LITERAL, NOT_LITERAL                            2   (+1 byte value)
    MASKED_LITERAL, MASKED_NOT_LITERAL              3   (+value, +mask)
    CLASS                                          34   (+RE_CLASS: negated
                                                         flag + 32-byte bitmap)
    JUMP                                            3   (+int16, rel. to opcode)
    SPLIT_A, SPLIT_B                                4   (+uint8 id, +int16)
    REPEAT_ANY_GREEDY / _UNGREEDY                   5   (+uint16 min, max)
    REPEAT_START/END_GREEDY / _UNGREEDY             9   (+u16 min, u16 max, i32)
"""

from __future__ import annotations

import string as _string
import struct
from dataclasses import dataclass
from typing import Optional

from .constants import ReOp

_FIXED_WIDTH = {
    ReOp.ANY: 1,
    ReOp.MATCH: 1,
    ReOp.WORD_CHAR: 1,
    ReOp.NON_WORD_CHAR: 1,
    ReOp.SPACE: 1,
    ReOp.NON_SPACE: 1,
    ReOp.DIGIT: 1,
    ReOp.NON_DIGIT: 1,
    ReOp.MATCH_AT_START: 1,
    ReOp.MATCH_AT_END: 1,
    ReOp.WORD_BOUNDARY: 1,
    ReOp.NON_WORD_BOUNDARY: 1,
    ReOp.LITERAL: 2,
    ReOp.NOT_LITERAL: 2,
    ReOp.MASKED_LITERAL: 3,
    ReOp.MASKED_NOT_LITERAL: 3,
    ReOp.CLASS: 34,
    ReOp.JUMP: 3,
    ReOp.SPLIT_A: 4,
    ReOp.SPLIT_B: 4,
    ReOp.REPEAT_ANY_GREEDY: 5,
    ReOp.REPEAT_ANY_UNGREEDY: 5,
    ReOp.REPEAT_START_GREEDY: 9,
    ReOp.REPEAT_END_GREEDY: 9,
    ReOp.REPEAT_START_UNGREEDY: 9,
    ReOp.REPEAT_END_UNGREEDY: 9,
}


class ReDecodeError(Exception):
    pass


@dataclass
class ReInstr:
    offset: int
    op: ReOp
    size: int
    #: LITERAL value / MASKED_LITERAL value
    value: Optional[int] = None
    mask: Optional[int] = None
    #: CLASS bitmap, plus its explicit negation flag (RE_CLASS.negated).
    #: The flag is authoritative -- do not infer negation from popcount.
    bitmap: Optional[bytes] = None
    negated: bool = False
    #: repeat bounds
    min: Optional[int] = None
    max: Optional[int] = None
    #: absolute branch target
    target: Optional[int] = None

    @property
    def end(self) -> int:
        return self.offset + self.size


def decode_instr(code: bytes, off: int) -> ReInstr:
    if off >= len(code):
        raise ReDecodeError(f"instruction pointer {off} past end of RE section")
    raw = code[off]
    try:
        op = ReOp(raw)
    except ValueError:
        raise ReDecodeError(f"unknown RE opcode 0x{raw:02x} at offset {off}") from None

    size = _FIXED_WIDTH[op]
    if off + size > len(code):
        raise ReDecodeError(f"truncated {op.name} at offset {off}")

    ins = ReInstr(offset=off, op=op, size=size)

    if op in (ReOp.LITERAL, ReOp.NOT_LITERAL):
        ins.value = code[off + 1]
    elif op in (ReOp.MASKED_LITERAL, ReOp.MASKED_NOT_LITERAL):
        ins.value = code[off + 1]
        ins.mask = code[off + 2]
    elif op is ReOp.CLASS:
        ins.negated = bool(code[off + 1])
        ins.bitmap = code[off + 2 : off + 34]
    elif op is ReOp.JUMP:
        (rel,) = struct.unpack_from("<h", code, off + 1)
        ins.target = off + rel
    elif op in (ReOp.SPLIT_A, ReOp.SPLIT_B):
        (rel,) = struct.unpack_from("<h", code, off + 2)
        ins.target = off + rel
    elif op in (ReOp.REPEAT_ANY_GREEDY, ReOp.REPEAT_ANY_UNGREEDY):
        ins.min, ins.max = struct.unpack_from("<HH", code, off + 1)
    elif op in (
        ReOp.REPEAT_START_GREEDY,
        ReOp.REPEAT_END_GREEDY,
        ReOp.REPEAT_START_UNGREEDY,
        ReOp.REPEAT_END_UNGREEDY,
    ):
        ins.min, ins.max, rel = struct.unpack_from("<HHi", code, off + 1)
        ins.target = off + rel

    return ins


def disassemble_program(code: bytes, start: int) -> list[ReInstr]:
    """Linearly decode instructions from ``start`` through the first MATCH."""
    out: list[ReInstr] = []
    off = start
    while True:
        ins = decode_instr(code, off)
        out.append(ins)
        if ins.op is ReOp.MATCH:
            return out
        off = ins.end


def segment_programs(code: bytes) -> list[tuple[int, int]]:
    """
    Split the whole RE code section into (start, end_exclusive) programs.

    Segmenting on a raw 0xAD byte would be wrong -- 0xAD occurs constantly
    inside CLASS bitmaps and literal operands -- so this walks instructions.
    """
    segments: list[tuple[int, int]] = []
    off = 0
    start = 0
    while off < len(code):
        try:
            ins = decode_instr(code, off)
        except ReDecodeError:
            break
        if ins.op is ReOp.MATCH:
            segments.append((start, ins.end))
            start = ins.end
        off = ins.end
    return segments


def program_containing(segments: list[tuple[int, int]], offset: int) -> Optional[tuple[int, int]]:
    for seg in segments:
        if seg[0] <= offset < seg[1]:
            return seg
    return None


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

_PRINTABLE = set(_string.ascii_letters + _string.digits + " !\"#%&',-/:;<=>@_`~")
_REGEX_META = set(r".^$*+?()[]{}|\/")


def _class_to_str(bitmap: bytes, negated: bool = False) -> str:
    """
    Turn a 256-bit class bitmap into a bracketed character class.

    ``negated`` comes from RE_CLASS.negated and is authoritative. The bitmap
    itself always lists the characters that *match*, so a negated class is
    rendered by complementing the set for readability only when that produces
    a shorter form.
    """
    members = [c for c in range(256) if bitmap[c // 8] & (1 << (c % 8))]
    if not members:
        return "[^\\x00-\\xff]"
    if len(members) == 256:
        return "."

    invert = len(members) > 128
    if invert:
        member_set = set(members)
        members = [c for c in range(256) if c not in member_set]

    ranges: list[tuple[int, int]] = []
    for c in members:
        if ranges and c == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], c)
        else:
            ranges.append((c, c))

    def esc(c: int) -> str:
        ch = chr(c)
        # "/" must be escaped too: patterns are emitted delimited by slashes,
        # so a bare "/" inside a class silently terminates the regexp.
        if ch in "\\]^-/[":
            return "\\" + ch
        if 0x20 <= c < 0x7F:
            return ch
        return f"\\x{c:02x}"

    body = "".join(
        esc(a) if a == b else (f"{esc(a)}{esc(b)}" if b == a + 1 else f"{esc(a)}-{esc(b)}")
        for a, b in ranges
    )
    return f"[{'^' if invert else ''}{body}]"


def _lit_regex(c: int) -> str:
    ch = chr(c)
    if ch in _REGEX_META:
        return "\\" + ch
    if 0x20 <= c < 0x7F:
        return ch
    return {9: "\\t", 10: "\\n", 13: "\\r"}.get(c, f"\\x{c:02x}")


def render_hex(instrs: list[ReInstr]) -> Optional[str]:
    """
    Render a hex-string program as ``{ ... }``.

    Returns None if the program contains constructs a hex string cannot
    express (alternation, classes), in which case the caller should fall back
    to regex rendering.
    """
    parts: list[str] = []
    for ins in instrs:
        if ins.op is ReOp.MATCH:
            break
        if ins.op is ReOp.LITERAL:
            parts.append(f"{ins.value:02X}")
        elif ins.op is ReOp.ANY:
            parts.append("??")
        elif ins.op is ReOp.MASKED_LITERAL:
            # High or low nibble wildcarded: mask 0xF0 keeps the high nibble.
            if ins.mask == 0xF0:
                parts.append(f"{ins.value >> 4:X}?")
            elif ins.mask == 0x0F:
                parts.append(f"?{ins.value & 0x0F:X}")
            else:
                parts.append(f"({ins.value:02X}&{ins.mask:02X})")
        elif ins.op in (ReOp.REPEAT_ANY_GREEDY, ReOp.REPEAT_ANY_UNGREEDY):
            lo, hi = ins.min, ins.max
            if hi >= 0xFFFF:
                parts.append(f"[{lo}-]")
            elif lo == hi:
                parts.append(f"[{lo}]")
            else:
                parts.append(f"[{lo}-{hi}]")
        else:
            return None
    return "{ " + " ".join(parts) + " }"


_INF = 0xFFFF


@dataclass
class _Piece:
    """A regex sub-expression plus its repetition bounds."""

    base: str
    lo: int = 1
    hi: int = 1
    greedy: bool = True
    #: True if ``base`` is already a self-contained group.
    atomic: bool = False


def _needs_group(base: str) -> bool:
    if len(base) == 1:
        return False
    if len(base) == 2 and base[0] == "\\":
        return False
    if base.startswith("[") and base.endswith("]") and "]" not in base[1:-1]:
        return False
    if base.startswith("(") and base.endswith(")"):
        return False
    if base.startswith("\\x") and len(base) == 4:
        return False
    return True


def _merge_pieces(pieces: list[_Piece]) -> list[_Piece]:
    """
    Fold adjacent repeats of the same sub-expression into one quantifier.

    YARA's code generator expands a bounded repeat ``e{2,4}`` into a mandatory
    part followed by optional parts, so a faithful disassembly reads back as
    ``e e{1,2} e?``. Summing the bounds of adjacent identical bases restores
    ``e{2,4}``, which is what the rule author actually wrote.
    """
    out: list[_Piece] = []
    for p in pieces:
        if (
            out
            and out[-1].base == p.base
            and out[-1].greedy == p.greedy
            and p.base != ""
            # Only fold when a real quantifier is involved. Four consecutive
            # ANY instructions come from "...." in the source, not ".{4}";
            # collapsing them would invent a greedy quantifier, which YARA
            # then refuses to mix with a genuine ungreedy one elsewhere in
            # the same pattern.
            and not (out[-1].lo == out[-1].hi == 1 and p.lo == p.hi == 1)
        ):
            prev = out[-1]
            hi = _INF if _INF in (prev.hi, p.hi) else prev.hi + p.hi
            out[-1] = _Piece(prev.base, prev.lo + p.lo, hi, prev.greedy, prev.atomic)
        else:
            out.append(p)
    return out


def _format_pieces(pieces: list[_Piece]) -> str:
    parts: list[str] = []
    for p in pieces:
        if not p.base:
            continue
        if p.lo == 1 and p.hi == 1:
            parts.append(p.base)
            continue
        # YARA's regexp engine has no non-capturing groups: "(?:" is a
        # syntax error there even though it is valid PCRE. Plain "(" is the
        # only grouping construct available.
        base = f"({p.base})" if (_needs_group(p.base) and not p.atomic) else p.base
        if p.lo == 0 and p.hi == 1:
            quant = "?"
        elif p.lo == 0 and p.hi >= _INF:
            quant = "*"
        elif p.lo == 1 and p.hi >= _INF:
            quant = "+"
        elif p.hi >= _INF:
            quant = f"{{{p.lo},}}"
        elif p.lo == p.hi:
            quant = f"{{{p.lo}}}"
        else:
            quant = f"{{{p.lo},{p.hi}}}"
        parts.append(base + quant + ("" if p.greedy else "?"))
    return "".join(parts)


class _RegexRenderer:
    """
    Structural recovery of a regexp from its bytecode.

    Handles the shapes YARA's code generator emits (libyara/re.c
    ``_yr_re_emit``): concatenation, ``?``, ``*``, ``+``, ``{n,m}``, and
    alternation. Anything it cannot fold is reported rather than silently
    mangled.
    """

    def __init__(self, instrs: list[ReInstr]) -> None:
        self.by_offset = {i.offset: i for i in instrs}
        self.order = [i.offset for i in instrs]
        self.unrecovered = False

    def render(self) -> str:
        end = self.order[-1]  # the MATCH
        return self._seq(self.order[0], end)

    # -- helpers -----------------------------------------------------------

    def _next(self, off: int) -> int:
        return self.by_offset[off].end

    def _atom(self, ins: ReInstr) -> str:
        op = ins.op
        if op is ReOp.LITERAL:
            return _lit_regex(ins.value)
        if op is ReOp.NOT_LITERAL:
            return f"[^{_lit_regex(ins.value)}]"
        if op is ReOp.ANY:
            return "."
        if op is ReOp.CLASS:
            return _class_to_str(ins.bitmap, ins.negated)
        if op is ReOp.WORD_CHAR:
            return "\\w"
        if op is ReOp.NON_WORD_CHAR:
            return "\\W"
        if op is ReOp.SPACE:
            return "\\s"
        if op is ReOp.NON_SPACE:
            return "\\S"
        if op is ReOp.DIGIT:
            return "\\d"
        if op is ReOp.NON_DIGIT:
            return "\\D"
        if op is ReOp.WORD_BOUNDARY:
            return "\\b"
        if op is ReOp.NON_WORD_BOUNDARY:
            return "\\B"
        if op is ReOp.MATCH_AT_START:
            return "^"
        if op is ReOp.MATCH_AT_END:
            return "$"
        if op is ReOp.MASKED_LITERAL:
            # No regex syntax for a nibble wildcard; express as a class.
            lo = ins.value & ins.mask
            members = bytearray(32)
            for c in range(256):
                if c & ins.mask == lo:
                    members[c // 8] |= 1 << (c % 8)
            return _class_to_str(bytes(members))
        self.unrecovered = True
        return f"(?#{op.name})"

    @staticmethod
    def _wrap(s: str) -> str:
        """Parenthesise ``s`` if a following quantifier would misbind."""
        if len(s) == 1 or (len(s) == 2 and s[0] == "\\"):
            return s
        if s.startswith("[") and s.endswith("]") and "]" not in s[1:-1]:
            return s
        return f"(?:{s})"

    # -- structure ---------------------------------------------------------

    def _seq(self, start: int, end: int) -> str:
        pieces: list[_Piece] = []
        starts: list[int] = []
        off = start
        guard = 0
        while off < end:
            guard += 1
            if guard > 100000:
                self.unrecovered = True
                break

            # A back-edge split closes a "+": YARA emits e+ as
            # "L: <e> ; SPLIT_B L". The body may span any number of
            # instructions -- "(ab)+" jumps back over two -- so the fold has
            # to happen here, where the piece boundaries are known, rather
            # than by peeking one unit ahead.
            ins = self.by_offset.get(off)
            if (
                ins is not None
                and ins.op in (ReOp.SPLIT_A, ReOp.SPLIT_B)
                and ins.target is not None
                and ins.target in starts
                and ins.end <= end
            ):
                idx = starts.index(ins.target)
                body = _format_pieces(_merge_pieces(pieces[idx:]))
                del pieces[idx:]
                del starts[idx:]
                greedy = ins.op is ReOp.SPLIT_B
                pieces.append(_Piece(body, 1, _INF, greedy))
                starts.append(ins.target)
                off = ins.end
                continue

            piece, nxt = self._unit(off, end)
            if piece is not None:
                pieces.append(piece)
                starts.append(off)
            off = nxt
        return _format_pieces(_merge_pieces(pieces))

    def _unit(self, off: int, end: int) -> tuple[Optional["_Piece"], int]:
        return self._unit_inner(off, end)

    def _unit_inner(self, off: int, end: int) -> tuple[Optional["_Piece"], int]:
        ins = self.by_offset.get(off)
        if ins is None:
            self.unrecovered = True
            return None, end

        # e{n,m}  ->  REPEAT_START ... REPEAT_END
        if ins.op in (ReOp.REPEAT_START_GREEDY, ReOp.REPEAT_START_UNGREEDY):
            greedy = ins.op is ReOp.REPEAT_START_GREEDY
            body_start = ins.end
            close = self._find_repeat_end(body_start, end)
            if close is not None:
                body = self._seq(body_start, close.offset)
                return (
                    _Piece(body, ins.min, ins.max, greedy),
                    close.end,
                )

        # e*  ->  L1: SPLIT_A L2 ; body ; JUMP L1 ; L2:
        if ins.op in (ReOp.SPLIT_A, ReOp.SPLIT_B) and ins.target is not None:
            tgt = ins.target
            if tgt > off:
                last = self.by_offset.get(self._prev_offset(tgt))
                if (
                    last is not None
                    and last.op is ReOp.JUMP
                    and last.target == off
                ):
                    body = self._seq(ins.end, last.offset)
                    star_greedy = ins.op is ReOp.SPLIT_A
                    return _Piece(body, 0, _INF, star_greedy), tgt
                # alternation: SPLIT_A L1 ; A ; JUMP L2 ; L1: B ; L2:
                if (
                    last is not None
                    and last.op is ReOp.JUMP
                    and last.target is not None
                    and last.target > tgt
                ):
                    left = self._seq(ins.end, last.offset)
                    right = self._seq(tgt, last.target)
                    return _Piece(f"({left}|{right})", 1, 1, True, atomic=True), last.target
                # e?  ->  SPLIT_A L1 ; e ; L1:
                body = self._seq(ins.end, tgt)
                opt_greedy = ins.op is ReOp.SPLIT_A
                return _Piece(body, 0, 1, opt_greedy), tgt

        if ins.op in (ReOp.REPEAT_ANY_GREEDY, ReOp.REPEAT_ANY_UNGREEDY):
            greedy = ins.op is ReOp.REPEAT_ANY_GREEDY
            return _Piece(".", ins.min, ins.max, greedy), ins.end

        if ins.op is ReOp.JUMP and ins.target is not None and ins.target > off:
            return None, ins.target

        return _Piece(self._atom(ins), 1, 1, True), ins.end

    @staticmethod
    def _quant(lo: int, hi: int) -> str:
        if hi >= 0xFFFF:
            return f"{{{lo},}}"
        if lo == hi:
            return f"{{{lo}}}"
        return f"{{{lo},{hi}}}"

    def _prev_offset(self, off: int) -> int:
        prev = -1
        for o in self.order:
            if o >= off:
                break
            prev = o
        return prev

    def _find_repeat_end(self, start: int, end: int) -> Optional[ReInstr]:
        depth = 0
        for o in self.order:
            if o < start or o >= end:
                continue
            ins = self.by_offset[o]
            if ins.op in (ReOp.REPEAT_START_GREEDY, ReOp.REPEAT_START_UNGREEDY):
                depth += 1
            elif ins.op in (ReOp.REPEAT_END_GREEDY, ReOp.REPEAT_END_UNGREEDY):
                if depth == 0:
                    return ins
                depth -= 1
        return None

def render_regex(instrs: list[ReInstr]) -> tuple[str, bool]:
    """Return (pattern, fully_recovered)."""
    r = _RegexRenderer(instrs)
    try:
        text = r.render()
    except (KeyError, RecursionError):
        return "", False
    return text, not r.unrecovered


def format_disassembly(instrs: list[ReInstr]) -> list[str]:
    lines = []
    for i in instrs:
        bits = [f"  {i.offset:05d}  {i.op.name}"]
        if i.value is not None:
            bits.append(f"0x{i.value:02x}")
        if i.mask is not None:
            bits.append(f"mask=0x{i.mask:02x}")
        if i.min is not None:
            bits.append(f"min={i.min} max={i.max}")
        if i.target is not None:
            bits.append(f"-> {i.target}")
        if i.bitmap is not None:
            bits.append(_class_to_str(i.bitmap, i.negated))
        lines.append(" ".join(bits))
    return lines


def literal_runs(instrs: list[ReInstr]) -> list[str]:
    """
    Extract maximal runs of consecutive LITERAL instructions as text.

    A ``base64`` pattern compiles to a single program containing the three
    permutations as alternatives, so the runs are exactly those permutations.
    """
    runs: list[str] = []
    current: list[str] = []
    for ins in instrs:
        if ins.op is ReOp.LITERAL and ins.value is not None:
            current.append(chr(ins.value))
        else:
            if current:
                runs.append("".join(current))
                current = []
    if current:
        runs.append("".join(current))
    return runs
