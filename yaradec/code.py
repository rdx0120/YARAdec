"""
Disassembles the VM code section and reconstructs rule conditions.

The original yaradec emitted a raw ``__yaradec_asm__`` listing because it
never reversed the condition. This module reconstructs real YARA source for
the common shapes and falls back to an annotated listing only where it
genuinely cannot.

Two observations make this tractable:

1. Rule bodies are delimited. ``OP_INIT_RULE`` carries the rule index and a
   jump over the body; ``OP_MATCH_RULE`` closes it. No guessing required.

2. The non-popping conditional jumps (``OP_JFALSE`` / ``OP_JTRUE`` / etc.)
   exist purely for short-circuit evaluation and leave the stack untouched.
   For *reconstruction* they are no-ops, so a plain linear symbolic execution
   recovers the expression without any control-flow analysis. Only the ``_P``
   ("pop") variants affect the stack.

Operand encoding notes:

* An arena reference passed to ``OP_PUSH`` is packed into the u64 as
  ``buffer_id`` in the low dword and ``offset`` in the high dword -- so a
  string reference looks like ``0x0000003800000003`` (buffer 3, offset 0x38).
* ``OP_OF`` reads a u64 selector: 0 = OF_STRING_SET, 1 = OF_RULE_SET.
* String sets are pushed after an ``OP_PUSH_U`` sentinel and are therefore
  read off the stack in reverse.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .arena import Arena, Ref
from .constants import (
    OPERAND_WIDTH,
    READ_INT_NAMES,
    OPERANDS,
    SIZEOF_RULE,
    SIZEOF_STRING,
    Op,
    Section,
)

UNDEFINED = object()

OF_STRING_SET = 0
OF_RULE_SET = 1


class CodeError(Exception):
    pass


@dataclass
class Instr:
    offset: int
    op: Op
    size: int
    operand: Optional[int] = None
    target: Optional[int] = None
    rule_index: Optional[int] = None

    @property
    def end(self) -> int:
        return self.offset + self.size


def decode(code: bytes, off: int) -> Instr:
    raw = code[off]
    try:
        op = Op(raw)
    except ValueError:
        raise CodeError(f"unknown opcode 0x{raw:02x} at {off}") from None

    kind = OPERANDS.get(op)
    width = OPERAND_WIDTH.get(kind, 0) if kind else 0
    ins = Instr(offset=off, op=op, size=1 + width)

    if kind == "u64":
        (ins.operand,) = struct.unpack_from("<Q", code, off + 1)
    elif kind == "u32":
        (ins.operand,) = struct.unpack_from("<I", code, off + 1)
    elif kind == "u16":
        (ins.operand,) = struct.unpack_from("<H", code, off + 1)
    elif kind == "u8":
        ins.operand = code[off + 1]
    elif kind == "jmp":
        (rel,) = struct.unpack_from("<i", code, off + 1)
        ins.target = off + rel
    elif kind == "jmp+u32":
        rel, idx = struct.unpack_from("<iI", code, off + 1)
        ins.target = off + rel
        ins.rule_index = idx
    return ins


def disassemble(code: bytes) -> list[Instr]:
    out: list[Instr] = []
    off = 0
    while off < len(code):
        ins = decode(code, off)
        out.append(ins)
        if ins.op is Op.HALT:
            break
        off = ins.end
    return out


def unpack_ref(value: int) -> Ref:
    """An arena ref packed into a u64 operand: buffer_id low, offset high."""
    return Ref(value & 0xFFFFFFFF, (value >> 32) & 0xFFFFFFFF)


# --------------------------------------------------------------------------
# Expression model
# --------------------------------------------------------------------------

# Higher binds tighter.
_PREC = {
    "or": 1,
    "and": 2,
    "cmp": 3,
    "add": 4,
    "mul": 5,
    "unary": 6,
    "atom": 7,
}


@dataclass
class Expr:
    text: str
    prec: int = _PREC["atom"]
    #: Original u64 operand, when this expression came from a literal PUSH.
    #: Needed because a double literal and an integer literal are the same
    #: eight bytes -- only the consuming opcode says which it is.
    raw: Optional[int] = None

    def paren(self, min_prec: int) -> str:
        return f"({self.text})" if self.prec < min_prec else self.text

    def __str__(self) -> str:  # pragma: no cover
        return self.text


_BINOP = {
    Op.INT_EQ: ("==", "cmp"), Op.INT_NEQ: ("!=", "cmp"),
    Op.INT_LT: ("<", "cmp"), Op.INT_GT: (">", "cmp"),
    Op.INT_LE: ("<=", "cmp"), Op.INT_GE: (">=", "cmp"),
    Op.INT_ADD: ("+", "add"), Op.INT_SUB: ("-", "add"),
    Op.INT_MUL: ("*", "mul"), Op.INT_DIV: ("\\", "mul"),
    Op.DBL_EQ: ("==", "cmp"), Op.DBL_NEQ: ("!=", "cmp"),
    Op.DBL_LT: ("<", "cmp"), Op.DBL_GT: (">", "cmp"),
    Op.DBL_LE: ("<=", "cmp"), Op.DBL_GE: (">=", "cmp"),
    Op.DBL_ADD: ("+", "add"), Op.DBL_SUB: ("-", "add"),
    Op.DBL_MUL: ("*", "mul"), Op.DBL_DIV: ("\\", "mul"),
    Op.STR_EQ: ("==", "cmp"), Op.STR_NEQ: ("!=", "cmp"),
    Op.STR_LT: ("<", "cmp"), Op.STR_GT: (">", "cmp"),
    Op.STR_LE: ("<=", "cmp"), Op.STR_GE: (">=", "cmp"),
    Op.MOD: ("%", "mul"),
    Op.BITWISE_AND: ("&", "add"), Op.BITWISE_OR: ("|", "add"),
    Op.BITWISE_XOR: ("^", "add"),
    Op.SHL: ("<<", "add"), Op.SHR: (">>", "add"),
    Op.AND: ("and", "and"), Op.OR: ("or", "or"),
    Op.MATCHES: ("matches", "cmp"),
    Op.CONTAINS: ("contains", "cmp"),
    Op.ICONTAINS: ("icontains", "cmp"),
    Op.STARTSWITH: ("startswith", "cmp"),
    Op.ISTARTSWITH: ("istartswith", "cmp"),
    Op.ENDSWITH: ("endswith", "cmp"),
    Op.IENDSWITH: ("iendswith", "cmp"),
    Op.IEQUALS: ("iequals", "cmp"),
}

#: Jumps that only exist for short-circuiting and leave the stack alone.
_DBL_OPS = {
    Op.DBL_EQ, Op.DBL_NEQ, Op.DBL_LT, Op.DBL_GT, Op.DBL_LE, Op.DBL_GE,
    Op.DBL_ADD, Op.DBL_SUB, Op.DBL_MUL, Op.DBL_DIV,
}


def _as_double(e: Expr) -> Expr:
    """Reinterpret a literal's raw bits as an IEEE-754 double."""
    if e.raw is None:
        return e
    (value,) = struct.unpack("<d", struct.pack("<Q", e.raw))
    text = repr(value)
    if text.endswith(".0"):
        text = text[:-2] + ".0"
    return Expr(text, e.prec)


def _escape_bytes(data: bytes) -> str:
    out = []
    for b in data:
        ch = chr(b)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif 0x20 <= b < 0x7F:
            out.append(ch)
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


_STACK_NEUTRAL_JUMPS = {
    Op.JFALSE, Op.JTRUE, Op.JNUNDEF, Op.JUNDEF, Op.JZ,
}
#: Jump variants that pop their operand.
_POPPING_JUMPS = {
    Op.JFALSE_P, Op.JTRUE_P, Op.JUNDEF_P, Op.JNUNDEF_P,
    Op.JZ_P, Op.JL_P, Op.JLE_P,
}


class ConditionRecovery:
    """Linear symbolic execution of one rule's condition bytecode."""

    def __init__(
        self,
        arena: Arena,
        code: bytes,
        string_names: dict[int, str],
        rule_names: dict[int, str],
        bindings: Optional[dict[int, str]] = None,
        depth: int = 0,
        rule_strings: Optional[list[str]] = None,
    ) -> None:
        self.arena = arena
        self.code = code
        self.string_names = string_names
        self.rule_names = rule_names
        self.notes: list[str] = []
        self.complete = True
        #: memory slot -> loop variable name, for nested loop bodies
        self.bindings: dict[int, str] = dict(bindings or {})
        self._depth = depth
        #: identifiers of every string belonging to the rule being recovered
        self.rule_strings: list[str] = list(rule_strings or [])
        self._allow_multi = False
        self._final_stack: Optional[list[str]] = None

    # -- operand helpers ---------------------------------------------------

    def _string_name(self, ref: Ref) -> Optional[str]:
        if ref.buffer_id != Section.STRINGS_TABLE:
            return None
        if ref.offset % SIZEOF_STRING:
            return None
        return self.string_names.get(ref.offset // SIZEOF_STRING)

    def _sz(self, ref: Ref) -> Optional[str]:
        if ref.buffer_id != Section.SZ_POOL:
            return None
        try:
            return self.arena.cstring(ref)
        except Exception:
            return None

    def _push_operand(self, value: int) -> Expr:
        if value == 0xFFFFFFFFFFFFFFFF:
            return Expr("undefined", raw=value)

        ref = unpack_ref(value)

        name = self._string_name(ref)
        if name is not None:
            return Expr(name)

        # A PUSH targeting the RE code section is the right-hand side of
        # "matches" -- a compiled regexp, which we can decompile.
        if ref.buffer_id == Section.RE_CODE_SECTION:
            return Expr(self._regex_literal(ref))

        # A PUSH targeting the string pool is always a SIZED_STRING literal;
        # C strings only ever arrive as OBJ_FIELD/OBJ_LOAD/IMPORT operands.
        if ref.buffer_id == Section.SZ_POOL:
            sized = self.arena.sized_string(ref)
            if sized is not None:
                data, _flags = sized
                return Expr('"' + _escape_bytes(data) + '"')

        return Expr(_int_literal(value), raw=value)

    def _regex_literal(self, ref: Ref) -> str:
        """
        Decompile the right-hand side of ``matches``.

        The operand points at a ``struct RE { uint32_t flags; uint8_t code[]; }``
        (libyara/include/yara/types.h), so the bytecode starts four bytes in --
        decoding from the reference itself hits the flags word and fails.
        The flags carry the /i and /s modifiers.
        """
        from . import repattern as rp
        from .constants import RE_FLAGS_DOT_ALL, RE_FLAGS_NO_CASE

        code = self.arena.buffer(Section.RE_CODE_SECTION)
        try:
            (flags,) = struct.unpack_from("<I", code, ref.offset)
            instrs = rp.disassemble_program(code, ref.offset + 4)
        except Exception as exc:
            self.notes.append(f"could not decompile regexp at {ref!r}: {exc}")
            return "/<unrecovered>/"

        text, full = rp.render_regex(instrs)
        if not full:
            self.notes.append("regexp operand only partially recovered")
        suffix = ""
        if flags & RE_FLAGS_NO_CASE:
            suffix += "i"
        if flags & RE_FLAGS_DOT_ALL:
            suffix += "s"
        return "/" + text + "/" + suffix

    # -- main --------------------------------------------------------------

    def run(self, instrs: list[Instr]) -> Optional[str]:
        stack: list[object] = []

        def pop() -> Expr:
            if not stack:
                self.complete = False
                return Expr("<underflow>")
            v = stack.pop()
            return v if isinstance(v, Expr) else Expr("undefined")

        loops = _find_loops(instrs)
        skip_until = -1

        for pos, ins in enumerate(instrs):
            if pos < skip_until:
                continue
            op = ins.op

            loop = loops.get(pos)
            if loop is not None:
                expr = self._recover_loop(instrs, loop, stack, pop)
                if expr is None:
                    return None
                stack.append(expr)
                skip_until = loop.end + 1
                continue

            if op in _STACK_NEUTRAL_JUMPS:
                continue
            if op in _POPPING_JUMPS:
                pop()
                continue
            if op in (Op.NOP, Op.INIT_RULE, Op.MATCH_RULE, Op.HALT, Op.IMPORT):
                continue

            if op is Op.PUSH:
                stack.append(self._push_operand(ins.operand))
            elif op in (Op.PUSH_8, Op.PUSH_16, Op.PUSH_32):
                stack.append(Expr(_int_literal(ins.operand)))
            elif op is Op.PUSH_U:
                stack.append(UNDEFINED)
            elif op is Op.PUSH_RULE:
                name = self.rule_names.get(ins.operand, f"rule_{ins.operand}")
                stack.append(Expr(name))
            elif op is Op.PUSH_M:
                name = self.bindings.get(ins.operand)
                if name is None:
                    self.notes.append(
                        f"reference to unbound memory slot {ins.operand} "
                        f"at offset {ins.offset}"
                    )
                    self.complete = False
                    return None
                stack.append(Expr(name))

            elif op is Op.FILESIZE:
                stack.append(Expr("filesize"))
            elif op is Op.ENTRYPOINT:
                stack.append(Expr("entrypoint"))

            elif op is Op.FOUND:
                stack.append(Expr(pop().text))
            elif op is Op.COUNT:
                s = pop().text
                stack.append(Expr("#" + s.lstrip("$")))
            elif op in (Op.LENGTH, Op.OFFSET):
                # Both pop the string *and* an occurrence index: "@x" is
                # sugar for "@x[1]", and the index is always emitted.
                s = pop().text
                index = pop().text
                sigil = "!" if op is Op.LENGTH else "@"
                base = sigil + s.lstrip("$")
                stack.append(Expr(base if index == "1" else f"{base}[{index}]"))
            elif op is Op.FOUND_AT:
                s = pop()
                offset = pop()
                stack.append(Expr(f"{s.text} at {offset.paren(_PREC['cmp'])}",
                                  _PREC["cmp"]))
            elif op is Op.FOUND_IN:
                s = pop()
                hi = pop()
                lo = pop()
                stack.append(
                    Expr(f"{s.text} in ({lo.text}..{hi.text})", _PREC["cmp"])
                )
            elif op is Op.COUNT_IN:
                s = pop().text
                hi = pop()
                lo = pop()
                stack.append(
                    Expr(f"#{s.lstrip('$')} in ({lo.text}..{hi.text})",
                         _PREC["cmp"])
                )

            elif op in (Op.OF, Op.OF_PERCENT, Op.OF_FOUND_IN, Op.OF_FOUND_AT):
                expr = self._recover_of(op, ins, stack, pop)
                if expr is None:
                    return None
                stack.append(expr)

            elif op is Op.NOT:
                v = pop()
                stack.append(Expr(f"not {v.paren(_PREC['unary'])}",
                                  _PREC["unary"]))
            elif op is Op.BITWISE_NOT:
                v = pop()
                stack.append(Expr(f"~{v.paren(_PREC['unary'])}",
                                  _PREC["unary"]))
            elif op in (Op.INT_MINUS, Op.DBL_MINUS):
                v = pop()
                stack.append(Expr(f"-{v.paren(_PREC['unary'])}",
                                  _PREC["unary"]))
            elif op is Op.DEFINED:
                v = pop()
                stack.append(Expr(f"defined {v.paren(_PREC['unary'])}",
                                  _PREC["unary"]))

            elif op in _BINOP:
                sym, cls = _BINOP[op]
                prec = _PREC[cls]
                rhs = pop()
                lhs = pop()
                if op in _DBL_OPS:
                    lhs, rhs = _as_double(lhs), _as_double(rhs)
                # Comparisons and arithmetic are left-associative; the right
                # operand needs parens at equal precedence.
                stack.append(
                    Expr(f"{lhs.paren(prec)} {sym} {rhs.paren(prec + 1)}", prec)
                )

            elif op is Op.OBJ_LOAD:
                name = self._sz(unpack_ref(ins.operand)) or "?"
                stack.append(Expr(name))
            elif op is Op.OBJ_FIELD:
                field_name = self._sz(unpack_ref(ins.operand)) or "?"
                base = pop()
                stack.append(Expr(f"{base.text}.{field_name}"))
            elif op is Op.OBJ_VALUE:
                pass  # value of the object already on the stack
            elif op is Op.INDEX_ARRAY or op is Op.LOOKUP_DICT:
                index = pop()
                base = pop()
                stack.append(Expr(f"{base.text}[{index.text}]"))
            elif op is Op.CALL:
                expr = self._recover_call(ins, stack, pop)
                if expr is None:
                    return None
                stack.append(expr)

            elif op in READ_INT_NAMES:
                addr = pop()
                stack.append(Expr(f"{READ_INT_NAMES[op]}({addr.text})"))

            elif op is Op.INT_TO_DBL:
                pass
            elif op is Op.STR_TO_BOOL:
                pass
            elif op is Op.SWAPUNDEF:
                pass

            else:
                # Loop/iterator machinery and anything else we do not model.
                self.notes.append(
                    f"unhandled {op.name} at offset {ins.offset}"
                )
                self.complete = False
                return None

        results = [v for v in stack if isinstance(v, Expr)]
        self._final_stack = [r.text for r in results]
        if not self.complete:
            return None
        if self._allow_multi:
            return results[-1].text if results else None
        if len(results) != 1:
            self.notes.append(
                f"expected exactly one value on the stack, found {len(results)}"
            )
            return None
        return results[0].text


    def _recover_loop(self, instrs, loop, stack, pop) -> Optional[Expr]:
        """Reconstruct ``for <quantifier> <var> in <iterable> : ( <body> )``."""
        # The quantifier was pushed before the header and popped into a slot.
        quantifier = pop().text
        if quantifier == "undefined":
            quantifier = "all"

        is_string_set = loop.kind in (
            Op.ITER_START_STRING_SET,
            Op.ITER_START_TEXT_STRING_SET,
        )

        # Iterable expression.
        if is_string_set:
            # A string set is pushed as an OP_PUSH_U sentinel followed by the
            # members, so it reduces to several stack values rather than one.
            members = self._sub_run_multi(instrs[loop.iter_lo : loop.iter_start])
            if members is None:
                self.notes.append(
                    "could not reconstruct the string set of a for-loop"
                )
                return None
            # ITER_START_STRING_SET pops a member count that is pushed after
            # the members themselves, so the last value is the cardinality,
            # not a member. Only strip it when it actually matches, so a
            # codegen change shows up as a warning instead of a silent
            # off-by-one.
            if len(members) >= 2 and members[-1].isdigit():
                if int(members[-1]) == len(members) - 1:
                    members = members[:-1]
                else:
                    self.notes.append(
                        f"string-set cardinality {members[-1]} does not match "
                        f"{len(members) - 1} members"
                    )
            if self.rule_strings and sorted(members) == sorted(self.rule_strings):
                iter_expr = "them"
            elif any(m == "$" for m in members):
                self.notes.append(
                    "for-loop iterates a partial set of anonymous strings, "
                    "which cannot be written in YARA source"
                )
                return None
            else:
                iter_expr = "(" + ", ".join(members) + ")"
        else:
            iter_expr = self._sub_run(
                instrs[loop.iter_lo : loop.iter_start],
                join_pairs=loop.kind is Op.ITER_START_INT_RANGE,
            )
            if iter_expr is None:
                self.notes.append(
                    "could not reconstruct the iterable of a for-loop"
                )
                return None

        # Loop variables are not stored in compiled rules -- only their memory
        # slots survive -- so a readable name has to be chosen here. This is
        # the one place the output is deliberately not byte-faithful; it does
        # not change semantics.
        if is_string_set:
            # In "for ... of (...)" the current string is referred to as "$",
            # and its offset/length as "@" and "!". There is no user-chosen
            # name to recover.
            var = "$"
        else:
            if loop.kind in (Op.ITER_START_INT_RANGE, Op.ITER_START_INT_ENUM):
                pool = _VAR_NAMES
            else:
                pool = _OBJ_VAR_NAMES
            used = set(self.bindings.values())
            var = next((v for v in pool if v not in used), f"v{loop.var_slot}")

        bindings = dict(self.bindings)
        bindings[loop.var_slot] = var

        body = self._sub_run(instrs[loop.body_lo : loop.body_hi], bindings=bindings)
        if body is None:
            self.notes.append("could not reconstruct the body of a for-loop")
            return None

        if is_string_set:
            head = f"for {quantifier} of {iter_expr}"
        else:
            head = f"for {quantifier} {var} in {iter_expr}"
        return Expr(f"{head} : ( {body} )", _PREC["cmp"])

    def _sub_run(self, sub, bindings=None, join_pairs: bool = False) -> Optional[str]:
        """Recover a nested instruction range as an expression."""
        if self._depth > 8:
            self.notes.append("for-loop nesting too deep")
            return None
        rec = ConditionRecovery(
            self.arena,
            self.code,
            self.string_names,
            self.rule_names,
            bindings=bindings if bindings is not None else self.bindings,
            depth=self._depth + 1,
            rule_strings=self.rule_strings,
        )
        if join_pairs:
            # An integer range pushes its low and high bounds separately.
            text = rec.run_multi(sub)
            self.notes.extend(rec.notes)
            if text is None or len(text) != 2:
                return None
            return f"({text[0]}..{text[1]})"
        out = rec.run(sub)
        self.notes.extend(rec.notes)
        return out

    def _sub_run_multi(self, sub) -> Optional[list[str]]:
        if self._depth > 8:
            self.notes.append("for-loop nesting too deep")
            return None
        rec = ConditionRecovery(
            self.arena,
            self.code,
            self.string_names,
            self.rule_names,
            bindings=self.bindings,
            depth=self._depth + 1,
            rule_strings=self.rule_strings,
        )
        values = rec.run_multi(sub)
        self.notes.extend(rec.notes)
        return values

    def run_multi(self, instrs: list[Instr]) -> Optional[list[str]]:
        """Like :meth:`run` but returns every value left on the stack."""
        saved = self._allow_multi
        self._allow_multi = True
        try:
            self.run(instrs)
        finally:
            self._allow_multi = saved
        return self._final_stack

    # -- composite opcodes -------------------------------------------------

    def _pop_set(self, stack: list, pop) -> Optional[list[str]]:
        """Pop items back to the OP_PUSH_U sentinel; they were pushed in order."""
        items: list[str] = []
        while stack:
            top = stack[-1]
            if top is UNDEFINED:
                stack.pop()
                items.reverse()
                return items
            items.append(pop().text)
            if len(items) > 65536:
                break
        self.complete = False
        return None

    def _recover_of(self, op: Op, ins: Instr, stack: list, pop) -> Optional[Expr]:
        extra_at = extra_in = None
        if op is Op.OF_FOUND_AT:
            extra_at = pop()
        elif op is Op.OF_FOUND_IN:
            hi, lo = pop(), pop()
            extra_in = (lo, hi)

        items = self._pop_set(stack, pop)
        if items is None:
            self.notes.append(f"could not delimit string set at {ins.offset}")
            return None
        quantifier = pop().text

        selector = ins.operand if ins.operand is not None else OF_STRING_SET
        kind = "them" if selector == OF_RULE_SET else "them"

        # "all of" is compiled by pushing UNDEFINED as the quantifier.
        # "any of" is compiled as the literal 1 and is therefore
        # indistinguishable from "1 of" -- they are semantically identical.
        if quantifier == "undefined":
            quantifier = "all"

        if op is Op.OF_PERCENT:
            quantifier = f"{quantifier}%"

        # Collapse a set covering every string in the rule back to "them".
        # This is not just cosmetic: rules using anonymous strings ($ = "...")
        # can ONLY be referenced via "them", so enumerating them produces
        # "5 of ($, $, $, ...)" which compiles but does not mean the same
        # thing. Whenever the set is the rule's full string list, "them" is
        # both the faithful rendering and the only correct one.
        if self.rule_strings and sorted(items) == sorted(self.rule_strings):
            text = f"{quantifier} of them"
        elif any(i == "$" for i in items):
            # A partial set of anonymous strings is not expressible in YARA
            # source, so this should be unreachable -- say so rather than
            # emit something that silently means something else.
            self.notes.append(
                "an 'of' expression references anonymous strings but does "
                "not cover the whole rule; this cannot be expressed in "
                "YARA source"
            )
            self.complete = False
            return None
        else:
            body = ", ".join(items)
            text = f"{quantifier} of ({body})"
        if extra_at is not None:
            text += f" at {extra_at.paren(_PREC['cmp'])}"
        elif extra_in is not None:
            lo, hi = extra_in
            text += f" in ({lo.text}..{hi.text})"
        _ = kind
        return Expr(text, _PREC["cmp"])

    def _recover_call(self, ins: Instr, stack: list, pop) -> Optional[Expr]:
        """
        OP_CALL's operand is the argument type-string (e.g. "i", "ss"), which
        gives the arity directly.
        """
        argfmt = self._sz(unpack_ref(ins.operand))
        if argfmt is None:
            self.notes.append(f"could not read call signature at {ins.offset}")
            self.complete = False
            return None
        argc = len(argfmt)
        args = [pop().text for _ in range(argc)][::-1]
        func = pop()
        return Expr(f"{func.text}({', '.join(args)})")


# --------------------------------------------------------------------------
# Loop (for ... in ...) recovery
# --------------------------------------------------------------------------

_ITER_STARTS = {
    Op.ITER_START_ARRAY,
    Op.ITER_START_DICT,
    Op.ITER_START_INT_RANGE,
    Op.ITER_START_INT_ENUM,
    Op.ITER_START_STRING_SET,
    Op.ITER_START_TEXT_STRING_SET,
}


@dataclass
class LoopShape:
    """Instruction-index landmarks of one compiled ``for`` loop."""

    header: int          # index of the first CLEAR_M
    quant_slot: int      # memory slot holding the quantifier
    iter_lo: int         # first index of the iterable expression
    iter_start: int      # index of the ITER_START_* opcode
    kind: Op
    var_slot: int        # memory slot holding the loop variable
    body_lo: int         # first index of the body
    body_hi: int         # exclusive end of the body
    end: int             # index of ITER_END


def _find_loops(instrs: list[Instr]) -> dict[int, LoopShape]:
    """
    Locate compiled ``for`` loops, keyed by the index of their first
    instruction so the main walk can hand off and skip the whole region.

    YARA emits a fixed shape (libyara/grammar.y, ``for_expression``):

        PUSH <quantifier>
        CLEAR_M m_acc ; CLEAR_M m_count ; POP_M m_quant
        <iterable>
        ITER_START_xxx
      L: ITER_NEXT ; POP_M m_var ; JTRUE_P -> E
        <body>
        INCR_M m_count ; PUSH_M m_acc ; PUSH_M m_quant
        ITER_CONDITION ; ADD_M m_acc ; JTRUE_P -> L
      E: POP ; PUSH_M m_count ; PUSH_M m_acc ; PUSH_M m_quant ; ITER_END

    Matching the shape is far more robust than trying to follow the control
    flow, because the jumps are all internal to the pattern.
    """
    out: dict[int, LoopShape] = {}
    n = len(instrs)

    for s_idx, ins in enumerate(instrs):
        if ins.op not in _ITER_STARTS:
            continue

        # Header: the nearest CLEAR_M, CLEAR_M, POP_M triple before the
        # iterable expression.
        header = None
        quant_slot = None
        for j in range(s_idx - 1, 1, -1):
            if (
                instrs[j].op is Op.POP_M
                and instrs[j - 1].op is Op.CLEAR_M
                and instrs[j - 2].op is Op.CLEAR_M
            ):
                header = j - 2
                quant_slot = instrs[j].operand
                iter_lo = j + 1
                break
        if header is None:
            continue

        # Loop preamble: ITER_NEXT, POP_M var, JTRUE_P
        if s_idx + 2 >= n:
            continue
        if instrs[s_idx + 1].op is not Op.ITER_NEXT:
            continue
        if instrs[s_idx + 2].op is not Op.POP_M:
            continue
        var_slot = instrs[s_idx + 2].operand
        body_lo = s_idx + 4 if instrs[s_idx + 3].op in _POPPING_JUMPS else s_idx + 3

        # Body ends at the INCR_M that begins the loop epilogue.
        body_hi = None
        for j in range(body_lo, n - 3):
            if (
                instrs[j].op is Op.INCR_M
                and instrs[j + 1].op is Op.PUSH_M
                and instrs[j + 2].op is Op.PUSH_M
                and instrs[j + 3].op is Op.ITER_CONDITION
            ):
                body_hi = j
                break
        if body_hi is None:
            continue

        end = None
        for j in range(body_hi, n):
            if instrs[j].op is Op.ITER_END:
                end = j
                break
        if end is None:
            continue

        out[header] = LoopShape(
            header=header,
            quant_slot=quant_slot,
            iter_lo=iter_lo,
            iter_start=s_idx,
            kind=ins.op,
            var_slot=var_slot,
            body_lo=body_lo,
            body_hi=body_hi,
            end=end,
        )
    return out


_VAR_NAMES = ("i", "j", "k", "n", "m")
_OBJ_VAR_NAMES = ("item", "elem", "entry", "value")


def _int_literal(value: int) -> str:
    if value == 0xFFFFFFFFFFFFFFFF:
        return "undefined"
    # Present large round numbers the way a human wrote them.
    # Only fold values that a human plausibly wrote as a size literal.
    # Folding 1024 into "1KB" is valid YARA but is a guess about intent, so
    # restrict this to whole megabytes.
    unit = 1 << 20
    if value and value % unit == 0 and value // unit < 1024:
        return f"{value // unit}MB"
    # Constants above 0x1000 that are not round decimals are almost always
    # magic values (0x5A4D, 0xFEEDFACE); hex is how they were written.
    if value > 0xFFF and value % 1000 and value % 1024:
        return f"0x{value:X}"
    return str(value)


def split_rule_bodies(instrs: list[Instr]) -> dict[int, list[Instr]]:
    """Slice the instruction stream into per-rule bodies."""
    bodies: dict[int, list[Instr]] = {}
    current: Optional[int] = None
    buf: list[Instr] = []
    for ins in instrs:
        if ins.op is Op.INIT_RULE:
            if current is not None:
                bodies[current] = buf
            current = ins.rule_index
            buf = []
            continue
        if ins.op is Op.MATCH_RULE:
            if current is not None:
                bodies[current] = buf
            current, buf = None, []
            continue
        if ins.op is Op.HALT:
            break
        if current is not None:
            buf.append(ins)
    if current is not None:
        bodies[current] = buf
    return bodies


def format_listing(instrs: list[Instr], resolve=None) -> list[str]:
    lines = []
    for ins in instrs:
        parts = [f"    {ins.offset:6d}  {ins.op.name:<22}"]
        if ins.operand is not None:
            extra = None
            if resolve:
                extra = resolve(ins)
            parts.append(extra if extra else f"0x{ins.operand:x}")
        if ins.target is not None:
            parts.append(f"-> {ins.target}")
        if ins.rule_index is not None:
            parts.append(f"rule={ins.rule_index}")
        lines.append(" ".join(parts).rstrip())
    return lines
