"""End-to-end decompilation pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import code as C
from . import repattern as rp
from . import b64
from .acmatch import collect_string_code
from .arena import Arena
from .constants import Op, Section, StringFlags
from .emit import EmitOptions, render_all
from .parser import CompiledRules, RulesParser


@dataclass
class Result:
    compiled: CompiledRules
    source: str
    warnings: list[str] = field(default_factory=list)
    listings: dict[int, list[str]] = field(default_factory=dict)

    @property
    def conditions_recovered(self) -> int:
        return sum(1 for r in self.compiled.rules if r.condition)

    @property
    def patterns_recovered(self) -> int:
        return sum(
            1
            for s in self.compiled.strings
            if (s.flags & StringFlags.LITERAL) or s.rendered
        )


def _recover_imports(instrs: list[C.Instr], arena: Arena) -> list[str]:
    out: list[str] = []
    for ins in instrs:
        if ins.op is Op.IMPORT and ins.operand is not None:
            ref = C.unpack_ref(ins.operand)
            if ref.buffer_id == Section.SZ_POOL:
                name = arena.cstring(ref)
                if name and name not in out:
                    out.append(name)
    return out


def _recover_patterns(compiled: CompiledRules) -> list[str]:
    """Fill in ``YrString.rendered`` for every non-literal pattern."""
    warnings: list[str] = []
    arena = compiled.arena
    re_code = arena.buffer(Section.RE_CODE_SECTION)
    if not re_code:
        return warnings

    segments = rp.segment_programs(re_code)
    code_map = collect_string_code(arena)

    for s in compiled.strings:
        if s.flags & StringFlags.LITERAL:
            continue

        entry = code_map.get(s.index)
        if entry is None or not entry.forward:
            warnings.append(
                f"{s.identifier}: no Aho-Corasick entry links this pattern to "
                f"a regexp program; cannot recover"
            )
            continue

        # A pattern may own several programs (base64 produces one per
        # permutation). Resolve each distinct forward offset to its segment.
        segs: list[tuple[int, int]] = []
        for off in sorted(entry.forward):
            seg = rp.program_containing(segments, off)
            if seg and seg not in segs:
                segs.append(seg)
        if not segs:
            warnings.append(f"{s.identifier}: forward code offset outside any program")
            continue

        rendered: list[str] = []
        exact = True
        for seg in segs:
            try:
                instrs = rp.disassemble_program(re_code, seg[0])
            except rp.ReDecodeError as exc:
                warnings.append(f"{s.identifier}: {exc}")
                exact = False
                continue

            is_hex = bool(s.flags & StringFlags.HEXADECIMAL)
            if is_hex:
                text = rp.render_hex(instrs)
                if text is not None:
                    rendered.append(text)
                    continue
            text, full = rp.render_regex(instrs)
            if not full:
                exact = False
            rendered.append("/" + text + "/" + _regex_suffix(s))

        if not rendered:
            continue

        # A base64 pattern compiles to the three permutations of its
        # plaintext. Those permutations fully determine the plaintext, so
        # recover it and validate by re-expanding -- never guess.
        if s.flags & (StringFlags.BASE64 | StringFlags.BASE64_WIDE):
            perms: list[str] = []
            for seg in segs:
                try:
                    perms.extend(
                        rp.literal_runs(rp.disassemble_program(re_code, seg[0]))
                    )
                except rp.ReDecodeError:
                    pass
            plaintext = b64.recover(perms) if perms else None
            if plaintext is not None:
                s.rendered = '"' + _escape(plaintext) + '"'
                continue
            warnings.append(
                f"{s.identifier}: base64 plaintext could not be recovered "
                f"from the compiled permutations; showing the raw alternation"
            )

        if len(rendered) == 1:
            s.rendered = rendered[0]
        else:
            s.rendered = rendered[0]
            warnings.append(
                f"{s.identifier}: {len(rendered)} regexp programs found; "
                f"showing the first"
            )
        if not exact:
            warnings.append(
                f"{s.identifier}: regexp contains constructs that could not be "
                f"folded back to source syntax; output is approximate"
            )
    return warnings


def _regex_suffix(s) -> str:
    suffix = ""
    if s.flags & StringFlags.NO_CASE:
        suffix += "i"
    if s.flags & StringFlags.DOT_ALL and s.flags & StringFlags.REGEXP:
        suffix += "s"
    return suffix


def decompile(
    path,
    *,
    opts: Optional[EmitOptions] = None,
    strict: bool = True,
) -> Result:
    arena = Arena.from_file(path, strict=strict)
    compiled = RulesParser(arena).parse()

    warnings: list[str] = []
    warnings.extend(_recover_patterns(compiled))

    code_buf = arena.buffer(Section.CODE_SECTION)
    listings: dict[int, list[str]] = {}
    if code_buf:
        instrs = C.disassemble(code_buf)
        compiled.imports = _recover_imports(instrs, arena)
        bodies = C.split_rule_bodies(instrs)

        string_names = {s.index: s.identifier for s in compiled.strings}
        rule_names = {r.index: r.identifier for r in compiled.rules}

        for rule in compiled.rules:
            body = bodies.get(rule.index, [])
            rec = C.ConditionRecovery(
                arena,
                code_buf,
                string_names,
                rule_names,
                rule_strings=[s.identifier for s in rule.strings],
            )
            try:
                cond = rec.run(body)
            except C.CodeError as exc:
                cond, rec.notes = None, rec.notes + [str(exc)]
            rule.condition = cond
            if cond is None:
                listings[rule.index] = C.format_listing(body)
                warnings.extend(
                    f"{rule.identifier}: {n}" for n in rec.notes
                )

    source, emit_warnings = render_all(compiled, opts, listings)
    warnings.extend(emit_warnings)
    return Result(
        compiled=compiled,
        source=source,
        warnings=warnings,
        listings=listings,
    )


def _escape(data: bytes) -> str:
    from .emit import escape_text

    return escape_text(data)
