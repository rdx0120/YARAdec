"""Renders recovered rules back into YARA source text."""

from __future__ import annotations

import string as _string
from dataclasses import dataclass
from typing import Optional

from .constants import MetaType, Section, StringFlags
from .parser import CompiledRules, Rule, YrString

_PRINTABLE = set(_string.printable) - set("\t\n\r\x0b\x0c")


def escape_text(data: bytes) -> str:
    out = []
    for b in data:
        ch = chr(b)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif 0x20 <= b < 0x7F:
            out.append(ch)
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def as_hex_bytes(data: bytes) -> str:
    return "{ " + " ".join(f"{b:02X}" for b in data) + " }"


def looks_textual(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if 0x20 <= b < 0x7F or b in (9, 10, 13))
    return printable / len(data) >= 0.9


@dataclass
class EmitOptions:
    indent: str = "    "
    #: Emit a comment for every modifier that cannot be recovered exactly.
    annotate_lossy: bool = True
    #: Include the VM listing for conditions that could not be reconstructed.
    include_listing: bool = True


def render_string_body(s: YrString) -> tuple[str, list[str]]:
    """Return (pattern_text, warnings)."""
    warnings: list[str] = []
    flags = s.flags

    if s.rendered is not None:
        return s.rendered, warnings

    if flags & StringFlags.LITERAL:
        if flags & StringFlags.HEXADECIMAL:
            return as_hex_bytes(s.data), warnings
        # Everything else was written as a text string. Render it as one even
        # when it holds NUL or high bytes -- "\xHH" escapes cover those.
        # Falling back to { } braces here would be wrong twice over: it
        # misrepresents the source, and hex strings cannot carry the wide /
        # fullword / nocase modifiers the string may have.
        return f'"{escape_text(s.data)}"', warnings

    warnings.append(
        f"pattern for {s.identifier} could not be reconstructed "
        f"(no regexp program reachable from the Aho-Corasick tables)"
    )
    return '"<unrecovered>"', warnings


def render_modifiers(s: YrString) -> tuple[list[str], list[str]]:
    """
    Return (modifiers, lossy_notes).

    Some modifiers are provably unrecoverable: ``xor`` ranges and ``base64``
    alphabets are consumed during atom generation and never stored in
    YR_STRING, so the exact source text cannot be reproduced. We emit the
    bare modifier and say so rather than inventing a range.
    """
    mods: list[str] = []
    notes: list[str] = []
    flags = s.flags

    is_regex = not (flags & StringFlags.LITERAL)
    is_base64 = bool(flags & (StringFlags.BASE64 | StringFlags.BASE64_WIDE))
    # A hex string accepts only "private". The compiled flags still carry
    # ASCII (and sometimes others) for hex strings, so they must be filtered
    # or the emitted source will not parse.
    is_hex = bool(flags & StringFlags.HEXADECIMAL) and bool(
        flags & StringFlags.LITERAL
    )
    if is_hex:
        return (["private"] if flags & StringFlags.PRIVATE else []), notes

    # YARA rejects base64/base64wide combined with nocase, xor, fullword or
    # wide. The compiled flags can still carry some of those bits, so emitting
    # them verbatim produces source that will not compile.
    if flags & StringFlags.NO_CASE and not is_regex and not is_base64:
        mods.append("nocase")
    if flags & StringFlags.WIDE and not is_base64:
        mods.append("wide")
    if flags & StringFlags.ASCII and flags & StringFlags.WIDE and not is_base64:
        mods.append("ascii")
    if flags & StringFlags.FULL_WORD and not is_base64:
        mods.append("fullword")
    if flags & StringFlags.PRIVATE:
        mods.append("private")
    if flags & StringFlags.XOR and not is_base64:
        mods.append("xor")
        notes.append(
            f"{s.identifier}: the xor key range is expanded into atoms at "
            f"compile time and is not stored in the compiled rules; "
            f"'xor' is emitted without its original (min-max) range"
        )
    if flags & StringFlags.BASE64:
        mods.append("base64")
        notes.append(
            f"{s.identifier}: base64 alphabet is not retained in compiled "
            f"rules; a custom alphabet, if any, cannot be recovered"
        )
    if flags & StringFlags.BASE64_WIDE:
        mods.append("base64wide")
    return mods, notes


def render_regex_suffix(s: YrString) -> str:
    suffix = ""
    if s.flags & StringFlags.NO_CASE:
        suffix += "i"
    if s.flags & StringFlags.DOT_ALL and s.flags & StringFlags.REGEXP:
        suffix += "s"
    return suffix


def render_rule(rule: Rule, opts: EmitOptions, listing: Optional[list[str]] = None) -> tuple[str, list[str]]:
    ind = opts.indent
    warnings: list[str] = []
    lines: list[str] = []

    header = []
    if rule.is_private:
        header.append("private")
    if rule.is_global:
        header.append("global")
    header.append("rule")
    header.append(rule.identifier)
    line = " ".join(header)
    if rule.tags:
        line += " : " + " ".join(rule.tags)
    lines.append(line)
    lines.append("{")

    if rule.metas:
        lines.append(f"{ind}meta:")
        for m in rule.metas:
            if m.type is MetaType.STRING:
                value = f'"{escape_text(str(m.value).encode())}"'
            elif m.type is MetaType.BOOLEAN:
                value = "true" if m.value else "false"
            else:
                value = str(m.value)
            lines.append(f"{ind}{ind}{m.identifier} = {value}")
        lines.append("")

    visible = [s for s in rule.strings if not s.is_chain_part or s.chained_to is None]
    if visible:
        lines.append(f"{ind}strings:")
        for s in visible:
            body, w = render_string_body(s)
            warnings.extend(w)
            mods, notes = render_modifiers(s)
            warnings.extend(notes)
            lines.append(
                f"{ind}{ind}{s.identifier} = {body}"
                + ("".join(" " + m for m in mods) if mods else "")
            )
        lines.append("")

    lines.append(f"{ind}condition:")
    if rule.condition:
        lines.append(f"{ind}{ind}{rule.condition}")
    else:
        # A condition block cannot be empty or the output will not parse.
        # Emit an explicit "false" so the file still compiles, and make the
        # substitution impossible to miss.
        # "false" alone would leave every string unreferenced, which YARA
        # rejects; "and any of them" keeps the references alive without
        # changing the (already placeholder) result.
        placeholder = "false and any of them" if visible else "false"
        lines.append(
            f"{ind}{ind}{placeholder}  // FIXME: condition NOT reconstructed"
            f" - placeholder, not the original logic"
        )
        warnings.append(
            f"{rule.identifier}: condition not reconstructed"
        )
        if listing and opts.include_listing:
            for entry in listing:
                lines.append(f"{ind}{ind}// {entry.strip()}")
    lines.append("}")
    return "\n".join(lines), warnings


def render_all(
    compiled: CompiledRules,
    opts: Optional[EmitOptions] = None,
    listings: Optional[dict[int, list[str]]] = None,
) -> tuple[str, list[str]]:
    opts = opts or EmitOptions()
    listings = listings or {}
    warnings: list[str] = []
    chunks: list[str] = []

    for module in compiled.imports:
        chunks.append(f'import "{module}"')
    if compiled.imports:
        chunks.append("")

    by_ns: dict[Optional[str], list[Rule]] = {}
    for r in compiled.rules:
        by_ns.setdefault(r.namespace, []).append(r)

    multi_ns = len([k for k in by_ns if k not in (None, "default")]) > 0

    for ns, rules in by_ns.items():
        if multi_ns:
            chunks.append(f"// namespace: {ns or 'default'}")
        for r in rules:
            text, w = render_rule(r, opts, listings.get(r.index))
            warnings.extend(w)
            chunks.append(text)
            chunks.append("")

    return "\n".join(chunks).rstrip() + "\n", warnings
