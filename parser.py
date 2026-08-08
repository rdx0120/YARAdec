"""
Parses the rule/string/meta/namespace tables out of a YARA 4.x arena.

The 4.x arena stores these as flat arrays in dedicated buffers, with the
element counts in a YR_SUMMARY struct. This is a large improvement over the
3.x format, where the only reliable way to enumerate rules was to walk the
bytecode looking for OP_INIT_RULE. We no longer guess: we read the tables.

Struct layouts (libyara/include/yara/types.h @ v4.5.8, pack(8), with
DECLARE_REFERENCE unions occupying 8 bytes each):

    YR_RULE      56 bytes   flags:i32 num_atoms:i32 required_strings:u32
                            unused:u32 identifier:ref tags:ref metas:ref
                            strings:ref ns:ref
    YR_STRING    56 bytes   flags:u32 idx:u32 fixed_offset:i64 rule_idx:u32
                            length:i32 string:ref chained_to:ref
                            chain_gap_min:i32 chain_gap_max:i32 identifier:ref
    YR_META      32 bytes   identifier:ref string:ref integer:i64 type:i32
                            flags:i32
    YR_NAMESPACE 16 bytes   name:ref idx:u32 (padded to 8)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .arena import Arena, ArenaError, Ref
from .constants import (
    META_FLAGS_LAST_IN_RULE,
    SIZEOF_META,
    SIZEOF_NAMESPACE,
    SIZEOF_RULE,
    SIZEOF_STRING,
    MetaType,
    RuleFlags,
    Section,
    StringFlags,
)

_RULE_FMT = "<iiII" + "II" * 5
_STRING_FMT = "<IIqIi" + "II" + "II" + "ii" + "II"
_META_FMT = "<IIIIqii"
_NS_FMT = "<IIQ"


@dataclass
class Meta:
    identifier: str
    type: MetaType
    value: object

    @property
    def is_last(self) -> bool:  # pragma: no cover - informational
        return False


@dataclass
class YrString:
    index: int
    identifier: str
    flags: StringFlags
    rule_index: int
    length: int
    data: bytes
    fixed_offset: Optional[int]
    chained_to: Optional[int]
    chain_gap_min: int
    chain_gap_max: int
    #: Offset of this string's regexp program in the RE code section, if any.
    re_code_ref: Optional[Ref] = None
    #: Reconstructed pattern text, filled in by the emitter.
    rendered: Optional[str] = None

    @property
    def is_anonymous(self) -> bool:
        return bool(self.flags & StringFlags.ANONYMOUS)

    @property
    def is_chain_part(self) -> bool:
        return bool(self.flags & StringFlags.CHAIN_PART)


@dataclass
class Rule:
    index: int
    identifier: str
    namespace: Optional[str]
    flags: RuleFlags
    tags: list[str] = field(default_factory=list)
    metas: list[Meta] = field(default_factory=list)
    strings: list[YrString] = field(default_factory=list)
    num_atoms: int = 0
    required_strings: int = 0
    #: Offset into the code section where this rule's condition begins.
    code_offset: Optional[int] = None
    #: Reconstructed condition text, filled in by the condition recovery pass.
    condition: Optional[str] = None

    @property
    def is_private(self) -> bool:
        return bool(self.flags & RuleFlags.PRIVATE)

    @property
    def is_global(self) -> bool:
        return bool(self.flags & RuleFlags.GLOBAL)


@dataclass
class Summary:
    num_rules: int
    num_strings: int
    num_namespaces: int


@dataclass
class CompiledRules:
    arena: Arena
    summary: Summary
    namespaces: list[str]
    rules: list[Rule]
    strings: list[YrString]
    imports: list[str] = field(default_factory=list)


class RulesParser:
    def __init__(self, arena: Arena) -> None:
        self.arena = arena
        self.summary = self._read_summary()

    # -- tables ------------------------------------------------------------

    def _read_summary(self) -> Summary:
        buf = self.arena.buffer(Section.SUMMARY_SECTION)
        if len(buf) < 12:
            raise ArenaError("summary section is too small")
        num_rules, num_strings, num_namespaces = struct.unpack_from("<III", buf, 0)
        return Summary(num_rules, num_strings, num_namespaces)

    def _ref(self, values: tuple, i: int) -> Ref:
        return Ref(values[i], values[i + 1])

    def parse_namespaces(self) -> list[str]:
        buf = self.arena.buffer(Section.NAMESPACES_TABLE)
        out: list[str] = []
        for i in range(self.summary.num_namespaces):
            off = i * SIZEOF_NAMESPACE
            if off + SIZEOF_NAMESPACE > len(buf):
                raise ArenaError(f"namespace table truncated at entry {i}")
            bid, boff, _idx = struct.unpack_from(_NS_FMT, buf, off)
            out.append(self.arena.cstring(Ref(bid, boff)) or "default")
        return out

    def parse_metas(self, start: Ref) -> list[Meta]:
        """Metas run until one carries META_FLAGS_LAST_IN_RULE."""
        if start.is_null:
            return []
        buf = self.arena.buffer(start.buffer_id)
        out: list[Meta] = []
        off = start.offset
        while off + SIZEOF_META <= len(buf):
            (
                id_bid,
                id_off,
                str_bid,
                str_off,
                integer,
                mtype,
                flags,
            ) = struct.unpack_from(_META_FMT, buf, off)

            identifier = self.arena.cstring(Ref(id_bid, id_off)) or ""
            if mtype == MetaType.STRING:
                value = self.arena.cstring(Ref(str_bid, str_off)) or ""
            elif mtype == MetaType.BOOLEAN:
                value = bool(integer)
            elif mtype == MetaType.INTEGER:
                value = integer
            else:
                # Unknown meta type -- stop rather than emit garbage.
                break

            out.append(Meta(identifier=identifier, type=MetaType(mtype), value=value))
            off += SIZEOF_META
            if flags & META_FLAGS_LAST_IN_RULE:
                break
            if len(out) > 4096:
                raise ArenaError("meta list did not terminate; file may be corrupt")
        return out

    def parse_strings(self) -> list[YrString]:
        buf = self.arena.buffer(Section.STRINGS_TABLE)
        out: list[YrString] = []
        for i in range(self.summary.num_strings):
            off = i * SIZEOF_STRING
            if off + SIZEOF_STRING > len(buf):
                raise ArenaError(f"string table truncated at entry {i}")
            vals = struct.unpack_from(_STRING_FMT, buf, off)
            (
                flags,
                idx,
                fixed_offset,
                rule_idx,
                length,
                s_bid,
                s_off,
                c_bid,
                c_off,
                gap_min,
                gap_max,
                id_bid,
                id_off,
            ) = vals

            sflags = StringFlags(flags)
            str_ref = Ref(s_bid, s_off)

            data = b""
            re_ref: Optional[Ref] = None
            if not str_ref.is_null:
                if not sflags & StringFlags.LITERAL:
                    # Any non-literal pattern (regexp, or a hex string with
                    # wildcards/jumps/alternatives) stores a compiled regexp
                    # program instead of raw bytes, and the "string" pointer
                    # targets the RE code section. Note that hex strings carry
                    # HEXADECIMAL|FAST_REGEXP but NOT the REGEXP flag, so
                    # keying off REGEXP alone silently misses them.
                    re_ref = str_ref
                elif length >= 0:
                    try:
                        data = self.arena.read(str_ref, length)
                    except ArenaError:
                        data = b""

            chained_to = None
            chain_ref = Ref(c_bid, c_off)
            if not chain_ref.is_null and chain_ref.buffer_id == Section.STRINGS_TABLE:
                chained_to = chain_ref.offset // SIZEOF_STRING

            out.append(
                YrString(
                    index=idx,
                    identifier=self.arena.cstring(Ref(id_bid, id_off)) or f"$__{i}",
                    flags=sflags,
                    rule_index=rule_idx,
                    length=length,
                    data=data,
                    fixed_offset=(
                        fixed_offset
                        if sflags & StringFlags.FIXED_OFFSET
                        else None
                    ),
                    chained_to=chained_to,
                    chain_gap_min=gap_min,
                    chain_gap_max=gap_max,
                    re_code_ref=re_ref,
                )
            )
        return out

    def parse_rules(self, namespaces: list[str], strings: list[YrString]) -> list[Rule]:
        buf = self.arena.buffer(Section.RULES_TABLE)
        by_rule: dict[int, list[YrString]] = {}
        for s in strings:
            by_rule.setdefault(s.rule_index, []).append(s)

        out: list[Rule] = []
        for i in range(self.summary.num_rules):
            off = i * SIZEOF_RULE
            if off + SIZEOF_RULE > len(buf):
                raise ArenaError(f"rule table truncated at entry {i}")
            vals = struct.unpack_from(_RULE_FMT, buf, off)
            flags, num_atoms, required_strings, _unused = vals[:4]

            rflags = RuleFlags(flags & 0xF)
            if rflags & RuleFlags.NULL:
                break  # sentinel terminating the table

            identifier = self.arena.cstring(self._ref(vals, 4)) or f"rule_{i}"
            tags = self.arena.cstring_list(self._ref(vals, 6))
            metas = self.parse_metas(self._ref(vals, 8))

            ns_ref = self._ref(vals, 12)
            namespace = None
            if not ns_ref.is_null:
                ns_idx = ns_ref.offset // SIZEOF_NAMESPACE
                if 0 <= ns_idx < len(namespaces):
                    namespace = namespaces[ns_idx]

            rule_strings = sorted(by_rule.get(i, []), key=lambda s: s.index)

            out.append(
                Rule(
                    index=i,
                    identifier=identifier,
                    namespace=namespace,
                    flags=rflags,
                    tags=tags,
                    metas=metas,
                    strings=rule_strings,
                    num_atoms=num_atoms,
                    required_strings=required_strings,
                )
            )
        return out

    def parse(self) -> CompiledRules:
        namespaces = self.parse_namespaces()
        strings = self.parse_strings()
        rules = self.parse_rules(namespaces, strings)
        return CompiledRules(
            arena=self.arena,
            summary=self.summary,
            namespaces=namespaces,
            rules=rules,
            strings=strings,
        )


def parse_file(path, *, strict: bool = True) -> CompiledRules:
    return RulesParser(Arena.from_file(path, strict=strict)).parse()
