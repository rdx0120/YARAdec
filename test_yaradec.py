"""
Tests for yaradec.

Rules are compiled with the real YARA at test time rather than checked in as
fixtures, so the suite tracks whatever YARA version is installed instead of
asserting against a frozen blob.
"""

from __future__ import annotations

import struct

import pytest

yara = pytest.importorskip("yara", reason="yara-python is required")

from yaradec.arena import Arena, ArenaError, Ref, UnsupportedVersionError  # noqa: E402
from yaradec import b64  # noqa: E402
from yaradec import repattern as rp  # noqa: E402
from yaradec.constants import (  # noqa: E402
    SIZEOF_META,
    SIZEOF_NAMESPACE,
    SIZEOF_RULE,
    SIZEOF_STRING,
    Section,
    StringFlags,
)
from yaradec.decompile import decompile  # noqa: E402


@pytest.fixture
def compile_rules(tmp_path):
    """Compile YARA source and return the path to the compiled rules."""

    def _compile(source: str, name: str = "r"):
        src = tmp_path / f"{name}.yar"
        src.write_text(source)
        out = tmp_path / f"{name}.yarc"
        yara.compile(filepath=str(src)).save(str(out))
        return out

    return _compile


@pytest.fixture
def roundtrip(compile_rules, tmp_path):
    """Decompile, recompile, and return (result, recompiled_rules)."""

    def _roundtrip(source: str):
        result = decompile(compile_rules(source))
        out = tmp_path / "back.yar"
        out.write_text(result.source)
        return result, yara.compile(filepath=str(out))

    return _roundtrip


# ---------------------------------------------------------------- container


def test_rejects_non_yara_file(tmp_path):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"NOPE" + b"\x00" * 64)
    with pytest.raises(ArenaError, match="bad magic"):
        Arena.from_file(bad)


def test_rejects_truncated_file(tmp_path):
    bad = tmp_path / "short.bin"
    bad.write_bytes(b"YAR")
    with pytest.raises(ArenaError, match="too small"):
        Arena.from_file(bad)


def test_legacy_version_gives_actionable_error(tmp_path):
    """A YARA 3.x file should name the version, not fail obscurely."""
    legacy = tmp_path / "old.yarc"
    legacy.write_bytes(b"YARA" + bytes([11, 12]) + b"\x00" * 64)
    with pytest.raises(UnsupportedVersionError) as exc:
        Arena.from_file(legacy)
    assert "3.x" in str(exc.value)


def test_arena_header(compile_rules):
    arena = Arena.from_file(compile_rules('rule a { condition: true }'))
    assert arena.version == 21
    assert len(arena.buffers) == 12


def test_null_ref_detection():
    assert Ref(0xFFFFFFFF, 0xFFFFFFFF).is_null
    assert not Ref(3, 0).is_null


# ------------------------------------------------------------ struct layout


def test_struct_sizes_match_compiled_output(compile_rules):
    """
    The table buffers must be exact multiples of our struct sizes. If a future
    YARA changes a struct, this fails loudly instead of silently misparsing.
    """
    path = compile_rules(
        """
        rule r1 { meta: a = 1 b = "x" strings: $s = "aaa" condition: $s }
        rule r2 { strings: $t = "bbb" condition: $t }
        """
    )
    arena = Arena.from_file(path)
    assert len(arena.buffer(Section.RULES_TABLE)) % SIZEOF_RULE == 0
    assert len(arena.buffer(Section.STRINGS_TABLE)) % SIZEOF_STRING == 0
    assert len(arena.buffer(Section.METAS_TABLE)) % SIZEOF_META == 0
    assert len(arena.buffer(Section.NAMESPACES_TABLE)) % SIZEOF_NAMESPACE == 0


def test_summary_counts_match(compile_rules):
    path = compile_rules(
        """
        rule a { strings: $x = "1" $y = "2" condition: $x and $y }
        rule b { strings: $z = "3" condition: $z }
        """
    )
    result = decompile(path)
    assert len(result.compiled.rules) == 2
    assert len(result.compiled.strings) == 3


# ------------------------------------------------------------------ parsing


def test_rule_flags_and_tags(roundtrip):
    result, _ = roundtrip(
        """
        private rule P { condition: true }
        global rule G { condition: filesize > 0 }
        rule T : alpha beta { condition: true }
        """
    )
    by_name = {r.identifier: r for r in result.compiled.rules}
    assert by_name["P"].is_private
    assert by_name["G"].is_global
    assert by_name["T"].tags == ["alpha", "beta"]


def test_all_meta_types(roundtrip):
    result, _ = roundtrip(
        """
        rule M {
            meta:
                s = "text"
                i = 42
                neg = -7
                t = true
                f = false
            condition: true
        }
        """
    )
    metas = {m.identifier: m.value for m in result.compiled.rules[0].metas}
    assert metas == {"s": "text", "i": 42, "neg": -7, "t": True, "f": False}


# ----------------------------------------------------------------- patterns


@pytest.mark.parametrize(
    "pattern",
    [
        '"plain"',
        '"nocase me" nocase',
        '"wide me" wide',
        '"both" wide ascii',
        '"word" fullword',
        "{ 4D 5A 90 00 }",
        "{ 4D 5A ?? 00 }",
        "{ 4D 5A [2-6] 00 }",
        "{ 4D 5A [4] 00 }",
        "{ 4D ?A 5? 00 }",
        "/abc[0-9]+/",
        "/abc[0-9]{2,4}/i",
        "/a(bc|de)f/",
        "/x*y+z?/",
        "/^anchored$/",
        r"/\w+\s\d+/",
    ],
)
def test_pattern_roundtrips(roundtrip, pattern):
    """Every pattern form must survive compile -> decompile -> recompile."""
    result, _ = roundtrip(f"rule P {{ strings: $a = {pattern} condition: $a }}")
    assert not any("unrecovered" in w for w in result.warnings)
    assert result.compiled.strings[0].rendered or (
        result.compiled.strings[0].flags & StringFlags.LITERAL
    )


def test_hex_wildcard_recovers_exactly(roundtrip):
    result, _ = roundtrip(
        "rule H { strings: $a = { 4D 5A 90 00 03 ?? 00 00 } condition: $a }"
    )
    assert result.compiled.strings[0].rendered == "{ 4D 5A 90 00 03 ?? 00 00 }"


def test_bounded_repeat_is_normalised(roundtrip):
    """
    YARA expands e{2,4} into a mandatory part plus optional parts. The merge
    pass must fold that back rather than emitting e e{1,2} e?.
    """
    result, _ = roundtrip("rule R { strings: $a = /x[0-9]{2,4}y/ condition: $a }")
    assert result.compiled.strings[0].rendered == "/x[0-9]{2,4}y/"


def test_literal_dots_are_not_turned_into_a_quantifier(roundtrip):
    """
    Four ANY instructions come from "...." in the source, not ".{4}".
    Collapsing them invents a greedy quantifier that YARA then refuses to mix
    with a genuine ungreedy one.
    """
    result, recompiled = roundtrip(
        r"rule D { strings: $a = /a....b.{3,9}?c/ condition: $a }"
    )
    assert recompiled is not None
    assert "{4}" not in (result.compiled.strings[0].rendered or "")


def test_regex_uses_capturing_groups(roundtrip):
    """YARA's engine has no (?:...) -- emitting it is a syntax error there."""
    result, _ = roundtrip("rule G { strings: $a = /(ab|cd)+e/ condition: $a }")
    assert "(?:" not in (result.compiled.strings[0].rendered or "")


def test_slash_in_class_is_escaped(roundtrip):
    """An unescaped / inside a class silently terminates the pattern."""
    result, _ = roundtrip(r"rule S { strings: $a = /[a-z\/]+x/ condition: $a }")
    rendered = result.compiled.strings[0].rendered
    assert rendered is not None and rendered.startswith("/")


def test_text_string_with_nul_stays_a_text_string(roundtrip):
    """
    A text string containing NUL must not be rendered as { } braces: hex
    strings cannot carry wide/fullword, so the output would not compile.
    """
    result, _ = roundtrip(
        r'rule N { strings: $a = "TEMP\x00\x00DEF" wide fullword condition: $a }'
    )
    assert '"' in result.source.split("$a =")[1].split("\n")[0]


# ------------------------------------------------------------------- base64


def test_base64_expansion_matches_yara(compile_rules):
    """Our model of YARA's permutation rule must match what YARA emits."""
    result = decompile(
        compile_rules('rule B { strings: $a = "b64me" base64 condition: $a }')
    )
    assert result.compiled.strings[0].rendered == '"b64me"'


@pytest.mark.parametrize(
    "plaintext", [b"b64me", b"powershell", b"ab", b"This program cannot"]
)
def test_base64_recovery_roundtrips(plaintext):
    assert b64.recover(b64.expand(plaintext)) == plaintext


def test_base64_recovery_rejects_garbage():
    """Recovery is validated by re-expansion, so it must not guess."""
    assert b64.recover(["!!!!not base64!!!!"]) is None


# --------------------------------------------------------------- conditions


@pytest.mark.parametrize(
    "condition",
    [
        "true",
        "filesize < 10MB",
        "uint16(0) == 0x5A4D",
        "uint32be(4) == 0x1234",
        "$a and $b",
        "$a or $b",
        "not $a",
        "$a and not $b",
        "#a > 2",
        "@a < 100",
        "!a == 3",
        "$a at 0",
        "$a in (0..1024)",
        "#a in (0..500) > 1",
        "2 of ($a, $b)",
        "all of them",
        "any of them",
        "1 of ($a*)",
        "for any i in (1..#a) : ( @a[i] < 100 )",
        "for all of them : ( $ in (0..1024) )",
        "for any of ($a, $b) : ( $ at 0 )",
        "(filesize > 10 and $a) or (filesize < 5 and $b)",
        "filesize \\ 1024 > 4",
        "$a and filesize % 2 == 0",
    ],
)
def test_condition_roundtrips(roundtrip, condition):
    # Declare only the strings the condition actually uses: YARA rejects a
    # rule that declares a string it never references.
    decls = "".join(
        f' ${n} = "{n * 3}"' for n in ("a", "b")
        if f"${n}" in condition or f"#{n}" in condition
        or f"@{n}" in condition or f"!{n}" in condition
        or "them" in condition
    )
    strings = f" strings:{decls}" if decls else ""
    result, _ = roundtrip(f"rule C {{{strings} condition: {condition} }}")
    assert result.compiled.rules[0].condition is not None, result.warnings


def test_condition_recovers_exactly(roundtrip):
    result, _ = roundtrip(
        """
        rule E {
            strings:
                $a = "aaa"
                $b = "bbb"
            condition:
                $a and #b > 1 and $a at 0
        }
        """
    )
    assert result.compiled.rules[0].condition == "$a and #b > 1 and $a at 0"


def test_anonymous_strings_collapse_to_them(roundtrip):
    """
    Anonymous strings can only be referenced via "them". Enumerating them as
    "2 of ($, $, $)" compiles but does not mean the same thing.
    """
    result, _ = roundtrip(
        """
        rule A {
            strings:
                $ = "one"
                $ = "two"
                $ = "three"
            condition:
                2 of them
        }
        """
    )
    assert result.compiled.rules[0].condition == "2 of them"


def test_double_literals_are_reinterpreted(roundtrip):
    """A double and an integer are the same eight bytes on the stack."""
    result, _ = roundtrip(
        'import "math" rule F { condition: math.entropy(0, filesize) > 7.0 }'
    )
    assert "7.0" in result.compiled.rules[0].condition


def test_condition_string_literals_are_sized_strings(roundtrip):
    """Reading a SIZED_STRING as a C string yields its length byte."""
    result, _ = roundtrip(
        'import "pe" rule S { condition: pe.pdb_path contains "release" }'
    )
    assert '"release"' in result.compiled.rules[0].condition


def test_matches_operand_skips_the_re_header(roundtrip):
    """struct RE puts a uint32 flags word before the bytecode."""
    result, _ = roundtrip(
        'import "pe" rule M { condition: pe.pdb_path matches /[a-z]+\\.pdb/i }'
    )
    cond = result.compiled.rules[0].condition
    assert "matches /" in cond and "unrecovered" not in cond


def test_offset_and_length_pop_two_values(roundtrip):
    """@x is sugar for @x[1]; both operands are always emitted."""
    result, _ = roundtrip(
        'rule O { strings: $a = "aaa" condition: for any i in (1..#a) : ( @a[i] > 0 ) }'
    )
    assert "@a[i]" in result.compiled.rules[0].condition


def test_imports_are_recovered(roundtrip):
    result, _ = roundtrip(
        'import "pe" import "math" rule I { condition: pe.number_of_sections > 1 }'
    )
    assert set(result.compiled.imports) == {"pe", "math"}


# ------------------------------------------------------------------- output


def test_output_never_has_an_empty_condition_block(roundtrip):
    """An empty condition block will not parse, so there must always be one."""
    result, _ = roundtrip('rule X { strings: $a = "aaa" condition: $a }')
    assert "condition:" in result.source
    body = result.source.split("condition:")[1].strip()
    assert body and not body.startswith("}")


def test_lossy_modifiers_are_reported_not_invented(roundtrip):
    """
    xor ranges are consumed during atom generation. Emitting xor(0x01-0xff)
    would be fabrication, so the bare modifier plus a warning is correct.
    """
    result, _ = roundtrip(
        'rule X { strings: $a = "s" xor(0x01-0xff) condition: $a }'
    )
    assert any("xor key range" in w for w in result.warnings)
    assert "xor(" not in result.source


def test_base64_modifier_conflicts_are_filtered(roundtrip):
    """YARA rejects base64 combined with wide/nocase/fullword/xor."""
    _, recompiled = roundtrip(
        'rule B { strings: $a = "hello" base64 condition: $a }'
    )
    assert recompiled is not None


def test_hex_strings_carry_no_text_modifiers(roundtrip):
    """A hex string accepts only "private"."""
    result, _ = roundtrip("rule H { strings: $a = { 90 90 90 } condition: $a }")
    line = [l for l in result.source.splitlines() if "$a =" in l][0]
    for bad in ("wide", "ascii", "nocase", "fullword"):
        assert bad not in line


# ------------------------------------------------------------- regex engine


def test_re_class_is_34_bytes():
    """
    RE_CLASS is a negated flag plus a 32-byte bitmap, so the CLASS
    instruction is 34 bytes. Getting this wrong desynchronises everything
    downstream of the first character class.
    """
    code = bytes([rp.ReOp.CLASS]) + b"\x00" + b"\xff" * 32 + bytes([rp.ReOp.MATCH])
    instr = rp.decode_instr(code, 0)
    assert instr.size == 34
    assert instr.end == 34


def test_re_programs_are_segmented_by_instruction_walk():
    """
    0xAD (MATCH) occurs constantly inside CLASS bitmaps, so segmenting on the
    raw byte would split programs in the wrong places.
    """
    bitmap = bytearray(32)
    bitmap[rp.ReOp.MATCH // 8] |= 1 << (rp.ReOp.MATCH % 8)
    code = (
        bytes([rp.ReOp.CLASS]) + b"\x00" + bytes(bitmap) + bytes([rp.ReOp.MATCH])
    )
    assert rp.segment_programs(code) == [(0, 35)]


def test_unknown_re_opcode_raises():
    with pytest.raises(rp.ReDecodeError):
        rp.decode_instr(b"\x01", 0)
