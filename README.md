# yaradec

Decompile compiled YARA rules (`.yarc`) back into readable YARA source.

Given a compiled rule file — the kind shipped inside security products, EDR
agents, and scanning appliances — `yaradec` reconstructs the rule names,
metadata, tags, strings (including regular expressions and wildcard hex
patterns), and the conditions.

```console
$ yaradec rules.yarc
import "pe"

rule Demo_Rule : trojan banker
{
    meta:
        author = "rdx0120"
        description = "demo rule for decompiler test"
        version = 3
        is_test = true

    strings:
        $a = "malicious_string" nocase wide ascii
        $b = { 4D 5A 90 00 03 ?? 00 00 }
        $c = /evil[0-9]{2,4}regex/i
        $d = "xored" xor
        $e = "b64me" base64
        $f = "fullword_hit" fullword

    condition:
        Helper_Priv and 2 of ($a, $b, $c) and #d > 1 and $e at 0
        and pe.number_of_sections > 2 and $f
}
```

## Why this exists

Detection logic ships compiled. When you are triaging a product's coverage, or
you have inherited a `.yarc` whose source was lost, or you want to know why a
scanner fired on a file, you need to read the rules — not the bytecode.

This is a rewrite of [jbgalet/yaradec](https://github.com/jbgalet/yaradec),
which targets YARA 3.x and cannot read anything a current YARA produces. It
also closes both limitations the original documented: regular expressions and
wildcard hex strings are now extracted, and conditions are reconstructed
instead of being dumped as a raw opcode listing.

## Scope

Supports the arena format **version 21**, emitted by **YARA 4.3.0 through
4.5.8** (4.5.8 is current as of this writing).

**YARA-X is not supported and is out of scope.** VirusTotal's Rust successor
compiles rule conditions to WebAssembly; recovering source from it is a
different problem needing a different tool, not a version bump here.

Files from YARA 3.x and early 4.x are detected and rejected with a message
naming the version, rather than failing obscurely.

## Install

```console
pip install -e .
```

The library itself has no dependencies. The test suite and verification
tools need `yara-python`:

```console
pip install -e ".[dev]"
```

## Usage

```console
yaradec rules.yarc                  # reconstructed YARA source
yaradec rules.yarc -f json          # structured output, per-string exactness
yaradec rules.yarc -f disasm        # VM and regexp bytecode listing
yaradec rules.yarc -f info          # arena layout and section sizes
yaradec rules.yarc -o out.yar -q    # write to a file, suppress warnings
```

Warnings go to stderr, so `yaradec x.yarc > out.yar` gives clean source while
you still see what was lossy.

As a library:

```python
from yaradec.decompile import decompile

result = decompile("rules.yarc")
print(result.source)
print(f"{result.conditions_recovered}/{len(result.compiled.rules)} conditions")
for warning in result.warnings:
    print(warning)
```

## Verification

Decompilers fail quietly. Output that looks plausible and means something
subtly different is worse than output that visibly breaks, and reading the
result will not catch it. So correctness here is measured by behaviour, not
by inspection.

`tools/roundtrip.py` compiles a rule file, decompiles it, recompiles the
result, and scans a corpus of buffers with **both** rule sets, asserting that
the same rules fire on the same inputs. Recompiling only proves the output
parses; the scan comparison proves it means the same thing.

Against the full [Yara-Rules/rules](https://github.com/Yara-Rules/rules)
corpus (465 compilable files):

| | |
|---|---|
| Rules parsed | 23,078 |
| Strings parsed | 44,278 |
| Crashes | **0** |
| Conditions reconstructed | **23,078 / 23,078 (100%)** |
| Files that recompile | **465 / 465** |
| Semantic mismatches | **0** across 6,816 scan buffers |

Reproduce with `python tools/roundtrip.py <files>`.

`tools/check_constants.py` re-derives the opcode operand table from a
checked-out YARA tree and diffs it against `yaradec/constants.py`. Operand
widths are the most fragile thing in the project — one wrong width
desynchronises every instruction after it and yields confident garbage — so
this runs in CI rather than being trusted to stay correct.

```console
git clone --depth 1 --branch v4.5.8 https://github.com/VirusTotal/yara.git
python tools/check_constants.py ./yara
```

## How it works

```
arena.py       container: header, buffer table, relocation list
parser.py      rule / string / meta / namespace tables
acmatch.py     Aho-Corasick match lists -> string-to-regexp-program mapping
repattern.py   regexp bytecode -> hex strings and regular expressions
b64.py         base64 permutations -> plaintext (validated by re-expansion)
code.py        VM bytecode -> conditions
emit.py        rules -> YARA source
decompile.py   pipeline
cli.py         command line
```

Three things in the format are worth knowing, because each one silently
produces wrong output if you assume otherwise:

**`YR_STRING.string` is NULL for every non-literal pattern.** In a saved
arena the compiled regexp program is reachable *only* through
`YR_AC_MATCH.forward_code` in the Aho-Corasick pool. Without walking that
pool there is no link at all from a string to its bytecode — which is why
regexps and wildcard hex strings could not be recovered before.

**Regexp programs must be segmented by walking instructions.** `0xAD` is the
`MATCH` opcode, but it also occurs constantly inside 32-byte character-class
bitmaps and as a literal operand. Scanning for the raw byte splits programs
in the wrong places.

**Jump operands are int32 offsets relative to the opcode byte**, not the
8-byte absolute addresses YARA 3.x used. Conditions are then recovered by
linear symbolic execution: the non-popping conditional jumps exist purely for
short-circuiting and leave the stack untouched, so they can be ignored
entirely and no control-flow analysis is needed.

## Known limitations

These are properties of the compiled format, not gaps in the implementation.
Where information is provably absent, `yaradec` says so instead of inventing
something plausible.

- **`xor` key ranges are not recoverable.** `xor(0x01-0xff)` is expanded into
  atoms at compile time and never stored in `YR_STRING`. The bare `xor`
  modifier is emitted with a warning. Any tool that reports the original
  range is fabricating it.
- **Custom `base64` alphabets are not recoverable** for the same reason. The
  *plaintext* is recovered, and is validated by re-expanding it and comparing
  against the compiled permutations — so it is proven, never guessed.
- **`for` loop variable names are invented** (`i`, `item`). Only memory slots
  survive compilation. This is the one place output is deliberately not
  faithful to the original text; it does not change semantics.
- **`any of` is emitted as `1 of`.** They compile to identical bytecode and
  are genuinely indistinguishable.
- **Comments, whitespace, and rule ordering within a namespace are lost.**
  They are not compiled.
- Some patterns are recovered in a semantically identical but denormalised
  form. A condition set covering every string in a rule is emitted as `them`,
  which is both more readable and, for rules using anonymous `$` strings, the
  only correct rendering.

If a condition ever fails to reconstruct, the rule is emitted with an
explicit `false // FIXME` placeholder and a warning — never a silently empty
or wrong condition.

## Development

```console
pip install -e ".[dev]"
pytest -q
python tools/roundtrip.py tests/data/*.yar
python tools/check_constants.py /path/to/yara
```

## License

Apache 2.0. The original `yaradec` by jbgalet was the starting point for this
work; the format handling has been rewritten for YARA 4.x.
