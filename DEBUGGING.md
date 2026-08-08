# Debugging notes

Notes I kept while building this, mostly so I wouldn't make the same mistake
twice. Every one of these cost me real time, and most of them were cases where
the tool produced output that *looked* fine and was wrong. That's the part
worth writing down: a decompiler that crashes tells you it's broken, but one
that emits plausible-and-wrong source will happily lie to you until something
downstream refuses it.

The recurring lesson: don't trust anything until it recompiles and scans
identically to the original. Reading the output is not verification.

---

## 1. The version byte, and realising this was a rewrite

I started out thinking I could port the old tool's structs forward. First
thing I did was dump the header of a freshly compiled `.yarc`:

```
magic: b'YARA' version: 21 num_buffers: 12
```

The original yaradec reads the header as `<4sLB` — magic, a 4-byte size, then
a version byte. On a v21 file that "version" byte is actually reading into the
buffer count, so it never even gets to the right number. The real header is
`<4sBB`: magic, version, num_buffers. No size field at all.

That was the moment I stopped thinking "upgrade" and accepted this was a
rewrite. The 3.x format is one flat blob patched with `0xFFFABADA` sentinels;
4.x is twelve named buffers with a buffer table and a relocation list. Nothing
carried over. I spent an hour trying to salvage the old relocation walk before
admitting it was dead weight.

---

## 2. Jump offsets: I assumed 8 bytes, they're int32 relative

When I first disassembled a condition, the instruction stream desynced a few
opcodes in and everything after it was garbage. I'd assumed jump targets were
8-byte absolute addresses (they are in 3.x). Went to `exec.c` and read
`jmp_if`:

```c
off = yr_unaligned_u32(ip);   // int32, not 64-bit
off -= 1;                     // relative to the opcode, not absolute
```

So a jump is a 4-byte signed offset measured from the opcode byte, not an
address. Once I fixed the operand width the whole stream lined up. This is the
kind of thing you cannot guess — I only got it right by reading the actual VM
loop rather than trusting the shape of the old code.

Takeaway I kept coming back to: read the source of truth, don't pattern-match
the previous tool. I got burned by this twice more (see §3 and §6).

---

## 3. Regexes are NULL — the Aho-Corasick detour

This one took the longest to figure out. I had string flags parsing correctly
and I could see which strings were regexes, but `YR_STRING.string` was NULL for
every single one of them:

```
2 flags=0x2004b len 0 strref Ref(NULL)   <- the /evil.../ regex
3 flags=0x1002d len 0 strref Ref(NULL)   <- the { .. ?? .. } hex string
```

Zero length, null pointer. I stared at this for a while assuming I'd parsed the
struct wrong and recounted the field offsets three times. The struct was fine.
The pointer is genuinely null in a saved file.

The compiled regexp program lives in a separate buffer (the RE code section),
and the only thing that points at it is the Aho-Corasick match table — the
automaton the scanner uses to find atoms. So to get from a string to its
bytecode you have to walk `YR_AC_STATE_MATCHES_POOL`, read the `YR_AC_MATCH`
entries, and follow `forward_code` back into the RE section. There is no direct
link.

When I finally dumped the pool it clicked:

```
string 0 entries 1
string 3 entries 16   <- one string, sixteen AC-match entries
```

One pattern produces many match entries, each resuming at a different point in
the *same* program. So I can't treat a `forward_code` offset as a program
start — I have to find the program that *contains* it. That distinction is why
`program_containing()` exists instead of just indexing by offset.

This is the whole reason regexes were listed as unrecoverable in the original
tool. It's not that the code is hard to disassemble; it's that finding it at
all requires understanding a data structure that has nothing obviously to do
with strings.

---

## 4. Segmentation stalled after two programs

Once I could reach the RE code, segmenting it into individual programs looked
easy — each program ends in `RE_OPCODE_MATCH` (0xAD), so split on that. My
first version only found two programs in a 420-byte section and then stopped.

I dumped the raw bytes and immediately saw why:

```
a5 00 00 00 00 00 00 00 ff 03 00 00 ...
```

That `a5` is `RE_OPCODE_CLASS`, followed by a 32-byte character-class bitmap.
And 0xAD absolutely occurs inside those bitmaps and inside literal operands —
it's a perfectly normal byte. Splitting on the raw byte cuts programs in half
at random. You have to actually decode instructions and only treat a MATCH as a
terminator when it lands on an instruction boundary.

Then even the instruction walk stalled, which led to the next one.

---

## 5. RE_CLASS is 33 bytes, not 32 — off by the negation flag

My CLASS instruction was 33 bytes: 1 opcode + 32 bitmap. The walk kept
desyncing right after the first character class. I'd read the bitmap size
correctly but assumed the instruction was `opcode + bitmap`. Went and read the
struct:

```c
struct RE_CLASS {
  uint8_t negated;      // <- I completely missed this
  uint8_t bitmap[32];
};
```

There's a `negated` flag *before* the bitmap. So CLASS is 34 bytes, not 33, and
— this is the part I nearly shipped wrong — negation is an explicit stored
flag, not something you infer. My first pass was going to guess negation from
whether the bitmap had more than 128 bits set, which would silently invert
classes like `[a-z]` written as their complement. The flag is authoritative;
guessing would have been wrong on real rules.

One wrong byte in an instruction width and everything after it in that program
is nonsense. This is why I ended up writing `check_constants.py` — I did not
trust myself to keep these numbers right by hand.

---

## 6. "release" came out as "\x07"

Ran the tool on a rule with `pe.pdb_path contains "release"` and got:

```
pe.pdb_path contains "\x07"
```

Seven-character string, and I'm printing `\x07`. That's the length byte. String
literals *inside conditions* aren't C strings — they're `SIZED_STRING`, which
is `length:u32, flags:u32, chars[]`. I was reading it as a NUL-terminated C
string, so I got the first byte of the length field (7) and then a NUL.

The confusing part is that identifiers — field names, module names, imports —
really *are* C strings in the same pool. So `pe` and `pdb_path` read fine and
only the user-supplied literal was mangled, which made it look like a
string-specific bug rather than a "wrong type" bug. Took me a minute to see
that the broken ones were all operands to `contains`/`matches` and the fine
ones were all `OBJ_FIELD` operands.

---

## 7. `matches` regex was garbage — the RE struct header

Right after fixing §6, `matches` still produced `/<unrecovered>/`. The operand
pointed into the RE code section, so I tried to disassemble from it directly
and hit an unknown opcode at offset 0:

```
20 00 00 00 a5 00 00 00 ...
unknown RE opcode 0x20 at offset 0
```

`0x20` isn't an opcode. It's the low byte of a `uint32 flags` field, because
the operand points at `struct RE { uint32_t flags; uint8_t code[]; }`, not at
the bytecode. The program starts four bytes in. And those four bytes aren't
noise I can skip — the flags carry `/i` and `/s`, so I need them to reconstruct
the modifiers anyway.

Two consecutive bugs (§6, §7) that both came down to the same root cause:
assuming a pointer targets raw data when it actually targets a struct with a
header. After this I got more careful about checking what a reference actually
points at before dereferencing it.

---

## 8. The bounded-repeat expansion, and inventing a quantifier

Two regex bugs that are mirror images of each other, both found by the stress
test rather than by reading output.

First: `x[0-9]{2,4}y` came back as `x[0-9][0-9]{1,2}[0-9]?y`. Not wrong,
exactly — it matches the same thing — but it's not what anyone wrote. YARA
compiles `e{2,4}` into a mandatory part plus optional parts, so a faithful
disassembly reads back denormalised. I added a merge pass that folds adjacent
identical pieces by summing their bounds, which restores `{2,4}`.

Then the merge pass immediately caused the opposite bug. A rule with `/a....b/`
(four literal dots) started failing to recompile:

```
greedy and ungreedy quantifiers can't be mixed in a regular expression
```

My merge pass had turned `....` into `.{4}` — it saw four identical `.` pieces
and folded them into a quantifier. But four dots in the source are four dots,
not a repeat. And by inventing a greedy `.{4}`, it collided with a genuine
ungreedy `.{3,9}?` elsewhere in the same pattern, which YARA rejects. So the
"improvement" from the first fix created a bug the first fix's own logic
triggered.

The fix was to only merge when a real quantifier is already involved — never
fold plain single-count atoms into each other. Subtle, and I'd never have found
it without a rule that happened to have both literal dots and a real ungreedy
quantifier in the same regex. That came from the real-world corpus, not from
anything I'd have thought to write by hand.

---

## 9. YARA has no `(?:...)`

Ran against ~500 real rule files and a cluster of them failed to recompile on
regexes like:

```
$shellcode5 = /%u[0-9A-Fa-f]{4}(?:%u[0-9A-Fa-f]{4}){3}/
```

`(?:...)` is a non-capturing group. Perfectly valid PCRE — and a syntax error
in YARA's engine, which only has plain `(...)`. I'd been emitting `(?:...)`
around grouped sub-expressions to be safe about precedence, which is exactly
the wrong instinct here. Changed grouping to plain parens.

Same batch turned up a class with a bare `/` in it terminating the pattern
early, because I emit patterns slash-delimited and wasn't escaping `/` inside
character classes. Both of these are things you only learn by feeding the tool
real rules written by real people, who use constructs I wouldn't have put in a
test.

---

## 10. `5 of ($, $, $, ...)` — anonymous strings

The last semantic bug, and the sneakiest, because everything compiled fine. The
round-trip *recompiled* cleanly but a handful of rules matched differently than
the original. That's the scenario I was most worried about the whole time: not
a crash, not a compile error, just a quietly different meaning.

The mismatching rules all used anonymous strings — `$ = "..."` with no name.
YARA lets you declare those but you can only reference them collectively, as
`them`. My `of` handler was faithfully enumerating them:

```
5 of ($, $, $, $, $, $, ...)
```

which parses, but `$` isn't a valid reference, so on recompile it means
something else entirely. The original was just `5 of them`.

The fix: when an `of` set covers every string in the rule, collapse it back to
`them`. That's not only more readable — for anonymous strings it's the *only*
correct rendering. I also made a partial set of anonymous strings a hard error
with a warning, because that genuinely can't be expressed in YARA source and I'd
rather say so than emit something that lies.

This is the bug that convinced me the scan-comparison harness was worth the
effort. Recompiling catches syntax; only comparing actual match results on real
buffers catches "compiles fine, means something different." If I'd trusted
"it recompiles" as my correctness bar, I'd have shipped this.

---

## 11. The for-loop stragglers

After all the above I was at 100% recompile but only ~93% of conditions
reconstructed — the rest fell back to the `false // FIXME` placeholder. Profiled
what was left and it was a single cause: `for` loops over string sets, e.g.
`for any of ($a*) : ( $ in (0..1024) )`.

Two things I'd gotten wrong. First, a string set is pushed as a `PUSH_U`
sentinel followed by its members, so it reduces to *several* stack values, not
one — my single-expression recovery always failed on it. Second, once I handled
that, the output had a stray number on the end:

```
for 1 of ($s1, $s2, ..., $s63, 63) : ( $ in (0..1024) )
```

That `63` is the member count, which `ITER_START_STRING_SET` pushes *after* the
members. I strip it now, but only when it actually equals the member count — if
a future YARA changes that, I want a warning, not a silent off-by-one.

---

## Things I'd tell someone starting this

- The format is not documented; the source is the spec. `exec.c`, `re.c`,
  `arena.c`, and the structs in `types.h` are the only ground truth. Every time
  I trusted memory or the old tool instead, I was wrong.
- Instruction widths are the load-bearing detail. One wrong operand size and
  everything after it decodes to nonsense, often without erroring. That's why
  they get re-derived from YARA's own source in CI rather than trusted.
- "It recompiles" is not "it's correct." Half the real bugs produced source
  that compiled fine and meant something different. The only bar I trust is:
  compile the original, decompile it, recompile that, and scan the same buffers
  with both — do the same rules fire on the same inputs? Everything else is a
  proxy.
- The real-world corpus found bugs my own test rules never would have, because
  real analysts write things I wouldn't think to write. `(?:...)`, bare slashes
  in classes, anonymous-string loops — all of it came from actual rules.
