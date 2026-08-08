"""
Recovers the string -> regexp-program mapping from the Aho-Corasick tables.

Why this is needed: in a *saved* arena, ``YR_STRING.string`` is NULL for every
non-literal pattern. The compiled regexp program is referenced only from
``YR_AC_MATCH.forward_code`` / ``.backward_code`` entries in the
YR_AC_STATE_MATCHES_POOL buffer. Without walking that pool there is no link
from a string to its bytecode, which is why hex-with-wildcards and regexps
could not be recovered before.

YR_AC_MATCH (libyara/include/yara/types.h @ v4.5.8), 40 bytes, pack(8):

    string:ref  forward_code:ref  backward_code:ref  next:ref
    backtrack:uint16 (padded to 8 by YR_ALIGN)

A pattern generates one YR_AC_MATCH per atom, so a single string usually maps
to several forward_code offsets pointing *into* the same program (each atom
resumes forward matching at a different instruction). We therefore resolve a
program by locating the segment that *contains* an offset, never by assuming
an offset is a program start.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .arena import Arena, Ref
from .constants import SIZEOF_STRING, Section

SIZEOF_AC_MATCH = 40
_AC_MATCH_FMT = "<IIIIIIIIQ"


@dataclass
class StringCode:
    """RE code offsets associated with one string."""

    forward: set[int] = field(default_factory=set)
    backward: set[int] = field(default_factory=set)


def collect_string_code(arena: Arena) -> dict[int, StringCode]:
    """Map string table index -> the RE code offsets that reference it."""
    pool = arena.buffer(Section.AC_STATE_MATCHES_POOL)
    out: dict[int, StringCode] = {}

    for off in range(0, len(pool) - SIZEOF_AC_MATCH + 1, SIZEOF_AC_MATCH):
        vals = struct.unpack_from(_AC_MATCH_FMT, pool, off)
        s_ref = Ref(vals[0], vals[1])
        f_ref = Ref(vals[2], vals[3])
        b_ref = Ref(vals[4], vals[5])

        if s_ref.is_null or s_ref.buffer_id != Section.STRINGS_TABLE:
            continue
        if s_ref.offset % SIZEOF_STRING:
            continue  # not a real string-table element

        idx = s_ref.offset // SIZEOF_STRING
        entry = out.setdefault(idx, StringCode())
        if not f_ref.is_null and f_ref.buffer_id == Section.RE_CODE_SECTION:
            entry.forward.add(f_ref.offset)
        if not b_ref.is_null and b_ref.buffer_id == Section.RE_CODE_SECTION:
            entry.backward.add(b_ref.offset)

    return out
