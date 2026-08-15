"""
Reader for the YARA 4.x serialized arena.

Layout produced by ``yr_arena_save_stream`` (libyara/arena.c):

    struct YR_ARENA_FILE_HEADER {   // pack(1)
        uint8_t  magic[4];          // "YARA"
        uint8_t  version;           // YR_ARENA_FILE_VERSION == 21
        uint8_t  num_buffers;
    };
    struct YR_ARENA_FILE_BUFFER {   // pack(1), one per buffer
        uint64_t offset;            // absolute file offset
        uint32_t size;
    };
    <buffer data, concatenated in buffer order>
    <relocation list: YR_ARENA_REF entries, terminated by 0xFFFFFFFF>

Relocation entries name a (buffer_id, offset) location whose 8 bytes hold a
``YR_ARENA_REF`` -- i.e. a pointer that was rewritten to {buffer_id, offset}
at save time.

This is a completely different container from the pre-4.3 flat arena, where a
single blob was patched with 0xFFFABADA sentinels. Nothing about the old
relocation walk carries over.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .constants import (
    ARENA_MAGIC,
    LEGACY_ARENA_VERSIONS,
    NULL_REF,
    SUPPORTED_ARENA_VERSIONS,
)


class ArenaError(Exception):
    """Raised when the input is not a parseable compiled-rules arena."""


class UnsupportedVersionError(ArenaError):
    def __init__(self, version: int) -> None:
        self.version = version
        hint = LEGACY_ARENA_VERSIONS.get(version)
        if hint:
            msg = (
                f"arena file version {version} ({hint}) is not supported. "
                f"This tool reads version(s) "
                f"{sorted(SUPPORTED_ARENA_VERSIONS)}, produced by YARA 4.3.0 "
                f"and later. Recompile the rules with a current YARA, or use "
                f"the original yaradec for 3.x files."
            )
        else:
            msg = (
                f"unknown arena file version {version}; this tool reads "
                f"version(s) {sorted(SUPPORTED_ARENA_VERSIONS)}"
            )
        super().__init__(msg)


@dataclass(frozen=True)
class Ref:
    """A YR_ARENA_REF: a buffer id plus an offset within that buffer."""

    buffer_id: int
    offset: int

    @property
    def is_null(self) -> bool:
        return (self.buffer_id, self.offset) == NULL_REF

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        if self.is_null:
            return "Ref(NULL)"
        return f"Ref(buf={self.buffer_id}, off=0x{self.offset:x})"


NULL = Ref(*NULL_REF)


@dataclass
class Arena:
    version: int
    buffers: list[bytes]
    relocations: set[tuple[int, int]] = field(default_factory=set)

    # -- construction ------------------------------------------------------

    @classmethod
    def parse(cls, data: bytes, *, strict: bool = True) -> "Arena":
        if len(data) < 6:
            raise ArenaError("file is too small to contain an arena header")

        magic, version, num_buffers = struct.unpack_from("<4sBB", data, 0)
        if magic != ARENA_MAGIC:
            raise ArenaError(
                f"bad magic {magic!r}; expected {ARENA_MAGIC!r}. "
                "This does not look like a compiled YARA rules file."
            )
        if version not in SUPPORTED_ARENA_VERSIONS:
            raise UnsupportedVersionError(version)

        off = 6
        table: list[tuple[int, int]] = []
        for i in range(num_buffers):
            try:
                b_off, b_size = struct.unpack_from("<QI", data, off)
            except struct.error as exc:
                raise ArenaError(f"truncated buffer table at entry {i}") from exc
            table.append((b_off, b_size))
            off += 12

        buffers: list[bytes] = []
        for i, (b_off, b_size) in enumerate(table):
            end = b_off + b_size
            if b_size and end > len(data):
                raise ArenaError(
                    f"buffer {i} runs past end of file "
                    f"(offset={b_off}, size={b_size}, file={len(data)})"
                )
            buffers.append(data[b_off:end])

        # The relocation list starts right after the last buffer.
        reloc_start = max((o + s) for o, s in table) if table else off
        relocations = cls._parse_relocations(data, reloc_start, strict=strict)

        return cls(version=version, buffers=buffers, relocations=relocations)

    @staticmethod
    def _parse_relocations(
        data: bytes, start: int, *, strict: bool
    ) -> set[tuple[int, int]]:
        relocations: set[tuple[int, int]] = set()
        pos = start
        while pos + 4 <= len(data):
            (buffer_id,) = struct.unpack_from("<I", data, pos)
            if buffer_id == 0xFFFFFFFF:
                break
            if pos + 8 > len(data):
                if strict:
                    raise ArenaError("truncated relocation list")
                break
            (offset,) = struct.unpack_from("<I", data, pos + 4)
            relocations.add((buffer_id, offset))
            pos += 8
        return relocations

    @classmethod
    def from_file(cls, path, *, strict: bool = True) -> "Arena":
        with open(path, "rb") as fh:
            return cls.parse(fh.read(), strict=strict)

    # -- accessors ---------------------------------------------------------

    def buffer(self, buffer_id: int) -> bytes:
        try:
            return self.buffers[buffer_id]
        except IndexError:
            raise ArenaError(
                f"buffer {buffer_id} does not exist "
                f"(arena has {len(self.buffers)})"
            ) from None

    def read(self, ref: Ref, size: int) -> bytes:
        """Read ``size`` bytes at ``ref``."""
        if ref.is_null:
            raise ArenaError("attempted to dereference a NULL arena reference")
        buf = self.buffer(ref.buffer_id)
        if ref.offset + size > len(buf):
            raise ArenaError(
                f"read of {size} bytes at {ref!r} runs past end of buffer "
                f"(buffer size {len(buf)})"
            )
        return buf[ref.offset : ref.offset + size]

    def unpack(self, ref: Ref, fmt: str) -> tuple:
        return struct.unpack(fmt, self.read(ref, struct.calcsize(fmt)))

    def ref_at(self, ref: Ref) -> Ref:
        """Read the YR_ARENA_REF stored at ``ref`` (a relocated pointer slot)."""
        buffer_id, offset = self.unpack(ref, "<II")
        return Ref(buffer_id, offset)

    def cstring(self, ref: Ref, encoding: str = "utf-8") -> Optional[str]:
        """Read a NUL-terminated string. Returns None for a NULL reference."""
        if ref.is_null:
            return None
        buf = self.buffer(ref.buffer_id)
        end = buf.find(b"\x00", ref.offset)
        if end == -1:
            raise ArenaError(f"unterminated string at {ref!r}")
        return buf[ref.offset : end].decode(encoding, errors="replace")

    def cstring_list(self, ref: Ref) -> list[str]:
        """
        Read a run of NUL-terminated strings terminated by an empty string.
        This is how rule tags are stored.
        """
        if ref.is_null:
            return []
        buf = self.buffer(ref.buffer_id)
        out: list[str] = []
        pos = ref.offset
        while pos < len(buf) and buf[pos] != 0:
            end = buf.find(b"\x00", pos)
            if end == -1:
                raise ArenaError(f"unterminated tag list at {ref!r}")
            out.append(buf[pos:end].decode("utf-8", errors="replace"))
            pos = end + 1
        return out

    def sized_string(self, ref: Ref) -> Optional[tuple[bytes, int]]:
        """
        Read a SIZED_STRING (libyara/include/yara/sizedstr.h), returning
        (data, flags).

        String literals appearing in *conditions* are SIZED_STRINGs --
        length-prefixed and NUL-safe -- not C strings. Reading one as a C
        string yields the first byte of the length field, which for a
        7-character literal renders as "\x07". Identifiers referenced by
        OBJ_FIELD / OBJ_LOAD / IMPORT operands really are C strings.
        """
        if ref.is_null:
            return None
        try:
            length, flags = self.unpack(ref, "<II")
        except ArenaError:
            return None
        if length > 1 << 24:
            return None
        try:
            data = self.read(Ref(ref.buffer_id, ref.offset + 8), length)
        except ArenaError:
            return None
        return data, flags

    def is_relocated(self, ref: Ref) -> bool:
        """True if the 8 bytes at ``ref`` were a relocatable pointer."""
        return (ref.buffer_id, ref.offset) in self.relocations
