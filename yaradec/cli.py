"""Command-line interface for yaradec."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from . import code as C
from . import repattern as rp
from .arena import Arena, ArenaError, UnsupportedVersionError
from .constants import MetaType, Section, StringFlags
from .decompile import decompile
from .emit import EmitOptions


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="yaradec",
        description=(
            "Decompile compiled YARA rules (.yarc) back to source. "
            "Supports the arena format used by YARA 4.3.0 - 4.5.8."
        ),
    )
    p.add_argument("path", type=Path, help="compiled rules file")
    p.add_argument(
        "-f",
        "--format",
        choices=("yara", "json", "disasm", "info"),
        default="yara",
        help="output format (default: yara)",
    )
    p.add_argument(
        "-o", "--output", type=Path, help="write to a file instead of stdout"
    )
    p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress warnings about lossy or unrecovered constructs",
    )
    p.add_argument(
        "--no-listing",
        action="store_true",
        help="omit the VM listing for conditions that could not be recovered",
    )
    p.add_argument(
        "--lenient",
        action="store_true",
        help="continue past a malformed relocation list instead of failing",
    )
    p.add_argument("--version", action="version", version=f"yaradec {__version__}")
    return p


def _cmd_info(path: Path) -> str:
    arena = Arena.from_file(path)
    lines = [
        f"file:            {path}",
        f"arena version:   {arena.version}",
        f"buffers:         {len(arena.buffers)}",
        f"relocations:     {len(arena.relocations)}",
        "",
        f"{'id':>3}  {'section':<28} {'bytes':>9}",
    ]
    for i, buf in enumerate(arena.buffers):
        try:
            name = Section(i).name
        except ValueError:
            name = "?"
        lines.append(f"{i:>3}  {name:<28} {len(buf):>9}")
    return "\n".join(lines)


def _cmd_disasm(path: Path) -> str:
    arena = Arena.from_file(path)
    out: list[str] = []

    code = arena.buffer(Section.CODE_SECTION)
    out.append(f"; ---- condition VM code ({len(code)} bytes) ----")

    def resolve(ins: C.Instr):
        if ins.operand is None:
            return None
        ref = C.unpack_ref(ins.operand)
        if ref.buffer_id == Section.SZ_POOL:
            try:
                text = arena.cstring(ref)
            except ArenaError:
                return None
            if text is not None:
                return f'"{text}"'
        if ref.buffer_id == Section.STRINGS_TABLE:
            return f"string[{ref.offset // 56}]"
        return None

    out.extend(C.format_listing(C.disassemble(code), resolve))

    re_code = arena.buffer(Section.RE_CODE_SECTION)
    if re_code:
        out.append("")
        out.append(f"; ---- regexp programs ({len(re_code)} bytes) ----")
        for start, end in rp.segment_programs(re_code):
            out.append(f"; program @ {start}..{end}")
            try:
                out.extend(rp.format_disassembly(rp.disassemble_program(re_code, start)))
            except rp.ReDecodeError as exc:
                out.append(f"  ; {exc}")
    return "\n".join(out)


def _to_json(result) -> str:
    payload = {
        "arena_version": result.compiled.arena.version,
        "imports": result.compiled.imports,
        "namespaces": result.compiled.namespaces,
        "warnings": result.warnings,
        "rules": [],
    }
    for r in result.compiled.rules:
        payload["rules"].append(
            {
                "identifier": r.identifier,
                "namespace": r.namespace,
                "private": r.is_private,
                "global": r.is_global,
                "tags": r.tags,
                "meta": [
                    {"identifier": m.identifier, "type": MetaType(m.type).name.lower(),
                     "value": m.value}
                    for m in r.metas
                ],
                "strings": [
                    {
                        "identifier": s.identifier,
                        "recovered": s.rendered
                        if s.rendered
                        else (
                            s.data.decode("utf-8", "replace")
                            if s.flags & StringFlags.LITERAL
                            else None
                        ),
                        "exact": bool(s.flags & StringFlags.LITERAL) or s.rendered is not None,
                        "flags": [f.name for f in StringFlags if s.flags & f],
                    }
                    for s in r.strings
                ],
                "condition": r.condition,
                "condition_recovered": r.condition is not None,
            }
        )
    return json.dumps(payload, indent=2)


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        if args.format == "info":
            output = _cmd_info(args.path)
            warnings: list[str] = []
        elif args.format == "disasm":
            output = _cmd_disasm(args.path)
            warnings = []
        else:
            result = decompile(
                args.path,
                opts=EmitOptions(include_listing=not args.no_listing),
                strict=not args.lenient,
            )
            output = _to_json(result) if args.format == "json" else result.source
            warnings = result.warnings
    except UnsupportedVersionError as exc:
        print(f"yaradec: {exc}", file=sys.stderr)
        return 3
    except ArenaError as exc:
        print(f"yaradec: {args.path}: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError:
        print(f"yaradec: {args.path}: no such file", file=sys.stderr)
        return 2

    try:
        if args.output:
            args.output.write_text(output)
        else:
            print(output)

        if warnings and not args.quiet and args.format != "json":
            print("", file=sys.stderr)
            for w in warnings:
                print(f"warning: {w}", file=sys.stderr)
    except BrokenPipeError:
        # Downstream closed the pipe (e.g. "yaradec x.yarc | head"). Detach
        # stdout so the interpreter does not report it again at shutdown.
        try:
            sys.stdout.close()
        except BrokenPipeError:
            pass
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
