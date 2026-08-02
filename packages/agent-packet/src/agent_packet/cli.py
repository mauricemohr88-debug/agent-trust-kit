"""CLI for agent-packet."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath

from . import __version__
from .builder import build_packet, inspect_packet, materialize_packet


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-packet",
        description=("Build and defensively materialize filtered task packets for AI agents."),
    )
    parser.add_argument("--version", action="version", version=f"agent-packet {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="Build a filtered packet from a workspace")
    b.add_argument("--task", required=True, help="Task instructions for receiving agent")
    b.add_argument("--root", type=Path, default=Path("."), help="Source workspace root")
    b.add_argument(
        "--include",
        action="append",
        default=[],
        help="Relative path to include (repeatable; required unless --include-all is used)",
    )
    b.add_argument(
        "--include-all",
        action="store_true",
        help="Explicitly select the entire root before deny and content filters",
    )
    b.add_argument("--out", type=Path, required=True, help="Output directory")
    b.add_argument("--deny", action="append", default=[], help="Extra deny glob")
    b.add_argument("--meta", type=Path, default=None, help="Optional JSON meta file")
    b.add_argument(
        "--allow-binary",
        action="store_true",
        help="Include reviewed binary files; their contents are not secret-scanned.",
    )
    b.add_argument(
        "--redact-secrets",
        action="store_true",
        help="Redact detected secret-like values. By default affected files are excluded.",
    )
    b.add_argument("--json", action="store_true")

    m = sub.add_parser("materialize", help="Extract + verify a packet")
    m.add_argument("packet", type=Path, help="Immutable packet.tar.gz archive")
    m.add_argument("--dest", type=Path, required=True)
    digest = m.add_mutually_exclusive_group(required=True)
    digest.add_argument(
        "--expect-sha256",
        help="SHA-256 obtained through an independent authenticated channel",
    )
    digest.add_argument(
        "--accept-untrusted-archive",
        action="store_true",
        help="Skip expected-digest authentication; use only in an isolated inspection workflow",
    )
    m.add_argument("--json", action="store_true")

    i = sub.add_parser("inspect", help="Show packet manifest summary")
    i.add_argument("packet", type=Path)
    i.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    if args.cmd == "build":
        meta = {}
        if args.meta:
            try:
                meta = json.loads(Path(args.meta).read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError) as exc:
                raise SystemExit(f"could not read packet metadata: {exc}") from exc
            if not isinstance(meta, dict):
                parser.error("--meta must contain a JSON object")
        if args.include_all and args.include:
            parser.error("--include-all cannot be combined with --include")
        if any(not PurePosixPath(raw.replace("\\", "/")).parts for raw in args.include):
            parser.error("selecting the entire root requires --include-all, not --include .")
        if not args.include_all and not args.include:
            parser.error("at least one --include is required (or explicitly use --include-all)")
        include = ["."] if args.include_all else args.include
        try:
            man = build_packet(
                task=args.task,
                source_root=args.root,
                include=include,
                out_dir=args.out,
                include_all=args.include_all,
                extra_deny_globs=args.deny,
                meta=meta,
                allow_binary=args.allow_binary,
                redact_secrets=args.redact_secrets,
            )
        except (OSError, ValueError) as exc:
            raise SystemExit(f"packet build failed: {exc}") from exc
        if args.json:
            print(json.dumps(man.to_dict(), indent=2))
        else:
            print(f"packet built: {Path(args.out) / 'packet.tar.gz'}")
            print(
                f"files={len(man.files)} denied={sum(man.denied.values())} "
                f"redactions={sum(man.redactions.values())}"
            )
            print(f"sha256={man.packet_sha256}")
            print(f"hash sidecar={Path(args.out) / 'PACKET_SHA256.txt'}")
        return 0

    if args.cmd == "materialize":
        try:
            report = materialize_packet(
                args.packet,
                args.dest,
                expect_sha256=args.expect_sha256,
                accept_untrusted_archive=args.accept_untrusted_archive,
            )
        except (OSError, ValueError) as exc:
            raise SystemExit(f"packet materialization failed: {exc}") from exc
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"materialized ok → {report['dest']}")
            print(
                f"files={report['files']} denied={report['denied']} "
                f"redactions={report['redactions']}"
            )
        return 0

    if args.cmd == "inspect":
        try:
            man, archive_hash = inspect_packet(args.packet)
        except (OSError, ValueError) as exc:
            raise SystemExit(f"packet inspection failed: {exc}") from exc
        if args.json:
            print(json.dumps(man, indent=2))
        else:
            print(
                f"schema={man.get('schema')} files={len(man.get('files', []))} "
                f"denied={sum(man.get('denied', {}).values())} "
                f"redactions={sum(man.get('redactions', {}).values())}"
            )
            print(f"task: {json.dumps(str(man.get('task', ''))[:200], ensure_ascii=True)}")
            print(f"packet_sha256={archive_hash or 'external hash not available'}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
