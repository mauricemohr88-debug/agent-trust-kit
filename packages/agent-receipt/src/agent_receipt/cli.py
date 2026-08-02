"""CLI for agent-receipt."""

from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path

from . import __version__
from .core import (
    VERIFIER_COMMAND_TIMEOUT,
    Claim,
    build_receipt,
    evidence_command,
    evidence_file_hash,
    evidence_path_exists,
    evidence_text_contains,
    load_receipt,
    save_receipt,
    sign_receipt,
    verify_receipt,
)
from .output_manifest import (
    OutputManifestError,
    create_output_manifest,
    load_output_manifest,
    manifest_digest,
    save_output_manifest,
    verify_output_manifest,
)


def _load_receipt_or_exit(path: Path) -> dict:
    try:
        return load_receipt(path)
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"could not read receipt {str(path)!r}: {exc}") from exc


def _manifest_file_exclusion(workspace_root: Path, manifest_path: Path) -> set[str]:
    """Exclude a controller-selected manifest file when it lives below the scanned root."""

    root = Path(workspace_root).resolve(strict=True)
    candidate = manifest_path.parent.resolve(strict=True) / manifest_path.name
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return set()
    return {relative.as_posix()} if relative.parts else set()


def _print_manifest_error(operation: str, exc: Exception, *, json_output: bool) -> int:
    message = f"manifest {operation} failed: {exc}"
    if json_output:
        print(json.dumps({"ok": False, "error": message}, sort_keys=True))
        return 1
    raise SystemExit(message) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-receipt",
        description="Build and verify claim→evidence receipts for AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"agent-receipt {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser(
        "build",
        help="Build a receipt from claims + evidence flags (simple CLI form)",
    )
    b.add_argument("--agent", default="unknown-agent")
    b.add_argument("--task", required=True)
    b.add_argument("--out", type=Path, required=True)
    b.add_argument(
        "--workspace-root",
        type=Path,
        required=True,
        help="Trusted workspace root; evidence is stored relative to it",
    )
    b.add_argument(
        "--claim",
        action="append",
        default=[],
        help='Claim id=statement (repeatable), e.g. tests="unit tests pass"',
    )
    b.add_argument(
        "--file-exists",
        action="append",
        default=[],
        help="Attach path_exists evidence to previous claim: claim_id=path",
    )
    b.add_argument(
        "--file-hash",
        action="append",
        default=[],
        help="Attach file_hash evidence: claim_id=path[,sha256]",
    )
    b.add_argument(
        "--text-contains",
        action="append",
        default=[],
        help="Attach text_contains: claim_id=path::snippet",
    )
    b.add_argument(
        "--command",
        action="append",
        default=[],
        help="Attach command evidence: claim_id=exit:cmd  e.g. tests=0:pytest -q",
    )
    b.add_argument(
        "--sign-private-key",
        type=Path,
        help="PEM Ed25519 private key; creates an authentication signature",
    )
    b.add_argument("--key-id", help="Trusted-key identifier required with --sign-private-key")
    b.add_argument("--packet-digest", help="Expected 64-character packet SHA-256")
    b.add_argument("--input-commit", help="Full 40- or 64-character Git commit ID")
    b.add_argument(
        "--output-manifest-digest",
        help="SHA-256 of the controller-generated canonical output manifest",
    )
    b.add_argument("--json", action="store_true")

    v = sub.add_parser("verify", help="Verify a receipt file")
    v.add_argument("receipt", type=Path)
    v.add_argument(
        "--recheck",
        action="store_true",
        help="Re-check file/path/text evidence (file hashes use the stored observed hash)",
    )
    v.add_argument("--packet-digest", help="Independently known packet SHA-256")
    v.add_argument("--input-commit", help="Independently known full Git commit ID")
    v.add_argument(
        "--output-manifest-digest",
        help="Independently computed external output-manifest SHA-256",
    )
    v.add_argument(
        "--recheck-commands",
        action="store_true",
        help="Re-run only commands explicitly listed with --allow-command",
    )
    v.add_argument(
        "--recheck-root",
        type=Path,
        help="Trusted workspace root used for every recheck",
    )
    v.add_argument(
        "--allow-command",
        action="append",
        default=[],
        help=(
            "Exact command with an absolute executable path permitted for recheck; verifier "
            f"requires exit 0, uses a fixed {VERIFIER_COMMAND_TIMEOUT}s timeout, and ignores "
            "worker-selected success expectations"
        ),
    )
    v.add_argument(
        "--minimum-assurance",
        choices=["reported", "partially_rechecked", "fully_rechecked"],
        default="fully_rechecked",
        help="Minimum independent recheck coverage required for exit code 0 (default: full)",
    )
    v.add_argument(
        "--trusted-key",
        action="append",
        default=[],
        help="key_id=public-key.pem; authenticates a receipt signature (repeatable)",
    )
    v.add_argument("--json", action="store_true")

    s = sub.add_parser("show", help="Pretty-print receipt summary")
    s.add_argument("receipt", type=Path)
    s.add_argument("--json", action="store_true")

    m = sub.add_parser("manifest", help="Create or independently verify an output manifest")
    manifest_sub = m.add_subparsers(dest="manifest_cmd", required=True)

    mc = manifest_sub.add_parser("create", help="Inventory the exact regular-file output set")
    mc.add_argument(
        "--workspace-root",
        type=Path,
        required=True,
        help="Controller-selected output root",
    )
    mc.add_argument(
        "--out",
        type=Path,
        help="Manifest destination (default: OUTPUT_MANIFEST.json under the root)",
    )
    mc.add_argument("--json", action="store_true")

    mv = manifest_sub.add_parser("verify", help="Re-scan and require the exact declared output")
    mv.add_argument(
        "manifest_file",
        type=Path,
        nargs="?",
        help="Manifest file (default: OUTPUT_MANIFEST.json under the root)",
    )
    mv.add_argument(
        "--workspace-root",
        type=Path,
        required=True,
        help="Controller-selected output root",
    )
    mv.add_argument(
        "--expected-digest",
        help="Independently trusted SHA-256 of the canonical manifest",
    )
    mv.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    if args.cmd == "manifest":
        if args.manifest_cmd == "create":
            try:
                root = args.workspace_root.resolve(strict=True)
                output = args.out or (root / "OUTPUT_MANIFEST.json")
                exclude = _manifest_file_exclusion(root, output)
                manifest, digest = create_output_manifest(root, exclude=exclude)
                save_output_manifest(manifest, output)
                result = {
                    "ok": True,
                    "digest": digest,
                    "files": manifest["file_count"],
                    "total_bytes": manifest["total_bytes"],
                    "manifest": str(output.parent.resolve(strict=True) / output.name),
                }
            except (OSError, UnicodeError, OutputManifestError, ValueError) as exc:
                return _print_manifest_error("create", exc, json_output=args.json)
            if args.json:
                print(json.dumps(result, sort_keys=True))
            else:
                print(f"manifest written: {result['manifest']}")
                print(
                    f"digest={result['digest']} files={result['files']} "
                    f"bytes={result['total_bytes']}"
                )
            return 0

        if args.manifest_cmd == "verify":
            try:
                root = args.workspace_root.resolve(strict=True)
                manifest_path = args.manifest_file or (root / "OUTPUT_MANIFEST.json")
                if (
                    args.expected_digest is not None
                    and re.fullmatch(r"[0-9a-f]{64}", args.expected_digest) is None
                ):
                    raise OutputManifestError("--expected-digest must be lowercase SHA-256 hex")
                manifest = load_output_manifest(manifest_path)
                loaded_digest = manifest_digest(manifest)
                if args.expected_digest is not None and loaded_digest != args.expected_digest:
                    result = {
                        "ok": False,
                        "digest": loaded_digest,
                        "files": manifest["file_count"],
                        "errors": ["manifest digest does not match trusted digest"],
                    }
                    if args.json:
                        print(json.dumps(result, sort_keys=True))
                    else:
                        print(f"ok=False digest={loaded_digest} files={manifest['file_count']}")
                        print(f"error: {result['errors'][0]}")
                    return 1
                exclude = _manifest_file_exclusion(root, manifest_path)
                result = verify_output_manifest(manifest, root, exclude=exclude)
            except (OSError, UnicodeError, OutputManifestError, ValueError) as exc:
                return _print_manifest_error("verify", exc, json_output=args.json)
            if args.json:
                print(json.dumps(result, sort_keys=True))
            else:
                print(f"ok={result['ok']} digest={result['digest']} files={result['files']}")
                for error in result["errors"]:
                    print(f"error: {error}")
            return 0 if result["ok"] else 1

    if args.cmd == "build":
        claims_map: dict[str, Claim] = {}
        for raw in args.claim:
            if "=" not in raw:
                raise SystemExit(f"bad --claim {raw!r}, expected id=statement")
            cid, statement = raw.split("=", 1)
            if not cid or cid in claims_map:
                raise SystemExit("claim ids must be non-empty and unique")
            claims_map[cid] = Claim(id=cid, statement=statement)

        def _need(cid: str) -> Claim:
            if cid not in claims_map:
                raise SystemExit(f"evidence refers to undeclared claim {cid!r}")
            return claims_map[cid]

        def _split_claim(raw: str) -> tuple[str, str]:
            if "=" not in raw:
                raise SystemExit(f"bad evidence {raw!r}, expected claim_id=value")
            cid, value = raw.split("=", 1)
            if not cid or not value:
                raise SystemExit(f"bad evidence {raw!r}, expected non-empty claim_id=value")
            return cid, value

        for raw in args.file_exists:
            cid, path = _split_claim(raw)
            _need(cid).evidence.append(
                evidence_path_exists(
                    Path(path), workspace_root=args.workspace_root, must_be_file=True
                )
            )

        for raw in args.file_hash:
            cid, rest = _split_claim(raw)
            if "," in rest:
                path, expect = rest.split(",", 1)
            else:
                path, expect = rest, None
            _need(cid).evidence.append(
                evidence_file_hash(
                    Path(path), workspace_root=args.workspace_root, expect_sha256=expect
                )
            )

        for raw in args.text_contains:
            cid, rest = _split_claim(raw)
            if "::" not in rest:
                raise SystemExit("text evidence format claim_id=path::literal")
            path, snippet = rest.split("::", 1)
            if not path:
                raise SystemExit("text evidence path must be non-empty")
            _need(cid).evidence.append(
                evidence_text_contains(Path(path), snippet, workspace_root=args.workspace_root)
            )

        for raw in args.command:
            cid, rest = _split_claim(raw)
            # format: exit:cmd...
            if ":" not in rest:
                raise SystemExit("command format claim_id=exit:cmd")
            exit_s, cmd_s = rest.split(":", 1)
            try:
                cmd = shlex.split(cmd_s)
                exit_code = int(exit_s)
            except ValueError as exc:
                raise SystemExit(f"invalid command evidence: {exc}") from exc
            _need(cid).evidence.append(
                evidence_command(cmd, workspace_root=args.workspace_root, expect_exit=exit_code)
            )

        if not claims_map:
            raise SystemExit("no claims provided")
        context_values = (args.packet_digest, args.input_commit, args.output_manifest_digest)
        if any(context_values) and not all(context_values):
            raise SystemExit("context flags must be supplied together")
        context = (
            {
                "packet_digest": args.packet_digest,
                "input_commit": args.input_commit,
                "output_manifest_digest": args.output_manifest_digest,
            }
            if all(context_values)
            else None
        )

        receipt = build_receipt(
            agent=args.agent,
            task=args.task,
            claims=list(claims_map.values()),
            workspace_root=args.workspace_root,
            context=context,
        )
        if bool(args.sign_private_key) != bool(args.key_id):
            raise SystemExit("--sign-private-key and --key-id must be used together")
        if args.sign_private_key:
            try:
                sign_receipt(receipt, args.sign_private_key.read_bytes(), args.key_id)
            except (OSError, ValueError, TypeError) as exc:
                raise SystemExit(f"could not sign receipt: {exc}") from exc
        save_receipt(receipt, args.out)
        if args.json:
            print(json.dumps(receipt.to_dict(), indent=2))
        else:
            print(f"receipt written: {args.out}")
            print(f"overall_ok={receipt.overall_ok} content_digest={receipt.content_digest}")
            for c in receipt.claims:
                ev = ",".join(f"{e.kind}:{'ok' if e.ok else 'FAIL'}" for e in c.evidence)
                print(f" - {c.id}: {c.statement} [{ev}]")
        return 0 if receipt.overall_ok else 1

    if args.cmd == "verify":
        data = _load_receipt_or_exit(args.receipt)
        if args.recheck_commands and not args.allow_command:
            raise SystemExit("--recheck-commands requires at least one explicit --allow-command")
        if (args.recheck or args.recheck_commands) and args.recheck_root is None:
            raise SystemExit("--recheck and --recheck-commands require --recheck-root")
        expected_values = (args.packet_digest, args.input_commit, args.output_manifest_digest)
        if any(expected_values) and not all(expected_values):
            raise SystemExit("context flags must be supplied together")
        expected_context = (
            {
                "packet_digest": args.packet_digest,
                "input_commit": args.input_commit,
                "output_manifest_digest": args.output_manifest_digest,
            }
            if all(expected_values)
            else None
        )
        try:
            allowed = {tuple(shlex.split(cmd)) for cmd in args.allow_command}
        except ValueError as exc:
            raise SystemExit(f"invalid --allow-command: {exc}") from exc
        if any(not cmd for cmd in allowed):
            raise SystemExit("--allow-command must not be empty")
        if any(not Path(cmd[0]).is_absolute() for cmd in allowed):
            raise SystemExit("--allow-command requires an absolute executable path")
        trusted_keys: dict[str, bytes] = {}
        for raw in args.trusted_key:
            if "=" not in raw:
                raise SystemExit("trusted key format is key_id=public-key.pem")
            key_id, key_path = raw.split("=", 1)
            if not key_id or key_id in trusted_keys:
                raise SystemExit("trusted key ids must be non-empty and unique")
            try:
                trusted_keys[key_id] = Path(key_path).read_bytes()
            except OSError as exc:
                raise SystemExit(f"could not read trusted key {key_path!r}: {exc}") from exc
        result = verify_receipt(
            data,
            recheck=args.recheck,
            recheck_commands=args.recheck_commands,
            recheck_root=args.recheck_root,
            allowed_commands=allowed if args.recheck_commands else None,
            trusted_keys=trusted_keys or None,
            expected_context=expected_context,
            minimum_assurance=args.minimum_assurance,
        )
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"ok={result['ok']} schema_ok={result['schema_ok']}")
            print(f"hash_ok={result['hash_ok']} authenticated={result['authenticated']}")
            print(f"assurance={result.get('assurance', 'unavailable')}")
            print(f"coverage={result.get('coverage', {})}")
            if "stored_overall_ok" in result:
                print(
                    f"overall stored={result['stored_overall_ok']} "
                    f"recomputed={result['recomputed_overall_ok']}"
                )
            for c in result["claims"]:
                print(f" - {c['id']}: {'OK' if c['ok'] else 'FAIL'} — {c['statement']}")
            for error in result.get("errors", []):
                print(f"error: {error}")
        return 0 if result["ok"] else 1

    if args.cmd == "show":
        data = _load_receipt_or_exit(args.receipt)
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print(f"agent={data.get('agent')!r} overall_ok={data.get('overall_ok')}")
            print(f"task={data.get('task')!r}")
            print(f"content_digest={data.get('content_digest')}")
            for c in data.get("claims", []):
                print(f"claim {c.get('id')!r}: {c.get('statement')!r}")
                for e in c.get("evidence", []):
                    print(f"  evidence {e.get('kind')!r} ok={e.get('ok')}")
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
