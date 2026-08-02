"""Offline, bounded claim receipts.

An unkeyed content digest detects inconsistent or unrehashed changes. Ed25519
signatures authenticate the signer of a digest. Neither establishes that a
claim is true.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import signal
import subprocess
import threading
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "agent-receipt/v1"
MAX_CLAIMS = 100
MAX_EVIDENCE_PER_CLAIM = 20
MAX_TOTAL_EVIDENCE = 200
MAX_COMMAND_EVIDENCE = 5
MAX_COMMAND_TOTAL_TIMEOUT = 120
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_STRING = 4_096
MAX_COMMAND_ARGS = 32
MAX_COMMAND_OUTPUT = 64 * 1024
MAX_COMMAND_TIMEOUT = 60
VERIFIER_COMMAND_TIMEOUT = 20
_EVIDENCE_KINDS = {"file_hash", "command", "text_contains", "path_exists"}
_SIGNING_CONTEXT = b"agent-receipt/v1\x00"
_ASSURANCE_RANK = {"reported": 0, "partially_rechecked": 1, "fully_rechecked": 2}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(obj: Any) -> str:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _bounded_string(value: Any, *, nonempty: bool = False) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= MAX_STRING
        and (bool(value) if nonempty else True)
        and "\x00" not in value
        and all(unicodedata.category(character) not in {"Cc", "Cf"} for character in value)
    )


def _trusted_root(root: Path) -> Path:
    resolved = Path(root).resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("workspace_root must be an existing directory")
    return resolved


def _workspace_target(path: Path, workspace_root: Path) -> tuple[Path, Path]:
    root = _trusted_root(workspace_root)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    # resolve follows links so both build-time and recheck-time escapes fail closed.
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("evidence path escapes workspace_root") from exc
    if resolved == root:
        raise ValueError("evidence path must name an entry below workspace_root")
    return root, resolved


def _relative_path(path: Path, workspace_root: Path) -> str:
    root, resolved = _workspace_target(path, workspace_root)
    return _validate_relative_path(resolved.relative_to(root).as_posix())


def _validate_relative_path(value: Any) -> str:
    if not _bounded_string(value, nonempty=True) or "\\" in value:
        raise ValueError("path must be a non-empty POSIX relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value in {".", ".."}
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("path must not be absolute, dot, or dot-dot")
    return value


def _recheck_path(root: Path, stored_path: str) -> Path:
    relative = _validate_relative_path(stored_path)
    trusted = _trusted_root(root)
    target = (trusted / relative).resolve(strict=False)
    try:
        target.relative_to(trusted)
    except ValueError as exc:
        raise ValueError("stored path escapes recheck_root") from exc
    return target


def _file_bytes(path: Path) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError("file exceeds receipt size limit")
    return path.read_bytes()


@dataclass
class Evidence:
    kind: str
    detail: dict[str, Any]
    ok: bool = False
    observed: dict[str, Any] = field(default_factory=dict)


@dataclass
class Claim:
    id: str
    statement: str
    evidence: list[Evidence] = field(default_factory=list)


@dataclass
class Receipt:
    schema: str
    created_at: str
    agent: str
    task: str
    claims: list[Claim]
    overall_ok: bool
    content_digest: str = ""
    context: dict[str, str] | None = None
    signatures: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evidence_file_hash(
    path: Path, *, workspace_root: Path, expect_sha256: str | None = None
) -> Evidence:
    root, target = _workspace_target(path, workspace_root)
    detail = {
        "path": _relative_path(target, root),
        "expect_sha256": expect_sha256,
    }
    try:
        data = _file_bytes(target)
        got = _sha256_bytes(data)
        return Evidence(
            "file_hash",
            detail,
            expect_sha256 is None or got == expect_sha256,
            {"sha256": got, "bytes": len(data)},
        )
    except (OSError, ValueError) as exc:
        return Evidence("file_hash", detail, False, {"error": type(exc).__name__})


def evidence_path_exists(
    path: Path, *, workspace_root: Path, must_be_file: bool = False
) -> Evidence:
    root, target = _workspace_target(path, workspace_root)
    detail = {
        "path": _relative_path(target, root),
        "must_be_file": must_be_file,
    }
    exists = target.exists()
    return Evidence(
        "path_exists",
        detail,
        exists and (target.is_file() if must_be_file else True),
        {
            "exists": exists,
            "is_file": target.is_file() if exists else False,
            "is_dir": target.is_dir() if exists else False,
        },
    )


def evidence_text_contains(path: Path, pattern: str, *, workspace_root: Path) -> Evidence:
    if not _bounded_string(pattern, nonempty=True):
        raise ValueError("text pattern must be a bounded, non-empty NUL-free literal")
    root, target = _workspace_target(path, workspace_root)
    detail = {"path": _relative_path(target, root), "literal": pattern}
    try:
        data = _file_bytes(target)
        matched = pattern in data.decode("utf-8", errors="replace")
        return Evidence("text_contains", detail, matched, {"bytes": len(data), "matched": matched})
    except (OSError, ValueError) as exc:
        return Evidence("text_contains", detail, False, {"error": type(exc).__name__})


def _command_detail(
    cmd: list[str], expect_exit: int, timeout: int, stdout_contains: str | None
) -> dict[str, Any]:
    if (
        not isinstance(cmd, list)
        or not 0 < len(cmd) <= MAX_COMMAND_ARGS
        or not all(_bounded_string(arg, nonempty=True) for arg in cmd)
    ):
        raise ValueError("command must contain bounded, non-empty string arguments")
    if isinstance(expect_exit, bool) or not isinstance(expect_exit, int):
        raise TypeError("expect_exit must be an integer")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 1 <= timeout <= MAX_COMMAND_TIMEOUT
    ):
        raise ValueError("timeout is outside the allowed range")
    if stdout_contains is not None and not _bounded_string(stdout_contains, nonempty=True):
        raise ValueError("stdout_contains must be a bounded, non-empty NUL-free literal")
    return {
        "cmd": cmd,
        "expect_exit": expect_exit,
        "stdout_contains": stdout_contains,
        "timeout": timeout,
    }


def evidence_command(
    cmd: list[str],
    *,
    workspace_root: Path,
    expect_exit: int = 0,
    timeout: int = 60,
    stdout_contains: str | None = None,
) -> Evidence:
    """Run without a shell under the trusted workspace root.

    This can execute repository code. Callers must treat every command as a
    deliberate execution decision; a receipt does not make it safe.
    """
    detail = _command_detail(cmd, expect_exit, timeout, stdout_contains)
    root = _trusted_root(workspace_root)
    try:
        proc = subprocess.Popen(  # noqa: S603 -- explicit caller-approved command evidence
            cmd,
            cwd=root,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env={
                "PATH": os.environ.get("PATH", os.defpath),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
        streams = {"stdout": proc.stdout, "stderr": proc.stderr}
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        output_limit_hit = threading.Event()

        def drain(name: str) -> None:
            stream = streams[name]
            if stream is None:
                return
            while chunk := stream.read(8_192):
                remaining = MAX_COMMAND_OUTPUT - len(buffers[name])
                if remaining > 0:
                    buffers[name].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    output_limit_hit.set()
                    _terminate_process(proc)
                    break

        readers = [threading.Thread(target=drain, args=(name,), daemon=True) for name in streams]
        for reader in readers:
            reader.start()
        try:
            return_code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_process(proc)
            proc.wait(timeout=5)
            for reader in readers:
                reader.join(timeout=1)
            return Evidence("command", detail, False, {"error": "TimeoutExpired"})
        for reader in readers:
            reader.join(timeout=1)
        if output_limit_hit.is_set():
            return Evidence("command", detail, False, {"error": "OutputLimitExceeded"})

        out, err = bytes(buffers["stdout"]), bytes(buffers["stderr"])
        stdout_contains_matched = stdout_contains is None or stdout_contains.encode() in out
        ok = return_code == expect_exit and stdout_contains_matched
        return Evidence(
            "command",
            detail,
            ok,
            {
                "exit_code": return_code,
                "stdout_sha256": _sha256_bytes(out),
                "stderr_sha256": _sha256_bytes(err),
                "stdout_bytes": len(out),
                "stderr_bytes": len(err),
                "output_truncated": False,
                "stdout_contains_matched": stdout_contains_matched,
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Evidence("command", detail, False, {"error": type(exc).__name__})


def _terminate_process(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except ProcessLookupError:
        return


def build_receipt(
    *,
    agent: str,
    task: str,
    claims: list[Claim],
    workspace_root: Path,
    context: dict[str, str] | None = None,
) -> Receipt:
    _trusted_root(workspace_root)
    provisional = Receipt(
        SCHEMA,
        datetime.now(timezone.utc).isoformat(),
        agent,
        task,
        claims,
        False,
        context=context,
    )
    errors = _schema_errors({**provisional.to_dict(), "content_digest": "0" * 64})
    if errors:
        raise ValueError("invalid receipt: " + "; ".join(errors))
    provisional.overall_ok = all(all(ev.ok for ev in claim.evidence) for claim in claims)
    provisional.content_digest = _receipt_digest(provisional.to_dict())
    return provisional


def _unsigned_body(data: dict[str, Any]) -> dict[str, Any]:
    body = dict(data)
    body.pop("content_digest", None)
    body.pop("signatures", None)
    return body


def _receipt_digest(data: dict[str, Any]) -> str:
    return _sha256_bytes(_canonical_json(_unsigned_body(data)).encode())


def _context_errors(value: Any) -> list[str]:
    if value is None:
        return []
    required = {"packet_digest", "input_commit", "output_manifest_digest"}
    if not isinstance(value, dict) or set(value) != required:
        return ["context must have packet_digest, input_commit, and output_manifest_digest"]
    if not all(_is_sha256(value[k]) for k in ("packet_digest", "output_manifest_digest")):
        return ["context packet_digest and output_manifest_digest must be SHA-256 hex"]
    if (
        not isinstance(value["input_commit"], str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value["input_commit"]) is None
    ):
        return ["context input_commit must be a full lowercase Git commit identifier"]
    return []


def _schema_errors(data: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["receipt must be an object"]
    required = {
        "schema",
        "created_at",
        "agent",
        "task",
        "claims",
        "overall_ok",
        "content_digest",
        "context",
        "signatures",
    }
    if set(data) != required:
        errors.append("receipt keys must be exactly: " + ", ".join(sorted(required)))
    for key in ("schema", "created_at", "agent", "task", "content_digest"):
        if not isinstance(data.get(key), str):
            errors.append(f"{key} must be a string")
    if not _bounded_string(data.get("agent"), nonempty=True) or not _bounded_string(
        data.get("task"), nonempty=True
    ):
        errors.append("agent and task must be bounded non-empty strings")
    if data.get("schema") != SCHEMA:
        errors.append(f"unsupported schema: {data.get('schema')!r}")
    if not _is_sha256(data.get("content_digest")):
        errors.append("content_digest must be lowercase SHA-256 hex")
    if not isinstance(data.get("overall_ok"), bool):
        errors.append("overall_ok must be boolean")
    errors.extend(_context_errors(data.get("context")))
    if (
        not isinstance(data.get("claims"), list)
        or not 0 < len(data.get("claims", [])) <= MAX_CLAIMS
    ):
        errors.append("claims must be a bounded non-empty list")
    if not isinstance(data.get("signatures"), list) or len(data.get("signatures", [])) > 10:
        errors.append("signatures must be a bounded list")
    try:
        datetime.fromisoformat(data.get("created_at", "").replace("Z", "+00:00"))
    except (TypeError, ValueError):
        errors.append("created_at must be ISO-8601")
    ids: set[str] = set()
    total_evidence = 0
    command_count = 0
    command_timeout_total = 0
    seen_commands: set[tuple[str, ...]] = set()
    for i, claim in enumerate(
        data.get("claims", []) if isinstance(data.get("claims"), list) else []
    ):
        prefix = f"claims[{i}]"
        if not isinstance(claim, dict) or set(claim) != {"id", "statement", "evidence"}:
            errors.append(f"{prefix} has invalid keys")
            continue
        if not _bounded_string(claim["id"], nonempty=True) or claim["id"] in ids:
            errors.append(f"{prefix}.id must be unique, bounded, non-empty string")
        ids.add(claim.get("id", ""))
        if not _bounded_string(claim["statement"], nonempty=True):
            errors.append(f"{prefix}.statement must be bounded non-empty string")
        if (
            not isinstance(claim["evidence"], list)
            or not 0 < len(claim["evidence"]) <= MAX_EVIDENCE_PER_CLAIM
        ):
            errors.append(f"{prefix}.evidence must be bounded non-empty list")
            continue
        total_evidence += len(claim["evidence"])
        for j, ev in enumerate(claim["evidence"]):
            errors.extend(_evidence_errors(ev, f"{prefix}.evidence[{j}]"))
            if (
                isinstance(ev, dict)
                and ev.get("kind") == "command"
                and isinstance(ev.get("detail"), dict)
                and isinstance(ev["detail"].get("cmd"), list)
                and all(isinstance(item, str) for item in ev["detail"]["cmd"])
            ):
                command = tuple(ev["detail"]["cmd"])
                if command in seen_commands:
                    errors.append(f"{prefix}.evidence[{j}] duplicates a command")
                seen_commands.add(command)
                command_count += 1
                timeout = ev["detail"].get("timeout")
                if isinstance(timeout, int) and not isinstance(timeout, bool):
                    command_timeout_total += timeout
    if total_evidence > MAX_TOTAL_EVIDENCE:
        errors.append("receipt exceeds total evidence limit")
    if command_count > MAX_COMMAND_EVIDENCE:
        errors.append("receipt exceeds command evidence limit")
    if command_timeout_total > MAX_COMMAND_TOTAL_TIMEOUT:
        errors.append("receipt exceeds total command timeout budget")
    for i, sig in enumerate(
        data.get("signatures", []) if isinstance(data.get("signatures"), list) else []
    ):
        if (
            not isinstance(sig, dict)
            or set(sig) != {"algorithm", "key_id", "signature"}
            or sig.get("algorithm") != "ed25519"
            or not _bounded_string(sig.get("key_id"), nonempty=True)
            or not _bounded_string(sig.get("signature"), nonempty=True)
        ):
            errors.append(f"signatures[{i}] is not a valid ed25519 signature")
            continue
        try:
            raw_signature = base64.b64decode(sig["signature"], validate=True)
            if len(raw_signature) != 64:
                raise ValueError
        except (ValueError, TypeError):
            errors.append(f"signatures[{i}].signature is not base64")
    return errors


def _evidence_errors(ev: Any, prefix: str) -> list[str]:
    if not isinstance(ev, dict) or set(ev) != {"kind", "detail", "ok", "observed"}:
        return [f"{prefix} has invalid keys"]
    if (
        ev.get("kind") not in _EVIDENCE_KINDS
        or not isinstance(ev.get("ok"), bool)
        or not isinstance(ev.get("detail"), dict)
        or not isinstance(ev.get("observed"), dict)
    ):
        return [f"{prefix} has invalid fields"]
    k, d, o = ev["kind"], ev["detail"], ev["observed"]
    expected = {
        "file_hash": {"path", "expect_sha256"},
        "path_exists": {"path", "must_be_file"},
        "text_contains": {"path", "literal"},
        "command": {"cmd", "expect_exit", "stdout_contains", "timeout"},
    }[k]
    if set(d) != expected:
        return [f"{prefix}.detail has invalid keys"]
    try:
        if k != "command":
            _validate_relative_path(d["path"])
        if (
            k == "file_hash"
            and d["expect_sha256"] is not None
            and not _is_sha256(d["expect_sha256"])
        ):
            raise ValueError
        if k == "path_exists" and not isinstance(d["must_be_file"], bool):
            raise ValueError
        if k == "text_contains" and not _bounded_string(d["literal"], nonempty=True):
            raise ValueError
        if k == "command":
            _command_detail(d["cmd"], d["expect_exit"], d["timeout"], d["stdout_contains"])
    except (KeyError, ValueError, TypeError):
        return [f"{prefix}.detail is invalid"]
    observed_keys = {
        "file_hash": {"sha256", "bytes"},
        "path_exists": {"exists", "is_file", "is_dir"},
        "text_contains": {"bytes", "matched"},
        "command": {
            "exit_code",
            "stdout_sha256",
            "stderr_sha256",
            "stdout_bytes",
            "stderr_bytes",
            "output_truncated",
            "stdout_contains_matched",
        },
    }
    # Failure observations carry only a bounded error class; success shape is exact.
    if set(o) == {"error"}:
        if _bounded_string(o["error"], nonempty=True) and ev["ok"] is False:
            return []
        return [f"{prefix}.error observation must be a bounded failure"]
    if set(o) != observed_keys[k]:
        return [f"{prefix}.observed has invalid keys"]
    if k == "file_hash":
        expected_ok = d["expect_sha256"] is None or o["sha256"] == d["expect_sha256"]
        if (
            not _is_sha256(o["sha256"])
            or isinstance(o["bytes"], bool)
            or not isinstance(o["bytes"], int)
            or not 0 <= o["bytes"] <= MAX_FILE_BYTES
            or ev["ok"] != expected_ok
        ):
            return [f"{prefix}.observed is inconsistent"]
    if k == "path_exists":
        expected_ok = o["exists"] and (not d["must_be_file"] or o["is_file"])
        if (
            not all(isinstance(o[x], bool) for x in o)
            or (not o["exists"] and (o["is_file"] or o["is_dir"]))
            or (o["is_file"] and o["is_dir"])
            or ev["ok"] != expected_ok
        ):
            return [f"{prefix}.observed is inconsistent"]
    if k == "text_contains":
        if (
            isinstance(o["bytes"], bool)
            or not isinstance(o["bytes"], int)
            or not 0 <= o["bytes"] <= MAX_FILE_BYTES
            or not isinstance(o["matched"], bool)
            or ev["ok"] != o["matched"]
        ):
            return [f"{prefix}.observed is inconsistent"]
    if k == "command" and (
        not isinstance(o["exit_code"], int)
        or isinstance(o["exit_code"], bool)
        or not _is_sha256(o["stdout_sha256"])
        or not _is_sha256(o["stderr_sha256"])
        or isinstance(o["stdout_bytes"], bool)
        or isinstance(o["stderr_bytes"], bool)
        or not isinstance(o["stdout_bytes"], int)
        or not isinstance(o["stderr_bytes"], int)
        or o["stdout_bytes"] < 0
        or o["stderr_bytes"] < 0
        or o["stdout_bytes"] > MAX_COMMAND_OUTPUT
        or o["stderr_bytes"] > MAX_COMMAND_OUTPUT
        or o["output_truncated"] is not False
        or not isinstance(o["stdout_contains_matched"], bool)
        or (d["stdout_contains"] is None and not o["stdout_contains_matched"])
        or ev["ok"] != (o["exit_code"] == d["expect_exit"] and o["stdout_contains_matched"])
    ):
        return [f"{prefix}.observed is inconsistent"]
    return []


def sign_receipt(receipt: Receipt, private_key_pem: bytes, key_id: str) -> Receipt:
    """Add signer attribution, not a truth guarantee."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey) or not _bounded_string(key_id, nonempty=True):
        raise ValueError("private key must be Ed25519 and key_id is required")
    digest = _receipt_digest(receipt.to_dict())
    if receipt.content_digest != digest:
        raise ValueError("cannot sign receipt with invalid content digest")
    receipt.signatures.append(
        {
            "algorithm": "ed25519",
            "key_id": key_id,
            "signature": base64.b64encode(
                key.sign(_SIGNING_CONTEXT + bytes.fromhex(digest))
            ).decode("ascii"),
        }
    )
    return receipt


def _signature_ok(
    data: dict[str, Any], trusted_keys: dict[str, bytes] | None
) -> tuple[bool | None, list[str]]:
    if trusted_keys is None:
        return None, []
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    digest = bytes.fromhex(data["content_digest"])
    errors: list[str] = []
    for sig in data["signatures"]:
        pem = trusted_keys.get(sig["key_id"])
        if pem is None:
            continue
        try:
            key = serialization.load_pem_public_key(pem)
            if not isinstance(key, Ed25519PublicKey):
                raise TypeError("trusted key is not Ed25519")
            key.verify(
                base64.b64decode(sig["signature"], validate=True),
                _SIGNING_CONTEXT + digest,
            )
            return True, []
        except (InvalidSignature, TypeError, ValueError):
            errors.append(f"invalid signature for trusted key {sig['key_id']!r}")
    return False, errors or ["no signature for a trusted key"]


def verify_receipt(
    data: dict[str, Any] | Receipt,
    *,
    recheck: bool = False,
    recheck_commands: bool = False,
    recheck_root: Path | None = None,
    allowed_commands: set[tuple[str, ...]] | None = None,
    trusted_keys: dict[str, bytes] | None = None,
    expected_context: dict[str, str] | None = None,
    minimum_assurance: str = "fully_rechecked",
) -> dict[str, Any]:
    data = data.to_dict() if isinstance(data, Receipt) else data
    errors = _schema_errors(data)
    if (recheck or recheck_commands) and recheck_root is None:
        errors.append("recheck_root is required for every recheck")
    if expected_context is not None:
        errors.extend(_context_errors(expected_context))
    if minimum_assurance not in _ASSURANCE_RANK:
        errors.append("minimum_assurance is invalid")
    if errors:
        return {
            "ok": False,
            "schema_ok": False,
            "hash_ok": False,
            "authenticated": None,
            "errors": errors,
            "claims": [],
        }
    try:
        root = _trusted_root(recheck_root) if recheck_root is not None else None
    except (OSError, ValueError):
        return {
            "ok": False,
            "schema_ok": True,
            "hash_ok": False,
            "authenticated": None,
            "errors": ["recheck_root must be an existing directory"],
            "claims": [],
        }
    data = dict(data)
    recomputed = _receipt_digest(data)
    digest_ok = recomputed == data["content_digest"]
    claim_results, overall = [], True
    total_evidence = 0
    rechecked_evidence = 0
    blocked_evidence = 0
    for claim in data["claims"]:
        ev_ok = True
        for stored in claim["evidence"]:
            total_evidence += 1
            ev = stored
            try:
                if recheck and stored["kind"] == "file_hash":
                    rechecked_evidence += 1
                    ev = asdict(
                        evidence_file_hash(
                            _recheck_path(root, stored["detail"]["path"]),
                            workspace_root=root,
                            expect_sha256=stored["observed"].get("sha256"),
                        )
                    )
                elif recheck and stored["kind"] == "path_exists":
                    rechecked_evidence += 1
                    ev = asdict(
                        evidence_path_exists(
                            _recheck_path(root, stored["detail"]["path"]),
                            workspace_root=root,
                            must_be_file=stored["detail"]["must_be_file"],
                        )
                    )
                elif recheck and stored["kind"] == "text_contains":
                    rechecked_evidence += 1
                    ev = asdict(
                        evidence_text_contains(
                            _recheck_path(root, stored["detail"]["path"]),
                            stored["detail"]["literal"],
                            workspace_root=root,
                        )
                    )
                elif recheck_commands and stored["kind"] == "command":
                    command = tuple(stored["detail"]["cmd"])
                    if not Path(command[0]).is_absolute():
                        blocked_evidence += 1
                        ev = {
                            **stored,
                            "ok": False,
                            "observed": {"error": "command_executable_not_absolute"},
                        }
                    elif allowed_commands is not None and command in allowed_commands:
                        rechecked_evidence += 1
                        ev = asdict(
                            evidence_command(
                                list(command),
                                workspace_root=root,
                                # The verifier policy, not the worker receipt, defines
                                # success semantics and the execution budget.
                                expect_exit=0,
                                timeout=VERIFIER_COMMAND_TIMEOUT,
                                stdout_contains=None,
                            )
                        )
                    else:
                        blocked_evidence += 1
                        ev = {
                            **stored,
                            "ok": False,
                            "observed": {"error": "command_not_explicitly_allowed"},
                        }
            except ValueError:
                ev = {
                    **stored,
                    "ok": False,
                    "observed": {"error": "recheck_path_invalid"},
                }
            ev_ok = ev_ok and ev["ok"]
        claim_results.append({"id": claim["id"], "ok": ev_ok, "statement": claim["statement"]})
        overall = overall and ev_ok
    authenticated, sig_errors = _signature_ok(data, trusted_keys)
    context_ok = expected_context is None or data["context"] == expected_context
    assurance = (
        "fully_rechecked"
        if rechecked_evidence == total_evidence
        else "partially_rechecked"
        if rechecked_evidence
        else "reported"
    )
    assurance_ok = _ASSURANCE_RANK[assurance] >= _ASSURANCE_RANK[minimum_assurance]
    result = {
        "ok": digest_ok
        and overall
        and data["overall_ok"] == overall
        and authenticated is not False
        and context_ok
        and assurance_ok,
        "schema_ok": True,
        "hash_ok": digest_ok,
        "authenticated": authenticated,
        "claimed_digest": data["content_digest"],
        "recomputed_digest": recomputed,
        "stored_overall_ok": data["overall_ok"],
        "recomputed_overall_ok": overall,
        "claims": claim_results,
        "schema": data["schema"],
        "agent": data["agent"],
        "task": data["task"],
        "context_ok": context_ok,
        "assurance": assurance,
        "minimum_assurance": minimum_assurance,
        "assurance_ok": assurance_ok,
        "coverage": {
            "total_evidence": total_evidence,
            "rechecked_evidence": rechecked_evidence,
            "reported_evidence": total_evidence - rechecked_evidence - blocked_evidence,
            "blocked_evidence": blocked_evidence,
        },
        "errors": sig_errors,
    }
    if not digest_ok:
        result["errors"].append("content_digest mismatch (tampered or non-canonical)")
    if data["overall_ok"] != overall:
        result["errors"].append("overall_ok disagrees with evidence")
    if not context_ok:
        result["errors"].append("receipt context does not match verifier expectations")
    if not assurance_ok:
        result["errors"].append(f"assurance {assurance!r} is below required {minimum_assurance!r}")
    return result


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_receipt(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("receipt exceeds size limit")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)


def save_receipt(receipt: Receipt, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(receipt.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
