from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_receipt import output_manifest
from agent_receipt.cli import main
from agent_receipt.core import (
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
from agent_receipt.output_manifest import (
    OutputManifestError,
    create_output_manifest,
    load_output_manifest,
    manifest_digest,
    save_output_manifest,
    verify_output_manifest,
)


def _receipt(root: Path, evidence):
    return build_receipt(
        agent="test-agent",
        task="test task",
        workspace_root=root,
        claims=[Claim("artifact", "artifact is valid", [evidence])],
    )


def test_receipt_stores_relative_paths_and_rechecks_with_trusted_root(tmp_path: Path):
    artifact = tmp_path / "out.txt"
    artifact.write_text("all green\n", encoding="utf-8")
    receipt = build_receipt(
        agent="test-agent",
        task="write artifact",
        workspace_root=tmp_path,
        claims=[
            Claim(
                "artifact",
                "output is valid",
                [
                    evidence_path_exists(artifact, workspace_root=tmp_path, must_be_file=True),
                    evidence_text_contains(artifact, "all green", workspace_root=tmp_path),
                    evidence_file_hash(artifact, workspace_root=tmp_path),
                ],
            )
        ],
    )
    assert receipt.claims[0].evidence[0].detail["path"] == "out.txt"
    assert verify_receipt(receipt, recheck=True, recheck_root=tmp_path)["ok"] is True
    assert verify_receipt(receipt, recheck=True)["schema_ok"] is False


def test_relative_build_path_is_resolved_from_workspace_root(tmp_path: Path, monkeypatch):
    artifact = tmp_path / "out.txt"
    artifact.write_text("root-bound", encoding="utf-8")
    monkeypatch.chdir(tmp_path.parent)
    evidence = evidence_text_contains(Path("out.txt"), "root-bound", workspace_root=tmp_path)
    assert evidence.ok is True
    assert evidence.detail["path"] == "out.txt"


@pytest.mark.parametrize("path", [Path("."), Path("../outside")])
def test_build_rejects_absolute_dot_and_parent_paths(tmp_path: Path, path: Path):
    with pytest.raises(ValueError):
        evidence_path_exists(path, workspace_root=tmp_path)
    with pytest.raises(ValueError):
        evidence_path_exists(tmp_path.parent / "outside", workspace_root=tmp_path)


def test_symlink_escape_is_rejected_at_build_and_recheck(tmp_path: Path):
    outside = tmp_path.parent / "outside-receipt-test.txt"
    outside.write_text("outside", encoding="utf-8")
    link = tmp_path / "escape"
    link.symlink_to(outside)
    with pytest.raises(ValueError):
        evidence_file_hash(link, workspace_root=tmp_path)

    safe = tmp_path / "safe.txt"
    safe.write_text("safe", encoding="utf-8")
    receipt = _receipt(tmp_path, evidence_file_hash(safe, workspace_root=tmp_path))
    safe.unlink()
    safe.symlink_to(outside)
    assert verify_receipt(receipt, recheck=True, recheck_root=tmp_path)["ok"] is False


def test_text_matching_is_literal_only(tmp_path: Path):
    artifact = tmp_path / "a.txt"
    artifact.write_text("abc", encoding="utf-8")
    assert evidence_text_contains(artifact, "a.c", workspace_root=tmp_path).ok is False
    with pytest.raises(TypeError):
        evidence_text_contains(
            artifact, "abc", True, workspace_root=tmp_path
        )  # v1 has no regex argument
    with pytest.raises(ValueError, match="non-empty"):
        evidence_text_contains(artifact, "", workspace_root=tmp_path)


def test_schema_rejects_duplicate_claims_extra_fields_and_bad_observed(tmp_path: Path):
    artifact = tmp_path / "a.txt"
    artifact.write_text("x", encoding="utf-8")
    data = _receipt(tmp_path, evidence_file_hash(artifact, workspace_root=tmp_path)).to_dict()
    duplicate = json.loads(json.dumps(data))
    duplicate["claims"].append(duplicate["claims"][0])
    assert verify_receipt(duplicate)["schema_ok"] is False
    extra = json.loads(json.dumps(data))
    extra["claims"][0]["evidence"][0]["observed"]["unexpected"] = True
    assert verify_receipt(extra)["schema_ok"] is False
    nul = json.loads(json.dumps(data))
    nul["claims"][0]["evidence"][0]["detail"]["path"] = "a\u0000.txt"
    assert verify_receipt(nul)["schema_ok"] is False
    inconsistent = json.loads(json.dumps(data))
    inconsistent["claims"][0]["evidence"][0]["ok"] = False
    assert verify_receipt(inconsistent)["schema_ok"] is False
    terminal_control = json.loads(json.dumps(data))
    terminal_control["task"] = "clear\u001b[2J"
    assert verify_receipt(terminal_control)["schema_ok"] is False


def test_file_hash_recheck_detects_change(tmp_path: Path):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("first", encoding="utf-8")
    receipt = _receipt(tmp_path, evidence_file_hash(artifact, workspace_root=tmp_path))
    artifact.write_text("changed", encoding="utf-8")
    result = verify_receipt(receipt, recheck=True, recheck_root=tmp_path)
    assert result["hash_ok"] is True
    assert result["recomputed_overall_ok"] is False


def test_command_recheck_needs_root_exact_allowlist_and_ignores_forged_cwd(
    tmp_path: Path,
):
    command = [sys.executable, "-c", "print('ok')"]
    receipt = _receipt(tmp_path, evidence_command(command, workspace_root=tmp_path))
    assert (
        verify_receipt(receipt, recheck_commands=True, allowed_commands={tuple(command)})[
            "schema_ok"
        ]
        is False
    )
    assert (
        verify_receipt(
            receipt,
            recheck_commands=True,
            recheck_root=tmp_path,
            allowed_commands=set(),
        )["ok"]
        is False
    )
    forged = receipt.to_dict()
    forged["claims"][0]["evidence"][0]["detail"]["cwd"] = str(tmp_path.parent)
    assert (
        verify_receipt(
            forged,
            recheck_commands=True,
            recheck_root=tmp_path,
            allowed_commands={tuple(command)},
        )["schema_ok"]
        is False
    )
    assert (
        verify_receipt(
            receipt,
            recheck_commands=True,
            recheck_root=tmp_path,
            allowed_commands={tuple(command)},
        )["ok"]
        is True
    )


def test_command_recheck_uses_controller_success_policy(tmp_path: Path):
    command = [sys.executable, "-c", "raise SystemExit(7)"]
    receipt = _receipt(
        tmp_path,
        evidence_command(command, workspace_root=tmp_path, expect_exit=7),
    )
    assert receipt.overall_ok is True
    result = verify_receipt(
        receipt,
        recheck_commands=True,
        recheck_root=tmp_path,
        allowed_commands={tuple(command)},
    )
    assert result["ok"] is False
    assert result["assurance"] == "fully_rechecked"
    assert result["recomputed_overall_ok"] is False


def test_command_recheck_rejects_non_absolute_executable(tmp_path: Path):
    command = [sys.executable, "-c", "print('ok')"]
    evidence = evidence_command(command, workspace_root=tmp_path)
    evidence.detail["cmd"][0] = Path(sys.executable).name
    receipt = _receipt(tmp_path, evidence)
    stored_command = tuple(evidence.detail["cmd"])
    result = verify_receipt(
        receipt,
        recheck_commands=True,
        recheck_root=tmp_path,
        allowed_commands={stored_command},
    )
    assert result["ok"] is False
    assert result["coverage"]["blocked_evidence"] == 1


def test_duplicate_command_evidence_is_rejected(tmp_path: Path):
    command = [sys.executable, "-c", "print('once')"]
    evidence = evidence_command(command, workspace_root=tmp_path)
    with pytest.raises(ValueError, match="duplicates a command"):
        build_receipt(
            agent="test-agent",
            task="duplicate command",
            workspace_root=tmp_path,
            claims=[Claim("commands", "commands pass", [evidence, evidence])],
        )


def test_command_output_limit_fails_without_storing_output(tmp_path: Path):
    evidence = evidence_command(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 70000)"],
        workspace_root=tmp_path,
    )
    assert evidence.ok is False
    assert evidence.observed == {"error": "OutputLimitExceeded"}


def test_context_is_strict_and_signature_authenticates_attribution(tmp_path: Path):
    artifact = tmp_path / "a.txt"
    artifact.write_text("x", encoding="utf-8")
    context = {
        "packet_digest": "a" * 64,
        "input_commit": "d" * 40,
        "output_manifest_digest": "b" * 64,
    }
    receipt = build_receipt(
        agent="worker",
        task="t",
        workspace_root=tmp_path,
        context=context,
        claims=[Claim("a", "exists", [evidence_path_exists(artifact, workspace_root=tmp_path)])],
    )
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sign_receipt(receipt, private_pem, "worker-1")
    assert verify_receipt(receipt, trusted_keys={"worker-1": public_pem})["authenticated"] is True
    data = receipt.to_dict()
    data["task"] = "forged"
    result = verify_receipt(data, trusted_keys={"worker-1": public_pem})
    assert result["ok"] is False and result["hash_ok"] is False
    assert verify_receipt(receipt, expected_context=context)["context_ok"] is True
    wrong = {**context, "input_commit": "a" * 40}
    assert verify_receipt(receipt, expected_context=wrong)["ok"] is False


def test_invalid_recheck_root_is_structured_failure_and_reports_coverage(tmp_path: Path):
    artifact = tmp_path / "a.txt"
    artifact.write_text("x", encoding="utf-8")
    receipt = _receipt(tmp_path, evidence_path_exists(artifact, workspace_root=tmp_path))
    invalid = verify_receipt(receipt, recheck=True, recheck_root=tmp_path / "missing")
    assert invalid["ok"] is False
    assert "recheck_root" in invalid["errors"][0]
    reported = verify_receipt(receipt)
    assert reported["ok"] is False
    assert reported["assurance"] == "reported"
    assert reported["assurance_ok"] is False
    assert reported["coverage"] == {
        "total_evidence": 1,
        "rechecked_evidence": 0,
        "reported_evidence": 1,
        "blocked_evidence": 0,
    }
    explicitly_accepted = verify_receipt(receipt, minimum_assurance="reported")
    assert explicitly_accepted["ok"] is True
    assert explicitly_accepted["assurance_ok"] is True


def test_cli_rejects_duplicate_and_undeclared_claim_evidence(tmp_path: Path):
    common = [
        "build",
        "--workspace-root",
        str(tmp_path),
        "--task",
        "t",
        "--out",
        str(tmp_path / "r.json"),
    ]
    with pytest.raises(SystemExit, match="unique"):
        main([*common, "--claim", "a=one", "--claim", "a=two"])
    with pytest.raises(SystemExit, match="undeclared"):
        main([*common, "--claim", "a=one", "--file-exists", "b=x"])
    with pytest.raises(SystemExit, match="expected"):
        main([*common, "--claim", "a=one", "--file-exists", "not-valid"])


def test_save_load_content_digest_name(tmp_path: Path):
    artifact = tmp_path / "a.txt"
    artifact.write_text("x", encoding="utf-8")
    receipt = _receipt(tmp_path, evidence_path_exists(artifact, workspace_root=tmp_path))
    path = tmp_path / "receipt.json"
    save_receipt(receipt, path)
    data = json.loads(path.read_text())
    assert "content_digest" in data and "receipt_sha256" not in data


def test_load_rejects_duplicate_json_keys(tmp_path: Path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema":"one","schema":"two"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_receipt(path)


def test_cli_reports_invalid_json_without_traceback(tmp_path: Path):
    path = tmp_path / "broken.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(SystemExit, match="could not read receipt"):
        main(["verify", str(path)])


def test_output_manifest_is_canonical_sorted_and_excludes_control_files(tmp_path: Path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "z.txt").write_bytes(b"last")
    (tmp_path / "nested" / "a.txt").write_bytes(b"first")
    (tmp_path / "receipt.json").write_text("controller receipt", encoding="utf-8")
    (tmp_path / "OUTPUT_MANIFEST.json").write_text("old manifest", encoding="utf-8")

    manifest, digest = create_output_manifest(tmp_path)

    assert [entry["path"] for entry in manifest["files"]] == ["nested/a.txt", "z.txt"]
    assert manifest["file_count"] == 2
    assert manifest["total_bytes"] == 9
    assert digest == manifest_digest(dict(reversed(list(manifest.items()))))
    save_output_manifest(manifest, tmp_path / "OUTPUT_MANIFEST.json")
    loaded = load_output_manifest(tmp_path / "OUTPUT_MANIFEST.json")
    assert loaded == manifest
    result = verify_output_manifest(loaded, tmp_path)
    assert result["ok"] is True
    assert result["digest"] == digest
    assert result["files"] == 2


def test_output_manifest_detects_mutation(tmp_path: Path):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("before", encoding="utf-8")
    manifest, _ = create_output_manifest(tmp_path)

    artifact.write_text("after", encoding="utf-8")
    result = verify_output_manifest(manifest, tmp_path)

    assert result["ok"] is False
    assert result["differences"]["changed"] == ["artifact.txt"]
    assert result["errors"] == ["changed files: 1"]


def test_output_manifest_detects_extra_and_missing_files(tmp_path: Path):
    expected = tmp_path / "expected.txt"
    expected.write_text("expected", encoding="utf-8")
    manifest, _ = create_output_manifest(tmp_path)

    expected.unlink()
    (tmp_path / "extra.txt").write_text("extra", encoding="utf-8")
    result = verify_output_manifest(manifest, tmp_path)

    assert result["ok"] is False
    assert result["differences"]["missing"] == ["expected.txt"]
    assert result["differences"]["unexpected"] == ["extra.txt"]


def test_output_manifest_rejects_symlinks(tmp_path: Path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        (tmp_path / "link.txt").symlink_to(outside)
        with pytest.raises(OutputManifestError, match="symbolic links"):
            create_output_manifest(tmp_path)
    finally:
        outside.unlink(missing_ok=True)


def test_output_manifest_rejects_hardlinks(tmp_path: Path):
    original = tmp_path / "original.txt"
    original.write_text("same inode", encoding="utf-8")
    os.link(original, tmp_path / "hardlink.txt")

    with pytest.raises(OutputManifestError, match="hard-linked"):
        create_output_manifest(tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable on this platform")
def test_output_manifest_rejects_special_files_without_blocking(tmp_path: Path):
    os.mkfifo(tmp_path / "pipe")

    with pytest.raises(OutputManifestError, match="special filesystem"):
        create_output_manifest(tmp_path)


def test_output_manifest_enforces_file_and_byte_bounds(tmp_path: Path, monkeypatch):
    (tmp_path / "one.txt").write_bytes(b"1")
    (tmp_path / "two.txt").write_bytes(b"2")
    monkeypatch.setattr(output_manifest, "MAX_FILES", 1)
    with pytest.raises(OutputManifestError, match="file limit"):
        create_output_manifest(tmp_path)

    monkeypatch.setattr(output_manifest, "MAX_FILES", 10)
    monkeypatch.setattr(output_manifest, "MAX_FILE_BYTES", 0)
    with pytest.raises(OutputManifestError, match="per-file byte limit"):
        create_output_manifest(tmp_path)


def test_output_manifest_load_rejects_duplicate_json_keys(tmp_path: Path):
    path = tmp_path / "manifest.json"
    path.write_text(
        '{"schema":"agent-output-manifest/v1","schema":"forged",'
        '"file_count":0,"total_bytes":0,"files":[]}',
        encoding="utf-8",
    )

    with pytest.raises(OutputManifestError, match="duplicate JSON key"):
        load_output_manifest(path)


def test_output_manifest_load_rejects_oversized_json_integer(tmp_path: Path):
    path = tmp_path / "manifest.json"
    path.write_text(
        '{"schema":"agent-output-manifest/v1","file_count":'
        + ("9" * 5_000)
        + ',"total_bytes":0,"files":[]}',
        encoding="utf-8",
    )

    with pytest.raises(OutputManifestError, match="digit limit"):
        load_output_manifest(path)


def test_output_manifest_rejects_path_swap_during_open(tmp_path: Path, monkeypatch):
    victim = tmp_path / "victim.txt"
    victim.write_text("first inode", encoding="utf-8")
    replacement = tmp_path.parent / f"{tmp_path.name}-replacement.txt"
    replacement.write_text("second inode", encoding="utf-8")
    real_open = output_manifest.os.open
    swapped = False

    def racing_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if path == "victim.txt" and kwargs.get("dir_fd") is not None and not swapped:
            swapped = True
            victim.unlink()
            replacement.rename(victim)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(output_manifest.os, "open", racing_open)
    try:
        with pytest.raises(OutputManifestError, match="path changed"):
            create_output_manifest(tmp_path)
    finally:
        replacement.unlink(missing_ok=True)


def test_output_manifest_rejects_content_change_after_hash(tmp_path: Path, monkeypatch):
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("hashed contents", encoding="utf-8")
    real_hash = output_manifest._hash_regular_file
    changed = False

    def racing_hash(*args, **kwargs):
        nonlocal changed
        result = real_hash(*args, **kwargs)
        if not changed:
            changed = True
            artifact.write_text("changed after hash", encoding="utf-8")
        return result

    monkeypatch.setattr(output_manifest, "_hash_regular_file", racing_hash)
    with pytest.raises(OutputManifestError, match="file changed"):
        create_output_manifest(tmp_path)


def test_output_manifest_requires_two_identical_scans(tmp_path: Path, monkeypatch):
    (tmp_path / "first.txt").write_text("first", encoding="utf-8")
    real_scan = output_manifest._scan_workspace_once
    scans = 0

    def racing_scan(*args, **kwargs):
        nonlocal scans
        result = real_scan(*args, **kwargs)
        scans += 1
        if scans == 1:
            (tmp_path / "late.txt").write_text("late", encoding="utf-8")
        return result

    monkeypatch.setattr(output_manifest, "_scan_workspace_once", racing_scan)
    with pytest.raises(OutputManifestError, match="consecutive scans"):
        create_output_manifest(tmp_path)


def test_output_manifest_cli_create_and_verify_json(tmp_path: Path, capsys):
    (tmp_path / "result.txt").write_text("ready", encoding="utf-8")
    output = tmp_path / "custom-manifest.json"

    assert (
        main(
            [
                "manifest",
                "create",
                "--workspace-root",
                str(tmp_path),
                "--out",
                str(output),
                "--json",
            ]
        )
        == 0
    )
    created = json.loads(capsys.readouterr().out)
    assert created["ok"] is True
    assert created["files"] == 1

    assert (
        main(
            [
                "manifest",
                "verify",
                str(output),
                "--workspace-root",
                str(tmp_path),
                "--expected-digest",
                created["digest"],
                "--json",
            ]
        )
        == 0
    )
    verified = json.loads(capsys.readouterr().out)
    assert verified["ok"] is True
    assert verified["digest"] == created["digest"]


def test_output_manifest_cli_json_failure_is_clean(tmp_path: Path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")

    assert (
        main(
            [
                "manifest",
                "verify",
                str(path),
                "--workspace-root",
                str(tmp_path),
                "--json",
            ]
        )
        == 1
    )
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert "invalid output manifest JSON" in result["error"]


def test_output_manifest_cli_digest_mismatch_fails_before_scan(tmp_path: Path, capsys, monkeypatch):
    (tmp_path / "result.txt").write_text("ready", encoding="utf-8")
    manifest, _ = create_output_manifest(tmp_path)
    path = tmp_path / "custom-manifest.json"
    save_output_manifest(manifest, path)

    def forbidden_scan(*args, **kwargs):
        raise AssertionError("workspace must not be scanned after a trusted-digest mismatch")

    monkeypatch.setattr(output_manifest, "_scan_workspace", forbidden_scan)
    assert (
        main(
            [
                "manifest",
                "verify",
                str(path),
                "--workspace-root",
                str(tmp_path),
                "--expected-digest",
                "0" * 64,
                "--json",
            ]
        )
        == 1
    )
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert result["errors"] == ["manifest digest does not match trusted digest"]
