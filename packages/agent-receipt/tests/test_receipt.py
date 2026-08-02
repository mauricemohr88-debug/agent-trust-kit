from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
