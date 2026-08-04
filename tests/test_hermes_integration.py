from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agent_packet.builder import materialize_packet
from agent_receipt.core import Claim, Evidence, build_receipt, evidence_file_hash, save_receipt
from agent_receipt.output_manifest import create_output_manifest, save_output_manifest
from hermes_integration import register
from hermes_integration.bootstrap import ensure_repo_local_core
from hermes_integration.cli import handle_cli, setup_cli
from hermes_integration.core import TrustError, TrustRuntime


@dataclass
class RegisteredTool:
    name: str
    toolset: str
    schema: dict[str, Any]
    handler: Any
    check_fn: Any
    description: str


class FakeContext:
    def __init__(self) -> None:
        self.tools: dict[str, RegisteredTool] = {}
        self.hooks: dict[str, Any] = {}
        self.cli: dict[str, Any] = {}

    def register_tool(self, **kwargs: Any) -> None:
        self.tools[kwargs["name"]] = RegisteredTool(
            name=kwargs["name"],
            toolset=kwargs["toolset"],
            schema=kwargs["schema"],
            handler=kwargs["handler"],
            check_fn=kwargs.get("check_fn"),
            description=kwargs["description"],
        )

    def register_hook(self, name: str, callback: Any) -> None:
        self.hooks[name] = callback

    def register_cli_command(self, **kwargs: Any) -> None:
        self.cli[kwargs["name"]] = kwargs


def _run_git(root: Path, *args: str) -> str:
    executable = shutil.which("git")
    assert executable is not None
    result = subprocess.run(
        [executable, "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    _run_git(root, "init", "-q")
    _run_git(root, "config", "user.name", "Agent Trust Test")
    _run_git(root, "config", "user.email", "agent-trust@example.invalid")
    _run_git(root, "config", "commit.gpgSign", "false")
    (root / "README.md").write_text("# Public fixture\n", encoding="utf-8")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("print('safe')\n", encoding="utf-8")
    _run_git(root, "add", "README.md", "src/app.py")
    _run_git(root, "commit", "-qm", "fixture")
    return root


def _runtime_and_project(tmp_path: Path) -> tuple[TrustRuntime, Path]:
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir(mode=0o700)
    project = _project(tmp_path)
    runtime = TrustRuntime(hermes_home)
    runtime.add_project("fixture", project, [])
    return runtime, project


def _prepare(runtime: TrustRuntime) -> dict[str, Any]:
    return runtime.prepare(
        {
            "project_id": "fixture",
            "task": "Review the public fixture and return a short result.",
            "include": ["README.md", "src/app.py"],
        }
    )


def _materialize_approved_return(runtime: TrustRuntime, handoff_id: str) -> tuple[Path, dict]:
    approval = runtime.approve(handoff_id)
    destination = runtime.return_path(handoff_id)
    materialize_packet(
        Path(approval["packet_path"]),
        destination,
        expect_sha256=approval["packet_digest"],
    )
    (destination / "RESULT.md").write_text("Review completed safely.\n", encoding="utf-8")
    state, _directory = runtime._state(handoff_id)
    return destination, state


def _write_manifest_and_receipt(
    return_root: Path,
    state: dict[str, Any],
    *,
    command_evidence: bool = False,
) -> Path | None:
    manifest, manifest_digest = create_output_manifest(return_root)
    save_output_manifest(manifest, return_root / "OUTPUT_MANIFEST.json")
    marker = return_root / "COMMAND_RAN"
    if command_evidence:
        empty_digest = hashlib.sha256(b"").hexdigest()
        evidence = Evidence(
            kind="command",
            detail={
                "cmd": ["/bin/sh", "-c", f"touch {marker}"],
                "expect_exit": 0,
                "stdout_contains": None,
                "timeout": 5,
            },
            ok=True,
            observed={
                "exit_code": 0,
                "stdout_sha256": empty_digest,
                "stderr_sha256": empty_digest,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
                "output_truncated": False,
                "stdout_contains_matched": True,
            },
        )
    else:
        evidence = evidence_file_hash(return_root / "RESULT.md", workspace_root=return_root)
    receipt = build_receipt(
        agent="synthetic-worker",
        task="Return a reviewed fixture.",
        claims=[Claim(id="result", statement="A result was returned.", evidence=[evidence])],
        workspace_root=return_root,
        context={
            "packet_digest": state["packet_digest"],
            "input_commit": state["input_commit"],
            "output_manifest_digest": manifest_digest,
        },
    )
    save_receipt(receipt, return_root / "receipt.json")
    return marker if command_evidence else None


def test_register_exposes_only_controller_tools_and_operator_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir()
    monkeypatch.setitem(
        sys.modules,
        "hermes_constants",
        SimpleNamespace(get_hermes_home=lambda: hermes_home),
    )
    context = FakeContext()

    register(context)

    assert set(context.tools) == {
        "handoff_prepare",
        "handoff_status",
        "handoff_verify_return",
    }
    assert {tool.toolset for tool in context.tools.values()} == {"agent_handoff"}
    assert set(context.hooks) == {"pre_tool_call"}
    assert set(context.cli) == {"agent-trust"}
    assert all(tool.check_fn is None for tool in context.tools.values())
    manifest = (Path(__file__).parents[1] / "plugin.yaml").read_text(encoding="utf-8")
    assert all(name in manifest for name in context.tools)
    assert "materialize" not in context.tools and "transport" not in context.tools
    with pytest.raises(SystemExit) as exit_info:
        context.cli["agent-trust"]["handler_fn"](SimpleNamespace(agent_trust_command=None))
    assert exit_info.value.code == 2


def test_plugin_loads_only_repo_local_core_modules() -> None:
    repo = Path(__file__).parents[1].resolve()
    origins = ensure_repo_local_core()

    assert origins["agent_packet"].is_relative_to(repo / "packages" / "agent-packet" / "src")
    assert origins["agent_receipt"].is_relative_to(repo / "packages" / "agent-receipt" / "src")


def test_project_registration_requires_exact_clean_git_root(tmp_path: Path) -> None:
    runtime, project = _runtime_and_project(tmp_path)
    assert runtime.list_projects()[0]["project_id"] == "fixture"

    (project / "dirty.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(TrustError, match="Commit or remove"):
        runtime.add_project("dirty", project, [])
    with pytest.raises(TrustError, match="top-level"):
        runtime.add_project("nested", project / "src", [])
    with pytest.raises(TrustError, match="overlaps"):
        runtime.add_project("home", tmp_path, [])


def test_prepare_uses_explicit_safe_defaults_and_hides_private_paths(tmp_path: Path) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)

    result = _prepare(runtime)

    assert result["status"] == "prepared"
    assert result["transported"] is False
    assert result["operator_review_required"] is True
    assert result["files"] == ["README.md", "src/app.py"]
    assert str(runtime.root) not in json.dumps(result)
    state, handoff_dir = runtime._state(result["handoff_id"])
    assert state["include"] == ["README.md", "src/app.py"]
    assert (handoff_dir / "packet" / "packet.tar.gz").is_file()
    assert stat_mode(handoff_dir) == 0o700
    assert stat_mode(handoff_dir / "state.json") == 0o600


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_prepare_fails_closed_on_denied_or_whole_project_input(tmp_path: Path) -> None:
    runtime, project = _runtime_and_project(tmp_path)
    (project / ".env").write_text("PUBLIC_NAME=fixture\n", encoding="utf-8")
    _run_git(project, "add", ".env")
    _run_git(project, "commit", "-qm", "add denied fixture")

    before = {path.name for path in runtime.handoffs_root.iterdir()}
    with pytest.raises(TrustError, match="whole-project"):
        runtime.prepare({"project_id": "fixture", "task": "x", "include": ["."]})
    with pytest.raises(TrustError, match="blocked"):
        runtime.prepare({"project_id": "fixture", "task": "x", "include": [".env"]})
    after = {path.name for path in runtime.handoffs_root.iterdir()}
    assert after == before


def test_prepare_rejects_ignored_file_not_present_at_input_commit(tmp_path: Path) -> None:
    runtime, project = _runtime_and_project(tmp_path)
    (project / ".gitignore").write_text("build/\n", encoding="utf-8")
    _run_git(project, "add", ".gitignore")
    _run_git(project, "commit", "-qm", "ignore build output")
    (project / "build").mkdir()
    (project / "build" / "cache.txt").write_text("not committed\n", encoding="utf-8")
    assert not _run_git(project, "status", "--porcelain=v1")

    with pytest.raises(TrustError, match="recorded commit"):
        runtime.prepare(
            {
                "project_id": "fixture",
                "task": "Return the selected cache file.",
                "include": ["build/cache.txt"],
            }
        )

    assert not list(runtime.handoffs_root.iterdir())


def test_model_handler_returns_bounded_error_without_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir()
    monkeypatch.setitem(
        sys.modules,
        "hermes_constants",
        SimpleNamespace(get_hermes_home=lambda: hermes_home),
    )
    context = FakeContext()
    register(context)

    raw = context.tools["handoff_prepare"].handler(
        {"project_id": "missing", "task": "safe task", "include": ["README.md"]}
    )
    result = json.loads(raw)

    assert result["ok"] is False
    assert result["error"] == "project_not_registered"
    assert "Traceback" not in raw and len(raw) < 1_024


def test_operator_approval_is_required_before_return_path(tmp_path: Path) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    prepared = _prepare(runtime)

    with pytest.raises(TrustError, match="Approve"):
        runtime.return_path(prepared["handoff_id"])
    approved = runtime.approve(prepared["handoff_id"])

    assert approved["status"] == "approved"
    assert Path(approved["packet_path"]).is_file()
    assert runtime.return_path(prepared["handoff_id"]).name == "return"
    assert not runtime.return_path(prepared["handoff_id"]).exists()


def test_operator_review_binds_packet_and_exposes_only_fixed_local_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    prepared = _prepare(runtime)
    parser = argparse.ArgumentParser()
    setup_cli(parser)

    args = parser.parse_args(["review", prepared["handoff_id"]])
    assert handle_cli(args, runtime) == 0
    result = json.loads(capsys.readouterr().out)

    assert result["status"] == "prepared"
    assert result["task"] == "Review the public fixture and return a short result."
    assert result["include"] == ["README.md", "src/app.py"]
    assert result["files"] == ["README.md", "src/app.py"]
    assert result["structural_validation"] == "passed"
    assert result["state_binding"] == "passed"
    assert set(result["paths"]) == {"packet", "digest", "manifest", "payload", "task"}
    assert all(
        Path(value).resolve(strict=True).is_relative_to(runtime.root)
        for value in result["paths"].values()
    )
    state, _directory = runtime._state(prepared["handoff_id"])
    assert state["status"] == "prepared" and state["approval"] is None


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("task", "A different but still bounded task."),
        ("include", ["README.md"]),
        ("files", ["README.md"]),
    ],
)
def test_operator_review_rejects_packet_state_mismatch(
    tmp_path: Path, field: str, replacement: Any
) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    prepared = _prepare(runtime)
    state, directory = runtime._state(prepared["handoff_id"])
    state[field] = replacement
    runtime._write_json(directory / "state.json", state)

    with pytest.raises(TrustError) as error:
        runtime.review(prepared["handoff_id"])

    assert error.value.code == "packet_state_mismatch"


def test_operator_review_and_approval_fail_closed_on_packet_tampering(tmp_path: Path) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    prepared = _prepare(runtime)
    replacement = _prepare(runtime)
    _state, directory = runtime._state(prepared["handoff_id"])
    _replacement_state, replacement_directory = runtime._state(replacement["handoff_id"])
    shutil.copyfile(
        replacement_directory / "packet" / "packet.tar.gz",
        directory / "packet" / "packet.tar.gz",
    )

    with pytest.raises(TrustError) as review_error:
        runtime.review(prepared["handoff_id"])
    with pytest.raises(TrustError) as approval_error:
        runtime.approve(prepared["handoff_id"])

    assert review_error.value.code == "packet_digest_mismatch"
    assert approval_error.value.code == "packet_digest_mismatch"
    assert runtime.status({"handoff_id": prepared["handoff_id"]})["status"] == "prepared"


def test_operator_review_rejects_mismatched_local_inspection_payload(tmp_path: Path) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    prepared = _prepare(runtime)
    _state, directory = runtime._state(prepared["handoff_id"])
    (directory / "packet" / "payload" / "README.md").write_text(
        "different local inspection copy\n", encoding="utf-8"
    )

    with pytest.raises(TrustError) as error:
        runtime.review(prepared["handoff_id"])

    assert error.value.code == "packet_artifact_mismatch"


@pytest.mark.parametrize(
    "tamper",
    [
        "manifest",
        "digest",
        "payload_symlink",
        "payload_hardlink",
        "payload_extra_file",
        "payload_fifo",
        "payload_directory_symlink",
    ],
)
def test_operator_review_and_approval_reject_local_artifact_tampering(
    tmp_path: Path, tamper: str
) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    prepared = _prepare(runtime)
    _state, directory = runtime._state(prepared["handoff_id"])
    packet_root = directory / "packet"
    payload_root = packet_root / "payload"

    if tamper == "manifest":
        (packet_root / "manifest.json").write_text("{}\n", encoding="utf-8")
    elif tamper == "digest":
        (packet_root / "PACKET_SHA256.txt").write_text(
            f"{'0' * 64}  packet.tar.gz\n", encoding="ascii"
        )
    elif tamper == "payload_symlink":
        target = payload_root / "README.md"
        target.unlink()
        target.symlink_to(tmp_path / "project" / "README.md")
    elif tamper == "payload_hardlink":
        replacement = tmp_path / "hardlink-source.txt"
        replacement.write_text("# Public fixture\n", encoding="utf-8")
        target = payload_root / "README.md"
        target.unlink()
        os.link(replacement, target)
    elif tamper == "payload_extra_file":
        (payload_root / "EXTRA.md").write_text("extra\n", encoding="utf-8")
    elif tamper == "payload_fifo":
        target = payload_root / "README.md"
        target.unlink()
        os.mkfifo(target)
    elif tamper == "payload_directory_symlink":
        target = payload_root / "src"
        shutil.rmtree(target)
        target.symlink_to(tmp_path / "project" / "src", target_is_directory=True)
    else:  # pragma: no cover - the parameter list is closed above
        raise AssertionError(f"unknown tamper case: {tamper}")

    with pytest.raises(TrustError) as review_error:
        runtime.review(prepared["handoff_id"])
    with pytest.raises(TrustError) as approval_error:
        runtime.approve(prepared["handoff_id"])

    assert review_error.value.code == "packet_artifact_mismatch"
    assert approval_error.value.code == "packet_artifact_mismatch"
    assert runtime.status({"handoff_id": prepared["handoff_id"]})["status"] == "prepared"


def test_return_verification_binds_packet_commit_and_exact_output(tmp_path: Path) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    prepared = _prepare(runtime)
    return_root, state = _materialize_approved_return(runtime, prepared["handoff_id"])
    _write_manifest_and_receipt(return_root, state)

    result = runtime.verify_return({"handoff_id": prepared["handoff_id"]})

    assert result["verified"] is True
    assert result["status"] == "verified"
    assert result["commands_executed"] == 0
    assert result["merge_performed"] is False
    assert result["verification"]["assurance"] == "fully_rechecked"
    state, directory = runtime._state(prepared["handoff_id"])
    snapshot = directory / "verified-snapshot"
    assert runtime.verified_path(prepared["handoff_id"]) == snapshot
    with pytest.raises(TrustError, match="verified-path"):
        runtime.return_path(prepared["handoff_id"])
    assert stat_mode(snapshot) == 0o500
    assert stat_mode(snapshot / "RESULT.md") == 0o400

    (return_root / "RESULT.md").write_text("untrusted later mutation\n", encoding="utf-8")
    assert runtime.status({"handoff_id": prepared["handoff_id"]})["status"] == "verified"

    snap_result = snapshot / "RESULT.md"
    snap_result.chmod(0o600)
    snap_result.write_text("snapshot tampered\n", encoding="utf-8")
    with pytest.raises(TrustError, match="snapshot"):
        runtime.status({"handoff_id": prepared["handoff_id"]})
    assert state["verification"]["files"] > 0


def test_concurrent_rejection_cannot_overwrite_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    prepared = _prepare(runtime)
    return_root, state = _materialize_approved_return(runtime, prepared["handoff_id"])
    _write_manifest_and_receipt(return_root, state)

    snapshot_started = threading.Event()
    release_snapshot = threading.Event()
    original_snapshot = runtime._snapshot_return

    def paused_snapshot(*args: Any, **kwargs: Any) -> str:
        snapshot_started.set()
        assert release_snapshot.wait(timeout=10)
        return original_snapshot(*args, **kwargs)

    monkeypatch.setattr(runtime, "_snapshot_return", paused_snapshot)
    verification_results: list[dict[str, Any]] = []
    verification_errors: list[BaseException] = []

    def verify() -> None:
        try:
            verification_results.append(
                runtime.verify_return({"handoff_id": prepared["handoff_id"]})
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            verification_errors.append(exc)

    verifier = threading.Thread(target=verify, daemon=True)
    verifier.start()
    assert snapshot_started.wait(timeout=10)

    child_code = """
import sys
from pathlib import Path
from hermes_integration.core import TrustError, TrustRuntime

runtime = TrustRuntime(Path(sys.argv[1]))
print("ready", flush=True)
try:
    runtime.reject(sys.argv[2])
except TrustError as exc:
    print(exc.code, flush=True)
    raise SystemExit(7)
print("rejected", flush=True)
"""
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            child_code,
            str(runtime.hermes_home),
            prepared["handoff_id"],
        ],
        cwd=Path(__file__).parents[1],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    assert process.stdout.readline().strip() == "ready"
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            process.wait(timeout=0.25)
    finally:
        release_snapshot.set()

    verifier.join(timeout=10)
    assert not verifier.is_alive()
    stdout, stderr = process.communicate(timeout=10)
    assert verification_errors == []
    assert verification_results[0]["status"] == "verified"
    assert process.returncode == 7
    assert stdout.strip() == "invalid_transition"
    assert stderr == ""
    assert runtime.status({"handoff_id": prepared["handoff_id"]})["status"] == "verified"


def test_return_verification_detects_extra_file(tmp_path: Path) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    prepared = _prepare(runtime)
    return_root, state = _materialize_approved_return(runtime, prepared["handoff_id"])
    _write_manifest_and_receipt(return_root, state)
    (return_root / "unexpected.txt").write_text("late change\n", encoding="utf-8")

    with pytest.raises(TrustError, match="exactly match"):
        runtime.verify_return({"handoff_id": prepared["handoff_id"]})


def test_return_verification_never_executes_command_evidence(tmp_path: Path) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    prepared = _prepare(runtime)
    return_root, state = _materialize_approved_return(runtime, prepared["handoff_id"])
    marker = _write_manifest_and_receipt(return_root, state, command_evidence=True)
    assert marker is not None and not marker.exists()

    with pytest.raises(TrustError, match="assurance"):
        runtime.verify_return({"handoff_id": prepared["handoff_id"]})

    assert not marker.exists()


def test_return_verification_rejects_empty_output_manifest(tmp_path: Path) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    prepared = _prepare(runtime)
    runtime.approve(prepared["handoff_id"])
    return_root = runtime.return_path(prepared["handoff_id"])
    return_root.mkdir()
    state, _directory = runtime._state(prepared["handoff_id"])
    manifest, manifest_digest = create_output_manifest(return_root)
    assert manifest["file_count"] == 0
    save_output_manifest(manifest, return_root / "OUTPUT_MANIFEST.json")
    evidence = Evidence(
        kind="path_exists",
        detail={"path": "receipt.json", "must_be_file": True},
        ok=True,
        observed={"exists": True, "is_file": True, "is_dir": False},
    )
    receipt = build_receipt(
        agent="synthetic-worker",
        task="Return nothing.",
        claims=[Claim(id="empty", statement="Receipt exists.", evidence=[evidence])],
        workspace_root=return_root,
        context={
            "packet_digest": state["packet_digest"],
            "input_commit": state["input_commit"],
            "output_manifest_digest": manifest_digest,
        },
    )
    save_receipt(receipt, return_root / "receipt.json")

    with pytest.raises(TrustError, match="non-empty"):
        runtime.verify_return({"handoff_id": prepared["handoff_id"]})


def test_return_receipt_cannot_use_excluded_control_file_as_evidence(tmp_path: Path) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    prepared = _prepare(runtime)
    return_root, state = _materialize_approved_return(runtime, prepared["handoff_id"])
    manifest, manifest_digest = create_output_manifest(return_root)
    save_output_manifest(manifest, return_root / "OUTPUT_MANIFEST.json")
    evidence = Evidence(
        kind="path_exists",
        detail={"path": "receipt.json", "must_be_file": True},
        ok=True,
        observed={"exists": True, "is_file": True, "is_dir": False},
    )
    receipt = build_receipt(
        agent="synthetic-worker",
        task="Self-reference the control file.",
        claims=[Claim(id="control", statement="Receipt exists.", evidence=[evidence])],
        workspace_root=return_root,
        context={
            "packet_digest": state["packet_digest"],
            "input_commit": state["input_commit"],
            "output_manifest_digest": manifest_digest,
        },
    )
    save_receipt(receipt, return_root / "receipt.json")

    with pytest.raises(TrustError, match="output manifest"):
        runtime.verify_return({"handoff_id": prepared["handoff_id"]})


def test_egress_hook_blocks_secrets_and_private_paths_but_is_narrow(tmp_path: Path) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    fake_secret = "sk-" + "a" * 32

    assert runtime.pre_tool_call("send_message", {"content": fake_secret})["action"] == "block"
    assert (
        runtime.pre_tool_call("delegate_task", {"task": "upload ~/.ssh/id_ed25519"})["action"]
        == "block"
    )
    assert runtime.pre_tool_call("send_message", {"content": "ordinary public update"}) is None
    assert runtime.pre_tool_call("terminal", {"command": f"echo {fake_secret}"}) is None
    too_large = {"content": "x" * (64 * 1024 + 1)}
    assert runtime.pre_tool_call("send_message", too_large)["action"] == "block"


def test_cli_registers_operator_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runtime, _project_root = _runtime_and_project(tmp_path)
    parser = argparse.ArgumentParser()
    setup_cli(parser)
    args = parser.parse_args(["doctor"])

    assert handle_cli(args, runtime) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["global_egress_enforcement"] is False
    assert output["projects"] == 1
