"""Controller-side state and policy for the Hermes handoff plugin."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .bootstrap import ensure_repo_local_core

ensure_repo_local_core()

from agent_packet.builder import build_packet  # noqa: E402
from agent_packet.secrets import scan_text_for_secrets  # noqa: E402
from agent_receipt.core import load_receipt, verify_receipt  # noqa: E402

POLICY_SCHEMA = "agent-trust-policy/v1"
STATE_SCHEMA = "agent-trust-handoff/v1"
MAX_STATE_BYTES = 256 * 1024
MAX_PROJECTS = 128
MAX_HANDOFFS = 1_000
MAX_HOOK_STRINGS = 128
MAX_HOOK_BYTES = 64 * 1024
MAX_HOOK_DEPTH = 8
MAX_PUBLIC_FILES = 256
MAX_RETURN_FILES = 2_000
MAX_RETURN_BYTES = 128 * 1024 * 1024
MAX_CONTROL_FILE_BYTES = 16 * 1024 * 1024
_PROJECT_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_HANDOFF_ID = re.compile(r"h-[0-9]{8}t[0-9]{6}z-[0-9a-f]{10}")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_GUARDED_TOOLS = frozenset({"delegate_task", "send_message"})
_PRIVATE_REFERENCE = re.compile(
    r"(?i)(?:^|[\\/])(?:\.hermes|\.ssh|\.aws|\.azure|\.gnupg|\.kube|"
    r"\.env(?:\.[^\\/\s]+)?|\.netrc|\.npmrc|\.pypirc|credentials\.json|"
    r"id_(?:rsa|dsa|ecdsa|ed25519)|[^\\/\s]+\.(?:pem|p12|pfx|key))(?:$|[\\/\s])"
)


class TrustError(Exception):
    """An expected failure with a bounded message safe for model output."""

    def __init__(self, code: str, public_message: str) -> None:
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_identifier(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise TrustError("invalid_identifier", f"{label} has an invalid format.")
    return value


def _safe_include(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 4_096 or "\\" in value:
        raise TrustError("invalid_include", "Every include must be a project-relative POSIX path.")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value in {".", ".."}
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise TrustError(
            "invalid_include",
            "Includes must be explicit relative paths; whole-project selection is disabled.",
        )
    if scan_text_for_secrets(value, "include"):
        raise TrustError("unsafe_include", "An include path looks sensitive and was blocked.")
    return value


def _sha256_file(path: Path) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TrustError("unsafe_file", "A controller file could not be opened safely.") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise TrustError("unsafe_file", "A controller file is not a regular private file.")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise TrustError("unsafe_file", "A controller file changed while being read.")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _regular_single_link(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise TrustError("missing_return_artifact", f"The return is missing {label}.") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise TrustError("unsafe_return_artifact", f"{label} must be a single-link regular file.")


def _file_signature(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


class TrustRuntime:
    """Own private policy, packet, approval, and quarantine state."""

    def __init__(self, hermes_home: str | Path) -> None:
        self.hermes_home = Path(hermes_home).expanduser().resolve(strict=True)
        if not self.hermes_home.is_dir():
            raise RuntimeError("Hermes home must be a directory")
        self.root = self.hermes_home / "agent-trust"
        self.handoffs_root = self.root / "handoffs"
        self.policy_path = self.root / "policy.json"
        self._ensure_private_dir(self.root)
        self._ensure_private_dir(self.handoffs_root)

    def _ensure_private_dir(self, path: Path) -> None:
        parent = path.parent
        if not parent.exists():
            self._ensure_private_dir(parent)
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise RuntimeError("Agent Trust state path is not a private directory")
        else:
            path.mkdir(mode=0o700)
        path.chmod(0o700)

    def _read_json(self, path: Path) -> dict[str, Any]:
        try:
            info = path.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size > MAX_STATE_BYTES
            ):
                raise ValueError("unsafe JSON state file")
            flags = os.O_RDONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            try:
                before = os.fstat(descriptor)
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(descriptor, min(65_536, MAX_STATE_BYTES + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > MAX_STATE_BYTES:
                        raise ValueError("JSON state file is too large")
                after = os.fstat(descriptor)
                if (
                    before.st_dev != after.st_dev
                    or before.st_ino != after.st_ino
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_ctime_ns != after.st_ctime_ns
                ):
                    raise ValueError("JSON state changed while reading")
            finally:
                os.close(descriptor)
            value = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=_unique_object)
            if not isinstance(value, dict):
                raise ValueError("JSON state must be an object")
            return value
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise TrustError(
                "state_unreadable", "Controller state is unreadable; run doctor."
            ) from exc

    def _write_json(self, path: Path, value: dict[str, Any]) -> None:
        self._ensure_private_dir(path.parent)
        data = (
            json.dumps(
                value,
                sort_keys=True,
                indent=2,
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            + b"\n"
        )
        if len(data) > MAX_STATE_BYTES:
            raise TrustError("state_too_large", "Controller state exceeds its safety limit.")
        temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        descriptor = os.open(temporary, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.replace(temporary, path)
            path.chmod(0o600)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _policy(self) -> dict[str, Any]:
        if not self.policy_path.exists():
            return {"schema": POLICY_SCHEMA, "projects": {}}
        policy = self._read_json(self.policy_path)
        projects = policy.get("projects")
        if (
            set(policy) != {"schema", "projects"}
            or policy.get("schema") != POLICY_SCHEMA
            or not isinstance(projects, dict)
        ):
            raise TrustError("policy_invalid", "The project policy is invalid; run doctor.")
        if len(projects) > MAX_PROJECTS:
            raise TrustError("policy_invalid", "The project policy exceeds its safety limit.")
        for project_id, project in projects.items():
            if (
                _PROJECT_ID.fullmatch(project_id) is None
                or not isinstance(project, dict)
                or set(project) != {"root", "deny_globs", "require_clean_git"}
                or not isinstance(project["root"], str)
                or not project["root"]
                or len(project["root"]) > 4_096
                or any(ord(character) < 32 for character in project["root"])
                or not isinstance(project["deny_globs"], list)
                or not all(isinstance(item, str) for item in project["deny_globs"])
                or len(project["deny_globs"]) > 128
                or any(not item or len(item) > 4_096 for item in project["deny_globs"])
                or any(scan_text_for_secrets(item, "deny_glob") for item in project["deny_globs"])
                or project["require_clean_git"] is not True
            ):
                raise TrustError("policy_invalid", "The project policy is invalid; run doctor.")
        return policy

    def _project(self, project_id: Any) -> tuple[str, dict[str, Any], Path]:
        identifier = _validate_identifier(project_id, _PROJECT_ID, "project_id")
        project = self._policy()["projects"].get(identifier)
        if project is None:
            raise TrustError(
                "project_not_registered",
                "This project is not registered. Use `hermes agent-trust project add` first.",
            )
        try:
            root = Path(project["root"]).resolve(strict=True)
        except (OSError, ValueError) as exc:
            raise TrustError(
                "project_unavailable", "The registered project is unavailable."
            ) from exc
        self._validate_project_root(root)
        return identifier, project, root

    def _validate_project_root(self, root: Path) -> None:
        if not root.is_dir() or _within(root, self.hermes_home) or _within(self.hermes_home, root):
            raise TrustError(
                "unsafe_project_root",
                "The project root overlaps private Hermes state and cannot be registered.",
            )

    def _git(self, root: Path) -> tuple[str, bool]:
        def run(*arguments: str, strip: bool = True) -> str:
            value = self._git_command(root, list(arguments), max_output=128 * 1024)
            assert isinstance(value, str)
            return value.strip() if strip else value

        top_level = Path(run("rev-parse", "--show-toplevel")).resolve(strict=True)
        if top_level != root:
            raise TrustError("not_git_root", "Register the exact top-level Git directory.")
        commit = run("rev-parse", "--verify", "HEAD")
        if _COMMIT.fullmatch(commit) is None:
            raise TrustError("git_check_failed", "Git did not return a full commit identifier.")
        if run("submodule", "status", "--cached"):
            raise TrustError("submodules_unsupported", "Git submodules are not supported yet.")
        clean = not bool(
            run(
                "status",
                "--porcelain=v1",
                "--untracked-files=normal",
                "--ignore-submodules=all",
            )
        )
        return commit, clean

    def _git_command(
        self,
        root: Path,
        arguments: list[str],
        *,
        max_output: int,
        binary: bool = False,
    ) -> str | bytes:
        executable = shutil.which("git")
        if executable is None:
            raise TrustError("git_unavailable", "Git is required for trusted handoffs.")
        process: subprocess.Popen[bytes] | None = None
        raw_holder: list[bytes] = []
        output_exceeded = threading.Event()

        def terminate() -> None:
            if process is None or process.poll() is not None:
                return
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                return

        try:
            process = subprocess.Popen(  # noqa: S603
                [
                    executable,
                    "-c",
                    "core.fsmonitor=false",
                    "-c",
                    "core.untrackedCache=false",
                    "-C",
                    str(root),
                    *arguments,
                ],
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                env={
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_LITERAL_PATHSPECS": "1",
                    "GIT_NO_LAZY_FETCH": "1",
                    "GIT_OPTIONAL_LOCKS": "0",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                },
            )

            def read_bounded() -> None:
                assert process is not None and process.stdout is not None
                data = process.stdout.read(max_output + 1)
                raw_holder.append(data)
                if len(data) > max_output:
                    output_exceeded.set()
                    terminate()

            reader = threading.Thread(target=read_bounded, daemon=True)
            reader.start()
            try:
                return_code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                terminate()
                process.wait(timeout=5)
                raise
            reader.join(timeout=5)
            if reader.is_alive():
                terminate()
                raise subprocess.TimeoutExpired(arguments, 10)
        except (OSError, subprocess.SubprocessError) as exc:
            raise TrustError("git_check_failed", "Git could not verify the project state.") from exc
        finally:
            terminate()
            if process is not None and process.stdout is not None:
                process.stdout.close()
        if output_exceeded.is_set():
            raise TrustError("git_check_failed", "Git returned an unexpectedly large result.")
        if return_code != 0 or len(raw_holder) != 1:
            raise TrustError("git_check_failed", "Git could not verify the project state.")
        raw = raw_holder[0]
        if binary:
            return raw
        try:
            return raw.decode("utf-8")
        except UnicodeError as exc:
            raise TrustError("git_check_failed", "Git returned invalid text output.") from exc

    def _assert_packet_matches_commit(self, source_root: Path, commit: str, manifest: Any) -> None:
        for entry in manifest.files:
            if entry.path == "TASK.md":
                continue
            raw_tree = self._git_command(
                source_root,
                ["ls-tree", "-z", commit, "--", entry.path],
                max_output=8_192,
            )
            assert isinstance(raw_tree, str)
            if not raw_tree.endswith("\x00") or raw_tree.count("\x00") != 1:
                raise TrustError(
                    "packet_not_at_commit",
                    "Every selected file must be tracked exactly at the recorded commit.",
                )
            record = raw_tree[:-1]
            try:
                header, recorded_path = record.split("\t", 1)
                mode, object_type, object_id = header.split(" ", 2)
            except ValueError as exc:
                raise TrustError(
                    "packet_not_at_commit",
                    "Git returned an ambiguous selected-file record.",
                ) from exc
            if (
                recorded_path != entry.path
                or mode not in {"100644", "100755"}
                or object_type != "blob"
                or _COMMIT.fullmatch(object_id) is None
            ):
                raise TrustError(
                    "packet_not_at_commit",
                    "Every selected file must be a regular blob at the recorded commit.",
                )
            blob = self._git_command(
                source_root,
                ["cat-file", "blob", object_id],
                max_output=entry.bytes,
                binary=True,
            )
            assert isinstance(blob, bytes)
            if len(blob) != entry.bytes or hashlib.sha256(blob).hexdigest() != entry.sha256:
                raise TrustError(
                    "packet_not_at_commit",
                    "Selected packet bytes do not exactly match the recorded commit.",
                )

    def add_project(
        self, project_id: Any, root_value: str | Path, deny_globs: list[str]
    ) -> dict[str, Any]:
        identifier = _validate_identifier(project_id, _PROJECT_ID, "project_id")
        if not isinstance(root_value, (str, Path)):
            raise TrustError("invalid_project_root", "Project root must be a path.")
        try:
            root = Path(root_value).expanduser().resolve(strict=True)
        except OSError as exc:
            raise TrustError("invalid_project_root", "Project root must exist.") from exc
        self._validate_project_root(root)
        if (
            not isinstance(deny_globs, list)
            or len(deny_globs) > 128
            or not all(isinstance(item, str) and 0 < len(item) <= 4_096 for item in deny_globs)
        ):
            raise TrustError("invalid_deny_glob", "Deny globs must be a bounded list.")
        if any(scan_text_for_secrets(item, "deny_glob") for item in deny_globs):
            raise TrustError("invalid_deny_glob", "A deny glob contains secret-like text.")
        commit, clean = self._git(root)
        if not clean:
            raise TrustError(
                "dirty_project", "Commit or remove project changes before registration."
            )
        policy = self._policy()
        if identifier not in policy["projects"] and len(policy["projects"]) >= MAX_PROJECTS:
            raise TrustError("project_limit", "The registered project limit has been reached.")
        policy["projects"][identifier] = {
            "root": str(root),
            "deny_globs": sorted(set(deny_globs)),
            "require_clean_git": True,
        }
        self._write_json(self.policy_path, policy)
        return {"project_id": identifier, "root": str(root), "commit": commit}

    def list_projects(self) -> list[dict[str, Any]]:
        result = []
        for identifier, project in sorted(self._policy()["projects"].items()):
            result.append(
                {
                    "project_id": identifier,
                    "root": project["root"],
                    "deny_globs": len(project["deny_globs"]),
                    "require_clean_git": True,
                }
            )
        return result

    def _handoff_dir(self, handoff_id: Any) -> tuple[str, Path]:
        identifier = _validate_identifier(handoff_id, _HANDOFF_ID, "handoff_id")
        self._ensure_private_dir(self.handoffs_root)
        directory = self.handoffs_root / identifier
        if directory.exists() or directory.is_symlink():
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise TrustError("unsafe_state", "The handoff state directory is unsafe.")
            try:
                if not _within(
                    directory.resolve(strict=True), self.handoffs_root.resolve(strict=True)
                ):
                    raise TrustError("unsafe_state", "The handoff state directory is unsafe.")
            except OSError as exc:
                raise TrustError("unsafe_state", "The handoff state directory is unsafe.") from exc
        return identifier, directory

    def _state(self, handoff_id: Any) -> tuple[dict[str, Any], Path]:
        identifier, directory = self._handoff_dir(handoff_id)
        state_path = directory / "state.json"
        if not state_path.exists():
            raise TrustError("handoff_not_found", "No such handoff exists.")
        state_data = self._read_json(state_path)
        required = {
            "schema",
            "handoff_id",
            "project_id",
            "status",
            "created_at",
            "updated_at",
            "task",
            "include",
            "input_commit",
            "packet_digest",
            "files",
            "approval",
            "verification",
        }
        status = state_data.get("status")
        approval = state_data.get("approval")
        verification = state_data.get("verification")
        include = state_data.get("include")
        files = state_data.get("files")
        if (
            set(state_data) != required
            or state_data.get("schema") != STATE_SCHEMA
            or state_data.get("handoff_id") != identifier
            or _PROJECT_ID.fullmatch(str(state_data.get("project_id", ""))) is None
            or status not in {"prepared", "approved", "rejected", "verified"}
            or not self._bounded_text(state_data.get("created_at"), 128)
            or not self._bounded_text(state_data.get("updated_at"), 128)
            or not self._bounded_text(state_data.get("task"), 32 * 1024)
            or bool(scan_text_for_secrets(state_data.get("task", ""), "task"))
            or _COMMIT.fullmatch(str(state_data.get("input_commit", ""))) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(state_data.get("packet_digest", ""))) is None
            or not isinstance(files, list)
            or not 0 < len(files) <= 2_000
            or not all(isinstance(item, str) for item in files)
            or len(set(files)) != len(files)
            or not isinstance(include, list)
            or not 0 < len(include) <= 256
            or not all(isinstance(item, str) for item in include)
            or len(set(include)) != len(include)
        ):
            raise TrustError("state_invalid", "Handoff state is invalid; run doctor.")
        try:
            for item in [*files, *include]:
                _safe_include(item)
        except TrustError as exc:
            raise TrustError("state_invalid", "Handoff state is invalid; run doctor.") from exc
        if status == "prepared" and (approval is not None or verification is not None):
            raise TrustError("state_invalid", "Handoff state is invalid; run doctor.")
        if status in {"approved", "verified"} and not self._valid_approval(approval, "approved_at"):
            raise TrustError("state_invalid", "Handoff state is invalid; run doctor.")
        if status == "rejected" and not self._valid_approval(approval, "rejected_at"):
            raise TrustError("state_invalid", "Handoff state is invalid; run doctor.")
        if status == "verified":
            if not self._valid_verification(verification):
                raise TrustError("state_invalid", "Handoff state is invalid; run doctor.")
        elif verification is not None:
            raise TrustError("state_invalid", "Handoff state is invalid; run doctor.")
        return state_data, directory

    @contextmanager
    def _handoff_lock(self, handoff_id: Any) -> Iterator[None]:
        _identifier, directory = self._handoff_dir(handoff_id)
        if not directory.is_dir() or directory.is_symlink():
            raise TrustError("handoff_not_found", "No such handoff exists.")
        lock_path = directory / ".lock"
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(lock_path, flags, 0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise OSError("unsafe lock file")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as exc:
            if "descriptor" in locals():
                os.close(descriptor)
            raise TrustError("state_lock_failed", "The handoff state could not be locked.") from exc
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _bounded_text(value: Any, byte_limit: int) -> bool:
        return (
            isinstance(value, str)
            and bool(value)
            and len(value.encode("utf-8")) <= byte_limit
            and all(
                (ord(character) >= 32 or character in {"\n", "\t"}) and ord(character) != 127
                for character in value
            )
        )

    def _valid_approval(self, value: Any, timestamp_key: str) -> bool:
        return (
            isinstance(value, dict)
            and set(value) == {timestamp_key, "method"}
            and value.get("method") == "operator_cli"
            and self._bounded_text(value.get(timestamp_key), 128)
        )

    def _valid_verification(self, value: Any) -> bool:
        return (
            isinstance(value, dict)
            and set(value)
            == {
                "verified_at",
                "output_manifest_digest",
                "receipt_digest",
                "receipt_file_sha256",
                "assurance",
                "files",
            }
            and self._bounded_text(value.get("verified_at"), 128)
            and re.fullmatch(r"[0-9a-f]{64}", str(value.get("output_manifest_digest", "")))
            is not None
            and re.fullmatch(r"[0-9a-f]{64}", str(value.get("receipt_digest", ""))) is not None
            and re.fullmatch(r"[0-9a-f]{64}", str(value.get("receipt_file_sha256", ""))) is not None
            and value.get("assurance") == "fully_rechecked"
            and isinstance(value.get("files"), int)
            and not isinstance(value.get("files"), bool)
            and 0 <= value["files"] <= MAX_RETURN_FILES
        )

    def _public_state(self, state_data: dict[str, Any]) -> dict[str, Any]:
        response: dict[str, Any] = {
            "handoff_id": state_data["handoff_id"],
            "project_id": state_data["project_id"],
            "status": state_data["status"],
            "created_at": state_data["created_at"],
            "updated_at": state_data["updated_at"],
            "input_commit": state_data["input_commit"],
            "packet_digest": state_data["packet_digest"],
            "file_count": len(state_data["files"]),
            "files": state_data["files"][:MAX_PUBLIC_FILES],
            "operator_review_required": state_data["status"] == "prepared",
        }
        verification = state_data.get("verification")
        if isinstance(verification, dict):
            response["verification"] = {
                key: verification[key]
                for key in (
                    "verified_at",
                    "output_manifest_digest",
                    "receipt_digest",
                    "assurance",
                )
                if key in verification
            }
        return response

    def prepare(self, args: dict[str, Any]) -> dict[str, Any]:
        if set(args) != {"project_id", "task", "include"}:
            raise TrustError(
                "invalid_arguments", "Only project_id, task, and include are accepted."
            )
        project_id, project, source_root = self._project(args["project_id"])
        task = args["task"]
        include_value = args["include"]
        if (
            not isinstance(task, str)
            or not task.strip()
            or len(task.encode("utf-8")) > 32 * 1024
            or scan_text_for_secrets(task, "task")
        ):
            raise TrustError("unsafe_task", "Task text is empty, too large, or looks sensitive.")
        if (
            not isinstance(include_value, list)
            or not 0 < len(include_value) <= 256
            or len(set(str(item) for item in include_value)) != len(include_value)
        ):
            raise TrustError("invalid_include", "A bounded, unique include list is required.")
        include = [_safe_include(item) for item in include_value]
        commit, clean = self._git(source_root)
        if project["require_clean_git"] and not clean:
            raise TrustError(
                "dirty_project", "Commit or remove project changes before preparing a handoff."
            )
        if len(list(self.handoffs_root.iterdir())) >= MAX_HANDOFFS:
            raise TrustError("handoff_limit", "The local handoff limit has been reached.")

        handoff_id = datetime.now(timezone.utc).strftime("h-%Y%m%dt%H%M%Sz-") + secrets.token_hex(5)
        final_dir = self.handoffs_root / handoff_id
        temporary = self.handoffs_root / f".{handoff_id}.{secrets.token_hex(4)}.tmp"
        self._ensure_private_dir(temporary)
        packet_dir = temporary / "packet"
        try:
            manifest = build_packet(
                task=task.strip(),
                source_root=source_root,
                include=include,
                out_dir=packet_dir,
                include_all=False,
                extra_deny_globs=project["deny_globs"],
                meta=None,
                allow_binary=False,
                redact_secrets=False,
            )
            if (
                manifest.denied
                or manifest.redactions
                or manifest.warnings
                or len(manifest.files) <= 1
            ):
                raise TrustError(
                    "packet_blocked",
                    "The packet was blocked because selected inputs were unsafe or missing.",
                )
            self._assert_packet_matches_commit(source_root, commit, manifest)
            packet_file = packet_dir / "packet.tar.gz"
            digest = _sha256_file(packet_file)
            if digest != manifest.packet_sha256:
                raise TrustError("packet_digest_mismatch", "Packet digest verification failed.")
            final_commit, final_clean = self._git(source_root)
            if final_commit != commit or not final_clean:
                raise TrustError(
                    "project_changed",
                    "The project changed while the handoff was being prepared.",
                )
            files = [entry.path for entry in manifest.files if entry.path != "TASK.md"]
            timestamp = _now()
            state_data = {
                "schema": STATE_SCHEMA,
                "handoff_id": handoff_id,
                "project_id": project_id,
                "status": "prepared",
                "created_at": timestamp,
                "updated_at": timestamp,
                "task": task.strip(),
                "include": include,
                "input_commit": commit,
                "packet_digest": digest,
                "files": files,
                "approval": None,
                "verification": None,
            }
            self._write_json(temporary / "state.json", state_data)
            self._harden_tree(temporary)
            if final_dir.exists() or final_dir.is_symlink():
                raise TrustError("handoff_collision", "A handoff identifier collision occurred.")
            os.replace(temporary, final_dir)
            self._harden_tree(final_dir)
            return {
                **self._public_state(state_data),
                "next_action": f"Operator review: hermes agent-trust approve {handoff_id}",
                "transported": False,
            }
        except TrustError:
            if temporary.exists():
                shutil.rmtree(temporary)
            raise
        except (OSError, ValueError) as exc:
            if temporary.exists():
                shutil.rmtree(temporary)
            raise TrustError(
                "packet_build_failed", "The packet could not be built safely."
            ) from exc

    def _harden_tree(self, root: Path) -> None:
        if not _within(root.resolve(strict=True), self.root.resolve(strict=True)):
            raise RuntimeError("refusing to harden a path outside Agent Trust state")
        for directory, directories, files in os.walk(root, topdown=True, followlinks=False):
            current = Path(directory)
            if stat.S_ISLNK(current.lstat().st_mode):
                raise TrustError("unsafe_state", "Agent Trust state contains a symbolic link.")
            current.chmod(0o700)
            for name in directories:
                child = current / name
                if stat.S_ISLNK(child.lstat().st_mode):
                    raise TrustError("unsafe_state", "Agent Trust state contains a symbolic link.")
            for name in files:
                child = current / name
                info = child.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise TrustError("unsafe_state", "Agent Trust state contains an unsafe file.")
                child.chmod(0o600)

    def status(self, args: dict[str, Any]) -> dict[str, Any]:
        if set(args) != {"handoff_id"}:
            raise TrustError("invalid_arguments", "Only handoff_id is accepted.")
        with self._handoff_lock(args["handoff_id"]):
            state_data, directory = self._state(args["handoff_id"])
            if state_data["status"] == "verified":
                self._assert_verified_snapshot(state_data, directory)
            return self._public_state(state_data)

    def list_handoffs(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for path in sorted(self.handoffs_root.iterdir(), reverse=True):
            if path.is_dir() and _HANDOFF_ID.fullmatch(path.name):
                try:
                    with self._handoff_lock(path.name):
                        state_data, directory = self._state(path.name)
                        if state_data["status"] == "verified":
                            self._assert_verified_snapshot(state_data, directory)
                        result.append(self._public_state(state_data))
                except TrustError:
                    result.append({"handoff_id": path.name, "status": "invalid"})
        return result

    def approve(self, handoff_id: Any) -> dict[str, Any]:
        with self._handoff_lock(handoff_id):
            return self._approve_locked(handoff_id)

    def _approve_locked(self, handoff_id: Any) -> dict[str, Any]:
        state_data, directory = self._state(handoff_id)
        if state_data["status"] == "approved":
            return {
                **self._public_state(state_data),
                "packet_path": str(directory / "packet" / "packet.tar.gz"),
            }
        if state_data["status"] != "prepared":
            raise TrustError("invalid_transition", "Only a prepared handoff can be approved.")
        digest = _sha256_file(directory / "packet" / "packet.tar.gz")
        if digest != state_data["packet_digest"]:
            raise TrustError("packet_digest_mismatch", "The packet changed after preparation.")
        timestamp = _now()
        state_data["status"] = "approved"
        state_data["updated_at"] = timestamp
        state_data["approval"] = {"approved_at": timestamp, "method": "operator_cli"}
        self._write_json(directory / "state.json", state_data)
        return {
            **self._public_state(state_data),
            "packet_path": str(directory / "packet" / "packet.tar.gz"),
            "digest_path": str(directory / "packet" / "PACKET_SHA256.txt"),
        }

    def reject(self, handoff_id: Any) -> dict[str, Any]:
        with self._handoff_lock(handoff_id):
            return self._reject_locked(handoff_id)

    def _reject_locked(self, handoff_id: Any) -> dict[str, Any]:
        state_data, directory = self._state(handoff_id)
        if state_data["status"] == "rejected":
            return self._public_state(state_data)
        if state_data["status"] not in {"prepared", "approved"}:
            raise TrustError("invalid_transition", "This handoff cannot be rejected now.")
        timestamp = _now()
        state_data["status"] = "rejected"
        state_data["updated_at"] = timestamp
        state_data["approval"] = {"rejected_at": timestamp, "method": "operator_cli"}
        self._write_json(directory / "state.json", state_data)
        return self._public_state(state_data)

    def return_path(self, handoff_id: Any) -> Path:
        with self._handoff_lock(handoff_id):
            state_data, directory = self._state(handoff_id)
            if state_data["status"] == "verified":
                self._assert_verified_snapshot(state_data, directory)
                raise TrustError(
                    "already_verified",
                    "This handoff is verified; use `hermes agent-trust verified-path`.",
                )
            if state_data["status"] != "approved":
                raise TrustError(
                    "approval_required", "Approve the handoff before accepting a return."
                )
            destination = directory / "return"
            if destination.exists():
                raise TrustError(
                    "return_already_present",
                    "The fixed return quarantine already exists; inspect it before continuing.",
                )
            return destination

    def verified_path(self, handoff_id: Any) -> Path:
        with self._handoff_lock(handoff_id):
            state_data, directory = self._state(handoff_id)
            if state_data["status"] != "verified":
                raise TrustError("verification_required", "Verify the handoff first.")
            self._assert_verified_snapshot(state_data, directory)
            return directory / "verified-snapshot"

    def _copy_return_file(
        self,
        source_root_fd: int,
        relative: str,
        destination: Path,
        *,
        max_bytes: int,
        expected_bytes: int | None = None,
        expected_sha256: str | None = None,
    ) -> tuple[int, str]:
        parts = PurePosixPath(relative).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise TrustError("snapshot_failed", "A return path is invalid.")
        parent_fd = os.dup(source_root_fd)
        descriptor: int | None = None
        output_descriptor: int | None = None
        completed = False
        try:
            for part in parts[:-1]:
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                next_fd = os.open(part, flags, dir_fd=parent_fd)
                opened = os.fstat(next_fd)
                if not stat.S_ISDIR(opened.st_mode):
                    os.close(next_fd)
                    raise TrustError("snapshot_failed", "A return directory is unsafe.")
                os.close(parent_fd)
                parent_fd = next_fd
            name = parts[-1]
            before_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino)
                or before.st_size > max_bytes
                or (expected_bytes is not None and before.st_size != expected_bytes)
            ):
                raise TrustError("snapshot_failed", "A returned file is unsafe or mismatched.")
            self._ensure_private_dir(destination.parent)
            output_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            output_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            output_descriptor = os.open(destination, output_flags, 0o600)
            digest = hashlib.sha256()
            copied = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                copied += len(chunk)
                if copied > max_bytes:
                    raise TrustError("snapshot_failed", "A returned file exceeds its size limit.")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(output_descriptor, view)
                    view = view[written:]
            os.fsync(output_descriptor)
            after = os.fstat(descriptor)
            after_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            observed_sha256 = digest.hexdigest()
            if (
                _file_signature(before) != _file_signature(after)
                or (after.st_dev, after.st_ino) != (after_path.st_dev, after_path.st_ino)
                or copied != before.st_size
                or (expected_sha256 is not None and observed_sha256 != expected_sha256)
            ):
                raise TrustError("snapshot_failed", "A returned file changed during snapshotting.")
            completed = True
            return copied, observed_sha256
        except (OSError, ValueError) as exc:
            raise TrustError(
                "snapshot_failed", "The return could not be snapshotted safely."
            ) from exc
        finally:
            if output_descriptor is not None:
                os.close(output_descriptor)
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent_fd)
            if destination.exists() and not completed:
                destination.unlink(missing_ok=True)

    def _snapshot_return(
        self,
        return_dir: Path,
        snapshot_dir: Path,
        manifest_data: dict[str, Any],
        manifest_digest: str,
    ) -> str:
        if (
            manifest_data["file_count"] <= 0
            or manifest_data["file_count"] > MAX_RETURN_FILES
            or manifest_data["total_bytes"] > MAX_RETURN_BYTES
        ):
            raise TrustError(
                "output_policy_failed",
                "The native return must contain a bounded, non-empty output file set.",
            )
        self._ensure_private_dir(snapshot_dir)
        root_info = return_dir.lstat()
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            root_fd = os.open(return_dir, flags)
        except OSError as exc:
            raise TrustError(
                "snapshot_failed", "The return root could not be opened safely."
            ) from exc
        try:
            opened_root = os.fstat(root_fd)
            if not stat.S_ISDIR(opened_root.st_mode) or (
                opened_root.st_dev,
                opened_root.st_ino,
            ) != (root_info.st_dev, root_info.st_ino):
                raise TrustError("snapshot_failed", "The return root changed while opening.")
            for entry in manifest_data["files"]:
                self._copy_return_file(
                    root_fd,
                    entry["path"],
                    snapshot_dir.joinpath(*PurePosixPath(entry["path"]).parts),
                    max_bytes=MAX_RETURN_BYTES,
                    expected_bytes=entry["bytes"],
                    expected_sha256=entry["sha256"],
                )
            self._copy_return_file(
                root_fd,
                "OUTPUT_MANIFEST.json",
                snapshot_dir / "OUTPUT_MANIFEST.json",
                max_bytes=MAX_CONTROL_FILE_BYTES,
            )
            _receipt_bytes, receipt_file_sha256 = self._copy_return_file(
                root_fd,
                "receipt.json",
                snapshot_dir / "receipt.json",
                max_bytes=MAX_CONTROL_FILE_BYTES,
            )
            current_root = return_dir.lstat()
            if (opened_root.st_dev, opened_root.st_ino) != (
                current_root.st_dev,
                current_root.st_ino,
            ):
                raise TrustError("snapshot_failed", "The return root changed while snapshotting.")
        finally:
            os.close(root_fd)

        from agent_receipt.output_manifest import load_output_manifest, verify_output_manifest

        copied_manifest = load_output_manifest(snapshot_dir / "OUTPUT_MANIFEST.json")
        copied_result = verify_output_manifest(copied_manifest, snapshot_dir)
        if not copied_result.get("ok") or copied_result.get("digest") != manifest_digest:
            raise TrustError("snapshot_failed", "The private return snapshot does not match.")
        return receipt_file_sha256

    def _freeze_snapshot(self, snapshot_dir: Path) -> None:
        for directory, directories, files in os.walk(
            snapshot_dir, topdown=False, followlinks=False
        ):
            current = Path(directory)
            for name in files:
                child = current / name
                info = child.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise TrustError(
                        "snapshot_failed", "The private snapshot contains an unsafe file."
                    )
                child.chmod(0o400)
            for name in directories:
                child = current / name
                if not stat.S_ISDIR(child.lstat().st_mode) or child.is_symlink():
                    raise TrustError(
                        "snapshot_failed", "The private snapshot contains an unsafe directory."
                    )
                child.chmod(0o500)
            current.chmod(0o500)

    @staticmethod
    def _receipt_paths_match_manifest(receipt_data: Any, manifest_data: dict[str, Any]) -> bool:
        allowed = {entry["path"] for entry in manifest_data["files"]}
        if not allowed or not isinstance(receipt_data, dict):
            return False
        claims = receipt_data.get("claims")
        if not isinstance(claims, list) or not claims:
            return False
        for claim in claims:
            if not isinstance(claim, dict) or not isinstance(claim.get("evidence"), list):
                return False
            for evidence in claim["evidence"]:
                if not isinstance(evidence, dict):
                    return False
                if evidence.get("kind") == "command":
                    continue
                detail = evidence.get("detail")
                if not isinstance(detail, dict) or detail.get("path") not in allowed:
                    return False
        return True

    def _remove_private_tree(self, path: Path) -> None:
        if not path.exists() and not path.is_symlink():
            return
        resolved_parent = path.parent.resolve(strict=True)
        if not _within(resolved_parent, self.root.resolve(strict=True)):
            raise RuntimeError("refusing to remove a path outside Agent Trust state")
        if path.is_symlink() or not path.is_dir():
            path.unlink()
            return
        for directory, _directories, files in os.walk(path, topdown=True, followlinks=False):
            current = Path(directory)
            current.chmod(0o700)
            for name in files:
                child = current / name
                if child.is_symlink() or child.is_file():
                    child.chmod(0o600, follow_symlinks=False)
        shutil.rmtree(path)

    def _assert_verified_snapshot(
        self, state_data: dict[str, Any], directory: Path
    ) -> dict[str, Any]:
        snapshot = directory / "verified-snapshot"
        if not snapshot.is_dir() or snapshot.is_symlink():
            raise TrustError("verified_snapshot_invalid", "The verified snapshot is unavailable.")
        manifest_path = snapshot / "OUTPUT_MANIFEST.json"
        receipt_path = snapshot / "receipt.json"
        _regular_single_link(manifest_path, "verified OUTPUT_MANIFEST.json")
        _regular_single_link(receipt_path, "verified receipt.json")
        try:
            from agent_receipt.output_manifest import (
                load_output_manifest,
                verify_output_manifest,
            )

            manifest_data = load_output_manifest(manifest_path)
            manifest_result = verify_output_manifest(manifest_data, snapshot)
            receipt_data = load_receipt(receipt_path)
        except (OSError, UnicodeError, ValueError) as exc:
            raise TrustError(
                "verified_snapshot_invalid", "The verified snapshot is unreadable."
            ) from exc
        verification = state_data["verification"]
        if (
            not manifest_result.get("ok")
            or manifest_result.get("digest") != verification["output_manifest_digest"]
            or manifest_result.get("files") != verification["files"]
            or _sha256_file(receipt_path) != verification["receipt_file_sha256"]
            or not self._receipt_paths_match_manifest(receipt_data, manifest_data)
        ):
            raise TrustError(
                "verified_snapshot_invalid", "The verified snapshot no longer matches its record."
            )
        expected_context = {
            "packet_digest": state_data["packet_digest"],
            "input_commit": state_data["input_commit"],
            "output_manifest_digest": manifest_result["digest"],
        }
        result = verify_receipt(
            receipt_data,
            recheck=True,
            recheck_commands=False,
            recheck_root=snapshot,
            allowed_commands=None,
            expected_context=expected_context,
            minimum_assurance="fully_rechecked",
        )
        if (
            not result.get("ok")
            or result.get("recomputed_digest") != verification["receipt_digest"]
        ):
            raise TrustError(
                "verified_snapshot_invalid", "The verified receipt no longer passes rechecks."
            )
        return result

    def verify_return(self, args: dict[str, Any]) -> dict[str, Any]:
        if set(args) != {"handoff_id"}:
            raise TrustError("invalid_arguments", "Only handoff_id is accepted.")
        with self._handoff_lock(args["handoff_id"]):
            return self._verify_return_locked(args["handoff_id"])

    def _verify_return_locked(self, handoff_id: Any) -> dict[str, Any]:
        state_data, directory = self._state(handoff_id)
        if state_data["status"] not in {"approved", "verified"}:
            raise TrustError(
                "approval_required", "The handoff must be approved before verification."
            )
        if state_data["status"] == "verified":
            result = self._assert_verified_snapshot(state_data, directory)
            return {
                **self._public_state(state_data),
                "verified": True,
                "output_file_count": state_data["verification"]["files"],
                "receipt_claim_count": len(result["claims"]),
                "commands_executed": 0,
                "merge_performed": False,
            }
        return_dir = directory / "return"
        if not return_dir.is_dir() or return_dir.is_symlink():
            raise TrustError(
                "return_not_ready", "No returned workspace exists in the fixed quarantine."
            )
        manifest_path = return_dir / "OUTPUT_MANIFEST.json"
        receipt_path = return_dir / "receipt.json"
        _regular_single_link(manifest_path, "OUTPUT_MANIFEST.json")
        _regular_single_link(receipt_path, "receipt.json")
        try:
            from agent_receipt.output_manifest import (
                load_output_manifest,
                verify_output_manifest,
            )

            manifest_data = load_output_manifest(manifest_path)
            manifest_result = verify_output_manifest(manifest_data, return_dir)
        except (OSError, UnicodeError, ValueError) as exc:
            raise TrustError("output_manifest_invalid", "The output manifest is invalid.") from exc
        if not manifest_result.get("ok"):
            raise TrustError(
                "output_manifest_mismatch",
                "Returned files do not exactly match the output manifest.",
            )
        if (
            manifest_result.get("files", 0) <= 0
            or manifest_result.get("files", 0) > MAX_RETURN_FILES
            or manifest_result.get("total_bytes", MAX_RETURN_BYTES + 1) > MAX_RETURN_BYTES
        ):
            raise TrustError(
                "output_policy_failed",
                "The native return must contain a bounded, non-empty output file set.",
            )
        snapshot_temporary = directory / f".verification.{secrets.token_hex(8)}.tmp"
        snapshot_final = directory / "verified-snapshot"
        if snapshot_final.exists() or snapshot_final.is_symlink():
            raise TrustError(
                "verified_snapshot_exists",
                "A private verified snapshot already exists; run doctor before retrying.",
            )
        try:
            receipt_file_sha256 = self._snapshot_return(
                return_dir,
                snapshot_temporary,
                manifest_data,
                manifest_result["digest"],
            )
            snapshot_manifest_path = snapshot_temporary / "OUTPUT_MANIFEST.json"
            snapshot_receipt_path = snapshot_temporary / "receipt.json"
            try:
                snapshot_manifest = load_output_manifest(snapshot_manifest_path)
                receipt_data = load_receipt(snapshot_receipt_path)
            except (OSError, UnicodeError, ValueError) as exc:
                raise TrustError("receipt_invalid", "The return receipt is invalid.") from exc
            if not self._receipt_paths_match_manifest(receipt_data, snapshot_manifest):
                raise TrustError(
                    "receipt_output_policy_failed",
                    "Receipt evidence must reference files declared in the output manifest.",
                )
            expected_context = {
                "packet_digest": state_data["packet_digest"],
                "input_commit": state_data["input_commit"],
                "output_manifest_digest": manifest_result["digest"],
            }
            result = verify_receipt(
                receipt_data,
                recheck=True,
                recheck_commands=False,
                recheck_root=snapshot_temporary,
                allowed_commands=None,
                expected_context=expected_context,
                minimum_assurance="fully_rechecked",
            )
            if not result.get("ok"):
                error_codes: list[str] = []
                if not result.get("schema_ok"):
                    error_codes.append("schema")
                if not result.get("hash_ok"):
                    error_codes.append("digest")
                if not result.get("context_ok", True):
                    error_codes.append("context")
                if not result.get("assurance_ok", True):
                    error_codes.append("assurance")
                if not error_codes:
                    error_codes.append("evidence")
                raise TrustError(
                    "receipt_verification_failed",
                    "Receipt verification failed (" + ", ".join(error_codes) + ").",
                )
            self._freeze_snapshot(snapshot_temporary)
            os.replace(snapshot_temporary, snapshot_final)
            timestamp = _now()
            state_data["status"] = "verified"
            state_data["updated_at"] = timestamp
            state_data["verification"] = {
                "verified_at": timestamp,
                "output_manifest_digest": manifest_result["digest"],
                "receipt_digest": result["recomputed_digest"],
                "receipt_file_sha256": receipt_file_sha256,
                "assurance": result["assurance"],
                "files": manifest_result["files"],
            }
            try:
                self._write_json(directory / "state.json", state_data)
            except Exception:
                self._remove_private_tree(snapshot_final)
                raise
            return {
                **self._public_state(state_data),
                "verified": True,
                "output_file_count": manifest_result["files"],
                "receipt_claim_count": len(result["claims"]),
                "commands_executed": 0,
                "merge_performed": False,
            }
        finally:
            if snapshot_temporary.exists() or snapshot_temporary.is_symlink():
                self._remove_private_tree(snapshot_temporary)

    def doctor(self) -> dict[str, Any]:
        origins = ensure_repo_local_core()
        policy = self._policy()
        invalid_handoffs = sum(
            1 for item in self.list_handoffs() if item.get("status") == "invalid"
        )
        return {
            "ok": invalid_handoffs == 0,
            "state_root": str(self.root),
            "policy_file": str(self.policy_path),
            "projects": len(policy["projects"]),
            "handoffs": len(self.list_handoffs()),
            "invalid_handoffs": invalid_handoffs,
            "core_modules": {name: str(path) for name, path in origins.items()},
            "git": shutil.which("git") is not None,
            "guarded_tools": sorted(_GUARDED_TOOLS),
            "global_egress_enforcement": False,
        }

    def pre_tool_call(
        self, tool_name: str, args: dict[str, Any] | None, **_kwargs: Any
    ) -> dict[str, str] | None:
        if tool_name not in _GUARDED_TOOLS:
            return None
        try:
            for value in self._iter_hook_strings(args):
                if scan_text_for_secrets(value, "tool_argument") or _PRIVATE_REFERENCE.search(
                    value
                ):
                    return {
                        "action": "block",
                        "message": (
                            "Agent Trust blocked secret-like or private-path content in this "
                            "transfer tool. Prepare and approve a bounded handoff instead."
                        ),
                    }
            return None
        except Exception:
            return {
                "action": "block",
                "message": "Agent Trust could not safely inspect this transfer tool call.",
            }

    def _iter_hook_strings(self, value: Any) -> Iterator[str]:
        counters = [0, 0]

        def walk(item: Any, depth: int) -> Iterator[str]:
            if depth > MAX_HOOK_DEPTH:
                raise ValueError("hook arguments are too deeply nested")
            if isinstance(item, str):
                counters[0] += 1
                counters[1] += len(item.encode("utf-8"))
                if counters[0] > MAX_HOOK_STRINGS or counters[1] > MAX_HOOK_BYTES:
                    raise ValueError("hook arguments exceed inspection limits")
                yield item
            elif isinstance(item, dict):
                for key, nested in item.items():
                    yield from walk(key, depth + 1)
                    yield from walk(nested, depth + 1)
            elif isinstance(item, (list, tuple)):
                for nested in item:
                    yield from walk(nested, depth + 1)
            elif item is not None and not isinstance(item, (bool, int, float)):
                raise ValueError("hook arguments contain an unsupported value")

        yield from walk(value, 0)
