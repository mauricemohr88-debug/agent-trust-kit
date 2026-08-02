"""Canonical, bounded output manifests for controller-selected workspaces.

The manifest is an inventory, not an authenticity mechanism.  Controllers can
bind its returned digest into a receipt or signature when they need attribution.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

SCHEMA = "agent-output-manifest/v1"
DEFAULT_EXCLUDES = frozenset({"receipt.json", "OUTPUT_MANIFEST.json"})

# These are hard safety ceilings, not recommendations about repository size.
MAX_FILES = 10_000
MAX_ENTRIES = 20_000
MAX_DEPTH = 64
MAX_PATH_BYTES = 1_024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
READ_CHUNK_BYTES = 128 * 1024

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class OutputManifestError(ValueError):
    """Raised when a tree or manifest cannot be handled safely."""


def _canonical_bytes(data: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OutputManifestError(f"manifest is not canonical JSON: {exc}") from exc


def _duplicate_key_guard(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            # Do not reflect an attacker-controlled, potentially huge key into logs.
            raise OutputManifestError("duplicate JSON key")
        result[key] = value
    return result


def _bounded_json_int(value: str) -> int:
    if len(value.lstrip("-")) > 20:
        raise OutputManifestError("JSON integer exceeds the manifest digit limit")
    return int(value)


def _reject_json_non_integer(value: str) -> None:
    del value
    raise OutputManifestError("manifest JSON numbers must be finite integers")


def _require_secure_platform() -> None:
    required_flags = ("O_NOFOLLOW", "O_DIRECTORY")
    if any(not hasattr(os, flag) for flag in required_flags):
        raise OutputManifestError("secure manifest traversal is unsupported on this platform")
    if os.stat not in os.supports_dir_fd or os.scandir not in os.supports_fd:
        raise OutputManifestError("secure descriptor-relative traversal is unsupported")


def _path_error(value: object) -> OutputManifestError:
    del value
    return OutputManifestError("invalid relative POSIX manifest path")


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise _path_error(value)
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise _path_error(value) from exc
    if len(encoded) > MAX_PATH_BYTES or value.startswith("/"):
        raise _path_error(value)
    raw_parts = value.split("/")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
        or path.as_posix() != value
    ):
        raise _path_error(value)
    if any(
        unicodedata.category(character) in {"Cc", "Cf"} for part in raw_parts for character in part
    ):
        raise _path_error(value)
    return value


def _validated_excludes(exclude: set[str] | None) -> frozenset[str]:
    values = set(DEFAULT_EXCLUDES)
    if exclude is not None:
        if not isinstance(exclude, set) or not all(isinstance(item, str) for item in exclude):
            raise OutputManifestError("exclude must be a set of relative POSIX paths")
        values.update(exclude)
    return frozenset(_validate_relative_path(value) for value in values)


def _identity(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))


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


def _directory_signature(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _open_flags(*, directory: bool = False) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    if directory:
        flags |= os.O_DIRECTORY
    else:
        # Prevent a regular-file-to-FIFO race from blocking the scanner.
        flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def _read_chunks(stream: BinaryIO, *, limit: int) -> bytes:
    result = bytearray()
    while chunk := stream.read(min(READ_CHUNK_BYTES, limit + 1 - len(result))):
        result.extend(chunk)
        if len(result) > limit:
            raise OutputManifestError("file exceeds the configured size limit")
    return bytes(result)


def _read_manifest_file(path: Path) -> bytes:
    _require_secure_platform()
    candidate = Path(path)
    parent = candidate.parent.resolve(strict=True)
    if not parent.is_dir() or candidate.name in {"", ".", ".."}:
        raise OutputManifestError("manifest path must name a regular file")
    parent_info = os.stat(parent, follow_symlinks=False)
    parent_fd = os.open(parent, _open_flags(directory=True))
    try:
        opened_parent = os.fstat(parent_fd)
        if _identity(parent_info) != _identity(opened_parent):
            raise OutputManifestError("manifest parent changed while opening it")
        before_path = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(before_path.st_mode):
            raise OutputManifestError("manifest path must not be a symlink or special file")
        if before_path.st_nlink != 1:
            raise OutputManifestError("manifest file must not be hard-linked")
        fd = os.open(candidate.name, _open_flags(), dir_fd=parent_fd)
        try:
            before_fd = os.fstat(fd)
            if _identity(before_path) != _identity(before_fd) or not stat.S_ISREG(
                before_fd.st_mode
            ):
                raise OutputManifestError("manifest path changed while opening it")
            if before_fd.st_nlink != 1 or before_fd.st_size > MAX_MANIFEST_BYTES:
                raise OutputManifestError("manifest exceeds link or size limits")
            with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
                raw = _read_chunks(stream, limit=MAX_MANIFEST_BYTES)
            after_fd = os.fstat(fd)
            after_path = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                _file_signature(before_fd) != _file_signature(after_fd)
                or _identity(before_fd) != _identity(after_path)
                or len(raw) != before_fd.st_size
            ):
                raise OutputManifestError("manifest changed while it was read")
            current_parent = os.stat(parent, follow_symlinks=False)
            if _identity(opened_parent) != _identity(current_parent):
                raise OutputManifestError("manifest parent path changed while reading")
            return raw
        finally:
            os.close(fd)
    except OSError as exc:
        raise OutputManifestError("could not safely read manifest") from exc
    finally:
        os.close(parent_fd)


def _validate_manifest(data: object) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise OutputManifestError("manifest must be a JSON object")
    required = {"schema", "file_count", "total_bytes", "files"}
    if set(data) != required:
        raise OutputManifestError("manifest keys must be exactly: " + ", ".join(sorted(required)))
    if data.get("schema") != SCHEMA:
        raise OutputManifestError("unsupported manifest schema")
    file_count = data.get("file_count")
    total_bytes = data.get("total_bytes")
    files = data.get("files")
    if (
        isinstance(file_count, bool)
        or not isinstance(file_count, int)
        or not 0 <= file_count <= MAX_FILES
    ):
        raise OutputManifestError("file_count is outside the allowed range")
    if (
        isinstance(total_bytes, bool)
        or not isinstance(total_bytes, int)
        or not 0 <= total_bytes <= MAX_TOTAL_BYTES
    ):
        raise OutputManifestError("total_bytes is outside the allowed range")
    if not isinstance(files, list) or len(files) != file_count:
        raise OutputManifestError("files must be a list matching file_count")

    paths: list[str] = []
    computed_total = 0
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "bytes"}:
            raise OutputManifestError("every file must contain exactly path, sha256, and bytes")
        path = _validate_relative_path(entry.get("path"))
        sha256 = entry.get("sha256")
        size = entry.get("bytes")
        if not isinstance(sha256, str) or _SHA256_RE.fullmatch(sha256) is None:
            raise OutputManifestError("file sha256 must be lowercase SHA-256 hex")
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_FILE_BYTES:
            raise OutputManifestError("file byte count is outside the allowed range")
        paths.append(path)
        computed_total += size
        if computed_total > MAX_TOTAL_BYTES:
            raise OutputManifestError("manifest total exceeds the allowed byte limit")
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise OutputManifestError("manifest paths must be unique and sorted")
    if computed_total != total_bytes:
        raise OutputManifestError("total_bytes does not match the file entries")
    if len(_canonical_bytes(data)) > MAX_MANIFEST_BYTES:
        raise OutputManifestError("canonical manifest exceeds its size limit")
    return data


def manifest_digest(data: dict[str, Any]) -> str:
    """Return SHA-256 over the validated canonical JSON manifest (without a newline)."""

    validated = _validate_manifest(data)
    return hashlib.sha256(_canonical_bytes(validated)).hexdigest()


def _relative_name(parts: tuple[str, ...], name: str) -> str:
    return _validate_relative_path("/".join((*parts, name)))


def _ensure_stable_excluded_file(
    parent_fd: int, name: str, path_info: os.stat_result
) -> tuple[int, ...]:
    if path_info.st_nlink != 1:
        raise OutputManifestError("hard-linked files are not allowed")
    try:
        fd = os.open(name, _open_flags(), dir_fd=parent_fd)
        try:
            opened = os.fstat(fd)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                _identity(path_info) != _identity(opened)
                or _file_signature(opened) != _file_signature(current)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
            ):
                raise OutputManifestError("excluded control file changed while inspecting it")
            return _file_signature(opened)
        finally:
            os.close(fd)
    except OSError as exc:
        raise OutputManifestError("could not safely inspect excluded control file") from exc


def _hash_regular_file(
    parent_fd: int,
    name: str,
    path_info: os.stat_result,
    *,
    total_before: int,
) -> tuple[str, int, tuple[int, ...]]:
    if path_info.st_nlink != 1:
        raise OutputManifestError("hard-linked files are not allowed")
    if path_info.st_size > MAX_FILE_BYTES:
        raise OutputManifestError("file exceeds the manifest per-file byte limit")
    if total_before + path_info.st_size > MAX_TOTAL_BYTES:
        raise OutputManifestError("workspace exceeds the manifest total byte limit")
    try:
        fd = os.open(name, _open_flags(), dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            if (
                _identity(path_info) != _identity(before)
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
            ):
                raise OutputManifestError("file path changed while opening it")
            digest = hashlib.sha256()
            byte_count = 0
            with os.fdopen(os.dup(fd), "rb", closefd=True) as stream:
                while chunk := stream.read(READ_CHUNK_BYTES):
                    byte_count += len(chunk)
                    if byte_count > MAX_FILE_BYTES or total_before + byte_count > MAX_TOTAL_BYTES:
                        raise OutputManifestError("file changed beyond manifest byte limits")
                    digest.update(chunk)
            after = os.fstat(fd)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                _file_signature(before) != _file_signature(after)
                or _identity(before) != _identity(current)
                or byte_count != before.st_size
            ):
                raise OutputManifestError("file changed while it was hashed")
            return digest.hexdigest(), byte_count, _file_signature(before)
        finally:
            os.close(fd)
    except OSError as exc:
        raise OutputManifestError("could not safely hash workspace file") from exc


def _scan_workspace_once(workspace_root: Path, excluded: frozenset[str]) -> dict[str, Any]:
    _require_secure_platform()
    root = Path(workspace_root).resolve(strict=True)
    if not root.is_dir():
        raise OutputManifestError("workspace_root must be an existing directory")
    root_info = os.stat(root, follow_symlinks=False)
    root_fd = os.open(root, _open_flags(directory=True))
    files: list[dict[str, Any]] = []
    paths: set[str] = set()
    counters = {"entries": 0, "total": 0}

    def walk(directory_fd: int, parts: tuple[str, ...], depth: int) -> None:
        if depth > MAX_DEPTH:
            raise OutputManifestError("workspace exceeds the manifest depth limit")
        before_directory = os.fstat(directory_fd)
        stable_files: list[tuple[str, tuple[int, ...]]] = []
        try:
            iterator = os.scandir(directory_fd)
            with iterator:
                for entry in iterator:
                    counters["entries"] += 1
                    if counters["entries"] > MAX_ENTRIES:
                        raise OutputManifestError("workspace exceeds the manifest entry limit")
                    relative = _relative_name(parts, entry.name)
                    try:
                        path_info = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError as exc:
                        raise OutputManifestError("workspace changed while scanning") from exc
                    mode = path_info.st_mode
                    if stat.S_ISLNK(mode):
                        raise OutputManifestError("symbolic links are not allowed")
                    if stat.S_ISDIR(mode):
                        try:
                            child_fd = os.open(
                                entry.name, _open_flags(directory=True), dir_fd=directory_fd
                            )
                        except OSError as exc:
                            raise OutputManifestError(
                                "directory path changed while scanning"
                            ) from exc
                        try:
                            opened = os.fstat(child_fd)
                            if _identity(path_info) != _identity(opened):
                                raise OutputManifestError("directory path changed while opening it")
                            walk(child_fd, (*parts, entry.name), depth + 1)
                            current = os.stat(
                                entry.name, dir_fd=directory_fd, follow_symlinks=False
                            )
                            if _directory_signature(opened) != _directory_signature(current):
                                raise OutputManifestError("directory path changed while scanning")
                        finally:
                            os.close(child_fd)
                    elif stat.S_ISREG(mode):
                        if relative in excluded:
                            signature = _ensure_stable_excluded_file(
                                directory_fd, entry.name, path_info
                            )
                            stable_files.append((entry.name, signature))
                            continue
                        if len(files) >= MAX_FILES:
                            raise OutputManifestError("workspace exceeds the manifest file limit")
                        digest, byte_count, signature = _hash_regular_file(
                            directory_fd,
                            entry.name,
                            path_info,
                            total_before=counters["total"],
                        )
                        stable_files.append((entry.name, signature))
                        if relative in paths:
                            raise OutputManifestError("duplicate manifest path encountered")
                        paths.add(relative)
                        counters["total"] += byte_count
                        files.append({"path": relative, "sha256": digest, "bytes": byte_count})
                    else:
                        raise OutputManifestError("special filesystem entries are not allowed")
            for name, expected_signature in stable_files:
                current_file = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if expected_signature != _file_signature(current_file):
                    raise OutputManifestError("file changed before its directory scan completed")
        except OSError as exc:
            raise OutputManifestError("could not safely scan workspace") from exc
        after_directory = os.fstat(directory_fd)
        if _directory_signature(before_directory) != _directory_signature(after_directory):
            raise OutputManifestError("directory changed while it was scanned")

    try:
        opened_root = os.fstat(root_fd)
        if _identity(root_info) != _identity(opened_root):
            raise OutputManifestError("workspace_root changed while opening it")
        walk(root_fd, (), 0)
        current_root = os.stat(root, follow_symlinks=False)
        if _directory_signature(opened_root) != _directory_signature(current_root):
            raise OutputManifestError("workspace_root path changed while scanning")
    finally:
        os.close(root_fd)
    files.sort(key=lambda item: item["path"])
    return {
        "schema": SCHEMA,
        "file_count": len(files),
        "total_bytes": counters["total"],
        "files": files,
    }


def _scan_workspace(workspace_root: Path, excluded: frozenset[str]) -> dict[str, Any]:
    # There is no portable transactional filesystem snapshot API. Requiring two
    # complete identical observations catches changes that land after an entry's
    # local post-read check but before the first traversal finishes.
    first = _scan_workspace_once(workspace_root, excluded)
    second = _scan_workspace_once(workspace_root, excluded)
    if first != second:
        raise OutputManifestError("workspace was not stable across consecutive scans")
    return second


def create_output_manifest(
    workspace_root: Path, *, exclude: set[str] | None = None
) -> tuple[dict, str]:
    """Create a canonical inventory for a trusted root and return it with its digest."""

    manifest = _scan_workspace(workspace_root, _validated_excludes(exclude))
    return manifest, manifest_digest(manifest)


def load_output_manifest(path: Path) -> dict:
    """Load bounded UTF-8 JSON while rejecting duplicate keys and unsafe file types."""

    raw = _read_manifest_file(path)
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_key_guard,
            parse_int=_bounded_json_int,
            parse_float=_reject_json_non_integer,
            parse_constant=_reject_json_non_integer,
        )
    except OutputManifestError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise OutputManifestError(f"invalid output manifest JSON: {exc}") from exc
    return _validate_manifest(parsed)


def save_output_manifest(data: dict, path: Path) -> None:
    """Atomically save canonical JSON without following a final-path symlink."""

    validated = _validate_manifest(data)
    payload = _canonical_bytes(validated) + b"\n"
    _require_secure_platform()
    destination = Path(path)
    parent = destination.parent.resolve(strict=True)
    if not parent.is_dir() or destination.name in {"", ".", ".."}:
        raise OutputManifestError("manifest destination must have an existing directory")
    parent_info = os.stat(parent, follow_symlinks=False)
    parent_fd = os.open(parent, _open_flags(directory=True))
    temp_name: str | None = None
    try:
        opened_parent = os.fstat(parent_fd)
        if _identity(parent_info) != _identity(opened_parent):
            raise OutputManifestError("manifest destination parent changed while opening")
        try:
            existing = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1):
            raise OutputManifestError(
                "existing manifest destination must be a non-linked regular file"
            )
        for _ in range(10):
            candidate = f".{destination.name}.{secrets.token_hex(8)}.tmp"
            try:
                fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent_fd,
                )
            except FileExistsError:
                continue
            temp_name = candidate
            break
        else:
            raise OutputManifestError("could not allocate a manifest temporary file")
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(
            temp_name,
            destination.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temp_name = None
        os.fsync(parent_fd)
        current_parent = os.stat(parent, follow_symlinks=False)
        if _identity(opened_parent) != _identity(current_parent):
            raise OutputManifestError("manifest destination parent path changed while saving")
    except OSError as exc:
        raise OutputManifestError("could not atomically save output manifest") from exc
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def verify_output_manifest(
    data: dict, workspace_root: Path, *, exclude: set[str] | None = None
) -> dict:
    """Re-scan a trusted root and require the exact declared set and contents."""

    try:
        expected = _validate_manifest(data)
        digest = manifest_digest(expected)
    except (OutputManifestError, TypeError, ValueError) as exc:
        return {"ok": False, "digest": None, "files": 0, "errors": [str(exc)]}

    try:
        observed, observed_digest = create_output_manifest(workspace_root, exclude=exclude)
    except (OSError, OutputManifestError, ValueError) as exc:
        return {
            "ok": False,
            "digest": digest,
            "files": 0,
            "expected_files": expected["file_count"],
            "errors": [str(exc)],
        }

    expected_by_path = {entry["path"]: entry for entry in expected["files"]}
    observed_by_path = {entry["path"]: entry for entry in observed["files"]}
    expected_paths = set(expected_by_path)
    observed_paths = set(observed_by_path)
    missing = sorted(expected_paths - observed_paths)
    unexpected = sorted(observed_paths - expected_paths)
    changed = sorted(
        path
        for path in expected_paths & observed_paths
        if expected_by_path[path] != observed_by_path[path]
    )
    errors: list[str] = []
    if missing:
        errors.append(f"missing files: {len(missing)}")
    if unexpected:
        errors.append(f"unexpected files: {len(unexpected)}")
    if changed:
        errors.append(f"changed files: {len(changed)}")
    return {
        "ok": not errors,
        "digest": digest,
        "observed_digest": observed_digest,
        "files": observed["file_count"],
        "expected_files": expected["file_count"],
        "total_bytes": observed["total_bytes"],
        "expected_total_bytes": expected["total_bytes"],
        "differences": {
            "missing": missing,
            "unexpected": unexpected,
            "changed": changed,
        },
        "errors": errors,
    }
