"""Build and defensively materialize filtered agent packets."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import math
import os
import stat
import tarfile
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .secrets import Finding, path_is_denied, redact_text, scan_text_for_secrets

SCHEMA = "agent-packet/v1"
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_DECOMPRESSED_ARCHIVE_BYTES = 160 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MEMBERS = 10_000
MAX_PAX_FIELDS = 4
MAX_PAX_FIELD_BYTES = 4_096
MAX_EXTENDED_HEADER_BYTES = 16 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_PAYLOAD_BYTES = 128 * 1024 * 1024
MAX_SELECTED_FILES = 2_000
MAX_INCLUDE_PATHS = 256
MAX_FINDINGS = 10_000
MAX_PATH_CHARS = 4_096
MAX_MANIFEST_STRING = 4_096
MAX_TASK_BYTES = 64 * 1024
MAX_META_BYTES = 32 * 1024
MAX_JSON_DEPTH = 8


@dataclass
class FileEntry:
    path: str
    sha256: str
    bytes: int
    redactions: int = 0
    mode: str = "text"


@dataclass
class PacketManifest:
    schema: str
    created_at: str
    task: str
    include: list[str]
    files: list[FileEntry]
    denied: dict[str, int]
    redactions: dict[str, int]
    warnings: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    # Kept as a return-value convenience only. It is deliberately not serialized:
    # embedding an archive hash in the archived manifest is self-referential.
    packet_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("packet_sha256", None)
        return data


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(value: str, *, label: str) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or len(value) > MAX_PATH_CHARS
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{label} must be a text path without control characters")
    value = value.replace("\\", "/")
    path = PurePosixPath(value)
    if (
        not value
        or not path.parts
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        raise ValueError(f"{label} must be a non-empty relative path without traversal")
    return path


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _resolved_output_path(path: Path) -> Path:
    """Resolve every existing ancestor before deciding whether it is in root."""
    absolute = path.absolute()
    suffix: list[str] = []
    cursor = absolute
    while not cursor.exists():
        suffix.append(cursor.name)
        cursor = cursor.parent
    resolved = cursor.resolve(strict=True)
    return resolved.joinpath(*reversed(suffix))


def _validate_json_data(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("meta exceeds maximum JSON nesting depth")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("meta numbers must be finite")
        return
    if isinstance(value, str):
        if scan_text_for_secrets(value, "metadata"):
            raise ValueError("task or meta contains secret-like content")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_data(item, depth=depth + 1)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            _validate_json_data(key, depth=depth + 1)
            _validate_json_data(item, depth=depth + 1)
        return
    raise ValueError("meta must contain JSON values only")


def _summary(findings: list[Finding] | list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        kind = finding.kind if isinstance(finding, Finding) else str(finding["kind"])
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _decode_text(data: bytes) -> str | None:
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _read_source_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("source file could not be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("source file is not a single-link regular file")
        if before.st_size > MAX_FILE_BYTES:
            raise ValueError("source file exceeds configured size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
        after = os.fstat(descriptor)
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("source file exceeds configured size limit")
        if (
            len(data) != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise ValueError("source file changed while it was being read")
        return data
    finally:
        os.close(descriptor)


def _has_symlink_component(path: Path, root: Path) -> bool:
    try:
        relative = path.absolute().relative_to(root.absolute())
    except ValueError:
        return True
    cursor = root
    for part in relative.parts:
        cursor /= part
        try:
            if stat.S_ISLNK(cursor.lstat().st_mode):
                return True
        except FileNotFoundError:
            return False
    return False


def _iter_files(
    root: Path, include: list[str], extra_deny_globs: list[str]
) -> tuple[list[Path], list[Finding], list[str]]:
    selected: dict[str, Path] = {}
    denied: list[Finding] = []
    accepted_includes: list[str] = []

    def deny(finding: Finding) -> None:
        denied.append(finding)
        if len(denied) > MAX_FINDINGS:
            raise ValueError("source produces too many denied findings")

    def select(path: Path, file_stat: os.stat_result) -> bool:
        if file_stat.st_nlink != 1:
            deny(
                Finding(
                    "hardlink_skipped",
                    "<omitted>",
                    "files with multiple hard links are never packetized",
                )
            )
            return False
        rel = path.relative_to(root).as_posix()
        try:
            normalized = _safe_relative(rel, label="selected file path").as_posix()
        except ValueError:
            deny(Finding("unsafe_path", "<omitted>", "path contains unsafe characters"))
            return False
        if normalized not in selected and len(selected) >= MAX_SELECTED_FILES:
            raise ValueError("selected file count exceeds configured limit")
        selected[normalized] = path
        return True

    for raw in include:
        if raw == ".":
            target = root
            normalized_include = "."
        else:
            rel = _safe_relative(raw, label="include path")
            target = root.joinpath(*rel.parts)
            normalized_include = rel.as_posix()
        try:
            st = target.lstat()
        except FileNotFoundError:
            deny(Finding("missing_include", "<omitted>", "include path does not exist"))
            continue
        if stat.S_ISLNK(st.st_mode) or _has_symlink_component(target, root):
            deny(Finding("symlink_skipped", "<omitted>", "symbolic links are never packetized"))
            continue
        target_deny = path_is_denied(target, root, extra_deny_globs)
        if target_deny:
            deny(target_deny)
            continue
        if stat.S_ISREG(st.st_mode):
            if select(target, st):
                accepted_includes.append(normalized_include)
            continue
        if not stat.S_ISDIR(st.st_mode):
            deny(
                Finding(
                    "special_file_skipped",
                    "<omitted>",
                    "only regular files are packetized",
                )
            )
            continue
        accepted_includes.append(normalized_include)
        for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
            current = Path(dirpath)
            for name in list(dirnames):
                candidate = current / name
                try:
                    directory_stat = candidate.lstat()
                except FileNotFoundError:
                    dirnames.remove(name)
                    deny(Finding("source_changed", "<omitted>", "source entry disappeared"))
                    continue
                if stat.S_ISLNK(directory_stat.st_mode):
                    dirnames.remove(name)
                    deny(
                        Finding(
                            "symlink_skipped",
                            "<omitted>",
                            "symbolic links are never packetized",
                        )
                    )
                    continue
                if not stat.S_ISDIR(directory_stat.st_mode):
                    dirnames.remove(name)
                    deny(
                        Finding(
                            "special_file_skipped",
                            "<omitted>",
                            "only real directories are traversed",
                        )
                    )
                    continue
                directory_deny = path_is_denied(candidate, root, extra_deny_globs)
                if directory_deny:
                    dirnames.remove(name)
                    deny(directory_deny)
            for name in sorted(filenames):
                candidate = current / name
                try:
                    file_stat = candidate.lstat()
                except FileNotFoundError:
                    deny(Finding("source_changed", "<omitted>", "source entry disappeared"))
                    continue
                if stat.S_ISLNK(file_stat.st_mode):
                    deny(
                        Finding(
                            "symlink_skipped",
                            "<omitted>",
                            "symbolic links are never packetized",
                        )
                    )
                elif stat.S_ISREG(file_stat.st_mode):
                    file_deny = path_is_denied(candidate, root, extra_deny_globs)
                    if file_deny:
                        deny(file_deny)
                    else:
                        select(candidate, file_stat)
                else:
                    deny(
                        Finding(
                            "special_file_skipped",
                            "<omitted>",
                            "only regular files are packetized",
                        )
                    )
    return (
        [selected[key] for key in sorted(selected)],
        denied,
        list(dict.fromkeys(accepted_includes)),
    )


def _prepare_empty_output(out_dir: Path, source_root: Path) -> None:
    if _is_within(out_dir, source_root):
        raise ValueError("output directory must not be inside the source root")
    if out_dir.exists():
        if out_dir.is_symlink() or not out_dir.is_dir():
            raise ValueError("output path must be a real directory")
        if any(out_dir.iterdir()):
            raise ValueError("output directory already contains files; refusing to overwrite it")
    else:
        out_dir.mkdir(parents=True)


def _manifest_bytes(manifest: PacketManifest) -> bytes:
    return (json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_archive(
    archive_path: Path,
    payload_dir: Path,
    manifest_data: bytes,
    entries: list[FileEntry],
) -> None:
    with tarfile.open(archive_path, "w:gz", format=tarfile.PAX_FORMAT) as tar:

        def add_bytes(name: str, data: bytes) -> None:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))

        add_bytes("manifest.json", manifest_data)
        for entry in entries:
            source = payload_dir.joinpath(*PurePosixPath(entry.path).parts)
            mode = source.lstat().st_mode
            if not stat.S_ISREG(mode):
                raise ValueError(f"staged payload changed before archiving: {entry.path}")
            data = source.read_bytes()
            if len(data) != entry.bytes or _sha256_bytes(data) != entry.sha256:
                raise ValueError(f"staged payload changed before archiving: {entry.path}")
            add_bytes("payload/" + entry.path, data)


def build_packet(
    *,
    task: str,
    source_root: Path,
    include: list[str],
    out_dir: Path,
    include_all: bool = False,
    extra_deny_globs: list[str] | None = None,
    meta: dict[str, Any] | None = None,
    allow_binary: bool = False,
    redact_secrets: bool = False,
) -> PacketManifest:
    if (
        not isinstance(include, list)
        or not include
        or len(include) > MAX_INCLUDE_PATHS
        or not all(isinstance(item, str) for item in include)
    ):
        raise ValueError("a bounded list of explicit include paths is required")
    if include_all:
        if include != ["."]:
            raise ValueError("include_all requires include=['.']")
    elif "." in include:
        raise ValueError("selecting the source root requires include_all=True")
    for item in include:
        if item != ".":
            _safe_relative(item, label="include path")
    if (
        not isinstance(task, str)
        or not task.strip()
        or len(task.encode("utf-8")) > MAX_TASK_BYTES
        or any(
            (ord(character) < 32 and character not in {"\n", "\t"}) or ord(character) == 127
            for character in task
        )
    ):
        raise ValueError("task must be non-empty text within the configured limits")
    if scan_text_for_secrets(task, "task"):
        raise ValueError("task contains secret-like content")
    if meta is not None and not isinstance(meta, dict):
        raise ValueError("meta must be a JSON object")
    _validate_json_data(meta or {})
    if (
        len(json.dumps(meta or {}, separators=(",", ":"), allow_nan=False).encode("utf-8"))
        > MAX_META_BYTES
    ):
        raise ValueError("meta exceeds configured size limit")
    deny_globs = extra_deny_globs or []
    if (
        not isinstance(deny_globs, list)
        or len(deny_globs) > MAX_INCLUDE_PATHS
        or not all(
            isinstance(pattern, str) and len(pattern) <= MAX_PATH_CHARS for pattern in deny_globs
        )
    ):
        raise ValueError("deny globs must be a bounded list of strings")
    source_root = source_root.resolve(strict=True)
    if not source_root.is_dir():
        raise ValueError("source root must be a directory")
    out_dir = _resolved_output_path(out_dir)
    _prepare_empty_output(out_dir, source_root)
    payload_dir = out_dir / "payload"
    payload_dir.mkdir()
    files, unsafe, accepted_includes = _iter_files(source_root, include, deny_globs)
    denied: list[Finding] = list(unsafe)
    redactions: list[dict] = []
    entries: list[FileEntry] = []
    total = 0

    def record_denied(findings: Finding | list[Finding]) -> None:
        denied.extend(findings if isinstance(findings, list) else [findings])
        if len(denied) > MAX_FINDINGS:
            raise ValueError("source produces too many denied findings")

    for f in files:
        rel = f.relative_to(source_root).as_posix()
        if rel == "TASK.md":
            record_denied(
                Finding("reserved_path", rel, "TASK.md is generated by the packet builder")
            )
            continue
        try:
            source_data = _read_source_bytes(f)
        except ValueError as exc:
            kind = "size_limit" if "size limit" in str(exc) else "source_changed"
            record_denied(Finding(kind, rel, str(exc)))
            continue
        raw = _decode_text(source_data)
        if raw is None:
            if not allow_binary:
                record_denied(
                    Finding(
                        "binary_skipped",
                        rel,
                        "binary file skipped (pass --allow-binary to include)",
                    )
                )
                continue
            data = source_data
            mode = "binary"
            count = 0
        else:
            findings = scan_text_for_secrets(raw, rel)
            if findings and not redact_secrets:
                record_denied(findings)
                continue
            cleaned, count = redact_text(raw) if findings else (raw, 0)
            for finding in findings:
                redactions.append(
                    {
                        "kind": finding.kind,
                        "path": finding.path,
                        "detail": finding.detail,
                        "line": finding.line,
                    }
                )
                if len(redactions) > MAX_FINDINGS:
                    raise ValueError("source produces too many redaction findings")
            data = cleaned.encode("utf-8")
            mode = "text"
        if len(data) > MAX_FILE_BYTES or total + len(data) > MAX_PAYLOAD_BYTES:
            record_denied(
                Finding("size_limit", rel, "transformed file or packet exceeds size limit")
            )
            continue
        dest = payload_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        total += len(data)
        entries.append(FileEntry(rel, _sha256_bytes(data), len(data), count, mode))

    task_body = (
        f"# Task\n\n{task.strip()}\n\n"
        "## Packet rules\n"
        "- Work only inside the materialised payload directory.\n"
        "- Do not request secrets or private paths outside this packet.\n"
        "- Return results + an agent-receipt if available.\n"
    )
    task_data = task_body.encode("utf-8")
    if total + len(task_data) > MAX_PAYLOAD_BYTES:
        raise ValueError("generated task would exceed the packet payload size limit")
    (payload_dir / "TASK.md").write_bytes(task_data)
    entries.insert(0, FileEntry("TASK.md", _sha256_bytes(task_data), len(task_data)))
    transported_paths = [PurePosixPath(entry.path) for entry in entries[1:]]
    transported_includes = [
        included
        for included in accepted_includes
        if included == "."
        or any(
            PurePosixPath(included) == path or PurePosixPath(included) in path.parents
            for path in transported_paths
        )
    ]
    warnings = ["no files matched include paths"] if not entries[1:] and not denied else []
    # Omitted paths and detector details are intentionally local-only: the archive
    # carries counts, preventing the manifest from becoming a privacy side channel.
    manifest = PacketManifest(
        SCHEMA,
        datetime.now(timezone.utc).isoformat(),
        task.strip(),
        transported_includes,
        entries,
        _summary(denied),
        _summary(redactions),
        warnings,
        meta or {},
    )
    manifest_data = _manifest_bytes(manifest)
    if len(manifest_data) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest exceeds configured size limit")
    (out_dir / "manifest.json").write_bytes(manifest_data)
    archive_path = out_dir / "packet.tar.gz"
    _write_archive(archive_path, payload_dir, manifest_data, entries)
    manifest.packet_sha256 = _sha256_file(archive_path)
    (out_dir / "PACKET_SHA256.txt").write_text(
        manifest.packet_sha256 + "  packet.tar.gz\n", encoding="ascii"
    )
    return manifest


def _validate_manifest(man: Any) -> dict[str, Any]:
    if not isinstance(man, dict) or set(man) != {
        "schema",
        "created_at",
        "task",
        "include",
        "files",
        "denied",
        "redactions",
        "warnings",
        "meta",
    }:
        raise ValueError("invalid manifest schema or fields")
    if (
        man["schema"] != SCHEMA
        or not isinstance(man["created_at"], str)
        or len(man["created_at"]) > 128
        or not isinstance(man["task"], str)
        or not isinstance(man["include"], list)
        or not isinstance(man["files"], list)
        or not isinstance(man["denied"], dict)
        or not isinstance(man["redactions"], dict)
        or not isinstance(man["warnings"], list)
        or not isinstance(man["meta"], dict)
        or len(man["files"]) > MAX_SELECTED_FILES + 1
        or len(man["include"]) > MAX_INCLUDE_PATHS
        or len(man["warnings"]) > MAX_FINDINGS
    ):
        raise ValueError("invalid manifest values")
    try:
        datetime.fromisoformat(man["created_at"].replace("Z", "+00:00"))
        _validate_json_data(man["meta"])
    except (TypeError, ValueError):
        raise ValueError("invalid manifest values") from None
    if (
        not man["task"].strip()
        or len(man["task"].encode("utf-8")) > MAX_TASK_BYTES
        or any(
            (ord(character) < 32 and character not in {"\n", "\t"}) or ord(character) == 127
            for character in man["task"]
        )
        or scan_text_for_secrets(man["task"], "task")
        or len(json.dumps(man["meta"], separators=(",", ":")).encode("utf-8")) > MAX_META_BYTES
    ):
        raise ValueError("invalid manifest values")
    if (
        any(
            not isinstance(item, str)
            or (
                item != "."
                and (
                    _safe_relative(item, label="manifest include").as_posix() != item
                    or bool(scan_text_for_secrets(item, item))
                )
            )
            for item in man["include"]
        )
        or any(
            not isinstance(key, str)
            or len(key) > 128
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > MAX_FINDINGS
            for key, value in man["denied"].items()
        )
        or any(
            not isinstance(key, str)
            or len(key) > 128
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > MAX_FINDINGS
            for key, value in man["redactions"].items()
        )
        or any(
            not isinstance(item, str)
            or len(item) > MAX_MANIFEST_STRING
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in man["warnings"]
        )
    ):
        raise ValueError("invalid manifest values")
    seen: set[str] = set()
    payload_bytes = 0
    for entry in man["files"]:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "sha256",
            "bytes",
            "redactions",
            "mode",
        }:
            raise ValueError("invalid manifest file entry")
        path = _safe_relative(entry["path"], label="manifest file path").as_posix()
        if (
            path in seen
            or not isinstance(entry["bytes"], int)
            or isinstance(entry["bytes"], bool)
            or entry["bytes"] < 0
            or entry["bytes"] > MAX_FILE_BYTES
            or not isinstance(entry["mode"], str)
            or entry["mode"] not in {"text", "binary"}
            or not isinstance(entry["sha256"], str)
            or len(entry["sha256"]) != 64
            or any(char not in "0123456789abcdef" for char in entry["sha256"])
            or not isinstance(entry["redactions"], int)
            or isinstance(entry["redactions"], bool)
            or entry["redactions"] < 0
            or entry["redactions"] > MAX_FINDINGS
            or bool(scan_text_for_secrets(path, path))
        ):
            raise ValueError("invalid manifest file entry")
        seen.add(path)
        payload_bytes += entry["bytes"]
    transported_paths = [PurePosixPath(item["path"]) for item in man["files"][1:]]
    if (
        not man["files"]
        or man["files"][0]["path"] != "TASK.md"
        or man["files"][0]["mode"] != "text"
        or payload_bytes > MAX_PAYLOAD_BYTES
        or len(set(man["include"])) != len(man["include"])
        or any(
            included != "."
            and not any(
                PurePosixPath(included) == path or PurePosixPath(included) in path.parents
                for path in transported_paths
            )
            for included in man["include"]
        )
    ):
        raise ValueError("manifest must begin with a bounded text TASK.md")
    return man


def _validate_member(member: tarfile.TarInfo) -> str:
    if "\\" in member.name:
        raise ValueError("archive contains an unsafe member path")
    try:
        name = _safe_relative(member.name, label="archive member").as_posix()
    except ValueError as exc:
        raise ValueError("archive contains an unsafe member path") from exc
    if not member.isfile():
        raise ValueError("archive contains a non-regular member")
    if getattr(member, "sparse", None):
        raise ValueError("archive contains a sparse member")
    if member.size < 0 or member.size > MAX_FILE_BYTES:
        raise ValueError("archive member exceeds its size limit")
    return name


class _BoundedTarInfo(tarfile.TarInfo):
    """Reject hidden tar extensions before tarfile reads them into memory."""

    def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        extended_types = {
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.SOLARIS_XHDTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
        }
        if self.type == tarfile.GNUTYPE_SPARSE:
            raise ValueError("sparse archive members are not supported")
        if self.type in extended_types and (self.size < 0 or self.size > MAX_EXTENDED_HEADER_BYTES):
            raise ValueError("extended tar header exceeds its size limit")
        return super()._proc_member(archive)


def _validate_pax_headers(member: tarfile.TarInfo) -> None:
    headers = member.pax_headers
    if len(headers) > MAX_PAX_FIELDS or set(headers) - {"path"}:
        raise ValueError("archive member has unsupported PAX metadata")
    for key, value in headers.items():
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or len(key.encode("utf-8")) > 64
            or len(value.encode("utf-8")) > MAX_PAX_FIELD_BYTES
        ):
            raise ValueError("archive member has oversized PAX metadata")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("manifest contains a duplicate JSON key")
        result[key] = value
    return result


def _tail_is_zero_filled(source: Path, offset: int) -> bool:
    with source.open("rb") as handle:
        handle.seek(offset)
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            if any(chunk):
                return False
    return True


def _read_verified_tar(source: Path, output_dir: Path | None = None) -> dict[str, Any]:
    """Parse a size-bounded, already decompressed tar snapshot."""
    try:
        tar = tarfile.open(source, "r:", tarinfo=_BoundedTarInfo)
    except (OSError, tarfile.TarError) as exc:
        raise ValueError("packet is not a valid tar archive") from exc
    with tar:
        total = 0
        names: set[str] = set()
        expected: set[str] | None = None
        expected_entries: dict[str, dict[str, Any]] = {}
        manifest: dict[str, Any] | None = None
        for count, member in enumerate(tar, start=1):
            if count > MAX_MEMBERS:
                raise ValueError("archive has too many members")
            _validate_pax_headers(member)
            name = _validate_member(member)
            if name in names:
                raise ValueError("archive contains duplicate member names")
            names.add(name)
            if count == 1 and (name != "manifest.json" or member.size > MAX_MANIFEST_BYTES):
                raise ValueError("manifest.json must be the first bounded archive member")
            total += member.size
            if total > MAX_PAYLOAD_BYTES + MAX_MANIFEST_BYTES:
                raise ValueError("archive exceeds total declared size limit")
            stream = tar.extractfile(member)
            if stream is None:
                raise ValueError("archive member could not be read")
            data = stream.read(member.size + 1)
            if len(data) != member.size:
                raise ValueError("archive member has an invalid size")
            if count == 1:
                try:
                    loaded = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json_object)
                    manifest = _validate_manifest(loaded)
                except (UnicodeError, ValueError, RecursionError) as exc:
                    raise ValueError("manifest.json is invalid") from exc
                expected_entries = {"payload/" + item["path"]: item for item in manifest["files"]}
                expected = {"manifest.json", *expected_entries}
            elif manifest is None:
                raise ValueError("manifest.json must be first")
            elif name not in expected_entries:
                raise ValueError("archive contains an undeclared member")
            if name != "manifest.json":
                entry = expected_entries[name]
                if len(data) != entry["bytes"] or _sha256_bytes(data) != entry["sha256"]:
                    raise ValueError("payload hash mismatch")
            if output_dir is not None:
                target = output_dir.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        if manifest is None or expected != names:
            raise ValueError("archive files do not exactly match manifest")
        tail_offset = tar.offset
    if not _tail_is_zero_filled(source, tail_offset):
        raise ValueError("archive contains non-zero data after its final member")
    return manifest


def _read_verified_archive(source: Path, output_dir: Path | None = None) -> dict[str, Any]:
    try:
        return _read_verified_tar(source, output_dir)
    except tarfile.TarError as exc:
        raise ValueError("packet has an invalid tar structure") from exc


def _snapshot_archive(source: Path, destination: Path) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if source.is_symlink():
        raise ValueError("packet archive may not be a symbolic link")
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise ValueError("packet archive could not be opened safely") from exc
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        path_stat = os.stat(source, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(path_stat.st_mode)
            or before.st_dev != path_stat.st_dev
            or before.st_ino != path_stat.st_ino
            or before.st_size <= 0
            or before.st_size > MAX_ARCHIVE_BYTES
        ):
            raise ValueError("invalid or oversized packet archive")
        total = 0
        with (
            os.fdopen(descriptor, "rb", closefd=False) as input_handle,
            destination.open("xb") as output_handle,
        ):
            for chunk in iter(lambda: input_handle.read(1024 * 1024), b""):
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError("invalid or oversized packet archive")
                digest.update(chunk)
                output_handle.write(chunk)
        after = os.fstat(descriptor)
        if (
            total != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            raise ValueError("packet archive changed while it was being read")
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _decompress_archive(source: Path, destination: Path) -> None:
    total = 0
    try:
        with gzip.open(source, "rb") as input_handle, destination.open("xb") as output_handle:
            for chunk in iter(lambda: input_handle.read(1024 * 1024), b""):
                total += len(chunk)
                if total > MAX_DECOMPRESSED_ARCHIVE_BYTES:
                    raise ValueError("decompressed packet archive exceeds its size limit")
                output_handle.write(chunk)
    except (EOFError, OSError) as exc:
        raise ValueError("packet is not a valid gzip archive") from exc


def _prepare_snapshot(source: Path, directory: Path) -> tuple[Path, str]:
    compressed = directory / "packet.snapshot.tar.gz"
    uncompressed = directory / "packet.snapshot.tar"
    archive_hash = _snapshot_archive(source, compressed)
    _decompress_archive(compressed, uncompressed)
    return uncompressed, archive_hash


def _fresh_destination(dest: Path) -> Path:
    requested = Path(os.path.abspath(os.fspath(dest)))
    if requested.exists() or requested.is_symlink():
        raise ValueError("destination already exists; refusing to overwrite it")
    if not requested.parent.is_dir():
        raise ValueError("destination parent must already exist")
    resolved_parent = requested.parent.resolve(strict=True)
    if not resolved_parent.is_dir():
        raise ValueError("destination parent must resolve to a real directory")
    canonical = resolved_parent / requested.name
    if canonical.exists() or canonical.is_symlink():
        raise ValueError("canonical destination already exists; refusing to overwrite it")
    return canonical


def inspect_packet(packet: Path) -> tuple[dict[str, Any], str | None]:
    source = Path(os.path.abspath(os.fspath(packet)))
    with tempfile.TemporaryDirectory(prefix=".agent-packet-inspect-") as temporary:
        archive, archive_hash = _prepare_snapshot(source, Path(temporary))
        return _read_verified_archive(archive), archive_hash


def materialize_packet(
    archive_or_dir: Path,
    dest: Path,
    *,
    expect_sha256: str | None = None,
    accept_untrusted_archive: bool = False,
) -> dict[str, Any]:
    source = Path(os.path.abspath(os.fspath(archive_or_dir)))
    dest = _fresh_destination(dest)
    if expect_sha256 is not None and accept_untrusted_archive:
        raise ValueError("expected sha256 and untrusted-archive opt-in are mutually exclusive")
    if expect_sha256 is None and not accept_untrusted_archive:
        raise ValueError(
            "an independently obtained expected sha256 is required; "
            "set accept_untrusted_archive=True only for isolated structural inspection"
        )
    normalized_hash: str | None = None
    if expect_sha256 is not None:
        if (
            not isinstance(expect_sha256, str)
            or len(expect_sha256) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in expect_sha256)
        ):
            raise ValueError("expected packet sha256 must be exactly 64 hexadecimal characters")
        normalized_hash = expect_sha256.lower()
    with tempfile.TemporaryDirectory(prefix=".agent-packet-", dir=dest.parent) as temporary:
        temporary_root = Path(temporary)
        compressed = temporary_root / "packet.snapshot.tar.gz"
        archive = temporary_root / "packet.snapshot.tar"
        actual_hash = _snapshot_archive(source, compressed)
        if normalized_hash is not None and actual_hash != normalized_hash:
            raise ValueError("packet sha256 mismatch")
        _decompress_archive(compressed, archive)
        stage = temporary_root / "materialized"
        stage.mkdir()
        man = _read_verified_archive(archive, stage)
        result = {
            "ok": True,
            "dest": str(dest),
            "files": len(man["files"]),
            "denied": sum(man["denied"].values()),
            "redactions": sum(man["redactions"].values()),
            "mismatches": [],
            "task": man["task"],
            "schema": man["schema"],
            "archive_sha256": actual_hash,
        }
        (stage / "materialize-report.json").write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        _fresh_destination(dest)
        stage.rename(dest)
    return result
