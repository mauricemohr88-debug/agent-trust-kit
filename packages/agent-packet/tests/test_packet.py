from __future__ import annotations

import io
import json
import math
import tarfile
from pathlib import Path

import pytest

from agent_packet import builder as packet_builder
from agent_packet.builder import build_packet, inspect_packet, materialize_packet
from agent_packet.cli import main
from agent_packet.secrets import redact_text, scan_text_for_secrets

OPENAI_TEST_KEY = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
ANTHROPIC_TEST_KEY = "sk-ant-" + "abcdefghijklmnopqrstuvwxyz123456"


def _build(tmp_path: Path, *, secret: bool = False, redact: bool = False):
    root = tmp_path / "ws"
    root.mkdir(parents=True)
    (root / "readme.md").write_text("# hi\n", encoding="utf-8")
    if secret:
        (root / "config.py").write_text(f'OPENAI_API_KEY="{OPENAI_TEST_KEY}"\n', encoding="utf-8")
    out = tmp_path / "packet"
    return (
        build_packet(
            task="Do the thing",
            source_root=root,
            include=["."],
            out_dir=out,
            include_all=True,
            redact_secrets=redact,
        ),
        out,
        root,
    )


def _evil_archive(path: Path, members: list[tuple[str, bytes, str]]) -> None:
    with tarfile.open(path, "w:gz") as tar:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "target"
            else:
                info.size = len(data)
            tar.addfile(info, None if kind == "symlink" else io.BytesIO(data))


def test_redact_openai_key():
    out, n = redact_text(f'api_key = "{OPENAI_TEST_KEY}"')
    assert n >= 1 and "sk-abc" not in out and "REDACTED" in out

    out, n = redact_text("DATABASE_URL=postgres://alice:correct-horse@db.example/app")
    assert n == 1 and "alice" not in out and "correct-horse" not in out


def test_anthropic_key_is_not_misclassified_as_openai():
    findings = scan_text_for_secrets(
        f"ANTHROPIC_API_KEY={ANTHROPIC_TEST_KEY}",
        "config.py",
    )

    assert [finding.kind for finding in findings] == ["anthropic_key"]


def test_secret_file_is_blocked_unless_redaction_opted_in(tmp_path: Path):
    man, out, _ = _build(tmp_path, secret=True)
    assert "config.py" not in {entry.path for entry in man.files}
    assert man.denied["openai_key"] >= 1
    assert "sk-abc" not in (out / "manifest.json").read_text()
    man, out, _ = _build(tmp_path / "redacted", secret=True, redact=True)
    assert "config.py" in {entry.path for entry in man.files}
    assert "sk-abc" not in (out / "payload" / "config.py").read_text()


def test_manifest_is_private_and_hash_is_external(tmp_path: Path):
    man, out, root = _build(tmp_path)
    data = json.loads((out / "manifest.json").read_text())
    assert str(root) not in json.dumps(data)
    assert "source_root" not in data and "packet_sha256" not in data
    assert (out / "PACKET_SHA256.txt").read_text().split()[0] == man.packet_sha256


def test_rejects_escape_include_and_nonempty_output(tmp_path: Path):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "a.txt").write_text("ok")
    with pytest.raises(ValueError, match="traversal"):
        build_packet(task="x", source_root=root, include=["../outside"], out_dir=tmp_path / "out")
    out = tmp_path / "occupied"
    out.mkdir()
    (out / "keep").write_text("keep")
    with pytest.raises(ValueError, match="refusing"):
        build_packet(task="x", source_root=root, include=["a.txt"], out_dir=out)


@pytest.mark.parametrize("root_alias", [".", "./", ".//", ".\\"])
def test_full_root_requires_visible_include_all_decision(tmp_path: Path, root_alias: str):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "a.txt").write_text("ok", encoding="utf-8")
    out = tmp_path / "packet"
    with pytest.raises(SystemExit):
        main(
            [
                "build",
                "--task",
                "x",
                "--root",
                str(root),
                "--include",
                root_alias,
                "--out",
                str(out),
            ]
        )
    assert not out.exists()


def test_library_full_root_requires_include_all_flag(tmp_path: Path):
    root = tmp_path / "ws"
    root.mkdir()
    with pytest.raises(ValueError, match="include_all"):
        build_packet(task="x", source_root=root, include=["."], out_dir=tmp_path / "packet")


def test_symlink_never_enters_payload(tmp_path: Path):
    _man, _out, root = _build(tmp_path)
    (root / "linked").symlink_to(root / "readme.md")
    # fresh output, as a build output must be empty/new
    out2 = tmp_path / "packet2"
    man = build_packet(task="x", source_root=root, include=["."], out_dir=out2, include_all=True)
    assert "linked" not in {entry.path for entry in man.files}
    assert man.denied["symlink_skipped"] >= 1


def test_symlink_ancestor_and_hardlink_never_enter_payload(tmp_path: Path):
    root = tmp_path / "ws"
    public = root / "public"
    public.mkdir(parents=True)
    (public / "ok.txt").write_text("ok", encoding="utf-8")
    path_marker = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
    (root / path_marker).symlink_to(public, target_is_directory=True)

    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (root / "hardlinked.txt").hardlink_to(outside)

    out = tmp_path / "packet"
    man = build_packet(
        task="x",
        source_root=root,
        include=[f"{path_marker}/ok.txt", "hardlinked.txt"],
        out_dir=out,
    )
    manifest_text = (out / "manifest.json").read_text(encoding="utf-8")
    assert man.include == []
    assert path_marker not in manifest_text
    assert "hardlinked.txt" not in manifest_text
    assert {entry.path for entry in man.files} == {"TASK.md"}
    assert man.denied["symlink_skipped"] == 1
    assert man.denied["hardlink_skipped"] == 1


def test_denied_paths_and_content_do_not_leak_into_manifest(tmp_path: Path):
    root = tmp_path / "ws"
    root.mkdir()
    private = root / "private"
    private.mkdir()
    (private / "family-client-acme.md").write_text("private", encoding="utf-8")
    path_marker = "sk-" + "abcdefghijklmnopqrstuvwxyz123456.txt"
    (root / path_marker).write_text("name is sensitive", encoding="utf-8")
    (root / ".envrc").write_text(
        "export DATABASE_URL=postgres://user:password@db.example/app\n",
        encoding="utf-8",
    )
    (root / "config.txt").write_text(
        "DATABASE_URL=postgres://user:password@db.example/app\n",
        encoding="utf-8",
    )
    family_name = "family-budget-2026.txt"
    (root / family_name).write_text('password="abcdefgh"\n', encoding="utf-8")

    out = tmp_path / "packet"
    man = build_packet(
        task="x",
        source_root=root,
        include=["."],
        out_dir=out,
        include_all=True,
    )
    manifest_text = (out / "manifest.json").read_text(encoding="utf-8")
    for marker in ("family-client-acme", path_marker, ".envrc", "config.txt", family_name):
        assert marker not in manifest_text
    assert {entry.path for entry in man.files} == {"TASK.md"}
    assert man.include == ["."]
    assert man.denied["url_credentials"] == 1

    explicit_out = tmp_path / "explicit"
    explicit = build_packet(
        task="x",
        source_root=root,
        include=[family_name],
        out_dir=explicit_out,
    )
    assert explicit.include == []
    assert family_name not in (explicit_out / "manifest.json").read_text(encoding="utf-8")


def test_sensitive_path_components_are_denied_at_every_depth(tmp_path: Path):
    root = tmp_path / "ws"
    root.mkdir()
    path_marker = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
    components = [".envrc", "x.pem", "credentials.json", "secret-vault", path_marker]
    includes = []
    for component in components:
        directory = root / component
        directory.mkdir()
        (directory / "notes.txt").write_text("ordinary", encoding="utf-8")
        includes.append(f"{component}/notes.txt")
    out = tmp_path / "packet"
    man = build_packet(task="x", source_root=root, include=includes, out_dir=out)
    manifest_text = (out / "manifest.json").read_text(encoding="utf-8")
    assert man.include == []
    assert {entry.path for entry in man.files} == {"TASK.md"}
    assert all(component not in manifest_text for component in components)


def test_control_character_filename_is_omitted(tmp_path: Path):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "bad\nname.txt").write_text("not transported", encoding="utf-8")
    man = build_packet(
        task="x",
        source_root=root,
        include=["."],
        out_dir=tmp_path / "packet",
        include_all=True,
    )
    assert all("\n" not in entry.path for entry in man.files)
    assert man.denied["unsafe_path"] == 1


def test_default_denied_directories_are_pruned_before_file_limit(tmp_path: Path):
    root = tmp_path / "ws"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
    dependency_dir = root / "node_modules" / "many"
    dependency_dir.mkdir(parents=True)
    for index in range(2_010):
        (dependency_dir / f"{index}.js").write_text("x", encoding="utf-8")

    man = build_packet(
        task="x",
        source_root=root,
        include=["."],
        out_dir=tmp_path / "packet",
        include_all=True,
    )
    assert "src/app.py" in {entry.path for entry in man.files}
    assert man.denied["denied_path"] == 1


def test_materialize_roundtrip_and_expected_hash(tmp_path: Path):
    man, out, _ = _build(tmp_path)
    dest = tmp_path / "sandbox"
    report = materialize_packet(out / "packet.tar.gz", dest, expect_sha256=man.packet_sha256)
    assert report["ok"] is True and report["archive_sha256"] == man.packet_sha256
    assert (dest / "payload" / "readme.md").exists()
    assert json.loads((dest / "materialize-report.json").read_text())["ok"] is True


@pytest.mark.parametrize(
    "name,kind", [("../escape", "file"), ("payload/link", "symlink"), ("payload/readme.md", "file")]
)
def test_materialize_rejects_malicious_tar(tmp_path: Path, name: str, kind: str):
    archive = tmp_path / "evil.tar.gz"
    # No valid manifest is needed for these structural rejections; duplicate requires one.
    if name == "payload/readme.md":
        manifest = {
            "schema": "agent-packet/v1",
            "created_at": "x",
            "task": "x",
            "include": ["."],
            "files": [
                {"path": "TASK.md", "sha256": "0" * 64, "bytes": 0, "redactions": 0, "mode": "text"}
            ],
            "denied": {},
            "redactions": {},
            "warnings": [],
            "meta": {},
        }
        _evil_archive(
            archive,
            [
                ("manifest.json", json.dumps(manifest).encode(), "file"),
                ("payload/TASK.md", b"", "file"),
                ("payload/TASK.md", b"", "file"),
            ],
        )
    else:
        _evil_archive(archive, [(name, b"x", kind)])
    with pytest.raises(ValueError):
        materialize_packet(archive, tmp_path / "dest", accept_untrusted_archive=True)


def test_materialize_refuses_existing_destination_and_extra_file(tmp_path: Path):
    _man, out, _ = _build(tmp_path)
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "keep").write_text("keep")
    with pytest.raises(ValueError, match="already exists"):
        materialize_packet(out / "packet.tar.gz", dest)
    assert (dest / "keep").read_text() == "keep"
    # An archive with an unlisted regular payload file cannot be materialized.
    tampered = tmp_path / "tampered.tar.gz"
    with tarfile.open(out / "packet.tar.gz", "r:gz") as src, tarfile.open(tampered, "w:gz") as dst:
        for member in src.getmembers():
            data = src.extractfile(member).read() if member.isfile() else None
            dst.addfile(member, io.BytesIO(data) if data is not None else None)
        extra = tarfile.TarInfo("payload/unlisted.txt")
        extra.size = 1
        dst.addfile(extra, io.BytesIO(b"x"))
    with pytest.raises(ValueError, match="undeclared member"):
        materialize_packet(tampered, tmp_path / "fresh", accept_untrusted_archive=True)


def test_build_and_materialize_require_explicit_trust_decisions(tmp_path: Path):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "a.txt").write_text("ok", encoding="utf-8")
    with pytest.raises(ValueError, match="include paths"):
        build_packet(task="x", source_root=root, include=[], out_dir=tmp_path / "packet")

    man, out, _ = _build(tmp_path / "built")
    with pytest.raises(ValueError, match="expected sha256"):
        materialize_packet(out / "packet.tar.gz", tmp_path / "dest")
    for index, invalid_digest in enumerate(("", "0" * 63, "g" * 64)):
        with pytest.raises(ValueError, match="64 hexadecimal"):
            materialize_packet(
                out / "packet.tar.gz",
                tmp_path / f"invalid-{index}",
                expect_sha256=invalid_digest,
            )
    report = materialize_packet(
        out / "packet.tar.gz",
        tmp_path / "accepted",
        expect_sha256=man.packet_sha256,
    )
    assert report["ok"] is True


def test_task_and_meta_secrets_are_blocked(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("ok")
    with pytest.raises(ValueError, match="secret-like"):
        build_packet(
            task=f"use {OPENAI_TEST_KEY}",
            source_root=root,
            include=["."],
            out_dir=tmp_path / "a",
            include_all=True,
        )
    with pytest.raises(ValueError, match="secret-like"):
        build_packet(
            task="x",
            source_root=root,
            include=["."],
            out_dir=tmp_path / "b",
            include_all=True,
            meta={"token": OPENAI_TEST_KEY},
        )

    with pytest.raises(ValueError, match="finite"):
        build_packet(
            task="x",
            source_root=root,
            include=["."],
            out_dir=tmp_path / "c",
            include_all=True,
            meta={"measurement": math.nan},
        )


def test_inspect_uses_verified_archive_parser(tmp_path: Path):
    man, out, _ = _build(tmp_path)
    inspected, digest = inspect_packet(out / "packet.tar.gz")
    assert inspected["files"][0]["path"] == "TASK.md" and digest == man.packet_sha256


def test_materialize_uses_hashed_snapshot_when_source_path_is_replaced(tmp_path: Path, monkeypatch):
    man_a, out_a, _ = _build(tmp_path / "a")
    root_b = tmp_path / "b" / "ws"
    root_b.mkdir(parents=True)
    (root_b / "readme.md").write_text("replacement-B\n", encoding="utf-8")
    out_b = tmp_path / "b" / "packet"
    build_packet(
        task="Do the thing",
        source_root=root_b,
        include=["."],
        out_dir=out_b,
        include_all=True,
    )
    original_decompress = packet_builder._decompress_archive

    def replace_then_decompress(snapshot: Path, destination: Path) -> None:
        (out_a / "packet.tar.gz").write_bytes((out_b / "packet.tar.gz").read_bytes())
        original_decompress(snapshot, destination)

    monkeypatch.setattr(packet_builder, "_decompress_archive", replace_then_decompress)
    dest = tmp_path / "materialized"
    report = materialize_packet(
        out_a / "packet.tar.gz",
        dest,
        expect_sha256=man_a.packet_sha256,
    )
    assert report["archive_sha256"] == man_a.packet_sha256
    assert (dest / "payload" / "readme.md").read_text(encoding="utf-8") == "# hi\n"


def test_materialize_uses_canonical_parent_when_destination_has_symlink_ancestor(tmp_path: Path):
    man, out, _ = _build(tmp_path / "built")
    real = tmp_path / "real"
    nested = real / "nested"
    nested.mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    dest = alias / "nested" / "dest"
    report = materialize_packet(out / "packet.tar.gz", dest, expect_sha256=man.packet_sha256)
    canonical_dest = real / "nested" / "dest"
    assert Path(report["dest"]) == canonical_dest
    assert canonical_dest.is_dir()


@pytest.mark.parametrize("pax_size", [5_000, 20_000])
def test_hidden_pax_metadata_is_bounded_and_rejected(tmp_path: Path, pax_size: int):
    _man, out, _ = _build(tmp_path)
    archive = tmp_path / f"pax-{pax_size}.tar.gz"
    with (
        tarfile.open(out / "packet.tar.gz", "r:gz") as source,
        tarfile.open(
            archive,
            "w:gz",
            format=tarfile.PAX_FORMAT,
            pax_headers={"comment": "x" * pax_size},
        ) as target,
    ):
        for member in source.getmembers():
            stream = source.extractfile(member)
            target.addfile(member, stream)
    with pytest.raises(ValueError):
        materialize_packet(archive, tmp_path / "dest", accept_untrusted_archive=True)


def test_decompressed_archive_limit_counts_hidden_tar_bytes(tmp_path: Path, monkeypatch):
    man, out, _ = _build(tmp_path)
    monkeypatch.setattr(packet_builder, "MAX_DECOMPRESSED_ARCHIVE_BYTES", 1_024)
    with pytest.raises(ValueError, match="decompressed"):
        materialize_packet(
            out / "packet.tar.gz",
            tmp_path / "dest",
            expect_sha256=man.packet_sha256,
        )


def test_digest_mismatch_is_rejected_before_decompression(tmp_path: Path, monkeypatch):
    _man, out, _ = _build(tmp_path)

    def must_not_run(_source: Path, _destination: Path) -> None:
        pytest.fail("digest mismatch must be rejected before decompression")

    monkeypatch.setattr(packet_builder, "_decompress_archive", must_not_run)
    with pytest.raises(ValueError, match="sha256 mismatch"):
        materialize_packet(
            out / "packet.tar.gz",
            tmp_path / "dest",
            expect_sha256="0" * 64,
        )


def test_post_transform_size_is_rechecked_before_archiving(tmp_path: Path, monkeypatch):
    root = tmp_path / "ws"
    root.mkdir()
    (root / "expand.txt").write_text('password="abcdefgh"\n' * 25, encoding="utf-8")
    original_limit = packet_builder.MAX_FILE_BYTES
    monkeypatch.setattr(packet_builder, "MAX_FILE_BYTES", 512)
    out = tmp_path / "packet"
    man = build_packet(
        task="x",
        source_root=root,
        include=["expand.txt"],
        out_dir=out,
        redact_secrets=True,
    )
    assert {entry.path for entry in man.files} == {"TASK.md"}
    monkeypatch.setattr(packet_builder, "MAX_FILE_BYTES", original_limit)
    inspected, _digest = inspect_packet(out / "packet.tar.gz")
    assert [entry["path"] for entry in inspected["files"]] == ["TASK.md"]
