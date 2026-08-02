"""Secret and private-path detection for outbound agent packets.

The detector is deliberately conservative, but it is not a replacement for a
dedicated DLP or secret-scanning product.  The packet builder therefore exposes
detected secrets as a blocking policy by default and treats redaction as an
explicit opt-in.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True, slots=True)
class SecretRule:
    kind: str
    pattern: re.Pattern[str]


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "private_key_block",
        re.compile(
            r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?"
            r"-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    SecretRule(
        "openai_key",
        re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
    ),
    SecretRule("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    SecretRule("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    SecretRule("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    SecretRule("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    SecretRule("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{20,}")),
    SecretRule("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    SecretRule("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    SecretRule("stripe_live_key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b")),
    SecretRule("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    SecretRule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    SecretRule("bearer_token", re.compile(r"(?i)\bbearer\s+[a-z0-9._=-]{20,}")),
    SecretRule(
        "url_credentials",
        re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@"),
    ),
    SecretRule(
        "credential_assignment",
        re.compile(
            r"(?im)\b(?:api[_-]?key|client[_-]?secret|secret[_-]?key|"
            r"aws_secret_access_key|access[_-]?token|refresh[_-]?token|"
            r"password|passwd|token)\b\s*[:=]\s*"
            r"(?:\"[^\"\r\n]{8,}\"|'[^'\r\n]{8,}'|[^\s#;,]{12,})"
        ),
    ),
)

DEFAULT_DENY_PATH_PARTS = {
    ".aws",
    ".azure",
    ".docker",
    ".direnv",
    ".git",
    ".gnupg",
    ".hg",
    ".kube",
    ".ssh",
    ".svn",
    ".venv",
    "__pycache__",
    "keychains",
    "node_modules",
    "passwords",
    "private",
    "secrets",
    "venv",
}

DEFAULT_DENY_NAMES = {
    ".git-credentials",
    ".envrc",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "auth.json",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}

DEFAULT_DENY_SUFFIXES = {".key", ".kdbx", ".p12", ".pem", ".pfx"}


@dataclass(slots=True)
class Finding:
    kind: str
    path: str
    detail: str
    line: int | None = None


def path_is_denied(path: Path, root: Path, extra_globs: Iterable[str] = ()) -> Finding | None:
    """Return a finding when a path must not cross the packet boundary."""

    try:
        rel_path = path.absolute().relative_to(root.absolute())
    except ValueError:
        return Finding("outside_root", str(path), "path escapes source root")

    rel = rel_path.as_posix()
    rel_parts = {part.lower() for part in rel_path.parts}
    denied_parts = rel_parts & DEFAULT_DENY_PATH_PARTS
    if denied_parts:
        denied = sorted(denied_parts)[0]
        return Finding("denied_path", rel, f"path contains denied segment: {denied}")

    for part in rel_path.parts:
        name = part.lower()
        suffix = Path(part).suffix.lower()
        if name in {".env", ".envrc"} or name.startswith((".env.", ".envrc.")):
            return Finding("denied_name", rel, "path contains a denied environment filename")
        if name in DEFAULT_DENY_NAMES:
            return Finding("denied_name", rel, "path contains a denied credential filename")
        if suffix in DEFAULT_DENY_SUFFIXES:
            return Finding("denied_ext", rel, "path contains a denied key-file extension")
        if "secret" in name or "credential" in name:
            return Finding("denied_name", rel, "path contains a sensitive filename pattern")
    if scan_text_for_secrets(rel, rel):
        return Finding("secret_like_path", rel, "path contains a secret-like pattern")

    pure_rel = PurePosixPath(rel)
    for raw_glob in extra_globs:
        pattern = raw_glob.strip().replace("\\", "/")
        if not pattern:
            continue
        if pure_rel.match(pattern) or PurePosixPath(path.name).match(pattern):
            return Finding("denied_glob", rel, f"matched deny pattern {raw_glob}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return Finding("outside_root", rel, "path resolves outside source root")
    return None


def scan_text_for_secrets(text: str, rel_path: str) -> list[Finding]:
    """Find known credential shapes without returning their values."""

    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            key = (rule.kind, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule.kind,
                    rel_path,
                    f"secret-like pattern on line {line}",
                    line=line,
                )
            )
    return sorted(findings, key=lambda finding: (finding.line or 0, finding.kind))


def redact_text(text: str) -> tuple[str, int]:
    """Replace every detected secret span, including complete private-key blocks."""

    count = 0
    cleaned = text
    for rule in SECRET_RULES:
        cleaned, replacements = rule.pattern.subn(f"[REDACTED:{rule.kind}]", cleaned)
        count += replacements
    return cleaned, count
