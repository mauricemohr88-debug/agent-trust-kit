#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

uv sync --all-packages --group dev --locked
uv run ruff check --config pyproject.toml .
uv run ruff format --config pyproject.toml --check .
uv run pytest -q
scripts/smoke_e2e.sh

build_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-handoff-build.XXXXXX")"
trap 'rm -rf "$build_dir"' EXIT

uv build packages/agent-packet --out-dir "$build_dir/agent-packet"
uv build packages/agent-receipt --out-dir "$build_dir/agent-receipt"
uvx --from twine==6.2.0 twine check "$build_dir"/*/*

uv venv "$build_dir/install-venv"
uv pip install \
  --python "$build_dir/install-venv/bin/python" \
  "$build_dir"/agent-packet/*.whl \
  "$build_dir"/agent-receipt/*.whl
"$build_dir/install-venv/bin/agent-packet" --version
"$build_dir/install-venv/bin/agent-receipt" --version
