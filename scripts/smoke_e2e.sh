#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
smoke_root="$(mktemp -d "${TMPDIR:-/tmp}/agent-handoff-smoke.XXXXXX")"
trap 'rm -rf "$smoke_root"' EXIT

source_dir="$smoke_root/source"
packet_dir="$smoke_root/packet"
worker_dir="$smoke_root/worker"
receipt_file="$smoke_root/receipt.json"

mkdir -p "$source_dir/src" "$source_dir/private"
printf 'print("hello")\n' > "$source_dir/src/app.py"
printf '%s%s\n' 'OPENAI_API_KEY="sk-' 'abcdefghijklmnopqrstuvwxyz123456"' > "$source_dir/.env"
printf 'not for transport\n' > "$source_dir/private/note.md"

cd "$repo_root"
uv run agent-packet build \
  --task "Review src/app.py and write RESULT.md with PASS." \
  --root "$source_dir" \
  --include-all \
  --out "$packet_dir"

uv run agent-packet inspect "$packet_dir/packet.tar.gz" --json > "$smoke_root/inspect.json"
packet_digest="$(awk '{print $1}' "$packet_dir/PACKET_SHA256.txt")"
uv run agent-packet materialize "$packet_dir/packet.tar.gz" \
  --dest "$worker_dir" \
  --expect-sha256 "$packet_digest"

test -f "$worker_dir/payload/src/app.py"
test ! -e "$worker_dir/payload/.env"
test ! -e "$worker_dir/payload/private/note.md"

printf 'PASS\n' > "$worker_dir/payload/RESULT.md"
uv run agent-receipt build \
  --workspace-root "$worker_dir/payload" \
  --agent smoke-worker \
  --task "write RESULT.md" \
  --claim result="RESULT.md exists and contains PASS" \
  --file-exists result=RESULT.md \
  --text-contains 'result=RESULT.md::PASS' \
  --file-hash result=RESULT.md \
  --out "$receipt_file"

uv run agent-receipt verify "$receipt_file" \
  --recheck \
  --recheck-root "$worker_dir/payload" \
  --json > "$smoke_root/verified.json"

python3 - "$smoke_root/verified.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
assert result["ok"] is True
assert result["assurance"] == "fully_rechecked"
assert result["coverage"]["reported_evidence"] == 0
PY

printf 'CHANGED\n' > "$worker_dir/payload/RESULT.md"
if uv run agent-receipt verify "$receipt_file" \
  --recheck \
  --recheck-root "$worker_dir/payload" >/dev/null 2>&1; then
  echo "tampered result unexpectedly verified" >&2
  exit 1
fi

echo "end-to-end smoke passed"
