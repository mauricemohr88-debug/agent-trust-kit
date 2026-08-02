# Contributing

Small, test-backed changes are welcome. Security claims must remain narrower than
the properties enforced by code and adversarial tests.

## Local checks

```bash
uv sync --all-packages --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
```

For changes to archive handling, add a rejection test for the malicious shape and
a normal round-trip test. For receipt changes, distinguish worker-reported data
from controller-rechecked data and add a path/command-policy regression test.

Do not add tests containing live credentials. Synthetic credential-shaped values
are acceptable when clearly marked as fixtures.

## Pull requests

- explain the trust boundary being changed;
- list verification commands and results;
- document new limits or compatibility changes;
- avoid words such as “safe”, “proof”, “tamper-proof”, or “secret-free” unless a
  precisely scoped statement is both enforced and tested.
