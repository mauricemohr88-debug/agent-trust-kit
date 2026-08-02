"""Load the two bundled libraries from this exact repository clone."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

_PACKAGES = ("agent_packet", "agent_receipt")


def ensure_repo_local_core() -> dict[str, Path]:
    repo_root = Path(__file__).resolve().parent.parent
    expected = {
        "agent_packet": (repo_root / "packages" / "agent-packet" / "src").resolve(),
        "agent_receipt": (repo_root / "packages" / "agent-receipt" / "src").resolve(),
    }
    for package, source_root in expected.items():
        if not (source_root / package / "__init__.py").is_file():
            raise RuntimeError(f"bundled {package} source is missing")
        loaded = sys.modules.get(package)
        if loaded is not None:
            module_path = Path(getattr(loaded, "__file__", "")).resolve()
            try:
                module_path.relative_to(source_root)
            except ValueError as exc:
                raise RuntimeError(f"refusing non-bundled {package} module") from exc
        source_text = str(source_root)
        if source_text not in sys.path:
            sys.path.insert(0, source_text)

    origins: dict[str, Path] = {}
    for package in _PACKAGES:
        module = importlib.import_module(package)
        origin = Path(module.__file__).resolve()
        try:
            origin.relative_to(expected[package])
        except ValueError as exc:
            raise RuntimeError(f"refusing non-bundled {package} module") from exc
        origins[package] = origin
    return origins
