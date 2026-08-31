from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import hermes_integration
import hermes_integration.core as core
from hermes_integration.core import (
    NATIVE_PLATFORM_ERROR,
    TrustError,
    TrustRuntime,
    require_supported_native_platform,
)


class _RunningProcess:
    pid = 4242

    def poll(self) -> None:
        return None


def _force_native_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core, "_native_platform", lambda: "win32")


def test_native_integration_imports_without_posix_fcntl() -> None:
    assert callable(hermes_integration.register)
    assert callable(TrustRuntime)
    if sys.platform == "win32":
        assert core.fcntl is None


def test_register_rejects_windows_before_registration_bootstrap_or_context_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_native_windows(monkeypatch)
    registration_bootstrap_called = False
    home_lookup_called = False

    def unexpected_bootstrap() -> dict[str, Path]:
        nonlocal registration_bootstrap_called
        registration_bootstrap_called = True
        return {}

    def unexpected_home_lookup() -> Path:
        nonlocal home_lookup_called
        home_lookup_called = True
        raise AssertionError("Hermes home must not be read on an unsupported platform")

    monkeypatch.setattr(hermes_integration, "ensure_repo_local_core", unexpected_bootstrap)
    monkeypatch.setitem(
        sys.modules,
        "hermes_constants",
        SimpleNamespace(get_hermes_home=unexpected_home_lookup),
    )

    with pytest.raises(TrustError) as error:
        hermes_integration.register(object())

    assert error.value.code == "unsupported_platform"
    assert error.value.public_message == NATIVE_PLATFORM_ERROR
    assert registration_bootstrap_called is False
    assert home_lookup_called is False


def test_runtime_rejects_windows_before_state_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _force_native_windows(monkeypatch)
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir()

    with pytest.raises(TrustError) as error:
        TrustRuntime(hermes_home)

    assert error.value.code == "unsupported_platform"
    assert error.value.public_message == NATIVE_PLATFORM_ERROR
    assert list(hermes_home.iterdir()) == []


def test_non_posix_cleanup_does_not_call_killpg(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def unexpected_killpg(_pid: int, _signal: int) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(core.os, "killpg", unexpected_killpg, raising=False)

    core._terminate_posix_process_group(  # type: ignore[arg-type]
        _RunningProcess(), platform_name="nt"
    )

    assert called is False


def test_posix_cleanup_keeps_process_group_behavior(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, Any]] = []
    synthetic_sigkill = getattr(core.signal, "SIGKILL", 9)
    monkeypatch.setattr(
        core.os,
        "killpg",
        lambda pid, selected_signal: calls.append((pid, selected_signal)),
        raising=False,
    )
    monkeypatch.setattr(core.signal, "SIGKILL", synthetic_sigkill, raising=False)

    core._terminate_posix_process_group(  # type: ignore[arg-type]
        _RunningProcess(), platform_name="posix"
    )

    assert calls == [(4242, synthetic_sigkill)]


@pytest.mark.skipif(
    sys.platform != "darwin" and not sys.platform.startswith("linux"),
    reason="supported native platform assertion",
)
def test_current_supported_platform_passes_boundary() -> None:
    require_supported_native_platform()
