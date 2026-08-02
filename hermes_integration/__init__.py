"""Native Hermes integration for bounded agent handoffs."""

from __future__ import annotations

import json
from typing import Any

from .bootstrap import ensure_repo_local_core
from .cli import handle_cli, setup_cli
from .core import TrustError, TrustRuntime
from .schemas import PREPARE_SCHEMA, STATUS_SCHEMA, VERIFY_SCHEMA


def _safe_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _tool_handler(runtime: TrustRuntime, operation: str):
    def handler(args: dict[str, Any], **_kwargs: Any) -> str:
        try:
            if not isinstance(args, dict):
                raise TrustError("invalid_arguments", "Tool arguments must be a JSON object.")
            result = getattr(runtime, operation)(args)
            return _safe_json({"ok": True, **result})
        except TrustError as exc:
            return _safe_json({"ok": False, "error": exc.code, "message": exc.public_message})
        except Exception:
            return _safe_json(
                {
                    "ok": False,
                    "error": "internal_error",
                    "message": "Agent Trust Kit failed closed. Run `hermes agent-trust doctor`.",
                }
            )

    return handler


def register(ctx: Any) -> None:
    """Register native tools, the operator CLI, and a narrow egress hook."""

    ensure_repo_local_core()
    from hermes_constants import get_hermes_home

    runtime = TrustRuntime(get_hermes_home())
    tools = (
        (
            "handoff_prepare",
            PREPARE_SCHEMA,
            "Prepare a bounded, secret-scanned handoff for operator review.",
            "prepare",
            "📦",
        ),
        (
            "handoff_status",
            STATUS_SCHEMA,
            "Read controller-side handoff state without exposing private paths.",
            "status",
            "🔎",
        ),
        (
            "handoff_verify_return",
            VERIFY_SCHEMA,
            "Verify an approved return with full non-command evidence rechecks.",
            "verify_return",
            "🛡️",
        ),
    )
    for name, schema, description, operation, emoji in tools:
        ctx.register_tool(
            name=name,
            toolset="agent_handoff",
            schema=schema,
            handler=_tool_handler(runtime, operation),
            description=description,
            emoji=emoji,
        )

    def cli_entry(args: Any) -> None:
        raise SystemExit(handle_cli(args, runtime))

    ctx.register_cli_command(
        name="agent-trust",
        help="Operate bounded agent handoffs",
        setup_fn=setup_cli,
        handler_fn=cli_entry,
        description=(
            "Register trusted projects, review prepared packets, and expose fixed "
            "quarantine paths for returned work."
        ),
    )
    ctx.register_hook("pre_tool_call", runtime.pre_tool_call)


__all__ = ["register"]
