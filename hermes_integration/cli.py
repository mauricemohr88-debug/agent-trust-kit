"""Operator-facing Hermes CLI for project registration and packet approval."""

from __future__ import annotations

import argparse
import json
from typing import Any

from .core import TrustError, TrustRuntime


def setup_cli(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="agent_trust_command")

    project = commands.add_parser("project", help="Register and list trusted Git projects")
    project_commands = project.add_subparsers(dest="project_command")
    add = project_commands.add_parser("add", help="Register an exact, clean Git project root")
    add.add_argument("project_id", help="Lowercase identifier, e.g. agent-trust-kit")
    add.add_argument("root", help="Exact top-level Git directory")
    add.add_argument(
        "--deny-glob",
        action="append",
        default=[],
        help="Additional project-relative deny pattern (repeatable)",
    )
    project_commands.add_parser("list", help="List registered projects")

    status = commands.add_parser("status", help="List handoffs or show one handoff")
    status.add_argument("handoff_id", nargs="?")

    approve = commands.add_parser(
        "approve", help="Record operator approval for a prepared packet after review"
    )
    approve.add_argument("handoff_id")

    reject = commands.add_parser("reject", help="Reject a prepared or approved handoff")
    reject.add_argument("handoff_id")

    returned = commands.add_parser(
        "return-path",
        help="Print the fixed private quarantine path for an approved return",
    )
    returned.add_argument("handoff_id")

    verified = commands.add_parser(
        "verified-path",
        help="Print the controller-owned read-only snapshot after verification",
    )
    verified.add_argument("handoff_id")

    commands.add_parser("doctor", help="Validate the integration and controller state")
    parser.set_defaults(func=handle_cli)


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def handle_cli(args: argparse.Namespace, runtime: TrustRuntime | None = None) -> int:
    if runtime is None:
        from hermes_constants import get_hermes_home

        runtime = TrustRuntime(get_hermes_home())
    command = getattr(args, "agent_trust_command", None)
    try:
        if command == "project":
            project_command = getattr(args, "project_command", None)
            if project_command == "add":
                _print(runtime.add_project(args.project_id, args.root, args.deny_glob))
                return 0
            if project_command == "list":
                _print(runtime.list_projects())
                return 0
            print("usage: hermes agent-trust project {add,list}")
            return 2
        if command == "status":
            if args.handoff_id:
                _print(runtime.status({"handoff_id": args.handoff_id}))
            else:
                _print(runtime.list_handoffs())
            return 0
        if command == "approve":
            _print(runtime.approve(args.handoff_id))
            return 0
        if command == "reject":
            _print(runtime.reject(args.handoff_id))
            return 0
        if command == "return-path":
            print(runtime.return_path(args.handoff_id))
            return 0
        if command == "verified-path":
            print(runtime.verified_path(args.handoff_id))
            return 0
        if command == "doctor":
            result = runtime.doctor()
            _print(result)
            return 0 if result["ok"] else 1
        print(
            "usage: hermes agent-trust "
            "{project,status,approve,reject,return-path,verified-path,doctor}"
        )
        return 2
    except TrustError as exc:
        print(f"agent-trust: {exc.public_message} [{exc.code}]")
        return 1
