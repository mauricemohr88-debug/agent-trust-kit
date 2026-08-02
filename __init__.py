"""Hermes entry point for Agent Trust Kit."""

if __package__:
    from .hermes_integration import register
else:  # Pytest imports a repository-root __init__.py without a package name.
    from hermes_integration import register

__all__ = ["register"]
