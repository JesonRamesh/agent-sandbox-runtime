"""Repo-root wrapper for `python -m orchestrator.cli`."""

from orchestrator.orchestrator.cli import build_parser, main, run

__all__ = ["build_parser", "main", "run"]


if __name__ == "__main__":
    main()
