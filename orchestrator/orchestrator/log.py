"""Shared logger for the orchestrator package.

We expose a single ``logger`` so callers can override the handler/level once
(``orchestrator.logging.configure(level=...)``) rather than chasing prints
across modules. The default configuration mirrors the prior ``print()`` UX:
INFO-and-above to stderr, no timestamp prefix, so existing demos keep
reading naturally.
"""
from __future__ import annotations

import logging
import sys

logger = logging.getLogger("orchestrator")

_DEFAULT_FORMAT = "%(message)s"
_VERBOSE_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

_configured = False


def configure(level: int = logging.INFO, *, verbose: bool = False) -> None:
    """Attach a single stderr handler at the requested level. Idempotent."""
    global _configured
    handler = logging.StreamHandler(sys.stderr)
    fmt = _VERBOSE_FORMAT if verbose else _DEFAULT_FORMAT
    handler.setFormatter(logging.Formatter(fmt))
    if _configured:
        for existing in list(logger.handlers):
            logger.removeHandler(existing)
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    _configured = True
