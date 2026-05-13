from __future__ import annotations

from pathlib import Path


def scenario_schema_path() -> Path:
    return Path(__file__).with_name("scenario.schema.json")
