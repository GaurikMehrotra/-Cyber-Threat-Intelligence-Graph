"""Validated resource bounds and environment-only authentication."""

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    load_dotenv(override=False)
    p = Path(path or os.getenv("CTIG_CONFIG", "configs/default.yaml"))
    value = yaml.safe_load(p.read_text())
    if not isinstance(value, dict):
        raise ValueError("Configuration must be a mapping")
    for k, v in value["limits"].items():
        if not isinstance(v, (int, float)) or isinstance(v, bool) or v <= 0:
            raise ValueError(f"Invalid positive bound: {k}")
    w = value["analytics"]["priority_weights"]
    if any(v < 0 for v in w.values()) or abs(sum(w.values()) - 1) > 1e-9:
        raise ValueError("Priority weights must be nonnegative and sum to one")
    return value
