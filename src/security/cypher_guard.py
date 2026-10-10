"""Accept only exact developer-owned read templates and bounded typed parameters."""

import re

from src.graph.queries import QUERIES


def validate(query: str, params: dict, row_cap: int = 100) -> None:
    if not isinstance(params, dict):
        raise ValueError("Query parameters must be a mapping")
    if query not in QUERIES.values():
        raise ValueError("Query is outside the read-only template allowlist")
    if set(params) != set(re.findall(r"\$([a-z_]+)", query)):
        raise ValueError("Exact template parameters are required")
    if (
        isinstance(params.get("limit"), bool)
        or not isinstance(params.get("limit"), int)
        or not 1 <= params["limit"] <= row_cap
    ):
        raise ValueError("Invalid row limit")
    if (
        not isinstance(params.get("offset", 0), int)
        or isinstance(params.get("offset", 0), bool)
        or not 0 <= params.get("offset", 0) <= 10000
    ):
        raise ValueError("Invalid offset")
    for key, value in params.items():
        if key in {"id", "text"} and (not isinstance(value, str) or len(value) > 512):
            raise ValueError("Invalid query value")
    if "ids" in params and (
        not isinstance(params["ids"], list)
        or len(params["ids"]) > 100
        or any(not isinstance(x, str) or len(x) > 512 for x in params["ids"])
    ):
        raise ValueError("Invalid ID list")
