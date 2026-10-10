"""User-authored expected answers; never grade a query against itself."""

import json
from pathlib import Path

from src.graph.client import Client
from src.graph.queries import QUERIES
from src.security.cypher_guard import validate


def run_golden(client: Client, path: str) -> dict:
    data = json.loads(Path(path).read_text())
    results = []
    skipped = 0
    for row in data:
        if row.get("expected_ids") is None and row.get("expected_rows") is None:
            skipped += 1
            continue
        query = QUERIES[row["template"]]
        validate(query, row["params"])
        try:
            actual = client.read(query, row["params"])
            expected = row.get("expected_rows")
            passed = (
                actual == expected
                if expected is not None
                else sorted(r["id"] for r in actual) == sorted(row["expected_ids"])
            )
            results.append({"question": row["question"], "passed": passed, "actual": actual})
        except Exception as exc:
            results.append(
                {"question": row["question"], "passed": False, "error": type(exc).__name__}
            )
    return {
        "status": "evaluated" if results else "unlabeled",
        "executed": len(results),
        "skipped": skipped,
        "accuracy": sum(r["passed"] for r in results) / len(results) if results else None,
        "results": results,
    }
