"""Write audit-friendly JSON quality artifacts."""

import json
from pathlib import Path

from src.graph.model import Graph
from src.quality.checks import checks


def write_report(graph: Graph, path: str | Path) -> dict:
    result = checks(graph)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result, indent=2))
    return result
