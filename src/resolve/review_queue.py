"""Human decisions create reversible ALIAS_OF assertions, never destructive merges."""

import json
from pathlib import Path

from src.graph.model import Graph
from src.ingest.provenance import evidence


def write_queue(rows: list[dict], path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps({**r, "human_decision": "pending"}) for r in rows) + "\n")


def approve(graph: Graph, left: str, right: str, reviewer: str, run: str, timestamp: str) -> str:
    if not reviewer.strip() or left == right or graph.nodes[left].label != graph.nodes[right].label:
        raise ValueError("Named reviewer and same-type distinct entities required")
    p = evidence("human-review", reviewer + ":" + left + ":" + right, run, first=timestamp)
    return graph.add_edge(
        left,
        right,
        "ALIAS_OF",
        p,
        inferred=True,
        hypothesis=True,
        decision="approved",
        reviewer=reviewer,
        caveat="Reversible analyst resolution hypothesis, not attribution.",
    ).id


def undo(graph: Graph, edge_id: str) -> None:
    edge = graph.edges[edge_id]
    if edge.type != "ALIAS_OF":
        raise ValueError("Not an alias assertion")
    del graph.edges[edge_id]

    for endpoint in (edge.source, edge.target):
        node = graph.nodes[endpoint]
        for key in edge.evidence:
            # Drop only empty relationship-support observations not used by another edge.
            if not node.observations.get(key) and not any(
                key in e.evidence and endpoint in (e.source, e.target) for e in graph.edges.values()
            ):
                node.evidence.pop(key, None)
                node.observations.pop(key, None)
