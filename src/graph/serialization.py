"""Portable bounded graph snapshots, never raw feeds in Git."""

import json
from pathlib import Path

from src.graph.model import Graph
from src.ingest.provenance import Provenance


def to_dict(g: Graph) -> dict:
    return {
        "nodes": [
            {
                "id": n.id,
                "label": n.label,
                "properties": n.properties,
                "evidence": [p.to_dict() for p in n.evidence.values()],
                "observations": n.observations,
            }
            for n in g.nodes.values()
        ],
        "edges": [
            {
                "source": e.source,
                "target": e.target,
                "type": e.type,
                "properties": e.properties,
                "evidence": [p.to_dict() for p in e.evidence.values()],
                "observations": e.observations,
            }
            for e in g.edges.values()
        ],
        "rejected": g.rejected,
    }


def from_dict(data: dict) -> Graph:
    g = Graph()
    for n in data["nodes"]:
        for p in n["evidence"]:
            g.add_node(
                n["id"],
                n["label"],
                n.get("observations", {}).get(Provenance(**p).key, n["properties"]),
                Provenance(**p),
            )
    for e in data["edges"]:
        for p in e["evidence"]:
            g.add_edge(
                e["source"],
                e["target"],
                e["type"],
                Provenance(**p),
                **e.get("observations", {}).get(Provenance(**p).key, e["properties"]),
            )
    g.rejected = data.get("rejected", [])
    return g


def save(g: Graph, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(to_dict(g), indent=2))


def load(path: str | Path) -> Graph:
    return from_dict(json.loads(Path(path).read_text()))
