"""Actor similarity describes overlap, never common identity or attribution."""

import numpy as np

from src.graph.model import Graph


def profiles(graph: Graph) -> dict[str, set[str]]:
    result = {n.id: set() for n in graph.nodes.values() if n.label == "ThreatActor"}
    for e in graph.edges.values():
        if (
            e.type == "USES"
            and e.source in result
            and graph.nodes[e.target].label == "Technique"
            and not e.properties.get("inferred", False)
        ):
            result[e.source].add(e.target)
    return result


def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a | b else 0.0


def similar_actors(graph: Graph, id: str, vectors: dict | None = None) -> list[dict]:
    pp = profiles(graph)
    if id not in pp:
        raise KeyError(id)
    rows = []
    for other, p in pp.items():
        if other == id:
            continue
        cosine = None
        if vectors is not None and id in vectors and other in vectors:
            a, b = np.asarray(vectors[id]), np.asarray(vectors[other])
            den = np.linalg.norm(a) * np.linalg.norm(b)
            cosine = float(a @ b / den) if den else 0.0
        rows.append(
            {
                "id": other,
                "jaccard": jaccard(pp[id], p),
                "embedding_cosine": cosine,
                "shared_techniques": sorted(pp[id] & p),
                "caveat": "Technique/tool sharing is not identity or attribution evidence.",
            }
        )
    return sorted(rows, key=lambda x: (-x["jaccard"], x["id"]))
