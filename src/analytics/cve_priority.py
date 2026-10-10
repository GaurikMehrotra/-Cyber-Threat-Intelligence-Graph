"""An explainable analyst heuristic, not a calibrated exploitation probability."""

from src.graph.model import Graph


def prioritize(
    graph: Graph, id: str, weights: dict, pagerank: dict | None = None, degree_scale: int = 10
) -> dict:
    if degree_scale < 1:
        raise ValueError("Positive graph-degree normalization required")
    node = graph.nodes[id]
    if node.label != "Vulnerability":
        raise ValueError("Expected Vulnerability")
    observed = [
        e
        for e in graph.edges.values()
        if id in (e.source, e.target) and not e.properties.get("inferred", False)
    ]
    ranked = pagerank or {}
    max_rank = max(ranked.values(), default=1) or 1
    props = node.properties
    values = {
        "kev": float(bool(props.get("kev", False))),
        "severity": min(max(float(props.get("cvss", 0)) / 10, 0), 1),
        "graph": min(len(observed) / degree_scale, 1),
        "centrality": ranked.get(id, 0) / max_rank,
        "epss": min(max(float(props.get("epss", 0)), 0), 1),
    }
    missing = [k for k, p in {"severity": "cvss", "epss": "epss"}.items() if p not in props]
    components = {
        k: {"value": v, "weight": weights[k], "contribution": v * weights[k]}
        for k, v in values.items()
    }
    return {
        "id": id,
        "score": sum(c["contribution"] for c in components.values()),
        "components": components,
        "missing_inputs": missing,
        "evidence": [p.to_dict() for p in node.evidence.values()],
        "caveat": "Heuristic priority, not exploitation probability. Missing inputs are zero and disclosed; local exposure is not measured.",
    }
