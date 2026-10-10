"""Exact ATT&CK aliases suggest reversible links; conflicts require review."""

from collections import defaultdict

from src.graph.model import Graph


def alias_candidates(graph: Graph) -> list[dict]:
    names = defaultdict(set)
    for n in graph.nodes.values():
        if n.label not in {"ThreatActor", "Malware", "Tool"}:
            continue
        for name in [n.properties.get("name", "")] + n.properties.get("aliases", []):
            if name.strip():
                names[(n.label, name.strip().casefold())].add(n.id)
    pairs = {tuple(sorted(ids)) for ids in names.values() if len(ids) == 2}
    conflicts = {id for ids in names.values() if len(ids) > 2 for id in ids}
    return [
        {
            "left": a,
            "right": b,
            "method": "attack-alias",
            "similarity": 1.0,
            "decision": "review" if a in conflicts or b in conflicts else "suggested",
            "reason": "Exact ATT&CK name/alias overlap; verify shared names before approving. No entity deletion.",
        }
        for a, b in sorted(pairs)
    ]


def decide_similarity(score: float, auto: float = 0.92, review: float = 0.75) -> str:
    if not 0 <= review <= auto <= 1 or not -1 <= score <= 1:
        raise ValueError("Invalid similarity thresholds")
    return "eligible" if score >= auto else "review" if score >= review else "reject"
