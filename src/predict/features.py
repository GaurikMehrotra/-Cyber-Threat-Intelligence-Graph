"""Actor-technique links from observed older-release edges only."""

from src.graph.model import Graph


def actor_technique_edges(graph: Graph) -> set[tuple[str, str]]:
    return {
        (e.source, e.target)
        for e in graph.edges.values()
        if e.type == "USES"
        and graph.nodes[e.source].label == "ThreatActor"
        and graph.nodes[e.target].label == "Technique"
        and not e.properties.get("inferred", False)
    }


def temporal_split(old: Graph, new: Graph, max_candidates: int = 100000) -> dict:
    train = actor_technique_edges(old)
    newer = actor_technique_edges(new)
    actors = sorted(n.id for n in old.nodes.values() if n.label == "ThreatActor")
    techniques = sorted(n.id for n in old.nodes.values() if n.label == "Technique")
    if len(actors) * len(techniques) > max_candidates:
        raise ValueError("Candidate space too large: scope actors before evaluation")
    candidates = {(a, t) for a in actors for t in techniques} - train
    positives = (newer - train) & candidates
    cold_start = (newer - train) - positives
    return {
        "train": train,
        "positive": positives,
        "negative": candidates - newer,
        "candidates": candidates,
        "cold_start": cold_start,
        "caveat": "New ATT&CK assertions are publication-time observations, not dates of attacker activity. Cold-start nodes excluded and disclosed.",
    }
