"""Observed actor technique coverage and pairwise co-occurrence."""

from collections import Counter
from itertools import combinations

from src.analytics.similarity import profiles
from src.graph.model import Graph


def coverage(graph: Graph) -> dict:
    p = profiles(graph)
    techniques = {n.id for n in graph.nodes.values() if n.label == "Technique"}
    used = set().union(*p.values()) if p else set()
    pairs = Counter(pair for v in p.values() for pair in combinations(sorted(v), 2))
    return {
        "total_techniques": len(techniques),
        "used_techniques": len(used),
        "fraction": len(used) / len(techniques) if techniques else 0,
        "actor_profiles": {k: sorted(v) for k, v in p.items()},
        "cooccurrence": [
            {"a": a, "b": b, "actors": count} for (a, b), count in sorted(pairs.items())
        ],
        "caveat": "ATT&CK observed coverage, not an organization's detection coverage.",
    }
