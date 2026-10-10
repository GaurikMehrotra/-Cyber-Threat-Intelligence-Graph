"""Evidence completeness, identifiers, orphans and coverage."""

from collections import Counter

from src.graph.model import IOCS, Graph
from src.intel.defang import normalize


def checks(graph: Graph) -> dict:
    degree = Counter(x for e in graph.edges.values() for x in (e.source, e.target))
    invalid = []
    for n in graph.nodes.values():
        if n.label in IOCS:
            try:
                normalize(n.label, n.properties["value"])
            except (KeyError, ValueError):
                invalid.append(n.public()["id"])
    aliases = Counter(
        (n.label, n.properties.get("value", n.properties.get("external_id") or n.id))
        for n in graph.nodes.values()
    )
    return {
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "duplicate_identifiers": sum(v - 1 for v in aliases.values() if v > 1),
        "orphans": len([n for n in graph.nodes if not degree[n]]),
        "invalid_iocs": invalid,
        "nodes_missing_provenance": sum(not n.evidence for n in graph.nodes.values()),
        "edges_missing_provenance": sum(not e.evidence for e in graph.edges.values()),
        "counts_by_node_type": dict(Counter(n.label for n in graph.nodes.values())),
        "counts_by_relationship_type": dict(Counter(e.type for e in graph.edges.values())),
        "source_node_coverage": dict(
            Counter(
                s for n in graph.nodes.values() for s in {p.source for p in n.evidence.values()}
            )
        ),
        "rejected_indicator_count": len(graph.rejected),
    }
