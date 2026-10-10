"""Never silently load the full database into NetworkX."""

import networkx as nx

from src.graph.model import Graph


def export_nx(
    graph: Graph, max_nodes: int = 5000, max_edges: int = 30000, relations: set[str] | None = None
) -> nx.Graph:
    if len(graph.nodes) > max_nodes or len(graph.edges) > max_edges:
        raise ValueError("Subgraph exceeds configured memory bounds; select fewer IDs")
    result = nx.Graph()
    result.add_nodes_from((n.id, {"label": n.label, **n.properties}) for n in graph.nodes.values())
    for e in graph.edges.values():
        if (relations is None or e.type in relations) and not e.properties.get("inferred", False):
            result.add_edge(e.source, e.target, type=e.type)
    return result
