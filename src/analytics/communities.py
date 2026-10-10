"""Louvain communities on observed bounded subgraphs."""

import networkx as nx


def communities(g: nx.Graph, seed: int = 42) -> list[list[str]]:
    if not g:
        return []
    if not g.number_of_edges():
        return [[x] for x in sorted(g.nodes)]
    return [sorted(c) for c in nx.community.louvain_communities(g, seed=seed)]
