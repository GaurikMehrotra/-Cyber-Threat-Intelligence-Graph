"""Undirected observed subgraph centrality; bounded approximate betweenness."""

import networkx as nx


def centrality(g: nx.Graph, seed: int = 42, samples: int = 100, alpha: float = 0.85) -> dict:
    if not g:
        return {"pagerank": {}, "betweenness": {}, "degree": {}}
    return {
        "pagerank": nx.pagerank(g, alpha=alpha),
        "betweenness": nx.betweenness_centrality(g, k=min(samples, len(g)), seed=seed),
        "degree": dict(g.degree()),
    }
