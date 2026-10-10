"""Two-hop type projections avoid identically-zero bipartite common neighbors."""

import math

import networkx as nx
import numpy as np

from src.analytics.similarity import jaccard, profiles
from src.graph.model import Graph


def training_projection(old: Graph) -> nx.Graph:
    p = profiles(old)
    g = nx.Graph()
    g.add_nodes_from(old.nodes)
    for actor, techniques in p.items():
        g.add_edges_from((actor, t) for t in techniques)
    actors = sorted(p)
    for i, a in enumerate(actors):
        for b in actors[i + 1 :]:
            if p[a] & p[b]:
                g.add_edge(a, b)
    return g


def score(g: nx.Graph, a: str, t: str, method: str) -> float:
    aa = set(g.neighbors(a))
    bb = set(g.neighbors(t))
    common = aa & bb
    if method == "common_neighbors":
        return float(len(common))
    if method == "jaccard":
        return jaccard(aa, bb)
    if method == "adamic_adar":
        return sum(1 / math.log(g.degree(n)) for n in common if g.degree(n) > 1)
    if method == "preferential_attachment":
        return float(len(aa) * len(bb))
    raise ValueError("Unknown baseline")


def text_similarity(a: np.ndarray, b: np.ndarray) -> float:
    den = np.linalg.norm(a) * np.linalg.norm(b)
    return float(a @ b / den) if den else 0.0
