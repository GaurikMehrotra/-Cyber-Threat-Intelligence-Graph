"""Bounded defensive pivots; no network operations."""

from collections import deque

import networkx as nx


def pivot(
    g: nx.Graph, start: str, depth: int = 2, hub_degree: int = 50, max_nodes: int = 200
) -> dict:
    if depth < 0 or depth > 3 or max_nodes < 1 or max_nodes > 500 or hub_degree < 1:
        raise ValueError("Pivot bounds exceeded")
    if start not in g:
        raise KeyError(start)
    found = {start}
    queue = deque([(start, 0)])
    hubs = []
    truncated = False
    while queue:
        node, distance = queue.popleft()
        if distance >= depth:
            continue
        if g.degree(node) > hub_degree:
            hubs.append(node)
            continue
        for neighbor in sorted(g.neighbors(node)):
            if neighbor in found:
                continue
            if len(found) >= max_nodes:
                truncated = True
                break
            found.add(neighbor)
            queue.append((neighbor, distance + 1))
    return {
        "nodes": sorted(found),
        "filtered_hubs": sorted(hubs),
        "truncated": truncated,
        "caveat": "Shared infrastructure is a pivot lead, not proof of attribution.",
    }
