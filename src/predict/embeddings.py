"""Older-release text only; newer text is never used in training features."""

from src.graph.model import Graph


def older_texts(graph: Graph, ids: list[str]) -> list[str]:
    return [
        graph.nodes[id].properties.get("name", "")
        + " "
        + graph.nodes[id].properties.get("description", "")
        for id in ids
    ]
