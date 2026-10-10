import networkx as nx
import pytest

from src.analytics.centrality import centrality
from src.analytics.communities import communities
from src.analytics.coverage import coverage
from src.analytics.cve_priority import prioritize
from src.analytics.pivot import pivot
from src.analytics.similarity import jaccard, profiles, similar_actors
from src.graph.export_nx import export_nx


def test_centralities_hand_graph():
    g = nx.path_graph(["a", "b", "c"])
    result = centrality(g)
    assert result["degree"] == {"a": 1, "b": 2, "c": 1}
    assert result["betweenness"] == {"a": 0.0, "b": 1.0, "c": 0.0}
    assert result["pagerank"]["b"] == pytest.approx(0.486486, abs=1e-5)
    assert result["pagerank"]["a"] == pytest.approx(result["pagerank"]["c"])


def test_louvain_disconnected():
    g = nx.Graph()
    g.add_edges_from([("a", "b"), ("c", "d")])
    assert {frozenset(c) for c in communities(g)} == {frozenset({"a", "b"}), frozenset({"c", "d"})}


def test_actor_overlap(graph):
    assert jaccard({1, 2}, {2, 3}) == pytest.approx(1 / 3)
    pp = profiles(graph)
    north = next(n.id for n in graph.nodes.values() if n.properties.get("name") == "Example North")
    east = next(n.id for n in graph.nodes.values() if n.properties.get("name") == "Example East")
    assert len(pp[north]) == 2 and len(pp[east]) == 1
    assert similar_actors(graph, north)[0]["jaccard"] == 0.5


def test_pivot_hub_and_depth():
    g = nx.star_graph(10)
    result = pivot(g, 0, 2, 5, 20)
    assert result["nodes"] == [0] and result["filtered_hubs"] == [0]
    assert len(pivot(g, 1, 1, 50, 20)["nodes"]) == 2
    assert len(pivot(g, 0, 2, 50, 3)["nodes"]) == 3
    with pytest.raises(ValueError):
        pivot(g, 0, 4)


def test_coverage(graph):
    result = coverage(graph)
    assert (
        result["used_techniques"] == 3
        and result["total_techniques"] == 4
        and result["fraction"] == 0.75
    )
    assert len(result["cooccurrence"]) == 1


def test_priority(graph, cfg):
    result = prioritize(graph, "CVE-2024-99999", cfg["analytics"]["priority_weights"])
    assert result["components"]["kev"]["contribution"] == 0.5
    assert result["components"]["severity"]["value"] == pytest.approx(0.81)
    assert "epss" in result["missing_inputs"]
    assert result["score"] == sum(x["contribution"] for x in result["components"].values())


def test_subgraph_bound(graph):
    with pytest.raises(ValueError):
        export_nx(graph, max_nodes=1)
