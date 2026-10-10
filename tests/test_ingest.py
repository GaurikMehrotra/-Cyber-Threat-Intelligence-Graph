import json
from pathlib import Path

import pytest

from src.graph.model import Graph
from src.graph.serialization import from_dict, to_dict
from src.ingest.attack import parse_attack
from src.ingest.cwe import parse_cwe
from src.ingest.provenance import evidence
from src.quality.checks import checks


def test_repeat_load(graph):
    before = to_dict(graph)
    graph.merge(from_dict(before))
    assert len(graph.nodes) == len(before["nodes"]) and len(graph.edges) == len(before["edges"])
    assert to_dict(graph) == before


def test_purge_recomputes_property():
    g = Graph()
    one = evidence("one", "n", "run1", first="2024-01-01T00:00:00Z")
    two = evidence("two", "n", "run2", first="2024-02-01T00:00:00Z")
    g.add_node("x", "ThreatActor", {"name": "old"}, one)
    g.add_node("x", "ThreatActor", {"name": "new"}, two)
    assert g.nodes["x"].properties["name"] == "new"
    g.purge(source="two")
    assert g.nodes["x"].properties["name"] == "old"
    g.purge(run="run1")
    assert not g.nodes


def test_shared_endpoints_survive():
    g = Graph()
    p = evidence("a", "n", "run1", first="2024-01-01T00:00:00Z")
    q = evidence("b", "edge", "run2", first="2024-01-01T00:00:00Z")
    g.add_node("a", "ThreatActor", {"name": "Actor"}, p)
    g.add_node("t", "Technique", {"name": "Technique"}, p)
    g.add_edge("a", "t", "USES", q)
    g.purge(source="a")
    assert set(g.nodes) == {"a", "t"} and len(g.edges) == 1


def test_attack_mapping_and_revoked():
    bundle = json.loads(Path("data/fixtures/attack-old.json").read_text())
    g = parse_attack(bundle, "old", "run")
    assert sum(n.label == "ThreatActor" for n in g.nodes.values()) == 3
    assert sum(n.label == "Technique" for n in g.nodes.values()) == 4
    bundle["objects"][0]["revoked"] = True
    other = parse_attack(bundle, "old", "run")
    assert bundle["objects"][0]["id"] not in other.nodes


def test_xml_entities_rejected():
    with pytest.raises(ValueError):
        parse_cwe('<!DOCTYPE foo [<!ENTITY x "boom">]><x/>', "run", "2024-01-01T00:00:00Z")


def test_quality(graph):
    result = checks(graph)
    assert (
        result["invalid_iocs"] == []
        and result["edges_missing_provenance"] == 0
        and result["nodes_missing_provenance"] == 0
    )
    assert result["counts_by_node_type"]["Vulnerability"] == 1
    assert "HAS_WEAKNESS" in result["counts_by_relationship_type"]


def test_reports_do_not_infer_attribution(graph):
    assert not any(e.type == "ATTRIBUTED_TO" for e in graph.edges.values())
    assert not any(e.type == "EXPLOITS" for e in graph.edges.values())


def test_graph_rejects_invalid_or_conflicting_indicator_identifiers():
    p = evidence("test", "indicator", "run", first="2024-01-01T00:00:00Z")
    g = Graph()
    with pytest.raises(ValueError):
        g.add_node("Domain:bad domain", "Domain", {}, p)
    with pytest.raises(ValueError):
        g.add_node("Domain:example.com", "Domain", {"value": "different.example"}, p)


def test_property_time_order_uses_instants_not_timestamp_strings():
    g = Graph()
    earlier = evidence("early", "n", "one", first="2024-01-01T01:00:00+00:00")
    later = evidence("later", "n", "two", first="2024-01-01T00:00:00-05:00")
    g.add_node("x", "ThreatActor", {"name": "early"}, earlier)
    g.add_node("x", "ThreatActor", {"name": "later"}, later)
    assert g.nodes["x"].properties["name"] == "later"
