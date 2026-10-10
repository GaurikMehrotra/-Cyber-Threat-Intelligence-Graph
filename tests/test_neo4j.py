"""Integration touches uniquely namespaced synthetic records only."""

import os
from uuid import uuid4

import pytest
from neo4j.exceptions import ConstraintError

from src.graph.client import Client
from src.graph.loaders import export_graph, load_graph, purge
from src.graph.model import Graph
from src.graph.schema import apply_schema
from src.ingest.provenance import evidence

pytestmark = pytest.mark.integration


@pytest.fixture
def client():
    if os.getenv("CTIG_INTEGRATION") != "1":
        pytest.skip("Set CTIG_INTEGRATION=1 with Neo4j running")
    client = Client()
    client.verify()
    apply_schema(client)
    yield client
    client.close()


@pytest.fixture
def owned(client):
    prefix = "test:" + str(uuid4()) + ":"
    p = evidence(prefix, "node", prefix, first="2024-01-01T00:00:00Z")
    g = Graph()
    g.add_node(prefix + "actor", "ThreatActor", {"name": "Test actor"}, p)
    g.add_node(prefix + "technique", "Technique", {"name": "Test technique"}, p)
    g.add_edge(prefix + "actor", prefix + "technique", "USES", p)
    yield g, prefix
    with client.driver.session() as s:
        s.run(
            "MATCH (n:Entity) WHERE n.id STARTS WITH $prefix DETACH DELETE n", prefix=prefix
        ).consume()


def test_schema_and_idempotent(client, owned):
    g, prefix = owned
    load_graph(client, g)
    load_graph(client, g)
    out = export_graph(client, list(g.nodes))
    assert len(out.nodes) == 2 and len(out.edges) == 1
    assert all(len(n.evidence) == 1 for n in out.nodes.values())
    with client.driver.session() as session:
        constraints = session.run("SHOW CONSTRAINTS YIELD name RETURN name").data()
        assert {"entity_id", "uses_id", "threatactor_id"} <= {r["name"] for r in constraints}
        with pytest.raises(ConstraintError):
            session.run("CREATE (:Entity:ThreatActor {id:$id})", id=prefix + "actor").consume()


def test_shared_provenance_purge(client, owned):
    g, prefix = owned
    load_graph(client, g)
    q = evidence(prefix + "second", "other", prefix + "run2", first="2024-02-01T00:00:00Z")
    h = Graph()
    h.add_node(prefix + "actor", "ThreatActor", {"name": "New name", "extra": "second-only"}, q)
    load_graph(client, h)
    out = export_graph(client, list(g.nodes))
    assert out.nodes[prefix + "actor"].properties["name"] == "New name"
    purge(client, source=prefix + "second")
    out = export_graph(client, list(g.nodes))
    assert (
        out.nodes[prefix + "actor"].properties["name"] == "Test actor"
        and "extra" not in out.nodes[prefix + "actor"].properties
    )
    purge(client, run=prefix)
    assert not export_graph(client, list(g.nodes)).nodes
