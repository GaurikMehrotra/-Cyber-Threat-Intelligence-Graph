"""Batched transaction-safe MERGE with per-property source observations."""

import json

from neo4j import Query, unit_of_work

from src.graph.client import Client
from src.graph.model import LABELS, RELATIONS, Edge, Graph, Node, aggregate
from src.graph.serialization import from_dict
from src.ingest.provenance import Provenance

NODE_LOCKS = {
    label: "UNWIND $rows AS row MERGE (n:Entity:"
    + label
    + " {id:row.id}) SET n._ctig_lock=true RETURN n.id AS id, n.evidence AS evidence"
    for label in LABELS
}
NODE_WRITES = {
    label: "UNWIND $rows AS row MATCH (n:Entity:"
    + label
    + " {id:row.id}) SET n += row.props, n.label=row.label, n.name=row.name, n.external_id=row.external_id, n.sources=row.sources, n.evidence=row.evidence, n.payload=row.payload REMOVE n._ctig_lock"
    for label in LABELS
}
EDGE_LOCKS = {
    rel: "UNWIND $rows AS row MATCH (a:Entity {id:row.source}), (b:Entity {id:row.target}) MERGE (a)-[r:"
    + rel
    + " {id:row.id}]->(b) SET r._ctig_lock=true RETURN r.id AS id, r.evidence AS evidence"
    for rel in RELATIONS
}
EDGE_WRITES = {
    rel: "UNWIND $rows AS row MATCH ()-[r:"
    + rel
    + "]->() WHERE r.id=row.id SET r += row.props, r.evidence=row.evidence, r.payload=row.payload REMOVE r._ctig_lock"
    for rel in RELATIONS
}
EXPORT_NODES = "MATCH (n:Entity) WHERE n.id IN $ids RETURN n.id AS id, n.label AS label, n.payload AS payload, n.evidence AS evidence LIMIT $limit"
EXPORT_EDGES = "MATCH (a:Entity)-[r]->(b:Entity) WHERE a.id IN $ids AND b.id IN $ids RETURN a.id AS source, b.id AS target, type(r) AS type, r.payload AS payload, r.evidence AS evidence LIMIT $limit"


def _unpack(raw: list[str]) -> tuple[dict, dict]:
    pp = {}
    obs = {}
    for text in raw or []:
        item = json.loads(text)
        p = Provenance(**item["provenance"])
        pp[p.key] = p
        obs[p.key] = item["properties"]
    return pp, obs


def _row(item, prior: list[str] | None = None) -> dict:
    evidence, observations = _unpack(prior or [])
    evidence.update(item.evidence)
    for key, props in item.observations.items():
        observations.setdefault(key, {}).update(props)
    properties = aggregate(evidence, observations)
    pp = list(evidence.values())
    sources = sorted({p.source for p in pp})
    native = {
        "source": sources,
        "source_id": sorted({p.source_id for p in pp}),
        "first_seen": min(p.first_seen for p in pp),
        "last_seen": max(p.last_seen for p in pp),
        "confidence": max(p.confidence for p in pp),
        "ingestion_run_id": sorted({p.ingestion_run_id for p in pp}),
        "inferred": properties.get("inferred", False),
    }
    row = {
        "id": item.id,
        "props": native,
        "sources": sources,
        "payload": json.dumps(properties),
        "evidence": [
            json.dumps(
                {"provenance": evidence[k].to_dict(), "properties": observations.get(k, {})},
                sort_keys=True,
            )
            for k in sorted(evidence)
        ],
    }
    if isinstance(item, Node):
        row.update(
            label=item.label,
            name=properties.get("name", item.id),
            external_id=properties.get("external_id", ""),
        )
    else:
        row.update(source=item.source, target=item.target)
    return row


def load_graph(client: Client, graph: Graph, batch_size: int = 200) -> None:
    if batch_size < 1 or batch_size > 1000:
        raise ValueError("Batch size must be 1..1000")

    @unit_of_work(timeout=5)
    def batch(tx, items, lock: str, write: str):
        old = {r["id"]: r["evidence"] for r in tx.run(lock, rows=[_row(x) for x in items])}
        rows = [_row(x, old.get(x.id)) for x in items]
        tx.run(write, rows=rows).consume()

    with client.driver.session() as session:
        for kind, items, locks, writes in [
            (LABELS, graph.nodes.values(), NODE_LOCKS, NODE_WRITES),
            (RELATIONS, graph.edges.values(), EDGE_LOCKS, EDGE_WRITES),
        ]:
            for key in sorted(kind):
                selected = sorted(
                    (x for x in items if (x.label if isinstance(x, Node) else x.type) == key),
                    key=lambda x: x.id,
                )
                for start in range(0, len(selected), batch_size):
                    session.execute_write(
                        batch, selected[start : start + batch_size], locks[key], writes[key]
                    )


def _export_item(row: dict) -> dict:
    pp, obs = _unpack(row.pop("evidence"))
    row["properties"] = json.loads(row.pop("payload"))
    row["evidence"] = [p.to_dict() for p in pp.values()]
    row["observations"] = obs
    return row


def export_graph(
    client: Client, ids: list[str], max_nodes: int = 5000, max_edges: int = 30000
) -> Graph:
    if len(ids) > max_nodes:
        raise ValueError("Select a smaller CTIG_SUBGRAPH ID list")
    with client.driver.session(default_access_mode="READ") as session:
        nodes = session.run(Query(EXPORT_NODES, timeout=5), ids=ids, limit=max_nodes + 1).data()
        edges = session.run(Query(EXPORT_EDGES, timeout=5), ids=ids, limit=max_edges + 1).data()
    if len(nodes) > max_nodes or len(edges) > max_edges:
        raise ValueError("Export exceeds configured resource bounds")
    return from_dict(
        {"nodes": [_export_item(r) for r in nodes], "edges": [_export_item(r) for r in edges]}
    )


def purge(client: Client, source: str | None = None, run: str | None = None) -> dict:
    """Bounded streaming transactions remove only matching observations and recompute properties.

    Maintenance operation: pause ingestion while purging. Each batch is atomic, not the whole purge.
    """
    if not source and not run:
        raise ValueError("Specify source or run")
    counts = {"nodes": 0, "edges": 0}
    with client.driver.session() as session:
        for key, read, is_node in [
            (
                "edges",
                "MATCH (a:Entity)-[x]->(b:Entity) WHERE x.id > $after RETURN x.id AS id, a.id AS source, b.id AS target, type(x) AS type, x.evidence AS evidence ORDER BY x.id LIMIT $limit",
                False,
            ),
            (
                "nodes",
                "MATCH (x:Entity) WHERE x.id > $after RETURN x.id AS id, x.label AS label, x.evidence AS evidence ORDER BY x.id LIMIT $limit",
                True,
            ),
        ]:
            after = ""
            while True:
                rows = session.run(Query(read, timeout=5), after=after, limit=200).data()
                if not rows:
                    break
                after = rows[-1]["id"]

                @unit_of_work(timeout=5)
                def remove(tx, rows, is_node=is_node):
                    affected = 0
                    for row in rows:
                        pp, obs = _unpack(row["evidence"])
                        keep = {
                            k: p
                            for k, p in pp.items()
                            if not (
                                (source and p.source == source)
                                or (run and p.ingestion_run_id == run)
                            )
                        }
                        if len(keep) == len(pp):
                            continue
                        affected += 1
                        if not keep:
                            q = (
                                "MATCH (x:Entity {id:$id}) DETACH DELETE x"
                                if is_node
                                else "MATCH ()-[x]->() WHERE x.id=$id DELETE x"
                            )
                            tx.run(q, id=row["id"]).consume()
                            continue
                        item = (
                            Node(row["id"], row["label"], {})
                            if is_node
                            else Edge(row["source"], row["target"], row["type"], {})
                        )
                        item.evidence = keep
                        item.observations = {k: obs[k] for k in keep}
                        write = NODE_WRITES[row["label"]] if is_node else EDGE_WRITES[row["type"]]
                        tx.run(write, rows=[_row(item)]).consume()
                    return affected

                counts[key] += session.execute_write(remove, rows)
    return counts
