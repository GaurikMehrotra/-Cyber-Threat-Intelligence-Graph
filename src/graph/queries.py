"""An exact template allowlist: no arbitrary query or LLM-generated Cypher."""

QUERIES = {
    "entity": "MATCH (n:Entity {id: $id}) RETURN n.id AS id, n.label AS label, n.payload AS payload, n.evidence AS evidence LIMIT $limit",
    "search": "MATCH (n:Entity) WHERE toLower(n.name) CONTAINS toLower($text) RETURN n.id AS id, n.label AS label, n.payload AS payload, n.evidence AS evidence ORDER BY n.id SKIP $offset LIMIT $limit",
    "neighbors": "MATCH (n:Entity {id: $id})-[r]-(m:Entity) RETURN m.id AS id, m.label AS label, m.payload AS payload, m.evidence AS evidence, type(r) AS relationship ORDER BY m.id SKIP $offset LIMIT $limit",
    "degree": "MATCH (n:Entity) WHERE n.id IN $ids OPTIONAL MATCH (n)-[r]-(m:Entity) WHERE m.id IN $ids AND coalesce(r.inferred, false) = false RETURN n.id AS id, count(DISTINCT m) AS degree LIMIT $limit",
    "counts": "MATCH (n:Entity) RETURN n.label AS label, count(n) AS count ORDER BY label LIMIT $limit",
    "orphan_count": "MATCH (n:Entity) WHERE NOT (n)--() RETURN count(n) AS count LIMIT $limit",
    "actor_profile": "MATCH (a:ThreatActor {id: $id})-[r:USES]->(t:Technique) WHERE coalesce(r.inferred, false) = false RETURN t.id AS id, t.name AS name, t.external_id AS external_id, r.evidence AS evidence ORDER BY t.id SKIP $offset LIMIT $limit",
}
