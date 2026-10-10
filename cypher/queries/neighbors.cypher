MATCH (n:Entity {id: $id})-[r]-(m:Entity) RETURN m.id AS id, m.label AS label, m.payload AS payload, m.evidence AS evidence, type(r) AS relationship ORDER BY m.id SKIP $offset LIMIT $limit;
