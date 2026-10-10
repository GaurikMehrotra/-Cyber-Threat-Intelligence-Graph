MATCH (n:Entity {id: $id}) RETURN n.id AS id, n.label AS label, n.payload AS payload, n.evidence AS evidence LIMIT $limit;
