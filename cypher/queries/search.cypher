MATCH (n:Entity) WHERE toLower(n.name) CONTAINS toLower($text) RETURN n.id AS id, n.label AS label, n.payload AS payload, n.evidence AS evidence ORDER BY n.id SKIP $offset LIMIT $limit;
