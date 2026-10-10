MATCH (n:Entity) RETURN n.label AS label, count(n) AS count ORDER BY label LIMIT $limit;
