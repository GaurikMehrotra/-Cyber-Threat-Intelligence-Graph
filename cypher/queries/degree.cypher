MATCH (n:Entity) WHERE n.id IN $ids OPTIONAL MATCH (n)-[r]-(m:Entity) WHERE m.id IN $ids AND coalesce(r.inferred, false) = false RETURN n.id AS id, count(DISTINCT m) AS degree LIMIT $limit;
