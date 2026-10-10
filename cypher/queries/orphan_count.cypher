MATCH (n:Entity) WHERE NOT (n)--() RETURN count(n) AS count LIMIT $limit;
