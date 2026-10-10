"""Official driver wrapper: bounded, timed reads with explicit ownership."""

import os

from neo4j import READ_ACCESS, GraphDatabase, Query

from src.config import load_config


class Client:
    def __init__(
        self, uri: str | None = None, user: str | None = None, password: str | None = None
    ):
        self.config = load_config()
        secret = password or os.getenv("NEO4J_PASSWORD")
        if not secret:
            raise ValueError("Set NEO4J_PASSWORD securely in your environment")
        self.driver = GraphDatabase.driver(
            uri or os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687"),
            auth=(user or os.getenv("NEO4J_USER", "neo4j"), secret),
            max_connection_pool_size=4,
            connection_timeout=self.config["limits"]["query_timeout_seconds"],
        )

    def close(self) -> None:
        self.driver.close()

    def verify(self) -> None:
        self.driver.verify_connectivity()

    def read(self, cypher: str, params: dict) -> list[dict]:
        from src.security.cypher_guard import validate

        validate(cypher, params)
        with self.driver.session(default_access_mode=READ_ACCESS) as session:
            result = session.run(
                Query(cypher, timeout=self.config["limits"]["query_timeout_seconds"]), params
            )
            return [r.data() for r in result]
