"""Apply developer-owned DDL, never user-supplied schema."""

from pathlib import Path

from src.graph.client import Client


def apply_schema(client: Client, path: str | Path = "cypher/schema.cypher") -> None:
    with client.driver.session() as session:
        for statement in Path(path).read_text().split(";"):
            if statement.strip():
                session.run(statement).consume()
