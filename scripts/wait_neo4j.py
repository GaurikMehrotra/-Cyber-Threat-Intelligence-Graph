"""Bounded driver-level startup readiness, not just an open port."""

import time

from src.graph.client import Client


def main() -> None:
    client = Client()
    try:
        for attempt in range(60):
            try:
                client.verify()
                with client.driver.session() as s:
                    value = s.run("RETURN $value AS value", value="ready").single()["value"]
                if value != "ready":
                    raise RuntimeError("Unexpected Neo4j response")
                print("Neo4j driver and query readiness verified")
                return
            except Exception:
                if attempt == 59:
                    raise
                time.sleep(2)
    finally:
        client.close()


if __name__ == "__main__":
    main()
