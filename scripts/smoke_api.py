"""Request only our local application; never contact indicator destinations."""

import os
from urllib.parse import urlsplit

import httpx
from dotenv import load_dotenv


def main() -> None:
    load_dotenv()
    base = os.getenv("CTIG_SMOKE_URL", "http://127.0.0.1:8000")
    u = urlsplit(base)
    if u.hostname not in {"127.0.0.1", "localhost", "::1"} or u.scheme != "http":
        raise ValueError("Smoke target must be local")
    headers = {"X-API-Key": os.environ["CTIG_API_KEY"]}
    with httpx.Client(base_url=base, timeout=30, follow_redirects=False) as client:
        response = client.get("/api/quality", headers=headers)
        response.raise_for_status()
        if response.json()["node_count"] <= 0:
            raise RuntimeError("No graph nodes")
        response = client.get("/api/visualization", headers=headers)
        response.raise_for_status()
        if len(response.json()["nodes"]) > 200:
            raise RuntimeError("Visualization node cap violated")
        if client.get("/api/quality").status_code != 401:
            raise RuntimeError("Authentication did not fail closed")
        body = {"template": "counts", "params": {"limit": 100}}
        result = client.post("/api/query/preview", json=body, headers=headers)
        result.raise_for_status()
        preview = result.json()
        if preview["executed"] is not False:
            raise RuntimeError("Preview executed unexpectedly")
        body.update(confirmed=True, preview_token=preview["preview_token"])
        result = client.post("/api/query/execute", json=body, headers=headers)
        result.raise_for_status()
        if not result.json()["items"]:
            raise RuntimeError("Confirmed query returned no counts")
    print("Live Neo4j API: quality, visualization, auth, preview and confirmed Cypher passed")


if __name__ == "__main__":
    main()
