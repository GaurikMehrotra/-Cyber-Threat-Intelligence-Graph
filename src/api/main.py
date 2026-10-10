"""Local single-worker API with explicit bounds and no IOC networking."""

import json
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from src.api.rate_limit import RateLimiter
from src.api.routes.entities import router
from src.config import load_config
from src.graph.serialization import load


def create_app(fixture_graph=None, config: dict | None = None) -> FastAPI:
    cfg = config or load_config()

    @asynccontextmanager
    async def lifespan(app):
        yield
        if app.state.client:
            app.state.client.close()

    app = FastAPI(
        title="Defensive Cyber Threat Intelligence Graph",
        version="0.1.0",
        lifespan=lifespan,
        description="Indicators are inert data. Attribution and predictions are hypotheses with evidence.",
    )
    app.state.preview_secret = secrets.token_bytes(32)
    app.state.config = cfg
    app.state.limiter = RateLimiter(
        cfg["limits"]["rate_limit"], cfg["limits"]["rate_window_seconds"]
    )
    app.state.client = None
    app.state.index = None
    backend = os.getenv("CTIG_BACKEND", "neo4j")
    if fixture_graph is not None:
        app.state.get_graph = lambda: fixture_graph
    elif backend == "fixture":
        g = load("data/fixtures/graph.json")
        app.state.get_graph = lambda: g
    else:

        def get_graph():
            from src.graph.client import Client
            from src.graph.loaders import export_graph

            if app.state.client is None:
                app.state.client = Client()
            limits = cfg["limits"]
            if os.getenv("CTIG_SUBGRAPH"):
                ids = json.loads(Path(os.environ["CTIG_SUBGRAPH"]).read_text())
            else:
                with app.state.client.driver.session(default_access_mode="READ") as session:
                    ids = [
                        r["id"]
                        for r in session.run(
                            "MATCH (n:Entity) RETURN n.id AS id ORDER BY id LIMIT $limit",
                            limit=limits["max_nodes"] + 1,
                        )
                    ]
            return export_graph(app.state.client, ids, limits["max_nodes"], limits["max_edges"])

        app.state.get_graph = get_graph

        def entity_graph(id: str):
            from src.graph.client import Client
            from src.graph.loaders import export_graph

            if app.state.client is None:
                app.state.client = Client()
            limits = cfg["limits"]
            return export_graph(app.state.client, [id], 1, limits["max_edges"])

        app.state.entity_graph = entity_graph
    if os.getenv("CTIG_INDEX"):
        from src.search.semantic_index import SemanticIndex

        app.state.index = SemanticIndex(
            os.environ["CTIG_INDEX"], cfg["search"]["mode"], cfg["search"]["max_documents"]
        )
        app.state.index.load()

    @app.middleware("http")
    async def bounds(request: Request, call_next):
        cap = cfg["limits"]["max_request_bytes"]
        size = 0
        parts = []
        async for part in request.stream():
            size += len(part)
            if size > cap:
                return JSONResponse({"detail": "Request body too large"}, status_code=413)
            parts.append(part)
        request._body = b"".join(parts)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    app.include_router(router, prefix="/api")

    @app.get("/health")
    def health():
        return {
            "status": "alive",
            "backend": backend,
            "readiness": "use authenticated /api/quality",
        }

    @app.get("/", response_class=HTMLResponse)
    def ui():
        return Path("app/index.html").read_text()

    from fastapi.staticfiles import StaticFiles

    app.mount("/static", StaticFiles(directory="app/static"), name="static")
    return app


app = create_app()
