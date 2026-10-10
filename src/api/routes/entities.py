"""Bounded evidence-aware API; no raw query endpoint."""

import hashlib
import hmac
import json
import time

import networkx as nx
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.analytics.centrality import centrality
from src.analytics.cve_priority import prioritize
from src.analytics.pivot import pivot
from src.analytics.similarity import profiles, similar_actors
from src.api.auth import authenticate
from src.graph.export_nx import export_nx
from src.graph.queries import QUERIES
from src.intel.defang import defang, refang
from src.intel.stix_export import export_stix
from src.quality.checks import checks
from src.search.nl2cypher import FakeLLM, preview
from src.security.cypher_guard import validate

router = APIRouter()


def secured(request: Request, identity: str = Depends(authenticate)) -> None:
    request.app.state.limiter.check()


router.dependencies = [Depends(secured)]


def graph(request: Request):
    try:
        return request.app.state.get_graph()
    except ValueError as exc:
        raise HTTPException(413, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "Graph backend unavailable") from exc


def node(g, id: str):
    id = refang(id)
    if id not in g.nodes:
        raise HTTPException(404, "Entity not found")
    return g.nodes[id]


def edges_public(g, ids: set[str]) -> list[dict]:
    return [
        {
            "source": g.nodes[e.source].public()["id"],
            "target": g.nodes[e.target].public()["id"],
            "type": e.type,
            "properties": e.properties,
            "provenance": [p.to_dict() for p in e.evidence.values()],
            "prediction": bool(e.properties.get("inferred")),
            "caveat": e.properties.get("caveat", ""),
        }
        for e in g.edges.values()
        if e.source in ids and e.target in ids
    ]


@router.get("/entity")
def entity(request: Request, id: str = Query(max_length=512)) -> dict:
    if hasattr(request.app.state, "entity_graph"):
        try:
            return node(request.app.state.entity_graph(refang(id)), id).public()
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(503, "Graph backend unavailable") from exc
    return node(graph(request), id).public()


@router.get("/search")
def search(
    request: Request,
    q: str = Query(min_length=1, max_length=512),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0, le=10000),
    semantic: bool = False,
) -> dict:
    g = graph(request)
    if semantic:
        index = request.app.state.index
        if index is None:
            raise HTTPException(503, "Build and configure CTIG_INDEX first")
        rows = index.search(q, limit)
        return {
            "items": [
                {**g.nodes[r["id"]].public(), "score": r["score"], "mode": r["mode"]}
                for r in rows
                if r["id"] in g.nodes
            ],
            "offset": 0,
        }
    nodes = sorted(
        (
            n
            for n in g.nodes.values()
            if q.casefold()
            in (
                n.properties.get("name", "")
                + " "
                + n.properties.get("description", "")
                + " "
                + " ".join(n.properties.get("aliases", []))
            ).casefold()
        ),
        key=lambda n: n.id,
    )
    return {
        "items": [n.public() for n in nodes[offset : offset + limit]],
        "total": len(nodes),
        "offset": offset,
    }


@router.get("/neighbors")
def neighbors(
    request: Request,
    id: str = Query(max_length=512),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0, le=10000),
) -> dict:
    g = graph(request)
    n = node(g, id)
    nxg = export_nx(g)
    ids = sorted(nxg.neighbors(n.id))[offset : offset + limit]
    selected = set(ids) | {n.id}
    return {
        "items": [g.nodes[x].public() for x in ids],
        "edges": edges_public(g, selected),
        "offset": offset,
    }


@router.get("/shortest-path")
def shortest_path(
    request: Request, source: str = Query(max_length=512), target: str = Query(max_length=512)
) -> dict:
    g = graph(request)
    a = node(g, source)
    b = node(g, target)
    try:
        path = nx.shortest_path(export_nx(g), a.id, b.id)
    except nx.NetworkXNoPath:
        raise HTTPException(404, "No observed path") from None
    if len(path) > 200:
        raise HTTPException(413, "Path exceeds rendering bound")
    return {
        "nodes": [g.nodes[x].public() for x in path],
        "edges": edges_public(g, set(path)),
        "caveat": "A path is not proof of attribution.",
    }


@router.get("/pivot")
def infrastructure_pivot(
    request: Request,
    id: str = Query(max_length=512),
    depth: int = Query(2, ge=0, le=3),
    limit: int = Query(100, ge=1, le=200),
) -> dict:
    g = graph(request)
    n = node(g, id)
    if n.label not in {"Domain", "IP", "URL", "FileHash", "Report", "Malware", "ThreatActor"}:
        raise HTTPException(422, "Unsupported pivot entity")
    limits = request.app.state.config["limits"]
    result = pivot(export_nx(g), n.id, depth, limits["hub_degree"], limit)
    ids = result.pop("nodes")
    return {
        **result,
        "nodes": [g.nodes[x].public() for x in ids],
        "edges": edges_public(g, set(ids)),
    }


@router.get("/similar-actors")
def similar(
    request: Request,
    id: str = Query(max_length=512),
    limit: int = Query(20, ge=1, le=100),
    embedding: bool = False,
) -> dict:
    g = graph(request)
    n = node(g, id)
    if n.label != "ThreatActor":
        raise HTTPException(422, "Expected actor")
    vectors = None
    if embedding:
        index = request.app.state.index
        if index is None:
            raise HTTPException(503, "Configure CTIG_INDEX for embedding similarity")
        vectors = dict(zip(index.ids, index.vectors, strict=True))
    return {"items": similar_actors(g, n.id, vectors)[:limit]}


@router.get("/actor-profile")
def actor_profile(request: Request, id: str = Query(max_length=512)) -> dict:
    g = graph(request)
    n = node(g, id)
    if n.label != "ThreatActor":
        raise HTTPException(422, "Expected actor")
    ids = profiles(g)[n.id]
    return {
        "actor": n.public(),
        "techniques": [g.nodes[t].public() for t in sorted(ids)],
        "edges": edges_public(g, ids | {n.id}),
    }


@router.get("/cve-context")
def cve_context(request: Request, id: str = Query(max_length=512)) -> dict:
    g = graph(request)
    n = node(g, id)
    if n.label != "Vulnerability":
        raise HTTPException(422, "Expected CVE")
    ranks = centrality(export_nx(g))["pagerank"]
    return {
        "entity": n.public(),
        "priority": prioritize(
            g,
            n.id,
            request.app.state.config["analytics"]["priority_weights"],
            ranks,
            request.app.state.config["analytics"]["priority_degree_scale"],
        ),
        "context": neighbors(request, n.id, 100, 0),
    }


@router.get("/quality")
def quality(request: Request) -> dict:
    return checks(graph(request))


@router.get("/stix")
def stix(request: Request) -> dict:
    # STIX interchange requires refanged SCO values. Explicit opt-in export; never active links.
    return export_stix(graph(request))


@router.get("/visualization")
def visualization(request: Request, limit: int = Query(100, ge=1, le=200)) -> dict:
    g = graph(request)
    nxg = export_nx(g)
    seeds = sorted(
        n.id
        for n in g.nodes.values()
        if n.label in {"ThreatActor", "Vulnerability", "Domain", "IP"}
    )
    ids = set()
    for seed in seeds:
        if len(ids) >= limit:
            break
        found = pivot(nxg, seed, 2, request.app.state.config["limits"]["hub_degree"], limit)
        for selected in found["nodes"]:
            if len(ids) >= limit:
                break
            ids.add(selected)
    for selected in sorted(g.nodes):
        if len(ids) >= limit:
            break
        ids.add(selected)
    return {
        "nodes": [g.nodes[x].public() for x in sorted(ids)],
        "edges": edges_public(g, ids),
        "truncated": len(g.nodes) > limit,
    }


@router.post("/query/preview")
def query_preview(request: Request, body: dict) -> dict:
    try:
        query = QUERIES[body["template"]]
        validate(query, body["params"])
    except (KeyError, ValueError, TypeError) as exc:
        raise HTTPException(422, "Invalid template or parameters") from exc
    expires = int(time.time()) + request.app.state.config["limits"]["preview_ttl_seconds"]
    digest = _preview_digest(request, body, expires)
    return {
        "cypher": query,
        "params": body["params"],
        "executed": False,
        "preview_token": str(expires) + ":" + digest,
    }


def _preview_digest(request: Request, body: dict, expires: int) -> str:
    payload = json.dumps(
        [body["template"], body["params"], expires], sort_keys=True, separators=(",", ":")
    )
    return hmac.new(request.app.state.preview_secret, payload.encode(), hashlib.sha256).hexdigest()


@router.post("/query/execute")
def query_execute(request: Request, body: dict) -> dict:
    result = query_preview(request, body)
    if body.get("confirmed") is not True:
        raise HTTPException(422, "Preview and explicitly confirm the displayed query first")
    try:
        expires_text, digest = body["preview_token"].split(":", 1)
        expires = int(expires_text)
        ttl = request.app.state.config["limits"]["preview_ttl_seconds"]
        if not int(time.time()) <= expires <= int(time.time()) + ttl or not hmac.compare_digest(
            digest, _preview_digest(request, body, expires)
        ):
            raise ValueError("Invalid preview token")
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(
            422, "Preview token missing, expired, or does not match this query"
        ) from exc
    client = request.app.state.client
    if client is None:
        graph(request)
        client = request.app.state.client
        if client is None:
            raise HTTPException(503, "Cypher requires Neo4j backend")
    rows = client.read(result["cypher"], result["params"])
    # Do not expose refanged indicator properties via the generic read endpoint.
    return {"items": _defang_rows(rows)}


def _defang_rows(value):
    if isinstance(value, str):
        return defang(value)
    if isinstance(value, list):
        return [_defang_rows(x) for x in value]
    if isinstance(value, dict):
        return {k: _defang_rows(v) for k, v in value.items()}
    return value


@router.post("/nl/preview")
def nl_preview(body: dict) -> dict:
    if not isinstance(body.get("question"), str) or len(body["question"]) > 512:
        raise HTTPException(422, "Invalid question")
    return {
        **preview(body["question"], FakeLLM()),
        "provider": "FakeLLM demo; no real interpretation",
    }
