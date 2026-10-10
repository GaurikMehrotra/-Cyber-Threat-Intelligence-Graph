"""Reproducible scoped benchmarks; synthetic index experiment never drops production indexes."""

import random
import statistics
import time

import psutil
from neo4j import Query

from src.analytics.centrality import centrality
from src.graph.client import Client
from src.graph.export_nx import export_nx
from src.graph.loaders import load_graph
from src.graph.model import Graph
from src.graph.queries import QUERIES

BENCH_LABEL = "CTIGBenchmark"


def benchmark(
    client: Client, graph: Graph, seed: int = 42, rounds: int = 20, size: int = 1000
) -> dict:
    if not 1 <= rounds <= 100 or not 1 <= size <= 10000:
        raise ValueError("Benchmark bounds exceeded")
    rss_before = psutil.Process().memory_info().rss
    start = time.perf_counter()
    load_graph(client, graph)
    elapsed = time.perf_counter() - start
    ng = export_nx(graph)
    begin = time.perf_counter()
    centrality(ng, seed=seed)
    nx_seconds = time.perf_counter() - begin
    # Up to 100 IDs are compared using unique-neighbor degree, same undirected semantics.
    ids = sorted(graph.nodes)[:100]
    start = time.perf_counter()
    cy = client.read(QUERIES["degree"], {"ids": ids, "limit": 100})
    cy_seconds = time.perf_counter() - start
    sub = ng.subgraph(ids)
    expected = dict(sub.degree())
    degree_equal = all(expected[r["id"]] == r["degree"] for r in cy)
    timings = {}
    # Deterministic benchmark sampling; no cryptographic use.
    rng = random.Random(seed)  # nosec B311
    with client.driver.session() as session:
        # Namespace is exclusively reserved for this diagnostic command.
        session.run("MATCH (n:CTIGBenchmark) DETACH DELETE n").consume()
        session.run("DROP INDEX ctig_benchmark_id IF EXISTS").consume()
        session.run(
            "UNWIND $rows AS row CREATE (:CTIGBenchmark {id:row.id})",
            rows=[{"id": f"bench-{i}"} for i in range(size)],
        ).consume()
        try:
            for indexed in (False, True):
                if indexed:
                    session.run(
                        "CREATE INDEX ctig_benchmark_id IF NOT EXISTS FOR (n:CTIGBenchmark) ON (n.id)"
                    ).consume()
                    session.run("CALL db.awaitIndexes($seconds)", seconds=30).consume()
                values = []
                dbhits = []
                for _ in range(rounds):
                    ident = f"bench-{rng.randrange(size)}"
                    begin = time.perf_counter()
                    output = session.run(
                        Query(
                            "PROFILE MATCH (n:CTIGBenchmark {id:$id}) RETURN n.id AS id LIMIT $limit",
                            timeout=5,
                        ),
                        id=ident,
                        limit=1,
                    )
                    records = output.data()
                    summary = output.consume()
                    values.append(time.perf_counter() - begin)
                    if records != [{"id": ident}]:
                        raise AssertionError("Benchmark lookup failed")

                    def hits(profile):
                        return profile.get("dbHits", 0) + sum(
                            hits(x) for x in profile.get("children", [])
                        )

                    dbhits.append(hits(summary.profile))
                timings["indexed" if indexed else "unindexed"] = {
                    "median_ms": statistics.median(values) * 1000,
                    "p95_ms": sorted(values)[int(0.95 * (len(values) - 1))] * 1000,
                    "median_db_hits": statistics.median(dbhits),
                    "rounds": rounds,
                }
        finally:
            session.run("MATCH (n:CTIGBenchmark) DETACH DELETE n").consume()
            session.run("DROP INDEX ctig_benchmark_id IF EXISTS").consume()
    return {
        "seed": seed,
        "index_experiment": {
            "dataset": "synthetic CTIGBenchmark equality lookup; not production query speed",
            "nodes": size,
            **timings,
        },
        "ingestion": {
            "seconds": elapsed,
            "items_per_second": (len(graph.nodes) + len(graph.edges)) / elapsed,
            "items": len(graph.nodes) + len(graph.edges),
        },
        "comparison": {
            "networkx_all_centrality_seconds": nx_seconds,
            "cypher_degree_seconds": cy_seconds,
            "degree_equal": degree_equal,
            "node_count": len(ids),
            "caveat": "Different workloads: NetworkX computes three centralities; Cypher computes degree only. Cypher compares selected subgraph degrees; no GDS plugin is assumed.",
        },
        "python_rss_before_bytes": rss_before,
        "python_rss_after_bytes": psutil.Process().memory_info().rss,
        "python_peak_rss_bytes": __import__("resource")
        .getrusage(__import__("resource").RUSAGE_SELF)
        .ru_maxrss
        * 1024,
        "neo4j_memory": "measure with docker stats --no-stream; container includes JVM/off-heap/page cache",
        "machine": "cloud current instance; laptop measurements must be rerun",
    }
