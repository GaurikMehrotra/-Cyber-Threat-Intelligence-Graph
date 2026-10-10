"""Reproducible terminal workflow; public collection requires a terms acknowledgment."""

import argparse
import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from src.config import load_config
from src.graph.model import Graph
from src.graph.serialization import load, save
from src.ingest.attack import load_attack, parse_attack
from src.ingest.cwe import parse_cwe
from src.ingest.kev import parse_kev
from src.ingest.nvd import parse_nvd
from src.ingest.reports import parse_report


def output(value: dict, path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(value, indent=2))
    print(json.dumps(value, indent=2))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Defensive CTIG: offline-first, no IOC network operations"
    )
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("fixtures")
    for name in ("load", "quality", "analytics", "stix", "purge", "benchmark"):
        pp = sub.add_parser(name)
        pp.add_argument("--graph", default="data/fixtures/graph.json")
        pp.add_argument("--output", default=f"reports/local/{name}.json")
        if name == "purge":
            pp.add_argument("--source")
            pp.add_argument("--run")
            pp.add_argument("--neo4j", action="store_true")
    sub.add_parser("schema")
    pp = sub.add_parser("predict")
    pp.add_argument("--old", default="data/fixtures/attack-old.json")
    pp.add_argument("--new", default="data/fixtures/attack-new.json")
    pp.add_argument("--output", default="reports/local/prediction.json")
    pp.add_argument("--sentence", action="store_true")
    pp = sub.add_parser("index")
    pp.add_argument("--graph", default="data/fixtures/graph.json")
    pp.add_argument("--directory", default="data/processed/index")
    pp.add_argument("--mode", choices=["sentence", "tfidf"], default="sentence")
    pp = sub.add_parser("golden")
    pp.add_argument("--questions", default="data/eval/golden_queries.json")
    pp.add_argument("--output", default="reports/local/golden.json")
    pp = sub.add_parser("er-eval")
    pp.add_argument("--pairs", default="data/eval/alias_pairs.csv")
    pp.add_argument("--output", default="reports/local/er.json")
    pp = sub.add_parser("resolve")
    pp.add_argument("--graph", default="data/fixtures/graph.json")
    pp.add_argument("--sentence", action="store_true")
    pp.add_argument("--output", default="data/processed/alias-review.jsonl")
    pp = sub.add_parser("ingest")
    pp.add_argument(
        "--kind", choices=["attack", "kev", "nvd", "cwe", "report", "ioc"], required=True
    )
    pp.add_argument("--input", required=True)
    pp.add_argument("--release", default="local-import")
    pp.add_argument("--run")
    pp.add_argument("--output", default="data/processed/graph.json")
    pp.add_argument("--source", default="local-ioc")
    pp.add_argument("--source-id", default="local-file")
    pp.add_argument("--published", default="2024-01-01T00:00:00Z")
    pp = sub.add_parser("collect")
    pp.add_argument("--accept-source-terms", action="store_true")
    pp.add_argument(
        "--sources", nargs="+", choices=["attack", "kev", "cwe"], default=["attack", "kev", "cwe"]
    )
    pp.add_argument("--old-tag", default="v16.1")
    pp.add_argument("--new-tag", default="v17.1")
    pp.add_argument("--with-nvd", action="store_true")
    pp.add_argument("--cwe-version", default="4.17")
    pp.add_argument("--output", default="data/processed/public-graph.json")
    return p


def main() -> None:
    args = parser().parse_args()
    cfg = load_config()
    limits = cfg["limits"]
    if args.command == "fixtures":
        from scripts.make_fixtures import main as make

        make()
        print("Synthetic fixtures generated")
        return
    if args.command == "collect":
        if not args.accept_source_terms:
            raise SystemExit(
                "Read DATA_SOURCES.md and current publisher terms, then explicitly pass --accept-source-terms"
            )
        from src.ingest.collect import Collector, collect_attack, collect_scoped_nvd

        c = Collector(
            delay=limits["feed_delay_seconds"],
            max_bytes=limits["collection_bytes"],
            timeout=limits["download_timeout_seconds"],
            retries=limits["download_retries"],
            ttl=limits["cache_ttl_seconds"],
            max_requests=limits["collection_requests"],
        )
        raw = Path("data/raw")
        graph = Graph()
        if "attack" in args.sources:
            for tag in [args.old_tag, args.new_tag]:
                release = Graph()
                for domain in ("enterprise", "mobile", "ics"):
                    bundle = collect_attack(c, tag, domain)
                    (raw / f"attack-{tag}-{domain}.json").write_text(json.dumps(bundle))
                    release.merge(parse_attack(bundle, tag, "attack:" + tag))
                save(release, Path("data/processed") / f"attack-{tag}.json")
                if tag == args.new_tag:
                    graph.merge(release)
        if "kev" in args.sources:
            kev = json.loads(
                c.fetch(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                )
            )
            (raw / "kev.json").write_text(json.dumps(kev))
            graph.merge(
                parse_kev(
                    kev,
                    "kev:"
                    + hashlib.sha256(json.dumps(kev, sort_keys=True).encode()).hexdigest()[:12],
                )
            )
        if args.with_nvd:
            if "kev" not in args.sources:
                raise ValueError("--with-nvd requires --sources kev to define the bounded CVE set")
            current = datetime.now(UTC).year
            cves = [
                x["cveID"]
                for x in kev["vulnerabilities"]
                if int(x["cveID"].split("-")[1]) >= current - limits["nvd_years"]
            ]
            nvd = collect_scoped_nvd(c, cves, limits["nvd_cve_limit"])
            (raw / "nvd.json").write_text(json.dumps(nvd))
            graph.merge(
                parse_nvd(
                    nvd,
                    "nvd:"
                    + hashlib.sha256(json.dumps(nvd, sort_keys=True).encode()).hexdigest()[:12],
                )
            )
        if "cwe" in args.sources:
            import re

            if not re.fullmatch(r"\d+\.\d+", args.cwe_version):
                raise ValueError("Invalid CWE version")
            zipped = c.fetch(f"https://cwe.mitre.org/data/xml/cwec_v{args.cwe_version}.xml.zip")
            with zipfile.ZipFile(io.BytesIO(zipped)) as z:
                candidates = [x for x in z.infolist() if x.filename.endswith(".xml")]
                if len(candidates) != 1 or candidates[0].file_size > limits["collection_bytes"]:
                    raise ValueError("Unexpected or excessive CWE archive")
                xml = z.read(candidates[0]).decode()
            graph.merge(parse_cwe(xml, "cwe:" + args.cwe_version, datetime.now(UTC).isoformat()))
        save(graph, args.output)
        print(f"Collected {len(graph.nodes)} nodes / {len(graph.edges)} edges; no IOCs contacted")
        return
    if args.command == "ingest":
        path = Path(args.input)
        if path.stat().st_size > limits["collection_bytes"]:
            raise ValueError("Input exceeds bound")
        text = path.read_text()
        run = args.run or hashlib.sha256(text.encode()).hexdigest()[:16]
        if args.kind == "cwe":
            g = parse_cwe(text, run, args.published)
        elif args.kind == "attack":
            g = parse_attack(json.loads(text), args.release, run)
        elif args.kind == "kev":
            g = parse_kev(json.loads(text), run)
        elif args.kind == "nvd":
            g = parse_nvd(json.loads(text), run)
        elif args.kind == "report":
            g = parse_report(json.loads(text), run, limits["ioc_limit"])
        else:
            from src.ingest.iocs import ingest_iocs
            from src.ingest.provenance import evidence

            g = ingest_iocs(
                json.loads(text),
                evidence(args.source, args.source_id, run, first=args.published),
                limits["ioc_limit"],
            )
        if Path(args.output).exists():
            g = load(args.output).merge(g)
        save(g, args.output)
        print(f"Saved {len(g.nodes)} nodes / {len(g.edges)} edges")
        return
    if args.command == "index":
        from src.search.semantic_index import SemanticIndex, SentenceEncoder

        g = load(args.graph)
        ids = sorted(g.nodes)
        texts = [
            g.nodes[id].properties.get("name", "")
            + " "
            + g.nodes[id].properties.get("description", "")
            for id in ids
        ]
        encoder = (
            SentenceEncoder(cfg["search"]["model"], cfg["search"]["batch_size"])
            if args.mode == "sentence"
            else None
        )
        index = SemanticIndex(args.directory, args.mode, cfg["search"]["max_documents"], encoder)
        index.build(ids, texts)
        print(index.search("phishing"))
        return
    if args.command == "resolve":
        from src.resolve.aliases import alias_candidates
        from src.resolve.review_queue import write_queue

        g = load(args.graph)
        rows = alias_candidates(g)
        if args.sentence:
            from src.resolve.embeddings import fuzzy_candidates
            from src.search.semantic_index import SentenceEncoder

            ids = sorted(
                n.id for n in g.nodes.values() if n.label in {"ThreatActor", "Malware", "Tool"}
            )
            vectors = SentenceEncoder().encode(
                [g.nodes[id].properties.get("name", "") for id in ids]
            )
            rows += fuzzy_candidates(
                ids,
                [g.nodes[id].label for id in ids],
                vectors,
                **{
                    k: cfg["resolution"][v]
                    for k, v in [
                        ("auto", "auto_threshold"),
                        ("review", "review_threshold"),
                        ("max_pairs", "max_pairs"),
                    ]
                },
            )
        write_queue(rows, args.output)
        print(f"Queued {len(rows)} candidates; no destructive merges")
        return
    if args.command == "predict":
        from src.predict.evaluate import evaluate
        from src.search.semantic_index import SentenceEncoder

        old = (
            load(args.old)
            if "nodes" in json.loads(Path(args.old).read_text())
            else load_attack(args.old, "old", "prediction-old")
        )
        new = (
            load(args.new)
            if "nodes" in json.loads(Path(args.new).read_text())
            else load_attack(args.new, "new", "prediction-new")
        )
        pp = cfg["prediction"]
        result = evaluate(
            old,
            new,
            pp["seeds"],
            pp["negatives_per_positive"],
            pp["k"],
            pp["max_candidates"],
            SentenceEncoder() if args.sentence else None,
        )
        output(result, args.output)
        return
    if args.command == "er-eval":
        from src.eval.er_eval import evaluate_pairs

        output(evaluate_pairs(args.pairs, cfg["resolution"]["auto_threshold"]), args.output)
        return
    if (
        args.command in {"schema", "load", "golden", "benchmark"}
        or args.command == "purge"
        and args.neo4j
    ):
        from src.graph.client import Client

        client = Client()
        try:
            client.verify()
            if args.command == "schema":
                from src.graph.schema import apply_schema

                apply_schema(client)
                print("Schema installed")
            elif args.command == "load":
                from src.graph.loaders import load_graph

                g = load(args.graph)
                load_graph(client, g, limits["batch_size"])
                print(f"Loaded {len(g.nodes)} nodes / {len(g.edges)} edges")
            elif args.command == "purge":
                from src.graph.loaders import purge

                output(purge(client, args.source, args.run), args.output)
            elif args.command == "golden":
                from src.eval.golden_queries import run_golden

                output(run_golden(client, args.questions), args.output)
            else:
                from src.eval.perf import benchmark

                output(benchmark(client, load(args.graph), cfg["analytics"]["seed"]), args.output)
        finally:
            client.close()
        return
    g = load(args.graph)
    if args.command == "purge":
        g.purge(source=args.source, run=args.run)
        save(g, args.output)
        return
    if args.command == "quality":
        from src.quality.checks import checks

        output(checks(g), args.output)
    elif args.command == "stix":
        from src.intel.stix_export import export_stix

        output(export_stix(g), args.output)
    elif args.command == "analytics":
        from src.analytics.centrality import centrality
        from src.analytics.communities import communities
        from src.analytics.coverage import coverage
        from src.analytics.cve_priority import prioritize
        from src.graph.export_nx import export_nx

        ng = export_nx(g, limits["max_nodes"], limits["max_edges"])
        cc = centrality(
            ng,
            cfg["analytics"]["seed"],
            cfg["analytics"]["betweenness_samples"],
            cfg["analytics"]["pagerank_alpha"],
        )
        output(
            {
                "centrality": cc,
                "communities": communities(ng, cfg["analytics"]["seed"]),
                "coverage": coverage(g),
                "cve_priority": [
                    prioritize(
                        g,
                        n.id,
                        cfg["analytics"]["priority_weights"],
                        cc["pagerank"],
                        cfg["analytics"]["priority_degree_scale"],
                    )
                    for n in g.nodes.values()
                    if n.label == "Vulnerability"
                ],
                "config": cfg["analytics"],
            },
            args.output,
        )


if __name__ == "__main__":
    main()
