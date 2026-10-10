"""Persist a deterministic bounded UI/search scope without truncating ingestion."""

import argparse
import json
from pathlib import Path

from src.config import load_config
from src.graph.serialization import from_dict, load, save, to_dict


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", default="data/processed/complete-public-graph.json")
    parser.add_argument("--kev-count", type=int, default=100)
    parser.add_argument("--output", default="data/processed/service-graph.json")
    parser.add_argument("--ids", default="data/processed/service-ids.json")
    args = parser.parse_args()
    if args.kev_count < 1:
        raise ValueError("Positive KEV scope required")
    graph = load(args.graph)
    ids = {
        n.id
        for n in graph.nodes.values()
        if any(
            p.source.startswith("attack:") or p.ingestion_run_id.startswith("fixture")
            for p in n.evidence.values()
        )
    }
    recent = sorted(
        (
            n.id
            for n in graph.nodes.values()
            if n.label == "Vulnerability" and n.properties.get("kev")
        ),
        reverse=True,
    )[: args.kev_count]
    seeds = set(recent)
    ids.update(seeds)
    for edge in graph.edges.values():
        if edge.source in seeds:
            ids.add(edge.target)
    data = to_dict(graph)
    data["nodes"] = [n for n in data["nodes"] if n["id"] in ids]
    data["edges"] = [e for e in data["edges"] if e["source"] in ids and e["target"] in ids]
    data["rejected"] = []
    limits = load_config()["limits"]
    if len(data["nodes"]) > limits["max_nodes"] or len(data["edges"]) > limits["max_edges"]:
        raise ValueError("Requested service scope exceeds bounds; reduce --kev-count")
    save(from_dict(data), args.output)
    Path(args.ids).write_text(json.dumps(sorted(ids)))
    print(f"Service view: {len(data['nodes'])} nodes / {len(data['edges'])} edges")


if __name__ == "__main__":
    main()
