"""Reports are offline evidence; co-mentions never establish attribution."""

import re

from src.graph.model import Graph
from src.ingest.iocs import ingest_iocs
from src.ingest.provenance import evidence
from src.security.sanitize import sanitize

PATTERNS = {
    "Domain": r"\b(?:[a-zA-Z0-9-]+(?:\[\.\]|\.))+[a-zA-Z]{2,}\b",
    "IP": r"\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}\b",
    "FileHash": r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b",
}


def parse_report(item: dict, run: str, ioc_limit: int = 200) -> Graph:
    p = evidence(
        item["source"], item["source_id"], run, item.get("confidence", 0.7), first=item["published"]
    )
    g = Graph()
    text = sanitize(item["text"])
    report_id = "report:" + item["source_id"]
    g.add_node(report_id, "Report", {"name": sanitize(item["title"]), "description": text}, p)
    rows = [
        {"kind": kind, "value": v}
        for kind, pattern in PATTERNS.items()
        for v in re.findall(pattern, text)
    ]
    rows.extend(item.get("indicators", []))
    iocs = ingest_iocs(rows[:ioc_limit], p, ioc_limit)
    g.merge(iocs)
    for id in iocs.nodes:
        g.add_edge(id, report_id, "MENTIONED_IN", p)
    for cve in sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", text))):
        g.add_node(cve, "Vulnerability", {"name": cve}, p)
        g.add_edge(cve, report_id, "MENTIONED_IN", p)
    # Explicit analyst/source assertions only; never derive edges from co-mentions.
    for assertion in item.get("assertions", []):
        for endpoint in ("subject", "object"):
            n = assertion[endpoint]
            g.add_node(n["id"], n["label"], {"name": sanitize(n["name"])}, p)
        g.add_edge(
            assertion["subject"]["id"],
            assertion["object"]["id"],
            assertion["relation"],
            p,
            hypothesis=assertion["relation"] == "ATTRIBUTED_TO",
            inferred=False,
            caveat="Source assertion, not independent attribution. Shared infrastructure, tools and false flags apply.",
        )
    return g
