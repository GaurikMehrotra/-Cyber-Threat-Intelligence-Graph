"""Scoped NVD CVEs, CPE products and weakness references."""

import re

from src.graph.model import Graph
from src.ingest.provenance import evidence
from src.security.sanitize import sanitize


def parse_nvd(data: dict, run: str) -> Graph:
    g = Graph()

    def cpes(nodes: list[dict]):
        for node in nodes:
            yield from (x for x in node.get("cpeMatch", []) if x.get("vulnerable", False))
            yield from cpes(node.get("nodes", []))

    for entry in data.get("vulnerabilities", []):
        c = entry["cve"]
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", c["id"]):
            raise ValueError("Invalid CVE")
        first = c["published"] + (
            "Z" if not c["published"].endswith("Z") and "+" not in c["published"] else ""
        )
        last = c["lastModified"] + (
            "Z" if not c["lastModified"].endswith("Z") and "+" not in c["lastModified"] else ""
        )
        p = evidence("nvd", c["id"], run, first=first, last=last)
        scores = [
            x["cvssData"]["baseScore"]
            for k, v in c.get("metrics", {}).items()
            if k.startswith("cvssMetric")
            for x in v
        ]
        g.add_node(
            c["id"],
            "Vulnerability",
            {
                "name": c["id"],
                "description": sanitize(
                    next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
                ),
                "cvss": max(scores, default=0),
            },
            p,
        )
        for weakness in c.get("weaknesses", []):
            for d in weakness.get("description", []):
                if re.fullmatch(r"CWE-\d+", d["value"]):
                    g.add_node(d["value"], "Weakness", {"name": d["value"]}, p)
                    g.add_edge(c["id"], d["value"], "HAS_WEAKNESS", p)
        for config in c.get("configurations", []):
            for match in cpes(config.get("nodes", [])):
                ident = "product:" + match["criteria"]
                g.add_node(ident, "Product", {"name": sanitize(match["criteria"])}, p)
                g.add_edge(
                    c["id"],
                    ident,
                    "AFFECTS",
                    p,
                    version_end_excluding=match.get("versionEndExcluding", ""),
                )
    return g
