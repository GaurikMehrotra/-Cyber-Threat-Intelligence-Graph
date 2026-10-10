"""CISA KEV is exploitation evidence, never actor attribution."""

import re

from src.graph.model import Graph
from src.ingest.provenance import evidence
from src.security.sanitize import sanitize


def parse_kev(data: dict, run: str) -> Graph:
    g = Graph()
    for item in data["vulnerabilities"]:
        cve = item["cveID"].upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            raise ValueError("Malformed KEV CVE")
        date = item["dateAdded"] + "T00:00:00+00:00"
        p = evidence("cisa-kev", cve, run, first=date)
        g.add_node(
            cve,
            "Vulnerability",
            {
                "name": cve,
                "description": sanitize(item.get("shortDescription", "")),
                "kev": True,
                "due_date": item.get("dueDate", ""),
                "required_action": sanitize(item.get("requiredAction", "")),
            },
            p,
        )
        product = "product:" + item["vendorProject"].lower() + ":" + item["product"].lower()
        g.add_node(
            product,
            "Product",
            {"name": sanitize(item["product"]), "vendor": sanitize(item["vendorProject"])},
            p,
        )
        g.add_edge(cve, product, "AFFECTS", p)
        for cwe in item.get("cwes", []):
            if re.fullmatch(r"CWE-\d+", cwe):
                g.add_node(cwe, "Weakness", {"name": cwe}, p)
                g.add_edge(cve, cwe, "HAS_WEAKNESS", p)
    return g
