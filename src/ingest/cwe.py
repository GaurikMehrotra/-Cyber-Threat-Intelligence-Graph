"""Bounded XML parsing with DTD and entity declarations rejected."""

from defusedxml import ElementTree as ET

from src.graph.model import Graph
from src.ingest.provenance import evidence
from src.security.sanitize import sanitize


def parse_cwe(xml: str, run: str, timestamp: str) -> Graph:
    if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        raise ValueError("DTD/entities forbidden")
    root = ET.fromstring(xml)
    published = root.attrib.get("Date")
    if published:
        timestamp = published + "T00:00:00Z" if len(published) == 10 else published
    g = Graph()
    for element in root.iter():
        if element.tag.split("}")[-1] != "Weakness":
            continue
        id = "CWE-" + element.attrib["ID"]
        p = evidence("mitre-cwe", id, run, first=timestamp)
        description = next(
            (
                sanitize(" ".join(c.itertext()))
                for c in element
                if c.tag.split("}")[-1] == "Description"
            ),
            "",
        )
        g.add_node(
            id,
            "Weakness",
            {"name": sanitize(element.attrib.get("Name", id)), "description": description},
            p,
        )
    return g
