"""Explicit STIX 2.1 ATT&CK mapping; no inferred attribution."""

import json
from pathlib import Path

from src.graph.model import Graph
from src.ingest.provenance import evidence
from src.security.sanitize import sanitize

MAPPING = {
    "intrusion-set": "ThreatActor",
    "threat-actor": "ThreatActor",
    "malware": "Malware",
    "tool": "Tool",
    "campaign": "Campaign",
    "attack-pattern": "Technique",
}
RELATION_MAP = {
    "uses": "USES",
    "attributed-to": "ATTRIBUTED_TO",
    "targets": "TARGETS",
    "related-to": "SIMILAR_TO",
    "subtechnique-of": "USES",
}


def parse_attack(bundle: dict, release: str, run: str) -> Graph:
    g = Graph()
    objects = bundle.get("objects", [])
    if bundle.get("type") != "bundle":
        raise ValueError("Expected STIX bundle")
    for obj in objects:
        if obj.get("type") not in MAPPING or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        refs = obj.get("external_references", [])
        external = next(
            (r.get("external_id") for r in refs if r.get("source_name") == "mitre-attack"), None
        )
        p = evidence(
            f"attack:{release}", obj["id"], run, first=obj.get("created"), last=obj.get("modified")
        )
        props = {
            "name": sanitize(obj.get("name", "")),
            "description": sanitize(obj.get("description", "")),
            "aliases": [sanitize(x) for x in obj.get("aliases", [])],
            "external_id": external or "",
            "platforms": obj.get("x_mitre_platforms", []),
            "tactics": [x["phase_name"] for x in obj.get("kill_chain_phases", [])],
            "subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
            "release": release,
        }
        g.add_node(obj["id"], MAPPING[obj["type"]], props, p)
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        rel = obj.get("relationship_type")
        if (
            rel not in RELATION_MAP
            or obj.get("source_ref") not in g.nodes
            or obj.get("target_ref") not in g.nodes
        ):
            continue
        p = evidence(
            f"attack:{release}", obj["id"], run, first=obj.get("created"), last=obj.get("modified")
        )
        g.add_edge(
            obj["source_ref"],
            obj["target_ref"],
            RELATION_MAP[rel],
            p,
            original_relationship=rel,
            description=sanitize(obj.get("description", "")),
            hypothesis=rel == "attributed-to",
            inferred=False,
            caveat="Source-reported attribution; shared tools, infrastructure and false flags limit certainty."
            if rel == "attributed-to"
            else "",
        )
    return g


def load_attack(path: str | Path, release: str, run: str) -> Graph:
    return parse_attack(json.loads(Path(path).read_text()), release, run)
