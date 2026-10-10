"""Valid STIX 2.1 export with explicit hypothesis caveats and custom provenance."""

import json
from datetime import UTC
from uuid import NAMESPACE_URL, uuid5

import stix2

from src.graph.model import IOCS, Graph

TYPE_MAP = {
    "ThreatActor": "threat-actor",
    "Malware": "malware",
    "Tool": "tool",
    "Campaign": "campaign",
    "Technique": "attack-pattern",
    "Vulnerability": "vulnerability",
    "Weakness": "x-ctig-weakness",
    "Domain": "domain-name",
    "IP": "ipv4-addr",
    "URL": "url",
    "FileHash": "file",
    "Report": "report",
    "Product": "x-ctig-product",
}


def export_stix(graph: Graph) -> dict:
    objects = []
    mapping = {}

    def timestamp(text: str) -> str:
        from datetime import datetime

        return (
            datetime.fromisoformat(text.replace("Z", "+00:00"))
            .astimezone(UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    for n in graph.nodes.values():
        kind = TYPE_MAP[n.label]
        if n.label == "IP" and ":" in n.properties["value"]:
            kind = "ipv6-addr"
        sid = kind + "--" + str(uuid5(NAMESPACE_URL, n.id))
        mapping[n.id] = sid
        p = list(n.evidence.values())
        when = timestamp(min(x.first_seen for x in p))
        modified = timestamp(max(x.last_seen for x in p))
        confidence = round(max((x.confidence for x in p), default=0) * 100)
        o = {
            "type": kind,
            "spec_version": "2.1",
            "id": sid,
            "x_ctig_provenance": [x.to_dict() for x in p],
            "x_ctig_defensive_only": True,
        }
        if n.label in IOCS:
            if n.label == "FileHash":
                val = n.properties["value"]
                alg = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}[len(val)]
                o["hashes"] = {alg: val}
            else:
                o["value"] = n.properties["value"]
            o["defanged"] = False
        else:
            o.update(
                created=when,
                modified=modified,
                name=n.properties.get("name", n.id),
                confidence=confidence,
            )
            if n.properties.get("description"):
                o["description"] = n.properties["description"]
            if n.label == "Malware":
                o["is_family"] = True
            if n.label == "Report":
                o.update(published=when, report_types=["threat-report"], object_refs=[])
        objects.append(o)
    for original, stix_id in mapping.items():
        if graph.nodes[original].label == "Report":
            refs = sorted(
                {
                    mapping[e.source]
                    for e in graph.edges.values()
                    if e.target == original and e.type == "MENTIONED_IN"
                }
            )
            if not refs:
                raise ValueError(
                    "STIX Report export requires at least one MENTIONED_IN object reference"
                )
            next(o for o in objects if o["id"] == stix_id)["object_refs"] = refs
    for e in graph.edges.values():
        when = timestamp(min(p.first_seen for p in e.evidence.values()))
        modified = timestamp(max(p.last_seen for p in e.evidence.values()))
        relid = "relationship--" + str(uuid5(NAMESPACE_URL, e.id))
        relation = e.properties.get("original_relationship") or e.type.lower().replace("_", "-")
        is_hypothesis = bool(e.properties.get("inferred") or e.properties.get("hypothesis"))
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": relid,
                "created": when,
                "modified": modified,
                "relationship_type": relation,
                "source_ref": mapping[e.source],
                "target_ref": mapping[e.target],
                "confidence": round(
                    max((p.confidence for p in e.evidence.values()), default=0) * 100
                ),
                "description": e.properties.get("caveat")
                or (
                    "Analyst hypothesis: verify evidence; shared tools, infrastructure and false flags may explain this link."
                    if is_hypothesis
                    else "Source-reported relationship, not independent confirmation."
                ),
                "x_ctig_inferred": is_hypothesis,
                "x_ctig_provenance": [p.to_dict() for p in e.evidence.values()],
            }
        )
    # Parsing validates the complete bundle; custom weakness/product objects retained.
    bundle = {
        "type": "bundle",
        "id": "bundle--" + str(uuid5(NAMESPACE_URL, "|".join(sorted(mapping)))),
        "objects": objects,
    }
    stix2.parse(json.dumps(bundle), allow_custom=True)
    return bundle
