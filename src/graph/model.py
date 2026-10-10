"""Bounded graph representation shared by parsers, analytics, and fixture tests."""

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from src.ingest.provenance import Provenance
from src.intel.defang import defang, normalize

LABELS = frozenset(
    {
        "ThreatActor",
        "Malware",
        "Tool",
        "Campaign",
        "Technique",
        "Vulnerability",
        "Weakness",
        "Domain",
        "IP",
        "URL",
        "FileHash",
        "Report",
        "Product",
    }
)
RELATIONS = frozenset(
    {
        "USES",
        "EXPLOITS",
        "COMMUNICATES_WITH",
        "RESOLVES_TO",
        "ATTRIBUTED_TO",
        "TARGETS",
        "AFFECTS",
        "HAS_WEAKNESS",
        "MENTIONED_IN",
        "ALIAS_OF",
        "SIMILAR_TO",
    }
)
IOCS = frozenset({"Domain", "IP", "URL", "FileHash"})


@dataclass
class Node:
    id: str
    label: str
    properties: dict[str, Any]
    evidence: dict[str, Provenance] = field(default_factory=dict)
    observations: dict[str, dict[str, Any]] = field(default_factory=dict)

    def public(self) -> dict:
        props = dict(self.properties)
        if self.label in IOCS:
            props = {k: defang(str(v)) if isinstance(v, str) else v for k, v in props.items()}
        return {
            "id": defang(self.id) if self.label in IOCS else self.id,
            "label": self.label,
            "properties": props,
            "provenance": [p.to_dict() for p in self.evidence.values()],
        }


@dataclass
class Edge:
    source: str
    target: str
    type: str
    properties: dict[str, Any]
    evidence: dict[str, Provenance] = field(default_factory=dict)
    observations: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return sha256(f"{self.source}\0{self.type}\0{self.target}".encode()).hexdigest()


@dataclass
class Graph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[str, Edge] = field(default_factory=dict)
    rejected: list[dict] = field(default_factory=list)

    def add_node(self, id: str, label: str, properties: dict, p: Provenance) -> Node:
        if label not in LABELS or not id:
            raise ValueError("Invalid graph identifier/label")
        if label in IOCS:
            value = normalize(label, id.removeprefix(label + ":"))
            if id != label + ":" + value:
                raise ValueError("IOC identifiers must be canonical type:value")
            if "value" in properties and normalize(label, properties["value"]) != value:
                raise ValueError("IOC value disagrees with identifier")
            properties = {**properties, "value": value}
        n = self.nodes.get(id)
        if n and n.label != label:
            raise ValueError("Conflicting node types")
        if n is None:
            n = Node(id, label, {})
            self.nodes[id] = n
        n.observations.setdefault(p.key, {}).update(properties)
        n.evidence[p.key] = p
        if properties:
            n.properties = aggregate(n.evidence, n.observations)
        return n

    def add_edge(
        self, source: str, target: str, type: str, p: Provenance, **properties: Any
    ) -> Edge:
        if type not in RELATIONS or source not in self.nodes or target not in self.nodes:
            raise ValueError("Unknown relation or dangling endpoint")
        e = Edge(source, target, type, properties)
        if e.id in self.edges:
            e = self.edges[e.id]
        e.observations.setdefault(p.key, {}).update(properties)
        e.evidence[p.key] = p
        e.properties = aggregate(e.evidence, e.observations)
        self.edges[e.id] = e
        # Endpoints retain evidence for a relationship after removal of another source.
        self.add_node(source, self.nodes[source].label, {}, p)
        self.add_node(target, self.nodes[target].label, {}, p)
        return e

    def merge(self, other: "Graph") -> "Graph":
        for n in other.nodes.values():
            for p in n.evidence.values():
                self.add_node(n.id, n.label, n.observations.get(p.key, n.properties), p)
        for e in other.edges.values():
            for p in e.evidence.values():
                self.add_edge(
                    e.source, e.target, e.type, p, **e.observations.get(p.key, e.properties)
                )
        self.rejected.extend(other.rejected)
        return self

    def purge(self, *, source: str | None = None, run: str | None = None) -> None:
        if not source and not run:
            raise ValueError("Specify a source or ingestion run")
        for items in (self.edges, self.nodes):
            for key, item in list(items.items()):
                item.evidence = {
                    k: p
                    for k, p in item.evidence.items()
                    if not ((source and p.source == source) or (run and p.ingestion_run_id == run))
                }
                item.observations = {
                    k: v for k, v in item.observations.items() if k in item.evidence
                }
                item.properties = aggregate(item.evidence, item.observations)
                if not item.evidence:
                    del items[key]
        self.edges = {
            k: e for k, e in self.edges.items() if e.source in self.nodes and e.target in self.nodes
        }


def aggregate(evidence: dict[str, Provenance], observations: dict[str, dict]) -> dict:
    """Latest timestamp wins per property; all individual assertions remain inspectable."""
    result = {}
    from datetime import datetime

    for key in sorted(
        (k for k in evidence if observations.get(k)),
        key=lambda k: (
            datetime.fromisoformat(evidence[k].last_seen.replace("Z", "+00:00")),
            evidence[k].source,
            evidence[k].source_id,
            k,
        ),
    ):
        result.update(observations.get(key, {}))
    return result
