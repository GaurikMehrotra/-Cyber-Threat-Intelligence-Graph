"""Offline, bounded indicator ingestion with rejection reasons."""

import logging

from src.graph.model import Graph
from src.ingest.provenance import Provenance
from src.intel.defang import normalize

logger = logging.getLogger(__name__)


def ingest_iocs(rows: list[dict], p: Provenance, limit: int = 200) -> Graph:
    g = Graph()
    if len(rows) > limit:
        raise ValueError("IOC sample exceeds configured limit")
    for row in rows:
        try:
            kind = row["kind"]
            value = normalize(kind, row["value"])
            g.add_node(f"{kind}:{value}", kind, {"name": value, "value": value}, p)
        except (KeyError, ValueError, UnicodeError) as exc:
            g.rejected.append({"row": len(g.nodes) + len(g.rejected), "reason": str(exc)})
            logger.warning("Rejected IOC: %s", exc)
    return g
