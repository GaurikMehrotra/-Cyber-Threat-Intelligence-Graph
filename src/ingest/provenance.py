"""Individual immutable evidence records, not overwritten source strings."""

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from functools import cached_property
from hashlib import sha256


@dataclass(frozen=True)
class Provenance:
    source: str
    source_id: str
    first_seen: str
    last_seen: str
    confidence: float
    ingestion_run_id: str

    def __post_init__(self) -> None:
        if not self.source or not self.source_id or not self.ingestion_run_id:
            raise ValueError("Source, source ID and run are required")
        first, last = (
            datetime.fromisoformat(s.replace("Z", "+00:00"))
            for s in (self.first_seen, self.last_seen)
        )
        if (
            first.tzinfo is None
            or last.tzinfo is None
            or first > last
            or not 0 <= self.confidence <= 1
        ):
            raise ValueError("Invalid evidence timestamps or confidence")

    def to_dict(self) -> dict:
        return asdict(self)

    @cached_property
    def key(self) -> str:
        return sha256(json.dumps(self.to_dict(), sort_keys=True).encode()).hexdigest()


def evidence(
    source: str,
    source_id: str,
    run: str,
    confidence: float = 1.0,
    first: str | None = None,
    last: str | None = None,
) -> Provenance:
    now = datetime.now(UTC).isoformat()
    return Provenance(source, source_id, first or now, last or first or now, confidence, run)
