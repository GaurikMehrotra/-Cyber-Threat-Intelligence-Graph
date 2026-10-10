import json

import pytest
import stix2

from src.ingest.iocs import ingest_iocs
from src.ingest.provenance import Provenance, evidence
from src.intel.defang import defang, normalize, refang
from src.intel.stix_export import export_stix
from src.security.sanitize import sanitize


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("Domain", "EXAMPLE[.]COM.", "example.com"),
        ("IP", "2001:0db8::1", "2001:db8::1"),
        ("IP", "198[.]51[.]100[.]10", "198.51.100.10"),
        ("FileHash", "A" * 64, "a" * 64),
        ("URL", "hxxps://EXAMPLE[.]COM/a", "https://example.com/a"),
    ],
)
def test_normalization(kind, value, expected):
    assert normalize(kind, value) == expected


@pytest.mark.parametrize(
    "kind,value",
    [
        ("Domain", "-bad.example"),
        ("Domain", "127.0.0.1"),
        ("IP", "999.1.1.1"),
        ("FileHash", "abc"),
        ("URL", "ftp://example.com"),
        ("URL", "https://user:secret@example.com"),
        ("URL", "http://example.com:99999"),
    ],
)
def test_invalid(kind, value):
    with pytest.raises(ValueError):
        normalize(kind, value)


def test_defang_roundtrip():
    assert refang(defang("https://example.com/a")) == "https://example.com/a"


def test_rejections():
    p = evidence("test", "row", "run", first="2024-01-01T00:00:00Z")
    g = ingest_iocs([{"kind": "IP", "value": "bad"}, {"kind": "IP", "value": "198.51.100.1"}], p)
    assert len(g.nodes) == 1 and len(g.rejected) == 1
    with pytest.raises(ValueError):
        ingest_iocs([{}] * 201, p)


def test_provenance_validation():
    with pytest.raises(ValueError):
        Provenance("a", "b", "2024-02-01T00:00:00Z", "2024-01-01T00:00:00Z", 1, "run")
    with pytest.raises(ValueError):
        evidence("test", "row", "run", 1.1)


def test_stix_valid(graph):
    bundle = export_stix(graph)
    parsed = stix2.parse(json.dumps(bundle), allow_custom=True)
    assert len(parsed.objects) == len(graph.nodes) + len(graph.edges)
    assert all(o.get("x_ctig_provenance") for o in bundle["objects"])


def test_iocs_public_defanged(graph):
    n = graph.nodes["Domain:example.com"].public()
    assert n["properties"]["value"] == "example[.]com" and "example.com" not in n["id"]


def test_sanitize():
    assert sanitize("<script>attack</script>\x00") == "attack"
