import pytest

from src.ingest.collect import Collector


def test_collector_rejects_iocs_before_network(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("No network permitted in tests")

    monkeypatch.setattr("httpx.Client", forbidden)
    c = Collector(tmp_path)
    for url in [
        "http://www.cisa.gov/a",
        "https://example.com/",
        "https://198.51.100.10/",
        "https://services.nvd.nist.gov/indicator",
        "https://raw.githubusercontent.com/evil/repo/main/feed",
    ]:
        with pytest.raises(ValueError):
            c.fetch(url)
    with pytest.raises(ValueError):
        c.fetch(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "secret",
        )


def test_nvd_kev_pagination_scope_and_missing(tmp_path, monkeypatch):
    import json

    from src.ingest.collect import collect_kev_nvd

    collector = Collector(tmp_path)
    calls = []

    def fetch(url, key=None):
        calls.append(url)
        start = 0 if url.endswith("=0") else 2
        rows = ["CVE-2024-1000", "CVE-2002-1000"] if start == 0 else ["CVE-2025-1000"]
        return json.dumps(
            {
                "totalResults": 3,
                "startIndex": start,
                "vulnerabilities": [{"cve": {"id": id}} for id in rows],
            }
        ).encode()

    monkeypatch.setattr(collector, "fetch", fetch)
    result = collect_kev_nvd(collector, ["CVE-2024-1000", "CVE-2025-1000", "CVE-2025-9999"])
    assert [x["cve"]["id"] for x in result["vulnerabilities"]] == ["CVE-2024-1000", "CVE-2025-1000"]
    assert result["missing_cve_ids"] == ["CVE-2025-9999"]
    assert len(calls) == 2 and collector.delay >= 6.1
    with pytest.raises(ValueError):
        collect_kev_nvd(collector, ["https://example.com"])
    with pytest.raises(ValueError):
        collect_kev_nvd(collector, ["CVE-2024-1000"], limit=2)
