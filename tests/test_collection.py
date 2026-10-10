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
