"""Allowlisted public publishers only. Indicator values never enter this module."""

import hashlib
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

PUBLISHERS = frozenset(
    {
        "raw.githubusercontent.com",
        "www.cisa.gov",
        "services.nvd.nist.gov",
        "cwe.mitre.org",
        "api.first.org",
    }
)
SOURCE_PATHS = {
    "raw.githubusercontent.com": ("/mitre-attack/attack-stix-data/",),
    "www.cisa.gov": ("/sites/default/files/feeds/known_exploited_vulnerabilities.json",),
    "services.nvd.nist.gov": ("/rest/json/cves/2.0",),
    "cwe.mitre.org": ("/data/xml/",),
    "api.first.org": ("/data/v1/epss",),
}


class Collector:
    def __init__(
        self,
        cache: str | Path = "data/raw",
        delay: float = 1.0,
        max_bytes: int = 100000000,
        timeout: float = 30,
        retries: int = 3,
        ttl: int = 86400,
        max_requests: int = 3000,
    ):
        self.cache = Path(cache)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.delay = delay
        self.max_bytes = max_bytes
        self.timeout = timeout
        self.retries = retries
        self.ttl = ttl
        self.max_requests = max_requests
        self.last = 0.0
        self.requests = 0

    def fetch(self, url: str, nvd_key: str | None = None) -> bytes:
        u = urlsplit(url)
        if (
            u.scheme != "https"
            or u.hostname not in PUBLISHERS
            or u.username
            or u.password
            or u.port not in {None, 443}
            or not any(u.path.startswith(p) for p in SOURCE_PATHS[u.hostname])
        ):
            raise ValueError("Destination is not a supported public feed endpoint")
        if nvd_key and u.hostname != "services.nvd.nist.gov":
            raise ValueError("NVD key destination mismatch")
        key = hashlib.sha256(url.encode()).hexdigest()
        p = self.cache / (key + ".bin")
        if p.exists() and time.time() - p.stat().st_mtime < self.ttl:
            body = p.read_bytes()
            if len(body) > self.max_bytes:
                raise ValueError("Cached source exceeds bound")
            return body
        for attempt in range(self.retries):
            if self.requests >= self.max_requests:
                raise ValueError("Collection request budget exceeded")
            time.sleep(max(0, self.delay - (time.monotonic() - self.last)))
            self.last = time.monotonic()
            self.requests += 1
            headers = {
                "User-Agent": "DefensiveCTIG/0.1 (+offline research; bounded public feed collection)"
            }
            if nvd_key:
                headers["apiKey"] = nvd_key
            with httpx.Client(timeout=self.timeout, follow_redirects=False, verify=True) as client:
                with client.stream("GET", url, headers=headers) as r:
                    if r.status_code in {429, 500, 502, 503, 504}:
                        if attempt + 1 == self.retries:
                            r.raise_for_status()
                        wait = min(float(r.headers.get("Retry-After", 2**attempt)), 60)
                        time.sleep(wait)
                        continue
                    r.raise_for_status()
                    chunks = []
                    total = 0
                    for chunk in r.iter_bytes():
                        total += len(chunk)
                        if total > self.max_bytes:
                            raise ValueError("Source exceeds byte limit")
                        chunks.append(chunk)
                    body = b"".join(chunks)
            temporary = p.with_suffix(".tmp")
            temporary.write_bytes(body)
            temporary.replace(p)
            p.with_suffix(".json").write_text(
                json.dumps(
                    {
                        "url": url,
                        "sha256": hashlib.sha256(body).hexdigest(),
                        "bytes": len(body),
                        "retrieved_at": time.time(),
                    }
                )
            )
            return body
        raise RuntimeError("Unreachable retry exhaustion")


def collect_attack(collector: Collector, tag: str, domain: str = "enterprise") -> dict:
    import re

    if not re.fullmatch(r"v\d+\.\d+(?:\.\d+)?", tag) or domain not in {
        "enterprise",
        "mobile",
        "ics",
    }:
        raise ValueError("Invalid official release/domain")
    return json.loads(
        collector.fetch(
            f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{tag}/{domain}-attack/{domain}-attack.json"
        )
    )


def collect_scoped_nvd(collector: Collector, cve_ids: list[str], limit: int = 3000) -> dict:
    import re

    if len(cve_ids) > limit:
        raise ValueError("NVD scope exceeds configured CVE limit")
    collector.delay = max(collector.delay, 6.1)
    rows = []
    for cve in sorted(set(cve_ids)):
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            raise ValueError("Invalid CVE selector")
        data = json.loads(
            collector.fetch(
                "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve,
                os.getenv("NVD_API_KEY"),
            )
        )
        rows.extend(data.get("vulnerabilities", []))
    return {"vulnerabilities": rows}
