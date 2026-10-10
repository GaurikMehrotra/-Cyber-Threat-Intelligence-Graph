"""Author small synthetic public-safe fixtures, never fetched feed dumps."""

import json
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from src.graph.serialization import save
from src.ingest.attack import parse_attack
from src.ingest.cwe import parse_cwe
from src.ingest.kev import parse_kev
from src.ingest.nvd import parse_nvd
from src.ingest.reports import parse_report

ROOT = Path("data/fixtures")
WHEN = "2024-01-01T00:00:00Z"


def sid(type: str, name: str) -> str:
    return type + "--" + str(uuid5(NAMESPACE_URL, "ctig-synthetic:" + name))


def obj(type: str, name: str, **kw):
    return {
        "type": type,
        "id": sid(type, name),
        "name": name,
        "created": WHEN,
        "modified": WHEN,
        **kw,
    }


def relation(a, b):
    return {
        "type": "relationship",
        "id": sid("relationship", a["id"] + b["id"]),
        "source_ref": a["id"],
        "target_ref": b["id"],
        "relationship_type": "uses",
        "created": WHEN,
        "modified": WHEN,
    }


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    actors = [
        obj("intrusion-set", n, description=d, aliases=[alias])
        for n, d, alias in [
            ("Example North", "Synthetic phishing credential group", "North Alias"),
            ("Example South", "Synthetic persistence group", "South Alias"),
            ("Example East", "Synthetic credential phishing actor", "East Alias"),
        ]
    ]
    techniques = [
        obj(
            "attack-pattern",
            n,
            description=d,
            external_references=[{"source_name": "mitre-attack", "external_id": ext}],
        )
        for n, d, ext in [
            ("Phishing", "Synthetic phishing delivery", "T1566"),
            ("Credential Access", "Synthetic credential capture", "T1003"),
            ("Persistence", "Synthetic persistence behavior", "T1547"),
            ("Discovery", "Synthetic host discovery description only", "T1082"),
        ]
    ]
    malware = obj(
        "malware", "Example Malware", description="Synthetic malware family", is_family=True
    )
    old_edges = [(0, 0), (0, 1), (1, 2), (2, 0)]
    old = {
        "type": "bundle",
        "id": sid("bundle", "old"),
        "objects": actors
        + techniques
        + [malware]
        + [relation(actors[a], techniques[t]) for a, t in old_edges],
    }
    new = {
        "type": "bundle",
        "id": sid("bundle", "new"),
        "objects": old["objects"]
        + [relation(actors[2], techniques[1]), relation(actors[1], techniques[3])],
    }
    kev = {
        "title": "Synthetic KEV-shaped fixture; not real vulnerability intelligence",
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-99999",
                "vendorProject": "Example",
                "product": "Example Product",
                "dateAdded": "2024-01-01",
                "shortDescription": "Synthetic validation vulnerability",
                "dueDate": "2024-02-01",
                "requiredAction": "Apply vendor updates",
                "cwes": ["CWE-79"],
            }
        ],
    }
    nvd = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-99999",
                    "published": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-01-02T00:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Synthetic injection issue in Example Product"}
                    ],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}]},
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }
    cwe = '<Weakness_Catalog><Weaknesses><Weakness ID="79" Name="Cross-site scripting"><Description>Synthetic CWE-shaped fixture.</Description></Weakness></Weaknesses></Weakness_Catalog>'
    report = {
        "source": "synthetic-report",
        "source_id": "fixture-report-1",
        "title": "Synthetic defensive research report",
        "published": WHEN,
        "confidence": 0.7,
        "text": "Example Malware is mentioned alongside example[.]com and 198[.]51[.]100[.]10 and CVE-2024-99999. These co-mentions are not attribution.",
        "indicators": [{"kind": "FileHash", "value": "a" * 64}],
        "assertions": [
            {
                "subject": {"id": malware["id"], "label": "Malware", "name": "Example Malware"},
                "object": {"id": "Domain:example.com", "label": "Domain", "name": "example.com"},
                "relation": "COMMUNICATES_WITH",
            }
        ],
    }
    for name, data in [
        ("attack-old.json", old),
        ("attack-new.json", new),
        ("kev.json", kev),
        ("nvd.json", nvd),
        ("report.json", report),
    ]:
        (ROOT / name).write_text(json.dumps(data, indent=2))
    (ROOT / "cwe.xml").write_text(cwe)
    g = parse_attack(old, "fixture-old", "fixture-run")
    g.merge(parse_kev(kev, "fixture-run"))
    g.merge(parse_nvd(nvd, "fixture-run"))
    g.merge(parse_cwe(cwe, "fixture-run", WHEN))
    g.merge(parse_report(report, "fixture-run"))
    p = next(iter(g.nodes["Domain:example.com"].evidence.values()))
    g.add_edge(
        "Domain:example.com",
        "IP:198.51.100.10",
        "RESOLVES_TO",
        p,
        hypothesis=False,
        inferred=False,
        caveat="Synthetic offline assertion. No DNS was performed.",
    )
    save(g, ROOT / "graph.json")


if __name__ == "__main__":
    main()
