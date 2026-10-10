"""Build independently specified source-reference checks, not human ground truth.

Run after official collection. Source STIX identities define silver alias labels;
separate source IDs are not proof of distinct real-world operators. The model's
scores never choose labels. The untouched human templates remain available.
"""

import argparse
import csv
import json
import random
from pathlib import Path

import numpy as np

from src.eval.er_eval import evaluate_pairs
from src.search.semantic_index import SentenceEncoder


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, default=Path("data/raw"))
    parser.add_argument("--release", default="v17.1")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--pairs-per-class", type=int, default=50)
    args = parser.parse_args()
    objects = {}
    for domain in ("enterprise", "mobile", "ics"):
        data = json.loads((args.raw / f"attack-{args.release}-{domain}.json").read_text())
        objects.update({o["id"]: o for o in data["objects"]})
    active = {
        id: o
        for id, o in objects.items()
        if not o.get("revoked") and not o.get("x_mitre_deprecated")
    }
    actors = sorted(
        (o for o in active.values() if o["type"] == "intrusion-set"), key=lambda o: o["id"]
    )
    positives = [
        (o, a) for o in actors for a in o.get("aliases", []) if a.casefold() != o["name"].casefold()
    ]
    # Reproducible benchmark sampling; not cryptographic randomness.
    rng = random.Random(args.seed)  # nosec B311
    rng.shuffle(positives)
    rows = [
        {"left": o["name"], "right": a, "label": 1, "left_id": o["id"], "right_id": o["id"]}
        for o, a in positives[: args.pairs_per_class]
    ]
    negatives = [
        (a, b)
        for i, a in enumerate(actors)
        for b in actors[i + 1 :]
        if a["name"].casefold() != b["name"].casefold()
    ]
    rng.shuffle(negatives)
    rows.extend(
        {"left": a["name"], "right": b["name"], "label": 0, "left_id": a["id"], "right_id": b["id"]}
        for a, b in negatives[: args.pairs_per_class]
    )
    if len(rows) != args.pairs_per_class * 2:
        raise ValueError("Insufficient independent source pairs")
    encoder = SentenceEncoder()
    left = encoder.encode([r["left"] for r in rows])
    right = encoder.encode([r["right"] for r in rows])
    for row, score in zip(rows, np.sum(left * right, axis=1), strict=True):
        row["similarity"] = float(score)
        row["evidence"] = f"MITRE ATT&CK {args.release}; STIX source identities"
    path = Path("data/eval/source_alias_pairs.csv")
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    metrics = evaluate_pairs(str(path))
    metrics.update(
        {
            "label_kind": "source-reference (silver), not human-reviewed",
            "seed": args.seed,
            "threshold": 0.92,
            "model": encoder.identity,
            "caveat": "Distinct STIX identities do not prove distinct real-world actors. Random negatives can be easier than analyst-review candidates. No threshold tuning on this set.",
        }
    )
    Path("reports/source_alias_evaluation.json").write_text(json.dumps(metrics, indent=2))
    questions = []
    for actor in actors:
        targets = sorted(
            {
                o["target_ref"]
                for o in active.values()
                if o["type"] == "relationship"
                and o.get("relationship_type") == "uses"
                and o.get("source_ref") == actor["id"]
                and o.get("target_ref") in active
                and active[o["target_ref"]]["type"] == "attack-pattern"
            }
        )
        if targets and len(targets) <= 100:
            questions.append(
                {
                    "question": f"Which active techniques does {actor['name']} use in ATT&CK {args.release}?",
                    "template": "actor_profile",
                    "params": {"id": actor["id"], "offset": 0, "limit": 100},
                    "expected_ids": targets,
                    "evidence": f"Official {args.release} STIX relationship source_ref/target_ref, enumerated independently of graph loader",
                }
            )
        if len(questions) == 20:
            break
    kev = json.loads((args.raw / "kev.json").read_text())
    for item in sorted(kev["vulnerabilities"], key=lambda x: x["cveID"])[-10:]:
        questions.append(
            {
                "question": f"Is {item['cveID']} represented from the official CISA catalog?",
                "template": "entity",
                "params": {"id": item["cveID"], "limit": 1},
                "expected_ids": [item["cveID"]],
                "evidence": "CISA official KEV mirror, catalogVersion " + kev["catalogVersion"],
            }
        )
    Path("data/eval/source_golden_queries.json").write_text(json.dumps(questions, indent=2))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
