"""Evaluate real labels only; false merges are costlier than missed aliases."""

import csv

from sklearn.metrics import precision_score, recall_score


def evaluate_pairs(path: str, threshold: float = 0.92) -> dict:
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    labeled = [r for r in rows if r.get("label") in {"0", "1"} and r.get("similarity")]
    if not labeled:
        return {
            "status": "unlabeled",
            "labeled_pairs": 0,
            "precision": None,
            "recall": None,
            "false_merge_rate": None,
        }
    y = [int(r["label"]) for r in labeled]
    pred = [float(r["similarity"]) >= threshold for r in labeled]
    fp = sum(p and not label for p, label in zip(pred, y, strict=True))
    accepted = sum(pred)
    return {
        "status": "evaluated",
        "labeled_pairs": len(y),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "false_merge_rate": fp / accepted if accepted else None,
        "definition": "False merges / accepted merges. Labels must be independently reviewed; a false merge is worse than a missed alias.",
    }
