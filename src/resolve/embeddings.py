"""Bounded same-type semantic candidates; no automatic destructive merges."""

import numpy as np

from src.resolve.aliases import decide_similarity


def fuzzy_candidates(
    ids: list[str],
    labels: list[str],
    vectors: np.ndarray,
    auto: float = 0.92,
    review: float = 0.75,
    max_pairs: int = 10000,
) -> list[dict]:
    if (
        len(ids) != len(labels)
        or len(ids) != len(vectors)
        or len(ids) * (len(ids) - 1) // 2 > max_pairs
    ):
        raise ValueError("Invalid or excessive candidate set")
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    vv = vectors / np.maximum(norms, 1e-12)
    rows = []
    for i, a in enumerate(ids):
        for j in range(i + 1, len(ids)):
            if labels[i] != labels[j]:
                continue
            score = float(np.clip(vv[i] @ vv[j], -1, 1))
            decision = decide_similarity(score, auto, review)
            if decision != "reject":
                rows.append(
                    {
                        "left": a,
                        "right": ids[j],
                        "similarity": score,
                        "decision": decision,
                        "method": "sentence-transformer",
                        "human_decision": "pending",
                    }
                )
    return rows
