"""Seeded temporal evaluation, with sampled classification and full ranking metrics."""

import platform
import random
import resource
import time
from collections import defaultdict
from datetime import UTC, datetime

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from src.graph.model import Graph
from src.predict.baselines import score, text_similarity, training_projection
from src.predict.embeddings import older_texts
from src.predict.features import temporal_split


def evaluate(
    old: Graph,
    new: Graph,
    seeds: list[int],
    negatives_per_positive: int = 5,
    k: int = 10,
    max_candidates: int = 100000,
    encoder=None,
) -> dict:
    started = time.perf_counter()
    split = temporal_split(old, new, max_candidates)
    train = training_projection(old)
    summary = {
        key: len(split[key])
        for key in ("train", "positive", "negative", "cold_start", "candidates")
    }
    methods = ["common_neighbors", "jaccard", "adamic_adar", "preferential_attachment"]
    vectors = None
    if encoder is not None:
        ids = sorted(old.nodes)
        vectors = dict(zip(ids, encoder.encode(older_texts(old, ids)), strict=True))
        methods.append("text_embedding")
    if not split["positive"] or not split["negative"]:
        return {
            "status": "insufficient_temporal_changes",
            "counts": summary,
            "results": [],
            "caveat": split["caveat"],
        }
    rows = []
    all_candidates = sorted(split["candidates"])
    for method in methods:
        scores = {
            (a, t): text_similarity(vectors[a], vectors[t])
            if method == "text_embedding"
            else score(train, a, t, method)
            for a, t in all_candidates
        }
        by_actor = defaultdict(list)
        for pair in all_candidates:
            by_actor[pair[0]].append(pair)
        ranks = []
        # Expected reciprocal rank within tied score blocks avoids arbitrary ID tie-breaking gains.
        for a, t in sorted(split["positive"]):
            other = [scores[e] for e in by_actor[a] if (e not in split["positive"] or e == (a, t))]
            above = sum(v > scores[(a, t)] for v in other)
            tied = sum(v == scores[(a, t)] for v in other)
            positions = range(above + 1, above + tied + 1)
            ranks.append(
                (sum(1 / p for p in positions) / tied, sum(p <= k for p in positions) / tied)
            )
        for seed in seeds:
            # Deterministic scientific sampling; no cryptographic use.
            rng = random.Random(seed)  # nosec B311
            negatives = rng.sample(
                sorted(split["negative"]),
                min(len(split["negative"]), negatives_per_positive * len(split["positive"])),
            )
            pairs = sorted(split["positive"]) + negatives
            labels = [int(p in split["positive"]) for p in pairs]
            values = [scores[p] for p in pairs]
            rows.append(
                {
                    "method": method,
                    "seed": seed,
                    "roc_auc": float(roc_auc_score(labels, values)),
                    "average_precision": float(average_precision_score(labels, values)),
                    "hits_at_k": float(np.mean([r[1] for r in ranks])),
                    "mrr": float(np.mean([r[0] for r in ranks])),
                    "k": k,
                    "sampled_negatives": len(negatives),
                }
            )
    return {
        "status": "evaluated",
        "counts": summary,
        "results": rows,
        "created_at": datetime.now(UTC).isoformat(),
        "performance": {
            "evaluation_seconds": time.perf_counter() - started,
            "python_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
            "platform": platform.platform(),
        },
        "encoder": getattr(encoder, "identity", None),
        "releases": {
            "old_sources": sorted(
                {p.source for n in old.nodes.values() for p in n.evidence.values()}
            ),
            "new_sources": sorted(
                {p.source for n in new.nodes.values() for p in n.evidence.values()}
            ),
        },
        "config": {"seeds": seeds, "negatives_per_positive": negatives_per_positive, "k": k},
        "text_baseline": "executed"
        if encoder is not None
        else "unrun: install ML extras and provide sentence encoder",
        "caveat": split["caveat"]
        + " Predictions are analyst leads, not facts. Negatives are unobserved assertions, not proven false. Ranking uses all older-node candidates; tied ranks averaged. No method tuning.",
    }
