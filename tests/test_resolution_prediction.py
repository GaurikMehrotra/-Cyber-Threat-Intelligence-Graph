import numpy as np
import pytest

from src.eval.er_eval import evaluate_pairs
from src.graph.serialization import to_dict
from src.ingest.attack import load_attack
from src.predict.baselines import score, training_projection
from src.predict.evaluate import evaluate
from src.predict.features import temporal_split
from src.resolve.aliases import alias_candidates, decide_similarity
from src.resolve.embeddings import fuzzy_candidates
from src.resolve.review_queue import approve, undo


@pytest.mark.parametrize("score,expected", [(0.95, "eligible"), (0.8, "review"), (0.5, "reject")])
def test_threshold(score, expected):
    assert decide_similarity(score) == expected


def test_fuzzy_same_type():
    rows = fuzzy_candidates(
        ["a", "b", "c"],
        ["ThreatActor", "ThreatActor", "Malware"],
        np.array([[1.0, 0.0], [1.0, 0.0], [1.0, 0.0]]),
    )
    assert len(rows) == 1 and rows[0]["decision"] == "eligible"


def test_review_reversible(graph):
    actors = [n.id for n in graph.nodes.values() if n.label == "ThreatActor"]
    before = len(graph.edges)
    eid = approve(graph, actors[0], actors[1], "analyst", "review1", "2024-01-01T00:00:00Z")
    assert len(graph.edges) == before + 1 and graph.edges[eid].properties["inferred"]
    undo(graph, eid)
    assert len(graph.edges) == before


def test_alias_overlap(graph):
    actor = next(n for n in graph.nodes.values() if n.label == "ThreatActor")
    p = next(iter(actor.evidence.values()))
    graph.add_node("actor-copy", "ThreatActor", {"name": actor.properties["aliases"][0]}, p)
    assert alias_candidates(graph)


def test_temporal_no_leakage():
    old = load_attack("data/fixtures/attack-old.json", "old", "old-run")
    new = load_attack("data/fixtures/attack-new.json", "new", "new-run")
    snapshot = to_dict(old)
    split = temporal_split(old, new)
    assert len(split["positive"]) == 2 and not split["train"] & split["positive"]
    assert not split["negative"] & (split["train"] | split["positive"])
    projected = training_projection(old)
    assert all(not projected.has_edge(a, t) for a, t in split["positive"])
    evaluate(old, new, [17, 42, 93])
    assert to_dict(old) == snapshot
    # Changing future descriptions cannot change the training projection or scores.
    pair = next(iter(split["positive"]))
    before = score(projected, *pair, "common_neighbors")
    for n in new.nodes.values():
        n.properties["description"] = "future secret"
    assert score(training_projection(old), *pair, "common_neighbors") == before


def test_metric_reproducibility():
    old = load_attack("data/fixtures/attack-old.json", "old", "old-run")
    new = load_attack("data/fixtures/attack-new.json", "new", "new-run")
    a = evaluate(old, new, [42])
    b = evaluate(old, new, [42])
    assert a["results"] == b["results"]
    assert len(a["results"]) == 4 and all(
        0 <= r["roc_auc"] <= 1 and 0 <= r["mrr"] <= 1 for r in a["results"]
    )


def test_er_unlabeled_and_metrics(tmp_path):
    p = tmp_path / "pairs.csv"
    p.write_text("left,right,label,similarity\na,b,,\n")
    assert evaluate_pairs(str(p))["status"] == "unlabeled"
    p.write_text("left,right,label,similarity\na,b,1,0.99\nc,d,0,0.99\ne,f,1,0.4\n")
    result = evaluate_pairs(str(p))
    assert (
        result["precision"] == 0.5 and result["recall"] == 0.5 and result["false_merge_rate"] == 0.5
    )
