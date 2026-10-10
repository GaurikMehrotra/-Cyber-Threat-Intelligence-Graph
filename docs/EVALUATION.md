# Evaluation protocol

## Temporal link prediction

Train only on the older release's observed actor USES technique assertions and older text. Evaluate additions in the newer release between nodes already present in the older release. New-node (cold-start) additions are separately counted and excluded. No newer descriptions or newer structural edges enter features. Held-out assertions are removed from negative candidates. Negatives are unobserved links, **not proven false real-world behavior**.

The native actor-technique graph is bipartite: direct common-neighbor/Jaccard/Adamic-Adar scores are identically zero for cross-partition pairs. We therefore explicitly add actor-actor edges when older actors share an older technique, then score actor-technique candidates in that older-only projection. Preferential attachment uses the same projection. This modeling choice is disclosed, not disguised as the raw bipartite baseline. A fifth baseline uses pinned MiniLM cosine on older node text.

No baseline is tuned; equal effort is the same fixed input, candidate universe and seeds (17,42,93) for each method. Sample up to five unobserved negatives per positive for ROC-AUC/AP; use all candidates for each actor in Hits@10/MRR, filter other known newer positives when ranking each target, and average over tie positions. Seeds vary negative sampling, not deterministic structural/text scores. Report per-seed metrics and mean/std. Class balance affects AP. This is release-time prediction, not forecasting attacker activity dates. Predicted edges are leads requiring source verification and are not loaded as facts.

Optional random-walk/classifier embeddings and Kaggle are deliberately not needed for the CPU baseline project; no claimed results for them. All implemented experiments run LOCAL. A third ATT&CK release would be needed for independent hyperparameter tuning; do not tune on the test release.

## Entity resolution and golden questions

`data/eval/alias_pairs.csv` has 100 blank review rows. Supply independently assessed true/false pairs and similarity outputs, reviewer and evidence. Do not assume an overlap is truth. `ctig er-eval` skips unlabeled rows and returns null metrics if none are labeled. Precision/recall use threshold 0.92; false-merge rate = false accepted aliases / all accepted aliases. Reviewable candidate JSONL is generated with `ctig resolve --sentence`. Label negatives too and record disagreements; report class balance and annotator agreement.

`data/eval/golden_queries.json` provides 30 blank user-authored questions. Use a listed template, exact parameters, expected IDs or ordered expected rows, reviewer and evidence. The runner executes real Cypher and compares independent expectations; blank answers are skipped, zero executed is not a pass. A separate `fixture_golden.json` has 30 manually specified answers about the authored synthetic graph (not real CTI validation). Run it in a fixture-only database; a database with public ATT&CK data will correctly fail its global counts question.

## Quality and performance

Quality counts duplicate normalized identifiers, orphan nodes, invalid IOCs, missing node/edge provenance, coverage by source and counts by type. The bounded snapshot scope is explicit; orphans can be legitimate standalone techniques/weaknesses and are not automatically deleted.

`ctig benchmark` measures actual batched fixture ingestion throughput, bounded NetworkX centrality vs parameterized Cypher unique-neighbor degree (compare the same selected IDs), and 20 indexed/unindexed synthetic equality lookups with PROFILE db hits. It never drops real entity indexes. The exclusive CTIGBenchmark namespace is created/cleaned by the command; do not store user data in it. This diagnostic is not a full production query benchmark. Small samples, JVM warm-up and planner overhead can make indexed wall time slower even when db hits fall; report measured numbers honestly.

Python RSS/peak RSS and container memory are cloud measurements only. On the i3/8GB laptop rerun the same seed/config and `docker stats --no-stream`; close unrelated apps, run one experiment at a time, and record versions/system specs. Docker memory is capped at 2GiB; CPU model batch16/threads2; dense TF-IDF bound is 5,000 x 10,000 float32 (~200MB); MiniLM index is 5,000 x384 (~7.7MB). The target is <6GB total, but laptop peak memory is not certified by cloud runs.

Committed reports contain aggregate statistics only. Raw feeds/graphs, model caches and full prediction candidate rankings stay ignored. See reports/VALIDATION.md for actual outcomes and pending independent evaluations.
