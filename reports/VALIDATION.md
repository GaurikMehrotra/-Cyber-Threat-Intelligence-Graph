# Verified outcomes — 11 October 2026

These are current cloud-instance measurements, not laptop benchmarks or a claim that remote GitHub Actions completed. Artifacts contain aggregate statistics, not raw feed dumps. The screenshot is the actual local UI using the explicitly synthetic 16-node fixture; a separate browser run also rendered the public/synthetic bounded view (200 nodes, 1,136 edges) and returned 20 phishing search results with no JavaScript errors and no external browser requests.

The final instrumented test run measured **63% source line coverage**; passing tests do not imply every branch is covered. A separate fresh core-only environment passed55 tests and skipped the optional FAISS test; the full CPU-ML environment passed all56 with no skips.

## Functional checks

| Check | Outcome | Scope |
|---|---|---|
| Pytest | 56 passing, zero skipped in integration-enabled final run | Offline authored fixtures plus actual Neo4j constraints/idempotence/provenance purge |
| Ruff lint and format | Passed | src, tests, scripts, app |
| Bandit | Passed | src, app, scripts; narrowly documented false positives for seeded sampling/fixed auditor subprocess |
| Core pip-audit | No known vulnerabilities, 87 packages directly audited, no skips | Pinned core requirements |
| Installed dependencies | No known advisories; CPU Torch upstream version audited separately | pip-audit cannot directly audit +cpu local version on PyPI; wrapper normalizes only official CPU Torch, fails unexpected skips, excludes only verified editable project source |
| Neo4j image/config | Real driver query and neo4j-admin validate-config passed | 5.26.27 Community; 2GiB container, 512–768MiB heap, 512MiB page cache, 128MiB transaction cap |
| Idempotence | Fixture and full v17.1 replay completed without new node/edge duplicates | Actual MERGE and observation reconstruction |
| Golden synthetic Cypher | 30/30 correct (accuracy1.0), zero skipped | Independently enumerated synthetic topology; fixture-only database before public data load |
| Human alias labels | Unlabeled; precision/recall/false-merge rate null | 100-row template; 111 full ATT&CK exact/fuzzy candidates queued, not merged |
| Human real-world golden queries | Unlabeled; accuracy null | 30-question template; zero executed, 30 skipped |
| MiniLM + FAISS | Actual pinned CPU model encoded data, persisted/reloaded, returned representative phishing results | Full v17.1 and combined service indexes; fake encoder also tests FAISS without network |
| FastAPI live Neo4j smoke | Passed | Quality, bounded visualization, unauthenticated401, signed preview then confirmed read |
| Browser | Passed | Local bundled Cytoscape, defanged values, evidence click, search; false observed-edge dashed styling checked and corrected |
| STIX2.1 | stix2.parse validated synthetic bundle | Custom weakness/product objects disclosed; actual evidence dates retained |
| Notebooks | All code cells executed | Three fixture notebooks; no network, no stored raw outputs |
| Live KEV/NVD/CWE | Not collected | Current authoritative terms/docs blocked by egress; synthetic parsing/linking tested |
| Laptop peak RAM | Unmeasured | Rerun on user's i3/8GB machine; no fabricated memory guarantee |
| GitHub Actions | Configured; remote outcome not yet verified | Ephemeral Neo4j service, CPU extras, Ruff, pytest, Bandit and pip-audit |

Docker image verified digest: `sha256:937fbd163e302a5751dd329b719c1b05e2a4293af223d61b1aa17e3dea087709`. Docker layer checksum and package TLS verification remained enabled.

## Real ATT&CK release evaluation

Full enterprise/mobile/ICS, active mapped objects only: v16.1 = 1,883 nodes / 17,109 relationships; v17.1 = 1,980 nodes / 18,364 relationships. Older actors163, older techniques858; newer actors170, newer techniques883. Train3,816 actor-technique assertions, held-out additions116, unobserved negatives135,922, candidate pairs136,038, excluded cold-start additions200. The source release commits and processed-input SHA-256 digests are recorded in attack_temporal.json. These two fixed releases are a reproducible comparison, not a claim of using the latest ATT&CK version.

All methods use equal fixed inputs/no hyperparameter tuning. Mean ± population standard deviation across negative-sampling seeds17,42,93:

| Method | ROC-AUC | Average precision | Hits@10 | MRR |
|---|---|---|---|---|
| adamic_adar | 0.7147 ± 0.0026 | 0.3887 ± 0.0107 | 0.0711 ± 0.0000 | 0.0536 ± 0.0000 |
| common_neighbors | 0.7139 ± 0.0027 | 0.3798 ± 0.0109 | 0.0776 ± 0.0000 | 0.0534 ± 0.0000 |
| jaccard | 0.6922 ± 0.0065 | 0.3248 ± 0.0046 | 0.0862 ± 0.0000 | 0.0533 ± 0.0000 |
| preferential_attachment | 0.7224 ± 0.0033 | 0.4203 ± 0.0140 | 0.0776 ± 0.0000 | 0.0466 ± 0.0000 |
| text_embedding | 0.5054 ± 0.0064 | 0.1717 ± 0.0013 | 0.0172 ± 0.0000 | 0.0130 ± 0.0000 |

These are publication-time assertions, not incident dates. Negative pairs are unobserved, not proven false. Classification metrics use five sampled negatives per positive; rankings use all candidates and average ties. Text similarity is close to chance here: no claim of superior semantic link prediction. Predictions are leads requiring verification. Native actor-technique common-neighbor scores would be zero; the older-only actor-sharing projection is explicitly described in docs/EVALUATION.md.

## Measured performance

| Measurement | Cloud result | Interpretation |
|---|---|---|
| Full v17.1 replay throughput | 1748.3 node/edge items/s; 11.636s for 20344 items | Existing graph MERGE replay, not first-load throughput |
| Unindexed lookup | 3.954ms median; 534 db hits | 1,000 synthetic CTIGBenchmark nodes, 20 rounds |
| Indexed lookup | 2.648ms median; 2 db hits | Same synthetic lookup; warm-up/ordering effects remain |
| NetworkX / Cypher | 1.034s / 0.078s | Different workloads; Cypher degrees match the same 100-ID selected subgraph |
| Prediction process peak RSS | 905.2MiB | Includes parsed release graphs and CPU model; measured by Linux getrusage |
| Temporal evaluation runtime | 47.025s | Evaluation/encoding, not downloads or JSON parsing |
| Analytics benchmark Python peak RSS | 236.1MiB | Cloud bounded subgraph analysis |
| Neo4j container / live API RSS spot check | 982.9MiB / 701.6MiB | Spot observations, not simultaneous whole-laptop peak certification |

The individual cloud processes and container measurements support the intended modest CPU workflow. They do not prove a <6GB peak on every laptop or under concurrent workloads. Run sequentially and record docker stats/Python memory on the target machine. Original fixture benchmark had indexed wall time slower than unindexed; artifacts intentionally use the subsequent documented public-graph benchmark and never imply universal speedups.

## Remaining independent work

Label the alias CSV and real-world golden queries, confirm current CISA/NVD/CWE terms/rate limits and permitted IOC/report sources before live collection, rerun laptop memory/latency measurements, and inspect the remote Actions run after pushing. Optional real LLM, random-walk classifiers and Kaggle experiments are not enabled or claimed. Source copyright notices and complete release licenses are retained.
