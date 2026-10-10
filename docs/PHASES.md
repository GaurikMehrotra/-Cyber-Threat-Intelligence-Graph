# All 19 phases — complete code and reproducible commands

The user requested all phases in one implementation, so there are no interactive “next” gates. Full code is in the linked directories; these are runnable checkpoints, not placeholders. Run from the repository root in an activated Python 3.12 environment. Commands marked `make run` keep serving; use a second terminal for smoke checks. Do not run two servers on the same port.

Commit examples below are for development changes you actually make at each checkpoint; they are not necessary to run the already committed project. Do not stage ignored feeds, credentials or database state. LOCAL means CPU-only on your laptop; no Kaggle experiment is needed or claimed.

## Phase 1: Environment and skeleton [LOCAL]

Code: `src/config.py`, `configs`, `.env.example`, `requirements.in`, `requirements.txt`, `requirements-ml.in`, `requirements-ml.txt`, `pyproject.toml`, `.python-version`, `.gitignore`.

```bash
python -m pip install -r requirements.txt
python -m scripts.init_env
make ml
```

Expected: Private .env is created once; CPU torch is selected. No credentials are printed.

```bash
git add src/config.py configs .env.example requirements.in requirements.txt requirements-ml.in requirements-ml.txt pyproject.toml .python-version .gitignore
git commit -m "Pin CPU development environment and resource configuration"
```

## Phase 2: Neo4j and schema [LOCAL]

Code: `docker`, `cypher/schema.cypher`, `src/graph`.

```bash
make db-up schema
```

Expected: Driver readiness and schema installation succeed. Memory settings are accepted by the official image.

```bash
git add docker cypher/schema.cypher src/graph
git commit -m "Define constrained evidence graph and capped Neo4j runtime"
```

## Phase 3: Public collection and exploration [LOCAL]

Code: `src/ingest/collect.py`, `DATA_SOURCES.md`, `licenses`, `notebooks/01_data_exploration.ipynb`.

```bash
python -m src.cli collect --accept-source-terms --sources attack
```

Expected: Two release snapshots are stored under ignored data/processed. Other source terms must be verified separately.

```bash
git add src/ingest/collect.py DATA_SOURCES.md licenses notebooks/01_data_exploration.ipynb
git commit -m "Add bounded cached public publisher collection"
```

## Phase 4: Provenance and IOC normalization [LOCAL]

Code: `src/ingest/provenance.py`, `src/intel/defang.py`, `src/security/sanitize.py`, `tests/test_intel.py`.

```bash
python -m pytest tests/test_intel.py tests/test_ingest.py -q
```

Expected: Valid domains/IPs/hashes normalize; malformed inputs are rejected with reasons; UI values defang.

```bash
git add src/ingest/provenance.py src/intel/defang.py src/security/sanitize.py tests/test_intel.py
git commit -m "Validate inert indicators and source observations"
```

## Phase 5: ATT&CK ingestion [LOCAL]

Code: `src/ingest/attack.py`, `src/graph/loaders.py`, `tests/test_neo4j.py`.

```bash
python -m src.cli load --graph data/processed/attack-v17.1.json
```

Expected: v17.1 has 1,980 scoped nodes and 18,364 edges across enterprise/mobile/ICS after exclusions.

```bash
git add src/ingest/attack.py src/graph/loaders.py tests/test_neo4j.py
git commit -m "Map ATTACK STIX and preserve idempotent batched evidence"
```

## Phase 6: CVE KEV and CWE linking [LOCAL]

Code: `src/ingest/kev.py`, `src/ingest/nvd.py`, `src/ingest/cwe.py`.

```bash
python -m src.cli ingest --kind kev --input data/fixtures/kev.json
python -m src.cli ingest --kind nvd --input data/fixtures/nvd.json
python -m src.cli ingest --kind cwe --input data/fixtures/cwe.xml
```

Expected: One synthetic CVE links to CWE-79 and two source-specific product identifiers; live sources remain separately gated.

```bash
git add src/ingest/kev.py src/ingest/nvd.py src/ingest/cwe.py
git commit -m "Link CVE KEV CWE and explicit source product evidence"
```

## Phase 7: Bounded reports and indicators [LOCAL]

Code: `src/ingest/reports.py`, `src/ingest/iocs.py`, `data/fixtures`.

```bash
python -m src.cli ingest --kind report --input data/fixtures/report.json
python -m src.cli ingest --kind ioc --input data/fixtures/iocs.json --source synthetic-iocs --source-id authored-sample
```

Expected: MENTIONED_IN is created; no attribution/exploitation inference or indicator contact occurs.

```bash
git add src/ingest/reports.py src/ingest/iocs.py data/fixtures
git commit -m "Ingest offline reports without co-mention attribution"
```

## Phase 8: Graph quality [LOCAL]

Code: `src/quality`.

```bash
python -m src.cli quality
```

Expected: Synthetic fixture reports no invalid IOCs or missing provenance; orphan counts are disclosed.

```bash
git add src/quality
git commit -m "Report graph quality and provenance completeness"
```

## Phase 9: Entity resolution [LOCAL]

Code: `src/resolve`, `src/eval/er_eval.py`, `data/eval/alias_pairs.csv`.

```bash
python -m src.cli resolve --sentence
python -m src.cli er-eval
```

Expected: Review JSONL is produced; blank human labels return unlabeled/null metrics, not manufactured scores.

```bash
git add src/resolve src/eval/er_eval.py data/eval/alias_pairs.csv
git commit -m "Add reversible alias resolution and independent label evaluation"
```

## Phase 10: Graph analytics [LOCAL]

Code: `src/analytics`, `tests/test_analytics.py`, `notebooks/02_graph_analytics.ipynb`.

```bash
python -m src.cli analytics
python -m pytest tests/test_analytics.py -q
```

Expected: PageRank, degree, betweenness, Louvain, co-occurrence and capped pivots are exercised by hand-computable tests.

```bash
git add src/analytics tests/test_analytics.py notebooks/02_graph_analytics.ipynb
git commit -m "Analyze bounded observed subgraphs and technique overlap"
```

## Phase 11: CVE prioritization [LOCAL]

Code: `src/analytics/cve_priority.py`, `configs`.

```bash
python -m src.cli analytics --output reports/local/priority-and-analytics.json
```

Expected: A weighted heuristic lists KEV, severity, graph, centrality and missing EPSS inputs with evidence/caveats.

```bash
git add src/analytics/cve_priority.py configs
git commit -m "Explain CVE priority components and missing inputs"
```

## Phase 12: Temporal prediction [LOCAL]

Code: `src/predict`, `notebooks/03_link_prediction.ipynb`, `tests/test_resolution_prediction.py`.

```bash
python -m src.cli predict --old data/processed/attack-v16.1.json --new data/processed/attack-v17.1.json --sentence --output reports/local/attack-temporal.json
```

Expected: Five baselines, three seeds, held-out additions and cold-start counts; ROC-AUC/AP/Hits@10/MRR with tie handling. LOCAL only.

```bash
git add src/predict notebooks/03_link_prediction.ipynb tests/test_resolution_prediction.py
git commit -m "Evaluate older-only graph and text prediction baselines"
```

## Phase 13: Semantic search and optional NL templates [LOCAL]

Code: `src/search`.

```bash
python -m src.cli index --mode sentence
```

Expected: MiniLM embeddings and FAISS persist/reload; phishing ranks the fixture technique; FakeLLM never executes Cypher.

```bash
git add src/search
git commit -m "Persist CPU semantic search and safe optional template previews"
```

## Phase 14: Golden queries and performance [LOCAL]

Code: `src/eval/golden_queries.py`, `src/eval/perf.py`, `data/eval`.

```bash
python -m src.cli golden --questions data/eval/golden_queries.json
python -m src.cli benchmark
```

Expected: Human questions remain unlabeled. The 30 fixture questions pass only in the synthetic-only database. Cloud metrics do not certify laptop peak RAM.

```bash
git add src/eval/golden_queries.py src/eval/perf.py data/eval
git commit -m "Benchmark actual queries and preserve independent evaluation templates"
```

## Phase 15: Authenticated FastAPI and STIX [LOCAL]

Code: `src/api`, `src/security/cypher_guard.py`, `src/intel/stix_export.py`, `scripts/smoke_api.py`.

```bash
make run
# In another terminal:
python -m scripts.smoke_api
```

Expected: Auth fails closed; local requests verify graph behavior and signed preview/execute. Explicit STIX export is valid with custom product/CWE objects.

```bash
git add src/api src/security/cypher_guard.py src/intel/stix_export.py scripts/smoke_api.py
git commit -m "Serve authenticated bounded evidence queries and validated STIX"
```

## Phase 16: Visualization [LOCAL]

Code: `app`, `reports/figures/ui.png`.

```bash
make run
```

Expected: Local bundled Cytoscape renders <=200 nodes. Clicking nodes/edges shows provenance; inferred edges use a dashed hypothesis style.

```bash
git add app reports/figures/ui.png
git commit -m "Display defanged indicators and inspectable graph evidence"
```

## Phase 17: Security quality and CI [LOCAL]

Code: `tests`, `.github/workflows/ci.yml`, `THREAT_MODEL.md`, `Makefile`, `LICENSE`.

```bash
make lint security integration audit
```

Expected: Meaningful fixture and database tests run; Ruff/Bandit/pip-audit gate CI. Remote CI status is not assumed from local checks.

```bash
git add tests .github/workflows/ci.yml THREAT_MODEL.md Makefile LICENSE
git commit -m "Add defensive quality gates and ephemeral Neo4j CI"
```

## Phase 18: Documentation and results [LOCAL]

Code: `README.md`, `docs`, `reports`.

```bash
python -m src.cli --help
```

Expected: README screenshot is from the actual local UI; tables separate measured, synthetic, unrun and human-required work.

```bash
git add README.md docs reports
git commit -m "Document reproducible workflows measured results and limitations"
```

## Phase 19: Final audit and GitHub publication [LOCAL]

Code: `README.md`, `reports/VALIDATION.md`.

```bash
git status --short
git ls-files data/raw data/processed .env docker/volumes
make lint security integration audit
git push -u origin main
```

Expected: No raw feeds, credentials or database files tracked. Push to the existing origin without force; see actual validation report for publication status.

```bash
git add README.md reports/VALIDATION.md
git commit -m "Complete defensive project validation and publication checklist"
```

## Final checklist

- [x] Complete runnable source files and pinned CPU dependencies.
- [x] Synthetic fixtures, idempotence, IOC normalization, alias/analytics, leakage, guard, auth/rate-limit, STIX and end-to-end validation.
- [x] Actual Docker Neo4j, public ATT&CK release loads, CPU sentence/FAISS search and local browser verified.
- [x] Raw/processed dumps, .env, caches, logs and DB files ignored; only aggregate artifacts committed.
- [x] Threat model, separate dataset attribution notices, schema rationale, evaluation caveats and phase commands documented.
- [ ] Human alias labels and real-world golden answers (cannot truthfully be automated).
- [x] Official CISA/CWE terms and live KEV/NVD/CWE ingestion, repeated loads and source-reference checks.
- [ ] Current NVD terms/rate documentation (blocked here), independent human reviews and laptop measurements.
- [ ] Laptop memory/performance replication.
- [ ] Remote GitHub Actions run verified (local tests do not prove remote CI completion).

The GitHub repository already exists; `gh repo create` would be redundant. For a separate fork/project, create an empty repo using your authenticated `gh repo create <owner>/<new-name> --public`, then add that remote intentionally. The current task pushes to the existing origin/main without rewriting remote history.
