# Threat model

This is a single-user local defensive research service, not an Internet-facing production system.

| Asset / trust boundary | Threat | Mitigation | Residual risk |
|---|---|---|---|
| API and Neo4j credentials | Disclosure in Git, logs, browser storage | Environment-only keys, ignored private .env, constant-time API key check, no key logging, UI keeps key in input memory | An authenticated local user can inspect their own process and files |
| Graph facts and provenance | Poisoned feeds, unsupported attribution, confidence laundering | Per-source per-property observations, documented aggregation, source IDs, reversible alias hypotheses, no co-mention attribution | Source assertions can be wrong; confidence is not calibrated probability |
| Query boundary | Cypher injection, writes via LLM | Exact read-only template allowlist, typed exact parameters, READ session, five-second transaction timeout, row cap, expiring signed query preview before explicit execution | Database user has ingestion write privileges locally; deployment should provision a separate read-only service identity (RBAC availability differs in Community) |
| Browser | XSS via report content, unsafe IOC links | Text sanitation, DOM textContent, no HTML from feeds, local bundled Cytoscape, no IOC hyperlinks, no external analytics/CDNs | Browser extensions and compromised local dependencies remain outside scope |
| Collection | SSRF, redirects to IOCs, DNS probing | Fixed official publisher HTTPS host/path allowlist; redirects disabled; collector never receives IOC values; extraction is offline | Publishers may change paths; failures require investigation, not broader allowlists |
| Parsing and embeddings | XML entities, pickle execution, malicious model code | defusedxml, byte bounds, safe YAML, allow_pickle=False NumPy files, pinned model revision, trust_remote_code=False, safe tensor model loading | Package/model supply-chain risk requires ongoing audits and trusted TLS/checksums |
| Memory and availability | Huge requests, exports, embeddings, graph traversals | 64 KiB request bodies, pagination, node/edge/candidate caps, bounded pivots with hub filtering, batch embeddings, Neo4j 2 GiB container | Limits are enforced per operation, not a universal guarantee of total laptop memory |
| ML evaluation | Future leakage, false claims, unknown negatives | Older-node features and text only, held-out newer assertions, full candidate rankings, disclose cold starts and ties, multiple seeds, blank human labels remain unevaluated | ATT&CK publication dates differ from incident dates; unobserved links are not true negatives |

Safety rules: never scan, probe, resolve or visit indicators; no exploit execution or malware downloads. Indicators are data. STIX export is an explicit machine interchange operation containing canonical SCO values; UI/API browsing is defanged. The code has no scanning component.

No real LLM provider is enabled. FakeLLM demonstrates the interface and always discloses its fixed response. An external adapter must return a validated template selection, not executable Cypher; ingested text remains untrusted JSON evidence below system instructions. API keys belong only in .env/environment.

Use one Uvicorn worker: the in-memory limiter is shared across valid-key requests within that process. Reverse proxy TLS, shared distributed rate limiting, centralized secret management, deployment hardening and multi-user authorization are outside this local portfolio scope. Keep ports on loopback.

Maintenance purge must pause ingestion. It uses bounded atomic batches, so interruption can leave partial removal; rerunning is safe. Every remaining property is reconstructed from retained observations. Source deletion is not a forensic erasure guarantee for Neo4j transaction logs, backups or exports.
