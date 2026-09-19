# TOOLBOX — every built tool has a home

Classes: WIRED (called by code or a gate) · HAND (you run it) · ARCHIVE (kept for its logic).

| tool | class | what it does | run |
|---|---|---|---|
| `sonar-bootstrap` / `sonar-bootstrap.js` | HAND | the fresh-session briefing, derived from disk only | `./sonar-bootstrap` |
| `sonar-brain.js` | WIRED | the manifest — an index of the sources of truth, never a source of truth | `node sonar-brain.js` |
| `sonar-doctor.js` | WIRED | the control plane: classifies every capability VERIFIED / BROKEN / UNKNOWN | `node sonar-doctor.js` |
| `sonar-trust.js` | WIRED | trust states + provenance | (library) |
| `sonar-boundary.js` | WIRED | the mandatory execution boundary | (library) |
| `sonar-run.js` | WIRED | run namespace, manifest, evidence graph | (library) |
| `sonar-pipeline.js` | WIRED | the contract enforcer and the only promotion gate | `node sonar-pipeline.js --promote <run>` |
| `sonar-adjudicate.js` | WIRED | role separation as artefacts | (library) |
| `sonar-registry.js` | WIRED | derived registries (capabilities, failures, prior art) | (library) |
| `sonar-decide.js` | HAND | the decision ledger | `node sonar-decide.js` |
| `sonar-firewall.js` | HAND | the regression firewall (failure patterns) | `node sonar-firewall.js --patterns` |
| `sonar-attack.js` | WIRED | the attack suite | `node sonar-attack.js` |
| `sonar-e2e.js` | WIRED | synthetic control case + one corruption per stage | `node sonar-e2e.js` |
| `sonar-persisttest.js` | WIRED | the persistence suite | `node sonar-persisttest.js` |
| `sonar-freshtest.js` | WIRED | the fresh-session test | `node sonar-freshtest.js` |
| `cc-sonar.sh` | HAND | CLI over the sweep | `bash cc-sonar.sh "<problem>"` |
| `sweep/sonar_sweep.py` | WIRED | the multi-angle GitHub sweep (generated from source by AST) | `python3 sweep/sonar_sweep.py "<problem>"` |
| `bench/devbench.py` | HAND | known-answer recall bench | `python3 bench/devbench.py` |
