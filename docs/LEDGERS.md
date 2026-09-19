# Ledgers — why they start empty

Sonar's state is derived from the filesystem, git and these append-only ledgers. The public tree
ships them **empty** on purpose: the original project's rows are its own evidence and history, and
the constitution (S13, S23) forbids back-filling or rewriting a chain. Your chain starts at your
first run.

| file | one row per | written by |
|---|---|---|
| `sonar/evidence.jsonl` | evidence node (hash-chained; `prev` → `hash`) | the pipeline, never by hand |
| `sonar/capabilities.jsonl` | capability + its executable verification | `sonar-registry.js` |
| `sonar/failures.jsonl` | known failure + its regression detector | `sonar-registry.js` / `sonar-firewall.js` |
| `sonar/decisions.jsonl` | permanent decision (`D-001` …) | `sonar-decide.js` |
| `sonar/pipeline.jsonl` | promotion event | `sonar-pipeline.js --promote` |
| `memory/frozen-lessons.jsonl` | lesson + the check that arms it | your handoff tooling |
| `memory/prior-art.jsonl` | prior-art READ (what was opened, what was found) | the sweep's evidence stage |
| `memory/sonar-bench.jsonl` | benchmark result | `bench/devbench.py` |

`sonar/phase.json` is the one hand-authored state file: it tells a fresh session what the next
phase is. Edit it at a phase boundary, commit it, and `./sonar-bootstrap` prints it first.
