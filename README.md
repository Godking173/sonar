# Sonar

An engineering-intelligence engine for the moment before you build something: it searches the
world's code for prior art, reads the candidates, and **refuses to conclude when the evidence is
thin**. Two halves:

- **Control plane** (`sonar-*.js`, Node, no dependencies) — makes it impossible for an AI operator
  to claim more than it can prove: a trust ladder (UNKNOWN → CLAIMED → OBSERVED → VERIFIED →
  ADVERSARIALLY_VERIFIED → REPRODUCED), provenance on every record, an append-only hash-chained
  evidence ledger, an execution boundary, an attack suite, and an adjudication flow in which no
  model judges its own conclusion. Rules: `SONAR_CONSTITUTION.md`.
- **Sweep** (`sweep/sonar_sweep.py`, Python, needs the `gh` CLI) — a multi-angle GitHub search
  (keyword · phrase · topic graph · README · name · synonyms · code) that names every word it
  drops, accounts for every match it hides, and reports a failed search as FAILED, never as zero.

## Run the proofs (no network needed)

    ./sonar-bootstrap                 # what a fresh session derives from disk alone
    node sonar-doctor.js --selftest   # the three-state promise (UNKNOWN is reachable)
    node sonar-e2e.js                 # one synthetic run, one corruption per stage, every one refused
    node sonar-persisttest.js         # an unreconstructable run can't be minted, admitted or consumed
    node sonar-attack.js              # the attack suite against the control plane itself
    node sonar-freshtest.js           # a fresh session rebuilds the state without conversation memory

## Run the sweep (needs `gh auth login` + internet)

    bash cc-sonar.sh "mutation testing javascript"
    python3 bench/devbench.py         # known-answer recall on bench/dataset.jsonl

## Honest limits

Read `docs/HONEST-LIMITS.md` before trusting a sweep. Measured, not remembered.

This tree was produced by a deterministic exporter from a private working repo; `MANIFEST.sha256`
lists every file. The ledgers under `sonar/` and `memory/` start empty on purpose — see
`docs/LEDGERS.md`.
