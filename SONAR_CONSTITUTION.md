# SONAR CONSTITUTION

Permanent rules. Version-controlled. Referenced by the verification system.
Each rule has an ID. Rules marked ENFORCED are checked mechanically by `sonar-doctor.js`
and `cc-verify.sh`; rules marked DOCTRINE are not yet mechanically enforceable and say so
rather than pretending otherwise.

**CLAUDE IS THE OPERATOR. SONAR'S MACHINE-DERIVED STATE IS THE SOURCE OF TRUTH. PROSE IS NEVER PROOF.**

| ID | Rule | Status | Enforced by |
|---|---|---|---|
| S01 | No evidence, no claim. | ENFORCED | `levelFor()` returns UNKNOWN with no record |
| S02 | A claim is not proof. CLAIMED never rises without an executed command. | ENFORCED | trust-state machine; attack A01 |
| S03 | Counts cannot represent relevance without normalization. | DOCTRINE | failure firewall pattern F-COUNT |
| S04 | Discovery and relevance are separate systems. | DOCTRINE | — |
| S05 | Eligibility, relevance and truth are three separate dimensions. | DOCTRINE | — |
| S06 | Metadata may FILTER but can never establish solution relevance. | DOCTRINE | `cc-priorart.js` depth gate |
| S07 | A repository may be evidence without being a solution. | DOCTRINE | distance taxonomy |
| S08 | A failed approach is valuable evidence and is kept, not deleted. | ENFORCED | `sonar/failures.jsonl` + detectors |
| S09 | Negative evidence must be preserved. | ENFORCED | failure ledger is append-only |
| S10 | Sealed experiments cannot be modified retroactively. | ENFORCED | git-blob seal check; attack A09 |
| S11 | Contaminated cases cannot contribute metrics; UNPROVEN is not CLEAN. | ENFORCED | `experiment().contamination` |
| S12 | UNKNOWN is not VERIFIED and is never upgraded without evidence. | ENFORCED | `--selftest`; attacks A03, A05, A06 |
| S13 | Missing historical evidence cannot be back-filled by hand. If the machine did not record the event when it happened, the event did not happen for evidence purposes. | ENFORCED | attack A08; `claims_with_no_read` |
| S14 | Every capability requires an executable verification. | ENFORCED | registry rejects a row with no check |
| S15 | Every known failure requires a regression detector. | ENFORCED | registry rejects a defect with no detector |
| S16 | Claude's memory is never authoritative. | ENFORCED | nothing reads model memory; all state derived |
| S17 | The filesystem, git and the evidence ledger are authoritative. | ENFORCED | all registries derived from those three |
| S18 | Rate limits are infrastructure state, never model belief, and are never cached. | ENFORCED | `resource()` is live-only |
| S19 | Caches are keyed by immutable content identity (commit SHA), never by name or time. | ENFORCED | `cc-priorart.js` SHA skip cache |
| S20 | Sonar must always be allowed to conclude INSUFFICIENT EVIDENCE. | ENFORCED | `cc-sonar-sufficiency.js` |
| S21 | A verification is true only on the host that produced it. | ENFORCED | provenance `host_key`; attacks A06, A12 |
| S22 | A check that cannot fail is not a check. | ENFORCED | probative lint; attack A03 |
| S23 | Evidence is an append-only hash chain. Rewriting history is detectable or it is not evidence. | ENFORCED | `verifyChain()`; attacks A04, A10 |
| S24 | A promoted research run must remain reconstructable from the canonical namespace: the run resolves on disk under sonar/runs/, its seal recomputes exactly, full verification passes from the persisted run, and the run is committed. Ephemeral/relocated namespaces are non-promotable; an orphaned record is permanently INADMISSIBLE and cannot be consumed as trusted. | ENFORCED | promote guard in `sonar-pipeline.js`; admissibility + seal recompute in `sonar-boundary.js`; consumption rejection in `sonar-trust.js`; suite `sonar-persisttest.js` |
| S25 | No model may establish the truth of its own conclusion. The synthesizer concludes blind to the contrarian; the contrarian attacks a frozen synthesis and never private reasoning; an independently-identified adjudicator resolves every claim against a frozen evidence snapshot with evidence-node citations; a contradiction blocks promotion; and declared identity never proves underlying weights — the UNKNOWN limitation is recorded or the record is refused. | ENFORCED | `sonar-adjudicate.js`; adjud.* checks in `sonar-pipeline.js`; attacks A43-A52 in `sonar-attack.js` |

## TRUST STATES — the only ladder

    UNKNOWN                 no proof of any kind
    CLAIMED                 an agent or an authored registry says so. Prose. Worth nothing alone.
    OBSERVED                a tool observed something (a path exists, a binary is on PATH)
    VERIFIED                a deterministic check reproduced it, on THIS host, against current HEAD
    ADVERSARIALLY_VERIFIED  the system was deliberately attacked and still reported the truth
    REPRODUCED              an independent host produced the same VERIFIED result

No state may be entered except by an executed command that leaves a provenance record.
A record from another host can only ever produce REPRODUCED on top of a local VERIFIED —
it can never, by itself, make anything true here.

## PROVENANCE — every record carries all of it or it is not a record

    who (host) · what (fact + claim) · when (timestamp) · where (cwd, paths)
    how (command) · exit code · stdout sha256 · stderr sha256 · tool version
    environment (network state, node version, platform/arch) · git HEAD · dirty flag
    source (filesystem | command | api) · prev record hash · this record hash
