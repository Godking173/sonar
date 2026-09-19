#!/usr/bin/env node
/* sonar-e2e.js — THE SYNTHETIC CONTROL CASE, AND ONE CORRUPTION PER STAGE.
 *
 * A control case whose answer is known in advance, run end to end through the contract, so that
 * "the pipeline works" is a measurement rather than an impression. It is SYNTHETIC on purpose:
 * it touches no network and no sealed benchmark case, so it can be run a thousand times without
 * contaminating anything and without spending a single API call. It tests the CONTRACT, not
 * discovery quality — discovery quality is what the sealed benchmark is for, and that stays frozen.
 *
 * Planted truth: the correct answer is acme/heartbeat-watchdog, whose file watchdog.js contains
 * the fragment that actually solves the problem. Two decoys are planted alongside it: one that is
 * eligible but irrelevant, one that is relevant but dead.
 *
 * Then, one at a time, a single artefact from each stage is corrupted and the pipeline must refuse
 * to produce a trustworthy verdict. A pipeline that only passes when everything is fine is not a
 * pipeline, it is a hope.
 */
"use strict";
const fs = require("fs"), path = require("path"), os = require("os");
/* The namespace is relocated here, first, in the open. sonar-run.js re-resolves the runs
   directory ON EVERY CALL — the original resolve-once-at-require design meant any transitive
   require that loaded sonar-run before this line silently un-relocated the namespace; the attack
   suite proved it (brain→boundary→run loaded at startup, sixteen throwaway runs landed in the
   CANONICAL namespace, and promotion judged them durable). See
   defect.runs-namespace-pinned-at-require-time in sonar/failures.jsonl. */
/* S24 (2026-08-11): relocation is for the THROWAWAY paths only. The corruption matrix and the
   attack suite build runs that must not litter a mount which cannot delete files — they relocate.
   The POSITIVE CONTROL does the opposite job: it promotes a REAL record into the REAL ledger, so
   its run must be built in the canonical namespace, survive the process, and be committed. The
   first positive control relocated like everything else, and the ledger then held a VERIFIED
   record whose run no longer existed (defect.promoted-run-not-persisted). Never again. */
const PROMOTE_CONTROL = process.argv.includes("--promote-control");
if (!process.env.SONAR_RUNS_DIR && !PROMOTE_CONTROL) process.env.SONAR_RUNS_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "sonar-e2e-"));
if (!process.env.SONAR_CACHE_DIR && process.env.SONAR_RUNS_DIR) process.env.SONAR_CACHE_DIR = path.join(process.env.SONAR_RUNS_DIR, "cache");
const BASE = process.env.SONAR_RUNS_DIR;
const Run = require("./sonar-run.js"), P = require("./sonar-pipeline.js"), T = require("./sonar-trust.js");

const PROBLEM = "a scheduled job silently stops running and the dashboard keeps showing green";
const TRUTH = { repo: "acme/heartbeat-watchdog", file: "watchdog.js", commit: "aaaa111122223333" };
const src = s => ({ source: s, at: new Date(0).toISOString(), host_key: T.hostKey(), git_head: T.gitHead() });

function buildCleanRun() {
  const id = Run.begin(PROBLEM, {
    model: { category: "job scheduling", mechanisms: ["heartbeat", "liveness", "last-success timestamp"], anti_concepts: ["cron syntax parser"] },
    discovery_config: { lanes: ["repo-search", "content-search"], cap: 6 },
    source_versions: { synthetic: "control-case-v1" },
    budget: { api_calls: 12, ai_invocations: 3 }
  });
  const pid = Run.node(id, { type: "PROBLEM", label: PROBLEM, provenance: src("run.problem_statement") });

  /* DISCOVERY (tier 5) */
  Run.stageStart(id, "DISCOVERY", ["run.problem_statement", "run.model"]);
  const concepts = ["heartbeat", "liveness", "last-success timestamp"];
  const cids = concepts.map(c => { const n = Run.node(id, { type: "CONCEPT", label: c, provenance: src("run.model.mechanisms") }); Run.edge(id, pid, "DECOMPOSES_TO", n, src("problem model")); return n; });
  const cands = [TRUTH.repo, "acme/cron-parser", "ghost/dead-heartbeat"];
  cands.forEach((repo, i) => {
    const q = Run.node(id, { type: "QUERY", label: `${concepts[i % concepts.length]} scheduled job`, provenance: src("synthetic:repo-search"), lane: i === 2 ? "content-search" : "repo-search" });
    Run.edge(id, cids[i % cids.length], "SEARCHED_AS", q, src("synthetic:query-builder"));
    const r = Run.node(id, { type: "REPOSITORY", label: repo, provenance: src("synthetic:repo-search"), lane: i === 2 ? "content-search" : "repo-search" });
    Run.edge(id, q, "RETURNED", r, src("synthetic:api-response#" + Run.sha(repo).slice(0, 8)));
  });
  Run.write(id, "discovery.jsonl", cands.map(c => JSON.stringify({ repo: c, via: "synthetic" })).join("\n") + "\n");
  Run.stageEnd(id, "DISCOVERY", { artefacts: ["discovery.jsonl", "graph.jsonl"], tools: ["cc-sonar-discover2.js", "cc-sonar-content.js"], commands: ["synthetic: no network"], api_calls: 6 });

  /* EVIDENCE_POOL (tier 1) — ELIGIBILITY ONLY. Never relevance. */
  Run.stageStart(id, "EVIDENCE_POOL", ["discovery.candidates"]);
  const pool = [
    { repo: TRUTH.repo, eligibility: { maintained: 8, license: "MIT", archived: false, verdict: "ELIGIBLE" }, lane: "repo-search" },
    { repo: "acme/cron-parser", eligibility: { maintained: 9, license: "MIT", archived: false, verdict: "ELIGIBLE" }, lane: "repo-search" },
    { repo: "ghost/dead-heartbeat", eligibility: { maintained: 0, license: "MIT", archived: true, verdict: "INELIGIBLE" }, lane: "content-search" }
  ];
  Run.write(id, "pool.jsonl", pool.map(p => JSON.stringify(p)).join("\n") + "\n");
  Run.stageEnd(id, "EVIDENCE_POOL", { artefacts: ["pool.jsonl"], tools: ["cc-sonar-rank.js"], commands: ["synthetic eligibility"], api_calls: 2 });

  /* DEEP_READ (tier 4) — evidence may only come from bytes actually read */
  Run.stageStart(id, "DEEP_READ", ["pool.jsonl"]);
  const repoNode = `REPOSITORY:${Run.sha(TRUTH.repo).slice(0, 12)}`;
  const fnode = Run.node(id, { type: "FILE", label: `${TRUTH.repo}/${TRUTH.file}`, provenance: src(`synthetic-clone:${TRUTH.repo}@${TRUTH.commit}`), blob_sha: "b10b1234" });
  Run.edge(id, repoNode, "CONTAINS", fnode, src(`git ls-files @${TRUTH.commit}`));
  const frag = Run.node(id, { type: "FRAGMENT", label: "if (Date.now() - lastSuccess > interval * 2) alert('job stopped')", provenance: src(`git grep -n lastSuccess ${TRUTH.file}`), lines: "41-43" });
  Run.edge(id, fnode, "CONTAINS", frag, src("git grep"));
  Run.write(id, "reads.jsonl", JSON.stringify({ repo: TRUTH.repo, commit: TRUTH.commit, depth: "code", files: 12 }) + "\n");
  Run.write(id, "fragments.jsonl", JSON.stringify({ node: frag, repo: TRUTH.repo, file: TRUTH.file, lines: "41-43" }) + "\n");
  Run.stageEnd(id, "DEEP_READ", { artefacts: ["reads.jsonl", "fragments.jsonl"], tools: ["cc-priorart.js"], commands: [`git clone --depth 1 ${TRUTH.repo}`, `git grep -n lastSuccess`], cache_hits: 0 });

  /* HISTORY (tier 8) */
  Run.stageStart(id, "HISTORY", ["reads.jsonl", "pool.jsonl"]);
  const iss = Run.node(id, { type: "ISSUE", label: `${TRUTH.repo}#12 silent failure went unnoticed for 4 days`, provenance: src(`synthetic-api:issues/${TRUTH.repo}/12`), url: `https://example.invalid/${TRUTH.repo}/issues/12` });
  Run.edge(id, repoNode, "HAS_HISTORY", iss, src("synthetic issue search"));
  Run.write(id, "history.jsonl", JSON.stringify({ repo: TRUTH.repo, kind: "issue", n: 12, distance: "direct" }) + "\n");
  Run.stageEnd(id, "HISTORY", { artefacts: ["history.jsonl"], tools: ["cc-sonar-history.js"], commands: ["synthetic issue search"], api_calls: 2 });

  /* COMPARISON (tier 9) — RELEVANCE, separately, max() not sum() */
  Run.stageStart(id, "COMPARISON", ["fragments.jsonl", "history.jsonl", "pool.jsonl"]);
  const rel = [
    { repo: TRUTH.repo, relevance: { level: "DIRECT_SOLUTION", best_evidence: "fragment", from_node: frag, method: "max" } },
    { repo: "acme/cron-parser", relevance: { level: "FALSE_POSITIVE", best_evidence: "none", from_node: null, method: "max" } }
  ];
  Run.write(id, "relevance.jsonl", rel.map(r => JSON.stringify(r)).join("\n") + "\n");
  Run.stageEnd(id, "COMPARISON", { artefacts: ["relevance.jsonl"], tools: ["cc-sonar-relevance.js"], commands: ["local"] });

  /* SYNTHESIS (tier 10) — the first AI stage, and it concludes BLIND (A51/B1): the role is
     declared, the inputs are frozen in a snapshot whose files_present proves contrarian.jsonl
     did not exist yet, and the CLAIM is authored by the SYNTHESIZER (B2). */
  const Adj = require("./sonar-adjudicate.js");
  Run.stageStart(id, "SYNTHESIS", ["relevance.jsonl", "fragments.jsonl", "history.jsonl"]);
  Adj.declareRole(id, "SYNTHESIS", { role: "SYNTHESIZER", model: "synthetic-control", model_version: "v1", prompt: "SYNTHESIZER: combine the frozen evidence into cited claims; no objection exists yet.", config: { temperature: 0, seed: 1 } });
  Adj.takeSnapshot(id, "SYNTHESIZER", ["relevance.jsonl", "fragments.jsonl", "history.jsonl", "graph.jsonl"]);
  const claim = Run.node(id, { type: "CLAIM", label: `${TRUTH.repo} solves silent job death via last-success timestamp comparison`, provenance: src("synthesis"), author: "SYNTHESIZER" });
  Run.edge(id, frag, "SUPPORTS", claim, src("fragment quoted verbatim"));
  Run.write(id, "synthesis.json", { answer: TRUTH.repo, mechanism: "compare last-success timestamp against 2x interval", claims: [{ id: "CL1", claim: `${TRUTH.repo} implements the mechanism`, cites: [frag, iss] }], cites: [frag, iss, claim] });
  Run.stageEnd(id, "SYNTHESIS", { artefacts: ["synthesis.json", "snapshots/SYNTHESIZER.json"], tools: [], commands: ["synthesis pass"], ai_invocations: 1 });

  /* CONTRARIAN (tier 10) — attacks the FROZEN synthesis: the conclusion and the evidence,
     never the synthesizer's private reasoning. Objections are tied to evidence-node ids. */
  Run.stageStart(id, "CONTRARIAN", ["synthesis.json", "relevance.jsonl", "fragments.jsonl"]);
  Adj.declareRole(id, "CONTRARIAN", { role: "CONTRARIAN", model: "synthetic-control", model_version: "v1", prompt: "CONTRARIAN: refute the frozen conclusion using only the evidence and the conclusion itself.", config: { temperature: 0, seed: 2 } });
  Adj.takeSnapshot(id, "CONTRARIAN", ["synthesis.json", "relevance.jsonl", "fragments.jsonl", "graph.jsonl"]);
  const counter = Run.node(id, { type: "COUNTERCLAIM", label: "one fragment and one issue is a thin pool; the alert path itself is unverified", provenance: src("contrarian pass"), author: "CONTRARIAN" });
  Run.edge(id, counter, "ATTACKS", claim, src("contrarian pass"));
  Run.write(id, "contrarian.jsonl", JSON.stringify({ objection_to: "CL1", attacks: [counter], evidence_nodes: [frag], verdict: "revised", unaddressed: "the alert delivery path was never read" }) + "\n");
  Run.stageEnd(id, "CONTRARIAN", { artefacts: ["contrarian.jsonl", "snapshots/CONTRARIAN.json"], tools: ["cc-sonar-bench.js"], commands: ["contrarian pass"], ai_invocations: 1 });

  /* ADJUDICATION (tier 10) — a third, separately-identified role resolves every claim against a
     FROZEN evidence snapshot. The independence ladder is recorded honestly: declared identity and
     observed execution only — underlying weights are UNKNOWN, and claiming more is refused. */
  Run.stageStart(id, "ADJUDICATION", ["synthesis.json", "contrarian.jsonl", "graph.jsonl", "manifest.json"]);
  const adjId = Adj.declareRole(id, "ADJUDICATION", { role: "ADJUDICATOR", model: "synthetic-control-adjudicator", model_version: "v1", prompt: "ADJUDICATOR: resolve each claim against the frozen evidence and the objections; you never see private reasoning.", config: { temperature: 0, seed: 3 } });
  const adjSnap = Adj.takeSnapshot(id, "ADJUDICATOR", ["synthesis.json", "contrarian.jsonl", "graph.jsonl"]);
  Run.write(id, "adjudication.json", {
    role: adjId, at: new Date().toISOString(),
    input_snapshot: "snapshots/ADJUDICATOR.json", input_snapshot_sha256: adjSnap.sha256,
    evidence_snapshot: { graph_bytes: adjSnap.files["graph.jsonl"].bytes, graph_prefix_sha256: adjSnap.files["graph.jsonl"].prefix_sha256, synthesis_sha256: adjSnap.files["synthesis.json"].sha256, contrarian_sha256: adjSnap.files["contrarian.jsonl"].sha256 },
    independence: { declared_identity: true, observed_execution: true, verified_configuration: false, underlying_weights: "UNKNOWN" },
    limitation: "Distinct declared identities prove DECLARED_IDENTITY and OBSERVED_EXECUTION only; underlying model weights are unprovable from inside this repository (B5).",
    claims: [{ id: "CL1", claim: `${TRUTH.repo} implements the mechanism`, cites: [claim], supporting: [frag, iss], contradicting: [counter], objections_considered: [counter], resolution: "PARTIALLY_SUPPORTED", why: "the fragment and the issue support the mechanism; the counterclaim stands on the unread alert path, so full support is refused" }]
  });
  Run.stageEnd(id, "ADJUDICATION", { artefacts: ["adjudication.json", "snapshots/ADJUDICATOR.json"], tools: ["sonar-adjudicate.js"], commands: ["adjudication pass"], ai_invocations: 1 });

  /* VERDICT (tier 10) — three separate dimensions, no collapsed score, downstream of adjudication */
  Run.stageStart(id, "VERDICT", ["synthesis.json", "contrarian.jsonl", "adjudication.json"]);
  const vnode = Run.node(id, { type: "VERDICT", label: `${TRUTH.repo} is a DIRECT_SOLUTION with LOW confidence`, provenance: src("verdict stage") });
  Run.edge(id, claim, "RESOLVES_TO", vnode, src("verdict stage"));
  Run.write(id, "verdict.json", {
    conclusion: `${TRUTH.repo} implements the mechanism`, repositories: [TRUTH.repo],
    eligibility: { [TRUTH.repo]: "ELIGIBLE" }, relevance: { [TRUTH.repo]: "DIRECT_SOLUTION" },
    truth: { proven: false, why: "one fragment read; the alert delivery path was never opened" },
    sufficiency: "SUFFICIENT_FOR_LOW_CONFIDENCE", confidence: "LOW", trust: "OBSERVED",
    cites: [frag, iss, claim, counter, vnode]
  });
  Run.stageEnd(id, "VERDICT", { artefacts: ["verdict.json"], tools: ["cc-sonar-sufficiency.js"], commands: ["sufficiency gate"] });
  Run.finish(id);
  return id;
}

/* one corruption per stage — each must make the pipeline refuse */
const CORRUPTIONS = [
  { stage: "DISCOVERY", what: "delete the artefact the stage claims it produced", apply: d => fs.unlinkSync(path.join(d, "discovery.jsonl")) },
  { stage: "EVIDENCE_POOL", what: "edit the artefact after the stage ended", apply: d => fs.appendFileSync(path.join(d, "pool.jsonl"), JSON.stringify({ repo: "smuggled/repo", eligibility: { verdict: "ELIGIBLE" } }) + "\n") },
  { stage: "DEEP_READ", what: "strip a fragment's provenance from the graph", apply: d => { const p = path.join(d, "graph.jsonl"); const rows = fs.readFileSync(p, "utf8").split("\n").filter(Boolean).map(JSON.parse); const f = rows.find(r => r.kind === "node" && r.type === "FRAGMENT"); delete f.provenance; fs.writeFileSync(p, rows.map(r => JSON.stringify(r)).join("\n") + "\n"); } },
  { stage: "HISTORY", what: "tamper with the history artefact", apply: d => fs.writeFileSync(path.join(d, "history.jsonl"), JSON.stringify({ repo: "acme/cron-parser", kind: "issue", n: 999, distance: "direct" }) + "\n") },
  { stage: "COMPARISON", what: "rewrite relevance after the stage ended", apply: d => fs.writeFileSync(path.join(d, "relevance.jsonl"), JSON.stringify({ repo: "acme/cron-parser", relevance: { level: "DIRECT_SOLUTION" } }) + "\n") },
  { stage: "CONTRARIAN", what: "delete the contrarian record so the objection disappears", apply: d => fs.unlinkSync(path.join(d, "contrarian.jsonl")) },
  { stage: "ADJUDICATION", what: "delete the adjudication record so no one independently resolved the claims", apply: d => fs.unlinkSync(path.join(d, "adjudication.json")) },
  { stage: "SYNTHESIS", what: "replace the synthesis with an uncited answer", apply: d => fs.writeFileSync(path.join(d, "synthesis.json"), JSON.stringify({ answer: "totally/different-repo", cites: [] })) },
  { stage: "VERDICT", what: "promote the verdict to VERIFIED with no verifying command", apply: d => { const p = path.join(d, "verdict.json"); const v = JSON.parse(fs.readFileSync(p, "utf8")); v.trust = "VERIFIED"; v.truth = { proven: true }; fs.writeFileSync(p, JSON.stringify(v)); } },
  { stage: "EVENTS", what: "rewrite the event chain to hide a stage", apply: d => { const p = path.join(d, "events.jsonl"); const rows = fs.readFileSync(p, "utf8").split("\n").filter(Boolean).map(JSON.parse); rows.splice(3, 1); fs.writeFileSync(p, rows.map(r => JSON.stringify(r)).join("\n") + "\n"); } }
];

function main() {
  const base = BASE, P2 = P;
  const id = buildCleanRun();
  const clean = P2.verifyRun(id);
  console.log("SYNTHETIC END-TO-END CONTROL CASE");
  console.log(`  run ${id} · planted answer ${TRUTH.repo} · no network, no sealed case touched\n`);
  console.log(`  CLEAN RUN: ${clean.passed}/${clean.total} contract checks ${clean.ok ? "✓ PASS" : "✗ FAIL"}`);
  if (!clean.ok) { for (const c of clean.checks.filter(c => !c.pass)) console.log(`    ✗ ${c.check}: ${c.detail}`); console.log("\n  A control case that cannot pass clean proves nothing. Stopping."); process.exit(1); }
  const golden = path.join(base, id + "-golden");
  fs.cpSync(path.join(base, id), golden, { recursive: true });

  console.log("\n  ONE CORRUPTION PER STAGE — each must be detected and must block promotion:");
  let undetected = 0;
  for (const c of CORRUPTIONS) {
    fs.rmSync(path.join(base, id), { recursive: true, force: true });
    fs.cpSync(golden, path.join(base, id), { recursive: true });
    try { c.apply(path.join(base, id)); } catch (e) { console.log(`  ! could not apply ${c.stage}: ${e.message}`); }
    const r = P2.verifyRun(id);
    const prom = P2.promote(id);
    const detected = !r.ok && !prom.promoted;
    if (!detected) undetected++;
    console.log(`  ${detected ? "✓ REFUSED " : "✗ ACCEPTED"} ${c.stage.padEnd(14)} ${c.what}`);
    console.log(`      caught by: ${r.failed_checks.join(", ") || "NOTHING — the pipeline accepted a corrupted run"}`);
  }
  fs.rmSync(path.join(base, id), { recursive: true, force: true });
  fs.cpSync(golden, path.join(base, id), { recursive: true });
  console.log(`\n  → ${CORRUPTIONS.length - undetected}/${CORRUPTIONS.length} corruptions refused.`);
  console.log(undetected ? "  ✗ FAIL — a corrupted run produced a verdict." : "  ✓ PASS — every corrupted run was refused a verdict.");
  process.exit(undetected ? 1 : 0);
}
/* ── THE POSITIVE CONTROL ────────────────────────────────────────────────────────────
   Proving 42 refusals proves nothing on its own: a system that refuses everything is trivially
   "safe" and completely useless. This proves the door OPENS for a legitimate controlled run.
   It is deliberately NOT part of the gate, because promotion appends to the real trusted ledger.
   The read it attests is REAL — this repository, at its real HEAD, with a command that actually
   executed — so the record it mints is true. Fabricating a read of the synthetic control repo
   would put a false claim into trusted evidence, which is the exact crime this system exists to
   prevent, and doing it to demo the system would be the worst possible way to fail. */
function promoteControl() {
  /* S24: the positive control PERSISTS. A relocated namespace would rebuild the exact orphan
     this system now refuses everywhere else, so refuse it here too — loudly, before any work. */
  if (path.resolve(Run.RUNS) !== Run.CANONICAL_RUNS) {
    console.log("POSITIVE CONTROL REFUSED (S24): SONAR_RUNS_DIR is set, so this run would be ephemeral.");
    console.log("The positive control persists its run in sonar/runs/ — unset SONAR_RUNS_DIR and re-run.");
    process.exit(1);
  }
  const id = buildCleanRun();
  const head = require("child_process").execSync("git rev-parse HEAD", { cwd: __dirname, encoding: "utf8" }).trim();
  const cmd = "git grep -c ADMISSION -- sonar-trust.js";
  const out = require("child_process").execSync(cmd, { cwd: __dirname, encoding: "utf8" }).trim();
  const src = { source: "positive-control: real local read", at: new Date().toISOString(), host_key: T.hostKey(), git_head: T.gitHead() };
  Run.stageStart(id, "VERIFICATION", ["verdict.json", "manifest.json", "events.jsonl", "graph.jsonl"]);
  const rid = Run.node(id, { type: "REPOSITORY", label: "local/this-repo", provenance: src, commit: head, read_command: cmd });
  const fid = Run.node(id, { type: "FRAGMENT", label: `git grep found ${out} match(es) for ADMISSION in sonar-trust.js`, provenance: { ...src, source: cmd } });
  Run.edge(id, rid, "CONTAINS", fid, { ...src, source: cmd });
  Run.stageEnd(id, "VERIFICATION", { artefacts: [], tools: ["git"], commands: [cmd] });
  Run.finish(id);
  const v = P.verifyRun(id);
  const prom = P.promote(id);
  console.log("POSITIVE CONTROL — does the door actually open for a legitimate run?");
  console.log(`  run ${id} · verification ${v.passed}/${v.total} ${v.ok ? "PASS" : "FAIL: " + v.failed_checks.join(", ")}`);
  console.log(`  seal ${(require("./sonar-boundary.js").computeSeal(id) || "").slice(0, 16)}…`);
  console.log(`  promoted: ${prom.promoted}${prom.why ? " — " + prom.why : ""} · research records admitted: ${prom.reads || 0}`);
  console.log(prom.promoted ? "  ✓ PASS — a controlled run CAN mint trusted evidence. The gate is a door, not a wall."
                            : "  ✗ FAIL — nothing can ever be promoted, which makes the whole pipeline decorative.");
  if (prom.promoted) console.log(`  run persisted at sonar/runs/${id}/ — COMMIT IT (cc-safe-commit.sh) or boundary-audit goes RED (S24).`);
  process.exit(prom.promoted ? 0 : 1);
}
if (require.main === module && process.argv.includes("--promote-control")) promoteControl();

module.exports = { buildCleanRun, CORRUPTIONS, PROBLEM, TRUTH, promoteControl };
if (require.main === module && !process.argv.includes("--promote-control")) main();
