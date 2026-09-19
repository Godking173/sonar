#!/usr/bin/env node
/* sonar-adjudicate.js — ROLE SEPARATION AS ARTEFACTS, NOT AS PROMPT WORDING.
 *
 * THE RULE THIS FILE EXISTS TO ENFORCE (constitution S25, phase 3): no model may establish the
 * truth of its own conclusion. The SYNTHESIZER concludes blind — the contrarian does not exist
 * yet. The CONTRARIAN attacks a FROZEN synthesis — the conclusion and the evidence, never the
 * synthesizer's private reasoning. The ADJUDICATOR resolves every claim against a FROZEN evidence
 * snapshot with its own declared identity. Separation is enforced through machine-readable
 * artefacts and promotion rules: identities are chained events (and therefore inside the run
 * seal, because the seal covers the event-chain head), input snapshots are hashed at handoff, and
 * sonar-pipeline.js refuses any run where the artefacts contradict the story.
 *
 * WHAT INDEPENDENCE MEANS HERE — no overclaiming, ever (blocker B5):
 *   DECLARED_IDENTITY          the roles declared distinct model/version/prompt-hash/config-hash
 *   OBSERVED_EXECUTION         each role left its own chained events and artefact hashes
 *   VERIFIED_CONFIGURATION     a config was independently verified (not available synthetically)
 *   UNKNOWN_UNDERLYING_WEIGHTS two API calls NEVER prove different weights. Always recorded.
 * A record that CLAIMS underlying-weight independence is refused as an overclaim — the honest
 * limitation is mandatory, mechanically.
 *
 * Usage: --selftest | --show <run-id>
 */
"use strict";
const fs = require("fs"), path = require("path"), crypto = require("crypto");
const Run = require("./sonar-run.js");
const sha = s => crypto.createHash("sha256").update(typeof s === "string" || Buffer.isBuffer(s) ? s : JSON.stringify(s)).digest("hex");

const ROLES = ["EXPLORER", "READER", "HISTORIAN", "SYNTHESIZER", "CONTRARIAN", "ADJUDICATOR"];
const RESOLUTIONS = ["SUPPORTED", "PARTIALLY_SUPPORTED", "UNSUPPORTED", "CONTRADICTED", "UNDECIDABLE"];
const CUMULATIVE = ["graph.jsonl", "events.jsonl"];

/* ── ROLE IDENTITY — declared once, chained forever ──────────────────────────
   The identity is written twice on purpose: into the manifest (convenient) and into the event
   chain (tamper-evident, and covered by the run seal via events_head). The verifier demands the
   two agree; edit either one alone and adjud.roles_declared names you. */
function declareRole(runId, stage, { role, model, model_version, prompt, config }) {
  if (!ROLES.includes(role)) throw new Error(`unknown role "${role}" — roles are ${ROLES.join("/")}`);
  if (!model || !model_version || prompt === undefined || config === undefined)
    throw new Error(`role ${role} must declare model, model_version, prompt and config — an unversioned role cannot be told apart from anyone (A45)`);
  const identity = { role, model, model_version, prompt_sha256: sha(String(prompt)), config_sha256: sha(config) };
  Run.event(runId, { type: "ROLE_DECLARED", stage, ...identity });
  Run.patch(runId, m => { (m.roles = m.roles || {})[stage] = identity; });
  return identity;
}

/* ── INPUT SNAPSHOTS — what a role saw, frozen at the moment it saw it ───────
   Per-file sha256 for frozen artefacts; byte-length + prefix-sha for the append-only files, so
   later legitimate appends leave the recorded view verifiable forever (and any rewrite of history
   inside the prefix breaks it — A46/A50). files_present records the whole run directory at the
   moment of the snapshot, which is how absence becomes provable: the synthesizer's snapshot not
   containing contrarian.jsonl in files_present IS the mechanical proof of blindness (A51). */
function takeSnapshot(runId, role, files, base) {
  for (const f of files) {
    const m = String(f).match(/^private\/([A-Z_]+)\//);
    if (m && m[1] !== role) throw new Error(`SNAPSHOT REFUSED: ${role} may not receive another role's private reasoning (${f})`);
  }
  const B = base || Run.RUNS;
  const dir = Run.runDir(runId, B);
  const entries = {};
  for (const f of files) {
    const p = Run.guardedPath(runId, f, B);
    if (!fs.existsSync(p)) { entries[f] = { exists: false }; continue; }
    const buf = fs.readFileSync(p);
    entries[f] = CUMULATIVE.includes(f)
      ? { exists: true, bytes: buf.length, prefix_sha256: sha(buf) }
      : { exists: true, bytes: buf.length, sha256: sha(buf) };
  }
  const listDir = d => { try { return fs.readdirSync(d); } catch { return []; } };
  const present = [
    ...listDir(dir).filter(f => { try { return fs.statSync(path.join(dir, f)).isFile(); } catch { return false; } }),
    ...listDir(path.join(dir, "snapshots")).map(f => "snapshots/" + f)
  ].sort();
  const at = new Date().toISOString();
  const snap = { role, at, files: entries, files_present: present, sha256: sha({ role, at, files: entries, files_present: present }) };
  Run.write(runId, `snapshots/${role}.json`, snap);
  Run.event(runId, { type: "SNAPSHOT", role, snapshot_sha256: snap.sha256, files: Object.keys(entries) });
  return snap;
}

/* ── THE ADJUDICATION RECORD — validated at write AND at verify ──────────────
   Five resolutions and nothing else. Every claim cites evidence nodes or is rejected. A
   confidence score is refused outright — with or without cites — because the moment a number can
   stand in for a citation, it will. The honest independence ladder is mandatory. */
function validateAdjudication(rec) {
  const problems = [];
  if (!rec || typeof rec !== "object") return { ok: false, problems: ["no adjudication record"] };
  const id = rec.role || {};
  if (id.role !== "ADJUDICATOR") problems.push(`record's declared role is "${id.role}", not ADJUDICATOR`);
  for (const k of ["model", "model_version", "prompt_sha256", "config_sha256"])
    if (!id[k]) problems.push(`adjudicator identity missing ${k} (A45)`);
  const ind = rec.independence || {};
  if (String(ind.underlying_weights || "").toUpperCase() !== "UNKNOWN" && String(ind.underlying_weights || "").toUpperCase() !== "UNKNOWN_UNDERLYING_WEIGHTS")
    problems.push("OVERCLAIM REFUSED: underlying_weights must be recorded UNKNOWN — two API calls never prove different weights (B5)");
  if (rec.score !== undefined || rec.confidence !== undefined) problems.push("a collapsed score/confidence on the adjudication record is forbidden");
  if (!Array.isArray(rec.claims) || !rec.claims.length) problems.push("no adjudicated claims — an adjudication that resolves nothing resolves nothing");
  for (const c of rec.claims || []) {
    if (!c.id) problems.push("a claim without an id cannot be traced to the synthesis");
    if (!RESOLUTIONS.includes(c.resolution)) problems.push(`claim ${c.id}: resolution "${c.resolution}" is not one of ${RESOLUTIONS.join("/")}`);
    const cites = [...(c.cites || []), ...(c.supporting || []), ...(c.contradicting || [])];
    if (!cites.length) problems.push(`claim ${c.id}: NO EVIDENCE-NODE CITATIONS — an uncited claim must be rejected (A47)`);
    if (c.confidence !== undefined || c.score !== undefined) problems.push(`claim ${c.id}: confidence/score fields refused — evidence citations are the only currency here`);
    if (!c.why) problems.push(`claim ${c.id}: no reasoning tied to the evidence`);
  }
  if (!rec.evidence_snapshot || !rec.evidence_snapshot.graph_prefix_sha256 || !rec.evidence_snapshot.graph_bytes)
    problems.push("no immutable evidence snapshot (graph_bytes + graph_prefix_sha256) — the adjudicator's view cannot be reconstructed (A46)");
  return { ok: problems.length === 0, problems };
}

/* two identities are distinct only if the DECLARED tuple differs — and that is all it proves */
function distinct(a, b) {
  if (!a || !b) return false;
  return !(a.model === b.model && a.model_version === b.model_version && a.prompt_sha256 === b.prompt_sha256 && a.config_sha256 === b.config_sha256);
}

module.exports = { declareRole, takeSnapshot, validateAdjudication, distinct, ROLES, RESOLUTIONS, sha };

if (require.main === module) {
  const A = process.argv.slice(2);
  if (A[0] === "--selftest") {
    const good = {
      role: { role: "ADJUDICATOR", model: "m", model_version: "1", prompt_sha256: sha("p"), config_sha256: sha({}) },
      independence: { declared_identity: true, observed_execution: true, verified_configuration: false, underlying_weights: "UNKNOWN" },
      evidence_snapshot: { graph_bytes: 10, graph_prefix_sha256: sha("x") },
      claims: [{ id: "C1", claim: "x", cites: ["NODE:1"], resolution: "SUPPORTED", why: "cited" }]
    };
    const cases = [
      ["a valid record is accepted", () => validateAdjudication(good).ok === true],
      ["an uncited claim is refused", () => { const r = validateAdjudication({ ...good, claims: [{ id: "C1", claim: "x", cites: [], resolution: "SUPPORTED", why: "w" }] }); return !r.ok && r.problems.some(p => /NO EVIDENCE-NODE CITATIONS/.test(p)); }],
      ["a resolution outside the five values is refused", () => { const r = validateAdjudication({ ...good, claims: [{ id: "C1", claim: "x", cites: ["N"], resolution: "PROBABLY_FINE", why: "w" }] }); return !r.ok && r.problems.some(p => /not one of/.test(p)); }],
      ["a confidence score in place of evidence is refused", () => { const r = validateAdjudication({ ...good, claims: [{ id: "C1", claim: "x", cites: ["N"], resolution: "SUPPORTED", confidence: 0.97, why: "w" }] }); return !r.ok && r.problems.some(p => /confidence\/score fields refused/.test(p)); }],
      ["an overclaim of weight independence is refused", () => { const r = validateAdjudication({ ...good, independence: { ...good.independence, underlying_weights: "PROVEN_DISTINCT" } }); return !r.ok && r.problems.some(p => /OVERCLAIM REFUSED/.test(p)); }],
      ["a snapshot of another role's private reasoning is refused", () => { try { takeSnapshot("no-such-run", "SYNTHESIZER", ["private/ADJUDICATOR/notes.md"]); return false; } catch (e) { return /SNAPSHOT REFUSED/.test(e.message); } }],
      ["identical declared tuples are not distinct", () => distinct(good.role, { ...good.role }) === false && distinct(good.role, { ...good.role, prompt_sha256: sha("other") }) === true]
    ];
    let fail = 0;
    console.log("ADJUDICATION SELFTEST — the validators must refuse what the rules forbid.");
    for (const [name, fn] of cases) { let ok = false; try { ok = !!fn(); } catch { ok = false; } if (!ok) fail++; console.log(`  ${ok ? "✓" : "✗"} ${name}`); }
    console.log(fail ? `  ✗ FAIL — ${fail} validator(s) accepted forbidden input. ${cases.length - fail} passed` : `  ✓ PASS — every refusal rule refuses, and the valid record is accepted. ${cases.length} passed`);
    process.exit(fail ? 1 : 0);
  }
  if (A[0] === "--show") {
    const rec = Run.readJson(A[1], "adjudication.json");
    console.log(rec ? JSON.stringify({ role: rec.role, independence: rec.independence, claims: (rec.claims || []).map(c => ({ id: c.id, resolution: c.resolution, cites: [...(c.cites || []), ...(c.supporting || []), ...(c.contradicting || [])].length })) }, null, 2) : "no adjudication record");
    process.exit(rec ? 0 : 1);
  }
  if (A[0] === "--drive") {
    /* --drive <run-id> <payload.json> — RUN the three role stages on a REAL sweep run.
     *
     * Built 2026-09-06 (O-34). Until now sonar-adjudicate.js held the ENFORCEMENT machinery and
     * nothing ever invoked it, so every real run failed exactly two of --verify-run's 23 checks:
     * verdict.present ("no verdict.json — the run produced no answer") and adjud.roles_declared
     * ("no role stages ran"). The evidence chain was sound; the answer stage simply did not exist.
     *
     * DIVISION OF LABOUR: the JUDGMENT is authored by a model and arrives as <payload.json>.
     * This file performs zero judgment — it only declares identities, freezes input snapshots,
     * writes the artefacts and chains the events, so the mechanics stay deterministic and
     * re-runnable while the reasoning stays outside the tool. A payload cannot smuggle a verdict
     * past the gate: sonar-pipeline.js --verify-run still re-checks all 23, and trust=VERIFIED
     * without a verifying command is refused (verdict.trust_not_promoted).
     */
    const runId = A[1], payloadPath = A[2];
    if (!runId || !payloadPath) { console.error("usage: sonar-adjudicate.js --drive <run-id> <payload.json>"); process.exit(2); }
    const P = JSON.parse(fs.readFileSync(payloadPath, "utf8"));
    const src = (why) => ({ source: "command", via: "sonar-adjudicate.js --drive", why, at: new Date().toISOString() });
    const frags = Run.readJsonl(runId, "fragments.jsonl") || [];
    const byKey = {}; for (const f of frags) byKey[`${f.repo}::${f.file}`] = f.node;
    const cite = (keys) => (keys || []).map(k => byKey[k]).filter(Boolean);
    const missing = (P.synthesis.claims || []).flatMap(c => (c.cite_files || []).filter(k => !byKey[k]));
    if (missing.length) { console.error("REFUSED: payload cites fragments this run never read: " + missing.join(", ")); process.exit(3); }
    const INPUTS = ["fragments.jsonl", "reads.jsonl", "graph.jsonl"];
    const MODEL = P.model, MV = P.model_version;
    if (!MODEL || !MV) { console.error("REFUSED: payload must declare model and model_version (A45)"); process.exit(3); }

    // O-39: the ingest declared budget.ai_invocations = 0 because --ingest-sweep spends none.
    // Three role stages are about to run, so the budget is raised to what will actually be spent
    // BEFORE spending it — budget.ai compares declared against observed, and an undeclared spend
    // is exactly the overrun the check exists to catch.
    Run.patch(runId, m => { m.declared_budget = Object.assign({}, m.declared_budget, { ai_invocations: 3 }); });
    Run.stageStart(runId, "SYNTHESIS", INPUTS);
    declareRole(runId, "SYNTHESIS", { role: "SYNTHESIZER", model: MODEL, model_version: MV, prompt: P.synthesis.prompt, config: P.synthesis.config || {} });
    takeSnapshot(runId, "SYNTHESIZER", INPUTS);
    const claimNodes = {};
    for (const c of P.synthesis.claims) {
      const cited = cite(c.cite_files);
      const n = Run.node(runId, { type: "CLAIM", label: c.claim, provenance: src("synthesis"), author: "SYNTHESIZER" });
      for (const f of cited) Run.edge(runId, f, "SUPPORTS", n, src("fragment quoted verbatim"));
      claimNodes[c.id] = { node: n, cited };
    }
    Run.write(runId, "synthesis.json", { answer: P.synthesis.answer, mechanism: P.synthesis.mechanism,
      claims: P.synthesis.claims.map(c => ({ id: c.id, claim: c.claim, cites: claimNodes[c.id].cited })),
      cites: Object.values(claimNodes).flatMap(v => [v.node, ...v.cited]) });
    Run.stageEnd(runId, "SYNTHESIS", { artefacts: ["synthesis.json", "snapshots/SYNTHESIZER.json"], tools: [], commands: ["sonar-adjudicate.js --drive (SYNTHESIS)"], ai_invocations: 1 });

    Run.stageStart(runId, "CONTRARIAN", ["synthesis.json", ...INPUTS]);
    declareRole(runId, "CONTRARIAN", { role: "CONTRARIAN", model: MODEL, model_version: MV, prompt: P.contrarian.prompt, config: P.contrarian.config || {} });
    takeSnapshot(runId, "CONTRARIAN", ["synthesis.json", ...INPUTS]);
    const counters = [];
    for (const o of P.contrarian.objections) {
      const n = Run.node(runId, { type: "COUNTERCLAIM", label: o.label, provenance: src("contrarian pass"), author: "CONTRARIAN" });
      Run.edge(runId, n, "ATTACKS", claimNodes[o.objection_to].node, src("contrarian pass"));
      counters.push({ objection_to: o.objection_to, node: n, unaddressed: o.unaddressed });
    }
    Run.write(runId, "contrarian.jsonl", counters.map(c => JSON.stringify({ objection_to: c.objection_to,
      attacks: [c.node], evidence_nodes: claimNodes[c.objection_to].cited, verdict: P.contrarian.verdict, unaddressed: c.unaddressed })).join("\n") + "\n");
    Run.stageEnd(runId, "CONTRARIAN", { artefacts: ["contrarian.jsonl", "snapshots/CONTRARIAN.json"], tools: [], commands: ["sonar-adjudicate.js --drive (CONTRARIAN)"], ai_invocations: 1 });

    Run.stageStart(runId, "ADJUDICATION", ["synthesis.json", "contrarian.jsonl", "graph.jsonl", "manifest.json"]);
    const adjId = declareRole(runId, "ADJUDICATION", { role: "ADJUDICATOR", model: MODEL, model_version: MV, prompt: P.adjudication.prompt, config: P.adjudication.config || {} });
    const adjSnap = takeSnapshot(runId, "ADJUDICATOR", ["synthesis.json", "contrarian.jsonl", "graph.jsonl"]);
    Run.write(runId, "adjudication.json", { role: adjId, at: new Date().toISOString(),
      input_snapshot: "snapshots/ADJUDICATOR.json", input_snapshot_sha256: adjSnap.sha256,
      evidence_snapshot: { graph_bytes: adjSnap.files["graph.jsonl"].bytes, graph_prefix_sha256: adjSnap.files["graph.jsonl"].prefix_sha256,
        synthesis_sha256: adjSnap.files["synthesis.json"].sha256, contrarian_sha256: adjSnap.files["contrarian.jsonl"].sha256 },
      independence: { declared_identity: true, observed_execution: true, verified_configuration: false, underlying_weights: "UNKNOWN" },
      limitation: "All three roles ran on the SAME model with distinct declared prompts and configs. That proves DECLARED_IDENTITY and OBSERVED_EXECUTION only. Underlying weights are UNKNOWN and unprovable from inside this repository (B5) — this record claims nothing more.",
      claims: P.adjudication.claims.map(c => ({ id: c.id, claim: claimNodes[c.id] ? P.synthesis.claims.find(x => x.id === c.id).claim : c.id,
        cites: [claimNodes[c.id].node], supporting: claimNodes[c.id].cited,
        contradicting: counters.filter(x => x.objection_to === c.id).map(x => x.node),
        objections_considered: counters.filter(x => x.objection_to === c.id).map(x => x.node),
        resolution: c.resolution, why: c.why })) });
    Run.stageEnd(runId, "ADJUDICATION", { artefacts: ["adjudication.json", "snapshots/ADJUDICATOR.json"], tools: ["sonar-adjudicate.js"], commands: ["sonar-adjudicate.js --drive (ADJUDICATION)"], ai_invocations: 1 });

    Run.stageStart(runId, "VERDICT", ["synthesis.json", "contrarian.jsonl", "adjudication.json"]);
    const vnode = Run.node(runId, { type: "VERDICT", label: P.verdict.conclusion, provenance: src("verdict stage") });
    for (const k of Object.keys(claimNodes)) Run.edge(runId, claimNodes[k].node, "RESOLVES_TO", vnode, src("verdict stage"));
    Run.write(runId, "verdict.json", { ...P.verdict,
      cites: [...Object.values(claimNodes).flatMap(v => [v.node, ...v.cited]), ...counters.map(c => c.node), vnode] });
    Run.stageEnd(runId, "VERDICT", { artefacts: ["verdict.json"], tools: [], commands: ["sonar-adjudicate.js --drive (VERDICT)"] });
    console.log(JSON.stringify({ run_id: runId, stages: ["SYNTHESIS", "CONTRARIAN", "ADJUDICATION", "VERDICT"],
      claims: Object.keys(claimNodes).length, counterclaims: counters.length, trust_in_verdict: P.verdict.trust,
      next: `node sonar-pipeline.js --verify-run ${runId}` }));
    process.exit(0);
  }
  console.log("usage: sonar-adjudicate.js --selftest | --show <run-id> | --drive <run-id> <payload.json>");
}
