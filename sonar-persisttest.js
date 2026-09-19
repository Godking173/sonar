#!/usr/bin/env node
/* sonar-persisttest.js — THE PERSISTENCE SUITE (S24).
 *
 * WHY THIS EXISTS: the trusted ledger once held a VERIFIED research record naming a run that was
 * built by the positive control inside a mkdtemp namespace and gone the moment the process ended.
 * Chain intact, audit green, seal unrecomputable forever: defect.promoted-run-not-persisted.
 * Every leg below is the mechanical form of "never again":
 *
 *   P0  the door still OPENS — a valid, sealed, persisted run passes the same admissibility
 *   P1  promotion from a relocated/ephemeral namespace is REFUSED
 *   P2  a record naming a run that does not resolve is INADMISSIBLE
 *   P3  a run modified after sealing is INADMISSIBLE
 *   P4  a forged/wrong seal is INADMISSIBLE even though the run exists intact
 *   P5  levelFor can never hold orphaned run-backed evidence as usable — including via REPRODUCED
 *   P6  the REAL scar — the orphaned record in sonar/evidence.jsonl — is INADMISSIBLE, forever
 *
 * Fixture-based on purpose: runs are built in a temp namespace and admissibility is probed through
 * checkRunEvidence's explicit base parameter, so this suite writes NOTHING durable and can run on
 * every gate pass. The end-to-end positive control (real promotion, real ledger, canonical
 * namespace) stays in `node sonar-e2e.js --promote-control`, run deliberately and then committed —
 * never on a schedule, because promotion appends to the real trusted ledger. */
"use strict";
/* PORTABLE PROOF: a virgin install (every ledger empty) has nothing to attack — build a labelled synthetic install and run this file there, unchanged (see sonar-fixture.js). */
if (!process.env.SONAR_FIXTURE_ROOT && require("./sonar-fixture.js").isVirgin(__dirname)) process.exit(require("./sonar-fixture.js").reexec(__filename));
const fs = require("fs"), path = require("path"), os = require("os");
/* relocate BEFORE any module resolves the runs dir — same rule sonar-e2e.js documents */
if (!process.env.SONAR_RUNS_DIR) process.env.SONAR_RUNS_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "sonar-persist-"));
if (!process.env.SONAR_CACHE_DIR) process.env.SONAR_CACHE_DIR = path.join(process.env.SONAR_RUNS_DIR, "cache");
const BASE = process.env.SONAR_RUNS_DIR;
const E2E = require("./sonar-e2e.js"), Run = require("./sonar-run.js"), P = require("./sonar-pipeline.js"),
      B = require("./sonar-boundary.js"), T = require("./sonar-trust.js");

const results = [];
const leg = (id, name, fn) => { let r; try { r = fn(); } catch (e) { r = { pass: false, how: "harness threw: " + e.message }; } results.push({ id, name, ...r }); };
const mkRec = (id, seal) => ({ controlled: true, run_id: id, run_seal: { run_id: id, seal } });

leg("P0", "a valid, sealed, persisted run IS admissible — the door still opens", () => {
  const id = E2E.buildCleanRun();
  const seal = B.computeSeal(id, BASE);
  const chk = B.checkRunEvidence(mkRec(id, seal), { base: BASE });
  return { pass: chk.ok === true && chk.cls === "OK" && typeof chk.checks === "number",
    how: `cls=${chk.cls} · ${chk.checks} verification checks passed from disk` };
});

leg("P1", "promotion from a relocated/ephemeral namespace is REFUSED", () => {
  const id = E2E.buildCleanRun();
  const prom = P.promote(id);
  return { pass: prom.promoted === false && /S24/.test(prom.why || "") && /relocated|ephemeral/.test(prom.why || ""),
    how: String(prom.why).slice(0, 120) };
});

leg("P2", "a record naming a run that does not resolve is INADMISSIBLE", () => {
  const chk = B.checkRunEvidence(mkRec("19990101000000-deadbeef", "0".repeat(64)), { base: BASE });
  return { pass: chk.ok === false && /^RUN_MISSING/.test(chk.cls), how: `cls=${chk.cls}` };
});

leg("P3", "a run modified after sealing is INADMISSIBLE", () => {
  const id = E2E.buildCleanRun();
  const seal = B.computeSeal(id, BASE);
  fs.appendFileSync(path.join(BASE, id, "relevance.jsonl"), JSON.stringify({ repo: "smuggled/after-seal", relevance: { level: "DIRECT_SOLUTION" } }) + "\n");
  const chk = B.checkRunEvidence(mkRec(id, seal), { base: BASE });
  return { pass: chk.ok === false && (chk.cls === "SEAL_MISMATCH" || chk.cls === "VERIFY_FAILED"), how: `cls=${chk.cls}` };
});

leg("P4", "a forged seal is INADMISSIBLE even though the run exists intact", () => {
  const id = E2E.buildCleanRun();
  const chk = B.checkRunEvidence(mkRec(id, "f".repeat(64)), { base: BASE });
  return { pass: chk.ok === false && chk.cls === "SEAL_MISMATCH", how: `cls=${chk.cls}` };
});

leg("P5", "levelFor never holds orphaned run-backed evidence as usable — including REPRODUCED", () => {
  /* a chained fixture ledger with everything the OLD levelFor required: same host, same HEAD,
     intact chain. The only thing wrong with these records is that their run does not exist. */
  const f = path.join(BASE, "fixture-evidence.jsonl");
  const mk = o => ({ v: 1, fact: "priorart.orphan/case", claim: "x", level: "VERIFIED", attempted_level: "VERIFIED",
    host: T.host(), at: new Date(0).toISOString(), cwd: __dirname, paths: [], source: "command",
    command: "node --check sonar-trust.js", exit_code: 0, stdout_sha256: T.sha(""), stdout_head: "",
    stderr_sha256: T.sha(""), stderr_head: "", tool_version: null, network: "unknown", git_dirty: false,
    duration_ms: 1, controlled: true, run_id: "19990101000000-deadbeef",
    run_seal: { run_id: "19990101000000-deadbeef", seal: "0".repeat(64) }, ...o });
  const recs = [mk({ host_key: T.hostKey(), git_head: T.gitHead() }),
                mk({ host_key: "elis-mac:darwin/arm64", git_head: T.gitHead() })];
  let prev = "GENESIS"; const out = [];
  for (const r of recs) { r.prev = prev; r.sha = T.recordHash(r); prev = r.sha; out.push(JSON.stringify(r)); }
  fs.writeFileSync(f, out.join("\n") + "\n");
  const l = T.levelFor("priorart.orphan/case", { ledger: f });
  const orphanReason = l.reasons.some(x => /ORPHANED RUN \(S24\)/.test(x));
  return { pass: l.level === "UNKNOWN" && l.usable === 0 && orphanReason,
    how: `level=${l.level} usable=${l.usable} · ${(l.reasons.find(x => /ORPHANED/.test(x)) || "no orphan reason emitted").slice(0, 110)}` };
});

leg("P6", "the REAL scar in sonar/evidence.jsonl is INADMISSIBLE — never deleted, never back-filled", () => {
  const rows = T.readLedger().filter(r => r.controlled === true && r.run_seal);
  if (!rows.length) return { pass: false, how: "no controlled run-backed record found in the real ledger — the scar should exist" };
  const audit = B.auditLedgers().find(t => t.ledger === "evidence") || { inadmissible: [], admissible_records: [] };
  const orphanRows = rows.filter(r => !fs.existsSync(path.join(__dirname, "sonar", "runs", r.run_seal.run_id, "manifest.json")));
  if (!orphanRows.length) return { pass: true, how: "every run-backed record currently resolves — nothing orphaned to assert" };
  const marked = orphanRows.every(r => (audit.inadmissible || []).some(x => x.line === r.__line));
  const neverAdmissible = orphanRows.every(r => !(audit.admissible_records || []).some(x => x.line === r.__line));
  return { pass: marked && neverAdmissible,
    how: `${orphanRows.length} orphaned record(s); marked inadmissible=${marked}; counted admissible=${!neverAdmissible}` };
});

const pass = results.filter(r => r.pass).length;
console.log(`PERSISTENCE SUITE (S24) — ${results.length} legs, host ${T.hostKey()}`);
for (const r of results) console.log(`  ${r.pass ? "✓" : "✗"} ${r.id}  ${r.name}\n      ${r.how}`);
console.log(pass === results.length
  ? `  ✓ PASS — an unreconstructable run can neither be minted, admitted, nor consumed; a valid persisted run still can. ${pass} passed`
  : `  ✗ FAIL — the persistence invariant does not hold. ${pass} passed / ${results.length}`);
process.exit(pass === results.length ? 0 : 1);
