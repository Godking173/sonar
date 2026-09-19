#!/usr/bin/env node
/* sonar-boundary.js — THE MANDATORY EXECUTION BOUNDARY.
 *
 * THE HOLE THIS CLOSES, stated plainly because I found it and reported it myself: the pipeline
 * contract only bound a stage that chose to call sonar-run. cc-priorart.js wrote
 * memory/prior-art.jsonl directly at clone time, and sonar-trust.attest() accepted any caller.
 * A constitution that an agent may opt out of is documentation, not control.
 *
 * WHAT IS AND IS NOT POSSIBLE — no overclaiming. I cannot stop a process with shell access from
 * executing a binary; no file in this repository can. So the boundary is NOT on execution. It is
 * on ADMISSION. Running a tool by hand stays possible, and stays useful for debugging. What is
 * impossible is for the result to become trusted evidence.
 *
 * THE MECHANISM: a trusted research record must carry a RUN SEAL. The seal is a hash over the run's
 * immutable state — manifest core, event-chain head, every stage artefact hash, verdict hash,
 * sealed-artefact hashes before and after. It is validated by RECOMPUTING it from the run on disk
 * and by re-running the full pipeline verification at admission time. There is no secret to steal
 * and no signature to forge, because the seal is not a credential: it is a summary of work. The
 * only way to produce a valid seal is to have actually done the run. Forging the seal and doing the
 * work are the same act.
 *
 * UNCONTROLLED EXECUTION is allowed, recorded, and permanently marked. A tool that runs outside a
 * run writes to <ledger>.uncontrolled.jsonl, stamps every record controlled:false, and appends to
 * sonar/uncontrolled.jsonl. Those records can never be imported: promotion rejects any run whose
 * artefacts carry controlled:false or an origin outside the run.
 *
 * Usage: --conformance | --uncontrolled | --seal <run-id> | --explain
 */
"use strict";
const fs = require("fs"), path = require("path"), crypto = require("crypto");
const ROOT = __dirname;
const sha = s => crypto.createHash("sha256").update(typeof s === "string" ? s : JSON.stringify(s)).digest("hex");
const UNCONTROLLED = path.join(ROOT, "sonar", "uncontrolled.jsonl");

/* Fact namespaces. CONTROL facts are the control plane verifying ITSELF — they are produced by
   doctor re-executing checks about this repository and require no run. RESEARCH facts are claims
   about the outside world and require one. Anything unrecognised is treated as RESEARCH: fail closed. */
const CONTROL_NS = [/^capability\./, /^control\./, /^attack\./];
const RESEARCH_NS = [/^priorart\./, /^discovery\./, /^benchmark\./, /^finding\./, /^history\./, /^relevance\./, /^repo\./];
function classifyFact(fact) {
  if (CONTROL_NS.some(r => r.test(fact))) return "CONTROL";
  if (RESEARCH_NS.some(r => r.test(fact))) return "RESEARCH";
  return "RESEARCH";                                  // unknown namespace → the stricter path
}

/* ── THE SEAL ─────────────────────────────────────────────────────────────────
   A summary of work, not a credential. Recomputable by anyone; producible only by doing the run. */
function computeSeal(runId, base) {
  const Run = require("./sonar-run.js");
  const at = base || Run.RUNS;
  const m = Run.manifest(runId, at);
  if (!m) return null;
  const events = Run.readJsonl(runId, "events.jsonl", at);
  const verdict = Run.readJson(runId, "verdict.json", at);
  const artefacts = {};
  for (const [stage, s] of Object.entries(m.stages || {})) for (const a of s.artefacts || []) {
    const p = path.join(Run.runDir(runId, at), a);
    artefacts[`${stage}:${a}`] = fs.existsSync(p) ? sha(fs.readFileSync(p)) : null;
  }
  return sha({
    run_id: m.run_id, git_head: m.git_head, host_key: m.host_key, problem_hash: m.problem_hash,
    events_head: events.length ? events[events.length - 1].sha : null, events_count: events.length,
    artefacts, verdict_sha: verdict ? sha(verdict) : null,
    sealed_before: m.sealed_before, sealed_after: m.sealed_after
  });
}

/* ── ADMISSION ────────────────────────────────────────────────────────────────
   Everything is re-derived here. A verification.json written earlier proves nothing on its own;
   the run is re-verified at the moment of admission. */
function validateSeal(runSeal) {
  if (!runSeal || !runSeal.run_id || !runSeal.seal) return { ok: false, why: "no run seal — a research fact must name the run that produced it" };
  const Run = require("./sonar-run.js"), P = require("./sonar-pipeline.js"), T = require("./sonar-trust.js");
  /* S24 — DURABILITY IS PART OF ADMISSION. A relocated namespace means the run under judgment is
     ephemeral by construction; admitting it mints a durable record about a run that dies with its
     process. That exact sequence produced defect.promoted-run-not-persisted. Fail closed here so
     NO caller — promotion or otherwise — can admit research evidence from a temp namespace. */
  if (path.resolve(Run.RUNS) !== Run.CANONICAL_RUNS)
    return { ok: false, why: "runs namespace is relocated (SONAR_RUNS_DIR) — an ephemeral run cannot mint durable trusted evidence (S24)" };
  const m = Run.manifest(runSeal.run_id);
  if (!m) return { ok: false, why: `run ${runSeal.run_id} does not exist` };
  if (m.quarantined) return { ok: false, why: `run ${runSeal.run_id} is QUARANTINED and is permanently non-promotable: ${m.quarantine_reason}` };
  const events = Run.readJsonl(runSeal.run_id, "events.jsonl");
  const bad = events.filter(e => ["ISOLATION_VIOLATION", "UNCONTROLLED_EXECUTION", "BYPASS_ATTEMPT", "QUARANTINE"].includes(e.type));
  if (bad.length) return { ok: false, why: `run contains ${bad.length} boundary event(s): ${[...new Set(bad.map(b => b.type))].join(", ")} — permanently non-promotable` };
  if (m.git_head !== T.gitHead()) return { ok: false, why: `run was produced at ${m.git_head}, HEAD is now ${T.gitHead()}` };
  if (m.host_key !== T.hostKey()) return { ok: false, why: `run was produced on ${m.host_key}, this host is ${T.hostKey()}` };
  const recomputed = computeSeal(runSeal.run_id);
  if (recomputed !== runSeal.seal) return { ok: false, why: "SEAL MISMATCH — the run's state does not hash to the presented seal" };
  const v = P.verifyRun(runSeal.run_id);
  if (!v.ok) return { ok: false, why: `run fails verification at admission time: ${v.failed_checks.join(", ")}` };
  return { ok: true, run_id: runSeal.run_id, checks: v.total };
}

/* ── QUARANTINE — sticky, and doubly enforced. The flag lives in the manifest AND as an event in
   the hash chain, so removing the flag leaves the event and removing the event breaks the chain. */
function quarantine(runId, reason) {
  const Run = require("./sonar-run.js");
  try { Run.event(runId, { type: "QUARANTINE", reason }); } catch { }
  try { Run.patch(runId, m => { m.quarantined = true; m.quarantine_reason = reason; m.trust_state = "UNCONTROLLED"; }); } catch { }
  return { quarantined: true, reason };
}

/* ── ENTERING A STAGE ─────────────────────────────────────────────────────────
   Controlled if SONAR_RUN_ID names a live run. Otherwise the tool still runs — debugging is not a
   crime — but everything it produces is stamped, diverted and logged. */
function enter(stage, opts = {}) {
  const runId = process.env.SONAR_RUN_ID || null;
  const Run = require("./sonar-run.js");
  let m = null; try { m = runId ? Run.manifest(runId) : null; } catch { m = null; }
  if (runId && m && !m.quarantined) {
    try { Run.event(runId, { type: "BOUNDARY_ENTER", stage, tool: opts.tool || path.basename(process.argv[1] || "unknown") }); } catch { }
    return { controlled: true, run_id: runId, stage, mark: o => ({ ...o, controlled: true, run_id: runId, stage }), ledger: k => trustedLedger(k, true) };
  }
  const rec = { type: "UNCONTROLLED_EXECUTION", stage, tool: opts.tool || path.basename(process.argv[1] || "unknown"),
    argv: process.argv.slice(2).join(" ").slice(0, 200), reason: runId ? (m ? "run is quarantined" : `SONAR_RUN_ID=${runId} names no run`) : "no SONAR_RUN_ID — executed outside the pipeline",
    at: new Date().toISOString(), cwd: process.cwd() };
  logUncontrolled(rec);
  if (runId && m) quarantine(runId, `uncontrolled execution of ${rec.tool} at stage ${stage}`);
  return { controlled: false, run_id: null, stage, reason: rec.reason,
    mark: o => ({ ...o, controlled: false, uncontrolled_reason: rec.reason, uncontrolled_at: rec.at }),
    ledger: k => trustedLedger(k, false) };
}
function trustedLedger(kind, controlled) {
  const MAP = { priorart: path.join(ROOT, "memory", "prior-art.jsonl"), bench: path.join(ROOT, "memory", "sonar-bench.jsonl"), evidence: path.join(ROOT, "sonar", "evidence.jsonl") };
  const p = MAP[kind]; if (!p) throw new Error(`unknown trusted ledger "${kind}"`);
  return controlled ? p : p.replace(/\.jsonl$/, ".uncontrolled.jsonl");
}
function logUncontrolled(rec) {
  try {
    fs.mkdirSync(path.dirname(UNCONTROLLED), { recursive: true });
    const rows = fs.existsSync(UNCONTROLLED) ? fs.readFileSync(UNCONTROLLED, "utf8").split("\n").filter(l => l.trim()).map(l => JSON.parse(l)) : [];
    const T = require("./sonar-trust.js");
    const r = { ...rec, host_key: T.hostKey(), git_head: T.gitHead(), prev: rows.length ? rows[rows.length - 1].sha : "GENESIS" };
    r.sha = T.recordHash(r);
    fs.appendFileSync(UNCONTROLLED, JSON.stringify(r) + "\n");
  } catch { }
}
const uncontrolledLog = () => fs.existsSync(UNCONTROLLED) ? fs.readFileSync(UNCONTROLLED, "utf8").split("\n").filter(l => l.trim()).map(l => JSON.parse(l)) : [];

/* ── CONFORMANCE — derived from disk, so a NEW unwrapped tool fails the gate rather than relying on
   anyone remembering to wire it. A tool is evidence-producing if it calls gh, clones, or writes a
   trusted ledger. Every such tool must require this module and call enter(). */
function conformance() {
  /* PRECISE RULES, tightened after the first scan flagged eleven files by mere mention.
     api-evidence  : `gh search <noun>` or `gh api repos/` — calls that return OUTSIDE-WORLD content.
                     `gh api rate_limit` is a control probe about our own quota and is NOT evidence.
     read-evidence : a clone of a REMOTE url. A synthetic clone command recorded as a string in the
                     control case is not a clone.
     ledger-write  : an actual appendFileSync into a RESEARCH ledger (prior-art / sonar-bench /
                     evidence). decisions.jsonl is an operator ledger, not research evidence.
     sonar-trust.js and sonar-boundary.js are excluded by identity: they ARE the admission point,
     and a gatekeeper cannot be required to present its own ticket. */
  const EXCLUDE = ["sonar-boundary.js", "sonar-trust.js"];
  const files = fs.readdirSync(ROOT).filter(f => /\.js$/.test(f) && !/-test\.js$/.test(f) && !EXCLUDE.includes(f));
  const rows = [];
  for (const f of files) {
    const src = fs.readFileSync(path.join(ROOT, f), "utf8");
    const produces = [];
    if (/gh search (repos|code|issues|prs|commits)/.test(src) || /gh api repos\//.test(src)) produces.push("api-evidence");
    if (/git clone[^"'`\n]*https:\/\//.test(src)) produces.push("read-evidence");
    /* a name is not a target: sonar-decide.js also appends to a constant called LEDGER, but its
       LEDGER is decisions.jsonl — an operator ledger, not research evidence. Resolve the constant. */
    const researchLedger = /const\s+(LEDGER|PRIORART)\s*=[^;\n]*(prior-art|sonar-bench|sonar["'`,\s)]*,?\s*["'`]?evidence)\.jsonl/.test(src);
    if (researchLedger && /appendFileSync\(\s*(LEDGER|PRIORART)\b/.test(src)) produces.push("ledger-write");
    else if (/appendFileSync\([^)\n]*(prior-art|sonar-bench)\.jsonl/.test(src)) produces.push("ledger-write");
    else if (/\.ledger\(["'](priorart|bench|evidence)["']\)/.test(src)) produces.push("ledger-write-via-boundary");
    if (!produces.length) continue;
    const requires = /require\(["']\.\/sonar-boundary\.js["']\)/.test(src);
    const enters = /\.enter\(|BOUNDARY_CTX\(/.test(src);
    rows.push({ tool: f, produces, requires_boundary: requires, calls_enter: enters, conformant: requires && enters });
  }
  return { rows, nonconformant: rows.filter(r => !r.conformant).map(r => r.tool), excluded_by_identity: EXCLUDE };
}


/* ── S24: DURABLE ADMISSIBILITY ──────────────────────────────────────────────
   The original audit checked that a research record NAMED a run. That is how the one promoted
   record in this ledger stayed "admissible" after its run — built in a mkdtemp namespace by the
   positive control — had ceased to exist: chain intact, seal unrecomputable forever, an orphan
   claim in exactly the shape this system exists to detect (defect.promoted-run-not-persisted).
   Admissibility now means the run RESOLVES:
     1. the run's manifest exists in the CANONICAL namespace (sonar/runs/<id>/) — or, for a
        fixture probe, in the explicitly supplied base;
     2. the run is not quarantined and carries no boundary events;
     3. when the record carries a seal, recomputing from disk reproduces it EXACTLY;
     4. unless opts.verify === false, the persisted run passes full pipeline verification NOW;
     5. when opts.requireTracked, the run must be git-tracked — a run that exists only in a
        working tree is one revert away from becoming the same orphan again.
   D-006 governs the scar this defect left: the orphaned record is never deleted, rewritten or
   back-filled. It stays in the chain, permanently INADMISSIBLE. */
function checkRunEvidence(rec, opts = {}) {
  const Run = require("./sonar-run.js"), cp = require("child_process");
  const base = opts.base || Run.CANONICAL_RUNS;
  const rid = rec.run_id || (rec.run_seal && rec.run_seal.run_id);
  if (!(rec.controlled === true) || !rid)
    return { ok: false, cls: "LEGACY", why: "no controlled origin and no run_id — predates the boundary or was written outside it" };
  const m = Run.manifest(rid, base);
  if (!m) {
    const inGit = (() => { try { cp.execSync(`git cat-file -e HEAD:sonar/runs/${rid}/manifest.json`, { cwd: ROOT, stdio: "ignore" }); return true; } catch { return false; } })();
    return inGit
      ? { ok: false, cls: "RUN_MISSING_RECOVERABLE", why: `run ${rid} is committed at HEAD but missing from the working tree — restore it (git checkout -- sonar/runs/${rid})` }
      : { ok: false, cls: "RUN_MISSING_PERMANENT", why: `run ${rid} does not resolve on disk and was never committed — its seal can never be recomputed; permanently inadmissible, never back-filled (D-006/S24)` };
  }
  const events = Run.readJsonl(rid, "events.jsonl", base);
  const badEv = events.filter(e => ["ISOLATION_VIOLATION", "UNCONTROLLED_EXECUTION", "BYPASS_ATTEMPT", "QUARANTINE"].includes(e.type));
  if (m.quarantined || badEv.length)
    return { ok: false, cls: "BOUNDARY", why: m.quarantined ? `run ${rid} is quarantined: ${m.quarantine_reason}` : `run ${rid} carries ${badEv.length} boundary event(s)` };
  if (rec.run_seal && rec.run_seal.seal) {
    const now = computeSeal(rid, base);
    if (now !== rec.run_seal.seal)
      return { ok: false, cls: "SEAL_MISMATCH", why: `run ${rid} no longer hashes to the recorded seal — the persisted run was altered after promotion` };
  }
  let checks = null;
  if (opts.verify !== false) {
    const v = require("./sonar-pipeline.js").verifyRun(rid, base);
    if (!v.ok) return { ok: false, cls: "VERIFY_FAILED", why: `run ${rid} fails pipeline verification from disk: ${v.failed_checks.join(", ")}` };
    checks = v.total;
  }
  let tracked = null;
  if (opts.requireTracked) {
    try { cp.execSync(`git ls-files --error-unmatch -- sonar/runs/${rid}/manifest.json`, { cwd: ROOT, stdio: "ignore" }); tracked = true; } catch { tracked = false; }
    if (!tracked) return { ok: true, cls: "UNTRACKED", tracked: false, checks, why: `run ${rid} resolves and verifies but is NOT git-tracked — commit sonar/runs/${rid} or the next revert recreates the orphan` };
  }
  return { ok: true, cls: "OK", tracked, checks };
}

function auditLedgers() {
  const T = require("./sonar-trust.js");
  const targets = [
    { kind: "priorart", file: path.join(ROOT, "memory", "prior-art.jsonl"), research: r => r.kind === "read" || r.kind === "claim" },
    { kind: "evidence", file: path.join(ROOT, "sonar", "evidence.jsonl"), research: r => classifyFact(r.fact || "") === "RESEARCH" }
  ];
  const out = [];
  for (const t of targets) {
    if (!fs.existsSync(t.file)) { out.push({ ledger: t.kind, missing: true }); continue; }
    const rows = fs.readFileSync(t.file, "utf8").split("\n").filter(l => l.trim()).map((l, i) => { try { const o = JSON.parse(l); o.__line = i + 1; return o; } catch { return { __line: i + 1, __bad: true }; } });
    const research = rows.filter(r => !r.__bad && t.research(r));
    const admissible = [], inadmissible = [];
    for (const r of research) {
      const rid = r.run_id || (r.run_seal && r.run_seal.run_id);
      if (r.controlled === true && rid) {
        /* S24: NAMED is not RESOLVED — the run must exist, re-hash to its seal, and re-verify. */
        const chk = checkRunEvidence(r, { requireTracked: true });
        if (chk.ok) admissible.push({ line: r.__line, run_id: rid, cls: chk.cls, tracked: chk.tracked !== false, checks: chk.checks || null });
        else inadmissible.push({ line: r.__line, run_id: rid, cls: chk.cls, why: chk.why, ref: r.repo || r.fact });
      }
      else inadmissible.push({ line: r.__line, cls: r.controlled === false ? "UNCONTROLLED" : "LEGACY", why: r.controlled === false ? "explicitly marked uncontrolled" : "no controlled origin and no run_id — predates the boundary or was written outside it", ref: r.repo || r.fact });
    }
    out.push({ ledger: t.kind, file: path.relative(ROOT, t.file), total: rows.length, research: research.length, admissible: admissible.length, admissible_records: admissible, inadmissible });
  }
  return out;
}
module.exports = { auditLedgers, checkRunEvidence, classifyFact, computeSeal, validateSeal, enter, quarantine, trustedLedger, conformance, uncontrolledLog, UNCONTROLLED, CONTROL_NS, RESEARCH_NS };

if (require.main === module) {
  const A = process.argv.slice(2);
  if (A[0] === "--conformance") {
    const c = conformance();
    console.log("EVIDENCE-PRODUCING TOOLS — every one must enter the boundary:");
    for (const r of c.rows) console.log(`  ${r.conformant ? "✓" : "✗"} ${r.tool.padEnd(26)} produces:[${r.produces.join(",")}]  requires=${r.requires_boundary} enters=${r.calls_enter}`);
    console.log(c.nonconformant.length ? `  ✗ NON-CONFORMANT: ${c.nonconformant.join(", ")} — these can produce evidence without entering the boundary` : `  ✓ all ${c.rows.length} evidence-producing tools enter the boundary`);
    process.exit(c.nonconformant.length ? 1 : 0);
  }
  if (A[0] === "--audit-ledgers") {
    const rows = auditLedgers();
    console.log("TRUSTED LEDGER AUDIT — a research record is admissible only if its run RESOLVES (S24).");
    console.log("This check reads the DATA, not the code: the named run must exist in sonar/runs/,");
    console.log("recompute to its recorded seal, and pass full pipeline verification right now.");
    console.log("A record that merely NAMED a run proved nothing once already — the run had been");
    console.log("built in a temp namespace and was gone (defect.promoted-run-not-persisted).");
    let red = 0;
    for (const r of rows) {
      if (r.missing) { console.log(`  ? ${r.ledger}: file absent`); continue; }
      console.log(`  ${r.inadmissible.length ? "!" : "✓"} ${r.file.padEnd(26)} ${r.research} research record(s) · ${r.admissible} admissible · ${r.inadmissible.length} INADMISSIBLE`);
      for (const x of r.inadmissible) {
        console.log(`      line ${String(x.line).padStart(3)}  [${x.cls || "LEGACY"}] ${String(x.ref || "").padEnd(30)} ${x.why}`);
        if (["RUN_MISSING_RECOVERABLE", "SEAL_MISMATCH", "VERIFY_FAILED", "BOUNDARY"].includes(x.cls)) red++;
      }
      for (const a of r.admissible_records || []) {
        console.log(`      line ${String(a.line).padStart(3)}  [ADMISSIBLE] run ${a.run_id} resolves · seal recomputes · ${a.checks} checks pass · ${a.tracked ? "git-tracked" : "NOT GIT-TRACKED"}`);
        if (!a.tracked) { red++; console.log("      ✗ COMMIT IT — an untracked promoted run is one revert away from re-creating the orphan."); }
      }
    }
    const bad = rows.reduce((a, r) => a + ((r.inadmissible || []).length), 0);
    console.log(bad ? `  → ${bad} record(s) are NOT admissible as evidence. They are marked, not deleted: D-006 forbids back-filling — a record whose run never persisted stays exactly as unproven as it always was.` : "  → every research record has a controlled origin AND a resolvable, verified run.");
    /* Exit contract: LEGACY / UNCONTROLLED / RUN_MISSING_PERMANENT records are facts about
       history — a permanently red gate gets switched off, and then it catches nothing. What DOES
       fail the gate: a promoted run that is recoverable-but-missing, altered after sealing,
       failing verification, quarantined, or not yet committed. Live losses with live remedies. */
    process.exit(red ? 1 : 0);
  }
  if (A[0] === "--uncontrolled") { const l = uncontrolledLog(); for (const r of l) console.log(`${r.at}  ${r.tool.padEnd(24)} ${r.stage.padEnd(12)} ${r.reason}`); console.log(`  ${l.length} uncontrolled execution(s) on record`); process.exit(0); }
  if (A[0] === "--seal") { console.log(computeSeal(A[1]) || "no such run"); process.exit(0); }
  console.log("usage: --conformance | --uncontrolled | --seal <run-id>");
}
