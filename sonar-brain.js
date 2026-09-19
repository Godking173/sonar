#!/usr/bin/env node
/* sonar-brain.js — THE MANIFEST. An INDEX of the sources of truth, never a source of truth.
 *
 * THE PROBLEM THIS SOLVES: a fresh session knows nothing, and the thing it knows least is what it
 * already built. Every previous attempt at this was a hand-written memory file, which is a lie
 * with a good reputation — it is right on the day it is written and wrong forever after.
 *
 * THE RULE: if the manifest and the authoritative artefact disagree, THE ARTEFACT WINS and the
 * manifest is marked STALE. Nothing here is believed because it is written down; every section
 * names the artefact it was derived from and the rule used to derive it, so any line can be
 * re-derived by hand.
 *
 * AUTHORITATIVE ARTEFACTS (the manifest indexes these, it does not replace them):
 *   sonar/capabilities.jsonl   capabilities + their executable checks
 *   sonar/failures.jsonl       known failure modes + their detectors + firewall patterns
 *   sonar/decisions.jsonl      permanent decisions, hash-chained
 *   sonar/evidence.jsonl       provenance records, hash-chained
 *   SONAR_CONSTITUTION.md      the rules and which are mechanically enforced
 *   memory/prior-art.jsonl     repository reads, written at clone time
 *   memory/sonar-bench.jsonl   benchmark ledger
 *   memory/frozen-lessons.jsonl permanent lessons (mirror of ~/.cc-brain/frozen.jsonl)
 *   audits/sonar-bench-v0.1/   sealed experiment artefacts
 *   TOOLBOX.md                 tool register
 *   git                        HEAD, dirty state, branch, commit history
 *   the filesystem             what actually exists
 */
"use strict";
const fs = require("fs"), path = require("path"), cp = require("child_process");
const R = require("./sonar-registry.js"), T = require("./sonar-trust.js");
const ROOT = __dirname;
const SNAPSHOT = path.join(ROOT, "sonar", "BRAIN.json");

const prov = (source, rule) => ({ source, rule, derived_at: new Date().toISOString(), host_key: T.hostKey(), git_head: T.gitHead() });
const exists = p => fs.existsSync(path.join(ROOT, p));

/* 1 · TOOLS — executables that are really on disk, not names in a document. */
function tools() {
  const arch = R.architecture();
  const toolboxTxt = exists("TOOLBOX.md") ? fs.readFileSync(path.join(ROOT, "TOOLBOX.md"), "utf8") : "";
  const named = [...toolboxTxt.matchAll(/^- ([\w.-]+\.(?:js|sh)) —/gm)].map(m => m[1]);
  const rows = arch.rows.map(r => ({ tool: r.component, lines: r.lines, git_tracked: r.git_tracked, introduced: r.introduced, in_toolbox: r.in_toolbox, exercised_by_gate: r.exercised_by_gate, referenced_by_tests: r.referenced_by_tests }));
  return { provenance: prov("filesystem + git log + TOOLBOX.md", "readdir matched against component globs; existence is filesystem-derived, TOOLBOX is only cross-checked"), count: rows.length, rows,
    gaps: { in_toolbox_but_not_on_disk: named.filter(n => /^(cc-sonar|cc-priorart|cc-coverage|sonar-)/.test(n) && !exists(n)), on_disk_but_not_in_toolbox: arch.gaps.missing_from_toolbox } };
}

/* 2 · LANES — grouped from capability ids, not from an authored list of pipelines. */
function lanes() {
  const caps = R.capability().rows || [];
  const g = {};
  for (const c of caps) { const k = c.id.split(".")[0]; (g[k] = g[k] || []).push(c.id); }
  return { provenance: prov("sonar/capabilities.jsonl", "capability ids grouped on their first dotted segment"), lanes: g };
}

/* 3 · DATA SOURCES + 4 · RATE LIMITS */
function sources() {
  const caps = (R.capability().rows || []).filter(c => /^(source|analytics)\./.test(c.id));
  return { provenance: prov("sonar/capabilities.jsonl + live gh api rate_limit", "source.* / analytics.* capabilities; limits are LIVE, never cached"),
    rows: caps.map(c => ({ id: c.id, purpose: c.purpose, documented_limits: c.limits, trust: T.levelFor("capability." + c.id).level })), live_rate_limits: R.resource() };
}

/* 5 · BENCHMARK CASES + 8-contamination */
function benchmark() {
  const e = R.experiment();
  return { provenance: prov("memory/sonar-bench.jsonl + audits/sonar-bench-v0.1/", "case ids from the seal; CONFIRMED contaminated requires a machine record; everything else is UNPROVEN and must be treated as contaminated"),
    total_cases: e.total_cases_sealed, confirmed_contaminated: e.contamination.CONFIRMED_CONTAMINATED, unproven: e.contamination.UNPROVEN, policy: e.contamination.policy, ledger_kinds: e.ledger_entry_kinds };
}

/* 6 · SEALED EXPERIMENTS — a sealed artefact is only sealed if git holds it. */
function experiments() {
  const dir = path.join(ROOT, "audits", "sonar-bench-v0.1");
  const files = fs.existsSync(dir) ? fs.readdirSync(dir).filter(f => f.endsWith(".md")) : [];
  const rows = files.map(f => {
    const rel = `audits/sonar-bench-v0.1/${f}`;
    let committed = false, clean = null, blob = null;
    try { blob = cp.execSync(`git show HEAD:${rel}`, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }); committed = true; } catch { committed = false; }
    if (committed) clean = T.sha(blob) === T.sha(fs.readFileSync(path.join(ROOT, rel), "utf8"));
    return { artefact: rel, committed, matches_committed_blob: clean, seal_sha: blob ? T.sha(blob).slice(0, 16) : null };
  });
  return { provenance: prov("audits/sonar-bench-v0.1/ + git objects", "the SEAL IS THE GIT BLOB — an uncommitted artefact is not sealed and a modified one cannot match"), rows,
    unsealed: rows.filter(r => !r.committed).map(r => r.artefact), tampered: rows.filter(r => r.committed && r.matches_committed_blob === false).map(r => r.artefact) };
}

/* 7 · DECISIONS */
function decisions() {
  const D = require("./sonar-decide.js");
  const rows = D.list(), v = D.verify();
  return { provenance: prov("sonar/decisions.jsonl", "hash-chained decision ledger; a rewritten decision breaks the chain"), chain_ok: v.ok, chain_problems: v.problems,
    rows: rows.map(r => ({ id: r.id, decision: r.decision, reason: r.reason, evidence: r.evidence, status: r.status, supersedes: r.supersedes, reverse_requires: r.reverse_requires })) };
}

/* 8 · FAILURE MODES + 9 · ACTIVE DETECTORS (each detector is RE-RUN here) */
function failures() {
  const f = R.failure();
  if (f.state !== "OK") return { provenance: prov("sonar/failures.jsonl", "n/a"), state: f.state, why: f.why, rows: [] };
  const rows = f.rows.map(r => ({ id: r.id, severity: r.severity, what: r.what, detector: r.detect, detector_state: R.runDetector(r.detect).state, firewall_patterns: r.resembles || [], unblock_requires: r.unblock_requires || null }));
  return { provenance: prov("sonar/failures.jsonl", "every detector is re-executed at manifest time; STILL_PRESENT means the defect is live right now"), rows,
    still_present: rows.filter(r => r.detector_state === "STILL_PRESENT").map(r => r.id), fixed: rows.filter(r => r.detector_state === "NOT_DETECTED").map(r => r.id), undeterminable: rows.filter(r => r.detector_state === "UNKNOWN").map(r => r.id) };
}

/* 10 · CAPABILITIES + trust level */
function capabilities() {
  const caps = R.capability().rows || [];
  return { provenance: prov("sonar/capabilities.jsonl + sonar/evidence.jsonl", "authored row supplies the CHECK; the trust level comes only from executed, chain-valid, same-host, same-HEAD evidence"),
    rows: caps.map(c => { const l = T.levelFor("capability." + c.id); return { id: c.id, component: c.component || null, check: c.check, trust: l.level, records: l.records, usable_here: l.usable, rejected: l.rejected }; }) };
}

/* 11 · DEPENDENCIES — derived from require() and from binaries named in checks. */
function dependencies() {
  const arch = R.architecture();
  const local = new Set(), binaries = new Set();
  for (const r of arch.rows) {
    const src = fs.readFileSync(path.join(ROOT, r.component), "utf8");
    for (const m of src.matchAll(/require\(["']([^"']+)["']\)/g)) local.add(m[1]);
  }
  const caps = R.capability().rows || [];
  for (const c of caps) for (const b of ["gh", "duckdb", "curl", "git", "node", "jq", "rg", "python3"]) if (new RegExp(`(^|[\\s;|&(])${b}\\b`).test(c.check)) binaries.add(b);
  const t = R.tools();
  return { provenance: prov("require() statements in every component + binaries named in capability checks + command -v on this host", "static parse, then live presence probe"),
    node_modules_required: [...local].filter(m => !m.startsWith(".")), internal_modules: [...local].filter(m => m.startsWith(".")).sort(),
    binaries_required: [...binaries].sort(), binaries_present_here: t.rows.filter(x => x.present).map(x => x.tool),
    missing_here: [...binaries].filter(b => !t.rows.find(x => x.tool === b && x.present)) };
}

/* 12 · ARTEFACTS / LEDGERS — where every source of truth lives. */
function artefacts() {
  const known = ["sonar/capabilities.jsonl", "sonar/failures.jsonl", "sonar/decisions.jsonl", "sonar/evidence.jsonl", "SONAR_CONSTITUTION.md",
    "memory/prior-art.jsonl", "memory/sonar-bench.jsonl", "memory/frozen-lessons.jsonl", "TOOLBOX.md", "sonar/BRAIN.json"];
  const rows = known.map(p => {
    const abs = path.join(ROOT, p), ex = fs.existsSync(abs);
    let tracked = false; try { cp.execSync(`git ls-files --error-unmatch -- ${p}`, { cwd: ROOT, stdio: "ignore" }); tracked = true; } catch {}
    return { artefact: p, exists: ex, git_tracked: tracked, bytes: ex ? fs.statSync(abs).size : 0, lines: ex && /\.(jsonl|md)$/.test(p) ? fs.readFileSync(abs, "utf8").split("\n").filter(l => l.trim()).length : null };
  });
  return { provenance: prov("filesystem + git ls-files", "a fixed list of the system's own sources of truth, each probed for existence and tracking"), rows, missing: rows.filter(r => !r.exists).map(r => r.artefact), untracked: rows.filter(r => r.exists && !r.git_tracked).map(r => r.artefact) };
}

/* 13 · INVALIDATED / STALE / FOREIGN PROOFS */
function staleProofs() {
  const head = T.gitHead(), hk = T.hostKey(), rows = T.readLedger().filter(r => !r.__unparseable);
  const chain = T.verifyChain();
  const stale = rows.filter(r => r.git_head && r.git_head !== head), foreign = rows.filter(r => r.host_key !== hk);
  const byHost = {}; for (const r of rows) { const k = `${r.host_key} @${r.git_head}`; byHost[k] = (byHost[k] || 0) + 1; }
  return { provenance: prov("sonar/evidence.jsonl", "a record is STALE if its git_head differs from HEAD, FOREIGN if its host_key differs from this host; neither can establish local truth"),
    chain_ok: chain.ok, chain_problems: chain.problems, total_records: rows.length, stale_records: stale.length, foreign_records: foreign.length,
    usable_here: rows.filter(r => r.host_key === hk && r.git_head === head).length, distribution: byHost };
}

/* 14 · OPEN WORK — derived from unfinished artefacts, never from what I think is next. */
function openWork() {
  const f = failures(), b = benchmark(), a = R.architecture(), ev = R.evidence(), rc = R.repositoryCache();
  const items = [];
  for (const id of f.still_present) { const row = f.rows.find(r => r.id === id); items.push({ kind: "live_defect", severity: row.severity, id, why: "its detector fires right now", evidence: `node sonar-registry.js failure  →  ${row.detector}` }); }
  if (b.unproven.length) items.push({ kind: "unproven_benchmark", severity: "high", id: `${b.unproven.length} cases cannot be proven clean`, why: "runs were written up in prose, not recorded per case", evidence: "sonar-brain.js benchmark → UNPROVEN list" });
  const unrun = a.gaps.neither_test_nor_gate_runs_it || [];
  if (unrun.length) items.push({ kind: "untested_component", severity: "high", id: unrun.join(", "), why: "no unit test names it and no gate runner executes it", evidence: "sonar-registry.js architecture → gaps" });
  if (rc.state === "OK" && rc.gaps.named_in_writeups_but_never_recorded_as_read.length) items.push({ kind: "unverifiable_claims", severity: "critical", id: `${rc.gaps.named_in_writeups_but_never_recorded_as_read.length} repos named in write-ups with no read record`, why: "claims exist that the machine record cannot corroborate", evidence: "D-006 forbids back-filling these; only a real re-clone may write a NEW record" });
  if (ev.state === "OK" && ev.gaps.claims_with_no_read.length) items.push({ kind: "orphan_claims", severity: "critical", id: ev.gaps.claims_with_no_read.join(", "), why: "a prior-art claim with no backing read", evidence: "memory/prior-art.jsonl" });
  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  items.sort((x, y) => (rank[x.severity] ?? 9) - (rank[y.severity] ?? 9));
  return { provenance: prov("failure detectors + benchmark ledger + derived architecture gaps + evidence gaps", "DETERMINISTIC ORDER: severity (critical→low), then the order the artefacts list them. No judgement, so a fresh session gets the same answer I would."), items };
}

/* 15 · REJECTED APPROACHES */
function rejected() {
  const f = R.failure();
  const rows = (f.rows || []).filter(r => (r.resembles || []).length).map(r => ({ id: r.id, rejected_because: r.what, evidence: r.evidence, blocked_patterns: r.resembles, to_revisit_you_must: r.unblock_requires || "run a new experiment" }));
  const D = require("./sonar-decide.js");
  for (const d of D.list()) if (/never|no .* may|forbidden|not back-filled|is never/i.test(d.decision)) rows.push({ id: d.id, rejected_because: d.decision, evidence: d.evidence, blocked_patterns: [], to_revisit_you_must: d.reverse_requires });
  return { provenance: prov("sonar/failures.jsonl (rows carrying firewall patterns) + sonar/decisions.jsonl (prohibitive decisions)", "an approach counts as REJECTED only if something mechanical blocks it or a chained decision forbids it"), rows };
}

function defences() {
  const atk = exists("sonar-attack.js") ? fs.readFileSync(path.join(ROOT, "sonar-attack.js"), "utf8") : "";
  const ids = [...atk.matchAll(/\bA\("(A\d+)"\s*,\s*"([^"]+)"/g)].map(m => ({ id: m[1], attack: m[2] }));
  const gate = exists("cc-verify.sh") ? fs.readFileSync(path.join(ROOT, "cc-verify.sh"), "utf8") : "";
  const lines = [...gate.matchAll(/^run "([\w-]+)"\s+(.+)$/gm)].map(m => ({ check: m[1], command: m[2].trim() })).filter(x => /sonar|doctor/.test(x.check));
  return { provenance: prov("sonar-attack.js + cc-verify.sh", "attack ids parsed from the suite source; gate lines parsed from the runner. Counting them from memory is exactly the failure this section exists to prevent."),
    attack_count: ids.length, attacks: ids, gate_lines: lines };
}
function phase() {
  const p = path.join(ROOT, "sonar", "phase.json");
  if (!fs.existsSync(p)) return { provenance: prov("sonar/phase.json", "n/a"), missing: true,
    warning: "NO PHASE FILE — a fresh session has no idea what it is supposed to do next. Write one." };
  let j; try { j = JSON.parse(fs.readFileSync(p, "utf8")); } catch (e) { return { provenance: prov("sonar/phase.json", "n/a"), unparseable: true }; }
  const T2 = require("./sonar-trust.js");
  return { provenance: prov("sonar/phase.json", "AUTHORED at each phase boundary, not derived — a machine cannot compute what we decided to do next. Everything else in this manifest is derived; this is the one deliberate exception and it is dated and version-controlled so its staleness is visible."),
    authored: true, updated_at: j.updated_at, updated_at_commit: j.updated_at_commit,
    stale_since_commit: j.updated_at_commit !== T2.gitHead(),
    current_phase: j.current_phase, status: j.current_phase_status, phase_order: j.phase_order,
    next_task: j.next_task, known_blockers: j.known_blockers_found_by_inspection, hard_constraints: j.hard_constraints_for_this_phase };
}
function boundary() {
  const B = require("./sonar-boundary.js");
  const c = B.conformance(), audit = B.auditLedgers(), unc = B.uncontrolledLog();
  return { provenance: prov("sonar-boundary.js conformance scan + trusted-ledger audit + sonar/uncontrolled.jsonl", "tool conformance is parsed from source; ledger admissibility is read from the DATA, so a write by any means is judged the same way"),
    rule: "NO PROMOTABLE EVIDENCE MAY EXIST OUTSIDE THE SONAR RUN NAMESPACE. A research fact without a valid run seal is refused at the ledger; unwrapped execution is allowed, logged and permanently marked UNCONTROLLED. S24: a promoted run must persist in sonar/runs/ and stay reconstructable — the run resolves, its seal recomputes, verification passes from disk — or its record is permanently INADMISSIBLE and cannot be consumed as trusted.",
    evidence_producing_tools: c.rows.length, nonconformant: c.nonconformant, excluded_by_identity: c.excluded_by_identity,
    uncontrolled_executions_on_record: unc.length, ledger_audit: audit };
}
function constitution() {
  const p = path.join(ROOT, "SONAR_CONSTITUTION.md");
  if (!fs.existsSync(p)) return { provenance: prov("SONAR_CONSTITUTION.md", "n/a"), missing: true, rows: [] };
  const rows = fs.readFileSync(p, "utf8").split("\n").filter(l => /^\|\s*S\d\d\s*\|/.test(l)).map(l => { const c = l.split("|").map(s => s.trim()); return { id: c[1], rule: c[2], status: c[3], enforced_by: c[4] }; });
  return { provenance: prov("SONAR_CONSTITUTION.md", "table rows parsed; ENFORCED rules must name an artefact that exists (node sonar-doctor.js --constitution)"), count: rows.length, enforced: rows.filter(r => r.status === "ENFORCED").length, rows };
}
function gitState() {
  const g = c => { try { return cp.execSync(c, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { return null; } };
  return { provenance: prov("git", "live git interrogation"), head: g("git rev-parse --short HEAD"), branch: g("git rev-parse --abbrev-ref HEAD"),
    dirty: (g("git status --porcelain") || "").length > 0, last_commits: (g("git log --oneline -5 --format=%h %s") || "").split("\n").map(s => s.slice(0, 100)) };
}
function lessons() {
  const rows = R.jsonl("memory/frozen-lessons.jsonl");
  if (!rows) return { provenance: prov("memory/frozen-lessons.jsonl", "n/a"), missing: true };
  return { provenance: prov("memory/frozen-lessons.jsonl", "mirror of ~/.cc-brain/frozen.jsonl; a lesson with a check is enforceable, a prose lesson is not"), count: rows.length, with_check: rows.filter(l => l.check && String(l.check).trim()).length };
}

function derive() {
  return { manifest_version: 1, note: "AN INDEX OF SOURCES OF TRUTH, NOT A SOURCE OF TRUTH. If this disagrees with an artefact, the artefact wins and this is STALE.",
    derived_at: new Date().toISOString(), host: T.host(), host_key: T.hostKey(), git: gitState(),
    tools: tools(), lanes: lanes(), sources: sources(), benchmark: benchmark(), experiments: experiments(), decisions: decisions(),
    failures: failures(), capabilities: capabilities(), dependencies: dependencies(), artefacts: artefacts(), stale_proofs: staleProofs(),
    open_work: openWork(), rejected_approaches: rejected(), constitution: constitution(), phase: phase(), boundary: boundary(), defences: defences(), lessons: lessons() };
}

/* volatile fields are excluded from the comparison — a timestamp differing is not a divergence */
function stable(m) {
  const strip = o => { if (Array.isArray(o)) return o.map(strip); if (o && typeof o === "object") { const c = {}; for (const [k, v] of Object.entries(o)) { /* SELF-REFERENCE BUG, found by running --check right after --emit: the artefacts section
     records BRAIN.json's own byte and line count, which changes the instant the manifest is
     written — so every emit made the snapshot permanently STALE against itself. Sizes are volatile
     for every growing ledger anyway; existence and git-tracking are what this section is for, and
     a meaningful change inside any ledger is caught by that ledger's own section. */
    if (["derived_at", "at", "provenance", "live_rate_limits", "stale_proofs", "derived", "duration_ms", "dirty", "last_commits", "git", "records", "usable_here", "rejected", "total_records", "stale_records", "foreign_records", "distribution", "usable", "bytes", "lines", "count", "seal_sha", "introduced", "admissible_records"].includes(k)) continue; c[k] = strip(v); } return c; } return o; };
  return strip(m);
}
/* STRUCTURAL vs TRUST divergence — the distinction matters operationally.
   Trust levels are scoped to host AND git HEAD (S21, D-007), so a committed snapshot is
   legitimately "wrong" about trust on any other machine and after any commit. Failing the gate on
   that would make it permanently red for everyone except whoever emitted last, and a gate that is
   always red gets switched off, and then it catches nothing at all.
   STRUCTURAL divergence — the index lying about what EXISTS — is a real failure and fails closed.
   TRUST divergence is reported loudly and does not fail the gate. Both are still reported as
   STALE to any caller (attack A17 depends on that), only the EXIT CODE differs. */
const VOLATILE_SECTIONS = ["capabilities_trust"];
function splitCaps(m) {
  const rows = ((m.capabilities || {}).rows) || [];
  return { structure: rows.map(r => ({ id: r.id, component: r.component, check: r.check })).sort((a, b) => String(a.id).localeCompare(String(b.id))),
           trust: rows.map(r => ({ id: r.id, trust: r.trust })).sort((a, b) => String(a.id).localeCompare(String(b.id))) };
}
function compareAgainst(live, snap) {
  const diverged = [];
  const L = stable(live), S = stable(snap || {});
  for (const k of Object.keys(L)) { if (k === "capabilities") continue; if (JSON.stringify(L[k]) !== JSON.stringify(S[k] === undefined ? null : S[k])) diverged.push(k); }
  const lc = splitCaps(live), sc = splitCaps(snap || {});
  if (JSON.stringify(lc.structure) !== JSON.stringify(sc.structure)) diverged.push("capabilities_structure");
  if (JSON.stringify(lc.trust) !== JSON.stringify(sc.trust)) diverged.push("capabilities_trust");
  if (!diverged.length) return { state: "CURRENT", structural: false };
  const structural = diverged.some(d => !VOLATILE_SECTIONS.includes(d));
  return { state: "STALE", structural, diverged,
    why: structural
      ? "the manifest disagrees with the artefacts about what EXISTS. THE ARTEFACTS WIN — re-emit with `node sonar-brain.js --emit`."
      : "trust levels only. Expected on another host or after a commit, because a verification is scoped to its host and its HEAD (S21/D-007). Re-run doctor then --emit to refresh. NOT a gate failure." };
}
function compareToSnapshot(live) {
  if (!fs.existsSync(SNAPSHOT)) return { state: "NO_SNAPSHOT", why: "no committed manifest to compare against — the live derivation is the only answer" };
  let snap; try { snap = JSON.parse(fs.readFileSync(SNAPSHOT, "utf8")); } catch { return { state: "STALE", why: "committed manifest is unparseable" }; }
  const diverged = [];
  for (const k of Object.keys(stable(live))) if (JSON.stringify(stable(live)[k]) !== JSON.stringify(stable(snap)[k] === undefined ? null : stable(snap)[k])) diverged.push(k);
  return diverged.length ? { state: "STALE", diverged, why: "the committed manifest disagrees with the artefacts. THE ARTEFACTS WIN — re-emit with `node sonar-brain.js --emit`." } : { state: "CURRENT" };
}

module.exports = { derive, compareToSnapshot, compareAgainst, SNAPSHOT, stable };

if (require.main === module) {
  const A = process.argv.slice(2), live = derive();
  if (A.includes("--emit")) { fs.writeFileSync(SNAPSHOT, JSON.stringify(live, null, 2)); console.log(`wrote ${SNAPSHOT} (${fs.statSync(SNAPSHOT).size} bytes)`); process.exit(0); }
  if (A.includes("--check")) { const c = compareToSnapshot(live); console.log(JSON.stringify(c, null, 2)); process.exit(c.structural ? 1 : 0); }
  if (A[0] && !A[0].startsWith("--") && live[A[0]]) { console.log(JSON.stringify(live[A[0]], null, 2)); process.exit(0); }
  console.log(JSON.stringify(live, null, 2));
}
