#!/usr/bin/env node
/* sonar-run.js — RUN NAMESPACE, RUN MANIFEST, EVIDENCE GRAPH, CONTENT CACHE.
 *
 * ISOLATION IS THE POINT. A research run is a guest in this repository. It may write to exactly
 * one place — sonar/runs/<run-id>/ — and nowhere else, ever. Sealed cases, sealed predictions,
 * benchmark rankings, decisions, the constitution, trust history and prior evidence are all
 * outside its reach by construction, not by good intentions. The write guard refuses the path
 * rather than trusting the caller to behave.
 *
 * A run can enter the permanent ledger through ONE door: sonar-pipeline.js --verify-run, and only
 * if every stage contract held. Until then a run is a hypothesis with a directory.
 *
 * A fresh session must be able to reconstruct any run from its manifest with no conversation
 * memory, which is why the manifest records the commands, hashes and rate-limit state rather than
 * conclusions.
 */
"use strict";
const fs = require("fs"), path = require("path"), cp = require("child_process"), crypto = require("crypto");
const T = require("./sonar-trust.js");
const ROOT = __dirname;
/* SONAR_RUNS_DIR exists so the adversarial suite and the end-to-end control case can build, break
   and discard real runs without leaving debris in the repository (this mount cannot delete files,
   so a hundred test runs would be permanent). It relocates the namespace ROOT; it does not weaken
   the guard, which still confines every write to <namespace>/<run-id>/. */
/* THE CANONICAL NAMESPACE (S24). SONAR_RUNS_DIR relocates where a PROCESS builds runs; it can
   never relocate what counts as DURABLE. Promotion, admission and consumption all resolve against
   this path — a run living anywhere else is ephemeral by definition, and an ephemeral run cannot
   back trusted evidence. This constant exists because the one promoted record in this ledger's
   history named a run built in a mkdtemp namespace that evaporated with its process
   (defect.promoted-run-not-persisted). */
const CANONICAL_RUNS = path.join(ROOT, "sonar", "runs");
/* RESOLVED AT EVERY CALL, NEVER AT REQUIRE TIME (defect.runs-namespace-pinned-at-require-time).
   The original `const RUNS = env || canonical` was evaluated once when this module first loaded,
   so ANY transitive require that reached sonar-run before a test harness set SONAR_RUNS_DIR
   silently un-relocated the namespace. The attack suite proved it the day S24 landed: loading
   brain→boundary→run at startup pinned RUNS to the canonical path, sixteen throwaway attack runs
   landed in real sonar/runs/, and promotion suddenly judged them "durable". A getter cannot be
   pinned by load order. */
const RUNS_ = () => process.env.SONAR_RUNS_DIR ? path.resolve(process.env.SONAR_RUNS_DIR) : CANONICAL_RUNS;
const CACHE_ = () => process.env.SONAR_CACHE_DIR ? path.resolve(process.env.SONAR_CACHE_DIR) : path.join(ROOT, "sonar", "cache");
const sha = s => crypto.createHash("sha256").update(typeof s === "string" ? s : JSON.stringify(s)).digest("hex");

/* ── run ids are derived, not random: same problem + same commit + same host = same lineage ──
   The counter suffix keeps two runs of the same problem distinguishable without a clock race. */
function newRunId(problem) {
  const stamp = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
  const h = sha(problem).slice(0, 8);
  let n = 0, id;
  do { id = `${stamp}-${h}${n ? "-" + n : ""}`; n++; } while (fs.existsSync(path.join(RUNS_(), id)));
  return id;
}
const runDir = (id, base = RUNS_()) => path.join(base, id);

/* ── THE WRITE GUARD. Every write in a run goes through here. It resolves the real path and
   refuses anything that escapes the namespace — including ../ traversal and symlink games. */
function guardedPath(id, rel, base = RUNS_()) {
  const rd = path.resolve(runDir(id, base));
  const target = path.resolve(rd, rel);
  if (target !== rd && !target.startsWith(rd + path.sep))
    throw new Error(`ISOLATION VIOLATION: run ${id} attempted to write outside its namespace → ${rel}`);
  return target;
}
/* A BLOCKED BREACH IS STILL A BREACH. Found by attack A27: the guard correctly refused a write
   outside the namespace and threw — and then the run verified clean and was PROMOTED, because
   nothing recorded the attempt. A stage that tried to escape its namespace is not trustworthy just
   because it failed. Every violation is now written into the run's own event chain before the
   throw, and the verifier refuses any run that contains one. */
function violation(id, rel, err) {
  try {
    const p = path.join(runDir(id), "events.jsonl");
    fs.mkdirSync(path.dirname(p), { recursive: true });
    const rows = fs.existsSync(p) ? fs.readFileSync(p, "utf8").split("\n").filter(l => l.trim()).map(l => JSON.parse(l)) : [];
    const rec = { type: "ISOLATION_VIOLATION", attempted_path: rel, error: String(err.message || err), at: new Date().toISOString(), host_key: T.hostKey(), git_head: T.gitHead(), prev: rows.length ? rows[rows.length - 1].sha : "GENESIS" };
    rec.sha = T.recordHash(rec);
    fs.appendFileSync(p, JSON.stringify(rec) + "\n");
    const mf = path.join(runDir(id), "manifest.json");
    if (fs.existsSync(mf)) { const m = JSON.parse(fs.readFileSync(mf, "utf8")); (m.failures = m.failures || []).push(`ISOLATION_VIOLATION: ${rel}`); m.trust_state = "UNKNOWN"; fs.writeFileSync(mf, JSON.stringify(m, null, 2)); }
  } catch { /* recording must never mask the original refusal */ }
}
function write(id, rel, data) {
  let p; try { p = guardedPath(id, rel); } catch (e) { violation(id, rel, e); throw e; }
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, typeof data === "string" ? data : JSON.stringify(data, null, 2));
  return p;
}
function append(id, rel, obj) {
  let p; try { p = guardedPath(id, rel); } catch (e) { violation(id, rel, e); throw e; }
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.appendFileSync(p, JSON.stringify(obj) + "\n");
  return p;
}
const readJson = (id, rel, base = RUNS_()) => { const p = guardedPath(id, rel, base); return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : null; };
const readJsonl = (id, rel, base = RUNS_()) => { const p = guardedPath(id, rel, base); return fs.existsSync(p) ? fs.readFileSync(p, "utf8").split("\n").filter(l => l.trim()).map(l => JSON.parse(l)) : []; };

/* ── SEALED ARTEFACTS: hashed before and after every run. Not a promise — a measurement. ── */
const SEALED_GLOBS = ["audits/sonar-bench-v0.1", "sonar/decisions.jsonl", "SONAR_CONSTITUTION.md", "memory/sonar-bench.jsonl", "sonar/failures.jsonl"];
function sealedHashes() {
  const out = {};
  for (const g of SEALED_GLOBS) {
    const abs = path.join(ROOT, g);
    if (!fs.existsSync(abs)) { out[g] = null; continue; }
    if (fs.statSync(abs).isDirectory()) for (const f of fs.readdirSync(abs)) { const p = `${g}/${f}`; out[p] = sha(fs.readFileSync(path.join(ROOT, p))); }
    else out[g] = sha(fs.readFileSync(abs));
  }
  return out;
}

/* ── CONTENT CACHE, keyed by immutable identity only (S19). A cache hit is NEVER reported as
   fresh: the record says which it was, and the pipeline verifier checks that it did. ── */
function cacheKey(kind, identity) {
  if (!/^(repo_commit|blob|query|api_response)$/.test(kind)) throw new Error(`cache kind must be an immutable identity, got "${kind}"`);
  return `${kind}-${sha(identity)}`;
}
function cacheGet(kind, identity) {
  const f = path.join(CACHE_(), cacheKey(kind, identity) + ".json");
  if (!fs.existsSync(f)) return null;
  const v = JSON.parse(fs.readFileSync(f, "utf8"));
  return { ...v, from_cache: true };
}
function cachePut(kind, identity, value) {
  fs.mkdirSync(CACHE_(), { recursive: true });
  const rec = { kind, identity_sha: sha(identity), stored_at: new Date().toISOString(), host_key: T.hostKey(), value_sha: sha(value), value };
  fs.writeFileSync(path.join(CACHE_(), cacheKey(kind, identity) + ".json"), JSON.stringify(rec, null, 2));
  return { ...rec, from_cache: false };
}

/* ── EVIDENCE GRAPH. Not a score. A trail you can walk backwards from any verdict. ── */
const NODE_TYPES = ["PROBLEM", "CONCEPT", "QUERY", "REPOSITORY", "FILE", "FRAGMENT", "COMMIT", "ISSUE", "PR", "EVENT", "CLAIM", "COUNTERCLAIM", "VERDICT"];
function node(id, { type, label, provenance, ...rest }) {
  if (!NODE_TYPES.includes(type)) throw new Error(`unknown node type ${type}`);
  if (!provenance || !provenance.source) throw new Error(`node ${type}/${label} has no provenance.source — every node must say where it came from`);
  const n = { kind: "node", id: `${type}:${sha(String(label)).slice(0, 12)}`, type, label, provenance, ...rest };
  append(id, "graph.jsonl", n);
  return n.id;
}
function edge(id, from, rel, to, provenance) {
  if (!provenance || !provenance.source) throw new Error(`edge ${from} -${rel}-> ${to} has no provenance`);
  append(id, "graph.jsonl", { kind: "edge", from, rel, to, provenance });
}
function graph(id, base = RUNS_()) {
  const rows = readJsonl(id, "graph.jsonl", base);
  return { nodes: rows.filter(r => r.kind === "node"), edges: rows.filter(r => r.kind === "edge") };
}

/* ── the manifest and its event chain ── */
function begin(problem, opts = {}) {
  const id = newRunId(problem);
  fs.mkdirSync(runDir(id), { recursive: true });
  const m = {
    run_id: id, created_at: new Date().toISOString(),
    git_head: T.gitHead(), git_dirty: (() => { try { return cp.execSync("git status --porcelain", { cwd: ROOT, encoding: "utf8" }).trim().length > 0; } catch { return null; } })(),
    host: T.host(), host_key: T.hostKey(),
    problem_statement: problem, problem_hash: sha(problem),
    model: opts.model || null, model_hash: opts.model ? sha(JSON.stringify(opts.model)) : null,
    discovery_config: opts.discovery_config || null,
    source_versions: opts.source_versions || {},
    rate_limit_at_start: opts.rate_limit || T.run("gh api rate_limit").exit === 0 ? "recorded" : "UNKNOWN (gh unavailable on this host)",
    declared_budget: opts.budget || { api_calls: 40, ai_invocations: 3 },
    sealed_before: sealedHashes(),
    stages: {}, tools_invoked: [], commands: [], failures: [], api_calls: 0, ai_invocations: 0,
    verdict: null, trust_state: "UNKNOWN", promoted: false
  };
  write(id, "manifest.json", m);
  event(id, { type: "RUN_BEGIN", run_id: id, problem_hash: m.problem_hash, git_head: m.git_head, host_key: m.host_key });
  return id;
}
function manifest(id, base = RUNS_()) { return readJson(id, "manifest.json", base); }
function patch(id, fn) { const m = manifest(id); fn(m); write(id, "manifest.json", m); return m; }
function event(id, obj) {
  const rows = readJsonl(id, "events.jsonl");
  const prev = rows.length ? rows[rows.length - 1].sha : "GENESIS";
  const rec = { ...obj, at: new Date().toISOString(), host_key: T.hostKey(), git_head: T.gitHead(), prev };
  rec.sha = T.recordHash(rec);
  append(id, "events.jsonl", rec);
  return rec;
}
/* every stage entry and exit is an event; artefacts are hashed at exit so a later edit is visible */
function stageStart(id, stage, inputs) { event(id, { type: "STAGE_START", stage, inputs }); patch(id, m => { m.stages[stage] = { started: new Date().toISOString(), status: "RUNNING" }; }); }
function stageEnd(id, stage, { artefacts = [], tools = [], commands = [], api_calls = 0, ai_invocations = 0, cache_hits = 0, failures = [] } = {}) {
  const hashes = {};
  for (const a of artefacts) { const p = guardedPath(id, a); hashes[a] = fs.existsSync(p) ? sha(fs.readFileSync(p)) : null; }
  event(id, { type: "STAGE_END", stage, artefact_hashes: hashes, tools, commands, api_calls, ai_invocations, cache_hits, failures });
  patch(id, m => {
    m.stages[stage] = { ...m.stages[stage], ended: new Date().toISOString(), status: failures.length ? "FAILED" : "OK", artefacts, artefact_hashes: hashes, tools, commands, api_calls, ai_invocations, cache_hits, failures };
    m.tools_invoked.push(...tools); m.commands.push(...commands);
    m.api_calls += api_calls; m.ai_invocations += ai_invocations; m.failures.push(...failures);
  });
}
function finish(id) { return patch(id, m => { m.sealed_after = sealedHashes(); m.finished_at = new Date().toISOString(); }); }
function list() { const R = RUNS_(); return fs.existsSync(R) ? fs.readdirSync(R).filter(d => fs.existsSync(path.join(R, d, "manifest.json"))).sort() : []; }

module.exports = { newRunId, runDir, guardedPath, write, append, readJson, readJsonl, begin, manifest, patch, event, stageStart, stageEnd, finish, list, graph, node, edge, sealedHashes, cacheGet, cachePut, cacheKey, sha, NODE_TYPES, CANONICAL_RUNS };
/* RUNS / CACHE stay exported for every existing caller, but as LIVE GETTERS — the value tracks
   the environment at the moment of access, so no consumer can hold a stale pin. */
Object.defineProperty(module.exports, "RUNS", { enumerable: true, get: RUNS_ });
Object.defineProperty(module.exports, "CACHE", { enumerable: true, get: CACHE_ });

if (require.main === module) {
  const A = process.argv.slice(2);
  if (A[0] === "--list") { for (const r of list()) { const m = manifest(r); console.log(`${r}  ${m.trust_state.padEnd(10)} promoted=${m.promoted}  ${String(m.problem_statement).slice(0, 60)}`); } process.exit(0); }
  if (A[0] === "--show") { console.log(JSON.stringify({ manifest: manifest(A[1]), graph: graph(A[1]), events: readJsonl(A[1], "events.jsonl").length }, null, 2)); process.exit(0); }
  if (A[0] === "--ingest-sweep") {
    // V3.9 (2026-09-06) — THE BRIDGE. A sweep's machine-readable artefact (server.py writes
    // <artefact>.json beside the markdown) becomes a real run in the namespace: DISCOVERY nodes
    // for every shown repository (provenance = the angles that found it + rank per angle),
    // DEEP_READ FRAGMENT nodes for every evidence-packet file, each carrying an EXPLICIT
    // evidence_state and an in-toto-style subject digest (sha256 of the fragment text —
    // adapted from in-toto/attestation's Statement.subject.digest, surfaced by Sonar itself
    // on 2026-09-06 with file evidence). States are DETERMINISTIC and never upgraded here:
    //   SURFACED            shown, no packet (candidate only)
    //   SURFACED_NAME_ONLY  packet ran, code search found no file with the term
    //   FETCHED_READ        packet has a file + fragment (the machine read it)
    //   MECHANISM_CANDIDATE fragment is source code carrying an implementation token
    //   NO_MECHANISM        fragment is prose/markdown mentioning the term
    // MECHANISM_VERIFIED / ADMISSIBLE are NOT minted here: verification is the pipeline's
    // VERIFICATION stage and admission is `sonar-pipeline.js --promote` — the one door (D-010).
    // trust_state stays UNKNOWN and promoted stays false, by construction.
    /* O-48: the provenance label above deliberately does NOT contain the literal command string.
       sonar-boundary.js::conformance() classifies any file matching /gh search (repos|code|...)/ as
       an api-evidence PRODUCER and then requires it to enter the boundary. --ingest-sweep calls no
       API at all — it reads an artefact the sweep already produced — so the old label
       (which named the gh code-search command verbatim) made this file look like an evidence
       producer it is not — and note the joke the machine played: the FIRST version of THIS comment
       re-tripped the scanner by quoting the pattern it was explaining. A scanner that matches source
       text matches comments too. Describe the command; never spell it. That left
       conformance non-conformant 1, and that single count was the whole reason attack A42 read
       UNDETECTED (its pass condition is refused && contracts===10 && tools>=6 && nonconformant===0;
       the REFUSAL always held). The label is now both accurate and inert. */
    const src = A[1]; if (!src || !fs.existsSync(src)) { console.error("usage: sonar-run.js --ingest-sweep <sweep-artefact.json>"); process.exit(2); }
    const sw = JSON.parse(fs.readFileSync(src, "utf8"));
    if (sw.FAILED) { console.error("REFUSED: a FAILED sweep is a failure, not evidence (F7)"); process.exit(3); }
    const problem = String(sw.original || sw.problem || "");
    const id = begin(problem, { model: { kind: "sonar_sweep", sweep: sw.sweep, ranking: sw.ranking, query_sent: sw.query_sent, limit: sw.limit, min_stars: sw.min_stars, expansion_gate: sw.expansion_gate || null }, discovery_config: { sweep: sw.sweep, ranking: sw.ranking, limit: sw.limit, min_stars: sw.min_stars, query_sent: sw.query_sent }, source_versions: { sweep: sw.sweep }, budget: { api_calls: sw.gh_calls || 0, ai_invocations: 0 } });
    const prov = (extra) => Object.assign({ source: "sonar_sweep", sweep: sw.sweep, artefact: path.basename(src) }, extra || {});
    const P = node(id, { type: "PROBLEM", label: problem, provenance: prov() });
    stageStart(id, "DISCOVERY", { problem, query_sent: sw.query_sent });
    const rankPerAngle = {}; for (const [ang, rows] of Object.entries(sw.top_by_angle || {})) rows.forEach((r, i) => { (rankPerAngle[r.fullName] ||= {})[ang] = i + 1; });
    const disc = [];
    for (const r of (sw.repos || [])) {
      const R = node(id, { type: "REPOSITORY", label: r.fullName, provenance: prov({ found_by: r.found_by, rank_per_angle: rankPerAngle[r.fullName] || {}, tier: r.tier, stars: r.stars }), evidence_state: "SURFACED" });
      edge(id, P, "CANDIDATE", R, prov({ found_by: r.found_by }));
      disc.push({ repo: r.fullName, via: (r.found_by || []).join("+"), rank_per_angle: rankPerAngle[r.fullName] || {}, tier: r.tier, evidence_state: "SURFACED" });
    }
    // discovery.jsonl is FROZEN at stage end (A28): repo-level evidence states live in reads.jsonl.
    write(id, "discovery.jsonl", disc.map(d => JSON.stringify(d)).join("\n") + (disc.length ? "\n" : ""));
    stageEnd(id, "DISCOVERY", { artefacts: ["discovery.jsonl", "graph.jsonl"], tools: ["sonar_sweep"], api_calls: sw.gh_calls || 0 });
    stageStart(id, "EVIDENCE_POOL", { candidates: disc.length });
    write(id, "pool.jsonl", disc.map(d => JSON.stringify({ repo: d.repo, via: d.via })).join("\n") + (disc.length ? "\n" : ""));
    stageEnd(id, "EVIDENCE_POOL", { artefacts: ["pool.jsonl"], tools: ["sonar-run.js --ingest-sweep"] });
    const repoState = {}; disc.forEach(d => { repoState[d.repo] = "SURFACED"; });
    // O-40: DEFINITION tokens only. Measured over all 32 source-file fragments on disk: the old
    // set (which admitted import/const/let/var/package and a bare trailing `{`) produced 21
    // candidates of which 10 — 47.6% — were false positives: 8 import-only fragments, a
    // `const … @import(…)` line, and a platform-selection branch that O-39 adjudicated
    // CONTRADICTED. This set: 21 -> 11, 0 gained, and every labelled true positive survives
    // (def weighted_rrf · def weighted_reciprocal_rank + its test · .zig `pub fn` · a py def).
    // `type|interface|module` were tried and REJECTED — they matched the English word
    // "interface" in "Python interface to ...". An import is not an implementation.
    const IMPL = /\b(def|func|function|class|struct|impl|fn)\b|=>/m;
    // O-38: MUST stay identical to server.py's SONAR_SOURCE_EXT. Divergence is a systematic
    // false-negative generator — discovery admits a language, classification then calls every
    // fragment in it NO_MECHANISM regardless of content (measured: 28 languages, incl. the .zig
    // fragment of lightpanda-io/browser reading "pub fn ... Browser.grantPermissions").
    // cc-sonar-test.js pins the two lists against each other so they can never drift again.
    const CODE = /\.(go|py|pyi|js|jsx|mjs|cjs|ts|tsx|rs|java|rb|c|h|cc|cpp|hpp|cs|kt|kts|swift|php|scala|sh|bash|zsh|pl|pm|lua|ex|exs|erl|clj|cljs|hs|ml|mli|zig|dart|vue|svelte|sql|r|jl|nim|sol)$/i;
    const reads = [], frags = []; let states = {};
    stageStart(id, "DEEP_READ", { packets: (sw.evidence || []).length });
    for (const pk of (sw.evidence || [])) {
      const R = `REPOSITORY:${sha(String(pk.repository)).slice(0, 12)}`;
      if (pk.status !== "ok" || !(pk.files || []).length) {
        const st = /NO_CODE_MATCH/.test(pk.status || "") ? "SURFACED_NAME_ONLY" : "SURFACED";
        states[st] = (states[st] || 0) + 1; repoState[pk.repository] = st;
        continue;
      }
      reads.push({ repo: pk.repository, depth: "code-search", files: pk.files.length, query_terms: pk.query_terms });
      for (const f of pk.files) {
        const frag = String(f.fragment || "");
        const st = !frag ? "FETCHED_READ" : (CODE.test(f.path || "") && IMPL.test(frag)) ? "MECHANISM_CANDIDATE" : "NO_MECHANISM";
        states[st] = (states[st] || 0) + 1;
        const F = node(id, { type: "FRAGMENT", label: `${pk.repository}:${f.path}`, provenance: prov({ via: "sweep evidence packet — the code search was performed by sonar_sweep, not here", query_terms: pk.query_terms }), evidence_state: st, subject_digest: "sha256:" + sha(frag), fragment: frag.slice(0, 200), file: f.path });
        edge(id, R, "HAS_FRAGMENT", F, prov());
        frags.push({ node: F, repo: pk.repository, file: f.path, evidence_state: st, subject_digest: "sha256:" + sha(frag) });
      }
      repoState[pk.repository] = frags.filter(x => x.repo === pk.repository).some(x => x.evidence_state === "MECHANISM_CANDIDATE") ? "MECHANISM_CANDIDATE" : "FETCHED_READ";
    }
    reads.forEach(r => { r.evidence_state = repoState[r.repo]; });
    for (const [repo, st] of Object.entries(repoState)) if (!reads.some(r => r.repo === repo)) reads.push({ repo, depth: "none", files: 0, evidence_state: st });
    write(id, "reads.jsonl", reads.map(r => JSON.stringify(r)).join("\n") + (reads.length ? "\n" : ""));
    write(id, "fragments.jsonl", frags.map(f => JSON.stringify(f)).join("\n") + (frags.length ? "\n" : ""));
    stageEnd(id, "DEEP_READ", { artefacts: ["reads.jsonl", "fragments.jsonl", "graph.jsonl"], tools: ["sonar_sweep(evidence=True)"], api_calls: 0 });

    /* HISTORY (O-38, 2026-09-07). sonar-pipeline's ORDER requires HISTORY and COMPARISON to run
       BEFORE any AI stage (order.deterministic_before_ai), and SYNTHESIS must declare
       relevance.jsonl + history.jsonl as inputs (stages.inputs_present). Until now --ingest-sweep
       produced NEITHER, so no real sweep run was adjudicable and blocker B could not be attempted
       without stapling artefacts from somewhere else.
       A sweep carries NO issue/PR history — cc-sonar-history.js is the engine that fetches it and
       it is not invoked here. So this stage records that ABSENCE truthfully, per repo, with the
       command that would fill it. Writing invented issues to satisfy a gate would be exactly the
       laundering the gate exists to catch. UNKNOWN is a valid measurement. */
    stageStart(id, "HISTORY", ["reads.jsonl", "pool.jsonl"]);
    const hist = disc.map(d => ({ repo: d.repo, kind: "none", available: false, distance: "UNKNOWN",
      why: "sonar_sweep does not fetch issue/PR history; run `node cc-sonar-history.js` against this repo to fill it" }));
    write(id, "history.jsonl", hist.map(h => JSON.stringify(h)).join("\n") + (hist.length ? "\n" : ""));
    stageEnd(id, "HISTORY", { artefacts: ["history.jsonl"], tools: [], commands: ["none — history not fetched, see history.jsonl.why"], api_calls: 0 });

    /* COMPARISON (O-38) — RELEVANCE, derived from the evidence this run actually read, and by
       MAX() over a repo's fragments, never a sum: an evidence COUNT is a size signal and mega-repos
       win it (the v1 failure recorded in cc-sonar-relevance.js's own header). Zero API calls. */
    stageStart(id, "COMPARISON", ["fragments.jsonl", "history.jsonl", "pool.jsonl"]);
    const LEVEL = { MECHANISM_CANDIDATE: "DIRECT_IMPLEMENTATION", FETCHED_READ: "SOURCE_READ_NO_MECHANISM",
                    NO_MECHANISM: "MENTIONS_ONLY", SURFACED_NAME_ONLY: "NAME_ONLY", SURFACED: "NAME_ONLY" };
    const RANK = ["NAME_ONLY", "MENTIONS_ONLY", "SOURCE_READ_NO_MECHANISM", "DIRECT_IMPLEMENTATION"];
    const rel = disc.map(d => {
      const mine = frags.filter(f => f.repo === d.repo);
      // Start at the FLOOR, not at the repo state: seeding `best` from repoState made every
      // fragment fail the > comparison, so a DIRECT_IMPLEMENTATION was emitted with from_node
      // null — a relevance level with no citation, which is precisely an unevidenced claim.
      let best = "NAME_ONLY", from = null;
      for (const f of mine) {
        const lv = LEVEL[f.evidence_state] || "NAME_ONLY";
        if (RANK.indexOf(lv) > RANK.indexOf(best)) { best = lv; from = f.node; }
      }
      if (!mine.length) best = LEVEL[repoState[d.repo]] || "NAME_ONLY";
      return { repo: d.repo, relevance: { level: best, best_evidence: from ? "fragment" : "none",
        from_node: from, method: "max", fragments_considered: mine.length } };
    });
    write(id, "relevance.jsonl", rel.map(r => JSON.stringify(r)).join("\n") + (rel.length ? "\n" : ""));
    stageEnd(id, "COMPARISON", { artefacts: ["relevance.jsonl"], tools: ["sonar-run.js --ingest-sweep"], commands: ["local — max() over fragment evidence states"], api_calls: 0 });

    patch(id, m => { m.evidence_states = states; m.ingested_from = src; m.trust_state = "UNKNOWN"; m.promoted = false; });
    finish(id);
    console.log(JSON.stringify({ run_id: id, repositories: disc.length, fragments: frags.length, evidence_states: states, trust_state: "UNKNOWN", promoted: false, next: "node sonar-pipeline.js --verify-run " + id + "  ·  admission only via --promote (D-010), never here" }));
    process.exit(0);
  }
  console.log("usage: sonar-run.js --list | --show <run-id> | --ingest-sweep <sweep-artefact.json>");
}
