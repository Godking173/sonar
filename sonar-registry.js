#!/usr/bin/env node
/* sonar-registry.js — THE DERIVED REGISTRIES.
 *
 * DESIGN RULE, one line: nothing in here is true because it is written down.
 * Every registry below is COMPUTED from the filesystem, from git, or from
 * append-only machine-written ledgers. Where a fact cannot be computed, the
 * answer is UNKNOWN and stays UNKNOWN. I am the operator, not the source.
 *
 * PRIOR ART (found by Sonar's content lane, not recalled): Backstage
 * catalog-info.yaml, seen independently in openedx / elastic / snyk /
 * ibm-messaging / contentful / harness. The property worth stealing is that
 * the catalog is DERIVED from components rather than hand-maintained.
 *
 * The one thing a derived registry still cannot do is notice that it was
 * derived somewhere else. Every record therefore carries HOST. A VERIFIED on
 * the Mac is not a VERIFIED in the Linux VM, and this file refuses to pretend
 * otherwise.
 */
"use strict";
const fs = require("fs"), cp = require("child_process"), path = require("path"), os = require("os");
const ROOT = __dirname;

function sh(cmd, ms = 20000) {
  try { return { ok: true, out: cp.execSync(cmd, { cwd: ROOT, encoding: "utf8", timeout: ms, stdio: ["ignore", "pipe", "pipe"] }).trim(), err: "" }; }
  catch (e) { return { ok: false, out: String(e.stdout || "").trim(), err: String(e.stderr || "").trim(), status: e.status }; }
}
function jsonl(rel) {
  const f = path.join(ROOT, rel);
  if (!fs.existsSync(f)) return null;
  return fs.readFileSync(f, "utf8").split("\n").filter(l => l.trim()).map(l => {
    try { return JSON.parse(l); } catch { return { __unparseable: l.slice(0, 90) }; }
  });
}
const HOST = () => ({ hostname: os.hostname(), platform: process.platform, arch: process.arch, node: process.version });

/* ── 1. CAPABILITY ───────────────────────────────────────────────────────
   The only hand-authored registry, and deliberately so: an executable check
   cannot be invented by derivation. But every ENTRY carries its own check, so
   the prose in it can never outrank the command in it. */
function capability() {
  const rel = "sonar/capabilities.jsonl", rows = jsonl(rel);
  if (!rows) return { state: "UNKNOWN", why: "sonar/capabilities.jsonl missing", rows: [] };
  /* S14 + S22: a row with no check is not a capability, and a row whose check CANNOT FAIL is a
     forged capability — the cheapest possible lie. Both fail the registry closed. */
  const T = require("./sonar-trust.js");
  const bad = rows.filter(r => r.__unparseable || !r.id || !r.check || !T.probative(r.check).ok);
  for (const r of rows) if (r.check && !T.probative(r.check).ok) r.__non_probative = T.probative(r.check).why;
  return { state: bad.length ? "BROKEN" : "OK", rows, malformed: bad, source: rel, authored: true };
}

/* ── 2. ARCHITECTURE ─────────────────────────────────────────────────────
   Derived from disk + git. Not a list I keep; a list the repo has. */
/* COMPONENT DISCOVERY — 2026-08-11. This was a hardcoded LIST of five filenames, which is an
   authored registry wearing a derivation costume: it silently omitted six real tools, including
   the manifest and the attack suite that is supposed to catch exactly this. Attack A14 is
   "hide an existing tool from the manifest" and my own glob was doing it.
   It is now a RULE, not a list. A file counts as a component if ANY of these hold:
     (a) it follows the naming convention, or
     (b) a capability check names it, or
     (c) it requires one of the system's own modules.
   Add a new sonar tool tomorrow and it discovers itself. */
const NAME_RULE = /^(sonar-|cc-sonar-|cc-priorart|cc-coverage-ratchet)[\w.-]*\.(js|sh)$/;
const SELF_MODULES = ["./sonar-trust.js", "./sonar-registry.js", "./sonar-brain.js", "./sonar-decide.js"];
function discoverComponents() {
  const all = fs.readdirSync(ROOT).filter(f => /\.(js|sh)$/.test(f) && !/-tests?\.js$/.test(f) && fs.statSync(path.join(ROOT, f)).isFile());
  const capChecks = (jsonl("sonar/capabilities.jsonl") || []).map(c => `${c.check || ""} ${c.component || ""}`).join(" ");
  return all.filter(f => {
    if (NAME_RULE.test(f)) return true;
    if (capChecks.includes(f)) return true;
    try { const src = fs.readFileSync(path.join(ROOT, f), "utf8"); return SELF_MODULES.some(m => src.includes(`require("${m}")`)); } catch { return false; }
  }).sort();
}
function architecture() {
  const files = discoverComponents();
  const capIds = (jsonl("sonar/capabilities.jsonl") || []).filter(c => c.component).map(c => c.component);
  const toolbox = fs.existsSync(path.join(ROOT, "TOOLBOX.md")) ? fs.readFileSync(path.join(ROOT, "TOOLBOX.md"), "utf8") : "";
  /* "what proves it works" is not only *-test.js. These tools are exercised by the GATE
     RUNNERS, which is weaker than a unit test and must be reported as a different thing. */
  const gateFiles = ["cc-verify.sh", "cc-verify-chunk.sh", ".cc-verify-slice.sh"].filter(f => fs.existsSync(path.join(ROOT, f)));
  const gateBlob = gateFiles.map(f => { try { return fs.readFileSync(path.join(ROOT, f), "utf8"); } catch { return ""; } }).join("\n");
  const testFiles = fs.readdirSync(ROOT).filter(f => /-tests?\.js$/.test(f));
  const testBlob = testFiles.map(f => { try { return fs.readFileSync(path.join(ROOT, f), "utf8"); } catch { return ""; } }).join("\n");
  const rows = files.map(f => {
    const st = fs.statSync(path.join(ROOT, f));
    const born = sh(`git log --diff-filter=A --format=%h\\ %ad --date=short -1 -- ${f}`);
    const last = sh(`git log --format=%h\\ %ad --date=short -1 -- ${f}`);
    const tracked = sh(`git ls-files --error-unmatch ${f}`).ok;
    return {
      component: f, bytes: st.size,
      lines: fs.readFileSync(path.join(ROOT, f), "utf8").split("\n").length,
      git_tracked: tracked,
      introduced: born.ok && born.out ? born.out : null,
      last_commit: last.ok && last.out ? last.out : null,
      in_capability_registry: capIds.includes(f),
      in_toolbox: toolbox.includes(f),
      referenced_by_tests: testBlob.includes(f),
      exercised_by_gate: gateBlob.includes(f)
    };
  });
  return {
    state: "OK", derived_from: "readdir + git log + TOOLBOX.md + *-test.js contents", rows,
    gaps: {
      untracked_by_git: rows.filter(r => !r.git_tracked).map(r => r.component),
      missing_from_capability_registry: rows.filter(r => !r.in_capability_registry).map(r => r.component),
      missing_from_toolbox: rows.filter(r => !r.in_toolbox).map(r => r.component),
      no_test_references_it: rows.filter(r => !r.referenced_by_tests).map(r => r.component),
      neither_test_nor_gate_runs_it: rows.filter(r => !r.referenced_by_tests && !r.exercised_by_gate).map(r => r.component)
    }
  };
}

/* ── 3. EVIDENCE ─────────────────────────────────────────────────────────
   Derived from memory/prior-art.jsonl, which is written BY cc-priorart.js at
   clone time, not by me at write-up time. A claim with no matching read is the
   exact shape of a hallucination and is surfaced as such. */
function evidence() {
  const rows = jsonl("memory/prior-art.jsonl");
  if (!rows) return { state: "UNKNOWN", why: "memory/prior-art.jsonl missing" };
  const reads = rows.filter(r => r.kind === "read"), claims = rows.filter(r => r.kind === "claim");
  const readRepos = new Set(reads.map(r => r.repo));
  return {
    state: "OK", source: "memory/prior-art.jsonl (machine-appended by cc-priorart.js)",
    reads: reads.map(r => ({ repo: r.repo, head: r.head, depth: r.depth, files: r.files, test_ratio: r.test_ratio, at: r.at })),
    claims: claims.map(c => ({ repo: c.repo, at: c.at, backed_by_read: readRepos.has(c.repo) })),
    gaps: { claims_with_no_read: claims.filter(c => !readRepos.has(c.repo)).map(c => c.repo) }
  };
}

/* ── 4. REPOSITORY CACHE ────────────────────────────────────────────────
   repo@commit actually analysed. Cross-checked against repos NAMED in the
   audit prose: anything written up but never recorded is an unrecorded read,
   which is the failure mode this whole build exists to catch. */
function repositoryCache() {
  const ev = evidence();
  if (ev.state !== "OK") return { state: "UNKNOWN", why: ev.why };
  const recorded = new Map();
  for (const r of ev.reads) recorded.set(r.repo, r.head);
  const auditDir = path.join(ROOT, "audits", "sonar-bench-v0.1");
  const named = new Set();
  if (fs.existsSync(auditDir)) {
    for (const f of fs.readdirSync(auditDir).filter(f => f.endsWith(".md"))) {
      const txt = fs.readFileSync(path.join(auditDir, f), "utf8");
      /* DERIVATION RULE, stated so it can be argued with: only a BACKTICKED owner/name counts.
         The loose version matched "10/min", "2PC/XA" and "keyset/cursor" and produced 118 junk
         rows — a gap report nobody can act on is the same as no gap report. Backticks are the
         convention these write-ups actually use. This under-reports rather than over-reports. */
      for (const m of txt.matchAll(/`([A-Za-z0-9][A-Za-z0-9._-]{1,38})\/([A-Za-z0-9][A-Za-z0-9._-]{1,60})`/g)) {
        const s = `${m[1]}/${m[2]}`;
        if (/\.(md|js|json|py|ts|yml|sh)$/i.test(s)) continue;
        if (/^(audits|memory|docs|scout|packages|src|test|tests|e2e|node_modules)\//i.test(s)) continue;
        named.add(s);
      }
    }
  }
  return {
    state: "OK",
    derived_from: "memory/prior-art.jsonl heads + BACKTICKED `owner/name` mentions in audits/sonar-bench-v0.1/*.md",
    analysed: [...recorded].map(([repo, head]) => ({ repo, head })),
    gaps: { named_in_writeups_but_never_recorded_as_read: [...named].filter(r => !recorded.has(r)).sort() }
  };
}

/* ── 5. EXPERIMENT ──────────────────────────────────────────────────────
   Derived from the bench ledger + audit artefacts + git. CONTAMINATION is the
   part I refuse to assert: a case is CONFIRMED contaminated only when a
   machine record names it. Everything else is UNKNOWN, and UNKNOWN must be
   treated as contaminated when measuring. Fail closed. */
function experiment() {
  const bench = jsonl("memory/sonar-bench.jsonl");
  const auditDir = path.join(ROOT, "audits", "sonar-bench-v0.1");
  const artefacts = fs.existsSync(auditDir) ? fs.readdirSync(auditDir).filter(f => f.endsWith(".md")) : [];
  const ids = new Set();
  const sealFile = path.join(auditDir, "STAGE-B-SEAL.md");
  if (fs.existsSync(sealFile)) for (const m of fs.readFileSync(sealFile, "utf8").matchAll(/\bC(\d{2})\b/g)) ids.add("C" + m[1]);

  const confirmed = new Set();
  for (const f of artefacts) { const m = f.match(/^(C\d{2})-/); if (m) confirmed.add(m[1]); }
  for (const r of bench || []) { const c = r.case || (r.kind === "case" ? r.id : null); if (c && /^C\d{2}$/.test(c)) confirmed.add(c); }

  const mentions = {};
  for (const f of artefacts) {
    const seen = new Set();
    for (const m of fs.readFileSync(path.join(auditDir, f), "utf8").matchAll(/\bC(\d{2})\b/g)) seen.add("C" + m[1]);
    mentions[f] = [...seen].sort();
  }
  const unproven = [...ids].filter(i => !confirmed.has(i)).sort();
  return {
    state: "OK",
    derived_from: "memory/sonar-bench.jsonl + audits/sonar-bench-v0.1/ filenames + STAGE-B-SEAL.md case ids",
    total_cases_sealed: ids.size,
    artefacts,
    ledger_entry_kinds: (bench || []).reduce((a, r) => (a[r.kind] = (a[r.kind] || 0) + 1, a), {}),
    contamination: {
      CONFIRMED_CONTAMINATED: [...confirmed].sort(),
      UNPROVEN: unproven,
      policy: "UNPROVEN is not CLEAN. Runs were written up in prose, not recorded per-case, so cleanliness is NOT machine-provable. Treat UNPROVEN as contaminated until a per-case machine record exists.",
      raw_mention_matrix: mentions
    }
  };
}

/* ── 6. FAILURE ─────────────────────────────────────────────────────────
   Each known defect carries a DETECTOR. A defect is not fixed because I say
   so; it is fixed when its detector stops firing, and a detector that cannot
   run is UNKNOWN, never fixed. */
function failure() {
  const rows = jsonl("sonar/failures.jsonl");
  if (!rows) return { state: "UNKNOWN", why: "sonar/failures.jsonl missing" };
  return { state: "OK", source: "sonar/failures.jsonl (each entry carries an executable detector)", rows };
}
function runDetector(cmd) {
  const r = sh(cmd, 30000);
  const missing = /not found|No such file|command not found|ENOENT/i.test(r.err || "");
  if (!r.ok && missing) return { state: "UNKNOWN", why: (r.err || "").split("\n")[0].slice(0, 90) };
  return { state: r.ok ? "STILL_PRESENT" : "NOT_DETECTED", exit: r.ok ? 0 : r.status };
}

/* ── 7. RESOURCE GOVERNOR ───────────────────────────────────────────────
   Live only. There is no cached rate limit; a cached rate limit is a lie with
   a timestamp on it. No gh on this host means UNKNOWN. */
function resource() {
  const h = HOST();
  const ghp = sh("command -v gh");
  if (!ghp.ok) return { state: "UNKNOWN", why: "gh not present on this host", host: h };
  const r = sh("gh api rate_limit", 25000);
  if (!r.ok) return { state: "UNKNOWN", why: (r.err || "gh api rate_limit failed").split("\n")[0].slice(0, 120), host: h };
  let j; try { j = JSON.parse(r.out); } catch { return { state: "UNKNOWN", why: "rate_limit response unparseable", host: h }; }
  const pick = k => j.resources && j.resources[k] ? { remaining: j.resources[k].remaining, limit: j.resources[k].limit, reset: new Date(j.resources[k].reset * 1000).toISOString() } : null;
  return { state: "LIVE", host: h, at: new Date().toISOString(), core: pick("core"), search: pick("search"), code_search: pick("code_search"), graphql: pick("graphql") };
}

/* ── tools actually installed, on THIS host ───────────────────────────── */
const TOOLS = ["git", "node", "gh", "curl", "duckdb", "jq", "python3", "rg"];
function tools() {
  return { host: HOST(), rows: TOOLS.map(t => { const r = sh(`command -v ${t}`); return { tool: t, present: r.ok, path: r.ok ? r.out.split("\n")[0] : null }; }) };
}

module.exports = { discoverComponents, capability, architecture, evidence, repositoryCache, experiment, failure, runDetector, resource, tools, HOST, sh, jsonl };

if (require.main === module) {
  const A = process.argv.slice(2);
  const all = { host: HOST(), at: new Date().toISOString(), capability: capability(), architecture: architecture(), evidence: evidence(), repository_cache: repositoryCache(), experiment: experiment(), failure: failure(), resource: resource(), tools: tools() };
  if (A.includes("--json")) { console.log(JSON.stringify(all, null, 2)); process.exit(0); }
  const only = A[0];
  console.log(JSON.stringify(only && all[only] ? all[only] : all, null, 2));
}
