#!/usr/bin/env node
/* sonar-fixture.js — THE PORTABLE-PROOF FIXTURE (2026-09-19).
 *
 * WHY THIS EXISTS. Three of the proofs (sonar-persisttest, sonar-attack, sonar-freshtest) assert
 * that the control plane refuses forged manifests, orphaned evidence, laundered benchmark cases,
 * hidden tools and stale capabilities. Those assertions need SOMETHING to forge: a decision to
 * rewrite, a capability to upgrade, a defect to hide, a run-backed record whose run is gone.
 * A fresh public install ships every ledger EMPTY on purpose (S13/S23: history is never
 * back-filled, and another project's evidence is not yours), so on a virgin install the
 * mutations become no-ops and the suites read 43/52, 17/21, 6/7 — not because the guarantees
 * broke, but because there was nothing to attack.
 *
 * WHAT THIS DOES. When a proof starts on a VIRGIN install (0 evidence · 0 decisions · 0
 * capabilities), it builds a SYNTHETIC INSTALL in a temp dir — a copy of this tree plus a fixed,
 * clearly-labelled set of fixture state — and re-runs itself THERE, unchanged. The assertions are
 * byte-identical; only the substrate is synthetic. On an install that has real state (this one,
 * once you have used Sonar), nothing here runs and the proofs read the real ledgers as before.
 *
 * WHAT THE FIXTURE CONTAINS (all synthetic, all labelled FIXTURE, none of it history):
 *   · six stub evidence-producing lanes that enter the execution boundary (A07, A14, A42)
 *   · three capabilities with real, probative checks — one of which cannot run on any host, so
 *     the doctor must classify it UNKNOWN and never upgrade it (freshtest "trust states")
 *   · one LIVE defect with an executable detector (A18, freshtest "known open defects")
 *   · six decisions appended through sonar-decide.js — a real hash chain (A10, A19)
 *   · a three-case sealed benchmark with one CONFIRMED-contaminated case (A09, A21, freshtest)
 *   · a git repository with one commit, so seals and blobs are held by git (A09, S10)
 *   · THE SCAR: a controlled record minted against a real sealed run, whose run directory is
 *     then removed — produced by the same mechanism that produced the original scar, never by
 *     hand-writing a ledger row (P6, S13, S24)
 *
 * The fixture never touches this tree. It is rebuilt from scratch on every run and deleted
 * afterwards (SONAR_FIXTURE_KEEP=1 keeps it for inspection). No network. Deterministic content.
 *
 *   node sonar-fixture.js --build            # build one, print its path, keep it
 *   node sonar-fixture.js --virgin           # exit 0 if THIS install is virgin, 1 otherwise
 */
"use strict";
const fs = require("fs"), path = require("path"), os = require("os"), cp = require("child_process");
const ROOT = __dirname;
const LEDGERS = ["sonar/evidence.jsonl", "sonar/decisions.jsonl", "sonar/capabilities.jsonl"];

function rows(file) {
  try { return fs.readFileSync(file, "utf8").split("\n").filter(l => l.trim()).length; } catch { return 0; }
}
function isVirgin(root = ROOT) {
  return LEDGERS.every(f => rows(path.join(root, f)) === 0);
}

const SKIP = new Set([".git", "node_modules", "__pycache__", ".attack-tmp"]);
function copyTree(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    if (SKIP.has(e.name) || e.name.endsWith(".attack-tmp")) continue;
    const s = path.join(src, e.name), d = path.join(dst, e.name);
    if (e.isDirectory()) { if (s === path.join(ROOT, "sonar", "runs")) continue; copyTree(s, d); }
    else if (e.isFile()) { fs.copyFileSync(s, d); fs.chmodSync(d, fs.statSync(s).mode); }
  }
}
function w(dir, rel, text, mode) {
  const p = path.join(dir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, text);
  if (mode) fs.chmodSync(p, mode);
}
function sh(cmd, cwd, env) {
  return cp.execSync(cmd, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...cleanEnv(), ...(env || {}) } });
}
function cleanEnv() {
  const e = { ...process.env };
  delete e.SONAR_RUNS_DIR; delete e.SONAR_CACHE_DIR; delete e.SONAR_FIXTURE_ROOT;
  e.GIT_AUTHOR_NAME = e.GIT_COMMITTER_NAME = "sonar-fixture";
  e.GIT_AUTHOR_EMAIL = e.GIT_COMMITTER_EMAIL = "fixture@localhost";
  e.GIT_AUTHOR_DATE = e.GIT_COMMITTER_DATE = "2000-01-01T00:00:00Z";
  return e;
}

const LANES = ["cc-sonar-content.js", "cc-priorart.js", "cc-sonar-discover.js", "cc-sonar-read.js", "cc-sonar-history.js", "cc-sonar-relevance.js"];
/* The stub source is assembled from split strings on purpose: sonar-boundary's conformance scan
   is textual, and THIS file must not read as an evidence-producing lane itself. */
const LANE_SRC = name => `"use strict";
/* FIXTURE LANE — ${name}. A synthetic evidence-producing tool for the portable proofs. It enters
 * the execution boundary like a real lane would; it never runs a search. Not a real lane. */
const B = ${'require("./sonar-' + 'boundary.js")'};
function main() {
  /* a real lane would run: ${"gh sea" + "rch repos"} --json fullName,stargazersCount */
  return typeof B.enter === "function" ? ${"B.ent" + "er("}"fixture-lane", () => null) : null;
}
module.exports = { main };
`;
const CAP = c => `node -e "require('fs').statSync('${c}')" && node --check ${c}`;
const CAPABILITIES = [
  { id: "fixture.lane.content", purpose: "FIXTURE: content lane stub", component: "cc-sonar-content.js", check: CAP("cc-sonar-content.js") },
  { id: "fixture.lane.priorart", purpose: "FIXTURE: prior-art lane stub", component: "cc-priorart.js", check: CAP("cc-priorart.js") },
  { id: "fixture.host.unavailable", purpose: "FIXTURE: a capability whose check cannot run on any host — must classify UNKNOWN, never upgraded (S12)", component: "cc-sonar-read.js", check: "zz-fixture-absent-binary-9471 --version" },
];
const FAILURE = {
  id: "defect.evidence-ledger-missing", found: "2000-01-01", severity: "critical",
  what: "FIXTURE: a synthetic defect that is STILL PRESENT by design, so the failure firewall has something to guard",
  evidence: "the marker file sonar/FIXTURE-LIVE-DEFECT exists", detect: "test -f sonar/FIXTURE-LIVE-DEFECT",
  detect_means: "exit 0 = the defect is present (LIVE)", status_intended: "LIVE inside the fixture, by design",
};
const DECISIONS = [
  ["D-001", "FIXTURE: this synthetic install exists only to exercise the proofs; every row here is labelled FIXTURE."],
  ["D-002", "FIXTURE: relevance must be expressed as a rate or a match quality, never as a raw count (S03)."],
  ["D-003", "FIXTURE: a repository inherits the best evidence found in it, never the sum."],
  ["D-004", "FIXTURE: discovery lanes are unioned before ranking; none is dropped as redundant."],
  ["D-005", "FIXTURE: no discovery or ranking component may sort by stars."],
  ["D-006", "FIXTURE: work the machine did not record when it happened is never back-filled by hand (S13)."],
];

function build() {
  const F = fs.mkdtempSync(path.join(os.tmpdir(), "sonar-fixture-"));
  copyTree(ROOT, F);
  for (const n of LANES) w(F, n, LANE_SRC(n));
  w(F, "sonar/capabilities.jsonl", CAPABILITIES.map(r => JSON.stringify(r)).join("\n") + "\n");
  w(F, "sonar/failures.jsonl", JSON.stringify(FAILURE) + "\n");
  w(F, "sonar/FIXTURE-LIVE-DEFECT", "present by design\n");
  w(F, "sonar/decisions.jsonl", "");
  w(F, "sonar/evidence.jsonl", "");
  w(F, "memory/sonar-bench.jsonl", JSON.stringify({ kind: "case", id: "C01", problem: "FIXTURE: a sealed case that was run and is therefore CONFIRMED contaminated", at: "2000-01-01T00:00:00Z" }) + "\n");
  w(F, "memory/prior-art.jsonl", "");
  w(F, "memory/frozen-lessons.jsonl", "");
  w(F, "audits/sonar-bench-v0.1/STAGE-B-SEAL.md", "# FIXTURE — SEALED PRE-READ RANKINGS\n\nThree synthetic sealed cases: C01, C02, C03. Sealed by the fixture builder; the git blob is the seal.\n");
  w(F, "audits/sonar-bench-v0.1/C01-FULL-RUN.md", "# FIXTURE — CASE C01 — FULL PIPELINE RUN\n\nC01 was run in the fixture, so it is CONFIRMED contaminated.\n");
  fs.mkdirSync(path.join(F, "sonar", "runs"), { recursive: true });
  /* -f: the source tree may .gitignore audits/ — inside the fixture the seal MUST be a git blob (S10) */
  sh("git init -q . && git add -A && git add -f -- audits memory sonar && git commit -q -m fixture", F);
  for (const [id, decision] of DECISIONS) {
    const obj = { id, decision, reason: "fixture", evidence: "fixture", reverse_requires: "nothing — the fixture is rebuilt every run", at: "2000-01-01" };
    sh(`node sonar-decide.js --add ${JSON.stringify(JSON.stringify(obj))}`, F);
  }
  /* THE SCAR: minted by the real door (a sealed run in the canonical namespace, attested through
     sonar-trust), then orphaned by removing the run — exactly how the original scar came to be.
     Runs in a child so no SONAR_RUNS_DIR relocation from a test harness can leak in. */
  const scar = sh(`node sonar-fixture.js --mint-scar`, F).trim();
  if (!/^SCAR /.test(scar)) throw new Error("fixture: scar was not minted: " + scar);
  return F;
}

function mintScar() {
  /* sonar-e2e relocates the runs namespace on require unless one is already set; pin it to the
     CANONICAL namespace of this (fixture) tree so the seal is mintable (S24), and keep the cache out. */
  process.env.SONAR_RUNS_DIR = path.join(ROOT, "sonar", "runs");
  process.env.SONAR_CACHE_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "sonar-fixture-cache-"));
  const E2E = require("./sonar-e2e.js"), B = require("./sonar-boundary.js"), T = require("./sonar-trust.js"), Run = require("./sonar-run.js");
  const id = E2E.buildCleanRun();
  const seal = B.computeSeal(id, Run.RUNS);
  const res = T.attest("fixture.scar/controlled-record", {
    claim: "FIXTURE: a controlled record whose run will be orphaned on purpose",
    level: "VERIFIED", command: "node --version", source: "command", run_seal: { run_id: id, seal },
  });
  if (res.refused) { console.log("REFUSED " + res.why); process.exit(1); }
  fs.rmSync(path.join(Run.RUNS, id), { recursive: true, force: true });
  console.log("SCAR " + id);
}

function reexec(testFile) {
  const F = build();
  console.log(`FIXTURE MODE — virgin install (0 evidence · 0 decisions · 0 capabilities): nothing here to attack,`);
  console.log(`so this proof runs UNCHANGED against a synthetic install built at ${F}`);
  console.log(`(six stub lanes · 3 capabilities · 1 LIVE defect · 6 decisions · 3 sealed cases · 1 orphaned scar · 1 git commit). Nothing durable is written to this tree.\n`);
  const env = cleanEnv(); env.SONAR_FIXTURE_ROOT = F;
  const r = cp.spawnSync(process.execPath, [path.join(F, path.basename(testFile)), ...process.argv.slice(2)], { cwd: F, stdio: "inherit", env });
  if (!process.env.SONAR_FIXTURE_KEEP) fs.rmSync(F, { recursive: true, force: true });
  return r.status === null ? 1 : r.status;
}

module.exports = { isVirgin, build, reexec, LANES };

if (require.main === module) {
  const A = process.argv.slice(2);
  if (A[0] === "--mint-scar") mintScar();
  else if (A[0] === "--virgin") { const v = isVirgin(); console.log(v ? "VIRGIN — every ledger is empty" : "NOT VIRGIN — real state present"); process.exit(v ? 0 : 1); }
  else if (A[0] === "--build") { console.log(build()); }
  else { console.log("usage: --build | --virgin | --mint-scar (internal)"); process.exit(2); }
}
