#!/usr/bin/env node
/* sonar-doctor.js — THE SONAR CONTROL PLANE. Claude is the operator, NOT the source of truth.
 *
 * WHY THIS EXISTS, in the operator's words: "you always forget, you always hallucinate, and you always
 * lie… you might even lie about the proof." Correct on all four. Any design where I ASSERT state
 * is a design where I can lie about state. So nothing here is true because it is written down.
 * Every answer below is RE-EXECUTED or RE-DERIVED at the moment you run this command.
 *
 * PRIOR ART (found by Sonar's own content lane, not recalled): Backstage catalog-info.yaml, seen
 * independently across openedx / elastic / snyk / ibm-messaging / contentful / harness. The
 * property worth stealing: the catalog is DERIVED from components, not hand-maintained.
 *
 * THREE STATES ONLY, and the third one is the important one:
 *   VERIFIED  the check ran, on THIS host, just now, and passed
 *   BROKEN    the check ran, on THIS host, and failed
 *   UNKNOWN   the check COULD NOT RUN here (tool absent, no egress). Never upgraded. Ever.
 *
 * A LIE THIS FILE ITSELF TOLD, found and fixed 2026-08-10: the previous version ran checks with
 * stdio:'ignore', so stderr was null, so the "could not run" branch was unreachable — UNKNOWN was
 * DEAD CODE and the headline promise guarded a state the program could not produce. `--selftest`
 * now proves the classifier works before you are allowed to believe any of its output.
 *
 * A SECOND LIE, same day: it reported "14 VERIFIED, 0 BROKEN" without naming the host. The same
 * commit on the Linux bridge VM gives 9 VERIFIED / 5 BROKEN, because gh, duckdb and network egress
 * do not exist there. Every record now carries HOST. A VERIFIED on the Mac is not a VERIFIED here.
 *
 * HOW TO AUDIT ME — do not trust this output, reproduce it:
 *   node sonar-doctor.js --show-checks   prints every command verbatim; run them yourself
 *   node sonar-doctor.js --selftest      proves the VERIFIED/BROKEN/UNKNOWN classifier is real
 *   node sonar-doctor.js --adversarial   deletes a component, demands doctor notice, restores it
 *   node sonar-registry.js --json        the raw derived registries, unformatted
 *
 * Usage: [--json] [--brief] [--show-checks] [--selftest] [--adversarial] [--only <id-prefix>]
 */
"use strict";
const fs = require("fs"), cp = require("child_process"), path = require("path"), os = require("os");
const R = require("./sonar-registry.js"), T = require("./sonar-trust.js");
const ROOT = __dirname, A = process.argv.slice(2), has = f => A.includes(f);
const only = (() => { const i = A.indexOf("--only"); return i !== -1 ? A[i + 1] : null; })();
const STATE = path.join(ROOT, "sonar", "doctor-state.json");
/* CRASH RECOVERY — --adversarial renames a real component out of the way. A kill between the
   two renames would leave the repo genuinely broken by the tool meant to prove it isn't. */
(function restoreAdversarial() {
  /* Two sibling tools rename this same component during their own crash-recovery-sensitive
     mutation tests, each with its own suffix: sonar-doctor's own --adversarial (below) uses
     ".adversarial-tmp"; sonar-attack.js's A07 "deleted component" attack uses ".attack-tmp".
     A doctor that only recognizes its own suffix cannot heal damage left by its sibling — that
     gap was found and fixed 2026-08-16 after a real interrupted A07 run required a manual `mv`.
     Recognize every known tmp suffix here, not just the one this file happens to produce. */
  const t = path.join(ROOT, "cc-sonar-content.js");
  const KNOWN_TMP_SUFFIXES = [".adversarial-tmp", ".attack-tmp"];
  for (const suffix of KNOWN_TMP_SUFFIXES) {
    const tmp = t + suffix;
    if (fs.existsSync(tmp) && !fs.existsSync(t)) {
      fs.renameSync(tmp, t);
      console.error(`! recovered cc-sonar-content.js from an interrupted run (found ${suffix})`);
    }
  }
})();
const HOST = R.HOST(), HOSTKEY = `${HOST.hostname}:${HOST.platform}/${HOST.arch}`;

/* ── the classifier. Its correctness is not assumed; --selftest proves it. ── */
const KNOWN_TOOLS = ["gh", "duckdb", "curl", "jq", "rg", "python3", "node", "git"];
let EGRESS = null;
function egressOK() {
  if (EGRESS !== null) return EGRESS;
  const r = R.sh("curl -s -m 8 -o /dev/null -w '%{http_code}' https://api.github.com", 12000);
  EGRESS = r.ok && /^[1-5][0-9][0-9]$/.test(r.out) && r.out !== "000";
  return EGRESS;
}
function classify(cmd) {
  /* Do not RUN a check that cannot be meaningful here. A network check from a host with no
     network does not measure the source; it measures the host. Short-circuit to UNKNOWN,
     which is also what stops one dead curl per source from eating the whole call window. */
  const missingPre = KNOWN_TOOLS.filter(t => new RegExp(`(^|[\\s;|&(])${t}\\b`).test(cmd) && !R.sh(`command -v ${t}`).ok);
  if (missingPre.length) return { status: "UNKNOWN", why: `tool not installed on this host: ${missingPre.join(", ")}` };
  if (/curl|https?:\/\//.test(cmd) && !egressOK()) return { status: "UNKNOWN", why: "no network egress from this host — a remote source cannot be judged from here" };
  const r = R.sh(cmd, 45000);
  if (r.ok) return { status: "VERIFIED", result: { exit: 0, stdout: r.out || "", stderr: "", ms: 0 } };
  const err = (r.err || "") + "\n" + (r.out || "");
  const missing = missingPre;
  if (missing.length) return { status: "UNKNOWN", why: `tool not installed on this host: ${missing.join(", ")}` };
  if (/not found|command not found|ENOENT/i.test(err)) return { status: "UNKNOWN", why: (err.match(/.*not found.*/i) || [""])[0].trim().slice(0, 80) };
  if (/curl|https?:\/\//.test(cmd) && !egressOK()) return { status: "UNKNOWN", why: "no network egress from this host — cannot judge a remote source from here" };
  return { status: "BROKEN", exit: r.status, why: (err.trim().split("\n")[0] || "").slice(0, 90) };
}

/* ── --selftest: the classifier must be provably able to produce all three states ── */
if (has("--selftest")) {
  const cases = [
    { cmd: "true", want: "VERIFIED", means: "a check that passes" },
    { cmd: "false", want: "BROKEN", means: "a check that ran and failed" },
    { cmd: "zz-definitely-not-a-real-binary-9471 --version", want: "UNKNOWN", means: "a check that could not run at all" }
  ];
  let pass = true;
  console.log("CLASSIFIER SELFTEST — can doctor actually produce all three states?");
  for (const c of cases) {
    const got = classify(c.cmd).status, ok = got === c.want; if (!ok) pass = false;
    console.log(`  ${ok ? "✓" : "✗"} ${c.means.padEnd(34)} want ${c.want.padEnd(8)} got ${got}`);
  }
  console.log(pass ? "  ✓ PASS — UNKNOWN is reachable. The three-state promise is real."
                   : "  ✗ FAIL — the classifier cannot produce all three states. Every state it prints is suspect.");
  if (pass && A.includes("--attest")) {
    const r = T.attest("control.doctor.classifier_three_state", { claim: "the classifier can produce VERIFIED, BROKEN and UNKNOWN", level: "VERIFIED", command: "node sonar-doctor.js --selftest", paths: ["sonar-doctor.js"], source: "command" });
    console.log(r.refused ? "  attest REFUSED: " + r.why : `  attested control.doctor.classifier_three_state = ${r.record.level}`);
  }
  process.exit(pass ? 0 : 1);
}

const CAP = R.capability();
if (CAP.state === "UNKNOWN") { console.error(`✗ ${CAP.why} — control plane cannot report. Failing closed.`); process.exit(2); }
if (CAP.state === "BROKEN") { console.error(`✗ capability registry malformed (${CAP.malformed.length} bad row(s)) — failing closed`); process.exit(2); }
const C = CAP.rows.filter(c => !only || c.id.startsWith(only));

/* --explain <fact>: for any fact, show exactly WHY the system holds it at its level, and
   every record behind it including the ones it refused to count. */
if (has("--explain")) {
  const f = A[A.indexOf("--explain") + 1];
  if (!f) { console.log("facts on record:"); for (const x of T.facts()) console.log("  " + T.levelFor(x).level.padEnd(23) + x); process.exit(0); }
  const l = T.levelFor(f);
  console.log(`FACT  ${f}`);
  console.log(`LEVEL ${l.level}   (ladder: ${T.LEVELS.join(" → ")})`);
  console.log(`HOST  ${T.hostKey()}   HEAD ${T.gitHead()}   chain_ok=${l.chain_ok}`);
  console.log(`records=${l.records} usable_here=${l.usable} rejected=${l.rejected}`);
  console.log("WHY:");
  for (const r of l.reasons) console.log("  · " + r);
  const recs = T.readLedger().filter(r => r.fact === f);
  if (recs.length) { console.log("PROVENANCE (most recent record):"); const r = recs[recs.length - 1];
    for (const k of ["host_key","at","cwd","command","exit_code","stdout_sha256","stderr_sha256","tool_version","network","git_head","git_dirty","source","paths","prev","sha"])
      console.log(`  ${k.padEnd(15)} ${JSON.stringify(r[k])}`); }
  process.exit(0);
}
/* --constitution: an ENFORCED rule that names a file which does not exist is a rule that is
   not enforced. Parse the table and prove each enforcement artefact is really on disk. */
if (has("--constitution")) {
  const p = path.join(ROOT, "SONAR_CONSTITUTION.md");
  if (!fs.existsSync(p)) { console.error("✗ SONAR_CONSTITUTION.md missing — failing closed"); process.exit(1); }
  const rows = fs.readFileSync(p, "utf8").split("\n").filter(l => /^\|\s*S\d\d\s*\|/.test(l)).map(l => l.split("|").map(s => s.trim()));
  let bad = 0, enforced = 0;
  for (const r of rows) {
    const [, id, rule, status, by] = r;
    if (status !== "ENFORCED") continue;
    enforced++;
    const files = [...(by || "").matchAll(/`([^`]+)`/g)].map(m => m[1]).filter(x => /\.(js|sh|jsonl|md)$/.test(x));
    const missing = files.filter(x => !fs.existsSync(path.join(ROOT, x)));
    if (missing.length) { bad++; console.log(`  ✗ ${id} claims enforcement by ${missing.join(", ")} which does not exist`); }
  }
  console.log(`CONSTITUTION — ${rows.length} rules, ${enforced} ENFORCED, ${bad} claiming a non-existent enforcer`);
  console.log(bad ? "  ✗ FAIL — a rule that names a missing enforcer is doctrine pretending to be enforcement." : "  ✓ PASS — every ENFORCED rule names an artefact that exists on disk.");
  process.exit(bad ? 1 : 0);
}
if (has("--show-checks")) { for (const c of C) console.log(`${c.id}\n  ${c.check}\n`); process.exit(0); }

if (has("--adversarial")) {
  const target = "cc-sonar-content.js", tmp = target + ".adversarial-tmp";
  const chk = C.find(c => c.id === "discovery.content").check;
  const before = classify(chk).status;
  fs.renameSync(path.join(ROOT, target), path.join(ROOT, tmp));
  const during = classify(chk).status;
  fs.renameSync(path.join(ROOT, tmp), path.join(ROOT, target));
  const after = classify(chk).status;
  const pass = before === "VERIFIED" && during !== "VERIFIED" && after === "VERIFIED";
  console.log(`ADVERSARIAL PROOF on ${HOSTKEY} — rename ${target}, re-check, restore`);
  console.log(`  before=${before}  during(file removed)=${during}  after=${after}`);
  console.log(pass ? "  ✓ PASS — doctor DETECTED the missing component. Its GREEN is earned, not recited."
                   : "  ✗ FAIL — doctor did not detect a missing component. Every GREEN it prints is worthless.");
  if (pass && A.includes("--attest")) {
    const r = T.attest("control.doctor.detects_missing_component", { claim: "doctor reports BROKEN when a component it depends on is removed", level: "ADVERSARIALLY_VERIFIED", command: "node sonar-doctor.js --adversarial", paths: ["sonar-doctor.js"], source: "command" });
    console.log(r.refused ? "  attest REFUSED: " + r.why : `  attested control.doctor.detects_missing_component = ${r.record.level}`);
  }
  process.exit(pass ? 0 : 1);
}

/* ── recompute everything ──
   STREAMING (2026-08-19): a slow check must look slow, not dead. Plain mode used to buffer all
   30 classify() calls behind one synchronous .map() with zero output until every row finished —
   see SONAR-DOCTOR-HANG-DIAGNOSIS-2026-08-19 for the full causal trace (control.brain/bootstrap/
   attacks alone cost ~56-57s here with nothing printed in between). This prints one line PER
   CAPABILITY as it completes, informational only: classification, ordering, JSON payload, exit
   code and every downstream consumer below are byte-for-byte unchanged. Checks still run strictly
   sequentially, in the same order, with the same per-command timeout inside classify()/R.sh() —
   nothing about WHAT runs or HOW it's judged is touched, only that its progress is now visible.
   Suppressed under --json so stdout stays pure JSON for programmatic consumers. */
const STREAM = !has("--json");
if (STREAM) console.log(`sonar doctor starting — ${C.length} checks\n`);
const caps = C.map((c, i) => {
  const t0 = Date.now();
  const result = { ...c, ...classify(c.check) };
  if (STREAM) {
    const ms = Date.now() - t0;
    const elapsed = ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
    const idx = String(i + 1).padStart(2, "0");
    console.log(`[${idx}/${C.length}] ${(c.id + " ").padEnd(26, ".")} ${result.status.padEnd(9)}${elapsed}`);
  }
  return result;
});
if (STREAM) console.log("\nsonar doctor complete");
const n = s => caps.filter(r => r.status === s).length;
/* Every VERIFIED capability leaves a provenance record. Deduped on (host, HEAD, level,
   command) so a hundred doctor runs at one commit do not produce a hundred identical records. */
let minted = 0;
for (const c of caps.filter(c => c.status === "VERIFIED")) {
  const fact = "capability." + c.id;
  const prevRecs = T.readLedger().filter(r => r.fact === fact);
  const last = prevRecs[prevRecs.length - 1];
  if (last && last.host_key === HOSTKEY && last.git_head === T.gitHead() && last.level === "VERIFIED" && last.command === c.check) continue;
  const paths = c.component && fs.existsSync(path.join(ROOT, c.component)) ? [c.component] : [];
  const res = T.attest(fact, { claim: c.purpose, level: "VERIFIED", command: c.check, paths, source: "command", result: c.result });
  if (!res.refused) minted++;
  else console.error("! attest refused for " + fact + ": " + res.why);
}
const chain = T.verifyChain();
const arch = R.architecture(), ev = R.evidence(), repo = R.repositoryCache();
const exp = R.experiment(), fail = R.failure(), res = R.resource(), tools = R.tools();
const failRows = fail.state === "OK" ? fail.rows.map(f => ({ ...f, detector: R.runDetector(f.detect) })) : [];

/* ── staleness: prior runs, per host. Absent state = UNKNOWN, which is correct. ── */
let prior = {}; try { prior = JSON.parse(fs.readFileSync(STATE, "utf8")); } catch { prior = {}; }
const priorHere = prior[HOSTKEY], nowISO = new Date().toISOString();
const otherHosts = Object.entries(prior).filter(([k]) => k !== HOSTKEY)
  .map(([k, v]) => ({ host: k, at: v.at, age_h: +((Date.now() - Date.parse(v.at)) / 3.6e6).toFixed(1), verified: v.verified, broken: v.broken, unknown: v.unknown }));
prior[HOSTKEY] = { at: nowISO, verified: n("VERIFIED"), broken: n("BROKEN"), unknown: n("UNKNOWN") };
try { fs.mkdirSync(path.join(ROOT, "sonar"), { recursive: true }); fs.writeFileSync(STATE, JSON.stringify(prior, null, 2)); } catch {}

const payload = { host: HOST, host_key: HOSTKEY, at: nowISO, egress: egressOK(), capabilities: caps, architecture: arch, evidence: ev, repository_cache: repo, experiment: exp, failures: failRows, resource: res, tools, prior_runs_other_hosts: otherHosts };
if (has("--json")) { console.log(JSON.stringify(payload, null, 2)); process.exit(n("BROKEN") ? 1 : 0); }

const M = s => s === "VERIFIED" ? "✓" : s === "BROKEN" ? "✗" : "?";
const L = (t) => console.log(`\n── ${t} ${"─".repeat(Math.max(0, 66 - t.length))}`);
console.log("═══ sonar doctor ═══════════════════════════════════════════════════");
console.log(`  HOST ${HOSTKEY}  node ${HOST.node}  egress=${egressOK() ? "yes" : "NO"}`);
console.log(`  AT   ${nowISO}`);
console.log("  Everything below was re-executed or re-derived just now, on THIS host.");
console.log("  A result from another machine is not evidence about this one.");

L("Q1  what capabilities exist, and do they work HERE?");
for (const r of caps) {
  const tl = T.levelFor("capability." + r.id).level;
  console.log(`  ${M(r.status)} ${r.status.padEnd(8)} ${tl.padEnd(23)} ${r.id.padEnd(22)} ${(r.purpose || "").slice(0, 30)}`);
  if (r.why) console.log(`               └ ${r.why}`);
}
console.log(`  VERIFIED ${n("VERIFIED")} · BROKEN ${n("BROKEN")} · UNKNOWN ${n("UNKNOWN")}   (UNKNOWN is never upgraded)`);
console.log(`  trust ladder: ${T.LEVELS.join(" → ")}`);
console.log(`  evidence chain: ${chain.ok ? "INTACT" : "BROKEN"} over ${chain.count} record(s); ${minted} new record(s) minted this run`);
if (!chain.ok) for (const p of chain.problems.slice(0, 5)) console.log(`    ✗ line ${p.line} ${p.kind} ${p.detail || ""}`);
console.log(`  explain any of them: node sonar-doctor.js --explain capability.<id>`);

L("Q2  what tools are installed on this host?");
console.log("  " + tools.rows.map(t => `${t.present ? "✓" : "✗"}${t.tool}`).join("  "));
for (const t of tools.rows.filter(t => t.present)) console.log(`     ${t.tool.padEnd(8)} ${t.path}`);

L("Q3  what components are actually built?");
for (const r of arch.rows) console.log(`  ${r.git_tracked ? "●" : "○"} ${r.component.padEnd(26)} ${String(r.lines).padStart(5)} lines  ${r.introduced || "UNCOMMITTED"}`);
for (const [k, v] of Object.entries(arch.gaps)) if (v.length) console.log(`  ! ${k}: ${v.join(", ")}`);

L("Q4  what tests prove they work?");
const untested = arch.gaps.no_test_references_it, unrun = arch.gaps.neither_test_nor_gate_runs_it || [];
console.log(`  named by a *-test.js file: ${arch.rows.length - untested.length}/${arch.rows.length}`);
console.log(`  run by a gate runner:      ${arch.rows.filter(r => r.exercised_by_gate).length}/${arch.rows.length}`);
if (untested.length) console.log(`  ! NO UNIT TEST NAMES THESE: ${untested.join(", ")}`);
if (unrun.length) console.log(`  !! NEITHER TESTED NOR RUN BY ANY GATE: ${unrun.join(", ")}`);
console.log("  Note: being named by a test file is the weakest possible evidence of correctness.");
console.log("  The real proofs are --selftest and --adversarial, which fail loudly when faked.");

L("Q5  what data sources are available HERE?");
for (const r of caps.filter(c => c.id.startsWith("source.") || c.id.startsWith("analytics."))) console.log(`  ${M(r.status)} ${r.status.padEnd(8)} ${r.id.padEnd(20)} ${r.limits || ""}`);

L("Q6  what rate limits remain?");
if (res.state !== "LIVE") console.log(`  ? UNKNOWN — ${res.why}. There is no cached rate limit; a cached rate limit is a lie with a timestamp on it.`);
else for (const k of ["core", "search", "code_search", "graphql"]) if (res[k]) console.log(`  ${k.padEnd(12)} ${String(res[k].remaining).padStart(5)} / ${String(res[k].limit).padEnd(5)} resets ${res[k].reset}`);

L("Q7  what experiments have been run?");
console.log(`  cases sealed: ${exp.total_cases_sealed}   ledger entries: ${JSON.stringify(exp.ledger_entry_kinds)}`);
console.log(`  artefacts: ${exp.artefacts.join(", ")}`);

L("Q8  which benchmark cases are contaminated?");
console.log(`  CONFIRMED CONTAMINATED (machine record exists): ${exp.contamination.CONFIRMED_CONTAMINATED.join(", ") || "none"}`);
console.log(`  UNPROVEN (${exp.contamination.UNPROVEN.length}): ${exp.contamination.UNPROVEN.join(", ") || "none"}`);
console.log(`  POLICY: ${exp.contamination.policy}`);

L("Q9  what known failures exist, and are they still real?");
for (const f of failRows) {
  const s = f.detector.state;
  console.log(`  ${s === "STILL_PRESENT" ? "✗" : s === "NOT_DETECTED" ? "✓" : "?"} ${s.padEnd(14)} ${f.id}  [${f.severity}]`);
  console.log(`     ${f.what.slice(0, 150)}`);
  if (f.detector.why) console.log(`     └ ${f.detector.why}`);
}
console.log(`  A defect is not fixed because I say so. It is fixed when its detector stops firing.`);

L("Q10 which repositories and commits were actually analysed?");
if (repo.state !== "OK") console.log(`  ? UNKNOWN — ${repo.why}`);
else {
  for (const r of repo.analysed) console.log(`  ● ${r.repo}@${r.head}`);
  const gap = repo.gaps.named_in_writeups_but_never_recorded_as_read;
  if (gap.length) { console.log(`  ! NAMED IN WRITE-UPS BUT NEVER RECORDED AS READ (${gap.length}) — unverifiable claims:`); console.log("    " + gap.join(", ")); }
}
if (ev.state === "OK" && ev.gaps.claims_with_no_read.length) console.log(`  ! CLAIMS WITH NO BACKING READ: ${ev.gaps.claims_with_no_read.join(", ")}`);

L("Q11 what permanent lessons are frozen?");
const les = R.jsonl("memory/frozen-lessons.jsonl");
if (!les) console.log("  ? UNKNOWN — memory/frozen-lessons.jsonl missing");
else {
  const withCheck = les.filter(l => l.check && String(l.check).trim()).length;
  console.log(`  ${les.length} frozen lessons; ${withCheck} carry a check, ${les.length - withCheck} are prose only.`);
  console.log(`  Prose-only lessons cannot be enforced by any machine. They rely on me remembering, which is the thing that fails.`);
}

L("Q12 which verifications are stale?");
console.log(`  NONE in this report — every line above was recomputed seconds ago on ${HOSTKEY}.`);
console.log(`  Anything you read in a document instead of running is stale by definition.`);
if (priorHere) console.log(`  previous run here: ${priorHere.at} (${((Date.now() - Date.parse(priorHere.at)) / 3.6e6).toFixed(1)}h ago) → V${priorHere.verified}/B${priorHere.broken}/U${priorHere.unknown}`);
for (const o of otherHosts) console.log(`  OTHER HOST ${o.host}: ${o.at} (${o.age_h}h ago) → V${o.verified}/B${o.broken}/U${o.unknown}  — NOT evidence about this host`);

console.log("\n═══════════════════════════════════════════════════════════════════");
console.log(`  ${M(n("BROKEN") ? "BROKEN" : "VERIFIED")} exit ${n("BROKEN") ? 1 : 0}   audit: --show-checks · prove: --selftest, --adversarial`);
process.exit(n("BROKEN") ? 1 : 0);
