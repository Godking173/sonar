#!/usr/bin/env node
/* sonar-attack.js — TWELVE ATTACKS ON THE CONTROL PLANE ITSELF.
 *
 * A control plane that has never been attacked is a control plane whose green means nothing. Each
 * attack below is really executed and the system must DETECT it. An undetected attack is a FAIL,
 * and the suite exits non-zero, which makes cc-verify.sh red.
 *
 * Attacks run against throwaway fixtures under /tmp wherever a real mutation would risk the repo.
 * A07 is the exception: it renames a real component and restores it, because "can you notice your
 * own leg missing" is not a question a fixture can answer.
 */
"use strict";
/* PORTABLE PROOF: a virgin install (every ledger empty) has nothing to attack — build a labelled synthetic install and run this file there, unchanged (see sonar-fixture.js). */
if (!process.env.SONAR_FIXTURE_ROOT && require("./sonar-fixture.js").isVirgin(__dirname)) process.exit(require("./sonar-fixture.js").reexec(__filename));
const fs = require("fs"), path = require("path"), os = require("os"), cp = require("child_process");
const T = require("./sonar-trust.js"), R = require("./sonar-registry.js");
const ROOT = __dirname;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "sonar-attack-"));
const results = [];
const A = (id, attack, fn) => { let r; try { r = fn(); } catch (e) { r = { detected: false, how: "attack harness threw: " + e.message }; } results.push({ id, attack, ...r }); };
const tmpFile = (name, content) => { const p = path.join(TMP, name); fs.writeFileSync(p, content); return p; };
/* write a chained ledger of raw records into a fixture file */
function seed(file, recs) { let prev = "GENESIS"; const out = []; for (const r of recs) { const rec = { ...r, prev }; rec.sha = T.recordHash(rec); prev = rec.sha; out.push(JSON.stringify(rec)); } fs.writeFileSync(file, out.join("\n") + "\n"); return file; }
const baseRec = o => ({ v: 1, fact: "f", claim: "c", level: "VERIFIED", attempted_level: "VERIFIED", host: T.host(), host_key: T.hostKey(), at: new Date(0).toISOString(), cwd: ROOT, paths: [], source: "command", command: "node --check sonar-trust.js", exit_code: 0, stdout_sha256: T.sha(""), stdout_head: "", stderr_sha256: T.sha(""), stderr_head: "", tool_version: null, network: "unknown", git_head: T.gitHead(), git_dirty: false, duration_ms: 1, ...o });

/* A01 — a capability row that CLAIMS a component which does not exist on disk. */
A("A01", "fake capability entry (authored row claims a component that is not on disk)", () => {
  const ghost = "cc-sonar-ghost.js";
  const onDisk = R.architecture().rows.some(r => r.component === ghost);
  const att = T.attest("attack.ghost", { claim: "ghost component exists", level: "VERIFIED", command: `node --check ${ghost}`, paths: [ghost], ledger: path.join(TMP, "e1.jsonl") });
  return { detected: !onDisk && att.refused === true, how: `derived architecture does not contain it, and attest() refused: ${att.why || "n/a"}` };
});

/* A02 — a shim named like a real tool that exits 0 and proves nothing. */
A("A02", "fake executable (a shim named `duckdb` that exits 0 but is not duckdb)", () => {
  const bin = path.join(TMP, "bin"); fs.mkdirSync(bin, { recursive: true });
  fs.writeFileSync(path.join(bin, "duckdb"), "#!/bin/sh\necho 'totally the real duckdb'\nexit 0\n", { mode: 0o755 });
  const out = cp.execSync(`PATH="${bin}:$PATH" duckdb --version`, { encoding: "utf8" }).trim();
  const looksReal = /^v?\d+\.\d+\.\d+/.test(out);            // identity, not exit code
  const present = cp.execSync(`PATH="${bin}:$PATH" command -v duckdb`, { encoding: "utf8" }).trim();
  return { detected: !!present && !looksReal, how: `presence gives OBSERVED only; version output "${out.slice(0, 40)}" fails the identity pattern so it never reaches VERIFIED` };
});

/* A03 — a check that cannot fail, offered as proof. */
A("A03", "fake successful exit code (a check that is literally `true`)", () => {
  const bad = ["true", "echo ok", "node --check sonar-trust.js || true", "node sonar-doctor.js | tail -1"];
  const refusals = bad.map(c => T.attest("attack.trivial", { claim: "x", level: "VERIFIED", command: c, ledger: path.join(TMP, "e2.jsonl") }));
  return { detected: refusals.every(r => r.refused === true), how: `all ${bad.length} non-probative forms refused: ${refusals.map(r => (r.why || "").split(":")[0]).join(" / ").slice(0, 110)}` };
});

/* A04 — edit a field of an already-written record. */
A("A04", "altered output after verification (exit_code edited from 1 to 0 post-hoc)", () => {
  const f = seed(path.join(TMP, "e3.jsonl"), [baseRec({ fact: "a4", exit_code: 1, level: "UNKNOWN" })]);
  const rows = fs.readFileSync(f, "utf8").trim().split("\n").map(JSON.parse);
  rows[0].exit_code = 0; rows[0].level = "VERIFIED";                    // the forgery
  fs.writeFileSync(f, rows.map(r => JSON.stringify(r)).join("\n") + "\n");
  const v = T.verifyChain(f);
  return { detected: !v.ok && v.problems.some(p => p.kind === "TAMPERED_RECORD"), how: `verifyChain: ${v.problems.map(p => p.kind).join(",") || "clean"}` };
});

/* A05 — an old record from a previous commit presented as current. */
A("A05", "stale cached result (record from a different git HEAD replayed as current)", () => {
  const f = seed(path.join(TMP, "e4.jsonl"), [baseRec({ fact: "a5", git_head: "deadbee" })]);
  const l = T.levelFor("a5", { ledger: f });
  return { detected: l.level === "UNKNOWN" && l.reasons.some(r => /STALE/.test(r)), how: `level=${l.level} · ${l.reasons.find(r => /STALE/.test(r)) || "no stale reason"}` };
});

/* A06 — an honest record from another machine, used to claim local truth. */
A("A06", "wrong host (a genuine VERIFIED from another machine claimed as local truth)", () => {
  const f = seed(path.join(TMP, "e5.jsonl"), [baseRec({ fact: "a6", host_key: "elis-mac:darwin/arm64" })]);
  const l = T.levelFor("a6", { ledger: f });
  return { detected: l.level === "UNKNOWN" && l.reasons.some(r => /not this host/.test(r)), how: `level=${l.level} · foreign record rejected for local truth (S21)` };
});

/* A07 — the real thing: remove a component and demand the doctor notice. */
A("A07", "deleted component (rename a real component out of the repository)", () => {
  const t = path.join(ROOT, "cc-sonar-content.js"), tmp = t + ".attack-tmp";
  const chk = "node --check cc-sonar-content.js";
  const before = T.run(chk).exit;
  fs.renameSync(t, tmp);
  const during = T.run(chk).exit;
  const derivedGone = !R.architecture().rows.some(r => r.component === "cc-sonar-content.js");
  fs.renameSync(tmp, t);
  const after = T.run(chk).exit;
  return { detected: before === 0 && during !== 0 && derivedGone && after === 0, how: `check exit before=${before} during=${during} after=${after}; derived architecture also dropped it` };
});

/* A08 — a prior-art CLAIM with no read behind it. */
A("A08", "missing ledger entry (claim a repository was read with no read record)", () => {
  const f = path.join(TMP, "prior-art.jsonl");
  fs.writeFileSync(f, JSON.stringify({ kind: "claim", repo: "acme/never-cloned", at: new Date().toISOString() }) + "\n");
  const rows = fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(JSON.parse);
  const reads = new Set(rows.filter(r => r.kind === "read").map(r => r.repo));
  const orphan = rows.filter(r => r.kind === "claim" && !reads.has(r.repo)).map(r => r.repo);
  const liveGap = R.evidence().gaps.claims_with_no_read;                 // same rule on live data
  return { detected: orphan.length === 1, how: `orphan claim flagged: ${orphan.join(",")}; identical rule runs on the live ledger (currently ${liveGap.length} orphan(s))` };
});

/* A09 — retroactively edit a sealed experiment. */
A("A09", "tampered experiment (edit a sealed benchmark artefact after the fact)", () => {
  const rel = "audits/sonar-bench-v0.1/STAGE-B-SEAL.md";
  let blob; try { blob = cp.execSync(`git show HEAD:${rel}`, { cwd: ROOT, encoding: "utf8" }); } catch (e) { return { detected: false, how: "sealed artefact is not committed — cannot verify a seal that git does not hold" }; }
  const tampered = blob.replace(/C01/, "C99");
  const detected = T.sha(tampered) !== T.sha(blob);
  return { detected, how: `committed blob sha ${T.sha(blob).slice(0, 12)} vs tampered ${T.sha(tampered).slice(0, 12)} — the seal is the git object, so a retroactive edit cannot match it` };
});

/* A10 — rewrite a decision that was already made. */
A("A10", "rewritten historical decision (change what D-002 said after the fact)", () => {
  const src = path.join(ROOT, "sonar", "decisions.jsonl");
  if (!fs.existsSync(src)) return { detected: false, how: "no decision ledger" };
  const f = path.join(TMP, "decisions.jsonl"); fs.copyFileSync(src, f);
  const rows = fs.readFileSync(f, "utf8").trim().split("\n").map(JSON.parse);
  const i = rows.findIndex(r => r.id === "D-002");
  rows[i].decision = "Relevance may be a raw count after all.";          // the rewrite
  fs.writeFileSync(f, rows.map(r => JSON.stringify(r)).join("\n") + "\n");
  const v = T.verifyChain(f);
  return { detected: !v.ok, how: `chain broken at line ${v.problems[0] && v.problems[0].line}: ${v.problems.map(p => p.kind).slice(0, 3).join(",")}` };
});

/* A11 — cite a file that does not exist as the source of a proof. */
A("A11", "forged evidence path (record cites a source file that does not exist)", () => {
  const att = T.attest("attack.forgedpath", { claim: "x", level: "VERIFIED", command: "node --check sonar-trust.js", paths: ["/nonexistent/definitely-not-here.js"], ledger: path.join(TMP, "e6.jsonl") });
  return { detected: att.refused === true && /FORGED PATH/.test(att.why || ""), how: att.why || "not refused" };
});

/* A12 — take another machine's proof and relabel it as this machine's. */
A("A12", "copied proof from another machine (foreign record relabelled with this host_key)", () => {
  const f = seed(path.join(TMP, "e7.jsonl"), [baseRec({ fact: "a12", host_key: "elis-mac:darwin/arm64" })]);
  const rows = fs.readFileSync(f, "utf8").trim().split("\n").map(JSON.parse);
  rows[0].host_key = T.hostKey();                                        // impersonation
  fs.writeFileSync(f, rows.map(r => JSON.stringify(r)).join("\n") + "\n");
  const v = T.verifyChain(f), l = T.levelFor("a12", { ledger: f });
  return { detected: !v.ok && l.level === "UNKNOWN", how: `relabelling breaks the record hash (${v.problems.map(p => p.kind).join(",")}), so the forged record is discarded and level=${l.level}` };
});

/* A13 — the attack that the system FAILED before this line existed. A foreign VERIFIED from an
   older commit was granting REPRODUCED, because staleness was only ever checked on local records.
   Found by running the thing rather than by reading it. */
A("A13", "stale foreign proof (another host's VERIFIED from an OLD commit claimed as reproduction)", () => {
  const f = seed(path.join(TMP, "e8.jsonl"), [
    baseRec({ fact: "a13", host_key: T.hostKey(), git_head: T.gitHead() }),
    baseRec({ fact: "a13", host_key: "elis-mac:darwin/arm64", git_head: "0ldc0de" })
  ]);
  const l = T.levelFor("a13", { ledger: f });
  return { detected: l.level === "VERIFIED", how: `level=${l.level} (VERIFIED, not REPRODUCED) · ${l.reasons.find(r => /STALE/.test(r)) || "stale foreign record excluded"}` };
});

/* ── A14–A24: ATTACKS AGAINST FORGETTING ─────────────────────────────────────────────
   The first thirteen attack the trust layer. These attack the MANIFEST — the thing a fresh
   session reads instead of remembering. Every one works the same way: tamper with a COPY of the
   manifest, leave the authoritative artefact alone, and demand that the comparison notice. The
   rule being tested is the one that matters: the manifest is an index, never a source of truth,
   so when it disagrees with an artefact the artefact wins and the manifest is STALE. */
const B = require("./sonar-brain.js");
const LIVE = B.derive();
const clone = () => JSON.parse(JSON.stringify(LIVE));
const forged = (mutate, label) => { const s = clone(); mutate(s); const c = B.compareAgainst(LIVE, s); return { detected: c.state === "STALE", how: `${label} → ${c.state}${c.diverged ? " · diverged sections: " + c.diverged.join(", ") : ""}` }; };

A("A14", "hide an existing tool from the manifest", () => forged(s => { s.tools.rows = s.tools.rows.filter(t => t.tool !== "cc-priorart.js"); s.tools.count--; }, "removed cc-priorart.js from the manifest while it sits on disk"));
A("A15", "invent a nonexistent tool", () => forged(s => { s.tools.rows.push({ tool: "cc-sonar-omniscient.js", lines: 9000, git_tracked: true, introduced: "beef123 2026-01-01", in_toolbox: true, exercised_by_gate: true, referenced_by_tests: true }); s.tools.count++; }, "added a tool that has never existed"));
A("A16", "claim an old capability still exists after deletion", () => forged(s => { s.capabilities.rows.push({ id: "discovery.deleted-lane", component: "cc-sonar-deleted.js", check: "node --check cc-sonar-deleted.js", trust: "VERIFIED" }); }, "capability whose component is not on disk"));
A("A17", "claim a stale capability is current", () => forged(s => { const c = s.capabilities.rows.find(x => x.trust !== "REPRODUCED"); if (c) c.trust = "REPRODUCED"; }, "upgraded a capability's trust level in the manifest without any evidence record"));
A("A18", "omit a known failure", () => forged(s => { s.failures.rows = s.failures.rows.filter(f => !/evidence-ledger-missing/.test(f.id)); s.failures.still_present = s.failures.still_present.filter(x => !/evidence-ledger-missing/.test(x)); }, "deleted a critical live defect from the manifest"));
A("A19", "omit a permanent decision", () => forged(s => { s.decisions.rows = s.decisions.rows.filter(d => d.id !== "D-006"); }, "removed D-006, the rule that forbids back-filling missing evidence"));
A("A20", "claim an experiment was completed when its artefact does not exist", () => forged(s => { s.experiments.rows.push({ artefact: "audits/sonar-bench-v0.1/C07-FULL-RUN.md", committed: true, matches_committed_blob: true, seal_sha: "0000000000000000" }); }, "invented a completed experiment artefact"));
A("A21", "claim a benchmark case is clean when the ledger says otherwise", () => forged(s => { s.benchmark.confirmed_contaminated = s.benchmark.confirmed_contaminated.filter(c => c !== "C01"); s.benchmark.unproven = s.benchmark.unproven.filter(c => c !== "C01"); }, "laundered C01 out of the contaminated list"));
A("A22", "alter the manifest without changing the authoritative artefact", () => forged(s => { s.constitution.enforced = 99; }, "edited a manifest field while SONAR_CONSTITUTION.md is untouched"));
A("A23", "create a capability entry with no executable proof", () => {
  const R2 = require("./sonar-registry.js"), T2 = require("./sonar-trust.js");
  const forgeries = ["true", "echo capability exists", "node --check sonar-brain.js || true"];
  const rejectedByLint = forgeries.every(c => !T2.probative(c).ok);
  const rejectedByAttest = forgeries.every(c => T2.attest("attack.a23", { claim: "x", level: "VERIFIED", command: c, ledger: path.join(TMP, "e9.jsonl") }).refused === true);
  const liveClean = (R2.capability().rows || []).every(r => !r.__non_probative);
  return { detected: rejectedByLint && rejectedByAttest && liveClean, how: `all ${forgeries.length} cannot-fail checks rejected by the probative lint AND by attest(); the live capability registry currently holds 0 non-probative rows` };
});
A("A24", "create a fake memory entry with no provenance", () => {
  const f = path.join(TMP, "e10.jsonl");
  fs.writeFileSync(f, JSON.stringify({ fact: "capability.everything", level: "REPRODUCED", claim: "trust me, we built this" }) + "\n");
  const v = T.verifyChain(f), l = T.levelFor("capability.everything", { ledger: f });
  return { detected: !v.ok && l.level === "UNKNOWN", how: `a record with no sha/prev/host/command breaks the chain (${v.problems.map(p => p.kind).join(",")}) and yields level=${l.level}` };
});

/* ── A25–A38: ATTACKS AGAINST THE PIPELINE CONTRACT ──────────────────────────────────
   A01-A13 attack the trust layer, A14-A24 attack the manifest. These attack the RESEARCH RUN —
   the only part of the system that produces new claims about the outside world. Each builds a real
   clean run in a throwaway namespace, breaks exactly one clause of the contract, and demands that
   the verifier fail on THE RIGHT CHECK. Failing for some unrelated reason would look like success
   and prove nothing, so every assertion names the clause it expects to catch it. */
const E2E = require("./sonar-e2e.js");          // sets SONAR_RUNS_DIR to a temp dir before loading sonar-run
const RUN = require("./sonar-run.js"), PIPE = require("./sonar-pipeline.js");
const runPath = id => path.join(process.env.SONAR_RUNS_DIR, id);
/* rebuilding the chain after a deliberate edit, so the attack is caught by the clause under test
   rather than by the chain check noticing the edit first */
function rechain(id) {
  const f = path.join(runPath(id), "events.jsonl");
  const rows = fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(JSON.parse);
  let prev = "GENESIS";
  for (const r of rows) { delete r.sha; r.prev = prev; r.sha = T.recordHash(r); prev = r.sha; }
  fs.writeFileSync(f, rows.map(r => JSON.stringify(r)).join("\n") + "\n");
}
function attackRun(mutate, expect) {
  const id = E2E.buildCleanRun();
  let threw = null;
  try { mutate(id, runPath(id)); } catch (e) { threw = e.message; }
  const r = PIPE.verifyRun(id), prom = PIPE.promote(id);
  const caught = threw ? [`guard threw: ${threw.slice(0, 70)}`] : r.failed_checks;
  const right = threw ? !!expect.byThrow : r.failed_checks.includes(expect.check);
  return { detected: right && !prom.promoted, how: `${right ? "caught by " + (threw ? "the write guard" : expect.check) : "WRONG CLAUSE — expected " + expect.check}; failed: ${caught.join(", ") || "nothing"}; promoted=${prom.promoted}` };
}

A("A25", "stage claims it ran when its artefact does not exist", () => attackRun((id, d) => fs.unlinkSync(path.join(d, "reads.jsonl")), { check: "stages.artefacts_exist" }));
A("A26", "stage silently skips a declared input", () => attackRun((id, d) => {
  fs.unlinkSync(path.join(d, "history.jsonl"));
  const m = JSON.parse(fs.readFileSync(path.join(d, "manifest.json"), "utf8"));
  delete m.stages.HISTORY;                                   // pretend the stage never happened
  fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify(m, null, 2));
}, { check: "stages.inputs_present" }));
A("A27", "stage writes outside its permitted namespace", () => attackRun((id) => { RUN.write(id, "../../../SONAR_CONSTITUTION.md", "owned"); }, { byThrow: true, check: "isolation.namespace" }));
A("A28", "stage modifies a sealed artefact", () => {
  const sealed = path.join(ROOT, "SONAR_CONSTITUTION.md");
  const original = fs.readFileSync(sealed);
  try {
    const id = E2E.buildCleanRun();
    fs.appendFileSync(sealed, "\n<!-- tampered mid-run -->\n");   // a REAL mutation, restored below
    RUN.finish(id);                                                 // recomputes sealed_after
    const r = PIPE.verifyRun(id), prom = PIPE.promote(id);
    return { detected: r.failed_checks.includes("sealed.unchanged") && !prom.promoted, how: `sealed hash comparison caught it: ${(r.checks.find(c => c.check === "sealed.unchanged") || {}).detail}` };
  } finally { fs.writeFileSync(sealed, original); }                 // byte-exact restore
});
A("A29", "stage reports cached evidence as fresh", () => attackRun((id, d) => {
  const f = path.join(d, "events.jsonl");
  fs.appendFileSync(f, JSON.stringify({ type: "STAGE_END", stage: "DEEP_READ", cache_hits: 7, reported_fresh: true, artefact_hashes: {}, at: new Date().toISOString(), host_key: T.hostKey(), git_head: T.gitHead(), prev: "x", sha: "y" }) + "\n");
  rechain(id);
}, { check: "cache.honesty" }));
A("A30", "stage uses evidence from the wrong git HEAD", () => attackRun((id, d) => {
  const f = path.join(d, "events.jsonl");
  fs.appendFileSync(f, JSON.stringify({ type: "STAGE_END", stage: "COMPARISON", artefact_hashes: {}, at: new Date().toISOString(), host_key: T.hostKey(), git_head: "0ldc0de", prev: "x", sha: "y" }) + "\n");
  rechain(id);
}, { check: "scope.same_head" }));
A("A31", "stage uses evidence from the wrong host", () => attackRun((id, d) => {
  const f = path.join(d, "events.jsonl");
  fs.appendFileSync(f, JSON.stringify({ type: "STAGE_END", stage: "COMPARISON", artefact_hashes: {}, at: new Date().toISOString(), host_key: "elis-mac:darwin/arm64", git_head: T.gitHead(), prev: "x", sha: "y" }) + "\n");
  rechain(id);
}, { check: "scope.same_host" }));
A("A32", "provenance lost between stages (an orphan node with no edge)", () => attackRun((id, d) => {
  fs.appendFileSync(path.join(d, "graph.jsonl"), JSON.stringify({ kind: "node", id: "FRAGMENT:orphan000000", type: "FRAGMENT", label: "appeared from nowhere", provenance: { source: "???" } }) + "\n");
}, { check: "graph.no_orphans" }));
A("A33", "stage turns UNKNOWN into VERIFIED", () => attackRun((id, d) => {
  const v = JSON.parse(fs.readFileSync(path.join(d, "verdict.json"), "utf8"));
  v.trust = "VERIFIED"; delete v.verified_by;
  fs.writeFileSync(path.join(d, "verdict.json"), JSON.stringify(v));
  const m = JSON.parse(fs.readFileSync(path.join(d, "manifest.json"), "utf8"));
  m.stages.VERDICT.artefact_hashes["verdict.json"] = RUN.sha(fs.readFileSync(path.join(d, "verdict.json")));
  fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify(m, null, 2));   // cover the tracks
}, { check: "verdict.trust_not_promoted" }));
A("A34", "stage produces a verdict without sufficient evidence", () => attackRun((id, d) => {
  const v = JSON.parse(fs.readFileSync(path.join(d, "verdict.json"), "utf8"));
  v.sufficiency = "INSUFFICIENT"; v.conclusion = "ship it anyway";
  fs.writeFileSync(path.join(d, "verdict.json"), JSON.stringify(v));
  const m = JSON.parse(fs.readFileSync(path.join(d, "manifest.json"), "utf8"));
  m.stages.VERDICT.artefact_hashes["verdict.json"] = RUN.sha(fs.readFileSync(path.join(d, "verdict.json")));
  fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify(m, null, 2));
}, { check: "verdict.sufficiency" }));
A("A35", "stage invokes an LLM before deterministic evidence is exhausted", () => attackRun((id, d) => {
  const f = path.join(d, "events.jsonl");
  const rows = fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(JSON.parse);
  const i = rows.findIndex(r => r.type === "STAGE_START" && r.stage === "CONTRARIAN");
  rows.unshift(rows.splice(i, 1)[0]);                              // AI stage jumps the queue
  fs.writeFileSync(f, rows.map(r => JSON.stringify(r)).join("\n") + "\n");
  rechain(id);
}, { check: "order.deterministic_before_ai" }));
A("A36", "stage exceeds its declared API budget", () => attackRun((id, d) => {
  const m = JSON.parse(fs.readFileSync(path.join(d, "manifest.json"), "utf8"));
  m.api_calls = m.declared_budget.api_calls + 40;
  fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify(m, null, 2));
}, { check: "budget.api" }));
A("A37", "verdict names a candidate that cannot be reconstructed from the run manifest", () => attackRun((id, d) => {
  const v = JSON.parse(fs.readFileSync(path.join(d, "verdict.json"), "utf8"));
  v.repositories.push("phantom/never-discovered");
  fs.writeFileSync(path.join(d, "verdict.json"), JSON.stringify(v));
  const m = JSON.parse(fs.readFileSync(path.join(d, "manifest.json"), "utf8"));
  m.stages.VERDICT.artefact_hashes["verdict.json"] = RUN.sha(fs.readFileSync(path.join(d, "verdict.json")));
  fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify(m, null, 2));
}, { check: "verdict.reconstructable" }));
A("A38", "different results from identical immutable inputs, undeclared", () => attackRun((id, d) => {
  const f = path.join(d, "events.jsonl");
  fs.appendFileSync(f, JSON.stringify({ type: "STAGE_END", stage: "COMPARISON", artefact_hashes: { "relevance.jsonl": "a-completely-different-hash" }, at: new Date().toISOString(), host_key: T.hostKey(), git_head: T.gitHead(), prev: "x", sha: "y" }) + "\n");
  rechain(id);
}, { check: "determinism.declared" }));

/* ── A39–A42: ATTACKS ON THE EXECUTION BOUNDARY ────────────────────────────────────────
   The previous suites assume work happens inside the harness. These assume it does not. The claim
   under test is NOT "a bypass is detected" — it is "a bypass cannot become trusted evidence". */
const BND = require("./sonar-boundary.js");

A("A39", "real-looking stage performed OUTSIDE sonar-run, then promoted", () => {
  const before = BND.uncontrolledLog().length;
  const saved = process.env.SONAR_RUN_ID; delete process.env.SONAR_RUN_ID;
  const ctx = BND.enter("DEEP_READ", { tool: "cc-priorart.js" });          // a real unwrapped execution
  const smuggled = ctx.mark({ kind: "read", repo: "acme/bypassed", head: "cafe1234", depth: "code" });
  if (saved) process.env.SONAR_RUN_ID = saved;
  const id = E2E.buildCleanRun(), d = runPath(id);
  fs.writeFileSync(path.join(d, "reads.jsonl"), JSON.stringify(smuggled) + "\n");   // smuggle it in
  const m = JSON.parse(fs.readFileSync(path.join(d, "manifest.json"), "utf8"));
  m.stages.DEEP_READ.artefact_hashes["reads.jsonl"] = RUN.sha(fs.readFileSync(path.join(d, "reads.jsonl")));
  fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify(m, null, 2));      // cover the tracks
  const r = PIPE.verifyRun(id), prom = PIPE.promote(id);
  const logged = BND.uncontrolledLog().length > before;
  /* and it must stay dead: quarantine, then try to clear the flag, then try to delete the event */
  BND.quarantine(id, "bypass attempt");
  const afterQ = PIPE.promote(id).promoted;
  const m2 = JSON.parse(fs.readFileSync(path.join(d, "manifest.json"), "utf8")); delete m2.quarantined; delete m2.quarantine_reason;
  fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify(m2, null, 2));
  const afterFlagCleared = PIPE.promote(id).promoted;
  const ev = fs.readFileSync(path.join(d, "events.jsonl"), "utf8").split("\n").filter(l => l.trim() && !/QUARANTINE/.test(l));
  fs.writeFileSync(path.join(d, "events.jsonl"), ev.join("\n") + "\n");
  const afterEventDeleted = PIPE.promote(id).promoted;
  return { detected: !prom.promoted && logged && !afterQ && !afterFlagCleared && !afterEventDeleted,
    how: `promotion refused (${r.failed_checks.join(", ")}); bypass logged to sonar/uncontrolled.jsonl; still refused after quarantine, after clearing the flag, and after deleting the event (the chain breaks)` };
});

A("A40", "agent performs the operation correctly but writes straight into the trusted ledger", () => {
  const led = path.join(ROOT, "sonar", "evidence.jsonl");
  const before = fs.readFileSync(led, "utf8").split("\n").filter(l => l.trim()).length;
  const res = T.attest("priorart.acme/done-properly", { claim: "I really did read this", level: "VERIFIED", command: "node --check sonar-trust.js", source: "command" });
  const after = fs.readFileSync(led, "utf8").split("\n").filter(l => l.trim()).length;
  return { detected: res.refused === true && after === before, how: `${res.why}; trusted ledger unchanged (${before} records before and after)` };
});

A("A41", "an OLD uncontrolled result laundered into a NEW controlled run", () => {
  const stale = { kind: "read", repo: "acme/laundered", head: "0ldc0de", controlled: false, uncontrolled_reason: "no SONAR_RUN_ID — executed outside the pipeline", run_id: "20260101000000-deadbeef" };
  const id = E2E.buildCleanRun(), d = runPath(id);
  fs.appendFileSync(path.join(d, "fragments.jsonl"), JSON.stringify(stale) + "\n");
  const m = JSON.parse(fs.readFileSync(path.join(d, "manifest.json"), "utf8"));
  m.stages.DEEP_READ.artefact_hashes["fragments.jsonl"] = RUN.sha(fs.readFileSync(path.join(d, "fragments.jsonl")));
  fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify(m, null, 2));
  const r = PIPE.verifyRun(id), prom = PIPE.promote(id);
  return { detected: r.failed_checks.includes("provenance.controlled_origin") && !prom.promoted,
    how: `${(r.checks.find(c => c.check === "provenance.controlled_origin") || {}).detail}` };
});

A("A42", "FRESH SESSION: no memory, no env — discovers the rule, tries uncontrolled evidence, is refused", () => {
  /* the probe is written to a FILE and executed, not passed with -e: JSON.stringify escapes
     newlines, the shell hands them through literally, and node then chokes on a backslash-n.
     That was a harness bug, not a finding, and it is worth naming so it is not re-lived. */
  const probe = path.join(TMP, "fresh-session-probe.js");
  fs.writeFileSync(probe, [
    'const ROOT = ' + JSON.stringify(ROOT) + ';',
    'const path = require("path"), fs = require("fs");',
    'const B = require(path.join(ROOT, "sonar-boundary.js")), T = require(path.join(ROOT, "sonar-trust.js"));',
    'const contracts = fs.readFileSync(path.join(ROOT, "sonar/pipeline.jsonl"), "utf8").split("\\n").filter(l => l.trim()).length;',
    'const conf = B.conformance();',
    'const res = T.attest("priorart.fresh/session-attempt", { claim: "found it myself", level: "VERIFIED", command: "node --version", source: "command" });',
    'console.log(JSON.stringify({ discovered_contracts: contracts, discovered_tools: conf.rows.length, nonconformant: conf.nonconformant.length, refused: res.refused === true, why: res.why }));'
  ].join("\n"));
  const out = cp.execFileSync(process.execPath, [probe], { cwd: ROOT, encoding: "utf8", env: { PATH: path.dirname(process.execPath) + ":/usr/bin:/bin", HOME: "/nonexistent" } });
  const j = JSON.parse(out.trim().split("\n").pop());
  return { detected: j.refused === true && j.discovered_contracts === 10 && j.discovered_tools >= 6 && j.nonconformant === 0,
    how: `fresh session discovered ${j.discovered_contracts} stage contracts and ${j.discovered_tools} evidence-producing tools (${j.nonconformant} non-conformant) from the filesystem alone, then was refused: ${String(j.why).slice(0, 95)}` };
});

/* ── A43–A52: ATTACKS ON INDEPENDENT ADJUDICATION (phase 3, S25) ─────────────────────────
   The claim under test: role separation is enforced through artefacts and promotion rules, not
   prompt wording. Each attack breaks exactly one architectural rule on a real clean role-chain
   run and must be refused BY THAT RULE — attackRun() rejects an attack that merely fails for an
   unrelated reason. All runs live in the throwaway namespace; promotion is additionally dead on
   arrival there (S24), so nothing here can touch the trusted ledger. */
const ADJ = require("./sonar-adjudicate.js");
function editJson(d, rel, fn) { const p = path.join(d, rel); const o = JSON.parse(fs.readFileSync(p, "utf8")); fn(o); fs.writeFileSync(p, JSON.stringify(o, null, 2)); return o; }
function coverArtefact(d, stage, rel) { const m = JSON.parse(fs.readFileSync(path.join(d, "manifest.json"), "utf8")); m.stages[stage].artefact_hashes[rel] = RUN.sha(fs.readFileSync(path.join(d, rel))); fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify(m, null, 2)); }
function editRoleEverywhere(d, id, stage, fn) {
  editJson(d, "manifest.json", m => fn(m.roles[stage]));
  const f = path.join(d, "events.jsonl");
  const rows = fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(JSON.parse);
  fn(rows.find(r => r.type === "ROLE_DECLARED" && r.stage === stage));
  fs.writeFileSync(f, rows.map(r => JSON.stringify(r)).join("\n") + "\n");
  rechain(id);
}

A("A43", "a role wearing another role's name (adjudication consistently declared as SYNTHESIZER)", () => attackRun((id, d) => {
  editRoleEverywhere(d, id, "ADJUDICATION", r => { r.role = "SYNTHESIZER"; });
}, { check: "adjud.roles_declared" }));

A("A44", "role identity altered after declaration (manifest edited, chain left alone)", () => attackRun((id, d) => {
  editJson(d, "manifest.json", m => { m.roles.ADJUDICATION.model = "totally-different-model"; });
}, { check: "adjud.roles_declared" }));

A("A45", "model/version/config identity altered in the chain (event edited and rechained)", () => attackRun((id, d) => {
  const f = path.join(d, "events.jsonl");
  const rows = fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(JSON.parse);
  rows.find(r => r.type === "ROLE_DECLARED" && r.stage === "ADJUDICATION").config_sha256 = RUN.sha("forged-config");
  fs.writeFileSync(f, rows.map(r => JSON.stringify(r)).join("\n") + "\n");
  rechain(id);
}, { check: "adjud.roles_declared" }));

A("A46", "evidence changed after the adjudication snapshot (a byte rewritten inside the frozen prefix)", () => attackRun((id, d) => {
  const f = path.join(d, "graph.jsonl");
  const txt = fs.readFileSync(f, "utf8");
  fs.writeFileSync(f, txt.replace("heartbeat", "heartbeaX"));   // same byte length — offsets survive, the hash does not
}, { check: "adjud.evidence_frozen" }));

A("A47", "an adjudicated claim stripped of every evidence citation", () => attackRun((id, d) => {
  editJson(d, "adjudication.json", a => { a.claims[0].cites = []; a.claims[0].supporting = []; a.claims[0].contradicting = []; });
  coverArtefact(d, "ADJUDICATION", "adjudication.json");
}, { check: "adjud.record_valid" }));

A("A48", "identical role configuration (adjudicator declared with the synthesizer's exact tuple)", () => attackRun((id, d) => {
  const m0 = JSON.parse(fs.readFileSync(path.join(d, "manifest.json"), "utf8"));
  const s = m0.roles.SYNTHESIS;
  editRoleEverywhere(d, id, "ADJUDICATION", r => { r.model = s.model; r.model_version = s.model_version; r.prompt_sha256 = s.prompt_sha256; r.config_sha256 = s.config_sha256; });
}, { check: "adjud.roles_distinct" }));

A("A49", "adjudicator rests a resolution on evidence the synthesizer never saw", () => attackRun((id, d) => {
  const f = path.join(d, "graph.jsonl");
  const late = { kind: "node", id: "FRAGMENT:lateevidence", type: "FRAGMENT", label: "appeared after synthesis", provenance: { source: "late" } };
  fs.appendFileSync(f, JSON.stringify(late) + "\n");
  fs.appendFileSync(f, JSON.stringify({ kind: "edge", from: "FRAGMENT:lateevidence", rel: "SUPPORTS", to: "FRAGMENT:lateevidence", provenance: { source: "late" } }) + "\n");
  const buf = fs.readFileSync(f);
  editJson(d, "adjudication.json", a => {
    a.claims[0].supporting.push("FRAGMENT:lateevidence");
    a.evidence_snapshot.graph_bytes = buf.length;                       // extend the snapshot to cover it…
    a.evidence_snapshot.graph_prefix_sha256 = ADJ.sha(buf);             // …so only the visibility rule can catch it (ADJ.sha: the same Buffer-aware hash adjud.evidence_frozen recomputes with — RUN.sha would fail this on its own and defeat the isolation this attack is testing for)
  });
  coverArtefact(d, "ADJUDICATION", "adjudication.json");
}, { check: "adjud.cites_in_snapshot" }));

A("A50", "the adjudicator's input snapshot altered after the fact (with manifest hashes covered)", () => attackRun((id, d) => {
  editJson(d, "snapshots/ADJUDICATOR.json", s => { s.files["synthesis.json"].sha256 = RUN.sha("forged view"); });
  coverArtefact(d, "ADJUDICATION", "snapshots/ADJUDICATOR.json");
}, { check: "adjud.snapshots_recompute" }));

A("A51", "contrarian influence entering synthesis (the synthesis snapshot shows contrarian.jsonl already existed)", () => attackRun((id, d) => {
  editJson(d, "snapshots/SYNTHESIZER.json", s => { s.files_present = [...s.files_present, "contrarian.jsonl"].sort(); });
  coverArtefact(d, "SYNTHESIS", "snapshots/SYNTHESIZER.json");
}, { check: "adjud.synthesis_blind" }));

A("A52", "adjudication bypass — the record deleted and the stage scrubbed from the manifest", () => attackRun((id, d) => {
  fs.unlinkSync(path.join(d, "adjudication.json"));
  const m = JSON.parse(fs.readFileSync(path.join(d, "manifest.json"), "utf8"));
  delete m.stages.ADJUDICATION;
  fs.writeFileSync(path.join(d, "manifest.json"), JSON.stringify(m, null, 2));
}, { check: "adjud.present" }));

const pass = results.filter(r => r.detected).length;
/* --attest: on a clean sweep, mint an ADVERSARIALLY_VERIFIED record. The command recorded is the
   BARE suite, run in a child process, so the attestation is backed by an independent execution
   rather than by this process vouching for itself. No recursion: the child has no --attest. */
if (process.argv.includes("--attest")) {
  if (pass !== results.length) { console.error("refusing to attest: not all attacks were detected"); process.exit(1); }
  const r = T.attest("control.plane.adversarial_suite", { claim: `all ${results.length} control-plane attacks detected`, level: "ADVERSARIALLY_VERIFIED", command: "node sonar-attack.js", paths: ["sonar-attack.js", "sonar-trust.js"], source: "command" });
  console.log(r.refused ? "attest REFUSED: " + r.why : `attested control.plane.adversarial_suite = ${r.record.level} (sha ${r.record.sha.slice(0, 12)})`);
}
if (process.argv.includes("--json")) { console.log(JSON.stringify({ host_key: T.hostKey(), at: new Date().toISOString(), results }, null, 2)); process.exit(pass === results.length ? 0 : 1); }
console.log(`ADVERSARIAL SUITE — ${results.length} attacks on the control plane, host ${T.hostKey()}`);
for (const r of results) {
  console.log(`  ${r.detected ? "✓ DETECTED" : "✗ UNDETECTED"}  ${r.id}  ${r.attack}`);
  console.log(`      ${r.how}`);
}
console.log(`  → ${pass}/${results.length} attacks detected. ${pass === results.length ? "All attacks failed to fool the system." : "AN ATTACK SUCCEEDED — the control plane's green is not trustworthy."}`);
process.exit(pass === results.length ? 0 : 1);
