#!/usr/bin/env node
/* sonar-trust.js — TRUST STATES + PROVENANCE. The layer that makes Sonar unable to trust itself.
 *
 * THE LADDER (SONAR_CONSTITUTION.md):
 *   UNKNOWN → CLAIMED → OBSERVED → VERIFIED → ADVERSARIALLY_VERIFIED → REPRODUCED
 * No state is entered by assertion. Every transition requires an executed command that leaves a
 * provenance record, and every record is a link in an append-only hash chain.
 *
 * WHAT EACH LEVEL ACTUALLY MEANS HERE, so nobody can quietly redefine them later:
 *   CLAIMED                an authored registry row says so. Prose. Worth nothing on its own.
 *   OBSERVED               a tool saw something — a path exists, a binary is on PATH. Existence,
 *                          not function. A shim named `duckdb` that prints nothing reaches OBSERVED.
 *   VERIFIED               a deterministic, PROBATIVE check exited 0 on THIS host at THIS git HEAD.
 *   ADVERSARIALLY_VERIFIED the fact survived a deliberate attack — the thing was broken on purpose
 *                          and the system reported it broken.
 *   REPRODUCED             a DIFFERENT host produced the same VERIFIED result for the same command.
 *
 * A record from another machine can never make anything true here. It can only add REPRODUCED on
 * top of a local VERIFIED. That rule exists because "14 VERIFIED / 0 BROKEN" on the Mac was
 * reported as a fact about the system while the same commit gave 9 VERIFIED / 5 UNKNOWN on Linux.
 */
"use strict";
const fs = require("fs"), cp = require("child_process"), path = require("path"), os = require("os"), crypto = require("crypto");
const ROOT = __dirname;
const LEDGER = path.join(ROOT, "sonar", "evidence.jsonl");
const LEVELS = ["UNKNOWN", "CLAIMED", "OBSERVED", "VERIFIED", "ADVERSARIALLY_VERIFIED", "REPRODUCED"];
const rank = l => LEVELS.indexOf(l);
const sha = s => crypto.createHash("sha256").update(String(s)).digest("hex");

function host() { return { hostname: os.hostname(), platform: process.platform, arch: process.arch, node: process.version }; }
function hostKey() { const h = host(); return `${h.hostname}:${h.platform}/${h.arch}`; }
function gitHead(root = ROOT) { try { return cp.execSync("git rev-parse --short HEAD", { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { return null; } }
function gitDirty(root = ROOT) { try { return cp.execSync("git status --porcelain", { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim().length > 0; } catch { return null; } }

/* ── S22: A CHECK THAT CANNOT FAIL IS NOT A CHECK. ───────────────────────────
   The cheapest possible forgery is a check that always exits 0. `true`, `:`, `echo ok`,
   `... || true` — all produce a green with no contact with reality. Refuse them at the door,
   before they can ever mint a VERIFIED record. */
const NON_PROBATIVE = [
  { re: /^\s*(true|:)\s*(#.*)?$/, why: "the command is literally `true` — it cannot fail" },
  { re: /^\s*echo\b/, why: "echo always exits 0 regardless of any fact about the system" },
  { re: /\|\|\s*(true|:)\s*$/, why: "trailing `|| true` swallows every failure" },
  { re: /;\s*(true|:)\s*$/, why: "trailing `; true` discards the real exit code" },
  { re: /^\s*exit\s+0\s*$/, why: "hardcoded exit 0" },
  { re: /\|\s*(head|tail|cat)\b(?![^|]*\bgrep\b)/, why: "piping through head/tail/cat replaces the real exit code with the pipe's — this exact mistake ate a failing exit code five times in one session" }
];
function probative(cmd) {
  for (const p of NON_PROBATIVE) if (p.re.test(cmd)) return { ok: false, why: p.why };
  if (!/[A-Za-z0-9_./-]{2,}/.test(cmd)) return { ok: false, why: "command references nothing" };
  return { ok: true };
}

function run(cmd, opts = {}) {
  const t0 = Date.now();
  try {
    const out = cp.execSync(cmd, { cwd: opts.cwd || ROOT, encoding: "utf8", timeout: opts.timeout || 45000, stdio: ["ignore", "pipe", "pipe"] });
    return { exit: 0, stdout: out, stderr: "", ms: Date.now() - t0 };
  } catch (e) {
    return { exit: e.status === undefined ? null : e.status, stdout: String(e.stdout || ""), stderr: String(e.stderr || e.message || ""), ms: Date.now() - t0 };
  }
}
let NET = null;
function network() {
  if (NET !== null) return NET;
  const r = run("curl -s -m 8 -o /dev/null -w '%{http_code}' https://api.github.com", { timeout: 12000 });
  NET = (r.exit === 0 && /^[1-5]\d\d$/.test(r.stdout.trim()) && r.stdout.trim() !== "000") ? "available" : "unavailable";
  return NET;
}

/* ── the chain ─────────────────────────────────────────────────────────────── */
function readLedger(file = LEDGER) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").split("\n").filter(l => l.trim()).map((l, i) => {
    try { const o = JSON.parse(l); o.__line = i + 1; return o; } catch { return { __line: i + 1, __unparseable: l.slice(0, 80) }; }
  });
}
function recordHash(rec) { const { sha: _s, __line, ...rest } = rec; return sha(JSON.stringify(rest)); }
/* S23 — evidence is an append-only hash chain. If you can rewrite it silently it is not evidence. */
function verifyChain(file = LEDGER) {
  const rows = readLedger(file), problems = [];
  let prev = "GENESIS";
  for (const r of rows) {
    if (r.__unparseable) { problems.push({ line: r.__line, kind: "UNPARSEABLE", detail: r.__unparseable }); continue; }
    if (recordHash(r) !== r.sha) problems.push({ line: r.__line, kind: "TAMPERED_RECORD", fact: r.fact, detail: "record content does not match its own sha — a field was edited after it was written" });
    if (r.prev !== prev) problems.push({ line: r.__line, kind: "BROKEN_LINK", fact: r.fact, detail: `prev=${String(r.prev).slice(0, 12)} expected=${String(prev).slice(0, 12)} — a record was inserted, deleted or reordered` });
    prev = r.sha;
  }
  return { ok: problems.length === 0, count: rows.length, problems };
}

/* ── minting a record. This is the ONLY way a fact moves up the ladder. ────── */
function attest(fact, opts0) {
  const { claim, level, command, source = "command", paths = [], tool_version = null, cwd = ROOT, ledger = LEDGER, allowNonProbative = false } = opts0;
  const opts = opts0;
  if (rank(level) < 0) throw new Error(`unknown trust level ${level}`);
  if (rank(level) >= rank("VERIFIED") && !allowNonProbative) {
    const p = probative(command || "");
    if (!p.ok) return { refused: true, why: `NON-PROBATIVE CHECK REFUSED (S22): ${p.why}`, fact, level };
  }
  /* THE ADMISSION GATE (2026-08-11). Before this, attest() accepted any caller, so any code path
     could mint trusted evidence — cc-priorart.js wrote memory/prior-art.jsonl directly at clone
     time with no run at all. A CONTROL fact (capability.* / control.*) is the control plane
     verifying itself and needs no run. A RESEARCH fact is a claim about the outside world and is
     refused unless it carries a run seal that revalidates RIGHT NOW: the run must exist, be
     unquarantined, carry no boundary violations, be at this HEAD on this host, hash to the seal
     presented, and pass full pipeline verification at this moment. The seal is not a credential —
     it is a summary of work, so forging it and doing the work are the same act. */
  if (ledger === LEDGER) {
    const B = require("./sonar-boundary.js");
    if (B.classifyFact(fact) === "RESEARCH") {
      const v = B.validateSeal(opts.run_seal);
      if (!v.ok) return { refused: true, why: `UNCONTROLLED RESEARCH FACT REFUSED: ${v.why}`, fact, level };
    }
  }
  /* S13 / forged paths — a record may not cite a path that does not exist at record time. */
  const missing = paths.filter(p => !fs.existsSync(path.isAbsolute(p) ? p : path.join(cwd, p)));
  if (missing.length) return { refused: true, why: `FORGED PATH REFUSED: ${missing.join(", ")} does not exist`, fact, level };

  /* opts.result lets a caller that ALREADY executed this exact command hand the result in,
     instead of paying for a second identical execution. doctor classifies every check and then
     attests the ones that passed; without this it ran the whole control plane twice, which grew
     from cheap to call-window-blowing the moment the checks included the attack suite and the
     end-to-end control case. The command is still recorded verbatim, so the record is reproducible
     by hand either way. */
  const r = opts.result || (command ? run(command, { cwd }) : { exit: 0, stdout: "", stderr: "", ms: 0 });
  const achieved = command ? (r.exit === 0 ? level : "UNKNOWN") : level;
  const rows = readLedger(ledger);
  const prev = rows.length ? rows[rows.length - 1].sha : "GENESIS";
  const rec = {
    v: 1, fact, claim: claim || fact, level: achieved, attempted_level: level,
    host: host(), host_key: hostKey(), at: new Date().toISOString(),
    cwd, paths, source, command: command || null, exit_code: r.exit,
    stdout_sha256: sha(r.stdout), stdout_head: r.stdout.trim().split("\n")[0] ? r.stdout.trim().split("\n")[0].slice(0, 120) : "",
    stderr_sha256: sha(r.stderr), stderr_head: r.stderr.trim().split("\n")[0] ? r.stderr.trim().split("\n")[0].slice(0, 120) : "",
    tool_version, network: network(), git_head: gitHead(cwd), git_dirty: gitDirty(cwd), duration_ms: r.ms,
    controlled: opts.run_seal ? true : undefined, run_id: opts.run_seal ? opts.run_seal.run_id : undefined, run_seal: opts.run_seal || undefined, prev
  };
  rec.sha = recordHash(rec);
  fs.mkdirSync(path.dirname(ledger), { recursive: true });
  fs.appendFileSync(ledger, JSON.stringify(rec) + "\n");
  return { refused: false, record: rec };
}

/* ── computing the current level of a fact ─────────────────────────────────── */
function levelFor(fact, opts = {}) {
  const ledger = opts.ledger || LEDGER, hk = opts.hostKey || hostKey(), head = opts.gitHead === undefined ? gitHead(opts.cwd || ROOT) : opts.gitHead;
  const chain = verifyChain(ledger);
  const rows = readLedger(ledger).filter(r => r.fact === fact && !r.__unparseable);
  const tamperedLines = new Set(chain.problems.map(p => p.line));
  const reasons = [];
  if (!rows.length) return { fact, level: "UNKNOWN", reasons: ["no evidence record of any kind exists for this fact"], records: [] };

  const usable = [], rejected = [];
  /* S24 — ORPHANED RUN-BACKED EVIDENCE IS REJECTED AT READ TIME. levelFor once judged a record
     only by chain integrity, host and HEAD, which left a resurrection path: check out the commit
     an orphaned record was minted at and it reads back as top-rank VERIFIED with nothing left to
     revalidate — its run is gone, its seal can never be recomputed. A record that names a run is
     usable only while that run still resolves in the canonical namespace and still hashes to the
     recorded seal. Full pipeline re-verification stays where it is affordable (admission and the
     ledger audit); resolution + seal identity is the floor for consumption. */
  const orphanWhy = r => {
    if (!r.run_seal && !r.run_id) return null;             // not run-backed — not this rule's business
    try {
      const chk = require("./sonar-boundary.js").checkRunEvidence(r, { verify: false });
      return chk.ok ? null : `ORPHANED RUN (S24): ${chk.why}`;
    } catch (e) { return `run-backed record but the boundary module failed (${String(e.message).slice(0, 60)}) — fail closed`; }
  };
  for (const r of rows) {
    if (tamperedLines.has(r.__line)) { rejected.push({ r, why: "chain integrity failure on this record — DISCARDED" }); continue; }
    if (r.host_key !== hk) { rejected.push({ r, why: `produced on ${r.host_key}, not this host — cannot establish local truth (S21)` }); continue; }
    if (head && r.git_head && r.git_head !== head) { rejected.push({ r, why: `STALE: recorded at ${r.git_head}, HEAD is now ${head}` }); continue; }
    const ow = orphanWhy(r);
    if (ow) { rejected.push({ r, why: ow }); continue; }
    usable.push(r);
  }
  let level = "UNKNOWN";
  for (const r of usable) if (rank(r.level) > rank(level)) level = r.level;
  for (const r of usable) reasons.push(`${r.level} · ${r.at} · exit ${r.exit_code} · ${String(r.command || r.source).slice(0, 70)}`);
  for (const x of rejected) reasons.push(`REJECTED(${x.r.level}) · ${x.why}`);

  /* REPRODUCED requires a second, independent host that ran the SAME command and got VERIFIED+. */
  if (rank(level) >= rank("VERIFIED")) {
    const cmds = new Set(usable.filter(r => rank(r.level) >= rank("VERIFIED")).map(r => r.command));
    /* BUG FOUND BY RUNNING THE SYSTEM, 2026-08-10: this filter originally omitted the staleness
       test, so a foreign record from an OLD commit still granted REPRODUCED. Local records were
       correctly rejected as stale while a Mac record from the previous HEAD sailed through — the
       exact asymmetry the ladder exists to prevent. Attack A13 now covers it. */
    const foreign = rows.filter(r => !tamperedLines.has(r.__line) && r.host_key !== hk && rank(r.level) >= rank("VERIFIED") && cmds.has(r.command) && (!head || !r.git_head || r.git_head === head) && !orphanWhy(r));
    const staleForeign = rows.filter(r => r.host_key !== hk && rank(r.level) >= rank("VERIFIED") && cmds.has(r.command) && head && r.git_head && r.git_head !== head);
    if (staleForeign.length && !foreign.length) reasons.push(`foreign proof exists but is STALE (recorded at ${staleForeign[0].git_head}, HEAD is ${head}) — does not grant REPRODUCED`);
    const hosts = new Set(foreign.map(r => r.host_key));
    if (hosts.size >= 1) { level = "REPRODUCED"; reasons.push(`REPRODUCED by independent host(s): ${[...hosts].join(", ")} running the identical command`); }
    else reasons.push("not REPRODUCED — no other host has run this exact check");
  }
  return { fact, level, reasons, chain_ok: chain.ok, records: rows.length, usable: usable.length, rejected: rejected.length };
}

function facts(ledger = LEDGER) { return [...new Set(readLedger(ledger).filter(r => r.fact).map(r => r.fact))].sort(); }

module.exports = { LEVELS, rank, attest, levelFor, verifyChain, readLedger, recordHash, probative, facts, host, hostKey, gitHead, network, run, sha, LEDGER };

if (require.main === module) {
  const A = process.argv.slice(2);
  if (A[0] === "--chain") { const c = verifyChain(); console.log(JSON.stringify(c, null, 2)); process.exit(c.ok ? 0 : 1); }
  if (A[0] === "--facts") { for (const f of facts()) { const l = levelFor(f); console.log(`${l.level.padEnd(23)} ${f}`); } process.exit(0); }
  if (A[0] === "--explain") { console.log(JSON.stringify(levelFor(A[1]), null, 2)); process.exit(0); }
  console.log("usage: sonar-trust.js --chain | --facts | --explain <fact>");
}
