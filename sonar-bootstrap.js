#!/usr/bin/env node
/* sonar-bootstrap.js — WHAT A COMPLETELY FRESH SESSION RUNS FIRST.
 *
 * Assume the reader has never seen this project, has no conversation history, and should not be
 * given any. Everything below is derived from artefacts on disk at the moment you run it. If a
 * fact here could only be known by remembering a conversation, that is a BUG, not a feature.
 *
 * Read the manifest's own rule before believing any of this: the manifest is an INDEX of the
 * sources of truth, not a source of truth. Where it disagrees with an artefact, the artefact wins.
 */
"use strict";
const B = require("./sonar-brain.js"), T = require("./sonar-trust.js");
const m = B.derive(), snap = B.compareToSnapshot(m);
const A = process.argv.slice(2);
if (A.includes("--json")) { console.log(JSON.stringify({ manifest: m, snapshot: snap }, null, 2)); process.exit(0); }

function PHASE_BLOCK(m) {
  const p = m.phase || {};
  console.log("\n══ WHAT YOU ARE SUPPOSED TO DO NEXT ══════════════════════════════════════");
  if (p.missing) { console.log("  ! NO sonar/phase.json — nobody wrote down what the next phase is."); return; }
  console.log(`  PHASE   ${p.current_phase}`);
  console.log(`  STATUS  ${p.status}`);
  console.log(`  set at  ${p.updated_at} (commit ${p.updated_at_commit})${p.stale_since_commit ? "  ⚠ COMMITS HAVE LANDED SINCE — re-read it critically" : ""}`);
  if (p.next_task) {
    console.log(`  OBJECTIVE: ${p.next_task.objective}`);
    if (p.next_task.roles_to_separate) console.log(`  roles: ${p.next_task.roles_to_separate.join(" · ")}`);
    if (p.next_task.attacks_to_add) console.log(`  attacks to add: ${p.next_task.attacks_to_add.length} (${p.next_task.attacks_to_add[0].split(" ")[0]}–${p.next_task.attacks_to_add[p.next_task.attacks_to_add.length-1].split(" ")[0]})`);
    for (const c of p.next_task.controls_required || []) console.log(`  control: ${c}`);
  }
  if ((p.known_blockers || []).length) {
    console.log("  BLOCKERS ALREADY FOUND BY INSPECTION — do not rediscover these:");
    /* print the finding in FULL. It was truncated at 150 chars and the cut landed mid-sentence,
       removing "Attack A51 is not hypothetical — it is the current default" — the single most
       load-bearing clause in the whole block. The fresh-session test caught it. Fix the output,
       never the assertion. */
    for (const b of p.known_blockers) console.log(`    ${b.id}  ${b.finding}\n         → ${b.consequence}`);
  }
  console.log("  HARD CONSTRAINTS THIS PHASE:");
  for (const c of p.hard_constraints || []) console.log(`    ⛔ ${c}`);
  console.log("  full detail: sonar/phase.json  ·  do not treat this block as optional");
}
const H = t => console.log(`\n${t}\n${"─".repeat(Math.min(74, t.length + 8))}`);
const cap = m.capabilities.rows;
const byTrust = l => cap.filter(c => c.trust === l).map(c => c.id);

console.log("════════════════════════════════════════════════════════════════════════");
console.log("  SONAR — BOOTSTRAP BRIEFING");
console.log(`  host ${m.host_key} · git ${m.git.head}${m.git.dirty ? " (DIRTY)" : ""} · branch ${m.git.branch} · ${m.derived_at}`);
console.log("  Nothing below is remembered. Every line was derived from disk just now.");
console.log("════════════════════════════════════════════════════════════════════════");

PHASE_BLOCK(m);
if (A.includes("--phase")) process.exit(0);

H("WHAT SONAR IS");
console.log("  An engineering intelligence engine: it searches the world's code for prior art before");
console.log("  anything gets built, reads the candidates, and refuses to conclude when the evidence is");
console.log("  thin. It is INTERNAL to its home project first (decision D-001). It sits on a control plane");
console.log("  whose whole job is to stop the operator — an AI that forgets, hallucinates and lies —");
console.log("  from being believed. Read SONAR_CONSTITUTION.md before changing anything.");
console.log(`  Trust ladder: ${T.LEVELS.join(" → ")}`);

H("WHAT EXISTS RIGHT NOW");
console.log(`  ${m.tools.count} executable tools on disk, ${m.tools.rows.filter(t => t.git_tracked).length} tracked by git`);
for (const t of m.tools.rows) console.log(`    ${t.git_tracked ? "●" : "○"} ${t.tool.padEnd(24)} ${String(t.lines).padStart(4)} lines  ${t.introduced || "UNCOMMITTED"}`);
console.log(`  lanes: ${Object.entries(m.lanes.lanes).map(([k, v]) => `${k}(${v.length})`).join(" · ")}`);
console.log(`  ledgers: ${m.artefacts.rows.filter(r => r.exists).map(r => `${r.artefact}${r.lines !== null ? `[${r.lines}]` : ""}`).join(", ")}`);
if (m.artefacts.missing.length) console.log(`  ! MISSING ARTEFACTS: ${m.artefacts.missing.join(", ")}`);
if (m.artefacts.untracked.length) console.log(`  ! UNTRACKED (would be lost on a fresh clone): ${m.artefacts.untracked.join(", ")}`);

H("WHAT I CAN USE ON THIS HOST RIGHT NOW");
for (const l of ["REPRODUCED", "ADVERSARIALLY_VERIFIED", "VERIFIED"]) if (byTrust(l).length) console.log(`  ${l.padEnd(23)} ${byTrust(l).join(", ")}`);
console.log(`  binaries present: ${m.dependencies.binaries_present_here.join(", ")}`);
if (m.dependencies.missing_here.length) console.log(`  ! NOT AVAILABLE HERE: ${m.dependencies.missing_here.join(", ")} — anything depending on these is UNKNOWN on this host, not broken`);

H("WHAT IS UNKNOWN, STALE OR FOREIGN");
if (byTrust("UNKNOWN").length) console.log(`  UNKNOWN capabilities: ${byTrust("UNKNOWN").join(", ")}`);
console.log(`  evidence ledger: ${m.stale_proofs.total_records} records · ${m.stale_proofs.usable_here} usable here · ${m.stale_proofs.stale_records} stale (different commit) · ${m.stale_proofs.foreign_records} foreign (different host)`);
console.log(`  chain integrity: ${m.stale_proofs.chain_ok ? "INTACT" : "BROKEN — nothing computed from it can be trusted"}`);
console.log(`  manifest snapshot vs artefacts: ${snap.state}${snap.diverged ? ` — diverged: ${snap.diverged.join(", ")} (ARTEFACTS WIN)` : ""}`);
console.log("  A record from another machine can never make anything true here. It can only add");
console.log("  REPRODUCED on top of a local VERIFIED (constitution S21, decision D-007).");

H("WHAT FAILED BEFORE — do not rediscover these");
for (const f of m.failures.rows) console.log(`  ${f.detector_state === "STILL_PRESENT" ? "✗ LIVE  " : f.detector_state === "NOT_DETECTED" ? "✓ fixed " : "? unknwn"} ${f.id} [${f.severity}]`);
console.log(`  ${m.rejected_approaches.rows.length} approaches are mechanically BLOCKED. The firewall refuses a change that`);
console.log(`  resembles one, with no --force flag: node sonar-firewall.js --diff`);
for (const r of m.rejected_approaches.rows.filter(r => r.blocked_patterns.length)) console.log(`    ⛔ ${r.id}  → ${r.to_revisit_you_must}`);

H("WHAT IS PERMANENT — decisions you may not quietly reverse");
console.log(`  decision chain: ${m.decisions.chain_ok ? "INTACT" : "BROKEN"}`);
for (const d of m.decisions.rows) console.log(`  ${d.id}  ${d.decision}\n        reverse requires: ${d.reverse_requires}`);

H("WHICH EXPERIMENTS ARE STILL CLEAN");
console.log(`  ${m.benchmark.total_cases} sealed cases. CONFIRMED CONTAMINATED: ${m.benchmark.confirmed_contaminated.join(", ") || "none"}`);
console.log(`  UNPROVEN (${m.benchmark.unproven.length}): ${m.benchmark.unproven.join(", ")}`);
console.log(`  ${m.benchmark.policy}`);
console.log(`  DO NOT tune against any case that has been run. DO NOT modify a sealed artefact —`);
console.log(`  the seal is the git blob, so a retroactive edit cannot match it.`);
if (m.experiments.unsealed.length) console.log(`  ! UNSEALED (not committed, therefore not sealed): ${m.experiments.unsealed.join(", ")}`);
if (m.experiments.tampered.length) console.log(`  ! TAMPERED: ${m.experiments.tampered.join(", ")}`);

H("DISCOVERY STATUS");
const frozen = m.decisions.rows.find(d => /FROZEN/i.test(d.decision));
console.log(`  ${frozen ? `${frozen.id}: ${frozen.decision}` : "no freeze decision on record — check sonar/decisions.jsonl"}`);
/* 2026-09-19 (S16/S17): a freeze is only current until a later decision supersedes it, and the
   phase file is only truthful while the engine on disk is the engine it describes. Both are
   DERIVED here, every boot — never remembered. */
const lifted = frozen && m.decisions.rows.find(d => d.supersedes && String(d.supersedes).includes(frozen.id));
if (lifted) console.log(`  → SUPERSEDED by ${lifted.id}: ${lifted.decision}`);
{
  const fs2 = require("fs"), path2 = require("path");
  const enginePaths = ["audit-render/cc-brain-plugin/mcp-server/server.py", "sweep/sonar_sweep.py"].map(r => path2.join(__dirname, r));
  const ep = enginePaths.find(f => fs2.existsSync(f));
  const onDisk = ep ? ((fs2.readFileSync(ep, "utf8").match(/SONAR_SWEEP_VERSION\s*=\s*"([^"]+)"/) || [])[1] || null) : null;
  let phaseSaid = null; try { phaseSaid = (JSON.parse(fs2.readFileSync(path2.join(__dirname, "sonar", "phase.json"), "utf8")).discovery_engine || {}).sweep_version_at_update || null; } catch {}
  if (!ep) console.log("  engine: NOT FOUND on disk (no server.py / sweep/sonar_sweep.py) — discovery status UNKNOWN here");
  else if (!phaseSaid) console.log(`  engine on disk: ${onDisk} · phase.json records no engine version — PHASE FILE INCOMPLETE, fix it at the next boundary`);
  else if (phaseSaid !== onDisk) console.log(`  ⚠ PHASE FILE STALE: phase.json describes engine ${phaseSaid} but the engine on disk is ${onDisk} — the code moved, the record did not (S16/S17)`);
  else console.log(`  engine on disk: ${onDisk} · matches phase.json — the phase record is current`);
}
console.log(`  Lanes A and B must be unioned before ranking (D-004): they overlapped on ZERO repos.`);

H("THE SINGLE HIGHEST-PRIORITY NEXT TASK");
const top = m.open_work.items[0];
if (!top) console.log("  Nothing open. Verify that by re-running the detectors before believing it.");
else {
  console.log(`  → [${top.severity}] ${top.kind}: ${top.id}`);
  console.log(`    why now: ${top.why}`);
  console.log(`    evidence: ${top.evidence}`);
  console.log(`  Chosen by a deterministic rule, not by judgement: ${m.open_work.provenance.rule}`);
  console.log(`  Full queue (${m.open_work.items.length}):`);
  for (const i of m.open_work.items.slice(1)) console.log(`    · [${i.severity}] ${i.kind}: ${String(i.id).slice(0, 90)}`);
}

H("THE EXECUTION BOUNDARY — what you are and are not allowed to claim");
console.log(`  ${m.boundary.rule}`);
console.log(`  ${m.boundary.evidence_producing_tools} evidence-producing tools, ${m.boundary.nonconformant.length} non-conformant${m.boundary.nonconformant.length ? ": " + m.boundary.nonconformant.join(", ") : ""}`);
for (const l of m.boundary.ledger_audit) if (!l.missing) console.log(`  ${l.file}: ${l.admissible} admissible · ${l.inadmissible.length} inadmissible research record(s)`);
console.log(`  ${m.boundary.uncontrolled_executions_on_record} uncontrolled execution(s) on record (sonar-boundary.js --uncontrolled)`);
console.log("  Running a tool by hand still works and is still useful. It just cannot become evidence.");

H("HOW THIS SYSTEM DEFENDS ITSELF");
console.log(`  ${m.defences.attack_count} adversarial attacks run against the control plane on every gate run.`);
console.log(`  A01-A13 attack the trust layer; A14-A24 attack the manifest — the thing you are reading.`);
for (const a of m.defences.attacks) console.log(`    ${a.id}  ${a.attack}`);
console.log(`  gate lines that enforce this: ${m.defences.gate_lines.map(g => g.check).join(", ")}`);

H("PROVE ANY OF THIS YOURSELF — do not trust this output");
console.log("  node sonar-doctor.js                  12 control-plane questions, re-executed");
console.log("  node sonar-doctor.js --show-checks    every check command, verbatim");
console.log("  node sonar-doctor.js --selftest       proves VERIFIED/BROKEN/UNKNOWN are all reachable");
console.log("  node sonar-doctor.js --adversarial    deletes a component, demands detection");
console.log("  node sonar-attack.js                  every attack on the control plane itself");
console.log("  node sonar-doctor.js --explain <fact> why a fact holds its level, with full provenance");
console.log("  node sonar-brain.js --check           is the committed manifest still true?");
console.log("  node sonar-firewall.js --diff         does my change resemble a known failure?");
console.log("  bash cc-verify.sh                     the whole gate");
console.log(`\n  Manifest rule: ${m.note}`);
process.exit(0);
