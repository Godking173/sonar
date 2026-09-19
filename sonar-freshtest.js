#!/usr/bin/env node
/* sonar-freshtest.js — THE FRESH-SESSION TEST, run mechanically so "I checked it" is not the proof.
 *
 * Pretend the reader has never seen this project. Run `sonar-bootstrap` in a SCRUBBED environment
 * (env -i, no HOME, no inherited variables) and assert that its OUTPUT ALONE reconstructs every
 * fact a new session needs. The assertions read nothing but that stdout — if a fact can only be
 * known by remembering a conversation, its assertion fails.
 *
 * Several assertions are cross-checks rather than string matches: the attack count must equal the
 * number of attacks really defined in the suite, the git HEAD must equal what git says right now,
 * and the tool list must contain every component really on disk. A briefing that merely SAYS a
 * number is not evidence; it has to say the RIGHT number, computed independently.
 */
"use strict";
/* PORTABLE PROOF: a virgin install (every ledger empty) has nothing to attack — build a labelled synthetic install and run this file there, unchanged (see sonar-fixture.js). */
if (!process.env.SONAR_FIXTURE_ROOT && require("./sonar-fixture.js").isVirgin(__dirname)) process.exit(require("./sonar-fixture.js").reexec(__filename));
const cp = require("child_process"), fs = require("fs"), path = require("path");
const ROOT = __dirname;
const out = (() => {
  try { return cp.execFileSync(process.execPath, [path.join(ROOT, "sonar-bootstrap.js")], { cwd: ROOT, encoding: "utf8", timeout: 120000, stdio: ["ignore", "pipe", "pipe"], env: { PATH: path.dirname(process.execPath) + ":/usr/bin:/bin", HOME: "/nonexistent" } }); }
  catch (e) { console.error("bootstrap FAILED to run in a scrubbed environment:", String(e.stderr || e.message).slice(0, 300)); process.exit(2); }
})();
const g = c => cp.execSync(c, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
const attackIds = [...fs.readFileSync(path.join(ROOT, "sonar-attack.js"), "utf8").matchAll(/\bA\("(A\d+)"/g)].map(m => m[1]);
const components = fs.readdirSync(ROOT).filter(f => /^(cc-sonar-|cc-priorart|cc-coverage-ratchet|sonar-)/.test(f) && f.endsWith(".js") && !/-test\.js$/.test(f));
const decisionIds = fs.readFileSync(path.join(ROOT, "sonar", "decisions.jsonl"), "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l).id);

const T = [
  ["trust ladder", () => /UNKNOWN → CLAIMED → OBSERVED → VERIFIED → ADVERSARIALLY_VERIFIED → REPRODUCED/.test(out)],
  ["the adversarial attacks", () => attackIds.every(id => out.includes(id)) && new RegExp(`\\b${attackIds.length} adversarial attacks`).test(out)],
  ["the constitution", () => /SONAR_CONSTITUTION\.md/.test(out)],
  ["permanent decisions", () => decisionIds.every(id => out.includes(id))],
  ["the firewall", () => /sonar-firewall\.js --diff/.test(out) && /no --force/.test(out)],
  ["the evidence ledger", () => /evidence ledger: \d+ records/.test(out) && /chain integrity: (INTACT|BROKEN)/.test(out)],
  ["all registered tools", () => components.every(c => out.includes(c))],
  ["current trust states", () => /(VERIFIED|REPRODUCED|ADVERSARIALLY_VERIFIED)\s+\S*capability|WHAT I CAN USE ON THIS HOST/.test(out) && /UNKNOWN capabilities:/.test(out)],
  ["known open defects", () => /WHAT FAILED BEFORE/.test(out) && /✗ LIVE/.test(out)],
  ["benchmark contamination status", () => /CONFIRMED CONTAMINATED: C01/.test(out) && /UNPROVEN \(\d+\)/.test(out)],
  ["discovery status", () => /DISCOVERY STATUS/.test(out) && /FROZEN/i.test(out)],
  ["no retroactive tuning on run cases", () => /DO NOT tune against any case that has been run/.test(out)],
  ["current git HEAD", () => out.includes(g("git rev-parse --short HEAD"))],
  ["capabilities unavailable on this host", () => /NOT AVAILABLE HERE|UNKNOWN capabilities:/.test(out)],
  ["the manifest is not the source of truth", () => /INDEX OF SOURCES OF TRUTH, NOT A SOURCE OF TRUTH/i.test(out)],
  ["the next phase and its constraints", () => /WHAT YOU ARE SUPPOSED TO DO NEXT/.test(out) && /HARD CONSTRAINTS THIS PHASE/.test(out) && /Do NOT run any of the 20 sealed benchmark cases/.test(out)],
  ["blockers already found, so they are not rediscovered", () => /BLOCKERS ALREADY FOUND BY INSPECTION/.test(out) && ["B1", "B2", "B3", "B4", "B5"].every(id => out.includes(id)) && /RESOLVED/.test(out) && /BOUNDED/.test(out) && !/→ undefined/.test(out)],
  ["the execution boundary rule", () => /NO PROMOTABLE EVIDENCE MAY EXIST OUTSIDE THE SONAR RUN NAMESPACE/.test(out) && /cannot become evidence/.test(out)],
  ["the persistence invariant — an orphaned run cannot be trusted (S24)", () => /S24/.test(out) && /must persist in sonar\/runs\//.test(out)],
  ["the adjudication flow — no model judges its own conclusion (S25)", () => /SYNTHESIS → CONTRARIAN → ADJUDICATION/.test(out) && /UNDECIDABLE/.test(out) && /underlying (model )?weights/i.test(out)],
  ["the highest-priority next task", () => /THE SINGLE HIGHEST-PRIORITY NEXT TASK/.test(out) && /Chosen by a deterministic rule/.test(out)]
];
let fail = 0;
console.log("FRESH-SESSION TEST — bootstrap run with env -i, no HOME, no inherited state.");
console.log("Every assertion below reads ONLY the briefing's stdout.\n");
for (const [name, fn] of T) { let ok = false; try { ok = !!fn(); } catch { ok = false; } if (!ok) fail++; console.log(`  ${ok ? "✓" : "✗"} ${name}`); }
console.log(`\n  ${T.length - fail}/${T.length} facts reconstructed from the filesystem alone.`);
console.log(fail ? "  ✗ FAIL — a fresh session could NOT rebuild the state without conversation memory." : "  ✓ PASS — a fresh session can rebuild the state without any conversation memory.");
if (process.argv.includes("--show")) console.log("\n" + out);
process.exit(fail ? 1 : 0);
