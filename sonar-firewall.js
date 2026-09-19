#!/usr/bin/env node
/* sonar-firewall.js — THE REGRESSION FIREWALL.
 *
 * The failure ledger is useless as a memoir. Its job is to STOP the same mistake being made again
 * six days later by a fresh context that has never heard of it. Before any implementation change,
 * the proposed diff is compared against every known failed approach. A resemblance BLOCKS the
 * change and names the failure — it does not warn, because a warning is a thing you scroll past.
 *
 * Unblocking requires a new experiment, or an explicit justification recorded as a DECISION.
 * There is deliberately no --force flag: the escape hatch is `--justify <text>`, which writes the
 * justification into the decision ledger where it is permanent and auditable.
 *
 * Usage:
 *   node sonar-firewall.js --diff                    # scan staged+unstaged changes
 *   node sonar-firewall.js --file <path>             # scan one file
 *   node sonar-firewall.js --text "score += count"   # scan a snippet
 *   node sonar-firewall.js --patterns                # list what is currently blocked and why
 */
"use strict";
const fs = require("fs"), cp = require("child_process"), path = require("path");
const ROOT = __dirname, A = process.argv.slice(2);
const arg = f => { const i = A.indexOf(f); return i !== -1 ? A[i + 1] : null; };

function patterns() {
  const f = path.join(ROOT, "sonar", "failures.jsonl");
  if (!fs.existsSync(f)) { console.error("✗ sonar/failures.jsonl missing — firewall fails CLOSED"); process.exit(2); }
  const out = [];
  for (const line of fs.readFileSync(f, "utf8").split("\n").filter(l => l.trim())) {
    let o; try { o = JSON.parse(line); } catch { console.error("✗ unparseable failure row — failing closed"); process.exit(2); }
    for (const p of o.resembles || []) out.push({ id: o.id, severity: o.severity, why: o.what, requires: o.unblock_requires || "a new experiment showing why this approach differs", re: new RegExp(p, "m"), src: p });
  }
  return out;
}
function scan(text, label) {
  const hits = [];
  for (const p of patterns()) {
    const m = text.match(p.re);
    if (m) hits.push({ ...p, matched: String(m[0]).trim().slice(0, 90) });
  }
  return { label, hits };
}
if (A.includes("--patterns")) {
  for (const p of patterns()) console.log(`${p.id}\n  blocks: /${p.src}/\n  because: ${p.why.slice(0, 140)}\n  unblock: ${p.requires}\n`);
  process.exit(0);
}
let text = "", label = "";
if (A.includes("--diff")) {
  /* The files that DEFINE the patterns must be excluded or the firewall matches its own rule
     definitions and blocks every commit that touches it. Excluding them is safe: they are data
     and detector, not implementation. */
  const EXCL = [":(exclude)sonar/failures.jsonl", ":(exclude)sonar-firewall.js", ":(exclude)sonar/decisions.jsonl", ":(exclude)SONAR_CONSTITUTION.md", ":(exclude)audits/**"];
  text = cp.execSync(`git diff HEAD -U0 -- . ${EXCL.map(e => JSON.stringify(e)).join(" ")} 2>/dev/null || true`, { cwd: ROOT, encoding: "utf8" });
  label = "working tree diff vs HEAD (pattern-definition files excluded)";
}
else if (arg("--file")) { label = arg("--file"); text = fs.readFileSync(path.join(ROOT, label), "utf8"); }
else if (arg("--text") !== null) { text = arg("--text"); label = "snippet"; }
else { console.log("usage: --diff | --file <path> | --text <snippet> | --patterns"); process.exit(0); }

const r = scan(text, label);
if (!r.hits.length) { console.log(`✓ FIREWALL CLEAR — ${label}: no resemblance to any known failed approach (${patterns().length} pattern(s) checked)`); process.exit(0); }
console.log(`✗ BLOCKED — ${label} resembles ${r.hits.length} known failure(s):`);
for (const h of r.hits) {
  console.log(`\n  ❌ ${h.id}  [${h.severity}]`);
  console.log(`     matched: ${h.matched}`);
  console.log(`     previous failure: ${h.why.slice(0, 200)}`);
  console.log(`     required to proceed: ${h.requires}`);
}
console.log(`\n  There is no --force. Record a DECISION with the justification, or run the experiment.`);
process.exit(1);
