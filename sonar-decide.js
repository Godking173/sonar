#!/usr/bin/env node
/* sonar-decide.js — THE DECISION LEDGER. Separate from the experiment ledger on purpose.
 * The experiment ledger says WHAT HAPPENED. The decision ledger says WHAT WE DECIDED AND WHY,
 * what it supersedes, and what evidence would be required to reverse it. Without it, a fresh
 * context six days from now proposes ranking by stars again and nothing in the machine objects.
 * Same append-only hash chain as the evidence ledger — a rewritten decision is detectable.
 * Usage: --list | --add <json> | --verify | --get <id>
 */
"use strict";
const fs = require("fs"), path = require("path");
const T = require("./sonar-trust.js");
const LEDGER = path.join(__dirname, "sonar", "decisions.jsonl");
const A = process.argv.slice(2);

function add(obj) {
  const rows = T.readLedger(LEDGER);
  const prev = rows.length ? rows[rows.length - 1].sha : "GENESIS";
  const rec = { v: 1, id: obj.id, decision: obj.decision, reason: obj.reason, evidence: obj.evidence,
    status: obj.status || "PERMANENT unless superseded", supersedes: obj.supersedes || null,
    reverse_requires: obj.reverse_requires, at: obj.at, host_key: T.hostKey(), git_head: T.gitHead(), prev };
  rec.sha = T.recordHash(rec);
  fs.mkdirSync(path.dirname(LEDGER), { recursive: true });
  fs.appendFileSync(LEDGER, JSON.stringify(rec) + "\n");
  return rec;
}
module.exports = { add, LEDGER, list: () => T.readLedger(LEDGER), verify: () => T.verifyChain(LEDGER) };

if (require.main === module) {
  if (A[0] === "--verify") { const v = T.verifyChain(LEDGER); console.log(JSON.stringify(v, null, 2)); process.exit(v.ok ? 0 : 1); }
  if (A[0] === "--add") { console.log(JSON.stringify(add(JSON.parse(A[1])), null, 2)); process.exit(0); }
  if (A[0] === "--get") { const r = T.readLedger(LEDGER).find(x => x.id === A[1]); console.log(r ? JSON.stringify(r, null, 2) : `no decision ${A[1]}`); process.exit(r ? 0 : 1); }
  for (const r of T.readLedger(LEDGER)) console.log(`${r.id}  ${r.decision}\n    why: ${r.reason}\n    evidence: ${r.evidence}\n    reverse requires: ${r.reverse_requires}${r.supersedes ? `\n    supersedes: ${r.supersedes}` : ""}\n`);
}
