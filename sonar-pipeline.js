#!/usr/bin/env node
/* sonar-pipeline.js — THE CONTRACT ENFORCER AND THE ONLY PROMOTION GATE.
 *
 * Every stage declares, in sonar/pipeline.jsonl, what it needs, what it may write, what it may
 * NEVER write, what counts as failure, and what invalidates it. This file is the thing that
 * actually checks. A run that cannot satisfy its own contracts does not get a verdict — it gets a
 * refusal that names the clause it broke.
 *
 * The promotion gate is the single door between a research run and the permanent ledger. Nothing
 * else in the system may append to memory/prior-art.jsonl or sonar/evidence.jsonl on a run's
 * behalf, and the gate refuses on ANY violation. Fail closed, every time.
 *
 * Usage: --contracts | --verify-run <id> [--json] | --promote <id>
 */
"use strict";
const fs = require("fs"), path = require("path");
const T = require("./sonar-trust.js"), Run = require("./sonar-run.js");
const ROOT = __dirname, CONTRACTS = path.join(ROOT, "sonar", "pipeline.jsonl");
const CUMULATIVE = ["graph.jsonl", "events.jsonl"];   // append-only across stages by design
/* B1 CLOSED (phase 3): the old order ran CONTRARIAN before SYNTHESIS, so the synthesizer saw the
   objections before concluding — attack A51 was the default. The synthesizer now concludes BLIND,
   the contrarian attacks a frozen synthesis, and an independent ADJUDICATION resolves each claim
   before any verdict. LEGACY_ORDER remains only so runs promoted under the old contract stay
   verifiable under the contract they were built with (D-013). */
const ORDER = ["DISCOVERY", "EVIDENCE_POOL", "DEEP_READ", "HISTORY", "COMPARISON", "SYNTHESIS", "CONTRARIAN", "ADJUDICATION", "VERDICT", "VERIFICATION"];
const LEGACY_ORDER = ["DISCOVERY", "EVIDENCE_POOL", "DEEP_READ", "HISTORY", "COMPARISON", "CONTRARIAN", "SYNTHESIS", "VERDICT", "VERIFICATION"];

function contracts() {
  if (!fs.existsSync(CONTRACTS)) { console.error("✗ sonar/pipeline.jsonl missing — the pipeline has no contract. Failing closed."); process.exit(2); }
  return fs.readFileSync(CONTRACTS, "utf8").split("\n").filter(l => l.trim()).map(l => JSON.parse(l));
}
const V = (checks, id, ok, detail) => checks.push({ check: id, pass: !!ok, detail });

/* THE ERA RULE (D-013). A run is verified under the pipeline contract in force at ITS OWN
   git_head, derived from git — never asserted by the run. Without this, tightening the contract
   would retroactively invalidate the committed, promoted, seal-verified run built under the old
   one; with a run-asserted version, a new run could claim the laxer era. Admission pins every NEW
   promotion to the current HEAD (validateSeal), so only history can be historic. A run at the
   CURRENT head is judged by the live contract file (the artefacts win over the git blob while a
   change is being built); any git failure falls back to the live file — strictness, not mercy. */
function contractsAt(head) {
  if (!head || head === T.gitHead()) return null;
  try {
    const txt = require("child_process").execSync(`git show ${head}:sonar/pipeline.jsonl`, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    const rows = txt.split("\n").filter(l => l.trim()).map(l => JSON.parse(l));
    return rows.length ? rows : null;
  } catch { return null; }
}

function verifyRun(runId, base = Run.RUNS) {
  const m = Run.manifest(runId, base), checks = [];
  if (!m) return { run_id: runId, ok: false, checks: [{ check: "manifest.exists", pass: false, detail: "no manifest.json — nothing to verify" }] };
  const C = contractsAt(m.git_head) || contracts();
  const adjudicationEra = C.some(c => c.stage === "ADJUDICATION");
  const STAGE_ORDER = adjudicationEra ? ORDER : LEGACY_ORDER;
  const events = Run.readJsonl(runId, "events.jsonl", base);
  const g = Run.graph(runId, base);

  /* 1. the event chain — a stage cannot quietly rewrite its own history */
  let prev = "GENESIS", chainOk = true, chainWhy = "";
  for (const e of events) { const { sha: s, ...rest } = e; if (T.recordHash(rest) !== s || e.prev !== prev) { chainOk = false; chainWhy = `broken at ${e.type}/${e.stage || ""}`; break; } prev = e.sha; }
  V(checks, "events.chain_intact", chainOk, chainWhy || `${events.length} events`);

  /* 2. sealed artefacts must be byte-identical before and after. Measured, not promised. */
  const before = m.sealed_before || {}, after = m.sealed_after || Run.sealedHashes();
  const changed = Object.keys(before).filter(k => before[k] !== after[k]);
  const appeared = Object.keys(after).filter(k => !(k in before));
  V(checks, "sealed.unchanged", changed.length === 0 && appeared.length === 0, changed.length ? `SEALED ARTEFACT MODIFIED DURING RUN: ${changed.join(", ")}` : `${Object.keys(before).length} sealed artefacts identical`);

  /* 3. isolation — every artefact named by every stage must resolve inside the run namespace */
  let escaped = [];
  for (const [stage, s] of Object.entries(m.stages || {})) for (const a of s.artefacts || []) { try { Run.guardedPath(runId, a, base); } catch { escaped.push(`${stage}:${a}`); } }
  const breaches = events.filter(e => e.type === "ISOLATION_VIOLATION");
  V(checks, "isolation.namespace", escaped.length === 0 && breaches.length === 0,
    escaped.length ? `WROTE OUTSIDE NAMESPACE: ${escaped.join(", ")}`
      : breaches.length ? `ATTEMPTED TO WRITE OUTSIDE NAMESPACE ${breaches.length} time(s) — blocked, but a run that tried is not trustworthy: ${breaches.map(b => b.attempted_path).join(", ")}`
      : "all artefacts inside sonar/runs/<id>/, no attempts to escape");

  /* 4. a stage that claims it ran must have left the artefact, and its hash must still match */
  const missing = [], tampered = [];
  for (const [stage, s] of Object.entries(m.stages || {})) {
    if (s.status === "RUNNING") missing.push(`${stage} (never ended)`);
    for (const a of s.artefacts || []) {
      const p = path.join(Run.runDir(runId, base), a);
      if (!fs.existsSync(p)) { missing.push(`${stage}:${a}`); continue; }
      if (CUMULATIVE.includes(a)) continue;                 // see CUMULATIVE above
      const now = Run.sha(fs.readFileSync(p));
      if (s.artefact_hashes && s.artefact_hashes[a] && s.artefact_hashes[a] !== now) tampered.push(`${stage}:${a}`);
    }
  }
  V(checks, "stages.artefacts_exist", missing.length === 0, missing.length ? `CLAIMED BUT ABSENT: ${missing.join(", ")}` : "every claimed artefact is on disk");
  V(checks, "stages.artefacts_unmodified", tampered.length === 0, tampered.length ? `ALTERED AFTER THE STAGE ENDED: ${tampered.join(", ")}` : "artefact hashes still match");

  /* 5. declared inputs must actually exist — a silently skipped input is the quietest lie here */
  const skipped = [];
  for (const c of C) {
    const s = (m.stages || {})[c.stage]; if (!s) continue;
    for (const inp of c.inputs || []) {
      if (/^run\./.test(inp)) { if (!m[inp.slice(4)]) skipped.push(`${c.stage} ← ${inp}`); continue; }
      const f = inp.includes(".") ? inp.split(".")[0] + (inp.endsWith("jsonl") ? "" : "") : inp;
      const cand = [inp, inp.replace(/\..*$/, ".jsonl"), inp.replace(/\..*$/, ".json")];
      if (!cand.some(x => fs.existsSync(path.join(Run.runDir(runId, base), x)))) skipped.push(`${c.stage} ← ${inp}`);
    }
  }
  V(checks, "stages.inputs_present", skipped.length === 0, skipped.length ? `INPUT SILENTLY SKIPPED: ${skipped.join(", ")}` : "every declared input exists");

  /* 6. stage order — a later stage may not have run before an earlier one it depends on */
  const ran = STAGE_ORDER.filter(s => (m.stages || {})[s]);
  const seq = events.filter(e => e.type === "STAGE_START").map(e => e.stage);
  const outOfOrder = seq.filter((s, i) => i > 0 && STAGE_ORDER.indexOf(s) < STAGE_ORDER.indexOf(seq[i - 1]));
  V(checks, "stages.order", outOfOrder.length === 0, outOfOrder.length ? `OUT OF ORDER: ${outOfOrder.join(", ")}` : ran.join(" → "));

  /* 7. DETERMINISTIC BEFORE AI. An AI invocation before every cheaper tier has run is a violation.
        AI interprets evidence; it does not manufacture discovery. */
  const aiStages = C.filter(c => c.deterministic_tier === 10).map(c => c.stage);
  const detStages = C.filter(c => c.deterministic_tier < 10).map(c => c.stage);
  const firstAiIdx = seq.findIndex(s => aiStages.includes(s));
  const firstAiStage = firstAiIdx === -1 ? null : seq[firstAiIdx];
  const ranBeforeAi = firstAiIdx === -1 ? [] : seq.slice(0, firstAiIdx);
  /* only the deterministic stages that come EARLIER IN THE PIPELINE than the first AI stage are
     owed; VERIFICATION is tier 1 and belongs at the end, and demanding it run first was a bug in
     this check, not in the pipeline. */
  const detMissing = firstAiIdx === -1 ? [] : detStages.filter(s => STAGE_ORDER.indexOf(s) < STAGE_ORDER.indexOf(firstAiStage) && !ranBeforeAi.includes(s));
  V(checks, "order.deterministic_before_ai", detMissing.length === 0, detMissing.length ? `AI STAGE RAN BEFORE DETERMINISTIC EVIDENCE WAS EXHAUSTED — missing: ${detMissing.join(", ")}` : "all deterministic tiers ran before any AI stage");

  /* 8. budget */
  const b = m.declared_budget || {};
  V(checks, "budget.api", !(b.api_calls >= 0) || m.api_calls <= b.api_calls, `${m.api_calls}/${b.api_calls} api calls`);
  V(checks, "budget.ai", !(b.ai_invocations >= 0) || m.ai_invocations <= b.ai_invocations, `${m.ai_invocations}/${b.ai_invocations} ai invocations`);

  /* 9. provenance must survive between stages: every node and edge carries a source, every
        non-PROBLEM node is reachable from something, and no fragment floats free of a file. */
  const nodeIds = new Set(g.nodes.map(n => n.id));
  const noProv = [...g.nodes.filter(n => !n.provenance || !n.provenance.source).map(n => n.id), ...g.edges.filter(e => !e.provenance || !e.provenance.source).map(e => `${e.from}->${e.to}`)];
  const linked = new Set(); for (const e of g.edges) { linked.add(e.from); linked.add(e.to); }
  const orphans = g.nodes.filter(n => n.type !== "PROBLEM" && !linked.has(n.id)).map(n => n.id);
  const danglingEdges = g.edges.filter(e => !nodeIds.has(e.from) || !nodeIds.has(e.to)).map(e => `${e.from}->${e.to}`);
  V(checks, "graph.provenance", noProv.length === 0, noProv.length ? `NO PROVENANCE: ${noProv.slice(0, 4).join(", ")}` : `${g.nodes.length} nodes / ${g.edges.length} edges all carry provenance`);
  V(checks, "graph.no_orphans", orphans.length === 0, orphans.length ? `PROVENANCE LOST BETWEEN STAGES: ${orphans.slice(0, 4).join(", ")}` : "every node is reachable");
  V(checks, "graph.edges_resolve", danglingEdges.length === 0, danglingEdges.length ? `EDGE POINTS AT A NODE THAT DOES NOT EXIST: ${danglingEdges.slice(0, 3).join(", ")}` : "all edges resolve");

  /* 10. cached evidence may never be reported as fresh */
  const freshLies = events.filter(e => e.type === "STAGE_END" && (e.cache_hits || 0) > 0 && e.reported_fresh === true).map(e => e.stage);
  V(checks, "cache.honesty", freshLies.length === 0, freshLies.length ? `CACHED EVIDENCE REPORTED AS FRESH: ${freshLies.join(", ")}` : "cache hits recorded as cache hits");

  /* 11. wrong HEAD / wrong host — a run is scoped like every other proof in this system */
  const badHead = events.filter(e => e.git_head && m.git_head && e.git_head !== m.git_head).map(e => `${e.type}/${e.stage || ""}`);
  const badHost = events.filter(e => e.host_key !== m.host_key).map(e => `${e.type}/${e.stage || ""}`);
  V(checks, "scope.same_head", badHead.length === 0, badHead.length ? `EVIDENCE FROM A DIFFERENT COMMIT: ${badHead.slice(0, 3).join(", ")}` : `all events at ${m.git_head}`);
  V(checks, "scope.same_host", badHost.length === 0, badHost.length ? `EVIDENCE FROM A DIFFERENT HOST: ${badHost.slice(0, 3).join(", ")}` : `all events on ${m.host_key}`);

  /* 12. the verdict itself */
  const verdict = Run.readJson(runId, "verdict.json", base);
  if (verdict) {
    const three = ["eligibility", "relevance", "truth"].every(k => verdict[k] !== undefined);
    V(checks, "verdict.three_dimensions", three, three ? "eligibility / relevance / truth reported separately" : "ELIGIBILITY, RELEVANCE AND TRUTH MUST BE THREE SEPARATE FIELDS");
    V(checks, "verdict.no_collapsed_score", verdict.score === undefined, verdict.score === undefined ? "no single collapsed score" : "A SINGLE COLLAPSED SCORE IS FORBIDDEN (D-002/D-003)");
    V(checks, "verdict.sufficiency", verdict.sufficiency !== "INSUFFICIENT" || verdict.conclusion === null, verdict.sufficiency === "INSUFFICIENT" && verdict.conclusion !== null ? "VERDICT EMITTED DESPITE INSUFFICIENT EVIDENCE (S20)" : `sufficiency=${verdict.sufficiency}`);
    const cited = (verdict.cites || []);
    const unknownCites = cited.filter(c => !nodeIds.has(c));
    V(checks, "verdict.cites_resolve", cited.length > 0 && unknownCites.length === 0, unknownCites.length ? `VERDICT CITES NODES THAT DO NOT EXIST: ${unknownCites.join(", ")}` : `${cited.length} cited node(s), all present`);
    /* every repository in the verdict must be reconstructable from the manifest+graph alone */
    const repoNodes = new Set(g.nodes.filter(n => n.type === "REPOSITORY").map(n => n.label));
    const unreconstructable = (verdict.repositories || []).filter(r => !repoNodes.has(r));
    V(checks, "verdict.reconstructable", unreconstructable.length === 0, unreconstructable.length ? `CANDIDATE NOT RECONSTRUCTABLE FROM THE RUN MANIFEST: ${unreconstructable.join(", ")}` : "every named repository is a node in the graph");
    V(checks, "verdict.trust_not_promoted", verdict.trust !== "VERIFIED" || verdict.verified_by, verdict.trust === "VERIFIED" && !verdict.verified_by ? "UNKNOWN SILENTLY PROMOTED TO VERIFIED WITHOUT A VERIFYING COMMAND" : `trust=${verdict.trust}`);
  } else V(checks, "verdict.present", false, "no verdict.json — the run produced no answer");

  /* 12a. BOUNDARY EVENTS — permanently non-promotable, and enforced twice on purpose. The flag
        lives in the manifest AND the event lives in the hash chain: clear the flag and the event
        remains; delete the event and the chain breaks. There is no third door. */
  const boundaryEvents = events.filter(e => ["QUARANTINE", "UNCONTROLLED_EXECUTION", "BYPASS_ATTEMPT", "ISOLATION_VIOLATION"].includes(e.type));
  V(checks, "boundary.controlled", boundaryEvents.length === 0 && !m.quarantined,
    m.quarantined ? `RUN IS QUARANTINED: ${m.quarantine_reason}`
      : boundaryEvents.length ? `RUN CARRIES ${boundaryEvents.length} BOUNDARY EVENT(S): ${[...new Set(boundaryEvents.map(e => e.type))].join(", ")} — permanently non-promotable`
      : "no boundary violations, no quarantine");

  /* 12b. IMPORTED UNCONTROLLED MATERIAL. A run cannot launder an old unwrapped result by copying
        it into its own namespace: any artefact record carrying controlled:false, an uncontrolled
        marker, or a run_id belonging to a DIFFERENT run is rejected. */
  const imported = [];
  for (const [stage, s] of Object.entries(m.stages || {})) for (const a of s.artefacts || []) {
    const fp = path.join(Run.runDir(runId, base), a);
    if (!fs.existsSync(fp)) continue;
    for (const line of fs.readFileSync(fp, "utf8").split("\n").filter(l => l.trim())) {
      let o; try { o = JSON.parse(line); } catch { continue; }
      const scan = x => {
        if (!x || typeof x !== "object") return;
        if (x.controlled === false) imported.push(`${stage}:${a} carries controlled:false`);
        if (x.uncontrolled_reason) imported.push(`${stage}:${a} carries an uncontrolled marker`);
        if (x.run_id && x.run_id !== runId) imported.push(`${stage}:${a} carries run_id ${x.run_id} from another run`);
        for (const v of Object.values(x)) if (v && typeof v === "object") scan(v);
      };
      scan(o);
    }
  }
  V(checks, "provenance.controlled_origin", imported.length === 0, imported.length ? `IMPORTED UNCONTROLLED MATERIAL: ${[...new Set(imported)].slice(0, 3).join("; ")}` : "no imported uncontrolled material");

  /* ── 12c. INDEPENDENT ADJUDICATION (phase 3, S25) — only for runs built under the adjudication
     contract; a legacy run is judged by the rules it was built under (D-013). Everything here is
     re-derived from the run's own artefacts: identities from the chained ROLE_DECLARED events vs
     the manifest, blindness from the synthesizer's files_present, freshness of the frozen
     evidence from byte-prefix hashes, and per-claim resolution from the adjudication record. */
  if (adjudicationEra) {
    const A2 = require("./sonar-adjudicate.js");
    const roles = m.roles || {};
    const roleFor = { SYNTHESIS: "SYNTHESIZER", CONTRARIAN: "CONTRARIAN", ADJUDICATION: "ADJUDICATOR" };
    const roleStages = Object.keys(roleFor).filter(s => (m.stages || {})[s]);

    /* roles declared, correctly named, and identical in manifest AND chain (A43/A44/A45) */
    const roleEvents = events.filter(e => e.type === "ROLE_DECLARED");
    const roleProblems = [];
    for (const s of roleStages) {
      const idm = roles[s], ide = roleEvents.find(e => e.stage === s);
      if (!idm || !ide) { roleProblems.push(`${s}: role not declared in the ${!idm ? "manifest" : "event chain"}`); continue; }
      if (idm.role !== roleFor[s]) roleProblems.push(`${s}: declared role "${idm.role}" is not ${roleFor[s]} — a role wearing another role's name (A43)`);
      for (const k of ["role", "model", "model_version", "prompt_sha256", "config_sha256"])
        if (idm[k] !== ide[k]) roleProblems.push(`${s}: manifest identity ${k} disagrees with the chained ROLE_DECLARED event — identity altered after declaration (A44/A45)`);
    }
    V(checks, "adjud.roles_declared", roleStages.length > 0 && roleProblems.length === 0, roleProblems.slice(0, 3).join("; ") || (roleStages.length ? `${roleStages.length} role(s) declared; manifest and event chain agree` : "no role stages ran"));

    /* pairwise-distinct DECLARED identities (A48) — and only declared: weights stay UNKNOWN (B5) */
    const dPairs = [["SYNTHESIS", "ADJUDICATION"], ["SYNTHESIS", "CONTRARIAN"], ["CONTRARIAN", "ADJUDICATION"]].filter(([a, b]) => roles[a] && roles[b]);
    const same = dPairs.filter(([a, b]) => !A2.distinct(roles[a], roles[b])).map(([a, b]) => `${a}≡${b}`);
    V(checks, "adjud.roles_distinct", same.length === 0, same.length ? `IDENTICAL DECLARED CONFIGURATION: ${same.join(", ")} — cannot claim even declared independence (A48); distinct declarations would still never prove distinct weights (B5)` : "role identities pairwise distinct at the declared level (underlying weights remain UNKNOWN by design)");

    /* the synthesizer concluded BLIND (A51): its snapshot proves what existed when it looked */
    if ((m.stages || {}).SYNTHESIS) {
      const sSnap = Run.readJson(runId, "snapshots/SYNTHESIZER.json", base);
      const saw = sSnap ? (sSnap.files_present || []).filter(f => /^(contrarian\.jsonl|adjudication\.json)$/.test(f)) : null;
      V(checks, "adjud.synthesis_blind", !!sSnap && saw.length === 0, !sSnap ? "SYNTHESIS took no input snapshot — blindness cannot be proven" : saw.length ? `CONTRARIAN MATERIAL EXISTED WHEN THE SYNTHESIS SNAPSHOT WAS TAKEN: ${saw.join(", ")} (A51)` : "contrarian.jsonl and adjudication.json did not exist when the synthesis snapshot was taken");
    }

    /* every role's input snapshot recomputes from disk; no private-path leak (A50, rule 13) */
    const snapProblems = [];
    for (const s of roleStages) {
      const role = roleFor[s];
      const snap = Run.readJson(runId, `snapshots/${role}.json`, base);
      if (!snap) { snapProblems.push(`${role}: no input snapshot`); continue; }
      for (const [f, e] of Object.entries(snap.files || {})) {
        if (!e.exists) continue;
        const p = path.join(Run.runDir(runId, base), f);
        if (!fs.existsSync(p)) { snapProblems.push(`${role}: snapshotted ${f} is gone`); continue; }
        const buf = fs.readFileSync(p);
        /* A2.sha, not Run.sha: takeSnapshot() recorded these hashes with sonar-adjudicate.js's
           Buffer-aware sha() (raw bytes). Run.sha() only special-cases strings — for a Buffer it
           falls through to JSON.stringify(buffer), hashing {"type":"Buffer","data":[...]} instead
           of the bytes, which never equals the recorded hash for ANY input, attacked or clean.
           Discovered by a clean control run failing 34/36 with zero corruption applied — see
           sonar/failures.jsonl defect.adjudication-recompute-used-wrong-sha. Do not "fix" Run.sha
           itself: sonar-run.js and sonar-boundary.js call it the same buggy way on both the write
           and read side, self-consistently, including inside the already-promoted S24 seal — that
           must not change. */
        if (e.prefix_sha256) { if (buf.length < e.bytes || A2.sha(buf.slice(0, e.bytes)) !== e.prefix_sha256) snapProblems.push(`${role}: ${f} prefix no longer matches its snapshot — history rewritten inside an append-only file`); }
        else if (e.sha256) { if (A2.sha(buf) !== e.sha256) snapProblems.push(`${role}: ${f} changed after it was snapshotted`); }
      }
      const leak = Object.keys(snap.files || {}).filter(f => { const mm = f.match(/^private\/([A-Z_]+)\//); return mm && mm[1] !== role; });
      if (leak.length) snapProblems.push(`${role}: snapshot contains another role's private reasoning: ${leak.join(", ")}`);
    }
    V(checks, "adjud.snapshots_recompute", roleStages.length === 0 || snapProblems.length === 0, snapProblems.slice(0, 3).join("; ") || "every role's input snapshot recomputes from disk; no private-path leak");

    /* the adjudication record itself */
    if ((m.stages || {}).SYNTHESIS || (m.stages || {}).ADJUDICATION) {
      const adj = Run.readJson(runId, "adjudication.json", base);
      const synth = Run.readJson(runId, "synthesis.json", base);
      V(checks, "adjud.present", !!adj, adj ? "adjudication record present" : "A SYNTHESIS EXISTS BUT NO ADJUDICATION RECORD — the conclusion was never independently adjudicated (A52)");
      if (adj) {
        const val = A2.validateAdjudication(adj);
        V(checks, "adjud.record_valid", val.ok, val.ok ? `${(adj.claims || []).length} claim(s); five-value resolutions; every claim cites evidence; independence recorded honestly (weights UNKNOWN)` : val.problems.slice(0, 3).join("; "));

        /* frozen evidence (A46): the graph prefix the adjudicator saw must still hash identically */
        const es = adj.evidence_snapshot || {};
        const gp = path.join(Run.runDir(runId, base), "graph.jsonl");
        let frozen = false, fdetail = "no evidence snapshot recorded";
        if (es.graph_prefix_sha256 && es.graph_bytes && fs.existsSync(gp)) {
          const buf = fs.readFileSync(gp);
          frozen = buf.length >= es.graph_bytes && A2.sha(buf.slice(0, es.graph_bytes)) === es.graph_prefix_sha256;
          fdetail = frozen ? `graph prefix (${es.graph_bytes} bytes) still hashes to the adjudication snapshot` : "EVIDENCE CHANGED AFTER THE ADJUDICATION SNAPSHOT (A46)";
        }
        V(checks, "adjud.evidence_frozen", frozen, fdetail);

        /* every synthesis claim resolved, per-claim (B4) */
        const sClaims = (synth && synth.claims) || [];
        const aIds = new Set((adj.claims || []).map(c => c.id));
        const unresolved = sClaims.filter(c => !aIds.has(c.id)).map(c => c.id);
        V(checks, "adjud.claims_resolved", sClaims.length > 0 && unresolved.length === 0, !sClaims.length ? "SYNTHESIS DECLARES NO CLAIMS — nothing was adjudicated" : unresolved.length ? `UNADJUDICATED CLAIM(S): ${unresolved.join(", ")}` : `${sClaims.length}/${sClaims.length} synthesis claims adjudicated per-claim`);

        /* cites resolve inside the frozen view; supporting evidence was synthesizer-visible (A47/A49) */
        const nodesBy = {};
        if (fs.existsSync(gp)) {
          let off = 0;
          for (const line of fs.readFileSync(gp, "utf8").split("\n")) {
            const len = Buffer.byteLength(line + "\n");
            if (line.trim()) { try { const o = JSON.parse(line); if (o.kind === "node") nodesBy[o.id] = { end: off + len, type: o.type }; } catch { } }
            off += len;
          }
        }
        const sSnap2 = Run.readJson(runId, "snapshots/SYNTHESIZER.json", base);
        const nSyn = sSnap2 && sSnap2.files && sSnap2.files["graph.jsonl"] ? sSnap2.files["graph.jsonl"].bytes : null;
        const nAdj = es.graph_bytes || null;
        const citeProblems = [];
        for (const c of adj.claims || []) {
          for (const n of [...(c.cites || []), ...(c.supporting || []), ...(c.contradicting || [])]) {
            const nb = nodesBy[n];
            if (!nb) { citeProblems.push(`${c.id} cites ${n} which does not exist in the graph`); continue; }
            if (nAdj && nb.end > nAdj) citeProblems.push(`${c.id} cites ${n} which entered the graph AFTER the adjudication snapshot`);
            else if (nSyn && !["COUNTERCLAIM", "VERDICT", "CLAIM"].includes(nb.type) && nb.end > nSyn) citeProblems.push(`${c.id} rests on ${n} (${nb.type}) which the SYNTHESIZER never saw (A49)`);
          }
        }
        V(checks, "adjud.cites_in_snapshot", citeProblems.length === 0, citeProblems.slice(0, 3).join("; ") || "every cite resolves inside the frozen snapshot; supporting evidence was synthesizer-visible");

        /* a contradiction blocks promotion until resolved (phase hard rule) */
        const contradicted = (adj.claims || []).filter(c => c.resolution === "CONTRADICTED").map(c => c.id);
        const vd = Run.readJson(runId, "verdict.json", base);
        V(checks, "adjud.contradiction_blocks", contradicted.length === 0 || !vd || vd.conclusion === null, contradicted.length ? (vd && vd.conclusion !== null ? `CLAIM(S) ${contradicted.join(",")} ADJUDICATED CONTRADICTED YET A CONCLUSION WAS EMITTED — a contradiction blocks promotion until resolved` : "contradiction present and the conclusion is correctly withheld") : "no contradicted claims");
      }

      /* authorship (B2): claims belong to the synthesizer, counterclaims to the contrarian */
      const authorProblems = [];
      for (const n of g.nodes) {
        if (n.type === "CLAIM" && n.author !== "SYNTHESIZER") authorProblems.push(`${n.id} authored by "${n.author || "nobody"}" — a CLAIM may only be authored by the SYNTHESIZER (B2)`);
        if (n.type === "COUNTERCLAIM" && n.author !== "CONTRARIAN") authorProblems.push(`${n.id} authored by "${n.author || "nobody"}" — a COUNTERCLAIM may only be authored by the CONTRARIAN`);
      }
      V(checks, "adjud.node_authorship", authorProblems.length === 0, authorProblems.slice(0, 2).join("; ") || "claims and counterclaims carry their authoring role");
    }
  }

  /* 13. determinism: identical immutable inputs must give identical artefact hashes, or say why */
  const reruns = events.filter(e => e.type === "STAGE_END");
  const byStage = {};
  for (const e of reruns) { (byStage[e.stage] = byStage[e.stage] || []).push(JSON.stringify(e.artefact_hashes)); }
  const nondet = Object.entries(byStage).filter(([, v]) => new Set(v).size > 1 && !events.some(x => x.type === "NONDETERMINISM_DECLARED" && x.stage === v)).map(([k]) => k);
  V(checks, "determinism.declared", nondet.length === 0, nondet.length ? `DIFFERENT OUTPUT FROM IDENTICAL INPUTS, UNDECLARED: ${nondet.join(", ")}` : "no undeclared nondeterminism");

  const failed = checks.filter(c => !c.pass);
  return { run_id: runId, git_head: m.git_head, host_key: m.host_key, ok: failed.length === 0, passed: checks.length - failed.length, total: checks.length, checks, failed_checks: failed.map(c => c.check) };
}

/* ── THE ONLY DOOR into the permanent ledger ── */
function promote(runId) {
  /* S24 — AN EPHEMERAL RUN CANNOT MINT DURABLE EVIDENCE. SONAR_RUNS_DIR exists so the attack
     suite and the e2e corruption matrix can build and discard runs without littering a mount that
     cannot delete files. But the trusted ledger is NOT relocatable, and the one time those two
     facts met — the positive control promoting from a mkdtemp namespace — the ledger gained a
     VERIFIED record whose run evaporated with the process (defect.promoted-run-not-persisted).
     Durability is a precondition of promotion, not a hope about what happens afterwards. */
  if (path.resolve(Run.RUNS) !== Run.CANONICAL_RUNS)
    return { promoted: false, why: `REFUSED (S24): runs namespace is relocated to ${Run.RUNS} — an ephemeral run cannot mint durable trusted evidence. Unset SONAR_RUNS_DIR and rebuild the run in sonar/runs/.` };
  const r = verifyRun(runId);
  if (!r.ok) return { promoted: false, why: `verification failed: ${r.failed_checks.join(", ")}`, verification: r };
  const g = Run.graph(runId), m = Run.manifest(runId);
  const reads = g.nodes.filter(n => n.type === "REPOSITORY" && n.commit && n.read_command);
  const B = require("./sonar-boundary.js");
  const seal = { run_id: runId, seal: B.computeSeal(runId) };
  const refusals = [];
  for (const n of reads) {
    const res = T.attest(`priorart.${n.label}`, { claim: `read ${n.label}@${n.commit} during run ${runId}`, level: "VERIFIED", command: n.read_command, source: "command", run_seal: seal });
    if (res.refused) refusals.push(`${n.label}: ${res.why}`);
  }
  if (refusals.length) return { promoted: false, why: `admission refused: ${refusals.join(" · ")}`, verification: r };
  Run.write(runId, "verification.json", { ...r, promoted_at: new Date().toISOString(), promoted_reads: reads.length });
  Run.patch(runId, mm => { mm.promoted = true; mm.trust_state = "VERIFIED"; });
  return { promoted: true, reads: reads.length, verification: r };
}

module.exports = { contracts, contractsAt, verifyRun, promote, ORDER, LEGACY_ORDER };

if (require.main === module) {
  const A = process.argv.slice(2), i = A.indexOf("--verify-run"), p = A.indexOf("--promote");
  if (A.includes("--contracts")) { for (const c of contracts()) console.log(`${c.stage.padEnd(15)} tier ${String(c.deterministic_tier).padStart(2)}  in:[${(c.inputs || []).join(",")}]  out:[${(c.outputs || []).join(",")}]\n   FORBIDDEN: ${(c.forbidden_mutations || []).join(" · ")}\n   verify: ${c.verify}\n`); process.exit(0); }
  if (i !== -1) { const r = verifyRun(A[i + 1]); if (A.includes("--json")) console.log(JSON.stringify(r, null, 2)); else { console.log(`RUN ${r.run_id} · ${r.git_head} · ${r.host_key}`); for (const c of r.checks) console.log(`  ${c.pass ? "✓" : "✗"} ${c.check.padEnd(34)} ${c.detail}`); console.log(`  → ${r.passed}/${r.total} ${r.ok ? "· VERIFIED" : "· REFUSED — no verdict may be trusted from this run"}`); } process.exit(r.ok ? 0 : 1); }
  if (p !== -1) { const r = promote(A[p + 1]); console.log(JSON.stringify({ promoted: r.promoted, why: r.why, reads: r.reads }, null, 2)); process.exit(r.promoted ? 0 : 1); }
  console.log("usage: --contracts | --verify-run <id> [--json] | --promote <id>");
}
