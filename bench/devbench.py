#!/usr/bin/env python3
"""cc-sonar-devbench.py — known-answer DEVBENCH for the sweep engine (sweep-v3.5+).

WHY (2026-09-06): four live sweeps found the known answer on some angle 4/4 times and showed it
on the page 1/4 times. No instrument measured that — cc-sonar-test.js's online groups assert
failure shapes and (until v3.5) literally asserted star-sorted order; cc-sonar-bench.js is the
CONTROL-PLANE benchmark whose 20 cases are sealed and unusable for tuning. This is the tuning
harness: NON-sealed cases in sonar/devbench-cases.json, the ONE engine imported from
audit-render/cc-brain-plugin/mcp-server/server.py (never a copy — F9), learning OFF so a bench
run can never poison the store or change the next run.

RUN (needs gh → the real Mac):   python3 cc-sonar-devbench.py [--only id] [--limit N] [--evidence] [--repeat N] [--no-cache]
DATASET: every sweep appends one row to results/dataset.jsonl (Part 11) — the growing empirical model.
OUT: results/<ts>.json + one line:  cc-sonar-devbench: GREEN|RED  k/n first-page …
METRICS per case: any_angle_recall (expected repo in some angle's top-3), first_page_recall
(in repos[]), noise_angle_share (learned/snowball angles ÷ angles), gh_calls, elapsed_ms,
vocabulary_applied, df_stopwords. Denominators are printed; never a bare percentage.
NOT: a token meter (that is .op-scripts/sonar-token-experiment.sh) · not the sealed benchmark.
"""
import importlib.util, json, os, sys, time, datetime, pathlib
ROOT = pathlib.Path(__file__).resolve().parent
SERVER = ROOT.parent / "sweep/sonar_sweep.py"
spec = importlib.util.spec_from_file_location("ccbrain", str(SERVER)); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
cases = json.loads((ROOT / "devbench-cases.json").read_text())["cases"]
# O-52 (2026-09-07): a case WITHDRAWN as invalid must not keep counting as a MISS. Two cases were
# minted and withdrawn the same day (the "buried answer" was actually beaten by equally valid peers);
# because this line loaded all seven, the generated handoff carried first_page_recall "5/7" while
# every LIVE case was a HIT. A benchmark that scores retired cases reports a defect that is not there.
cases = [c for c in cases if c.get("tier") != "withdrawn"]
only = sys.argv[sys.argv.index("--only")+1] if "--only" in sys.argv else None
lim_override = int(sys.argv[sys.argv.index("--limit")+1]) if "--limit" in sys.argv else None
EVIDENCE = "--evidence" in sys.argv   # V3.6: also measure evidence packets (adds code-search calls)
REPEAT = int(sys.argv[sys.argv.index("--repeat")+1]) if "--repeat" in sys.argv else 1   # V3.10: reproducibility
NOCACHE = "--no-cache" in sys.argv or REPEAT > 1   # a repeat is meaningless against the cache
if NOCACHE: os.environ["SONAR_NO_CACHE"] = "1"
import subprocess, tempfile
DATASET = ROOT / "dataset.jsonl"   # Part 11: one row per sweep, grows forever
def _sig(out):
    """Deterministic identity of a sweep result: what must be identical for two runs to count as reproduced."""
    return {"query_sent": out.get("query_sent"),
            "angles": [[a["angle"], a["status"], a.get("returned")] for a in (out.get("angles") or [])],
            "shown": [r["fullName"] for r in (out.get("repos") or [])],
            "counts": out.get("counts"), "gh_calls": out.get("gh_calls"),
            "evidence": [[p["repository"], p["status"], [f.get("path") for f in p.get("files", [])]] for p in (out.get("evidence") or [])]}
def _ingest_states(out):
    """Reuse the ONE classifier (sonar-run.js --ingest-sweep) in a scratch namespace to get evidence states."""
    jp = out.get("artifact_json")
    if not jp or not os.path.exists(jp): return {"error": "no artifact_json"}
    with tempfile.TemporaryDirectory() as td:
        r = subprocess.run(["node", str(ROOT / "sonar-run.js"), "--ingest-sweep", jp], cwd=str(ROOT), capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, SONAR_RUNS_DIR=td))
        try: return json.loads(r.stdout.strip().splitlines()[-1]).get("evidence_states", {})
        except Exception: return {"error": (r.stderr or r.stdout)[:120]}
os.environ["SONAR_NO_LEARN"] = "1"
results = []; first = 0; anyr = 0; n = 0
for c in cases:
    if only and c["id"] != only: continue
    n += 1
    if n > 1: time.sleep(70)   # one GitHub search-bucket window between sweeps
    t0 = time.time()
    runs = []
    for k in range(REPEAT):
        if k: time.sleep(70)
        runs.append(m.sonar_sweep(c["problem"], limit=lim_override or c["limit"], min_stars=50, evidence=EVIDENCE))
    out = runs[0]
    repro = None
    if REPEAT > 1:
        sigs = [json.dumps(_sig(x), sort_keys=True) for x in runs]
        if all(sg == sigs[0] for sg in sigs): repro = {"identical": True, "runs": REPEAT}
        else:
            diff = [k for k in _sig(runs[0]) if json.dumps(_sig(runs[0])[k], sort_keys=True) != json.dumps(_sig(runs[1])[k], sort_keys=True)]
            repro = {"identical": False, "runs": REPEAT, "differs_in": diff}
    response_bytes = len(json.dumps(out))   # what the MCP/CLI caller ingests; tokens ≈ bytes/4
    states = _ingest_states(out) if EVIDENCE else {}
    shown = [r.get("fullName") for r in (out.get("repos") or [])]
    tba = out.get("top_by_angle") or {}
    seen_any = {e.get("fullName") for v in tba.values() for e in v}
    hit_first = [x for x in c["expect_any"] if x in shown]
    hit_any = [x for x in c["expect_any"] if x in seen_any or x in shown]
    angles = out.get("angles") or []
    noise = [a["angle"] for a in angles if str(a["angle"]).startswith(("learned:", "snowball:", "synonym:")) and a.get("status") == "ok"]
    skipped = [a["angle"] for a in angles if a.get("status") == "SKIPPED"]
    r = {"id": c["id"], "problem": c["problem"], "FAILED": bool(out.get("FAILED")), "state": out.get("state"),
         "sweep": out.get("sweep"), "ranking": out.get("ranking"), "gh_calls": out.get("gh_calls"),
         "elapsed_ms": out.get("elapsed_ms", int((time.time()-t0)*1000)), "cached": out.get("cached"),
         "shown": shown, "first_page_hit": hit_first, "any_angle_hit": hit_any,
         "noise_angles": len(noise), "angles": len(angles), "expansion_gate": out.get("expansion_gate"), "skipped_angles": skipped,
         "previous_failures": out.get("previous_failures"), "failed_search_recorded": out.get("failed_search_recorded"), "vocabulary_applied": out.get("vocabulary_applied"),
         "df_stopwords": out.get("vocabulary_df_stopwords"), "persist_skipped": out.get("vocabulary_persist_skipped"),
         "counts": out.get("counts"), "artifact": out.get("artifact"),
         "response_bytes": response_bytes, "est_tokens": response_bytes // 4,
         "cache_mode": out.get("cache_mode"), "learning_mode": out.get("learning_mode"), "reproducibility": repro, "evidence_states": states,
         "bytes_fetched": out.get("bytes_fetched"), "sh_calls": out.get("sh_calls"), "packet_bytes": out.get("packet_bytes"), "stage_ms": out.get("stage_ms"),
         "evidence_status": out.get("evidence_status"),
         "evidence": [{"repository": p["repository"], "status": p["status"], "files": [f.get("path") for f in p.get("files", [])]} for p in (out.get("evidence") or [])]}
    results.append(r); first += bool(hit_first); anyr += bool(hit_any)
    # Part 11 — the growing empirical dataset (one row per sweep, machine-readable, on disk)
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(ROOT), capture_output=True, text=True).stdout.strip()
        row = {"ts": datetime.datetime.now().isoformat(timespec="seconds"), "commit": commit, "sweep": out.get("sweep"),
               "case": c["id"], "query": c["problem"], "normalized_query": out.get("query_sent"),
               "angles": len(angles), "angles_fired": sum(1 for a in angles if a.get("status") == "ok"), "noise_fired": len(noise),
               "gh_calls": out.get("gh_calls"), "results_total": (out.get("counts") or {}).get("matched_total_deduped"),
               "unique_repos": (out.get("counts") or {}).get("matched_total_deduped"),
               "raw_rows": sum((a.get("returned") or 0) for a in angles),
               "surfaced": len(shown), "fetched": sum(1 for p in (out.get("evidence") or []) if p.get("status") == "ok"),
               "files": sum(len(p.get("files", [])) for p in (out.get("evidence") or [])), "fragments": sum(len(p.get("files", [])) for p in (out.get("evidence") or [])),
               "mechanism_candidates": states.get("MECHANISM_CANDIDATE", 0), "mechanism_verified": 0, "admissible": 0,
               "name_only": states.get("SURFACED_NAME_ONLY", 0), "no_mechanism": states.get("NO_MECHANISM", 0),
               "elapsed_ms": r["elapsed_ms"], "bytes_returned": response_bytes, "fable_tokens_est": response_bytes // 4,
               "bytes_fetched": out.get("bytes_fetched"), "sh_calls": out.get("sh_calls"), "packet_bytes": out.get("packet_bytes"),
               "packet_tokens_est": (out.get("packet_bytes") or 0) // 4, "stage_ms": out.get("stage_ms"),
               "raw_to_full_reduction": (round(1 - response_bytes / out["bytes_fetched"], 3) if out.get("bytes_fetched") else None),
               "raw_to_packet_reduction": (round(1 - (out.get("packet_bytes") or 0) / out["bytes_fetched"], 3) if out.get("bytes_fetched") else None),
               "cache_mode": out.get("cache_mode"), "learning_mode": out.get("learning_mode"),
               "failure_count": len(out.get("angles_failed") or []), "rate_limit_waits": out.get("rate_limit_waits"),
               "expected_answer": c["expect_any"], "expected_found": bool(hit_any), "expected_first_page": bool(hit_first),
               "reproducibility": repro}
        with open(DATASET, "a") as fh: fh.write(json.dumps(row, sort_keys=True) + "\n")
    except Exception as e:
        print("  dataset row NOT written:", str(e)[:120], flush=True)
    print("  %-22s first-page %s any-angle %s gh_calls %s elapsed %sms fetched %s B → full %d B → packet %s B (~%d tok) noise %d/%d evidence %s repro %s" % (
        c["id"], "HIT" if hit_first else "MISS", "HIT" if hit_any else "MISS", r["gh_calls"], r["elapsed_ms"],
        out.get("bytes_fetched"), response_bytes, out.get("packet_bytes"), (out.get("packet_bytes") or 0) // 4, len(noise), len(angles), r["evidence_status"], repro), flush=True)
ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
summary = {"ts": ts, "host": os.uname().nodename, "sweep": results[0]["sweep"] if results else None,
           "cases": n, "first_page_recall": "%d/%d" % (first, n), "any_angle_recall": "%d/%d" % (anyr, n),
           "gh_calls_total": sum((r["gh_calls"] or 0) for r in results),
           "elapsed_ms": [r["elapsed_ms"] for r in results], "results": results}
(ROOT / "results" / (ts + ".json")).write_text(json.dumps(summary, indent=1))
verdict = "GREEN" if first == n and n > 0 else "RED"
print("cc-sonar-devbench: %s  first-page %d/%d · any-angle %d/%d · gh_calls %d · %s · results/%s.json" % (
    verdict, first, n, anyr, n, summary["gh_calls_total"], summary["sweep"], ts))
sys.exit(0 if verdict == "GREEN" else 1)
