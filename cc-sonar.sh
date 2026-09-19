#!/usr/bin/env bash
# topic sweep). This one answers ONE question the moment you have it:
# "we hit problem X — has someone already built/solved this on GitHub?"
# someone who fixed that problem with repos so that you don't have to come up with
# things yourself all the time."
#
# REBUILT 2026-08-01. What this script used to do wrong, all verified live:
#   * On zero rows from GitHub it printed "nothing cleared the proven-or-fresh bar —
#     showing raw top result(s) anyway so you are not left empty-handed" and then
#     iterated an EMPTY list. 19 of the 37 files then in scout/cc-sonar-results/ are
#     exactly that: a reassurance followed by nothing. Exit code 0.  (`any([])` is False.)
#   * `--limit` truncated GitHub's ranking BEFORE the client-side proven-or-fresh
#     filter, so the "fresh but small" lane the filter exists to rescue was unreachable.
#   * `2>&1` merged gh's stderr into the JSON, so any gh warning would have produced a
#     header-only file with no error shown.
#   * Two different long problems on the same day collided on one 50-char slug filename.
#   * One query shape only: name+description. It could not see GitHub's topic graph,
#     where the large curated answers actually live.
#
# It no longer carries its own copy of that logic. It calls the SAME sweep the
# cc-brain MCP tool calls (sonar_sweep in audit-render/cc-brain-plugin/mcp-server/
# server.py), so the two surfaces cannot drift into different bugs again — which is
# exactly what had already happened by 2026-08-01.
#
# Needs: `gh` CLI, authenticated, real internet — same as empire SONAR. Confirmed
# proxy blocks curl/gh's access to api.github.com specifically (403 from the proxy,
# not a real GitHub response) and device_bash (the local Linux VM) has neither `gh`
# nor internet either way — so THIS SCRIPT, which shells out to the real `gh`
# CORRECTED 2026-08-05 (was WRONG since 2026-07-24): the line above used to claim
# against api.github.com directly (slower, by-hand, no `gh` niceties) — NOT this
#
# Usage:
#   bash cc-sonar.sh "rate limiter for a node scraper"
#   bash cc-sonar.sh "linkedin automation without getting flagged" --limit 8 --min-stars 100
set -u
cd "$(dirname "$0")" || exit 2
SELF="$(pwd)"

SERVER="$SELF/sweep/sonar_sweep.py"
[ -f "$SERVER" ] || { echo "cc-sonar: MISSING SOURCE — $SERVER not found. This script deliberately has no second copy of the sweep; without that file it refuses rather than answering from a divergent duplicate."; exit 2; }

command -v gh >/dev/null 2>&1 || { echo "cc-sonar: gh CLI not found — install the GitHub CLI and run 'gh auth login'."; exit 2; }
gh auth status >/dev/null 2>&1 || { echo "cc-sonar: gh is not authenticated — run 'gh auth login' first."; exit 2; }

PROBLEM=""
LIMIT=8
MIN_STARS=50
EVIDENCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --limit) LIMIT="${2:-8}"; shift 2 ;;
    --min-stars) MIN_STARS="${2:-50}"; shift 2 ;;
    --evidence) EVIDENCE=1; shift ;;   # V3.6: repo->file->fragment packets for query-word hits (code search, 10/min)
    *) PROBLEM="${PROBLEM:+$PROBLEM }$1"; shift ;;
  esac
done
[ -n "$PROBLEM" ] || { echo "Usage: bash cc-sonar.sh \"<problem description>\" [--limit N] [--min-stars N]"; exit 2; }

mkdir -p "$SELF/scout/cc-sonar-results"
echo "cc-sonar: multi-angle sweep for: \"$PROBLEM\" (keyword + topic graph + readme + unfloored)..."

# The sweep writes its own scout artifact and returns a dict. We render the human view
# here and set the exit code from what actually happened — a FAILED search exits 1, a
# PARTIAL_FAILURE or RATE_LIMITED_PARTIAL sweep exits 2, a clean sweep exits 0.
CC_CRM_ROOT="${CC_CRM_ROOT:-$SELF}" \
CC_SONAR_PROBLEM="$PROBLEM" CC_SONAR_LIMIT="$LIMIT" CC_SONAR_MIN_STARS="$MIN_STARS" \
CC_SONAR_SERVER="$SERVER" CC_SONAR_EVIDENCE="$EVIDENCE" python3 - <<'PYEOF'
import importlib.util, os, sys

spec = importlib.util.spec_from_file_location("cc_brain_server", os.environ["CC_SONAR_SERVER"])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

out = mod.sonar_sweep(os.environ["CC_SONAR_PROBLEM"],
                      limit=int(os.environ["CC_SONAR_LIMIT"]),
                      min_stars=int(os.environ["CC_SONAR_MIN_STARS"]),
                      evidence=os.environ.get("CC_SONAR_EVIDENCE") == "1")

for pkt in (out.get("evidence") or []):
    print("\n🔬 EVIDENCE %s — %s" % (pkt["repository"], pkt["status"]))
    for f in pkt.get("files", []):
        print("   %s :: %s" % (f.get("path"), (f.get("fragment") or "")[:120]))
if out.get("FAILED"):
    print("\n❌ %s" % out["FAILED"])
    print("   %s" % out.get("error", ""))
    print("   DO NOT TREAT AS: %s" % out.get("do_not_treat_as", ""))
    for a in out.get("angles") or []:
        print("   - %-22s %s  %s" % (a.get("angle"), a.get("status"), a.get("error") or ""))
    sys.exit(1)

print('\n## SONAR (multi-angle sweep) — "%s"' % out["original"])
print("query sent: %r   kept: %s" % (out["query_sent"], ", ".join(out["keywords_kept"])))
if out.get("dropped_words"):
    print("WORDS DROPPED FROM YOUR QUERY: %s" % ", ".join(out["dropped_words"]))
    for d in out["dropped_words_why"]:
        print("   · %s" % d)
print("angles:")
for a in out.get("angles") or []:
    print("   - %-22s %-8s %s" % (a["angle"], a["status"],
                                  ("%s row(s)" % a["returned"]) if a["status"] == "ok" else (a.get("error") or "")))
c = out["counts"]
print("matched %s · shown %s · dropped_archived %s · dropped_below_%s★ %s · curated_lists %s · beyond_limit %s (all accounted for: %s)"
      % (c["matched_total_deduped"], c["shown"], c["dropped_archived"], out["min_stars"],
         c["dropped_below_star_floor"], c["set_aside_curated_lists"], c["dropped_beyond_limit"],
         c["all_accounted_for"]))
print("state: %s" % out["state"])
if out.get("PARTIAL_FAILURE"):
    print("⚠  %s" % out["PARTIAL_FAILURE"])

# v3 diagnostics (S9) — compact, printed only when the field is actually present.
if out.get("topic_discovery") is not None:
    print("topic_discovery: %s" % out["topic_discovery"])
if out.get("synonyms_tried") is not None:
    print("synonyms tried: %d" % len(out["synonyms_tried"]))
if out.get("snowball_fired") is not None:
    print("snowball fired: %d" % len(out["snowball_fired"]))
if out.get("vocabulary_loaded") is not None or out.get("vocabulary_applied") is not None:
    applied = out.get("vocabulary_applied") or []
    print("vocabulary: %s learned term(s) on file, %d applied this sweep%s"
          % (out.get("vocabulary_loaded"), len(applied),
             (" (%s)" % ", ".join(applied)) if applied else ""))
if out.get("vocabulary_persist_error"):
    print("⚠⚠ VOCABULARY PERSIST ERROR (learning was NOT saved this sweep): %s" % out["vocabulary_persist_error"])
if out.get("previous_hunts"):
    print("previous hunts on this exact problem: %d" % len(out["previous_hunts"]))
    for h in out["previous_hunts"]:
        print("   - %s (%s)" % (h.get("file"), h.get("date")))
if out.get("gh_calls") is not None:
    print("gh calls fired: %s" % out["gh_calls"])
if out.get("rate_limit_waits"):
    print("waited out GitHub's rate limit %d time(s), %ds total — resumed automatically, not a failure"
          % (out["rate_limit_waits"], out.get("rate_limit_wait_seconds") or 0))
if out.get("rate_limited"):
    print("⚠⚠ RATE LIMITED — gave up after waiting out the full retry budget; one or more angles "
          "were short-circuited, not run. Do NOT treat as zero.")
if out.get("serving_stale_vs_source"):
    sv = out["serving_stale_vs_source"]
    print("⚠  PLUGIN STALE — serving %s, source now %s. Install newest plugin + restart." % (sv.get("serving"), sv.get("source")))
print("")
for r in out.get("repos") or []:
    print("- %s ⭐%s · pushed %s · via %s — %s  ·  %s"
          % (r["fullName"], r["stars"], r["pushed"], "+".join(r["found_by"]), r["description"], r["url"]))
for ang, tops in (out.get("top_by_angle") or {}).items():
    print("best from %-24s %s" % (ang, ", ".join(
        "%s (%s%s)" % (t["fullName"], t["stars"], ", BELOW floor" if t["below_star_floor"] else "")
        for t in tops) or "nothing"))
print("")
for r in out.get("curated_lists") or []:
    print("- (curated link-list, a map not an implementation) %s ⭐%s · via %s  ·  %s"
          % (r["fullName"], r["stars"], "+".join(r["found_by"]), r["url"]))
for r in out.get("below_star_floor_examples") or []:
    print("- (BELOW the %s★ floor, shown so you know it exists) %s ⭐%s · via %s  ·  %s"
          % (out["min_stars"], r["fullName"], r["stars"], "+".join(r["found_by"]), r["url"]))
for r in out.get("archived_excluded") or []:
    print("- (ARCHIVED, excluded) %s ⭐%s  ·  %s" % (r["fullName"], r["stars"], r["url"]))
print("")
print("Surface-only: this never auto-installs anything. Read the repo, decide, then port/adapt by hand.")
print("cc-sonar: saved to %s" % out.get("artifact"))

# Exit codes (S9): 1 stays reserved for FAILED (handled above, exits early). A
# PARTIAL_FAILURE or a RATE_LIMITED_PARTIAL sweep completed but is not fully
# trustworthy, so it gets its own code rather than a silent 0. Only a clean
# sweep exits 0.
exit_code = 0
if out.get("PARTIAL_FAILURE") or str(out.get("state", "")).startswith("RATE_LIMITED_PARTIAL"):
    exit_code = 2
sys.exit(exit_code)
PYEOF
CC_SONAR_EXIT=$?
exit "$CC_SONAR_EXIT"
