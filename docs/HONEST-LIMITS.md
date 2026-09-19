# SONAR HANDOFF — 2026-09-06 (start the next Sonar chat HERE, not in the the home project chat)

Everything the the home project campaign (D1–D20, 2026-09-05 → 09-06) measured about `cc_sonar` / `cc-sonar.sh` (cc-brain plugin, sweep-v3.4). Numbers only from runs; the raw results are on disk.

## What was tested, and how
- **Instrument:** `cc-sonar-capacity-bench.py` (runs the SAME `sonar_sweep()` the MCP tool runs, SEQUENTIALLY, timed; 15 queries) + `cc-sonar-capacity-score.py` (scorecard). Raw run: `scout/cc-sonar-bench-2026-09-06.json` (14:17–14:32Z on the Mac). Not to be confused with the older `cc-sonar-bench.js` (the sealed-blind-ranking BENCHMARK CONTRACT, wired into cc-verify) — the two measure different things: the .js one measures reassessment honesty, the .py one measures recall/latency/noise. Both stay.
- **Known-answer** (5): mutation testing javascript → stryker-mutator/stryker-js · property based testing typescript → dubzzz/fast-check · metro2 credit reporting → moov-io/metro2 · pdf.js text extraction → mozilla/pdf.js · pdfminer layout analysis → pdfminer/pdfminer.six.
- **Formulation experiment** (7 shapes of ONE mechanism, PDF layout text reconstruction): topic "pdf" · keyword "pdf layout text" · phrase "pdftotext layout" · mechanism "glyph gap word break" · implementation "TextOutputDev" · readme "preserve layout text extraction" · API "getTextContent whitespace".
- **Unknown-answer** (3, real CC gaps): "two column wrapped continuation parser" · "golden file parser regression ledger" · "tradeline bureau column parser".
- Earlier in the campaign: D16 (stryker/fast-check/pdftabextract/Parsr fetched + read), D17 (3 sweeps; the PHRASE angle found PDFLayoutTextStripper), D18/D19 (mechanism sweeps; 5 of 6 parallel MCP calls "timed out").

## Results (measured)
| measure | value |
|---|---|
| timeout rate, sequential | **0/15** (median 42 s · min 5 s · max 114 s · total 882 s) |
| timeout rate through the MCP tool | 3 of 15 sweeps exceed the tool's **60 s transport cap** (K2 114 s, K3 100 s, K5 98 s); 5 of 6 PARALLEL calls died at the cap this morning — **the sweeps still completed and persisted** under `scout/cc-sonar-results/` |
| known-answer recall, any angle (`top_by_angle`) | **3/5** (stryker, fast-check, metro2) |
| known-answer recall, merged shown-8 | **2/5** (stryker #4, fast-check #5) |
| first page (rank ≤ 5) | **2/5** |
| merged-list problem | **moov-io/metro2 was #1 in BOTH the keyword and topic angles and absent from the merged list** — star-sort buries agreement hits (this is the 2026-08-15 lesson, re-measured) |
| query truncation | the query sent is the first TWO kept words: "pdf.js text extraction" → "pdf.js text"; "pdfminer layout analysis" → "pdfminer layout"; "tradeline bureau column parser" → "tradeline bureau" — the discriminating word is dropped every time |
| vocabulary contamination | `snowball:programming/free/development` + `synonym:*` angles = **50–70% of matched rows in 15/15 sweeps, 0 hits** (build-your-own-x, freeCodeCamp, public-apis in every sweep) |
| topic angle | mechanism-blind: "text" → speech-to-text / text-classification; "layout" → UI kits; "bureau" → bureau_of_meteorology; "whitespace" → the Whitespace language |
| formulation experiment | **0/7** shapes put a PDF-text mechanism repo in the shown 8; keyword+phrase AGREEMENT on two specific nouns was the only shape that ranked an on-topic repo #1 in an angle (pdfminer-layout-scanner) |
| unknown-answer hunts | **0/3 useful** (auth portals, dictionaries, weather) |
| what Sonar found this campaign | PDFLayoutTextStripper's glyph rule (phrase angle; never needed), stryker/fast-check (known names), pdfminer-layout-scanner (documentation) |
| what deterministic instruments found instead | every real defect of D16–D20: ledger grading, live-text lane, scan-object parity (`cc-scan-parity.ts --check`) — 14 mechanisms, 0 from Sonar |

## Verdict (evidence, not opinion)
Sonar is a **scout for NAMED prior art with distinctive nouns** (mutation testing, property testing, metro2). It is **not a mechanism-discovery engine**: it cannot express a mechanism-shaped question (two-word cut + topic explosion + learned noise), and its merged ranking hides its own best angle hits. Use it less, sequentially, with the two most specific nouns, and read `top_by_angle` before the merged list.

## Proposed Sonar v2 changes (each backed by a row above; ship with the packaging gate #21/#23/#24 and the belt check)
1. Send ALL kept words to the keyword/phrase angles (or run first-two AND all).
2. `snowball:*` / learned vocabulary OFF by default; only vocabulary from the query's own words.
3. Rank by multi-angle AGREEMENT first, stars second; always print `top_by_angle` #1s above the merged list.
4. Topic angle only when a kept compound slug exists (mutation-testing, property-based-testing, metro2) — never a single generic word.
5. MCP path must never block: return a run id, persist the sweep, let `cc_sonar` fetch the result (the CLI path already persists).
6. Re-run `cc-sonar-capacity-bench.py` after each change; the scorecard is the acceptance test (recall any-angle ≥ 5/5 and merged ≥ 4/5 on the same 5 known answers, noise share < 10%, 0 transport failures).

## Where things are
CRM root: `cc-sonar.sh` (CLI, same code as the MCP), `cc-sonar-bench.js` (benchmark contract, wired), `cc-sonar-capacity-bench.py`, `cc-sonar-capacity-score.py`, `TOOLBOX.md` (registry), `LEARNINGS-ARCHIVE.md` L-2026-09-06-a/-b, `scout/cc-sonar-results/` (every sweep), `scout/cc-sonar-bench-2026-09-06.json` (this scorecard's raw data), `docs/SONAR-INTELLIGENCE-ENGINE.md`, `docs/SONAR-SOLUTIONS-PLAYBOOK.md` (older design docs). Plugin source: `audit-render/cc-brain-plugin/mcp-server/server.py` (`sonar_sweep`). Do NOT confuse with the `sonar-*.js` research OS at the CRM root (memory #21).
