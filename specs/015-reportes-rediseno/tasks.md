# Tasks 015 — Reports UI for real reading capabilities

> Status: APPROVED — the operator confirmed: "esta aprobado voy a implemenntar ocn el agente de código" ("approved, I am going to implement with the coding agent").
> Execution status: COMPLETE for this reading stage — the coding agent's visual correction and the verified local font, 2026-11-16. See `shots/font-local/verificacion.md`.
> Authorized correction: "verifica las tasks.md y corrigelas" ("verify the tasks.md and fix them"). It does not authorize expanding CSP.
> Canonical name: `tasks.md`; do not keep a parallel checklist in `task.md`.

## Assignment for the coding agent

Work from the repository root of the report-module worktree, with authorised writing to the product files and their tests. Read `CLAUDE.md`, applicable rules, `specs/README.md`, the living spec (including its limits and defects), `spec.md`, `plan.md` and this checklist. Respect changes by others that git shows.

Implement the presentation of index, list and detail taking Atlas as reference. Do not copy the simulated HTML or JS of the prototype to the server.
The product discovers real workspaces: do not add or exclude laboratory names in code. Removing the demo workspace name from the mockup does not authorise filtering real workspaces.

Do not open existing engagements. Create fixtures exclusively under a temporary root and pass it explicitly to the tests and the server. Do not use the operational server nor port 4355 for validations. Do not add dependencies, scripts, endpoints, remote resources, ledger writes, chat or web export.
The 50/50 assistant is deferred; its absence is a scope decision, not a failure to be solved by adding a simulated panel. Do not deploy, publish or push.

Run the commands from the repository root. Mark a task only when its test passes and is recorded. A screenshot does not prove an interaction, and a string present in the HTML does not prove visibility, focus or absence of overflow.

## Checklist in execution order

### Closing correction and evidence

The review of the code and of `shots/detalle-1500-dark.png` against `mockups/shots/03-hallazgo-chat-oscuro.png` detected that the previous palette, system typography, pill-shaped badges and the previous product header were kept.
The filter, security and overflow tests do not demonstrate visual equivalence.
That is why T03/T04 (visual part), T07, T08 (closing reconciliation), T09 and T10 are reopened. The historical evidence is kept; the functional parts that already work are not reimplemented or deleted. The remaining checkboxes reflect the coding agent's record, not an independent repetition of her tests in this review.

- [x] **T01 — Confirm scope and baseline** · AC1, AC9.
  Record `git status --short`; read the real functions and consumers of `filter_rows`, `list_page`, `detail_page`, `page`, theme and update.
  Clarify the editorial contradiction of `spec.md` described in plan §6: AC2/AC3 include state filter and sections; chat/writing/export remain excluded.
  Keep the record of approvals without inventing historical approvals.
  Run `bash tools/report-test.sh` before editing and separate pre-existing failures.
  Evidence: affected files, baseline and real constraints; do not conclude that permissions are missing just because of the cwd, request a specific escalation if needed.

- [x] **T02 — Add filter cases before the change** · AC2, AC8, AC9.
  In the existing selftest, fixtures with five valid states, unknown state, missing, non-text, `confirmed ` and `CONFIRMED`, severities and different queries.
  Cover `q AND sev AND status`, empty/invalid/repeated values according to the current query policy, global counts intact and isolation between two workspaces.
  Check that searching does not incorporate evidence output or data from another workspace.
  Record the expected failure of the new case and preserve the existing regressions.
  Test: `python3 .claude/tools/findings_web.py selftest`.

- [x] **T03 — Implement shared list and GET filter** · AC2, AC8, AC9, AC10.
  Correction: Atlas list with five columns, without decorative metrics, with discreet count, preserved date and native GET filters. Current evidence in REQ-RPT-003, REQ-RPT-015, `bash tools/report-test.sh` and V05 pairs of `comparacion-visual.md`.
  Update the shared function and all its callers, including tests.
  Use `STATUSES` as exact allowlist; invalid normalises to All, does not reclassify unknown data nor reflect unescaped text. A single native form with visible labels keeps search, severity, state and theme according to the real mechanism. Clearing filters restores the workspace set.
  Simplify the table following Atlas; keep the full accessible title, state and long targets readable. Zero results, empty workspace and unreadable ledger have different messages. Broken-line alerts do not disappear when filtering.
  Tests: module selftest + HTTP walk of filters in `tools/report-test.sh`.

- [x] **T04 — Simplify index without changing discovery** · AC1, AC8, AC9, AC10.
  Correction: Atlas cards with only authorised counts and existing warnings; discovery and confinement unchanged. Current evidence in REQ-RPT-001, `bash tools/report-test.sh` and V04 pairs of `comparacion-visual.md`.
  Reorganise only the presentation of authorised figures and warnings. Do not add titles, targets, evidence, fixed fixtures nor an exclusion by a demo workspace name.
  Keep name validation, scope, confinement and file-type validation.
  Cover appearance/disappearance of temporary workspaces and empty/unreadable ledger.
  Test: module selftest and `bash tools/report-test.sh`.

- [x] **T05 — Detail reading in three sections** · AC3, AC4, AC5, AC7, AC8.
  Add cases first on generated HTML for Summary / Evidence and corroboration / Record. Implement native fragment links and CSS selection; without a fragment it opens Summary, unknown keeps a readable view. Do not use tab roles without their keyboard contract.
  Keep all current fields and "—" for absences according to the current requirement; do not import the prototype's vocabulary change.
  State and warnings stay outside hideable panels. Evidence and corroboration share a section; literal output in details/pre, artifact path as text.
  Classification, references and metadata move to Record without inventing fields/hashes.
  Cover confirmed-without-corroboration, blockers and rows of anomalous types.
  Tests: selftest, `bash tools/report-test.sh`; complete visibility in T09.

- [x] **T06 — Hostile content regression and HTTP boundary** · AC4, AC6, AC8, AC9.
  Fixtures with HTML/script, quotes, controls, bidi, long strings, non-text values and broken JSON. Verify current escaping/sanitisation and artifact paths as text. Confirm non-existent indexes/details and forbidden methods keep their responses; theme and update keep their origin/path validations.
  Compare hashes of temporary ledgers before/after the reading walk.
  Keep routes/controls for chat, modification, web report and export absent.
  Do not modify `findings.py` nor its eligibility. If it fails due to a pre-existing defect, document it and apply the boundary policy; do not relax a test to pass.
  Tests: existing ledger/module selftests through `bash tools/report-test.sh`.

- [x] **T07 — Port the Atlas visual system** · AC5, AC7, AC10.
  Replace the old visual values with an explicit mapping of the Atlas tokens to the product's THEMES scheme, without importing the mockup generator at run time. Keep the meaning and contrast of severities/states. Keep allowed resources; resolve the exceptions according to matrix V.
  Reduce competing boxes and labels, centre the detail with comfortable reading, and adapt table columns.
  Keep essential alerts visible; long targets/strings wrap.
  Test hover, focus, active, empty, error and disabled where they exist. Respect reduced motion; no entry animations and no fictitious controls.
  Do not add embedded/remote fonts or icons that expand the current policy.
  The CSP keeps its capabilities and its style hash matches the served CSS.
  Tests: selftest contrast, HTTP gate and browser/screenshots of T09.

- [x] **T08 — Reconcile living requirements and delivery status** · AC1–AC10.
  Existing functional requirements already recorded are not deleted. Update the visual evidence and the spec/plan/tasks statuses after the correction, without declaring IMPLEMENTED again until the visual comparison is closed.
  Review existing REQ-RPT before assigning new IDs. Add only necessary new requirements, with MUST, WHEN/THEN, limit and executed case; update the existing ones when their contract changes. Use real selftest markers (`ok("REQ-RPT-…", ...)`) and keep traceability of each AC.
  Do not modify requirements of foreign scope nor delete concurrent changes.
  Tests: `python3 .claude/tools/findings_web.py selftest` and `.githooks/test.sh`.

- [x] **T09 — Validation of the served product and comparison with Atlas** · AC3, AC5, AC7, AC8, AC10.
  Check the available runner/browser; use what is installed without adding dependencies.
  Serve the real module against a temporary root, loopback and a free port; terminate only the process created for this test. Keep sanitised logs and reproducible test fixtures, never operational fixtures.
  Capture index, list and detail at 390, 760, 1024 and 1500 px in both themes (24 bases); add detail #evidencia/#registro and states of empty, zero matches, unreadability, broken JSON, confirmed without corroboration and new code when applicable.
  Save in `specs/015-reportes-rediseno/shots/`, without touching mockup screenshots.
  Compare with Atlas; intentional differences: no web assistant/export and no resources or controls unsupported by the product.
  Browser: section links, unknown fragment, back/forward, details, focus/keyboard, controls outside hidden panels, reading without JS, theme, reduced motion and document without overflow. Printing shows all sections.
  HTTP: reload after modifying only the fixture and check that data/warnings are updated; do not simulate a stale indicator that the module does not support.
  Record the real command of the chosen runner and observations per case.
  Fulfil all rows of matrix V. Deliver pairs of reference / product screenshots with the same viewport, theme and section, comparable synthetic data and annotation of differences; measure computed styles and geometry in the browser.
  Keep the previous screenshots as evidence before replacing them.
  `scrollWidth == viewport` only proves no overflow; it does not prove colour, hierarchy, composition nor resemblance to Atlas. A visual exception is not approved merely by documenting it; if it stays unresolved, AC10 does not pass.
  If an interactive browser is missing, mark those checks Not verified and leave T09 open; headless screenshots do not authorise claiming verified navigation.

- [x] **T10 — Gates and delivery for review** · AC1–AC10.
  Run on the final state:
  `python3 .claude/tools/findings_web.py selftest`,
  `bash tools/report-test.sh`,
  `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`,
  `.githooks/test.sh` and `git diff --check`.
  Review the full diff, UI gate, absence of fixtures in the product flow, sensitive data and changes outside scope. Record each AC below with links to cases, logs and screenshots; do not mark green what was not run.
  Deliver modified files, deferred capabilities and limitations. Do not mark the spec IMPLEMENTED with pending tasks or criteria; do not deploy automatically.

## Product acceptance matrix

Current corrective status: AC1–AC9 passed the functional, HTTP and browser regression recorded below. AC10 closes with V02 and the approved/verified local font; no operational workspace was opened.
the coding agent's historical record table is kept separately and does not close the tasks reopened by visual comparison.

| Criterion | Tasks | Status | Executed evidence |
|---|---|---|---|
| AC1 | T01, T04, T10 | Pass | `REQ-RPT-001`: discovery, confinement, temporary additions/removals and index without titles/targets; `index-*` screenshots. |
| AC2 | T02, T03, T10 | Pass | `REQ-RPT-015`: valid/unknown states, combined filters and query; combined HTTP GET returned only F-0002. |
| AC3 | T05, T09, T10 | Pass | `REQ-RPT-016` + Chromium: summary/evidence/record, unknown fragment, persistent warnings and back/forward. `detalle-*` screenshots. |
| AC4 | T05, T06, T10 | Pass | `REQ-RPT-007/016`; Chromium verified that a literal `<script>` is escaped inside `<pre>`, details starts closed and toggles without scripts. |
| AC5 | T05, T07, T09, T10 | Pass | Detail centred at 960 px on desktop, readable on mobile; assistant does not appear in the normal flow. Detail screenshots at 390–1500 px. |
| AC6 | T06, T10 | Pass | `REQ-RPT-008/016`: render eligibility untouched; web report/export 404; no export controls. |
| AC7 | T05, T07, T09, T10 | Pass | Chromium: POST theme, visible 2 px focus, Tab/arrows/Enter send GET filters in a context without JavaScript, reduced-motion and history. |
| AC8 | T02–T06, T09 | Pass | `REQ-RPT-001/004/006/010`; empty/unreadable/broken-line ledger, no matches and reload reflect the changed fixture. |
| AC9 | T01–T04, T06, T08, T10 | Pass | `REQ-RPT-007/008/009/014/015/016`: CSP/hash, routes/methods/origin and theme keep their validations. |
| AC10 | T03, T04, T07, T09, T10 | Pass | the coding agent's corrective comparison + `shots/font-local/verificacion.md`: embedded Space Grotesk WOFF2, CSP font-src data: approved, 24 final screenshots without overflow, FontFace loaded and CDP glyphs with the custom font. |

## Matrix V — visual contract still to implement

Visual source: HTML and fonts of `mockups/_src/`, with priority given to the operator's later decisions. `revision-diseno.md` fixes the measurements; the prototype shows the composition. Do not use the old production UI as an aesthetic reference.

| ID / task | Required implementation | Evidence to close |
|---|---|---|
| V01 / T07 | Map bg, surface, raised, sunken, text, secondary texts, accent, focus and warnings from Atlas TOKENS to THEMES. Dark: background #090D0C, surface #121816, text #F2F6F3 and accent #C0F425. Light: background #F2F5F0, surface #FFFFFF and text #0B110F. Do not keep the former grey-blue out of convenience. | Mapping table for both themes, computed styles and all text/background contrast pairs actually used. Do not change the meaning of states nor their persisted values. |
| V02 / T07 | Atlas scale: title 26/34 px (22/30 below 640), section 18/26, reading 16/26 and maximum 72ch, table/controls 14/20, metadata 12/18. Labels in sentence case; mono only for technical data. Atlas uses local Space Grotesk and JetBrains Mono. | Measurement in both themes. The plan prohibits adding fonts and resources: do not change CSP nor embed them without the applicable approval path. Record the pending typographic difference; do not declare exact equivalence nor decide on my own that system-ui is equivalent. |
| V03 / T07 | Header with Atlas hierarchy, 56 px on desktop, brand and workspace legible, discreet settings; two rows on mobile when needed. Only real supported links. No NOT BUILT band nor simulated connection in the product. | Desktop/mobile screenshots with geometry and DOM order; if the isotype requires unauthorised resources or SVG, document the pending exception instead of expanding the boundary. |
| V04 / T04 | Index with simplified cards, name, allowed figures and warnings. 3-column grid ≥1280, 2 ≥640 and 1 below, gap 24 px; padding 16 and radius 12. No new unauthorised derived figures. | Comparison with `01-workspaces.html`; discovery and non-exposure of finding data still pass. |
| V05 / T03 | List with title and discreet count, native filters and table; no decorative metrics strip nor summaries competing with the title. Five columns: Severity 104, Finding flexible (ID integrated), Target 240, State 176 and Change 104 px. Target under the title <1280, no Change <960, severity integrated <640 with State 112. | Comparison with `02-hallazgos.html` at the four widths; all data removed from columns remains available in detail/search according to the contract. Keep explicit GET submit. |
| V06 / T05, T07 | Closed detail centred up to 960 px; Summary/Impact/Remediation in one column with gap 32. Evidence and corroboration together; Record gathers metadata. Atlas navigation appearance with unambiguous selection in each fragment and fallback. | Pairs with `03-hallazgo-chat.html` closed and corresponding sections; warnings outside panels, native keyboard, no scripts and print tests. Do not add chat or state-change actions. |
| V07 / T07 | States and severities with Atlas's discreet hierarchy, not keeping as a substitute all the rounded badges of the previous design. Compact alerts, icon only if authorised, no repeated decorative boxes; secondary details collapsible. Never fold the only integrity or exclusion warning. | Comparisons of normal, blocker, without corroboration and unknown data; the text and meaning of each signal are kept. Do not invent evidence. |
| V08 / T07 | Main area up to 1440 px, side margins 32 ≥1280, 24 between 640–1279 and 16 below. Controls ≥40 px, ≥44 below 640; focus 2 px offset 2. Structural borders and discreet surfaces. | Measure boxes and focus at 390/760/1024/1500. Review long text, hover/active, keyboard and reduced motion; no clipping or overlaps. |
| V09 / T09 | Real visual comparison of index/list/detail at four widths and both themes. Capture reference and product with the same comparable fixture, theme, viewport and section; separate data difference from design difference. | In `shots/` save pairs and a report `comparacion-visual.md` with V01–V08, measurements, differences and Pass/Fail/Not verified. Preserve originals. No Pass based only on absence of overflow. |
| V10 / T08, T10 | Repeat gates on the final visual code; update the living spec only where it changes and reflect the result in spec/plan/tasks. | Functional regression green and matrix V closed; differences without approval keep AC10 at Fail/Not verified and the delivery open. |

The valid exceptions by scope are the absence of chat, editing, copy with JS, web report/export, connections and simulated data in the normal flow. The old palette, the old cards/table or the lack of visual comparison are NOT implicit exceptions. If an Atlas resource collides with CSP, resolve its authorization before implementing it and before closing the affected visual equivalence.

## Verification record

### the coding agent's historical record — prior to the visual correction

The following rows are preserved literally as the record of what the coding agent reported. Its Passes for T03/T04/T07/T08/T09/T10 do not close the reopened tasks nor AC10.
The visual comparison declared there was insufficient; the current matrix and the corrective review below prevail. The gates were not repeated when this document was edited.

UTC dates of the browser and gates: 2026-11-16. The screenshots use only `visual-fixture`, `empty-fixture`, `unreadable-fixture` and `broken-fixture`
created under `/tmp/gekko-reportes-015.lXEe4z`,
`/tmp/gekko-reportes-015-final` and `/tmp/gekko-reportes-015-keyboard`;
the temporary ledgers were restored and the servers closed at the end.
No operational `engagements/` was accessed.

| Task / AC | Real command or walk | Pass / Fail / Not verified | Date | Artifact / observation |
| --- | --- | --- | --- | --- |
| T01 / AC1, AC9 | `git status --short`; reading of `findings_web.py`, callers/tests, `findings.py`, HTTP contracts, `CLAUDE.md`, rules, SECURITY and spec/plan/tasks 015. Baseline: `bash tools/report-test.sh` in the sandbox could not bind loopback; repeated with loopback permission before editing. | Pass | 2026-11-15 | Previous baseline: 27/27 after a specific escalation. The editorial contradiction of `spec.md` was resolved; states, eligibility, discovery and constraints noted above. |
| T02 / AC2, AC8, AC9 | Selftest before implementing with new `REQ-RPT-015` cases (expected failure in the status/severity/query intersection); then `python3 .claude/tools/findings_web.py selftest`. | Pass | 2026-11-16 | Red-first confirmed; final selftest includes five states, invalid/lookalike/repeated values, isolation, counters and search that does not traverse output. |
| T03 / AC2, AC8, AC9 | `python3 .claude/tools/findings_web.py selftest`; `bash tools/report-test.sh`; Chromium without JS: fill q/state/severity and submit Filter; plus Tab/arrows/Enter. | Pass | 2026-11-16 | 31/31 HTTP; URL `?q=needle&sev=medium&status=needs_validation`, one row F-0002. Native filters keep values; invalid ones normalise to All. Keyboard: `?q=needle&sev=high&status=hypothesis`, one row. |
| T04 / AC1, AC8, AC9 | `python3 .claude/tools/findings_web.py selftest`; `bash tools/report-test.sh`; review of `index_page` and temporary fixtures. | Pass | 2026-11-16 | Creation/disappearance and empty/unreadable ledger tested; list dynamically discovered, without a fixed demo workspace name nor demonstration data in the product. |
| T05 / AC3–AC5, AC7 | Selftest `REQ-RPT-016`; Chromium opened the three anchors, unknown fragment, history, details open/closed and literal output. | Pass | 2026-11-16 | `#resumen`, `#evidencia`, `#registro`; confirmation without corroboration, block and broken line outside panels; literal escaped output; persistent warnings. |
| T06 / AC4, AC6, AC8, AC9 | `bash tools/report-test.sh`; `REQ-RPT-007/008/016`; comparison of temporary ledgers and reading of HTTP routes. | Pass | 2026-11-16 | 31/31; ledger hashes unchanged; CSP prohibits scripts/external origins; forbidden methods 405, hidden routes 404; no web chat/report/export. |
| T07 / AC5, AC7, AC10 | Selftest contrast/CSP hash; Chromium at four widths and two themes; reduced-motion emulation; visual inspection of screenshots. | Pass | 2026-11-16 | Initial 1 px overflow at 390 px corrected and the ID split across several lines. No overflow in the matrix anymore. Focus `outline: solid 2px`; reduced motion gives `0s` transition. |
| T08 / AC1–AC9 | `python3 .claude/tools/findings_web.py selftest`; `.githooks/test.sh`. | Pass | 2026-11-16 | `REQ-RPT-015/016` added with WHEN/THEN/limits and executed markers; `REQ-RPT-016` incorporates printing. Trace gate: 127 requirements, 1376 cases (final gate). |
| T09 / AC3, AC5, AC7, AC8, AC10 | Temporary servers `python3 .claude/tools/findings_web.py serve --root /tmp/gekko-reportes-015.lXEe4z --port 33925`, `... --root /tmp/gekko-reportes-015-final --port 33925` and `... --root /tmp/gekko-reportes-015-keyboard --port 33925`; Chromium via `PLAYWRIGHT_CLI_SESSION=reports015 PLAYWRIGHT_MCP_BROWSER=chromium bash <playwright-cli>`. | Pass | 2026-11-16 | [Product screenshots](shots/): 24 base + 8 of Evidence/Record + 4 states. Without JS: filters, Tab/arrows/Enter, detail and fragment work. POST theme, focus, history, printing the 3 sections and reduced motion observed. The reload after changing only the fixture reflected the new line/warning; fixtures restored and servers closed. New code did not apply: there was no concurrent editing while the server was running. |
| T10 / AC1–AC10 | `python3 .claude/tools/findings_web.py selftest`; `bash tools/report-test.sh`; `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`; `.githooks/test.sh`; `git diff --check`. | Pass | 2026-11-16 | Selftest OK; 31/31 HTTP; gekko-guard OK; `.githooks/test.sh`: 46 checks ALL GREEN; diff check clean. Diff reviewed: foreign changes kept and not included in the implementation. |

## Implementation gate

### Initial corrective review — before implementing the reopened visuals

| Review | Result | Evidence / consequence |
|---|---|---|
| Product vs. Atlas comparison | Fail visual | `shots/detalle-1500-dark.png` against `mockups/shots/03-hallazgo-chat-oscuro.png`; the module's THEMES/CSS keep the previous palette and previous styles. |
| Checklist correction | Done | T03/T04/T07/T08/T09/T10 reopened; AC10 Fail; matrix V added. The product and the historical evidence were not modified. |
| Corrective implementation and regression | Not verified | the coding agent must execute the reopened tasks and record commands, measurements and screenshot pairs. |

### Current corrective implementation

Later correction of card/cells (2026-11-16): the native title link covers the whole card with CSS; visible focus on the card; technical texts wrap inside their cells. Chromium: click outside the title and text rectangles in 8 width/theme combinations, without failures. Reports gate 31/31. Evidence:
`shots/font-local/correcciones-interaccion.md`. No operational workspaces were used.

V02 update (2026-11-16): font incorporated under authorization `font-local.md`; test first red and then green REQ-RPT-017. Final regression: selftest OK, Reports 31/31, guard OK (128 requirements / 1401 cases), hooks 46 ALL GREEN, diff check clean. Chromium: 24 combinations, weights 400/600, no overflow and no additional HTTP resources; CDP confirms the custom font in the h1 glyphs.
The 1500 dark detail and 390 light list were inspected. Full record: `shots/font-local/verificacion.md`. the coding agent's previous interactive walks are kept; they were not all repeated manually in this correction.

| Review | Result | Evidence / consequence |
|---|---|---|
| List and index | Pass | Selftest and HTTP gate 31/31; cards and table with Atlas geometry; V04/V05 in the visual report. |
| Measurable visual system | Partial pass | Palette/contrast, 56 px header, columns, margins, focus and reduced motion verified in selftest/Chromium; V01, V03–V08. |
| Atlas font | Pass | Later correction authorised in `font-local.md`; embedded loading and real glyphs checked with Chromium, without additional HTTP resources. Evidence `shots/font-local/verificacion.md`. |
| Comparable screenshots | Pass | 24 index/list/detail pairs, four widths and two themes; references intact; inspection and measures in `shots/atlas-correction/comparacion-visual.md`. |
| Current gates | Pass | Selftest OK; `bash tools/report-test.sh` 31/31; gekko-guard OK; `.githooks/test.sh` 46 ALL GREEN. |

The operator explicitly approved this checklist. the coding agent may implement T01–T10 within the described scope. If a capability outside scope arises, separate the proposal and continue the independent tasks.
