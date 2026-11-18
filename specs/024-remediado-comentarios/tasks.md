# Tasks 024 — Image in comments, unsaved-changes warning, «Fuera del reporte» and «Remediado»

> Status: `IMPLEMENTADA` (2026-11-18) (derived from the operator's approval of spec and plan, 2026-11-18: «Aprobada, adelante» — "Approved, go ahead"; P1 =
> mandatory text) · Date: 2026-11-18
> Spec: [`spec.md`](spec.md) (`APROBADA`) · Plan: [`plan.md`](plan.md) (`APROBADO`). Branch
> `spec/024-remediado-comentarios`, base `5934973` (`report-module`).
> Each task closes ≥1 criterion (or is a baseline) and names its test. The box is ticked ONLY with the green test and its row
> in the log.

**Tests:** **L** = `python3 .claude/tools/findings.py selftest` · **WS** = `python3 .claude/tools/findings_web.py selftest` ·
**W** = `bash tools/report-test.sh` · **G** = `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types
toolbox/gekko-guard.ts` (prints `REQ trace: …` without FAIL) · **K** = `bash .githooks/test.sh` · **TUI** = `bash
tools/tui-test.sh` · **WST** = `bash tools/ws-test.sh` · **PW** = agent's Playwright run (spec §5 and §7).

**Rules for the agent:**
- **Simple, no over-engineering**: the smallest code that meets each AC; nothing outside plan §3; reuse what 023a
  has (`prepare_images`, `_store_images`, `shot_img`, `captures_section` → `capture_item`, `<details class="adjuntar">`,
  `_comment_append`, `set_row(check=)`, `ticket()`, `parse_multipart`). One case per behavior.
- **Red first** for every new behavior: the case that fails goes before the code and its message goes in the log.
- **Living spec:** each new or amended REQ (plan §4) enters `specs/SECURITY-GUARDRAILS-SPEC.md` in the **same commit**
  as its first case `ok("REQ-…", …)`, so G stays green in each task (deviation from plan §8 step 1, which wrote it
  whole in T1 with G red until T4; same final text). The hook requires the spec next to `findings*.py`,
  `report-test.sh` and the panel; `GEKKO_SPEC_UNCHANGED=1` only in a tests-only commit, noted.
- **Commits:** one per task after its tests are green, `spec 024 Tn: …` in Spanish, **with no AI attribution**.
- **Forbidden:** reading or writing `engagements/` or `.gekko-state/` of any worktree (temporary roots with synthetic workspaces `A`/`B`); using or connecting to 4355, 4356 or 4357; killing processes except one's own by numeric PID (never `pkill -f`/`pgrep -f`); network or real Provider (`SelftestProvider`); push; other worktrees; `~/.codex`; 023b.
- The today's assertions that turn the report page red (plan §3) are **rewritten** to «exactly the fixed script + `CSP_REPORT`»; never deleted. If the plan does not match the code, the code prevails and it is noted; if something cannot be done as written, stop and report it.

## Wave 0 — Baseline
- [x] **T0** — no code. `git status` clean; relocate by name the `file:line` citations of plan §3 (they are from
  `54b5fad`); measure `len(CSS.encode())` (expected 98 197); note the 16 sha256 of 021 AC1 and the `render`
  baseline (REQ-LED-002) as reference for AC11; note `N passed` of W and the total of G · no AC · test: L, WS, W, G,
  K, TUI, WST

## Wave 1 — «Remediado» in the ledger (`findings.py`)
- [x] **T1** — `selftest_remediated`, in red: transition matrix with sha256 of the ledger before/after (from
  corroborated `confirmed` with `retest` → changes; without note, blank, from another status, without corroboration → ≠ 0 naming
  the rule and nothing written; `remediated` → `remediated` keeps the note; → `confirmed` is valid and the note stays);
  `add --status remediated` rejected; `list --status remediated`; real CLI via `subprocess`. Then `STATUSES`,
  docstring, `cmd_add`, `set_row(retest=)` with `not_confirmed`/`no_retest`, `set_evidence`/`cmd_set`/`--retest`. Living
  spec: **REQ-LED-011** new, amendment LED-003 · closes `AC8` · test: L (red → green), G
- [x] **T2** — report in `findings.py`, in red: remediated with canaries in Technical/Executive × md/html/imprimir × es/en
  and `render`/`render --all`/`render --tipo` (after the open ones, «Remediados (N)»/«Remediated (N)», «Nueva prueba»/
  «Retest», status only where the card shows it, count separate only with N > 0, only remediated → empty label and then the block; without note or without corroboration it does not come out; old `blocker` absent); the 16 hashes of 021 AC1 and the LED-002
  baseline equal; confirmed with old `retest` without the note; `DOC_CSS`/`DOWNLOAD_CSS` same sha256. Then
  `LABELS`, `included`, `report_fields`, `render_md`, `DOC`, `report_model`, `render_report`. Living spec: amendments
  LED-002, RPT-046, RPT-047 · closes `AC10`, `AC11` (L part) · test: L (red → green), G
  
## Wave 2 — Web of «Remediado», «outside the report» notice and script (`findings_web.py`)
- [x] **T3** — web status, in red: «Remediado» radio and `retest` textarea in `.need-retest` (`:has()`); body without
  `retest` → 303, repeated → 400, only written with target `remediated`, AC8 rules → 422 in Spanish keeping what was
  written; badge `st-remediated`, filter `?status=remediated`, «Nueva prueba» in the detail only with `retest`;
  token contrast in both themes; web matrix = CLI and radio list (RPT-018/039) adjusted; remediated block in
  `report_body_for` (WS part of AC10/AC11). Then `STATUS_CLASS`/`STATUS_LABEL`, token in `THEMES`, `:has()` rule,
  `state_form`, `post_state`, `list_page`, `detail_page`, `report_body_for`. Living spec: amendments RPT-008, RPT-018,
  RPT-039 · closes `AC9`, `AC10`/`AC11` (WS part) · test: WS (red → green), G
- [x] **T4** — «Fuera del reporte», in red: `confirmed` without corroboration and `remediated` without note written by hand →
  `<details class="prov">` without `open`, «Fuera del reporte (2)», an explanatory line, escaped id, link and reason; no
  loose `<ul>`; with N = 0 it does not appear. Then `report_gap(row)` (replaces `unsupported_confirmed`) and `report_route`.
  Living spec: amendments RPT-004, RPT-021 · closes `AC7` · test: WS (red → green), G
- [x] **T5** — report script, in red (`selftest_unsaved_script`): a single `<script>` = `UNSAVED_JS` just before
  `</body>` on GET, «Vista previa», the report's 409 and 422; sha256 fixed in the test; CSP = exact `CSP_REPORT`;
  `data-sin-guardar` only with `ctx.draft_values`; `UNSAVED_JS` without `fetch`/`XMLHttpRequest`/`Storage`; RPT-054 sweep
  extended: no other route (index, list, detail, gallery, image, 4xx/413, status/edit/comment/chat rejections) carries
  `<script` nor `script-src`; downloads with their CSPs and today's bytes; `markup_problems(report=True)` passes with the
  fixed script and fails with an altered one or a second `<script`; plan §3 assertions rewritten (RPT-007/021/048/051/
  054), hostile cases green. Then `UNSAVED_JS`, `UNSAVED_JS_HASH`, `CSP_REPORT`, `response_headers(csp=)`,
  `page(script=)`, `report_page`, `draft_form`, `markup_problems(report=)`. Living spec: **REQ-RPT-071** new (with the
  sha256), amendments RPT-007, RPT-021, RPT-048, RPT-051, RPT-054 and the line of §4 «Huecos conocidos» (known gaps) · closes `AC4`,
  `AC5` (WS part) · test: WS (red → green), G

## Wave 3 — Comments with image
- [x] **T6** — `findings.py`, in red (`selftest_comment_images`): `comment_add` with `choose` and `images` (union without
  repeats, upload in `evidencia/` with its record), without images byte for byte as today, double submit → one copy, same id with
  other images → `stale`, hash of another workspace or withdrawn → `not_in_gallery`, 9 → `limit`, blank text with
  image → rejection (P1), comments file broken or at the cap → nothing written and no upload, folding of hostile `images`
  → bad line, editing keeps `images`; `gallery_delete` with one row and two comments (`edit` events with the
  same text, removal with `comentarios`, old fingerprint after a new comment → `stale`, broken/over-cap/
  full comments → `comments_state` and nothing written, faults injected at (b), (a), (c), (d) with no reference to a deleted file, without
  comments = today's keys); two threads × 20 removal ‖ comment with image finishes; sha256 of `render*` and deliverables
  equal with and without comments with images. Then `_apply_comment_event`, `_comment_append(before_write=)`,
  `comment_add(images=, choose=)`, `_fold_gallery`, `delete_stamp(comments_size=)`, `gallery_delete`. Living spec:
  **REQ-RPT-070** new, amendments LED-009, LED-010, RPT-037, RPT-060 · closes `AC1`, `AC2`, `AC3` (L part) · test: L
  (red → green), G
- [x] **T7** — web, in red: «Agregar comentario» form multipart with the `<details class="adjuntar">` (live checkboxes of the
  workspace, `input type=file multiple`), without `<script`/events/`style=`; adding with two chosen and one uploaded
  → 303 and the comment shows each image with `capture_item` (`alt="Captura N"`, `ampliar`, «Abrir original»; absent
  or altered → notice with sha256); today's urlencoded byte for byte; rejections with nothing written (invalid image, hash absent/
  withdrawn/from another workspace, > 8 → 422; bad token, `cross-site` → 403; broken or full comments → 409; `elegir`/
  `archivo` in `editar`/`borrar` → 400) and «Vuelve a elegir los archivos…» if there were files; «usada por» with «F-0001 ·
  comentario», 409 of fingerprint and `comments_state` message in the gallery; the detail stops showing the deleted one; `SelftestProvider` body
  equal with and without comments with images. Then `capture_item`, common attach block,
  `comments_section`/`comment_block`, `post_comment(content_type)`, `body_limit`, `gallery_page`/`gallery_refusal`.
  Living spec: amendments RPT-008, RPT-009, RPT-019, RPT-035, RPT-036, RPT-061 · closes `AC1`, `AC2`, `AC3` (WS part) ·
  test: WS (red → green), G

## Wave 4 — Rest of the repo, real HTTP and closing
- [x] **T8** — panel and texts, in red: `FINDING_STATUSES` = `STATUSES` (RPT-003), `countFindings` with seven integers,
  «remediado» row and ` remediados N` only with N > 0, HALLAZGOS card with 8 rows without cutting in `DEFAULT_ROW_CAP`
  (008-AC18). Then `toolbox/gekko-panel.ts` and `gekko-panel-selftest.ts`; one sentence in the docstring, `finding-verifier` and
  `report-writer` of `.claude`/`.pi`/`.codex`, `kb/techniques/finding-triage-gate.md`, `CLAUDE.md`/`AGENTS.md` (twins)
  and `docs/pi-hitl.md` §4c. Living spec: amendments RPT-003, TUI-001, TUI-018 · closes `AC12` (G part) · test: G (red →
  green), TUI, WST
- [x] **T9** — `tools/report-test.sh` (own server on a free port ≠ 4355–4357, numeric PID): `curl -F
  archivo=@png --form-string texto=…` with token scraped and `sha256sum` of the saved one (AC1); `curl -D` of the report (with
  `script-src`) and of the list (without it) (AC5); `--data-urlencode` confirmed → remediated without note (422) and with note (303)
  (AC9); the three `report-writer` name `remediated` (AC12); `len(CSS) ≤ 100 000`, note the real one (expected ≈ 98 442)
  (AC13). Existing checks unchanged. Commit with `GEKKO_SPEC_UNCHANGED=1` if they are only tests, noted · closes
  `AC1`, `AC5`, `AC9`, `AC12`, `AC13` (W part) · test: W
- [x] **T10** — PW (replaces the operator's run; script outside the repo, headless Chromium from the cache, temporary root
  with a copy of `.claude/tools` and a synthetic workspace, free port ≠ 4355–4357, captures outside the repo): AC6
  (`page.on("dialog")` `beforeunload` when changing a field and pressing «Hallazgos»; no dialog on «Guardar borrador» or
  «Vista previa»; dialog on leaving after «Vista previa»; touching nothing, no dialog; `javaScriptEnabled: false` saves and
  does not ask); comment with one chosen and one uploaded, see it, enlarge it, delete it from «Adjuntos» and see it disappear;
  Confirmado → Remediado without note (rejection) and with note (badge) and back; «Fuera del reporte (N)» closed and open;
  Technical and Executive `.md`/`.html`/`.imprimir` with the remediated one and `sha256sum` = Procedencia; light/dark captures at
  1500 and 420 px · closes `AC6` · test: PW (log)
- [x] **T11** — closing: living spec against plan §4 line by line (LED-011, RPT-070/071 and all amendments with their Limit;
  no orphan REQ nor case without REQ); what was delivered against the textual list of AC1–AC13; `CLAUDE.md`/`AGENTS.md`
  (spec list) and `Status` of spec, plan and tasks → `IMPLEMENTADA`; all gates together green on the final tree; the main session
  runs `code-auditor` over the script, the locks and `included` (plan §8 step 9) · closes
  `AC13` · test: L, WS, W, G, K, TUI, WST

## Verification log
> On closing each task: command run + result (green/red, with the red's message) + commit hash.

| Task | Command | Result | Date |
|---|---|---|---|
| T0 | L WS W G K TUI WST baseline | green; CSS 98197 B; W 118 passed; G REQ trace 203 reqs/2554 cases; K 56; TUI 55; WST 186 | 2026-11-18 |
| T1 | L selftest_remediated; G; W | red: AssertionError: remediated is the last status; green (L ok, G REQ trace 204/2569, W 118). Advanced from T3/T8 the minimum so that WS/G/W stay green (label, token, filter, FINDING_STATUSES, remediado row) | 2026-11-18 |
| T2 | L selftest_remediated_report; G; W | red: AssertionError: included: open confirmed first by severity, then remediated ...; green (G REQ trace 204/2584) | 2026-11-18 |
| T3 | WS selftest_remediated_web; G; W | red: AssertionError: REQ-RPT-018 the state form has the Remediado radio and the retest textarea shown only with it chosen (:has); green (WS ok, G REQ trace 204/2595, W 118; CSS 98409 B) | 2026-11-18 |
| T4 | WS; G; W | red: AssertionError: REQ-RPT-021 excluded rows go in a closed details.prov with title, count, ...; green | 2026-11-18 |
| T5 | WS selftest_unsaved_script; G; W | red: AssertionError: REQ-RPT-071 the report page carries exactly the pinned script right before </body>...; then expected reds in RPT-021/007/048/051/056/054 rewritten to 'fixed script + CSP_REPORT'; green (G 205 reqs/2605 cases; once RPT-012 'two simultaneous ensure' failed in G and passed on repetition: flaky). sha256 c3144454...7bde | 2026-11-18 |
| T6 | L selftest_comment_images; WS; G; W | red: TypeError: comment_add() got an unexpected keyword argument 'images'; green (G 206 reqs/2626 cases) | 2026-11-18 |
| T7 | WS selftest_comment_images_web; G; W | red: AssertionError: REQ-RPT-070 the add-comment form is multipart with the adjuntar block ...; green (G 206/2639; CSS 98442 B). Adjusted 2 assertions of REQ-RPT-006 that counted 'elegir' over the whole page (there is now also a block in the comment form) | 2026-11-18 |
| T8 | G; TUI; WST | panel (FINDING_STATUSES, seven counts, remediado row, 8 rows) already entered in T1 with a prior red (RPT-003 'STATUSES equals FINDING_STATUSES', 008-AC8/AC18 with 6 rows); texts and amendments here. G 206/2639, TUI 55 passed, WST 186 passed | 2026-11-18 |
| T9 | W report-test.sh | 126 passed, 0 failed (curl -F + sha256sum, curl -D report/list, confirmed->remediated 422/303, 3 report-writer, CSS<=100000) | 2026-11-18 |
| T10 | PW (agent, Chromium 1254, headless, captures in the session scratchpad `pw024/`, not in the repo) | PASS: `beforeunload` fires after editing a field + link, not after Guardar nor when touching nothing, fires on leaving after «Vista previa»; with JS off it saves without dialog; no CSP violation. Comment with image: choose + upload are seen, blank text 422, removing from Adjuntos detaches it. «Fuera del reporte (1)» closed with a working link. Remediado: 422 without note / 303 with note, badge, filter, «Nueva prueba»; preview and `.html` show Remediated (1) after the open ones and the tiles do not count it; going back to Confirmado works | 2026-11-18 |
| T11 (partial) | L, WS, W, G, K, TUI, WST together | green: L selftest OK; WS selftest OK; W 126 passed; G REQ trace 206/2639; K ALL GREEN 56; TUI 55 passed; WST 186 passed; CSS 98442 B. Not done: AC6 (PW), Status -> IMPLEMENTADA, spec list of CLAUDE.md/AGENTS.md, code-auditor | 2026-11-18 |
| T11 | L, WS, W, G, K, TUI, WST together (after the 5 review fixes) | green: L selftest OK; WS selftest OK; W 126 passed, 0 failed; G gekko-workspace selftest: all passed, REQ trace 206 requirements/2646 cases; K ALL GREEN 56; TUI 55 passed; WST 186 passed. Living spec (LED-011, RPT-070/071 and the 25 amendments) against plan §4: no drift except the §4 Huecos line (goes in the Limit of RPT-071; plan corrected) | 2026-11-18 |
| | | | |
