# Spec 024 — Image in comments, unsaved-changes warning, «outside the report» notice and «Remediado» status

> Status: `IMPLEMENTADA` (2026-11-18) (operator, 2026-11-18: «Aprobada, adelante» — "Approved, go ahead"; P1 = yes, mandatory text). Written 2026-11-18. Design source: operator requests (2026-11-18): (1) «comentarios también debería
> dejarme agregar una imagen y verla ahí» (comments should also let me add an image and see it there); (2) «en la parte del reporte, si edité algo en el resumen y me quiero mover,
> debe pedirme guardar para no perder avance» (in the report, if I edited something in the summary and want to move, it must ask me to save so I do not lose progress); (3) «organizar mejor esto para que las F-00X no queden ahí» (organize this better so the F-00X entries do not stay there) (right column of the report); (4) «debe existir el estado remediated o remediado, pensando la lógica del retest post arreglo» (there must be a remediated or remediado status, thinking about the logic of the post-fix retest).
> The decisions in §4 come from the request; they are not reopened.
> Proportional security (that of 023, `../023-capturas-evidencia/spec.md` §6): **R1** hostile site in the operator's browser (HMAC token, `Sec-Fetch-Site`/`Host`, 409 with stale data), **R2** target content shown on pages (escape, CSP), **R3** the client's deliverable (nothing hidden). Plus sha256 custody and isolation between workspaces. «Make it simple, sin sobreingeniería» (no over-engineering).
> **Loosens the boundary at three points**, hence it takes the long flow: (a) a new write route for images from the web (the comment form); (b) the module's first `<script>` and the first `script-src` of a CSP, only in `/w/<ws>/reporte` (today REQ-RPT-007/054 say «sin scripts» (no scripts) in every response); (c) a row that is not `confirmed` enters the client's report (`remediated`; today `included` only takes corroborated confirmed ones).
> `file:line` citations from the `report-module` worktree at `54b5fad`.

## 1. Problem (one sentence)
A comment only stores text (`comment_add`, `findings.py:686`; urlencoded form in `comments_section`,
`findings_web.py:1934`); the report's draft is silently lost when leaving the page unsaved (`draft_form`, `findings_web.py:2496`, with no warning: there is no script); the report's right column shows a `<ul>` of
untitled `F-000X` (`findings_web.py:2547`, `2579`); and there is no status for a finding that was fixed and re-tested (`STATUSES`, `findings.py:42`).

## 2. Goal (one sentence)
A comment can carry images from «Adjuntos» (attachments) and show them; the report page warns before losing a changed draft; the confirmed findings that the report leaves out are shown in a notice with title, count and reason; and `remediated` («Remediado») exists, only from `confirmed`, with a mandatory new-test note, and comes out in the report separately from the open ones.

## 3. Context / why now
- 023a left the «Adjuntos» gallery, `prepare_images`, `_store_images`, the image route, `shot_img` and
  `captures_section` (`findings.py:796-1056`, `findings_web.py:917-967`, `2682-2788`): attaching to a comment is
  reusing them, with no new store. `gallery_delete` (`findings.py:971`) today only unlinks rows from the ledger.
- Comments are an append-only event file (REQ-LED-009) that never reaches the report or the chat
  (REQ-LED-010, REQ-RPT-037).
- The draft is submitted with buttons outside the `<form id="borrador">` (`form="borrador"`, `findings_web.py:2572`); «Vista previa» (Preview) returns the page with **unsaved** values (`ctx.draft_values`), so the warning must also be shown there.
- `STATUSES` is enumerated in `findings.py`, `findings_web.py` (`STATUS_CLASS`, `STATUS_LABEL`, `list_page`, `DOC`) and
  `toolbox/gekko-panel.ts:1135` (`FINDING_STATUSES`, which REQ-RPT-003 requires to be equal to `STATUSES`).

## 4. Scope
**In (with the decisions already taken):**
1. **Comment with image.** When **adding** a comment (the «Comentarios» tab) images can be attached just like in the
   «Evidencia» (Evidence) block of 023a: choose from «Adjuntos» of the same workspace or upload (what is uploaded enters the gallery).
   The image is shown inside the comment, with the same fixed `<img>` and the enlargement `<details class="ampliar">`.
   Deleting the image from «Adjuntos» also removes it from the comments (`edit` event with the same text) and «usada por» (used by)
   names the comments. Comments remain internal notes: never in the report, the chat or the Provider.
   The 023a code is reused; no new store. The text remains mandatory (**P1**, §8; default yes).
   Editing the text keeps the images.
2. **Unsaved-changes warning.** A minimal inline script, **only** in `/w/<ws>/reporte`: if a field of the
   `#borrador` changed (or the page shows unsaved values after «Vista previa» or a rejection) and the operator leaves without
   submitting, the browser asks (`beforeunload`); submitting the form disarms it. Fixed in that response's CSP
   by sha256 (`script-src 'sha256-…'`); no other page carries `script-src` nor `<script`; the script reads no data and
   sends nothing (and the CSP `default-src 'none'` denies it every connection); no event attributes; with JS off the page
   works the same, without a warning. `.md`, `.html` and `.imprimir` carry no script.
3. **«Outside the report» notice.** The loose `<ul>` becomes a `<details>` closed by default with a title and count («Fuera
   del reporte (N)» — Outside the report (N)), a line that explains that they are confirmed (or remediated) but the report does not include them, and per finding its id, link and reason («sin corroboración» — no corroboration, «sin nota de nueva prueba» — no new-test note). No JS; reuses the class `.prov`.
4. **`remediated` status** (it is «Remediado», in «Remediated»), for the new test after the fix:
   - only a `confirmed` row moves to `remediated` (saving `remediated` over `remediated` also works, as today with
     any status), and on entry it requires a **new-test note** in that same call (what was re-tested and with what result; text, never an image) in the new field `retest`; corroboration is still required;
   - if the new test fails, it goes back to `confirmed` (permitted transition); the note stays in the row as history and does not come out in the report of a confirmed one. The other transitions do not change (today there are no transition rules);
   - in the report: `included` also takes `remediated` ones with corroboration and note; they come out **after** the open ones, labeled «Remediado»/«Remediated» with their note; the severity count counts only the open ones and the remediated ones are counted separately (only if there is any);
   - the old `blocker` of a remediated one does not come out in any deliverable (as today for a confirmed one);
   - covers the CLI (`add` rejects it as it does `confirmed`; `set --status remediated --retest …`; `list --status`;
     `render`/`render --all`/`render --tipo`), the status form (016/019), list, filter, badges, detail, Markdown, HTML and
     `.imprimir` of the two templates, i18n, the TUI panel (`FINDING_STATUSES`) and the texts that describe the ledger's flow (agents, KB, `CLAUDE.md`/`AGENTS.md`, `docs/pi-hitl.md`);
   - **with no `remediated` rows, every output of today stays byte for byte equal** (021 AC1 hashes, `render` baseline).

**Out (explicit, anti scope-creep):**
- 023b (screenshots in the report): not touched.
- Changing the images of an already-written comment (it is deleted and written again); comment with only an image.
- Images in the new-test note; badge for the exclusion reason in the list or detail; note history (one only, replaced on re-entering `remediated`).
- New transition rules beyond «only from `confirmed`»; new metrics or progress in the list.
- Changing the template JSONs or their validator: the note comes through the row, not through `campos`.
- Script on any other page, in downloads, or for anything else (drag, paste, autosave).

## 5. Acceptance criteria (testable)
> **L** = `python3 .claude/tools/findings.py selftest`. **WS** = `python3 .claude/tools/findings_web.py selftest`.
> **W** = `bash tools/report-test.sh`. **G** = `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types
> toolbox/gekko-guard.ts` (`REQ ↔ case` trace, also runs the panel selftest). **K** = `.githooks/test.sh`.
> **PW** = a Playwright run by an agent (Chromium headless from the cached copy, not in `setup.sh`) over a copy of
> `.claude/tools` and a synthetic workspace; it is recorded in `tasks.md`, it is not part of the gate. «Nada escrito» (nothing written) = same bytes of ledger, comments and index and same listing of `evidencia/`.

| # | Criterion (observable) | Test |
|---|---|---|
| **A · Comment with image** | | |
| AC1 | **Add with image**: the «Agregar comentario» (Add comment) form is `multipart/form-data` with the `<details class="adjuntar">` of 023a (`elegir` checkboxes for the live images of «Adjuntos» of that workspace and `<input type="file" name="archivo" multiple>`), without `<script`, event attributes or `style=`. Adding with two chosen and one uploaded gives 303; the `add` event carries `images` = the union without repeats; the upload is in `evidencia/` and with its record (as 023a AC1); the comment shows each image with the fixed `<img>` (`alt="Captura N"`) inside `<details class="ampliar">` and «Abrir original» (Open original); absent or altered → «imagen ausente o alterada» (image missing or altered) with the sha256. Editing the text keeps `images`. Without images, the event, the file and the page come out byte for byte as today and the urlencoded body is still accepted. Rejections, all with nothing written: invalid image (the wiring cases of 023a AC5) → 422; hash absent, withdrawn or from another workspace → 422; more than 8 images → 422; blank text with image → 422 (P1); bad token → 403; `Sec-Fetch-Site: cross-site` → 403; broken or full comments file → 409 (without leaving the uploaded image); `elegir`/`archivo` in `editar` or `borrar` → 400. A rejection with uploaded files says «Vuelve a elegir los archivos: el navegador no los conserva» (Choose the files again: the browser does not keep them). The same submission twice leaves one comment and one copy. | L + WS + W |
| AC2 | **Deleting from «Adjuntos» removes the image from the comments**: the gallery's «usada por» (used by) also names the findings whose current comments use it («F-0001 · comentario»). Deleting an image used by one row and by two comments gives 303: the row loses it (as 023a AC7), each comment gains an `edit` event with the same text and `images` without that hash, the removal carries `comentarios: [ids]` and the detail stops showing it. A comment added or changed after the gallery was shown → 409 (the fingerprint counts the comments file), nothing written; broken, over-cap or full comments file → 409 with a message that names the comments, nothing written (the `edit` events are written first). Faults injected at each step leave at most an unused image or a file with a removal, never a comment that points to a deleted file. Without comments with that image, the removal comes out with today's keys. | L + WS |
| AC3 | **They remain internal notes**: with comments with images, `.md`, `.html`, `.imprimir`, `render`, `render --all`, `render --tipo` and the request body to the Provider are byte for byte those without comments (the socket sweep of REQ-RPT-062 still covers the path). | L + WS |
| **B · Unsaved-changes warning** | | |
| AC4 | **The fixed script**: the page `/w/<ws>/reporte` (GET, «Vista previa» and its 409/422) carries exactly one `<script>` whose content is the constant `UNSAVED_JS`, with its sha256 fixed in the test and in the living spec; its CSP is that of the pages plus `; script-src 'sha256-<that hash>'` and nothing else. The script goes just before `</body>`. The `<form id="borrador">` has no event attributes and carries `data-sin-guardar` only when the page shows unsaved values (`ctx.draft_values`). `UNSAVED_JS` only touches the form and `beforeunload` (no network nor storage). | WS |
| AC5 | **That page only**: the index, the list, the detail, the gallery, the image, the fixed 4xx/413 responses and the rejection pages of status, edit, comment and chat carry no `<script` nor `script-src`; `.md`, `.html` and `.imprimir` carry no script and their CSP and bytes are today's (021 AC1). `markup_problems(page, report=True)` removes exactly one `<script>{UNSAVED_JS}</script>` and fails with any other `<script`; today's assertions that look at the report page are rewritten to «exactly the fixed script + the report's CSP», never deleted (`plan.md` §3), and the hostile cases of REQ-RPT-007/051 stay green. | WS + W |
| AC6 | **Browser behavior**: with JS: changing a field and pressing «Hallazgos» (Findings) opens the `beforeunload` dialog; after «Guardar borrador» (Save draft) or «Vista previa» there is no dialog on submit; after «Vista previa» (unsaved values) leaving opens the dialog; without touching anything there is no dialog. With JS off, saving the draft works the same and there is no dialog. | PW |
| **C · «Outside the report» notice** | | |
| AC7 | With `confirmed` rows without corroboration and `remediated` rows without a note (written by hand), the right column carries a `<details class="prov">` **without** `open` whose `<summary>` says «Fuera del reporte (N)», a line that explains why, and per row, escaped id, link `/w/<ws>/f/<línea>` and reason; no loose `<ul>` remains outside it; with N = 0 it does not appear. | WS |
| **D · «Remediado» status** | | |
| AC8 | **Ledger and CLI**: `STATUSES` ends in `remediated`. `set --status remediated --retest "…"` on a corroborated `confirmed` changes `status` and stores `retest`; without `--retest` (or blank) on entry, from any other status, or without corroboration → exits ≠ 0 naming the rule and the ledger stays byte for byte; `remediated` → `remediated` without `--retest` keeps the note; `remediated` → `confirmed` is valid and the note stays; `add --status remediated` exits ≠ 0 with no new rows; `list --status remediated` filters. | L |
| AC9 | **Web**: the status form carries the «Remediado» radio and «¿Qué se volvió a probar y con qué resultado?» (What was re-tested and with what result?) (`retest`), visible only with «Remediado» chosen (`:has()`, as `need-confirmed`); `retest` is optional in the body (a body from today without it still gets 303), repeated → 400 and it is only written if the target status is `remediated`; the rules of AC8 give 422 in Spanish, keeping what was written; the list carries the badge `st-remediated` «Remediado» and the filter `?status=remediated`; the detail shows «Nueva prueba» (New test) only if the row has `retest`; the contrast pairs of the new token pass in both themes. | WS + W |
| AC10 | **Report**: `included` = corroborated confirmed + corroborated remediated with note, open first and each group by severity. In Technical and Executive × Markdown/HTML/`.imprimir` × es/en, and in `render`, `render --all` and `render --tipo`, the remediated ones come out after the open ones under the subtitle «Remediados (N)»/«Remediated (N)», each with «Nueva prueba»/«Retest» and its note (escaped or in a *code span*, REQ-RPT-051); where the card shows status (Technical, `render`) it says «Remediado»/«Remediated»; the Executive has no status column: the subtitle and the field suffice. Only with remediated ones, the findings section shows the empty label and then the remediated block. The severity count counts only open ones and «Remediados: N» is added only with N > 0; a remediated one without a note or without corroboration does not come out, and the old `blocker` of a remediated one does not come out in any deliverable (canaries absent). `DOC_CSS` and `DOWNLOAD_CSS` do not change (same sha256). | L + WS |
| AC11 | **Without remediated ones, nothing changes**: the 16 sha256 of 021 AC1 and the `render` baseline (REQ-LED-002) stay equal; a `confirmed` with an old `retest` does not show the note in any output. | L + WS |
| AC12 | **The rest of the repo**: `FINDING_STATUSES` = `STATUSES` (REQ-RPT-003); `countFindings` returns seven integers; the HALLAZGOS card carries the «remediado» row and the summary counts it; its 7 status rows + «visor» = 8 fit in `DEFAULT_ROW_CAP` without cutting; the texts of the ledger's flow (docstring of `findings.py`, `finding-verifier` and `report-writer` in `.claude/.pi/.codex`, `kb/techniques/finding-triage-gate.md`, `CLAUDE.md`/`AGENTS.md`, `docs/pi-hitl.md`) name `remediated`; W checks that the three `report-writer` mention it. | G + W |
| **Cross-cutting** | | |
| AC13 | The pages' CSS stays ≤ 100 000 bytes; the `REQ ↔ case` trace green with the new and amended REQs; L, WS, W, G and K green together. | W + G + K |

## 6. Risks (accepted)
- *The script loosens R2.* A target value cannot inject script: only the text whose hash the CSP fixes runs, and `default-src 'none'` denies it connections. What is accepted is that this page stops being «sin script» (no script); the test fixes the hash and the absence on all the others.
- *`beforeunload` is not reliable.* The browser may omit the dialog without prior user interaction, and a download link may trigger it; it is an aid, not a control.
- *More rows in the deliverable (R3).* A remediated one enters the client's report; only with corroboration and note, and one written by hand without them stays out and is seen in the notice of AC7.
- *Deleting from «Adjuntos» marks the comment as «editado»* (it is an `edit` event); the text does not change.
- *A single new-test note*: re-entering `remediated` replaces it (the ledger rewrites rows in place).
- *CSS budget*: about 1.5 KB of the cap is left for 023b (`plan.md` §5).
- *The model may mark `remediated` via the CLI* (`ledgerCliOnly` lets `findings.py set` through), with the same rules as for `confirmed`.

## 7. Signals of "done"
L, WS, W, G and K green + checklist of `tasks.md`. Validation in the browser **by an agent** with Playwright (cached copy, Chromium headless, temporary root with a copy of `.claude/tools` and a synthetic workspace; never the real `engagements/`): AC6 in full; add a comment with one chosen image and another uploaded, see it and enlarge it, delete it from «Adjuntos» and see that the comment loses it; take a finding from Confirmado to Remediado (without note → rejection; with note → badge) and back; see the «Fuera del reporte (N)» notice closed and open it; download Technical and Executive `.md`/`.html` and `.imprimir` with the remediated one and check `sha256sum` = Procedencia; light/dark captures at 1500 and 420 px. The operator only looks at the captures (one minute); they do not have to click.

## 8. Operator questions (resolved)
- **P1** — DECIDED 2026-11-18: yes, the text remains mandatory. Does the comment text remain mandatory even when it carries an image? By default **yes** (a comment is a
  note; the image does not explain itself): blank text with image → 422. If the operator says no, AC1 and
  `validate_comment` change only for images with nothing else.
