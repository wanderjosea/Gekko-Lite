# Spec 019 — Reports V3: comments, inline editing, CVSS, Executive/Technical report and collapsible bar

> Status: `IMPLEMENTADA` (operator, 2026-11-17: closed; real runs done by the operator; final regression at `66a7506`: guard 190/2245, L, WS, sanitizer, report-test 84/0, hooks 48, ws-test 184/0, tui-test 55/0 and toolbox-test with Docker green) · before that (operator, 2026-11-17: «implementalo con tus recomendaciones» — "implement it with your recommendations"; decisions resolved in §8, without an
> intermediate plan/tasks gate at the operator's request).
> Date: 2026-11-17 · Design source: the operator's V3 prototype (`GEKKO-Reports-v3.html`, README and three screenshots;
> outside the repo, read as data, not run and its JS not copied) with the Gekko brand kit (outside the repo, `LEEME.md`)
> in place of the generic «G» and flash of V3. Coexists with [`018`](../018-chat-hallazgo/spec.md) (DRAFT,
> finding chat): everything about the chat belongs to 018, and where the two touch the same thing this spec **defers** to its decision (§6).
> Branch: the one of 018 (§8, D12). **Loosens the boundary three times** — editing of drafting fields and CVSS through the web,
> a new file of comments and another of report drafts per workspace — and changes `render`: it takes the long flow, like [`016`](../016-estado-desde-web/spec.md). §8 D1 proposes splitting it into 019a and 019b.

## 1. Problem (one sentence)
The operator cannot leave or correct their own comment on a finding, nor correct summary, impact,
remediation, CWE, CVE or CVSS from the module (the only write is `/estado`, REQ-RPT-008, `findings_web.py:1066`);
CVSS is a loose number with no vector to justify it (limit of REQ-LED-001), and the report is a single
text projection with no cover page or framing (017 §4, Out of scope) that does not separate the executive reader from the technical one.

## 2. Goal (one sentence)
From the detail view the operator comments on a finding (add, edit, delete, with a trail), edits the drafting fields and computes CVSS v3.1 from its metrics on the server, all without JavaScript, with the defenses of 016 and the same rule as `findings.py`; and the report comes out in two types (Executive and Technical) with their own drafts,
always as a projection of the corroborated confirmed findings, in Markdown/HTML/PDF and with the Gekko brand.

## 3. Context / why now
Read in the code (`main`, `745d6f7`):
- `respond` rejects every POST that is not `/actualizar`, `/tema` or `/w/<ws>/f/<n>/estado` (`findings_web.py:1066`).
  `set` writes `summary`, `impact`, `remediation`, `cvss`, `cwe`, `cve` (`findings.py:195`, `_optional_fields` tied to
  `argparse`); it does not write `severity`, `title`, `target`, `repro` or `kb`, and it does not delete a key.
- `cvss` is a `float` 0–10 with no vector; CLAUDE.md: «never guess a CVSS/CWE/CVE». The concept of a comment does not exist in the ledger or in the module; 016 (D3) left the change history out «for now».
- `render_md` (`findings.py:385`) is the only projection; 017 requires the downloaded `.md` to be byte for byte its
  output (REQ-RPT-022). The PDF is an own generator of 80-column text lines with standard fonts
  (`findings_web.py:933`). 017 left out cover page, logo, summary table and saving anything in the workspace.
- CSP with no scripts (`findings_web.py:398`, REQ-RPT-007). The brand is a letter «G» in a `<span>` (`sidebar`,
  `findings_web.py:449`). JetBrains Mono is named in the CSS but does not ship embedded; Michroma is not there.
- The theme preference already lives in a cookie with `POST /tema` (REQ-RPT-014): it is the mold for the collapsible bar.
- 018 (in parallel) brings: an «Aplicar» (Apply) path that writes `summary`/`impact`/`remediation` via `set_row`, its D5
  (delete a key), its D8 (brand as PNG in `data:` and `img-src data:`) and a history file per workspace (D6).

## 4. Scope
**In:**
- **A · Operator comments** per finding: add, edit and delete, with date, an «edited» mark and channel
  (`web`/`cli`); append-only trail (D2); parity in `findings.py comment add|edit|delete|list`.
- **B · Inline editing** in the detail view (`?editar=1`, a single form covering the sections, so moving between them does not lose text): `summary`, `impact`, `remediation`, `cwe`, `cve` and the CVSS. Save/Cancel; 409 on a changed row. **CVSS v3.1 base calculator** on the server: eight metrics, editable vector, «Calcular» (Calculate) without writing, score and band calculated on save, mandatory justification if the band ≠ the recorded severity.
- **C · Executive and Technical report**: report type selectable on the report page; one draft per type and workspace
  (cover and framing texts); server-side preview; the three formats of 017 × two types × two languages;
  `findings.py render --tipo … --borrador …` reproduces the Markdown; brand in HTML and PDF.
- **D · UI**: collapsible sidebar at 70 px with preference in a cookie; kit icon/logo in place of the «G»;
  report builder in two equal columns with its own scrolling (stacked below 1280 px);
  kit typography (D11).
- Reconciliation on merge: REQ-RPT-007, -008, -014, -021, -022, -023, -024, REQ-LED-001, -002; new `REQ`s for
  comments, editing, CVSS, drafts and the bar.

**Out (explicit, anti scope-creep):**
- Everything from 018: assistant panel, proposals, «Aplicar/Deshacer» (Apply/Undo), chat history, output to the Provider.
- Editing `status`, `corroboration`, `blocker` (they stay in the 016 form), `title`, `target`, `severity`
  (D5), `repro`, `kb`, `evidence`, `id`, `created`; creating or deleting findings; editing several at once.
- **Not adopted from V3:** persistence in `localStorage` (findings, drafts, bar); demo data and responses and the «Prototipo · sin backend» (Prototype · no backend) badge; context declared by the client; painting with `innerHTML`;
  status, severity, title, asset and «category» inside the edit form; the `pending` option that puts unconfirmed findings into the report; per-draft exclusion (D7); the «Impacto ejecutivo» (Executive impact) field (D13); the single-finding report; the «Actividad» (Activity) tab as an invented log (here it only shows comments); the «G» and the flash.
- **JavaScript only, outside this spec** (REQ-RPT-007): recalculating CVSS when touching a metric, preview while typing, floating notices, unsaved-changes warning, a button that calls `window.print`, collapsing the bar without a reload, keyboard shortcuts. The no-JS equivalent: buttons that submit the form and re-render,
  and a `@media print` sheet on the report page.
- Comments with replies, mentions, author per person or login (limit of REQ-RPT-009 / decision 1 of 016).
- DOCX and other formats; translating the content of findings or drafts; the interface in English.

## 5. Acceptance criteria (testable)
> Tests: **L** = `python3 .claude/tools/findings.py selftest`. **W** = `bash tools/report-test.sh` (L + selftest of
> `findings_web.py` + real HTTP over a temporary root). **H** = `.githooks/test.sh`. **G** = the gate. «No escribe» (does not write) = 
> sha256 of the ledger, of the comments file, of the drafts and the workspace listing equal before and after. «Defensas de la 016» (016 defenses) = those of REQ-RPT-019 in their order (Host and user, method and path, `Sec-Fetch-Site`, 413 over `MAX_BODY`, strict UTF-8, HMAC token bound to workspace and object, row editable according to `editable_reason`), GET to the path 404, other methods 405. Fictitious data in temporary roots; no case reads real `engagements/`.

| # | Criterion (observable) | Test |
|---|---|---|
| **A · Comments** | | |
| AC1 | The detail of a row with a unique id shows «Comentarios» (Comments) from oldest to newest, each with text, creation time, «editado · hora» (edited · time) if it was edited, and channel; a form to add and, per comment, «Editar» (Edit) and «Borrar» (Delete). WHEN the row is not editable (`editable_reason`), THEN it shows the existing ones without actions and says why. | W |
| AC2 | Add, edit and delete are POST with the 016 defenses; the token for edit/delete is additionally bound to the last event seen of the comment. Token absent, false, from another finding or workspace: 403 without writing. | W |
| AC3 | Each operation **appends** an event to the D2 file and nothing is rewritten in place; `findings.jsonl` stays byte for byte equal. The file is regular, `0600`, under `engagements/<ws>/`, opened without following links and covered by `.gitignore`. WHEN the comment changed since it was shown, THEN 409 without writing and the operator's text is kept. A double submit writes once. | W |
| AC4 | Empty text or only invisible characters (rule of REQ-LED-007), more than 8 KiB in UTF-8, or file at its cap: rejected whole, stating the maximum; never truncated. | W |
| AC5 | With the hostile content from 012 and invisible characters, the comment is stored as is and all pages show it escaped; REQ-RPT-007 keeps holding. | W |
| AC6 | `findings.py comment add|edit|delete|list` writes the same events with the same validation (one single rule): what is added by the web is listed in the terminal and vice versa; the rejections match in a table of cases. | L + W |
| AC7 | Comments do not enter the index, the list, `render` or any download (D3): `render` and the downloads are byte for byte equal with and without the comments file. | L + W |
| **B · Inline editing** | | |
| AC8 | `GET …/f/<n>?editar=1` does not write and shows a single `<form>` with `summary`, `impact`, `remediation`, `cwe`, `cve` and the calculator, with the current values, Save and Cancel; the evidence stays in view; the status form from 016 stays the same. No editable field is `status`, `corroboration`, `blocker`, `severity`, `title`, `target`, `repro`, `kb`, `evidence`, `id`. | W |
| AC9 | Save is `POST …/f/<n>/editar` with the 016 defenses and writes via `set_row(extra=…, expect=visto)` only the changed fields and `updated`; the rest of the row and the other rows stay byte for byte equal. Extra fields in the request (`status`, `severity`, `title`, numeric `cvss`, `id`) do not reach the ledger. | W |
| AC10 | For a table of cases (valid and invalid CWE/CVE, text with only spaces, long values), saving via the web and `findings.py set` on copies of the ledger give the same result; invalid → 422 in Spanish naming the field, without writing, with all the operator's text kept. An emptied field is handled per D5 of 018 and never writes `""` by default. | L + W |
| AC11 | WHEN the row changed (a `set` or a write from 018) between showing and saving, THEN 409 without writing; the page shows the current values next to the operator's text. | W |
| AC12 | A single drafting write: by static test (as REQ-RPT-008), in the module only the status action (016) and one shared drafting-fields function call `set_row`; if 018 is merged, its «Aplicar» uses that same function and validator. | W |
| **B · CVSS v3.1** | | |
| AC13 | The calculator offers the eight base metrics with their v3.1 values and the vector. «Calcular» sends the same form with `accion=calcular`: 200, re-renders with all the operator's texts, the score and band calculated on the server, and does not write. | W |
| AC14 | The calculation matches the FIRST v3.1 base formula (including rounding up) on a table of vectors with known result (e.g. `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8, scope changed, all `N` = 0.0). A vector that is not `CVSS:3.1/` with the eight base metrics exactly once, or with out-of-table values, temporal/environmental, v3.0 or v4.0, is rejected without writing. | L |
| AC15 | Saving with a vector writes `cvss_vector` and `cvss` = score calculated on the server (a sent number is ignored). WHEN the band (None→`info`, Low, Medium, High, Critical) differs from `severity` and there is no justification, THEN 422 without writing; with it, `cvss_justification` is saved. `severity` never changes (D5). | W |
| AC16 | `findings.py set --cvss-vector V [--cvss-justification T]` gives the same result as the web; `--cvss` with a vector whose score does not match is rejected; `--cvss` is only rejected if it contradicts the parseable vector of the row; without a vector, or with one that does not parse, it passes as today and the page marks it «sin vector» (no vector). | L + W |
| **C · Report** | | |
| AC17 | The report page offers Technical (default) and Executive, and the two languages; both types use `included`: no option pulls in another status or leaves out a corroborated confirmed finding (D7). | W |
| AC18 | Technical without a draft: the `.md` is byte for byte today's `render_md` (017 AC8 stays green) except for rows with `cvss_vector`, which add vector and justification. With a draft, its sections go before and after, and the findings block is byte for byte the same as without a draft. | L + W |
| AC19 | Executive: cover and summary from the draft, count by severity of the included ones, table id/title/severity/target, per finding title, severity and impact from the ledger, and recommendations from the draft. With canaries in `evidence`, `repro`, command and artifact, none appears in the Executive in any format. | L + W |
| AC20 | One draft per (workspace, type) at the path of D8, regular `0600`, without following links, gitignored; saving is POST with the 016 defenses and a token bound to the sha256 of the draft seen (409 if it changed); saving one does not change the other. Only fields from the fixed list of D8, each with a cap; no per-finding field. `accion=previsualizar` (preview) re-renders the preview with what was sent without writing. | W |
| AC21 | `findings.py render --tipo tecnico|ejecutivo [--borrador F] --lang L` gives byte for byte the `.md` of the web; there is a single projection. An unknown type or an invalid draft exit ≠ 0 without a report. | L + W |
| AC22 | The three downloads exist for both types and both languages; the link binds the sha256 of the ledger **and** that of the draft: if either changed, 409 without a file. The page shows the sha256 of ledger, draft, `.md` and `.html`, and they match what was downloaded. The PDF meets 017 AC10 and carries the same ids. | W |
| AC23 | With hostile content in the ledger and in the draft: the views escape it; the `.md` leaves no image, link or HTML that a CommonMark viewer would interpret outside the spans/fences (REQ-LED-002 proof); the HTML meets 017 AC9. No download or view opens a connection that is not loopback. | L + W |
| AC24 | The downloaded HTML carries the kit's horizontal logo in its black variant (light background) as `data:` per D8 of 018, and its internal CSP gains only `img-src data:`; the PDF carries the brand per D9. No automatic date or workspace name outside what the operator wrote in the draft (017 D4). | W |
| **D · UI** | | |
| AC25 | Collapsing/expanding the bar is a `POST /barra` form that sets the cookie `gekko_barra` only to `plegada` or `abierta` (`HttpOnly`, `SameSite=Strict`), redirects with `safe_back` and applies the `Sec-Fetch-Site` rule of REQ-RPT-014; any other value is ignored and does not appear in the response. Collapsed it measures 70 px, shows the icon and each link keeps its accessible name. Without a cookie, D10 applies. | W |
| AC26 | The «G» disappears: the bar shows the kit's icon (collapsed) or horizontal logo (open), color/white in dark and black in light, per D8 of 018; no page requests an external resource; the contrasts of REQ-RPT-014 keep being ≥ 4.5:1. | W + §7 |
| AC27 | No new response carries `<script`, event attributes or the word `localStorage`; the pages' CSP does not gain `script-src` or `connect-src`, and its only relaxation is that of 018 D8. | W |
| **Cross-cutting** | | |
| AC28 | 10 edit saves on different rows, 10 web comments, 10 `findings.py comment add` and 10 `findings.py add` at the same time all leave all the changes; `findings.py list` and `comment list` exit 0. | L + W |
| AC29 | An action in one workspace does not change another (sha256 of the ledger, comments and drafts of the other equal); workspace, line or comment that does not exist → 404 without creating anything. | W |
| AC30 | The cases run in **L** and **W**; `.githooks/pre-commit` runs them when touching `findings.py` or `findings_web.py`; the `REQ ↔ case` trace stays green with the reconciled `REQ`s. | H + G |

## 6. Risks / limits this spec accepts
**Fit with 018 (explicit conflicts):**
- *Single writer.* 018 writes the saved proposal (its AC13); 019 the text of the form. Same function and validator
  (AC12); whoever merges second adapts to the first. The recommended order is 018 → 019a (D12).
- *Emptied field.* Depends on D5 of 018 (delete a key): 019 does not re-decide it (AC10).
- *CVSS/CWE.* 018 D4 leaves CVSS/CWE without «Aplicar» from the chat; 019 lets **the operator** write them via form. They do not contradict each other if 018 D4 is approved that way; if 018 opens CVSS to the chat, it must go through AC15.
- *Brand.* 019 uses D8 of 018 (reduced PNG as `data:`); if that D8 comes out as (c) SVG, 019 follows it. The
  brand of the collapsible bar, which 018 left to 019, is AC25–AC26.
- *Files per workspace.* 018 creates `.gekko-chat/`; 019 comments and drafts. D8 proposes a single directory of the module so that retention and `.gitignore` are checked in one place.
- *REQ-RPT-008.* 016, 017, 018 and 019 rewrite it: each merge is reconciled over the previous one.

**Limits:**
- «Never guess a CVSS» remains a prompt rule: the vector makes each metric inspectable, it does not prove that the choice is correct; the CLI lets the agent write a vector (D6). The ledger does not store who wrote it.
- Deleting a comment does not destroy it (D4): a secret pasted by mistake stays in the file until retention.
- Drafts and comments are operator text but may carry target data or the real client name (`engagement-authorization.md` §2): they live gitignored; the download leaves the workspace (limit of 017).
- The HMAC token is CSRF, not a human in the loop (limit of REQ-RPT-019). No login (decision 1 of 016).
- Without JS the calculator and the preview need one submit per change; AC14 tests a table, not every vector.

**For `plan.md`:** extract from `_optional_fields` a pure validator shared by CLI and web (AC10, AC16); format
of comment events and their folding; anchoring of the comment 409; exact sections of each type and their order in
md/html/pdf; how the 80-column PDF draws the cover and the table; font subset and CSS weight on each
page; layout of edit mode with the 018 panel at 50/50.

## 7. Signals of "done"
**L**, **W**, **H** and the gate green + checklist of `tasks.md` with its log + real run by the operator:
comment, edit and delete a comment; edit impact and CWE; calculate a CVSS with and without justification; a save over a row that the agent changed; Executive and Technical drafts; the six downloads checked with `sha256sum`;
bar collapsed and open; screenshots in both themes at 1500 and 760 px.

## 8. Operator decisions
**Resolved on 2026-11-17** («implementalo con tus recomendaciones»): all according to each one's recommendation —
D1 (b), implemented as two deliveries within this spec (019a = A + B, 019b = C + D) in the order 018 → 019a → 019b;
D2 (b), D3 (a), D4 (a), D5 (a), D6 (a) with the adjustment to CLAUDE.md/AGENTS.md, D7 (a), D8 as proposed, D9 (a),
D10 (b), D11 only Michroma in subset, D12 `report-module`, D13 (a). CVSS and CWE in editing keep the
aesthetics of V3 (operator). V3 is a demo with no backend that only contributes style.

Original text of the options:
1. **D1 · Split the spec.** (a) A single one. (b) **019a** = A + B (comments, editing, CVSS: what writes into the workspace and touches `set_row`, collides with 018) and **019b** = C + D (report, drafts, bar, brand). **I recommend
   (b)**: different surfaces and risks, and 019b does not wait for 018 except for its D8.
2. **D2 · Where comments live.** (a) List inside the row: a comment changes the fingerprint and gives a 409 to an open status save or «Aplicar»; editing overwrites. (b) Append-only file of events per workspace, key = finding id, written only by `findings.py` with its lock. **I recommend (b).**
3. **D3 · Comments in the report.** (a) Never (internal notes). (b) Per-comment mark «include in Technical». (c) All in the Technical. **I recommend (a)** in this spec.
4. **D4 · Delete.** (a) Tombstone event; the text stays until retention. (b) Purge by rewriting the file (loses the trail). **I recommend (a)**, with the limit written on the page.
5. **D5 · CVSS vs severity.** (a) The web never changes `severity`; if it differs, justification (V3). (b) Offer to align the severity: new capability (`set --severity`). **I recommend (a).**
6. **D6 · Who writes the vector.** (a) Web and CLI (parity; the agent too). (b) Web only: breaks parity.
   **I recommend (a)** and adjust the CLAUDE.md line to «never guess; a CVSS carries its vector».
7. **D7 · Exclude confirmed by draft** (V3 `excluded`). (a) No: to remove it, its status is changed. (b) Yes, with a mandatory reason listed in «out of the report». **I recommend (a).**
8. **D8 · Drafts.** Path `engagements/<ws>/.gekko-web/borradores/<tipo>.json` (comments in
   `.gekko-web/comentarios.jsonl`; move 018 D6's history there if accepted), `0600`. Fields: title, client,
   period, version, author, classification, summary, scope, methodology (Technical), limitations, recommendations;
   4 KiB per field. «Cliente» (Client): the form suggests the codename. Writing only by the web; `render` reads the file
   (a draft is presentation, not evidence). **I recommend that.**
9. **D9 · Brand in the PDF.** (a) Logotype as text «GEKKO · Offensive Security» with the generator's fonts. 
   (b) PNG icon as an image in the PDF (new image code). **I recommend (a).**
10. **D10 · Bar by default.** (a) Always collapsed (V3). (b) Open ≥ 1280 px and collapsed below it (CSS), the cookie wins. **I recommend (b).**
11. **D11 · Typography.** Michroma (headings) and JetBrains Mono embedded as `data:` (mold of REQ-RPT-017) weigh on each page because the CSS goes inline. **I recommend** only Michroma in subset (capitals and digits), with its OFL.
12. **D12 · Branch and order.** **I recommend** the one of 018 (`report-module`, its D11) and merging 018 → 019a → 019b.
13. **D13 · «Impacto ejecutivo» (Executive impact).** (a) The Executive uses `impact`. (b) New field `business_impact`. **I recommend (a).**

> Amendment 2026-11-17: AC22/AC24/D9 (80-column PDF) are replaced by the browser's print view `.imprimir` (REQ-RPT-024); the server's PDF generator no longer exists.
