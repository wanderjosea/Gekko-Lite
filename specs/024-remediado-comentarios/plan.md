# Technical plan 024 — Image in comments, unsaved-changes warning, «outside the report» notice and «Remediado»

> Status: `IMPLEMENTADA` (2026-11-18) (operator, 2026-11-18, together with the spec). Spec: [`spec.md`](spec.md) (`APROBADA`). `file:line` citations from the `report-module` worktree at `54b5fad`; T0 relocates them if the tree changed.

## 1. Approach
Four small changes on what already exists, with no store, dependency or new route:
1. **Comment with image** = the «Adjuntar imagen» (Attach image) block of 023a inside the add-comment form, plus a
   `images` key in the `add` event. `comment_add` in `findings.py` writes it (REQ-RPT-008: every web write goes through
   its `findings.py` function) under the ledger lock, which is what already serializes the gallery; `gallery_delete` adds a
   step that appends `edit` events to the affected comments.
2. **Unsaved warning** = a constant `UNSAVED_JS` and a `script` parameter in `page()` that only `report_page` passes
   (it emits it just before `</body>`); that response carries the pages' CSP plus `script-src 'sha256-…'`, which
   `response_headers(ctx, identify, csp=CSP)` receives as an argument.
3. **«Outside the report» notice** = change two lines of `report_route` into a `<details class="prov">`.
4. **`remediated`** = one more status in `STATUSES`, a rule in `set_row`, a `retest` field, and `report_model` that
   splits the included into open and remediated. The rest (radios, filter, badge, contrast) comes out of `STATUSES` alone.

## 2. Contracts

| What | Form |
|---|---|
| `add` comment event | today's + `"images": [<sha256>, …]` (1…`ROW_MAX_IMAGES` = 8, distinct, `SHA_RE`) **only if there are images**: without them the line comes out byte for byte as today |
| `edit` comment event | today's; with `"images"` (0…8) it replaces the list, without the key it keeps it. Written by `gallery_delete` (same text, `via: "web"`) |
| Folding (`_apply_comment_event`) | malformed `images` (not a list, invalid hash, repeated, more than 8, empty list on `add`) → bad line; the comment's state gains `images` (`[]` by default) |
| Gallery removal | today's + `"comentarios": [<C-…>]` only if it was unlinked from some comment (`_fold_gallery` admits it as optional, like `archivo`) |
| Deletion stamp | `delete_stamp(ledger_digest, gallery_digest, comments_size=0)`: appends `\n<size>` only if `comments_size` > 0 (the file only grows: its size names its state, like `nuevo` in `comments_section`) |
| Comment form fields | today's (`accion`, `texto`, `nuevo`, `ficha`) + `elegir` (repeatable) + `archivo` (files), only with `accion=agregar`; in `editar`/`borrar` → 400 |
| Ledger row | `retest`: text, the new-test note. Written only if the target status is `remediated` and it arrives non-blank |
| Status form field | `retest` (textarea, optional: absent = empty; repeated → 400) |
| New `Refusal` kinds | `not_confirmed` (to `remediated` from another status) 422 · `no_retest` (enters `remediated` without a note) 422 · `comments_state` (in `gallery_delete`, the comments file gave `full`/`corrupt`/`too_large`) 409 with «el archivo de comentarios está roto o lleno; no se escribió nada» (the comments file is broken or full; nothing was written) |
| Labels | `STATUS_LABEL`/`list_page`/`DOC.status`: «Remediado»/«Remediated»; `LABELS.retest`: «Nueva prueba»/«Retest»; `DOC.remediated`: «Remediados»/«Remediated» |
| `report_model` | `chosen` = open (`confirmed`, as today) and `remediated` = included remediated; `tiles` only from `chosen`; `fixed_n` = `len(remediated)` |
| `UNSAVED_JS` | just before `</body>`: `(()=>{const f=document.getElementById("borrador");if(!f)return;let d=f.hasAttribute("data-sin-guardar");f.addEventListener("input",()=>{d=true});f.addEventListener("submit",()=>{d=false});addEventListener("beforeunload",e=>{if(d){e.preventDefault();e.returnValue=""}})})()` — its sha256 is fixed in WS and in REQ-RPT-071 |
| Report CSP | `UNSAVED_JS_HASH` in base64 like `CSS_HASH`; `CSP_REPORT = CSP + "; script-src 'sha256-" + UNSAVED_JS_HASH + "'"`; the rest of responses, today's `CSP` |
| `markup_problems(page, report=False)` | with `report=True` removes exactly one occurrence of `<script>{UNSAVED_JS}</script>` and continues: any other `<script` is a problem |

**`remediated` rules in `set_row`** (`findings.py:349`, after `needs_validation`'s, before `check`):
`status == "remediated"` and `previous` ∉ {`confirmed`, `remediated`} → `not_confirmed`; `previous != "remediated"` and
`retest` blank → `no_retest` (the note belongs to **this** call: an old one from a previous cycle does not count); blank corroboration → `no_corroboration` (the existing one). Every rejection comes out before `_save`: nothing written.

**`included`** (`findings.py:1113`): `confirmed` with corroboration, or `remediated` with corroboration and a non-blank `retest`; order `(status == "remediated", severity rank)`. Without remediated ones the order is today's (`sorted` is stable).

**`report_fields`** (`findings.py:1137`): adds `("campo", labels["retest"], retest)` only if `status == "remediated"`,
**without looking at `keys`** (like severity and status, it always goes): thus neither templates nor `validate_template` change, and a confirmed one with an old note does not show it. The `blocker` line (`:1148`) now hides it with `status in
("confirmed", "remediated")`: the blocker of a remediated one is also history (R3).

**`render_md`** (`findings.py:1198`, `render` and `render --all`): after the open rows, if there are remediated ones, the line
`**Remediated (N)**` (es: «Remediados») and the remediated ones with `_md_finding` (which already brings «Retest» via `report_fields`).
Without remediated ones nothing new is emitted: the REQ-LED-002 baseline stays byte for byte.

**Order of `gallery_delete`** (`findings.py:971`), all under `_locked(ledger)`: read ledger, index **and comments**
(`read_comments_state`, only for the fingerprint and «usada por»); fingerprint with the three; then (b) a `_comment_append` with the
`edit` events (one write; omitted if no comment uses the image), (a) `_save` of the ledger without the reference,
(c) removal from the index, (d) `web_unlink`. (b) goes first so that a comments file that is full, broken or over its cap
rejects with nothing written: `full`/`corrupt`/`too_large` from that file come out as `comments_state` (409, comments message in
`gallery_refusal`, `findings_web.py:2729`). The `decide` of (b) rebuilds the events from the folding it receives under the lock (live comments with that hash, `prev` = their `last`) and never raises `stale`: the fingerprint already covered the changes. A failure after (b) or (a) leaves the image alive with fewer references; after (c), a file with its removal; the file is deleted last, so no comment points to a deleted file. Fixed lock order: ledger →
comments (never the reverse; `comment_add` without images still does not take the ledger's, as today).

**`comment_add` with images**: `comment_add(..., images=(), choose=())`; with none, today's path byte for byte. With some:
`_locked(ledger)` → `read_gallery` (broken or full → `gallery_state` 409) → `choose` ⊆ live (`not_in_gallery`
422) → cap 8 (`limit` 422) → `_comment_append(..., decide, before_write)`: `decide` folds and builds the event, the file cap is measured **before** `before_write`, which calls `_store_images` (from 023a), and only then is the event written. A rejection from the comments file does not leave the uploaded image behind. Double submit (same `nuevo`, same text and same
images) → does not write; same id with other images → `stale`.

## 3. Affected functions
| File:line | Change | AC |
|---|---|---|
| `findings.py:11` docstring, `:42` `STATUSES` | `remediated` at the end; `retest` line | AC8, AC12 |
| `findings.py:322` `cmd_add` (`:324`), selftest `:2850` (loop of rejected `add`) | rejects `remediated` too; the loop adds `remediated` | AC8 |
| `findings.py:349` `set_row` | `retest` parameter, rules of §2 | AC8, AC9 |
| `findings.py:568` `_apply_comment_event`, `:648` `_comment_append`, `:686` `comment_add` | `images`; `decide` may return a list; `before_write` optional | AC1, AC2 |
| `findings.py:822` `_fold_gallery` (`_BAJA_KEYS`, `:770`), `:966` `delete_stamp`, `:971` `gallery_delete` | removal with `comentarios`; fingerprint with comments; step (b) | AC2 |
| `findings.py:1021` `set_evidence`, `:1059` `cmd_set`, `:4168` `set` parser | passes `retest`; `--retest` | AC8, AC9 |
| `findings.py:1091` `LABELS`, `:1113` `included`, `:1137` `report_fields` (`retest`; `blocker` hidden also on remediated, `:1148`), `:1198` `render_md`, `:1256` `DOC` | §2 | AC10, AC11 |
| `findings.py:1910` `report_model`, `:1950` `render_report` | `chosen`/`remediated`; after each findings section, if there are remediated ones: `**Remediados (N)**` and the same tables/cards; count + ` · **Remediados:** N` only with N > 0 | AC10, AC11 |
| `findings_web.py:165` `STATUS_CLASS`, `:174` `STATUS_LABEL`, `:216` `status_pill`, `:223` `unsupported_confirmed` → `report_gap(row)` («sin corroboración» / «sin nota de nueva prueba» / «») | badge and reason | AC7, AC9 |
| `findings_web.py:314`, `:325` `THEMES` | only the token `st-remediated` (e.g. `#4FD1C5` dark, `#0F766E` light); the rule `.st-remediated{color:…}` comes out by itself from `STATUS_TOKENS` (`:402`) and the `CONTRAST_PAIRS` pairs test it alone | AC9 |
| `findings_web.py:494` `:has()` rule | `.need-retest` like `need-confirmed` | AC9 |
| `findings_web.py:613` `CSP`, `:618` `response_headers` (argument `csp`), `:692` `page` (parameter `script`, before `</body>`), `:2491` `report_page`, `:2496` `draft_form` (`data-sin-guardar` if `ctx.draft_values`) | §2 | AC4, AC5 |
| `findings_web.py:792` `list_page` (labels, `:799`) | «Remediado» | AC9 |
| `findings_web.py:947` `captures_section` | its per-image body goes to `capture_item(name, n, sha, gallery, workspace)`, which comments also use | AC1 |
| `findings_web.py:970` `state_form`, `:1044` `post_state` (`:1056` fields) | `retest` textarea; messages for `not_confirmed`/`no_retest` | AC9 |
| `findings_web.py:1221` `COMMENT_FIELDS`, `:1224` `post_comment` (receives `content_type`; the route `:2821` passes it, as to `post_state`), `:1911` `comment_block`, `:1934` `comments_section` | multipart for add; images in the comment with `capture_item`; form with the `<details class="adjuntar">` (common function with `evidence_block`, `:923`); a rejection with files reuses «Vuelve a elegir los archivos: el navegador no los conserva» (`:1106`) | AC1 |
| `findings_web.py:2034` `detail_page` (`#evidencia`, `:2096`) | «Nueva prueba» after «Corroboración» only with `retest` | AC9 |
| `findings_web.py:2212` `body_limit` | `MULTIPART_BODY` also on `COMMENT_PATH` with multipart | AC1 |
| `findings_web.py:2387` `report_body_for` | remediated block; `<li><b>N</b><span>Remediados</span></li>` **without class** (does not touch `DOC_CSS`) | AC10 |
| `findings_web.py:2547`, `:2579` `report_route` | `<details class="prov"><summary>Fuera del reporte (N)</summary><p>…</p><ul>…</ul></details>` with `report_gap` | AC7 |
| `findings_web.py:2687` `gallery_page`, `:2729` `gallery_refusal` | «usada por» with comments; fingerprint with comments; `comments_state` → 409 with its message | AC2 |
| `findings_web.py:4187` `markup_problems` | `report` parameter (§2) | AC4, AC5 |
| Today's assertions that turn red on the report page — they are **rewritten** to «exactly the fixed script + `CSP_REPORT`», never deleted (they guard hostile content): `findings_web.py:4019-4022` (RPT-007, CSP of `/w/ws/reporte`), `:4504` (RPT-048, draft 409), `:4632` (RPT-051, hostile pages), `:5124-5129` and `:5146-5150` (RPT-054, brand and sweep: only the report responses go to `report=True`), `:6639` (RPT-021, Markdown view) | `markup_problems(p, report=True)` and exact CSP | AC5 |
| Assertions that grow with `STATUSES`: `findings_web.py:6319-6336` (RPT-018, web matrix = CLI: starts from a corroborated `confirmed` and passes `retest` to `remediated`), `:5206-5208` (RPT-039, exact list of radios + `("remediated", "Remediado")`), `:6297-6299` (RPT-018, `:has()` rules with `.need-retest`) | adjust to the new status | AC9 |
| `toolbox/gekko-panel.ts:1135`, `:1139`, `:1224-1231` | `remediated` in `FINDING_STATUSES`, counter, «remediado» row (`✓`, `ok`) and in the summary (`:1226`) ` remediados N` only with N > 0; 7 rows + «visor» = `DEFAULT_ROW_CAP` 8 (`:1303`), no new entry in `ROW_CAP` | AC12 |
| `toolbox/gekko-panel-selftest.ts:825`, `:842-843`, `:898` (008-AC18) | `remediated` in the count literals; seven statuses + others; the HALLAZGOS card with `reportUrl` shows its 8 rows without cutting | AC12 |
| `tools/report-test.sh` | §6 (W) | AC1, AC5, AC9, AC12 |
| `.claude/agents/{finding-verifier,report-writer}.md` + `.pi/agents/…` + `.codex/agents/…toml`, `kb/techniques/finding-triage-gate.md`, `CLAUDE.md`/`AGENTS.md` (ledger flow line), `docs/pi-hitl.md` §4c | one sentence each: `confirmed` → `remediated` with `--retest`; the report includes remediated ones separately | AC12 |
| `specs/SECURITY-GUARDRAILS-SPEC.md` | §4 | AC13 |

Unchanged: `report-templates/*.json`, `validate_template`, `DOC_CSS`, `DOWNLOAD_CSS`, `report_html` (except what
`report_body_for` brings), `chat_context` (`CHAT_CONTEXT_NAMES`, `findings_web.py:1450`: neither `retest` nor comments),
`EDIT_FIELDS` (the note is only written from the status form or the CLI), `gekko-guard.ts`.

## 4. New and amended REQs (living spec)
**New** (023a reached 062 and 023b reserved «063 en adelante» (063 onward) without closing the count: 070–071 are taken so as not to collide):
- **REQ-LED-011 — `remediated`: only from `confirmed`, with a new-test note, and separately in the report.** MUST
  reject without writing the move to `remediated` from another status, without corroboration or without a non-blank `retest` in the
  same call on entry; `add` MUST reject it; `remediated` → `confirmed` MUST be valid; `included` MUST take
  corroborated remediated ones with a note, after the open ones, and the severity count MUST count only open ones; without
  remediated ones MUST stay byte for byte. WHEN AC8, AC10, AC11. Limit: the note is text; it does not prove that the new test
  took place; one note per row.
- **REQ-RPT-070 — Images in comments.** Adding a comment MUST be able to attach live images from the workspace's «Adjuntos» or uploaded ones (validated as in 023a), all or nothing under the ledger lock; MUST show them with the
  fixed `<img>` form; deleting from «Adjuntos» MUST remove them from the comments (`edit` events first, removal with
  `comentarios`, fingerprint with the comments file, file deleted last); comments with images MUST NOT change the report,
  `render*` nor the request to the Provider. WHEN AC1–AC3.
- **REQ-RPT-071 — A single script, fixed by hash, only on the report page.** `/w/<ws>/reporte` MUST carry
  exactly `<script>{UNSAVED_JS}</script>` with sha256 `<fixed in T3>` and CSP `CSP + script-src 'sha256-…'`; every other
  response, and `.md`/`.html`/`.imprimir`, MUST NOT carry `<script` nor `script-src`; the script only touches the form and
  `beforeunload`. WHEN AC4–AC6. Limit: `beforeunload` is decided by the browser.

**Amended** (one line; final text in T1):
| REQ | Change |
|---|---|
| LED-002 | `render`/`render --all` (`render_md`) also project corroborated remediated ones with note, after the open ones, with «Retest»; `blocker` of a remediated one hidden; baseline intact |
| LED-003 | adds the `remediated` rule and `add` rejects it |
| LED-009 | `add`/`edit` events with optional `images`; `gallery_delete` is another writer (via `_comment_append`) |
| LED-010 / RPT-037 | same with comments with images |
| RPT-003 | `FINDING_STATUSES` with six statuses (seven integers with «otros») |
| RPT-004 | reason «sin nota de nueva prueba» for a remediated one written by hand without a note |
| RPT-007 / RPT-054 | «sin scripts» except the one of REQ-RPT-071 (`markup_problems(report=True)`); CSS ≤ 100 000 measured with what is in §5 |
| RPT-021 / RPT-048 / RPT-051 | the report page (and its Markdown view, 409 and hostile cases) carries exactly the fixed script and `CSP_REPORT`; nothing else changes |
| RPT-035 | the «Comentarios» section shows the images with the fixed `<img>` form |
| RPT-039 | the list of radios adds «Remediado» |
| RPT-008 | the status also writes `retest`; adding a comment may write images (`comment_add`); `gallery_delete` also writes comments |
| RPT-009 / RPT-019 / RPT-036 | `MULTIPART_BODY` also on the comment route with `multipart/form-data`; same order of controls |
| RPT-018 | `retest` optional, repeated 400, only written with target `remediated`, LED-011 rules in 422; web matrix = CLI with six statuses |
| RPT-021 | in addition, the excluded ones go in a closed `<details class="prov">` with title, count and reason |
| RPT-046 / RPT-047 | remediated block in Technical and Executive; the Executive shows the note (it is not evidence: it is operator text) |
| RPT-060 / RPT-061 | deletion: order with comments and three-part fingerprint; comment `<img>` with the same fixed form |
| TUI-001 | the WHEN of the counts adds `remediated:0` |
| TUI-018 | seven integers; the HALLAZGOS card fits in `DEFAULT_ROW_CAP` |

That `beforeunload` is an aid and not a control (the browser may omit it) goes in the «Límite» (Limit) of REQ-RPT-071, not in §4 «Huecos conocidos» (known gaps) (the rule of §2b: what a fix does not cover goes in the Limit of its requirement).

## 5. CSS budget
Page CSS today **98 197 B** (measured 2026-11-18 importing `findings_web` at `54b5fad`; cap 100 000, REQ-RPT-054).
| New rule | Bytes |
|---|---|
| `;--st-remediated:#4FD1C5` in the 3 token blocks | 72 |
| `.st-remediated{color:var(--st-remediated)}\n` (generated from `STATUS_TOKENS`) | 44 |
| `,#estado .need-retest` + `#estado form:has(input[value=remediated]:checked) .need-retest{display:grid}` | 98 |
| `.comment .captura{margin:8px 0 0}` | 33 |
| «Outside the report» notice (`.prov`), attach in comments (`.adjuntar`, `.adj-op`, `.ampliar`, `.captura`), remediated count (`<li>` without class) | 0 |
| **Total** | **≈ 245 → ≈ 98 442 B** (≈ 1 558 left for 023b) |
It fits without raising the cap. If T0 measures something else and it does not fit: first remove `.comment .captura` (33 B); then, the measured contingency of 023a (Space Grotesk subset with `pyftsubset`, −8 768 B, `../023-capturas-evidencia/plan.md`
§2.6), which the operator decides. `DOC_CSS` does not change: the downloads keep their hash.

## 6. Test plan per AC
| AC | Cases |
|---|---|
| AC1 | **L** `selftest_comment_images`: `comment_add` with `choose` and `images`, double submit, same id with other images, hash of another workspace, 9 images, comments file broken and at the cap (the upload does not remain: `evidencia/` listing equal), folding of hostile `images`. **WS** form marking (multipart, no `<script`/events/`style=`), 303 and page with `capture_item`, rejections with their codes and «Vuelve a elegir…» if there were files, today's urlencoded byte for byte. **W** `curl -F archivo=@png --form-string texto=…` with the token scraped and `sha256sum` of the saved file |
| AC2 | **L** `gallery_delete` with one row and two comments: `edit` events, removal with `comentarios`, old fingerprint after a new comment → 409, comments broken, over the cap or full → `comments_state` 409 with nothing written, fault injected at (b), (a), (c), (d), removal without comments = today's keys. **WS** «usada por» with comments; the detail no longer shows it |
| AC3 | **L/WS** sha256 of `.md`, `.html`, `.imprimir`, `render*` and of the body of `SelftestProvider` with and without comments with images |
| AC4 | **WS** `selftest_unsaved_script`: a single `<script>` = `UNSAVED_JS` just before `</body>`, fixed sha256, exact CSP, `data-sin-guardar` only with `draft_values` (preview, 422, 409) |
| AC5 | **WS** `markup_problems(report=True)`: passes with the fixed script, fails with an altered one or a second `<script`; the §3 assertions rewritten; REQ-RPT-054 sweep extended: all routes except the report without `<script`/`script-src`; downloads with their CSPs and the hashes of 021 AC1. **W** `curl -D` of the report (with `script-src`) and of the list (without it) |
| AC6 | **PW** agent's Playwright script (not in the repo): `page.on("dialog")` with `type == "beforeunload"` in the four cases; context `javaScriptEnabled: false` saves and does not ask |
| AC7 | **WS** `confirmed` rows without corroboration and `remediated` without a note: `<details class="prov">` without `open`, «Fuera del reporte (2)», escaped links and reasons, no `<ul>` outside; without excluded ones it does not appear |
| AC8 | **L** `selftest_remediated`: transition matrix with sha256 of the ledger before/after; `cmd_add`, `cmd_list`; real CLI via `subprocess` |
| AC9 | **WS** radio and textarea with their `:has()` rule, 422 with text kept, body without `retest` → 303, repeated → 400, badge, filter, «Nueva prueba» in the detail, token contrast. **W** `curl --data-urlencode` of confirmed → remediated with and without note |
| AC10 | **L/WS** remediated row with canaries in Technical/Executive × md/html/imprimir × es/en and `render`/`render --all`/`render --tipo`: order, subtitle, status only where the card shows it, note, count separate; only remediated → empty label and then the block; canaries absent from a remediated one without note and from the old `blocker` of a remediated one; sha256 of `DOC_CSS`/`DOWNLOAD_CSS` equal |
| AC11 | **L/WS** the 16 hashes of 021 AC1 and the REQ-LED-002 baseline untouched; confirmed with an old `retest` without the note |
| AC12 | **G** panel cases (008-AC18 with seven statuses and the HALLAZGOS card entirely in 8 rows, REQ-TUI-001/018) and REQ-RPT-003 (`STATUSES` = `FINDING_STATUSES` via node). **W** the three `report-writer` name `remediated` |
| AC13 | **W** `len(CSS) ≤ 100000`; **G** trace; **K** |

## 7. Risks and mitigation
- **Lock deadlock** → fixed order ledger → comments; `comment_add` only takes the ledger's with images; an L case
  runs removal and comment with image in two threads × 20 (always finishes).
- **Breaking the report baseline** → AC11 runs before touching `report_model` (T0) and after each task.
- **The script slips into another page or into a download** → `markup_problems` admits it only with `report=True` and the
  AC5 sweep covers all routes.
- **Loosening a hostile test when admitting the script** → the §3 assertions are rewritten to «exactly the fixed script»,
  never deleted.
- **Pre-commit hook** → touching `gekko-panel.ts` and `findings*.py` requires touching the living spec (T1 goes first).

## 8. Order of attack
0. **T0:** clean tree; L, WS, W, G, K green; relocate citations; measure `len(CSS)`.
1. **T1 — living spec:** REQ-LED-011, REQ-RPT-070/071 and the amendments of §4 (G red for «REQ without case» until T2–T4).
2. **T2 — `remediated` in `findings.py`** (L-AC8, L-AC10, L-AC11 red → green): `STATUSES`, `set_row`, CLI,
   `included`, `report_fields`, `render_md`, `report_model`, `render_report`.
3. **T3 — web of `remediated` and «outside the report» notice** (WS-AC7, WS-AC9, WS-AC10): `STATUS_*`, token, `:has()`,
   `state_form`, `post_state`, `detail_page`, `report_gap`, `report_body_for`, `report_route`.
4. **T4 — report script** (WS-AC4/AC5): `UNSAVED_JS`, `page(script=)`, `response_headers(csp=)`, `CSP_REPORT`,
   `data-sin-guardar`, `markup_problems(report=)` and the §3 assertions rewritten.
5. **T5 — comments with image in `findings.py`** (L-AC1/AC2/AC3): folding, `comment_add`, `_comment_append`,
   `gallery_delete`, `delete_stamp`.
6. **T6 — comments with image on the web** (WS-AC1/AC2): `capture_item`, form, `post_comment`, `body_limit`,
   `gallery_page`.
7. **T7 — panel and repo texts** (G, W-AC12).
8. **T8 — W** (`report-test.sh`) and CSS measurement.
9. **T9 — closing:** L + WS + W + G + K together, `code-auditor` on script, locks and `included`, PW run of §7 of the
   spec with captures for the operator, `CLAUDE.md`/`AGENTS.md` (spec list), `Status` → `IMPLEMENTADA`.
