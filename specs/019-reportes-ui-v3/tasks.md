# Tasks 019 — Reports V3: comments, inline editing, CVSS, Executive/Technical report and collapsible bar

> Status: `IMPLEMENTADA` (operator, 2026-11-17: closed; real runs done by the operator; final regression at `66a7506`: guard 190/2245, L, WS, sanitizer, report-test 84/0, hooks 48, ws-test 184/0, tui-test 55/0 and toolbox-test with Docker green) · before that — operator, 2026-11-17, without an intermediate gate; external review of the code before coding.
> Spec: [`spec.md`](spec.md) (`APROBADA`, 2026-11-17, 30 AC) · Plan: [`plan.md`](plan.md) (`APROBADO`, 2026-11-17)
> Each task closes ≥1 criterion and names its test. The box is ticked ONLY with the green test and its row in the log.

**Tests:** **L** = `python3 .claude/tools/findings.py selftest` · **V** = `python3 .claude/tools/findings_web.py selftest` ·
**W** = `bash tools/report-test.sh` (runs L and V + HTTP checks against the real module) ·
**S** = `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` (gate and `REQ ↔ case` trace) ·
**K** = `.githooks/test.sh` (the **H** of the spec) · **P** = `bash tools/ws-test.sh` · **U** = `bash tools/tui-test.sh`

**Who:** the code, its tests, the living spec and the docs are written by **a Sonnet 5.5 agent** in this worktree. The tasks marked
**`[operador]`** (operator) or **`[sesión principal]`** (main session) are skipped by it; the main session reviews each delivery against the
AC list and does its own tasks afterwards.

**Rules for the agent:** do not commit or push · do not read or write in `engagements/` (the tests use temporary roots with fictitious data) · do not use port 4355 · kill only processes whose command line names the temporary root · touch only the files in the table of plan §4 · every task with new logic starts with the case that fails
and records its red in the log before the fix · existing REQ cases are not touched except in T14 (REQ-RPT-008), T34 (REQ-RPT-023), T35 (REQ-RPT-024), T38 (REQ-RPT-017) — each names the case and its new assertion, and changes it in the same step as the code so that L, V and W stay green — and in the reconciliation tasks (T22, T42), which update the REQ text in the living spec · every message to the operator in Spanish.

**Deliveries:** 019a (A + B) is finished, audited, really run and committed **before** starting 019b (C + D). The new cases use `ok("REQ-…")` with the ids from plan §4: until T22/T42 the S gate stays red for an unknown id. That red is expected; L, V and W must be green when each task closes.

## Wave 0 — Falsifiers (before changing code)
- [x] **F1** — 018 is merged into `report-module`: `git log` shows it; `findings.py` exports `validate_field`
  and `set_fields`; the `.gekko-web/` helper exists; the living spec has REQ-RPT-025… and the CSP carries `img-src data:`.
  If something is missing, **019a does not start**: it is noted and reported · no AC · test: log
- [x] **F2** — baseline: L, V, W and S on the base; note the number of `ok REQ-…` cases per id (especially
  REQ-LED-001…007 and REQ-RPT-007, -008, -016, -021…024), the `N passed` of W and the trace of S. Generate on the base the
  `render_md` of a fixed test ledger (literal rows, with `cvss` and without vector) and save it in the agent's scratchpad
  (the selftest root is a new `mkdtemp()` on each run, `findings.py:429`); T8 copies it as a literal string
  inside `cmd_selftest` · no AC · test: L, V, W, S
- [x] **F3** — read what 018 left against plan §0: `validate_field` covers `cwe`/`cve`, what it does with a blank;
  `set_fields` denies keys outside the list and deletes with `None`; the helper opens each component with `O_NOFOLLOW`,
  descends via `dir_fd`, sets `0600`/`0700`, checks owner and where it lives (plan 018 puts it in `findings_web.py`:
  T6 moves it); the static case of `set_row`/`set_fields`; relocate by function name the
  `file:line` citations of the plan (they are from base `88dff55`). Each gap becomes a step of T3 or T6 · no AC · test: log
- [x] **F4** — the agent's sandbox can bind `127.0.0.1` and run `node` (if not, V, W and S are left for the main session,
  as in 016) · no AC · test: log

---
# Delivery 019a — comments, inline editing, CVSS

## Wave 1 — Ledger (`.claude/tools/findings.py`)
- [x] **T1** — in red: `REQ-LED-009` cases with the table of plan §2.2 (the 12 vectors with score and band), the two
  «formula only» ones against a reference implementation written separately in the selftest with `decimal.Decimal`, the
  four `roundup` cases (4.02 → 4.1, 4.0 → 4.0, 4.000002 → 4.0, 4.00001 → 4.1), the same vector in another order
  gives the same canonical form, and each rejection in the plan's list (v3.0, v4.0, no prefix, 7 metrics, repeated, `AV:X`,
  lowercase, temporal, environmental, empty, spaces, trailing `/`, > 100 characters) raises `Refusal` with `kind == "invalid"`
  and the message names `cvss_vector` · test: L (red recorded)
- [x] **T2** — `cvss31(vector) -> (canonico, puntaje, banda)`, weight tables, `roundup`, band → ledger severity,
  exactly as plan §2.2 · closes `AC14` · test: L
- [x] **T3** — `NARRATIVE_FIELDS` and 018's `validate_field` add `cvss_vector` (canonical via `cvss31`) and
  `cvss_justification` (non-blank text), plus whatever F3 found missing. Cases first: the two
  new names, valid and invalid, name their field; the chat's `allowed` from 018 still does not accept `cvss_vector`; the
  blank cases from 018 (`--summary ""`, `"   "`, `"​"` exit 1) and those of REQ-LED-001 run **without touching them**.
  Before closing, `grep -rn -- '--\(summary\|impact\|remediation\) ""'` in
  `kb/`, `.claude/`, `.pi/` and `.codex/`: zero calls · closes `AC10` (L part), `AC16` (part) · test: L
- [x] **T4** — `set_row(..., check=None)`: `check(r)` with the lock taken, right before `r.update(extra)`
  (`findings.py:283`); `set_fields` writes derived `cvss` from `cvss_vector` and passes `check=cvss_check(changes)`; its
  `allowed` never accepts `cvss` from the caller. Flags `--cvss-vector` and `--cvss-justification` in `_add_optional_flags`
  (`add` and `set`). Cases first: `set --cvss-vector` writes canonical vector and `cvss` as a number; band ≠ severity
  without justification → exits 1 and bytes equal; with justification in the call or already in the row → writes;
  `--cvss 9.0 --cvss-vector <9.8>` → exits 1 naming `cvss`; `--cvss 9.8 --cvss-vector <9.8>` → writes; `--cvss`
  alone, with or without vector in the row → as today (AC16; limit of REQ-LED-010); `severity` never changes; the
  `check` runs under the lock (a spy `check` verifies the lock is taken). REQ-LED-003/004/007 untouched · closes `AC15` (L part), `AC16` · test: L
- [x] **T5** — in red: `REQ-LED-008` cases on a temporary root: format of the three events; `prev` is the sha256
  of the comment's previous line; folding (order, «editado», tombstone that hides but leaves the text in the file);
  bad events (broken JSON, missing field, unknown `op`, broken `prev`, final line without `\n`) → list of bad ones with
  its number and every write `Refusal("corrupt")`; blank text, invisible or 8193 bytes → `invalid` stating the
  maximum, without writing and without truncating; file near 1 MiB → `full`; `edit` with old `expect` → `stale`; `add` with
  an id that already exists → does not write; each write leaves the previous bytes as an exact prefix (append only);
  `findings.jsonl` byte for byte equal; regular file `0600` and `.gekko-web/` `0700`; a symbolic link planted in
  `.gekko-web/` or in `comentarios.jsonl` → rejection without touching the target; 20 simultaneous `comment add` processes leave 20
  events and a fold with no bad ones · test: L (red recorded)
- [x] **T6** — `comments_path`, `validate_comment`, `comment_add`, `comment_edit`, `comment_delete`, `read_comments`
  per plan §2.3, on the helper. Before, with a case first: `web_open`/`web_unlink` (already in `findings.py`
  since 018; they are not moved) gain the `O_DIRECTORY` variant and the owner control of plan §0: cases of pure `owner_ok` (`st_uid == euid` →
  yes; `st_uid == ws_uid` with `euid == 0` → yes; other → no) and of the `fchown` on creation with `euid == 0` (injecting
  fake `geteuid` and `fchown`: it is called with `ws_uid, ws_gid` before writing; if it fails, it does not write), plus what F3
  found · closes `AC3`
  (L part), `AC4` (L part) · test: L
- [x] **T7** — `findings.py comment add|edit|delete|list` (subparser and `cmd_comment`): prints the id when adding;
  `list` one line per live comment with no controls; negatives with exit 1 and the same `kind` as the function. Table
  of rejections (blank, invisibles, 8193 bytes, comment that does not exist, full file, file with bad events) that T20
  reuses against the web · closes `AC6` (L part) · test: L
- [x] **T8** — `report_fields` shows `cvss_vector` and `cvss_justification` after `cvss`, with `LABELS` in en/es. Cases: the
  `render_md` of F2's fixed ledger comes out byte for byte equal; a row with vector and justification shows them in both
  languages, in a span; `render` is byte for byte equal with and without `comentarios.jsonl` next to the ledger · closes `AC18`
  (vector part), `AC7` (L part) · test: L

## Wave 2 — Module (`.claude/tools/findings_web.py`)
> Every new web write follows the order of controls of plan §2.4. Forgery case first.

- [x] **T9** — in red: the table of `AC10` — for each case (valid and invalid CWE/CVE, `cwe-79`, ` CWE-79`, text
  with only spaces, U+200B, a 60 000-byte value, valid vector, v3.0 vector, vector with band ≠ severity with and without
  justification) it is saved via `respond("POST", "/w/ws/f/<n>/editar", …)` and via `findings.py set` in a subprocess on
  a copy of the same ledger: both reject (422 in Spanish naming the field, text kept, sha256 equal) or
  both rows are equal except `updated`. Plus: a request with extra `status`, `severity`, `title`, `cvss=1.0` and `id` does not
  change them (`AC9`) · test: V (red recorded)
- [x] **T10** — edit mode: `ticket(ctx, kind, *parts)`; `GET …/f/<n>?editar=1` draws a single `<form>` around
  the sections card with `resumen`, `impacto`, `remediacion` (Summary), `cwe`, `cve` and the calculator
  (Record: eight radio groups with the v3.1 values, `vector`, `vector_mostrado`, score, band,
  `justificacion`), Save, Calculate and Cancel; the evidence is shown without fields; the HTML of `state_form` is the same
  as outside edit mode. Cases: sha256 and workspace listing equal after the GET; the form's `name`s (with an
  `HTMLParser`, like `FormFields`) are exactly the plan's list and none is `status`, `corroboration`,
  `blocker`, `severity`, `title`, `target`, `repro`, `kb`, `evidence` or `id`; no nested `<form>` on any
  page; non-editable row → no form and with the reason · closes `AC8` · test: V
- [x] **T11** — `post_edit` and its branch in `respond` (POST list of `findings_web.py:1066`; 413 for every write route,
  not only `/estado` and 018's chat): translates fields to `EDIT_FIELDS`, detects what changed (plan §2.4: equal is not sent;
  absent and empty is not sent; present and blank → 422), calls `set_fields(…, expect=visto, max_bytes=LEDGER_MAX_BYTES)`
  and `allowed=EDIT_FIELDS`; `Refusal.kind` → notice in Spanish; accepted → 303 to the line by id with `editado=<huella>`;
  no changes → 303 without writing. «Edición guardada · `<updated>`» notice only with the current fingerprint. Cases: only the
  changed keys and `updated` change; the rest of the row and the other rows byte for byte equal; T9 green · closes
  `AC9`, `AC10` · test: V
- [x] **T12** — changed row: old `visto` after a `findings.py set` (and after a 018 `set_fields` if present) →
  409 without writing, with «Ahora en el ledger» next to the operator's text in each field that differs; the same form
  sent twice → one write; reloading the notice's URL → none. Case first · closes `AC11` ·
  test: V
- [x] **T13** — calculator: `accion=calcular` → 200 with all the operator's texts, server score and band, and
  equal sha256; full radios → canonical vector; typed vector ≠ `vector_mostrado` → the typed one wins; both changed → 422; half radios → 422 «faltan métricas: …» (metrics missing); empty vector on a row with a vector → 422; saving with band ≠ severity without justification → 422 without writing, with it → saves `cvss_justification`; a `cvss` in the
  request is ignored; `severity` never changes; row with `cvss` but no vector → «sin vector»; vector and number that
  do not match → notice · closes `AC13`, `AC15` · test: V
- [x] **T14** — static case: **modifies** the two `ok("REQ-RPT-008", …)` of `findings_web.py:1628–1637` (in the
  version 018 left), with its test on synthetic fragments. New assertion: with `ast`, the calls to `set_row` are only inside `post_state` and those of `set_fields` only inside `post_edit` and `post_chat` (018's);
  the string `comentarios.jsonl` does not appear in the module outside `cmd_selftest`; `_save`, `_locked`, `cmd_add`, `cmd_set` and `import findings` remain prohibited. The REQ-RPT-008 text is reconciled in T22 · closes `AC12` ·
  test: V
- [x] **T15** — `#comentarios` section in the detail (fourth entry of `detail-nav` and its `:target` rules,
  `findings_web.py:374`, `:382–383`): oldest to newest, text, time, «editado · hora», channel, «Editar»
  (`?comentario=C-…`), «Borrar» and «Agregar comentario»; the D4 note; row without a unique id or not editable → the
  existing ones without actions and the reason; file with bad events → notice with line numbers and no actions; unreadable
  file (e.g. owned by another user) → «no se pudieron leer los comentarios» (comments could not be read), 200, never 500; in edit mode, no
  forms. Cases first · closes `AC1` · test: V
- [x] **T16** — `post_comment` (`/w/<ws>/f/<n>/comentario`, `accion` agregar/editar/borrar), in the order of plan §2.4.
  Forgery cases first: token absent, false, from another finding, from another workspace, from another action (one from
  `/estado`, from 018's chat or from `/editar`) → 403 without writing; foreign `Sec-Fetch-Site` → 403; GET → 404; PUT/DELETE/PATCH → 405;
  body `MAX_BODY + 1` → 413; comment, line or workspace that do not exist → 404 and `.gekko-web/` is not created;
  workspace linked to another one under `engagements/` or `findings.jsonl` not regular → 409, ledger and target intact, without
  `.gekko-web/` in either (same for `/editar`); old `visto`
  → 409 with the text kept; double submit of add → one event; blank or 8193 bytes → 422 stating the
  maximum; `findings.jsonl` byte for byte equal always; the file is born `0600` inside `.gekko-web/` `0700` and is under
  `engagements/` (which `.gitignore` covers: the case reads the repo's `.gitignore` line) · closes `AC2`, `AC3`, `AC4` ·
  test: V
- [x] **T17** — hostile content: each value of `HOSTILE` (`findings_web.py:1350`) and U+202E, U+200B, U+2066, U+FEFF in
  a comment and in each field of the edit: they stay as is in the file and in the ledger, and come out escaped in the
  detail, the edit `<textarea>`, the 409/422 pages and the comment view; the REQ-RPT-007 controls
  (no `<script`, no `<img`, no event attribute, the gear as the only `<svg`, no ESC) on all those pages ·
  closes `AC5` · test: V
- [x] **T18** — comments outside the projections: index, list, report page, `render` and the three downloads byte for byte
  equal with and without `comentarios.jsonl` (with a canary in a comment: it appears in none) · closes
  `AC7` · test: V
- [x] **T19** — 019a isolation: with two workspaces, editing and commenting in one leaves the sha256 of the other's ledger and
  comments equal; non-existent ws, line or comment → 404 without creating anything; a workspace B that is a link to A →
  `/editar` and `/comentario` on B give 409 and A's ledger and comments sha256 does not change · closes
  `AC29` (019a part) · test: V

## Wave 3 — Real process (`tools/report-test.sh`)
- [x] **T20** — HTTP checks against `serve` on the temporary root (after 016's, before concurrency, `tools/report-test.sh:91`): request
  `?editar=1`, extract `visto` and `ficha`, save `impacto` and `cwe`
  (303 and changed row); `accion=calcular` (200, equal sha256); a 422 (invalid CWE); a 409 (changed row with a
  `findings.py set` in between); add, edit and delete a comment with `curl`; `findings.py comment list` shows the web's
  one and the page shows one added by the CLI; the rejection table of T7 gives the same result by both routes;
  `git -C "$REPO" check-ignore -q engagements/x/.gekko-web/comentarios.jsonl`. No red of its own: the routes already exist
  since T11/T16 and their red was in V; here the real process is tested · closes `AC2`, `AC6`, `AC9` (real process) ·
  test: W
- [x] **T21** — concurrency for `AC28`: 10 edit saves on different rows, 10 web comments, 10
  `findings.py comment add` and 10 `findings.py add` at the same time; three rounds; all the changes, events and rows remain;
  `findings.py list` and `findings.py comment list` exit 0 · closes `AC28` · test: W

## Wave 4 — Closing 019a
- [x] **T22** — living spec `specs/SECURITY-GUARDRAILS-SPEC.md`, in the same change as the code: REQ-LED-008, -009,
  -010 and REQ-RPT-035…042 new (MUST + WHEN/THEN + Code + Limit: `ledgerCliOnly` does not accept `comment`; the file
  created inside the container depends on the `fchown` of plan §0 (whatever T26 gives); `--cvss` alone is not checked against the row's
  vector (the page warns) — these two Limits were replaced by T27-fix L7 and the documentation correction: see REQ-LED-008 and REQ-LED-010 as they stand; the old justification is not deleted; «never guess» remains
  a prompt rule; the token is CSRF, not a human in the loop); rewritten over what 018 left:
  REQ-RPT-008 (two new routes, who writes what, T14's static case), REQ-RPT-016 (Comments section and edit
  mode), REQ-RPT-007 (WHEN with comments and editing), REQ-LED-001 (`cvss_vector` and justification in the single
  rule), REQ-LED-002 (eight fields), REQ-LED-007 (`check` under the lock); limit of REQ-RPT-009 (a proxy
  outside loopback also edits and comments). Each «Código:» (Code:) names functions that exist · closes `AC30` (part) ·
  test: S (trace without failures)
- [x] **T23** — docs and prompts: `CLAUDE.md:96` and `AGENTS.md:153` (twins, same change, over the text 018's T29 left) change to «never guess a
  CVSS/CWE/CVE; un CVSS lleva su vector (`--cvss-vector CVSS:3.1/…`)» (a CVSS carries its vector) (D6), and the module line says it also
  comments and edits fields (spec 019); `.claude/agents/finding-analyzer.md`, `.pi/agents/finding-analyzer.md`,
  `.claude/agents/exploit-developer.md`, `.pi/agents/exploit-developer.md` and their `.codex/agents/*.toml`: a CVSS only
  with `--cvss-vector`; `tools/report-test.sh:141–145` adds `--cvss-vector` to the required words; `docs/pi-hitl.md`
  §4c: the proxies notice includes editing and commenting, and where comments live and their retention · no AC (D6) ·
  test: W (prompt checks) + `grep -n "un CVSS lleva su vector" CLAUDE.md AGENTS.md`
- [x] **T24** — L, V, W and S green at once after the last change (S and W only if F4 allows it; otherwise the main session) ·
  closes `AC30` (part) · test: L, V, W, S
- [x] **T25** `[sesión principal]` — K green and `.githooks/pre-commit` keeps running `tools/report-test.sh` when touching
  `findings.py` or `findings_web.py`; independent security review of the 019a diff (`code-auditor` agent,
  read-only); each finding is fixed with a case first or noted as a limit in the living spec · closes `AC30` ·
  test: K + report + L, V, W, S green afterwards
- [x] **T26** `[operador]` — real run of 019a in the browser with `tools/pi-hitl.sh`, test workspace with
  synthetic data: comment, edit and delete a comment; edit impact and CWE; calculate a CVSS with and without
  justification (check `AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N` and `AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L` in FIRST's calculator
  and note their scores); a save over a row that the agent changed (409); in toolbox mode, both directions: (1) without `comentarios.jsonl`, `findings.py comment add` from a container shell, `ls -ln` shows
  owner = operator and `0600`, and the module lists it; (2) with the file created from the web, `comment add` and `comment
  list` from the container exit 0 and the page shows the new one; screenshots in both themes at 1500
  and 760 px (no lab data in the repo) · closes spec §7 (019a part) · test: screenshots + log
- [x] **T27** `[sesión principal]` — regression and commit of 019a: L, W, K, S, P and U green at once; review of
  AC1–AC16 and the 019a part of AC28–AC30 one by one against the log; commit in `report-module` (the `pre-commit`
  runs gitleaks and `tools/report-test.sh`) · test: the six commands + real commit

---
# Delivery 019b — Executive/Technical report, drafts, brand, bar

## Wave 5 — Falsifiers 019b
- [x] **F5** — 019a is committed and L, V, W, S, K green on it; note cases by REQ-RPT-014, -017,
  -021…024 id and the size of `CSS` (56 644 bytes on the base; note the real one after 018 and 019a) · no AC · test: L, V, W, S, K
- [x] **T28** `[operador]` — deliver `Michroma-Regular.ttf` and its `OFL.txt` (Google Fonts, folder `ofl/michroma/` of
  `google/fonts`) outside the repo, with its sha256 in the log. The agent makes the subset with
  `pyftsubset Michroma-Regular.ttf --unicodes="U+0020-003A,U+0041-005A,U+00B7,U+00C0-00DD" --flavor=woff2 --output-file=<scratch>/michroma.woff2`
  and notes sha256 and size · no AC (D11) · test: log

## Wave 6 — Ledger (`.claude/tools/findings.py`)
- [x] **T29** — in red: `render_report(rows, lang, "tecnico", None)` == `render_md(rows, lang)`; with a draft it contains
  `render_md(rows, lang)` as an exact substring, the draft's sections before and «Recommendations» after;
  Executive with the order of plan §3.1, count by severity equal to `included`, one table row and one `### ` per
  included even if the title carries `## `, line breaks or `|` (four cells per row under GFM's rule: splitting at an unescaped `|`); with canaries in `evidence.command`, `evidence.artifact`, `evidence.output`, `repro`, `corroboration`,
  `summary` and `remediation`, none appears in the Executive; `validate_draft` rejects unknown key, Technical key in Executive (`metodologia`), non-text value, 4097 bytes and a line break in a one-line field, naming the field ·
  test: L (red recorded)
- [x] **T30** — `DRAFT_FIELDS`, `ONE_LINE`, `validate_draft`, `render_report` and new labels in `LABELS`;
  `render --tipo tecnico|ejecutivo [--borrador F]` (read by `_read_regular` with cap `DRAFT_MAX_BYTES`, plan
  §3.2); unknown type,
  invalid draft or `--all` with `--tipo` → exits ≠ 0 without printing a report · closes `AC18`, `AC19` (Markdown), `AC21`
  (L part) · test: L

## Wave 7 — Module (`.claude/tools/findings_web.py`)
- [x] **T31** — draft store through the helper: `read_draft(ws, tipo) -> (dict | None, sha256 | "ninguno")` and
  `save_draft(ws, tipo, campos, expect)` (lock over `borradores/`, temporary `O_EXCL` `0600` via `openat`,
  `os.replace` in the same directory). Cases first: regular file `0600`, `borradores/` `0700`; symbolic link in
  `.gekko-web/`, in `borradores/` or in `<tipo>.json` → rejection without touching the target; old `expect` → `stale`; saving
  `tecnico` does not change the sha256 of `ejecutivo` · closes `AC20` (store) · test: V
- [x] **T32** — report page (`report_route`, `findings_web.py:985`): type selector (Technical by default) and
  language, unknown parameters to the default value, draft form of the type with its D8 fields
  (placeholder «Cliente» = workspace, never a value), two equal columns ≥ 1280 px and stacked below, `@media print`
  only the preview; `post_draft` (`/w/<ws>/reporte/borrador`) in the order of plan §2.4: `borrador` token bound to
  ws, type and `visto`; forgeries first (token absent/false/of another type/of another ws → 403; GET → 404; 413; broken UTF-8 →
  400; linked workspace or non-regular `findings.jsonl` → 409 without creating `borradores/`; body
  `DRAFT_MAX_BODY + 1` → 413); a Technical with the 11 fields at their 4096-B cap made of `€` (3 UTF-8 bytes, ×3 when encoded) is saved (303) and read back the same by the web and by `render --borrador`; `previsualizar` → 200 without writing
  with the preview of what was sent; invalid `guardar` → 422 with the
  text; old `visto` → 409 with the text; accepted → 303. Both types use `included`: no parameter (`?all=1`,
  `estado=…`) pulls in another status or leaves out a corroborated confirmed finding · closes `AC17`, `AC20` · test: V
- [x] **T33** — downloads per type: link with `tipo`, `idioma`, `ledger` and `borrador` (absent = `ninguno`); ledger or
  draft changed → 409 without a file; `.md` == `render_report` == `findings.py render --tipo … --borrador …` (by
  subprocess) for both types and both languages; the page shows sha256 of ledger, draft, `.md` and `.html` and they
  match what was downloaded; name `<ws>-reporte-<tipo>-<idioma>.<ext>` with explicit `tipo`, and today's one,
  `<ws>-reporte-<idioma>.<ext>`, without `tipo` (plan §3.2): 017's checks (`findings_web.py:2051–2058`,
  `tools/report-test.sh:52`) stay green without touching them ·
  closes `AC21` (web), `AC22` · test: V
- [x] **T34** — `report_html` per type: logo `horizontal-claro.png` as `data:` background in the `<style>` with hash (the
  base64 matches the file in `.claude/tools/brand/`), `print-color-adjust:exact`, internal CSP with `img-src data:`
  as the only novelty, no `<img`, `<script`, links or external resources; deterministic; no workspace name nor
  today's date unless they are in the draft; Executive without T29's canaries. **Modifies** the case of
  REQ-RPT-023 (`findings_web.py:2065–2072`): `"url(" not in html_response[2]` becomes «every `url(` in the HTML is
  `url(data:image/png;base64,…)`» and the comparison with `report_html` uses the new signature; the REQ text is reconciled in
  T42 · closes `AC19` (HTML), `AC24` (HTML) · test: V
- [x] **T35** — PDF by segments: first line «GEKKO · Offensive Security» in bold; cover on its page if the draft carries it;
  Executive table one line per row and ≤ 80 columns with «…» when cut and the full id on the card; `pdf_page_count` per segment equal to
  the generated pages; **modifies** the case of REQ-RPT-024
  (`findings_web.py:2030`): `pdf_page_count(pdf_lines(...))` receives the segments and adds per segment, and stays equal to
  the number of `/Type /Page /Parent`; the other REQ-RPT-024 cases stay green without touching them; the PDF does not carry
  today's date nor the workspace name unless they are in the draft; Executive without T29's canaries; same ids as the
  `.md` · closes `AC19` (PDF), `AC22` (PDF), `AC24` (PDF) · test: V
- [x] **T36** — hostile content in ledger **and** draft (REQ-LED-002's values and `HOSTILE` in each draft field):
  preview and page escape everything; the `.md` of both types, with spans and fences removed via `_CODE_SPAN`,
  carries no `<`, `![` or `](`; the HTML meets 017 AC9; no view or download opens a connection other than
  loopback (REQ-RPT-022's socket audit) · closes `AC23` · test: L + V
- [x] **T37** — bar: `post_barra` and route `/barra`; cookie `gekko_barra` only with `plegada`/`abierta`
  (`HttpOnly`, `SameSite=Strict`), 303 to `safe_back`; `BACK_RE` accepts `/w/<ws>/reporte?tipo=…` (collapsing from the
  report page returns to it; case also for `/tema`) and still rejects `/w/<ws>/reportes`,
  `/w/../reporte` and `//x`; invalid value → no `Set-Cookie` and no echo; `Sec-Fetch-Site:
  cross-site` → 403 without `Set-Cookie`; GET → 404; REQ-RPT-014's hostile cookie values yield no class and do not
  appear; the CSS has 70 px collapsed and D10's rules by width; each navigation link keeps its
  accessible name (non-empty text not `aria-hidden`) collapsed and open · closes `AC25` · test: V
- [x] **T38** — brand and font: the case checks that no «G» remains in `sidebar` (`findings_web.py:449`) nor in
  `top-brand` (`:467`) (018 already changes it); bar open with `--logo` and collapsed with `--iso`, per theme; `@font-face` Michroma of T28's subset (`wOF2` signature) next to
  Space Grotesk, `OFL-Michroma.txt`; Michroma only in the classes of plan §3.2; new pairs in `CONTRAST_PAIRS` ≥ 4.5:1
  in both themes; no page names an external origin; `len(CSS.encode()) ≤ 90000` and the real number to the log;
  **modifies** the case of REQ-RPT-017 (`findings_web.py:2177–2179`): `len(font_urls) == 1` becomes `== 2`, each with
  `wOF2` signature, with `font-family:"Space Grotesk"` and `font-family:"Michroma"`; the REQ text is reconciled in T42 ·
  closes `AC26` · test: V
- [x] **T39** — `AC27` sweep: all new responses (edit, calculate, comments, draft, preview, bar, 409/422/413 pages, downloads of both types) without `<script`, without event attributes and without the word
  `localStorage`; the pages' CSP without `script-src` nor `connect-src` and its only relaxation `img-src data:` ·
  closes `AC27` · test: V
- [x] **T40** — 019b isolation: saving a draft in one workspace leaves the other's ledger, comments and drafts equal;
  non-existent workspace → 404 without creating anything · closes `AC29` · test: V

## Wave 8 — Real process
- [x] **T41** — HTTP checks: save an Executive and a Technical draft with `curl`; the six downloads (two types ×
  three formats, in `es`) with their sha256 against the page; each type's `.md` == `findings.py render --tipo …
  --borrador <file>`; change the draft and repeat an old download → 409; `POST /barra` sets the cookie and the index carries the class;
  `pdftotext` (if present) finds «GEKKO · Offensive Security» and the table; `git check-ignore` of the
  draft · closes `AC21`, `AC22` (real process) · test: W

## Wave 9 — Closing 019b
- [x] **T42** — living spec: REQ-RPT-045…054 new; rewritten REQ-RPT-007 (brand, Michroma), -008 (draft and bar),
  -014 (bar), -017 (two fonts), -021…024 (type, draft, brand, segments), REQ-LED-002 (`--tipo`, `--borrador`);
  limits: REQ-RPT-009 (also saves drafts), `.md` table with `\|`, «…» cut only in the PDF table, the viewer must respect the CSP and
  `print-color-adjust`, weight per page · closes `AC30` (part) · test: S
- [x] **T43** — docs: `docs/pi-hitl.md` §4c (types, drafts, where they live and their retention, bar, sha256 of the
  downloads); `report-writer` in `.claude/agents/`, `.pi/agents/` and `.codex/agents/`: `render --tipo` and `--borrador`;
  `tools/report-test.sh:146–148` requires `--tipo` in those prompts · no AC · test: W + review
- [x] **T44** — L, V, W and S green at once after the last change · closes `AC30` (part) · test: L, V, W, S
- [x] **T45** `[sesión principal]` — K green; independent security review of the 019b diff (`code-auditor`);
  each finding with a case first or as a limit · closes `AC30` · test: K + report + L, V, W, S
- [x] **T46** `[operador]` — real run of 019b: Executive and Technical drafts; the six downloads checked
  with `sha256sum` against the page; open HTML and PDF in a viewer (the logo shows and prints); bar collapsed and
  open; screenshots in both themes at 1500 and 760 px · closes spec §7 and `AC26` (§7 part) · test: screenshots +
  log
- [x] **T47** `[sesión principal]` — regression and commit of 019b: L, W, K, S, P and U green at once; review of
  AC1–AC30 against the log; commit in `report-module`; `Status` of spec, plan and tasks → `IMPLEMENTADA`; 019 in the list of merged specs in `CLAUDE.md` and `AGENTS.md` (twins) · test: the six commands + real commit

## AC → tasks map
| AC | Tasks | AC | Tasks | AC | Tasks |
|---|---|---|---|---|---|
| AC1 | T15 | AC11 | T12 | AC21 | T30, T33, T41 |
| AC2 | T16, T20 | AC12 | T14 | AC22 | T33, T35, T41 |
| AC3 | T5, T6, T16 | AC13 | T13 | AC23 | T36 |
| AC4 | T5, T6, T16 | AC14 | T1, T2 | AC24 | T34, T35 |
| AC5 | T17 | AC15 | T4, T13 | AC25 | T37 |
| AC6 | T7, T20 | AC16 | T3, T4, T9, T13 | AC26 | T38, T46 |
| AC7 | T8, T18 | AC17 | T32 | AC27 | T39 |
| AC8 | T10 | AC18 | T8, T29, T30, T33 | AC28 | T21 |
| AC9 | T9, T11, T20 | AC19 | T29, T30, T34, T35 | AC29 | T19, T40 |
| AC10 | T3, T9, T11 | AC20 | T31, T32 | AC30 | T22, T24, T25, T42, T44, T45 |

## Open questions
1. F1: if 018 has not merged yet or its contract differs from plan §0, 019a waits; the difference is resolved in 018's
   plan, not here.
2. T26: if either direction fails despite the owner of plan §0 (e.g. remapped userns), the mode or the file owner is decided by the long flow (today the spec fixes `0600`) and it remains as a limit of REQ-LED-008.

## Verification log
| Task | Command | Result | Date |
|---|---|---|---|
| F1-F4 | reading `findings.py`/`findings_web.py` from 018; loopback bind and `node` available | 018 contract present; `web_open` only lacked owner/directory (T6) | 2026-11-17 |
| T1-T4, T8 | `python3 .claude/tools/findings.py selftest` | red (NameError `cvss31`, `drop` accepting `cvss_vector`) → green; 123 `ok` (base 79); 12 plan scores verified with the FIRST formula in `Decimal` and the 2592 vectors: none corrected | 2026-11-17 |
| T5-T7 | ditto | red (NameError `owner_ok`, comments) → green: `prev` chain, tombstone, double submit, 20 processes, CLI | 2026-11-17 |
| T9-T19 | `python3 .claude/tools/findings_web.py selftest` | red (REQ-RPT-008 static, REQ-RPT-038/039) → green; 273 `ok`; REQ-RPT-035…042 | 2026-11-17 |
| T20, T21 | `bash tools/report-test.sh` | 73 passed, 0 failed (HTTP edit/comments and 3 rounds of 40 writes) | 2026-11-17 |
| T22-T24 | guard 180 requirements/2147 cases; sanitizer; `.githooks/test.sh` 48; `ws-test.sh` 184 | green (tui-test: see report) | 2026-11-17 |
| T27-fix M1 | `findings_web.py selftest` | red (impact with ANSI, `\r\n` and invisibles rewritten with U+FFFD when editing only `cwe`) → green: `impact` byte for byte equal in the ledger | 2026-11-17 |
| T27-fix M2 | `findings.py selftest`, mutation (copy without the `fcntl.flock` of `_comment_append`) | 12 processes editing the same comment, with a pause after reading: without lock, red (lines 3.. «cadena prev rota» (broken prev chain)); with lock, green: 13 lines, chain recomputed separately | 2026-11-17 |
| T27-fix M3 | `findings.py selftest`, guard (trace) | `ok()` ids realigned with the spec (CVSS=008, comments=009, CLI/not in report=010); new case `list` with and without `.gekko-web` (010); RPT-008 rewritten (four web writes) and AST case of `comment_*` only in `post_comment` (with synthetic fragments); RPT-016, RPT-007, LED-001, LED-002, LED-007 were not rewritten as T22 said: reconciled; RPT-036/039 point to REQ-RPT-019 (the order of controls; RPT-017 is the source) | 2026-11-17 |
| T27-fix L1 | `findings_web.py selftest`, mutation (without `orig_*`) | red (the resend after a 409 reverted the other writer's `impact` and its vector) → green: only the fields differing from what was shown are applied (`orig_*` = sha256 of what was shown); the 409 page shows «Ahora en el ledger» also for the vector | 2026-11-17 |
| T27-fix L2 | spec REQ-LED-009 | documentation only: the `prev` chain carries no key; whoever writes the workspace rebuilds it without anything detecting it | 2026-11-17 |
| T27-fix L3 | `findings.py selftest` | red (`comment list` printed `at` raw and `finding` with ESC) → green: one line, no Cc/Cf in any field | 2026-11-17 |
| T27-fix L4 | `findings.py` and `findings_web.py selftest`, mutation (without the rejection) | red (`UnicodeEncodeError`, 500 on the web) → green: `invalid` without writing or creating a directory; in a hand-made file it is a bad line; the web does not give 500 | 2026-11-17 |
| T27-fix L5 | `findings_web.py selftest`, mutation (joins all lines) | red (page of 14 701 185 bytes) → green: <200 KB, first 5 lines and the total (1048576) | 2026-11-17 |
| T27-fix L6 | `findings_web.py selftest`, mutation (always validates) | red (422 when editing `cwe` with `cvss_vector: "garbage"`) → green: saves and does not rewrite the vector; the invalid vector written is still 422 | 2026-11-17 |
| T27-fix L7 | `findings.py selftest` | red (`set --cvss 3.3` over a 9.8 vector was written) → green: rejected naming `cvss`; the equal one and the row without vector pass | 2026-11-17 |
| T27-fix L8 | `findings.py selftest` | red (the planted FIFO was opened with `os.open`) → green: `stat` without following links before opening; `os.open` never receives its name | 2026-11-17 |
| T27-fix L9 | `findings.py selftest` | the two `chown` cases print `skip … NOT checked` as root instead of counting as `ok` | 2026-11-17 |
| T27-fix doc | spec REQ-LED-010, plan §6 | `ledgerCliOnly`: only a `bash` naming a scope entry is blocked except `findings.py add\|set\|list\|render`; a `comment` without a scope host passes; operator's decision | 2026-11-17 |
| T27-fix N1 (M1 surrogate) | `findings_web.py selftest`, REQ-RPT-039 | red (editing only `cwe` rewrote `impact` "antes \udc80 despues" as "antes ? despues") → green: `seen_digest` computes over the bytes served (`encode("utf-8","replace")`); `impact` stays the same in the ledger | 2026-11-17 |
| T27-fix N2 (M1 line break) | `findings_web.py selftest`, REQ-RPT-039 | same case with `cve` "CVE-2024-1234\n" and the submission without CR/LF like a browser → green: the fingerprint of `cwe`/`cve` (`TEXT_INPUT_KEYS`) ignores CR/LF; `cve` stays the same | 2026-11-17 |
| T27-fix N3 (L7 doc) | spec.md AC16, plan.md §2 | AC16 and the plan reconciled with `cvss_check`: `--cvss` alone is rejected only if it contradicts the parseable vector | 2026-11-17 |
| T27-fix N4 (M3 plan) | plan.md | REQ-LED references renumbered per the living spec (008 CVSS, 009 comments, 010 not in the report) | 2026-11-17 |
| T27-fix N5 (RPT-008 Code line) | SECURITY-GUARDRAILS-SPEC.md | Code adds `post_edit`, `post_comment`, `set_fields`, `comment_add\|edit\|delete`; the THEN names the four status fields | 2026-11-17 |
| T27-fix N6 (RPT-008 AST) | `findings_web.py selftest` | red (the fragment `m.comment_edit(y)` / `sys.modules[...].comment_delete(z)` did not count) → green: `users_of` counts attributes; `Ctx.comment_edit` renamed `comment_editing` | 2026-11-17 |
| T25 | `code-auditor` review of the 019a diff; `.githooks/test.sh`; `toolbox-test.sh` | M1–M3, L1–L9 fixed (T27-fix rows); pre-commit ran `report-test.sh` when committing `findings.py`; toolbox-test PASS | 2026-11-17 |
| T27 | L, V, W, S, K, `.githooks/test.sh`, `ws-test.sh`, `tui-test.sh` | guard 180/2162, selftests OK, report-test 73/0, githooks 48, ws 184/0, tui 55/0, toolbox-test PASS; commit 0ef54c0 in `report-module` | 2026-11-17 |
| T28 | `sha256sum`; `pyftsubset` (fonttools 4.63.0) | font from the operator's brand kit (operator's decision; 14 copies on disk with the same hash): `Michroma-Regular.ttf` b62301163788bc5b7f8fcac0b74b184e34e1827e577b499ecb724da065098f87, `OFL.txt` 33c39ce59a45bfb0dae3280e98bdb46be59d6d68efc62d4dc5fae90a26d2f393 (OFL 1.1, The Michroma Project Authors); subset `michroma.woff2` d71f1f9eed8b8636bcc7fa436027cd58014dc83f1501281f6edb5502c85f00c2, 8516 bytes | 2026-11-17 |
| F5 | `git log`, L, V, W, S, K on 019a (`0ef54c0`, clean tree); `len(CSS.encode())` | baseline: trace 180 requirements / 2167 cases; L, V, W, S, K green; CSS 74 857 bytes (018 and 019a already counted) | 2026-11-17 |
| T29, T30 | `python3 .claude/tools/findings.py selftest` | red (`NameError: render_report`) → green: 147 `ok` (123 before); Technical without draft == `render_md`; with draft `render_md` is an exact substring; Executive with count, one row and one `###` per included, four cells per row GFM, seven canaries absent; `validate_draft` rejects 8 cases naming the field; `render --tipo/--borrador` == `render_report`, and unknown type, invalid or missing draft, `--all` with `--tipo` and `--borrador` without `--tipo` exit ≠ 0 without stdout | 2026-11-17 |
| T31-T33 | `python3 .claude/tools/findings_web.py selftest` | red (`REQ-RPT-045` on 018's page; then `NameError: read_draft`, downloads per type with 500 on the Executive PDF) → green: store `0600`/`0700`, `stale`, planted links in `.gekko-web/`, `borradores/` and `<tipo>.json` rejected without touching the target; false token, of another type or of another workspace 403; foreign origin 403; old fingerprint 409 with text kept; 4097 bytes and line break 422; eleven fields of 1365 `€` (`DRAFT_MAX_BODY`) save and read back the same by the web and by `render --borrador`; six downloads == CLI; hashes on the page == those downloaded; download with changed draft 409 | 2026-11-17 |
| T34, T35 | ditto (REQ-RPT-052 and REQ-RPT-047 cases) | HTML with the logotype `data:` as the only URL, `img-src data:` the only novelty in the internal CSP, no `<img`/`<a`/`<script`, deterministic, no workspace or date; PDF with the bold brand, cover on its page, lines ≤ 80 columns, «…» only in the table, pages per segment == generated. Modified: REQ-RPT-023 (`url(` now «every `url(` is `data:image/png`») and the signature of `report_html`/`pdf_*` (final parameters with default value: the other REQ-RPT-024 cases run without touching them) | 2026-11-17 |
| T36 | L and V (REQ-RPT-051) | hostile `.md` (ledger and draft, two types) without `<`, `![`, `](` nor forged headings outside spans and fences; HTML and pages with no active markup; socket audit with no connections | 2026-11-17 |
| T37-T40 | ditto (REQ-RPT-053, -054, -048) | `POST /barra` only with `plegada`/`abierta`, 303 to `safe_back` (`/w/<ws>/reporte` valid; `/w/<ws>/reportes`, `/w/../reporte`, `//x` not), garbage without `Set-Cookie`, 403/404/405; `barra-*` class only with exact value, sharing attribute with the theme; accessible names collapsed and open; no «G»; Michroma `wOF2` sha256 `d71f1f9e…00c2` next to `OFL-Michroma.txt`; **CSS 88 888 bytes** (cap 90 000); AC27 sweep; isolation between workspaces and linked workspace (409). Modified: REQ-RPT-017 (`len(font_urls) == 2`) and REQ-RPT-034 (the report opens only its drafts with `web_open`, never the chat history) | 2026-11-17 |
| T41 | `bash tools/report-test.sh` | 85 passed, 0 failed (12 new checks: preview, save both types, `0600`/`0700`/`check-ignore`, six downloads with sha256 against the page and `.md` == `render --tipo --borrador`, 409 with changed draft, bar cookie and class) | 2026-11-17 |
| T42, T43 | `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` | red (`marker REQ-RPT-045… does not exist in the spec`, then `REQ-RPT-046 … no case covers it`) → green: 190 requirements / 2223 cases; REQ-RPT-045…054 new and reconciled 007, 008, 009, 014, 017, 019, 021–024 and REQ-LED-002; `docs/pi-hitl.md` §4c and the three `report-writer` with `--tipo`/`--borrador` | 2026-11-17 |
| T44 | L, V, W, S | L 147 `ok`, V 321 `ok`, W 85/0, S 190/2223: green | 2026-11-17 |
| T45-fix B1 | `python3 .claude/tools/findings.py selftest` | red (`AssertionError: a refusal naming a hostile draft key carries no control byte…`, ESC in the message and in stderr of `render --borrador`) → green with `{key!r}` in `validate_draft`; REQ-LED-002 | 2026-11-17 |
| T45-fix B2 | `python3 .claude/tools/findings_web.py selftest` | red (the case with a foreign `flock` hung for more than 120 s) → green: `LOCK_EX\|LOCK_NB` with bounded wait `DRAFT_LOCK_SECONDS`=3 s → `Refusal("stale")`; `OSError` → `not_regular`; temporary deleted if `os.replace` fails; REQ-RPT-048 | 2026-11-17 |
| T45-fix B3 | ditto | red (the 409 did not carry the current saved text) → green: `stale_message` adds the saved text to the response; REQ-RPT-048 | 2026-11-17 |
| T45-fix B4 | ditto | red (preview/409/422 with download links and `volver` = `/`) → green: `answer()` sets `back` to `/w/<ws>/reporte?tipo=…` and the right column replaces the downloads with a notice if there are `draft_values`; REQ-RPT-048 | 2026-11-17 |
| T45-fix B5 | ditto | documentation only + new case (planted directory → notice and 409 with and without `tipo`), green on entry because the code was already conservative; Limit of REQ-RPT-050, nothing loosened | 2026-11-17 |
| T45-fix B6 | ditto | cases strengthened: link exactly 409 and no `.gekko-web` at a new destination, 8 concurrent saves → 1 success, tokens `estado`/`editar`/`chat`/`comentario` → 403; green on entry (the code already complied; the test was weaker than the text) | 2026-11-17 |
| T45 (closing) | L, V, W, S, K, `ws-test.sh`, `tui-test.sh`, `toolbox-test.sh`; 3 mutations of the verification | cases strengthened after the adversarial verification: the 409 for an old draft with hostile `alcance` (without `esc` in the notice → red), `DRAFT_LOCK_SECONDS == 3.0` with wait in [2.5; 4) s (9 s → red), `DRAFT_MAX_BODY == 196608` (×500 → red); Limit of REQ-LED-002 names the raw draft via stdout | 2026-11-17 |
| UI-r3 A | `python3 .claude/tools/findings_web.py selftest` | red (the old pinned cases: `Reporte · N incluidos`, `class="downloads"`, `class="preview sheet"`) → green with the case «UI-r3: one header row…» (6 actions, `form="borrador"`, one primary, segmented, `<details open>`, provenance in a `<details>`) | 2026-11-17 |
| UI-r3 B | ditto and `findings.py selftest` | red (`Technical without a draft is byte-for-byte render_md`; the `.md` ≠ `render_report(…, workspace)`) → green: cover, numbered sections, severity cards, localized labels in MD/HTML/PDF; plain `render_md` intact except KB | 2026-11-17 |
| UI-r3 C1 | `findings_web.py selftest` | new case of radios in Spanish and `state-actions` (the button is no longer a direct child of the grid) | 2026-11-17 |
| UI-r3 C2 | `findings.py selftest`, `findings_web.py selftest`, `report-test.sh` | red against HEAD (probe: `KB leaked: [True, True, False, True, True]` in `render_md`, Technical `render_report`, HTML, PDF) → green (`[False]*5`); cases «a row with kb set renders no KB line…» and «…reaches no Markdown, HTML, PDF or report page, while the Registro tab still shows it» | 2026-11-17 |
| UI-r3 C3 | `findings_web.py selftest` | case of the `notice flash` with short date plus time, `@keyframes flash` and `prefers-reduced-motion` rule in the CSS, without `style=` | 2026-11-17 |
| UI-r3 D | screenshots `r3-after/detail-*` | the «Propuesta» block is no longer cut (the log has no own scroll, the assistant does) and the summary line fits in two lines at 1500 px; visual check, no automatic case | 2026-11-17 |
| UI-r3 rev1 | `findings_web.py selftest` | red (assistant CSS with its own scroll, `.flash` without initial `overflow`, monospaced radios, `short_stamp` without timezone, provenance over the sheet, repeated `Repro:`) → green: fixed compositor with scrollable log, `.flash{overflow:hidden}`, time with « UTC»/offset, `<details class="prov">` under the sheet, sheet header in two `<span>`, sticky left panel, faint placeholders, repro in `<ol>`; REQ-RPT-021/039/051 | 2026-11-17 |
| UI-r3 rev2 | `findings.py selftest` | new coverage case (every field line of `render_md` is in the Technical: green on entry, closes the gap) and red→green case of `render --tipo` without `--workspace` outside `engagements/` (it no longer puts the folder name); REQ-LED-002 | 2026-11-17 |
| UI-r4 print | `findings_web.py selftest`, `report-test.sh` | red (new REQ-RPT-024 case: `.imprimir` gave 404 and the CSS had no `@page`) → green: `reporte.imprimir` = bytes of the `.html` (same sha256), inline, CSP with the hash of the document's CSS, help es/en, footer repeated with escaped classification, `.pdf` = 404. A first version served `.imprimir` with the page's CSP and Chromium blocked the style (probe with `page.pdf`: document with no style) → `PRINT_CSP` added; the footer `position:fixed;bottom:-13mm` was cut onto the next page → repeated table footer (`tfoot`). Removed with the function `pdf_lines`, `pdf_page_count`, `pdf_bytes`, `_pdf_literal`, `pdf_text`, `PDF_MAX_PAGES`, the `.pdf` route, and the cases that only pinned the PDF (80-column hostile, determinism/WinAnsi, page cap, generator failure, segments, bold brand); the shared cases (REQ-RPT-022/047/050/052/033/037) move from `pdf` to `imprimir` without loosening anything. `report-test.sh`: `pdftotext` removed, `cmp` and sha256 of the print view against the `.html` and 404 of `.pdf` added (84/84) | 2026-11-17 |
| UI-r4 print (review) | `findings_web.py selftest` | red (REQ-RPT-024 requires `table-layout:fixed` and `.doc td,.doc th{overflow-wrap:anywhere}`; they were absent) → green: a long token in title/target no longer widens the Executive table. Rules outside `@media print`, only in the download's CSS | 2026-11-17 |
| UI-r5 status | `findings_web.py selftest` | red (new REQ-RPT-018 case: the form had «Corroboración actual/nueva» and «Bloqueo actual/nuevo» and the values outside the placeholder) → green: one field per requirement with label and hint, current value as escaped text under the label (neutral placeholder), a line «Vacío conserva…» (empty keeps…), `:has()` inside `@supports`; the empty-keeps and byte-for-byte resend cases stay the same | 2026-11-17 |
| | | | |
