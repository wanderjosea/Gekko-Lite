# Technical plan 019 — Reports V3: comments, inline editing, CVSS, Executive/Technical report and collapsible bar

> Status: `IMPLEMENTADA` (operator, 2026-11-17: closed; real runs done by the operator; final regression at `66a7506`: guard 190/2245, L, WS, sanitizer, report-test 84/0, hooks 48, ws-test 184/0, tui-test 55/0 and toolbox-test with Docker green) · before that — operator, 2026-11-17, without an intermediate gate (§8 of the spec); external review of the code before
> coding.
> Spec: [`spec.md`](spec.md) (`APROBADA`, 2026-11-17, 30 AC) · Branch `report-module`, base `88dff55` + 018 merged
> Coding: a Sonnet 5.5 agent in this worktree, after the external review of spec, plan and tasks;
> verification, security review and integration are done by the main session.
> `file:line` citations: from base `88dff55`. 018 shifts `findings.py` and `findings_web.py`; F3 relocates each
> citation by function name before using it.

## 0. Two deliveries and what they expect from 018
D1 (b): one plan, two deliveries in order **018 → 019a → 019b**, each with its gates green and its commit.
- **019a** = blocks A + B (AC1–AC16, plus their part of AC28–AC30): comments, inline editing, CVSS. Writes into the
  workspace and touches `set_row`.
- **019b** = blocks C + D (AC17–AC27, plus their part of AC29–AC30): per-type report, drafts, brand, bar.

Fixed contract between specs (not renamed). 019a **does not start** if 018 did not leave this in `report-module` (F1):
- `findings.py` `NARRATIVE_FIELDS = ("summary", "impact", "remediation", "cwe", "cve")` and
  `validate_field(name: str, value: str) -> str`: pure, extracted from `_optional_fields` (`findings.py:199`); non-blank
  text (`_blank`) for the three drafting ones, `FORMAT_FIELDS` for `cwe`/`cve`, any other name `invalid`;
  raises `Refusal(kind="invalid")` with a Spanish message containing the key. The rejection of blank in `add`/`set`
  is brought by 018 (plan 018 §2).
- `findings.py` `set_fields(ledger: Path, line: int, changes: dict[str, str | None], expect: str, max_bytes: int,
  *, allowed: frozenset[str]) -> dict`: wraps `set_row` (`findings.py:249`) without nesting the lock; every key must
  be in `allowed` and in `NARRATIVE_FIELDS`; each non-`None` value goes through `validate_field`; `None` deletes the key via
  `set_row(drop=…)` and requires `expect` (only 018's «Deshacer» (Undo), its D5).
- The module's file helper `web_open(workspace, parts, flags) -> int` / `web_unlink(workspace, parts)`
  (plan 018 §2, «Historia» (History); here **«the helper»**): descends from the workspace with `O_DIRECTORY | O_NOFOLLOW`
  component by component via `dir_fd`, creates directories `0700`, opens the last one with `O_NOFOLLOW | O_NONBLOCK |
  O_CLOEXEC` and mode `0600`, `fstat` regular. 018 already leaves it in `findings.py` (comments are also written by the
  CLI, D2; the module imports it, no copy), so **T6 does not move it** and, with a case first, adds the directory variant
  (`O_DIRECTORY`, for the drafts lock) and the owner check (reverse reconciliation: tightens). **Owner with the toolbox in
  mind:** the container runs as root (`toolbox/Dockerfile` without `USER`, `toolboxRunArgs` without `--user`,
  `toolbox/gekko-workspace.ts:265`) and the module with the operator's UID. Hence the accepted owner is
  `owner_ok(st_uid, euid, ws_uid)` = `st_uid ∈ {euid, ws_uid}`, with
  `ws_uid` = owner of the workspace directory (`fstat` of its `dir_fd`); and when the helper **creates** a file or
  directory with `euid == 0` and `ws_uid ≠ 0`, it does `os.fchown(fd, ws_uid, ws_gid)` before writing. This way a
  `comment add` from the toolbox leaves the operator's file (`0600`, readable by the module) and the container's CLI
  opens the one the module created.
- Static case of 018 «the module calls `set_row` only from `post_state` and `set_fields` only from
  `post_chat`»: 019a adds `post_edit` to it (AC12).
- Order of controls of 018's write routes (`post_chat`), the same as §2.4; 413 via `ctx.too_long` already applies to `/estado` and the chat routes.
- CSP with `img-src data:` and the CSS variables of the kit's logo/icon in both themes (018 D8). 019b reuses them.

## 1. Approach
Everything fits in the two Python files of the boundary, with no JavaScript and no new dependencies. The rules live
once in `findings.py` and the web calls them: field validation (`validate_field`), writing (`set_fields`), CVSS
(`cvss31`), comments (`comment_*`) and per-type projections (`render_report`). The web adds POST routes with the 016
defenses in their order, forms that re-render on the server (the calculator and the preview submit the form) and cookies
modeled on `/tema`. Comments and drafts live outside the ledger, in
`.gekko-web/`, and never enter `render` (comments) or the evidence (drafts).

## 2. Contracts — 019a

### 2.1 `findings.py`: validation, writing and CVSS
```python
NARRATIVE_FIELDS += ("cvss_vector", "cvss_justification")   # 019a; the chat list (018) does not include them
validate_field(name, value) -> str     # 018; 019a adds cvss_vector (canonical) and cvss_justification (text)
set_row(..., drop=(), check=None)      # drop is from 018; check(row) runs with the lock taken, before update
set_fields(..., allowed=…)             # 018; 019a: if "cvss_vector" is in changes, also writes the derived "cvss"
cvss31(vector) -> (canonico, puntaje, banda)   # raises Refusal("invalid", "cvss_vector …") if the vector is not v3.1 base
cvss_check(changes) -> callable        # the band ≠ severity check without justification
EDIT_FIELDS = frozenset({"summary", "impact", "remediation", "cwe", "cve", "cvss_vector", "cvss_justification"})
```
- **One field rule** (AC10, AC16). 018's `validate_field` plus two names: `cvss_justification` → non-blank text,
  like the drafting ones; `cvss_vector` → the canonical vector from `cvss31`. `_optional_fields` already calls it for
  everything except `--cvss` (018); the numeric `--cvss` keeps its current path (`findings.py:205`). 018's chat passes its
  own `allowed` (`summary`, `impact`, `remediation`), so widening `NARRATIVE_FIELDS` does not open CVSS to it.
- **`set_row(check=…)`.** One line before `r.update(extra)` (`findings.py:283`): `if check: check(r)`. With the lock
  taken and before `_save`, so the rule that looks at the row (severity) has no window. No other change to
  `set_row`; the cases of REQ-LED-003/004/007 (and 018's `drop` cases) run without touching them.
- **CVSS in `set_fields`.** `allowed` never includes `cvss`: the number comes from `cvss31(changes["cvss_vector"])`
  and is written as `float`. `check` = `cvss_check(changes)`: if there is a new vector, its band ≠ the row's `severity` and
  `changes.get("cvss_justification", fila.get("cvss_justification"))` is blank → `Refusal("needs_justification")`.
  `severity` is never written (D5).
- **CLI** (AC16): `_add_optional_flags` (`findings.py:875`) adds `--cvss-vector` and `--cvss-justification` to `add` and
  `set`. `set --cvss-vector V` → `cvss_vector` + derived `cvss`, with `check=cvss_check`; in `add`, the same rule with
  the severity of the new entry. `--cvss X --cvss-vector V` with `X ≠ puntaje(V)` → exits 1 naming `cvss`. `--cvss` alone
  (AC16) is rejected if it contradicts the parseable vector of the row (`cvss_check`); without a vector, or with one that does not
  parse, it passes as today and the page marks it «sin vector» (no vector) or «el puntaje no coincide con el vector» (score does not match the vector) (§2.4); REQ-LED-008
  writes it.
- **`render`** (AC18): `report_fields` (`findings.py:368`) shows `cvss_vector` and `cvss_justification` right after
  `cvss`, with new labels in `LABELS` (`CVSS vector`/`Vector CVSS`, `CVSS justification`/`Justificación CVSS`).
  A row without those keys comes out byte for byte the same as today.

### 2.2 CVSS v3.1 base (FIRST formula, specification v3.1 §7.1 and appendix A)
Weights: **AV** N 0.85 · A 0.62 · L 0.55 · P 0.2 — **AC** L 0.77 · H 0.44 — **PR** N 0.85 · L 0.62 (0.68 if `S:C`) ·
H 0.27 (0.5 if `S:C`) — **UI** N 0.85 · R 0.62 — **C, I, A** H 0.56 · L 0.22 · N 0 — **S** U | C (picks the branch).
```
ISS            = 1 − [(1 − C) × (1 − I) × (1 − A)]
Impacto        = 6.42 × ISS                                         si S:U
               = 7.52 × (ISS − 0.029) − 3.25 × (ISS − 0.02)^15      si S:C
Explotabilidad = 8.22 × AV × AC × PR × UI
Base           = 0                                                  si Impacto ≤ 0
               = Roundup(min(Impacto + Explotabilidad, 10))         si S:U
               = Roundup(min(1.08 × (Impacto + Explotabilidad), 10)) si S:C
```
```python
def roundup(x: float) -> float:          # apéndice A de v3.1: evita que 4.000002 suba a 4.1
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0
```
Band → ledger severity: 0.0 None → `info` · 0.1–3.9 Low → `low` · 4.0–6.9 Medium → `medium` · 7.0–8.9 High →
`high` · 9.0–10.0 Critical → `critical`.

**Accepted vector** (AC14): exact prefix `CVSS:3.1/`, then exactly the eight base metrics separated by `/`,
each once, in any order, with a table value (exact uppercase); it is stored in canonical order
`AV/AC/PR/UI/S/C/I/A`. Rejected: `CVSS:3.0/…`, `CVSS:4.0/…`, no prefix, seven metrics, one repeated, `AV:X`,
`av:n`, temporal (`/E:F`, `/RL:O`, `/RC:C`), environmental (`/CR:H`, `/MAV:N`), empty, spaces, trailing `/`, more than
100 characters.

| Vector (after `CVSS:3.1/`) | Score | Band | Verified |
|---|---|---|---|
| `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | 9.8 | critical | published + formula |
| `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | 10.0 | critical | published + formula |
| `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | 9.9 | critical | published + formula |
| `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 8.8 | high | published + formula |
| `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | 8.1 | high | published + formula |
| `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` | 7.8 | high | published + formula |
| `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | 7.5 | high | published + formula |
| `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | medium | published + formula |
| `AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | 5.4 | medium | published + formula |
| `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | 5.3 | medium | published + formula |
| `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` | 0.0 | info | formula (Impact ≤ 0) |
| `AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N` | 0.0 | info | formula (Impact ≤ 0; AC14 example) |
| `AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N` | — | — | formula only: the case computes it |
| `AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L` | — | — | formula only: the case computes it |

`roundup`: 4.02 → 4.1 · 4.0 → 4.0 · 4.000002 → 4.0 · 4.00001 → 4.1.
**How it was verified (2026-11-17):** the ten «published» ones are commonly used scores (NVD and FIRST examples) that the
wording recalled, and an implementation of the formula above, run in the session's scratchpad (outside the
repo), gave the same ten: two signals. The two 0.0 come from the `Impact ≤ 0` rule. The last two have no reliable
known value: they do **not** go with a fixed number; the case compares them against a second implementation written separately
inside the selftest with `decimal.Decimal` (gave 1.6 and 5.1 with `float`; not settled as data), and the operator
checks them in FIRST's calculator in the real run.

### 2.3 Comments: file, events, folding and the 409 anchor
File `engagements/<ws>/.gekko-web/comentarios.jsonl` (D2 b), one JSON line per event, append-only:
```json
{"v":1,"op":"add","finding":"F-0001","comment":"C-9f2c1a7b3d4e5f60","text":"…","at":"2026-11-17T10:00:00Z","via":"web","prev":""}
{"v":1,"op":"edit","finding":"F-0001","comment":"C-9f2c1a7b3d4e5f60","text":"…","at":"…","via":"cli","prev":"<sha256>"}
{"v":1,"op":"delete","finding":"F-0001","comment":"C-9f2c1a7b3d4e5f60","at":"…","via":"web","prev":"<sha256>"}
```
- `prev` = sha256 of the bytes of the last event line of that comment (without the `\n`); `""` on `add`. The id is
  `C-` + 16 hex from `secrets`. `via` ∈ {`web`, `cli`}; `at` with `_now()`.
- `findings.py`: `comments_path(ledger)` = `ledger.parent / ".gekko-web" / "comentarios.jsonl"`;
  `validate_comment(text) -> str` (non-blank per `_blank`; ≤ 8192 bytes in UTF-8; otherwise `Refusal("invalid")`
  stating the maximum; never truncates); `comment_add(ledger, fid, text, via, comment_id=None)`,
  `comment_edit(ledger, cid, text, via, expect=None)`, `comment_delete(ledger, cid, via, expect=None)`,
  `read_comments(ledger, max_bytes) -> (por_hallazgo, malos)`. The three writes: the helper opens the file
  `O_RDWR | O_APPEND | O_CREAT`; exclusive `flock` on **that** descriptor (the file is never replaced, so the lock holds between the CLI and the module's threads); re-read through the same descriptor with a cap, fold, check,
  `os.write` of the whole line, release. `fid` must appear exactly once in the ledger (lock-free read of the ledger: ids
  are never deleted).
- **Folding** in file order: `add` creates (new id, otherwise a bad event); `edit`/`delete` require a live comment and
  `prev` = hash of its last event; the text goes through `validate_comment`. Visible = live ones, in the order of their `add`,
  with «editado · hora» (edited · time) if it had an `edit`. Deletion = tombstone (D4 a): the text stays in the file.
- **Bad events** (broken JSON, missing field, unknown `op`, broken `prev` chain, final line without `\n`): the
  page shows the valid comments, warns with line numbers and offers no actions; every write exits
  `Refusal("corrupt")` → 409. Same treatment as a bad ledger line (REQ-LED-004).
- **Caps:** 8 KiB per text; 1 MiB per file (`COMMENTS_MAX_BYTES`): if the current size plus the new line
  exceeds it, `Refusal("full")` → 422 stating the maximum.
- **409 anchor** (AC2, AC3): `visto` for edit/delete = the hash of the last event seen of that comment; with the lock
  taken, if it differs → `Refusal("stale")`. For add, the form carries `nuevo` (16 hex created when the page is drawn) and the token binds it: the event uses `C-<nuevo>`; if an `add` with that id already exists, it does not write and responds as success → a double submit writes once without a false 409.
- **CLI** (AC6): `findings.py comment add --ledger L --id F-0001 --text T` · `comment edit --ledger L --comment C-… --text T`
  · `comment delete --ledger L --comment C-…` · `comment list --ledger L [--id F-0001]` (one line per live comment, no controls, `_oneline`). The CLI does not pass `expect` (like `set`).

### 2.4 `findings_web.py`: routes, tokens and forms
| Request | Response |
|---|---|
| `GET /w/<ws>/f/<n>?editar=1` | 200, edit mode; does not write |
| `GET /w/<ws>/f/<n>?comentario=C-…#comentarios` | 200, that comment with its `<textarea>`; does not write |
| `POST /w/<ws>/f/<n>/editar`, `accion=guardar` accepted | 303 to `/w/<ws>/f/<línea por id>?editado=<huella nueva>`; no changes: 303 without writing |
| same, `accion=calcular` | 200, re-render with all texts, score and band; does not write |
| same, invalid field, half-filled metrics, vector and metrics changed at once, band ≠ severity without justification, emptied field | 422 in Spanish naming the field; operator's text kept |
| same, row changed | 409 with «Ahora en el ledger» (Now in the ledger) next to the operator's text |
| `POST /w/<ws>/f/<n>/comentario`, `accion` ∈ {`agregar`, `editar`, `borrar`} | 303 to `…/f/<n>#comentarios`; 409 `stale`/`corrupt`; 422 `invalid`/`full`; 404 comment does not exist |
| either of the two, token absent or false, foreign `Sec-Fetch-Site` | 403 fixed · body > `MAX_BODY`: 413 · broken UTF-8 or no `visto`/`accion`: 400 |
| `GET` to those routes | 404 · other methods: 405 |

- **Order of controls** (that of REQ-RPT-019, `findings_web.py:1060`): Host and user → method and path (the POST list of
  `findings_web.py:1066` gains `/editar` and `/comentario`) → `Sec-Fetch-Site` (`:1070`) → 413 (in the base only for the
  state route, `:1072`; 018 extends it to the chat; it applies to every write route) → UTF-8 and fields → ws, line and (edit/delete) comment exist
  (404, without creating `.gekko-web/`) → **linked workspace (`workspace.is_symlink()`) or `findings.jsonl` not regular per
  `lstat` → 409 without writing** (the mold of `post_state`, `findings_web.py:729–741`; `discover` accepts a link inside
  `engagements/` and `_locked(ledger.parent)` would follow it, so without this step editing in A would write B's
  ledger) → token (403) → `editable_reason` (`:644`, 409) → write. Applies equally to `/editar`, `/comentario` and
  `/reporte/borrador`.
- **Tokens.** `ticket(ctx, kind, *parts)` = HMAC-SHA256(`ctx.secret`, `"\n".join([kind + ":", *parts])`), compared
  with `hmac.compare_digest`. `editar`: (ws, n, visto). `comentario-nuevo`: (ws, n, id, nuevo). `comentario`: (ws, n,
  id, cid, visto). `state_ticket` (`:671`) and `chat_ticket` (018) do not change: they start with the workspace name, which
  never carries `:` (`NAME_RE`, `findings_web.py:28`), so no `ticket` token is valid for one of them (and the type prefix separates the `ticket` ones from each other; a workspace named `editar` does not collide).
- **`/editar` fields** (`application/x-www-form-urlencoded`): `resumen`, `impacto`, `remediacion`, `cwe`, `cve`,
  `av`, `ac`, `pr`, `ui`, `s`, `c`, `i`, `a`, `vector`, `vector_mostrado`, `justificacion`, `accion`, `visto`, `ficha`.
  The server maps them to the keys of `EDIT_FIELDS`; any other field (`status`, `severity`, `title`, `cvss`,
  `id`…) is ignored. `\r\n` → `\n` and nothing else.
- **What changed.** For each text field, the submitted value is compared with `_t(fila[clave])`: equal → not sent;
  key absent and empty value → not sent (never writes `""`); key present and blank value → 422 «‹campo›: el
  ledger no borra campos desde la edición» (the ledger does not delete fields from editing). Only the changed ones go in `changes` to `set_fields(…, expect=visto, allowed=EDIT_FIELDS)`.
- **Vector or metrics** (no JS, AC13): the eight radio buttons are drawn checked according to `vector_mostrado`. If `vector` ≠
  `vector_mostrado`, the typed vector wins; if the radios also differ from `vector_mostrado` → 422 «cambiaste
  métricas y vector a la vez» (you changed metrics and vector at once). Otherwise the radios win: eight → canonical vector; none → no vector; some → 422
  «faltan métricas: …» (metrics missing). Empty vector on a row with a vector → 422 (not deleted). On save, the score is always
  the server's; a `cvss` in the request is ignored.
- **Layout of edit mode** (V3, AC8): the `<form>` wraps only the sections card (`detail-card`,
  `findings_web.py:815`); the three sections remain `:target` destinations (`:374`, `:382–383`), so switching tabs does not reload or lose text (fields in a hidden section are sent anyway). Summary carries `resumen`,
  `impacto`, `remediacion`; Record carries `cwe`, `cve` and the calculator (segmented button groups as in V3,
  vector, score, band, justification); Evidence stays read-only. Save, Calculate and Cancel go in a bar
  stuck to the foot of the card. The right column stays as 018 leaves it: ≥ 1280 px the assistant at 50/50 and 016's
  status form in place; below, stacked. **No nested `<form>`:** in edit mode the Comments section is shown without forms («leave edit mode to comment»).
- **Comments in the detail** (AC1): fourth section `#comentarios` («Comentarios») in `detail-nav`, with its
  `:target` rules. Each comment: escaped text (`white-space:pre-wrap`), creation time, «editado · hora», channel, and
  «Editar» (GET link) and «Borrar» (button in its own `<form>`). Below, «Agregar comentario» (Add comment). Row without a unique id or not
  editable: the existing ones without actions and the reason from `editable_reason`. Fixed note: «Borrar oculta el comentario; el
  texto queda en `.gekko-web/comentarios.jsonl` hasta la retención del engagement» (Delete hides the comment; the text stays in `.gekko-web/comentarios.jsonl` until the engagement's retention).
- **Save notice:** «Edición guardada · `<updated>`» (Edit saved) only if `editado` carries the fingerprint of the current row (mold of
  `saved_notice`, `:703`). A row with `cvss` but no `cvss_vector` shows «sin vector»; one where the two do not match (edited by hand) shows «el puntaje no coincide con el vector».

## 3. Contracts — 019b

### 3.1 `findings.py`: drafts and per-type projections
```python
DRAFT_FIELDS = {"tecnico": ("titulo", "cliente", "periodo", "version", "autor", "clasificacion",
                            "resumen", "alcance", "metodologia", "limitaciones", "recomendaciones"),
                "ejecutivo": (los mismos sin "metodologia")}
ONE_LINE = ("titulo", "cliente", "periodo", "version", "autor", "clasificacion")
validate_draft(tipo, data: bytes) -> dict    # JSON object; keys ⊆ DRAFT_FIELDS[tipo]; str ≤ 4096 B; ONE_LINE without line breaks
render_report(rows, lang, tipo="tecnico", draft=None) -> str   # the only Markdown projection
```
- `validate_draft` raises `Refusal("invalid_draft", …)` naming the field; it never truncates or corrects. A draft with
  no field carrying text counts as «sin borrador» (no draft).
- **Technical** (AC18): without a draft → `render_md(rows, lang)` exactly. With a draft:
  ```
  # `<titulo>`                     ← if there is no title: "# Technical report" / "# Reporte técnico"
  - **Client:** `<cliente>`         ← _code(_oneline) per field present, order cliente, periodo, version, autor, clasificacion
  ## Summary · ## Scope · ## Methodology · ## Limitations     ← present ones, each with its value in a fence (_fence)
  <render_md(rows, lang) byte for byte, from "# Findings">
  ## Recommendations               ← in a fence
  ```
- **Executive** (AC19), no evidence, command, artifact, steps, corroboration, technical summary or remediation:
  ```
  # `<titulo>` | "# Executive report" / "# Reporte ejecutivo"
  - cover as above · ## Summary · ## Scope                (from the draft, in a fence)
  ## Findings by severity
  - **critical:** 1 · **high:** 0 · **medium:** 2 · **low:** 0 · **info:** 0     (figures of included)
  ## Findings
  | ID | Title | Severity | Target |                            (labels per language)
  |---|---|---|---|
  | `F-0001` | `<título>` | `high` | `<objetivo>` |              (_code of each value, `|` → `\|`)
  ### `F-0001` — `<título>`
  - **Severity:** `high`
  - **Impact:** …                                             (_field; omitted if there is no impact)
  ## Limitations · ## Recommendations                         (from the draft, in a fence)
  ```
  No included findings: the `empty` label of `LABELS` instead of the table and cards. Row order: that of `included`.
- **CLI** (AC21): `render --ledger L [--tipo tecnico|ejecutivo] [--borrador F] [--lang L]`; without `--tipo`, as today. The draft
  is read with `_read_regular(F, DRAFT_MAX_BYTES)` (§3.2) and `validate_draft`. Unknown type, invalid draft or `--all`
  together with `--tipo` → exits ≠ 0 without printing a report.

### 3.2 `findings_web.py`: report page, drafts and downloads
- **Page** `GET /w/<ws>/reporte?tipo=tecnico|ejecutivo&idioma=en|es&vista=documento|md` (unknown → default, as today in `report_route`, `findings_web.py:985`). Two equal columns ≥ 1280 px, each with `overflow:auto` and the window height; stacked below. Left: type and language selector, the draft form for that type («Cliente» placeholder = workspace name; never as a value), «Vista previa» (Preview), «Guardar» (Save).
  Right: preview (the same body as the downloadable HTML), downloads and provenance (sha256 of ledger,
  draft, `.md`, `.html`). `@media print` leaves only the preview.
- **Draft** `engagements/<ws>/.gekko-web/borradores/<tipo>.json` via the helper; only the module writes it:
  `flock` lock on the descriptor of the `borradores/` directory (`O_DIRECTORY` variant of the helper, T6), temporary file `O_CREAT | O_EXCL` `0600` via `openat` and `os.replace`
  relative to the same descriptor, never following a link. `POST /w/<ws>/reporte/borrador` with `tipo`, the fields of
  `DRAFT_FIELDS[tipo]`, `accion` ∈ {`guardar`, `previsualizar`}, `visto` = sha256 of the bytes of the draft shown or
  `ninguno` (none), `ficha` = `ticket("borrador", ws, tipo, visto)`. Same defenses and order as §2.4. `previsualizar` → 200
  with what was sent and the preview, without writing; `guardar` → `validate_draft` (422) → current sha256 ≠ `visto` → 409
  with the text kept → writes only fields with text → 303 to `/w/<ws>/reporte?tipo=…&idioma=…`.
  **Reconciled caps:** 11 fields × 4096 B = 45 056 B of text; in `x-www-form-urlencoded` each byte may be `%XX`
  (×3) → ~135 KB, more than `MAX_BODY` (`findings_web.py:33`, 65 536). This route uses `DRAFT_MAX_BODY = 196 608`
  (192 KiB ≥ 3 × 45 056 + names and token); the others keep `MAX_BODY`. `Handler._handle` (`:1168`) chooses the
  `too_long` cap per route (`DRAFT_MAX_BODY` only for `/w/<ws>/reporte/borrador`). The file is written with
  `json.dumps(…, ensure_ascii=False)` and read (web and `render --borrador`) with `DRAFT_MAX_BYTES = 274 432`
  (6 × 45 056 + 4096: the worst JSON escape, `\u00XX` of a control character, is 6 bytes per byte).
- **Downloads** (AC22): `/w/<ws>/reporte.{md,html,pdf}?tipo=&idioma=&ledger=<sha>&borrador=<sha|ninguno>`; without
  `borrador` it is `ninguno` (017's links keep working if there is no draft). If the ledger or the draft
  changed → 409 without a file (mold of `findings_web.py:1042–1044`). `.md` = `render_report`. File name
  (`findings_web.py:1054`): without `tipo` in the request the current one is kept, `<ws>-reporte-<idioma>.<ext>` (017's
  checks, `findings_web.py:2051–2058` and `tools/report-test.sh:52`, do not change); with an explicit `tipo`,
  `<ws>-reporte-<tipo>-<idioma>.<ext>`. The new page's links always carry `tipo`.
- **HTML** `report_html(rows, lang, tipo, draft)` (`:905`): `<header>` with `<span class="logo" role="img"
  aria-label="GEKKO · Offensive Security">` whose background is the kit's **black** horizontal PNG (`horizontal-claro.png`)
  as `data:` inside the `<style>` with hash, with `print-color-adjust:exact` (without it the browser does not print backgrounds);
  cover and draft sections; `report_body` (`:891`) for Technical or `executive_body` for Executive. Internal CSP
  `default-src 'none'; style-src 'sha256-…'; img-src data:`. Fixed `<title>` per type and language. No embedded fonts.
- **PDF** (D9 a, AC22, AC24): `pdf_lines` now returns **segments** (each one starts a page); `pdf_page_count`
  adds `max(1, ⌈lines/55⌉)` per segment, still by arithmetic before splitting (`:928`). First line always
  «GEKKO · Offensive Security» in bold (U+00B7 exists in cp1252). With a cover in the draft: segment 1 = brand,
  title and cover fields; segment 2 = the rest. The draft's prose is split at its line breaks and then at 80
  columns as today (`:937`). Executive table on one line per row: `ID` 10 · `Severidad` 9 · `Título` 36 ·
  `Objetivo` 21, separated by a space (79 columns); a longer value is cut with «…» (the full value appears in that finding's card, below). Values go through the same control-character normalization (`:925`).
- **Bar** (AC25): `POST /barra` with `barra` ∈ {`plegada`, `abierta`} and `volver`: cookie `gekko_barra` (`Path=/;
  SameSite=Strict; HttpOnly; Max-Age=31536000`), 303 to `safe_back` (`:866`); any other value → 303 without `Set-Cookie`.
  `BACK_RE` (`:862`) today does not accept `/w/<ws>/reporte`, and collapsing from the report page would return to the index: it becomes
  `(?:f/[0-9]+|reporte)?` after `/w/<ws>/` (the module's own route, same `valid_name`; also valid for `/tema`). The
  `Sec-Fetch-Site` rule already covers every POST (`:1070`). The `barra-plegada`/`barra-abierta` class on `<html>` comes
  only from a cookie with an exact value (mold of `theme_cookie`, `:872`). Without a cookie (D10 b): open ≥ 1280 px,
  collapsed 960–1279 px, hidden < 960 px as today (`:386`). Collapsed: 70 px, icon, the navigation texts in `.sr`
  (accessible name intact) and a visible initial `aria-hidden`. The button is a form with two buttons
  («Plegar barra» (Collapse bar) / «Desplegar barra» (Expand bar)); the CSS shows the one that applies according to class and width.
- **Brand** (AC26): 018 already changes the «G» of `.brand-mark` (`sidebar`, `:449`; `top-brand`, `:467`) to the icon
  with the `--iso`/`--logo` variables of each theme (plan 018 §2, «Marca» (Brand); empty `<span>`s `aria-hidden`, no `<img>`).
  019b only decides what is seen in the bar: horizontal logo (`--logo`) when open, icon (`--iso`) when collapsed; the accessible name of the link remains the text «GEKKO · REPORTES», in `.sr` when collapsed.
- **Fonts and CSS weight** (D11): Michroma as a WOFF2 subset (U+0020–003A, U+0041–005A, U+00B7, U+00C0–00DD:
  capitals with Spanish accents, digits and punctuation), `@font-face` in the CSS with hash, `OFL-Michroma.txt` next
  to the module; only on fixed module text already in capitals (`.overline`, `.eyebrow`, `.brand-caption`, metric labels), never in ledger values. The CSS goes inside each page: today 56 644 bytes (Space Grotesk in base64:
  33 180). Expected sum: the four kit PNGs (7 212 B → ~9.6 KB in base64; 018 brings them), Michroma (to be measured; expected < 8 KB in base64) and ~6 KB of 019 rules → ~80 KB per page. A case sets the ceiling at 90 000 bytes.

## 4. Affected files
| File | Change | Delivery · AC |
|---|---|---|
| `.claude/tools/findings.py` | `NARRATIVE_FIELDS`/`validate_field` (vector, justification), `set_row(check=)`, `set_fields` (derived cvss), `cvss31`/`roundup`/`cvss_check`, `web_open`/`web_unlink` moved from the module, comments and `cmd_comment`, flags, `report_fields`/`LABELS`; cases | 019a · AC3–AC7, AC10, AC14–AC16, AC18 (vector) |
| same | `DRAFT_FIELDS`, `validate_draft`, `render_report`, `render --tipo --borrador`; cases | 019b · AC18, AC19, AC21, AC23 |
| `.claude/tools/findings_web.py` | `ticket`, Comments section, `post_comment`, edit mode, calculator, `post_edit`, routes in `respond`, 413 for every write, CSS; cases | 019a · AC1–AC13, AC15, AC28, AC29 |
| same | report page per type, `post_draft`, downloads per type, `report_html`/`pdf_*` per type, `post_barra`, brand, Michroma; cases | 019b · AC17, AC19–AC27, AC29 |
| `.claude/tools/OFL-Michroma.txt` | create (font license) | 019b · AC26 |
| `tools/report-test.sh` | HTTP checks 019a (edit, calculate, comment, CLI↔web) and 019b (draft, six downloads, bar); AC28 concurrency; `--cvss-vector` in the prompts | AC2, AC6, AC9, AC21, AC22, AC28 |
| `specs/SECURITY-GUARDRAILS-SPEC.md` | new and rewritten `REQ`s (below) | AC30 |
| `CLAUDE.md`, `AGENTS.md` (twins) | rule reworded to «never guess; a CVSS carries its vector» (D6), module line, merged specs | D6 |
| `.claude/agents/finding-analyzer.md`, `.pi/agents/finding-analyzer.md`, `.claude/agents/exploit-developer.md`, `.pi/agents/exploit-developer.md`, `.codex/agents/{finding-analyzer,exploit-developer}.toml` | a CVSS only with `--cvss-vector` | D6 |
| `.claude/agents/report-writer.md`, `.pi/agents/report-writer.md`, `.codex/agents/report-writer.toml` | `render --tipo` and `--borrador` | AC21 |
| `docs/pi-hitl.md` §4c | proxies: now also edit, comment and save drafts; where they live and their retention | limits §6 |

Unchanged: `.githooks/pre-commit` (it already runs `tools/report-test.sh` when touching `findings.py` or `findings_web.py`,
`.githooks/pre-commit:85–97`; `.githooks/test.sh:99–103` tests it), `.gitignore` (`engagements/` already covers
`.gekko-web/`), `toolbox/gekko-workspace.ts` (`ledgerCliOnly` stays the same: see §6), the panel and the launcher.

**New `REQ`s.** 019a: REQ-LED-008 (CVSS v3.1 base, `set` with vector, justification, coherent `--cvss`), REQ-LED-009
(comments in `findings.py`: events, folding, validation, CLI), REQ-LED-010 (comments do not reach the report or the ledger), REQ-RPT-035 (comments in the
detail), -036 (comment writing: defenses, anchor, double submit, private file), -037 (comments outside
the list, index, `render` and downloads), -038 (edit mode without writing and allowed fields), -039 (save edit via
`set_fields` with the `set` rule), -040 (changed row), -041 (calculator on the server), -042 (019a simultaneous and isolated writes). 019b: REQ-RPT-045 (type and language over `included`), -046 (Technical), -047 (Executive without
evidence), -048 (drafts), -049 (`render --tipo` = web), -050 (downloads bound to ledger and draft), -051
(hostile content in report and draft), -052 (brand in downloads), -053 (collapsible bar), -054 (brand in pages and
CSP without scripts).

**Rewritten `REQ`s** (018 first; 019 reconciles over what it left):
| REQ | 018 | 019a | 019b |
|---|---|---|---|
| RPT-007 | `img-src data:`, brand by CSS, the «G» becomes icon | WHEN adds comments and edit form | bar brand; Michroma |
| RPT-008 | chat via `set_fields`, `.gekko-web/` files, static case | `/editar` via `set_fields`, `/comentario` via `comment_*`; `post_edit` in the static case | `/reporte/borrador` and `/barra` |
| RPT-009 (limit) | a proxy outside loopback also asks and applies | also edits and comments | also saves drafts |
| RPT-011 (limit) | the new-code notice covers the sanitizer | — | — |
| RPT-012 | the environment case adds the canary for the Provider key env var (D1 a) | — | — |
| RPT-014 | — | — | cookie `gekko_barra`, new contrasts |
| RPT-016 | stops saying «MUST NOT add chat» | Comments section and edit mode | — |
| RPT-017 | — | — | second font source (Michroma) |
| RPT-021–024 | 022: WHEN «igual con y sin historia» (same with and without history) | — | type, draft, brand, PDF segments |
| LED-001 | `validate_field`, blank rejected | `cvss_vector`, `cvss_justification` | — |
| LED-002 | — | eight fields (vector and justification) | `render --tipo`, `--borrador` |
| LED-007 | `drop` requires `expect` | `check` under the lock | — |

## 5. Decisions (answers «Para `plan.md`» (For `plan.md`) of the spec §6)
- **Shared validator:** 018's (`validate_field`), extended here with two names; `_optional_fields` and
  `set_fields` call it, and AC10 compares web against CLI on copies. Blank is already invalid in the single rule (018):
  that is why «sólo espacios» (only spaces) gives the same result in web and CLI, and the web never writes `""`.
- **Emptied field** (AC10): 018's D5 limits deleting a key to «Deshacer» (Undo); 019 does not widen it. Emptying
  a field that had a value is 422 without writing (§2.4). If the operator wants to empty from editing, that is another decision
  that goes through 018 D5.
- **CVSS without JS:** radios + vector + `vector_mostrado` decide who wins; «Calcular» is the same form. Two buttons
  «leer vector»/«calcular» (read vector / calculate) are discarded: more branches, same result.
- **Band rule under the lock:** `set_row(check=)` instead of reading the severity outside and trusting `expect`: the CLI
  does not pass `expect`, so both paths apply the rule at the same instant.
- **Comments:** format and anchor of §2.3. Add does not use `visto` but an id chosen when drawing (`nuevo`): a
  fingerprint of the file would give a 409 every time someone else adds to another finding.
- **Sections and order of each type:** §3.1 (md), §3.2 (html, pdf). In the `.md` all draft text goes in a span or a fence,
  as with the ledger: it is operator text, but it may carry target data (§6 of the spec).
- **Cover and table in the 80-column PDF:** §3.2. Cut with «…» only in the summary table; never in the cards.
- **Fonts and weight:** §3.2. JetBrains Mono is still not embedded (D11). The downloadable HTML embeds no fonts.
- **Edit mode next to 018's panel at 50/50:** §2.4. The edit form occupies the sections column; the assistant and the status
  stay in the other one, without nesting.
- **Brand in the HTML download as CSS background** and not `<img>`: it meets the contract (PNG as `data:` in the CSS with hash)
  and still has no `<img` in any response; `print-color-adjust:exact` prints it.

## 6. Risks and mitigation
- **`ledgerCliOnly` and `comment`** (REQ-TBX-005, `toolbox/gekko-workspace.ts`): in toolbox mode only an agent's `bash` whose command names an entry of the scope is blocked, unless it is exactly `findings.py add|set|list|render`;
  `comment` is not in that list, so `findings.py comment …` naming a host of the scope is blocked and one that does not
  name it passes. Operator's decision: it stays this way (comments are their notes); widening it loosens the boundary and
  would go through its own flow. It remains as a limit of REQ-LED-010.
- **Toolbox as root against the operator's module:** without more, a file created by the module would be rejected by the container's CLI
  (owner ≠ 0) and one created by the container's CLI (root, `0600`) would not be read by the module. Mitigation
  in §0: accepted owner ∈ {euid, workspace owner} and `fchown` to the workspace owner when root creates. If the
  `fchown` fails (e.g. remapped userns), the helper does not write and the page says «no se pudieron leer los
  comentarios» (comments could not be read) without a 500 (case). T26 tests both directions; if either fails, the change goes through the long flow and remains
  as a limit of REQ-LED-009.
- **Invalid blank (018) breaks an agent call with `--impact ""`.** T3 searches prompts and KB for calls with
  empty values; the message says what to do (omit the option).
- **`set_row(check=)` changes a boundary function** → the cases of REQ-LED-003/004/007 run without touching them before and
  after; they are the first falsifier.
- **The CVSS formula gets an edge case wrong** → table of 12 vectors with two signals, `roundup` with its four
  floating-point cases and a reference implementation with `Decimal` in the selftest; the operator checks two vectors
  in FIRST's calculator.
- **An old justification stays on the row** when the band matches again (it is not deleted): the page and the report
  show it. Limit written in REQ-LED-008.
- **Markdown table with hostile `|`:** it is escaped as `\|` inside the span; GFM shows `|`, a CommonMark viewer without
  tables shows the backslash. The case counts four cells per row with GFM's rule.
- **Weight of each page** (~80 KB) → ceiling of 90 000 bytes in a case; the log notes the real number.
- **Michroma is not in the repo or on the host** → T28 asks the operator for it (Google Fonts, OFL) with its sha256; the subset is made with `pyftsubset` (fonttools 4.63 and brotli present, checked 2026-11-17).
- **Tokens after «Buscar actualizaciones» (Check for updates):** they are invalidated (limit of REQ-RPT-019); the browser keeps the text when going back. Same for drafts and comments.
- **A draft or comment with the client's real name** stays gitignored under `engagements/` and in retention;
  the download leaves the workspace (limit of 017). `docs/pi-hitl.md` §4c says so.

## 7. Order of attack
1. **Falsifiers without code:** F1 (018 is there and meets the contract), F2 (baseline of L, V, W, S), F3 (what the
   helper and `validate_field` are missing), F4 (sockets and node in the agent's sandbox).
2. 019a, ledger: CVSS in red and then green (pure function, the cheapest falsifier); `validate_field` and `set_row(check=)`
   with the old cases intact; comments and their CLI.
3. 019a, module: edit mode and `post_edit` with the web-vs-CLI table in red first; calculator; static case;
   comments in the detail and `post_comment`; hostile, isolation; HTTP and concurrency in `tools/report-test.sh`.
4. 019a: living spec, docs, prompts, CLAUDE.md/AGENTS.md; gates together; `code-auditor`; real run; commit.
5. 019b: `render_report` and `validate_draft` in red and then green; drafts; page; downloads; HTML; PDF; hostile;
   bar; brand and Michroma; AC27 sweep; HTTP; isolation.
6. 019b: living spec, docs; gates together; `code-auditor`; real run; commit; `Status` → `IMPLEMENTADA`.

## 8. Review
External review of 2026-11-17 (10 findings, all accepted after reading the code):
- Existing cases that change, named by task: T14 (REQ-RPT-008), T34 (REQ-RPT-023), T35 (REQ-RPT-024), T38
  (REQ-RPT-017); the REQ text is reconciled in T22/T42.
- Download name: without `tipo`, that of 017 (§3.2, «Descargas» (Downloads)).
- Owner of the `.gekko-web/` files with the toolbox as root (§0, §6); T26 tests both directions.
- Step «linked workspace or non-regular ledger → 409» in the order of §2.4, with a case in T16, T19 and T32.
- `--cvss` alone stays as today (AC16); the plan no longer rejects it over a row with a vector (§2.1).
- Draft caps reconciled with the body and the JSON escape (§3.2, «Borrador» (Draft)).
- `BACK_RE` accepts `/w/<ws>/reporte` (§3.2, «Barra» (Bar)).
- Tasks: T20 without «rojo primero» (red first), complete AC map, F2 reference as a literal in `cmd_selftest`.

> Amendment 2026-11-17: the references to `pdf_lines`/`pdf_*`, `.pdf` and the 80-column PDF (§3.2, downloads, REQ table) are replaced by the browser print view `.imprimir` (REQ-RPT-024).
