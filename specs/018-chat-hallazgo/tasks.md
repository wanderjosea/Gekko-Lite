# Tasks 018 — Finding chat: ask the model and apply what it drafts

> Status: `IMPLEMENTADA` (operator, 2026-11-17: closed; real runs done by the operator; final regression in `66a7506`: guard 190/2245, L, WS, sanitizer, report-test 84/0, hooks 48, ws-test 184/0, tui-test 55/0 and toolbox-test with Docker green) · earlier — operator 2026-11-17, without an intermediate gate (external review before coding).
> Spec: [`spec.md`](spec.md) (`APROBADA`, 2026-11-17, 23 AC) · Plan: [`plan.md`](plan.md) (`APROBADO`, 2026-11-17)
> Each task closes ≥1 criterion and names its test. The checkbox is marked ONLY with the test green and its row in the record.

**Tests:** **L** = `python3 .claude/tools/findings.py selftest` · **Z** = `python3 .claude/tools/sanitize_target_content.py --selftest` ·
**V** = `python3 .claude/tools/findings_web.py selftest` · **W** = `bash tools/report-test.sh` (runs L, Z and V + checks over
HTTP against the real module) · **S** = `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`
(gate and `REQ ↔ case` trace) · **K** = `bash .githooks/test.sh` · **P** = `bash tools/ws-test.sh` · **U** = `bash tools/tui-test.sh`

**Who:** the code, its tests, the living spec and the docs are written by **a Sonnet 5.5 agent** in this worktree
(the `report-module` worktree, branch `report-module`), task by task and in this order. The tasks
marked **`[operador]`** (operator) it skips: they are done by the main session or the operator.

**Rules for the agent:** do not commit or push · do not read or write in real `engagements/` nor in the repo's
`.gekko-state/` (the tests use temporary roots with fictitious data and a canary key) · no test talks to the real Provider nor to network outside `127.0.0.1` · do not use port 4355 (own free port) · stop only processes whose command line names the temporary root · touch only the files in the table of plan §3 ·
each task with new logic starts with the case that fails and records its red in the record before the fix ·
the new cases use `ok("REQ-…", …)` with the ids of plan §3.

> Until T30 the gate **S** stays red due to unknown ids (REQ-RPT-025…034). That is the expected red; L, Z, V and W must
> be green when closing each task. So an existing case that the new code breaks is adjusted **in the same task** that breaks it (T9: REQ-RPT-011 because of the import; T15: REQ-RPT-016 because of "Asistente"), not at the end.

## Wave 0 — Falsifiers (before changing code)
- [x] **F1** — baseline: L, Z, V, W, S and K green; note how many lines `ok REQ-LED-001`, `-003`, `-004`,
  `-007`, `ok REQ-RPT-007`, `-008`, `-012`, `-016` come out today · no AC · test: record
- [x] **F2** — the environment allows the gate: `python3 -c` that binds `127.0.0.1:0`, `command -v node curl git`,
  `git check-ignore -q engagements/x/.gekko-web/chat/a.jsonl` exits 0 · no AC · test: record

## Wave 1 — Shared rule and write (`.claude/tools/findings.py`)
- [x] **T1** — new cases in `cmd_selftest`, in red: `validate_field` accepts text with visible characters and
  `CWE-89`/`CVE-2024-12345`; rejects with `Refusal.kind == "invalid"` and a message that names the field: `""`, `"   "`,
  `"​"`, `cwe-79`, `CVE-24-1`, and the names `cvss`, `status`, `id`, `corroboration`, `x`; `add`/`set --summary ""`
  exit 1 without changing the sha256 of the ledger (`REQ-LED-001`) · test: L (red recorded)
- [x] **T2** — `NARRATIVE_FIELDS` and `validate_field` (plan §2); `_optional_fields` (`findings.py:199-220`) calls it
  for the five and keeps `cvss`. The existing cases of REQ-LED-001/003/004 run **without touching them** · closes
  `AC10` (part), `AC14` (part) · test: L
- [x] **T3** — in red: `set_row(..., drop=("summary",), expect=<fingerprint>)` deletes the key and nothing else; `drop` without
  `expect` → `invalid` without writing (`REQ-LED-007`); `set_row(..., drop=("status",), expect=<fingerprint>)` and
  `drop=("corroboration",)` → `invalid`, sha256 equal (`REQ-LED-007`); `set_fields` with a key outside `allowed`, with `status`
  even if it is in `allowed`, with a value that does not validate → `invalid`, sha256 equal; `None` deletes; non-existent line →
  `not_unique`; after an `add` that does not move the row and another `set` that does change it → `stale`; a linked ledger with
  `max_bytes` → `not_regular` (`REQ-RPT-032`) · test: L (red recorded)
- [x] **T4** — `set_row(drop=)` and `set_fields(ledger, line, changes, expect, max_bytes, *, allowed) -> dict` as in
  plan §2 (no own lock; `set_row` takes it) · closes `AC13` (part), `AC15` (part) · test: L

## Wave 2 — Sanitiser counter (`.claude/tools/sanitize_target_content.py`)
- [x] **T5** — cases in `_selftest`, red first: `sanitize_counted` returns the same string as `sanitize` for
  all the existing vectors and a count equal to the number of substitutions (`<system>x</system>` → 2; clean text → 0);
  `wrap_counted("x </TARGET-CONTENT> y")` counts 1 and its text is `wrap(...)`. Then both functions
  with `subn`; `sanitize`/`wrap` delegate · closes `AC4` (part) · test: Z, L

## Wave 3 — Module (`.claude/tools/findings_web.py`), in this order: a single file
- [x] **T6** — test infrastructure, without product code: inside `cmd_selftest`, a fake Provider
  (`http.server` on `127.0.0.1:<free>`, own thread) that stores each connection, headers and body, and responds by mode: `normal` (SSE with the requested text), `401`, `500`, `302` towards a **second** fake server that counts
  connections, `json-malo` (bad JSON), `vacio` (empty), `enorme` (huge), `gota` (one byte every 0.3 s), `colgado` (headers and nothing else); a helper that writes a temporary `<raíz>/.gekko-state/env` with `GEKKO_LLM_URL=http://127.0.0.1:<p>/v1` and
  `GEKKO_PROVIDER_KEY=CANARY-KEY-<uuid>`. Red case of `AC5`: with the Provider configured, all the GET routes
  (those of the list at `findings_web.py:2226` + `/w/ws/f/1?salida=1`, `/w/ws/f/1/chat`, the three actions), `POST
  /tema`, `/actualizar` and `/estado` → the fake Provider records **zero** connections and `socket.create_connection` (wrapped) zero calls (`REQ-RPT-028`) · test: V (red recorded if the case already fails; if not, green and noted)
- [x] **T7** — `web_open`/`web_unlink` (in `findings.py`, cases in L), `read_history`, `append_event` (plan §2, "Historia"). Cases first: the file is born `0600` and its directories `0700` with umask `022`; a link planted in `.gekko-web`, in `chat/` or in
  the file → not followed (the target keeps its bytes); a FIFO in its place does not block (< 2 s); two ids in two
  workspaces give different files; emptying deletes a link as a link · closes `AC18` (part) · test: V
- [x] **T8** — `provider_config` and `PinnedConnection`/`resolve_host` without calling them from routes yet. Cases first:
  `env` absent, link, FIFO, > 16 KiB, line with `$(…)` or `` ` `` (ignored; never executed: a marker file does not
  appear), no URL, no key, key with a space or a newline → reason without the key; URL `ftp://`, with user, with
  query; literal IP `8.8.8.8`, `[::1]`, `10.0.0.5`, `100.64.0.1`, `172.32.0.1`; a name whose `resolve_host`
  (substituted) returns `203.0.113.5` → rejected without any call to `create_connection` · closes `AC5` (part)
  · test: V
- [x] **T9** — `chat_context` + `CHAT_SYSTEM` + `parse_proposals` (pure). Cases first: a row with all the
  D10 fields plus canaries in `evidence.output`, in another row, in another workspace, in `scope.txt` and in the artifact
  file (it exists on disk) → only the fields of the list, in their order, the artifact path without its content,
  no workspace name; with `salida=1` the output appears and nothing else; a `<system>` and an `ignore previous
  instructions` in the summary come out as `[STRIPPED-…]`; a `</TARGET-CONTENT>` and the six variants of REQ-FW-002 in the title → a single closing; the count is the sum of the two functions of T5; the question is after the closing; U+202E, U+200B, `\x85` and U+FEFF in a value and in a previous turn come out as U+FFFD in the context (the substitution of `esc`). This task brings the first `import` of the sanitiser, so in it: `CODE_FILES`
  (`findings_web.py:26`) adds `sanitize_target_content.py`, the `expected` of the REQ-RPT-011 case (`:2633`) is
  computed with `code_hash` over the files of the copy instead of adding two by hand (the copy of `:2611` already walks `CODE_FILES`), and `tools/toolbox-test.sh:38` also copies the sanitiser · closes `AC3` (part), `AC4` (part) ·
  test: V, `bash -n tools/toolbox-test.sh`
- [x] **T10** — `ask_provider` (plan §2: resolution, connection by IP, `Authorization`, SSE, caps, watcher) against the fake Provider, without a route yet. Cases first: `normal` → text; body received with `model ==
  "qwen3.8-flash-next"` (the fixed `CHAT_MODEL`), `stream` true and the two messages; `401` → category "clave"; `500`, `302` (the second server: zero connections), `json-malo`, `vacio` → their category; `enorme` (with `CHAT_MAX_ANSWER` and `CHAT_MAX_RAW` lowered) → "demasiado grande"; `gota` and `colgado` with `CHAT_IDLE_S=1`, `CHAT_TOTAL_S=2` → "tiempo agotado" in
  < 3 s; `client_gone` that becomes true at 0.5 s → the Provider sees the connection closed within 2 s and returns what was
  received with state `detenido`; no exception leaves the function · closes `AC5` (part), `AC6` (part),
  `AC21` (part) · test: V
- [x] **T11** — route `…/chat` (ask) in `respond` and `post_chat`, `chat_ticket`, `Ctx.chat_busy`/`chat_lock`/
  `client_gone`/`stopping`/`chat_message`/`chat_question`; `Handler._handle` sets `client_gone`; `cmd_serve` sets
  `stopping`. Cases first, all without writing and with the fake Provider at **zero** connections: `Sec-Fetch-Site`
  `cross-site`/`same-site`/`none` → 403; token absent, false, from `/estado`, from another finding, from another workspace →
  403; foreign `Host` or `peer_ok=False` → fixed 403; body `MAX_BODY + 1` → 413; not UTF-8, no `pregunta`, empty question or > 8000 → 400; non-existent ws or line → 404; row without unique id, broken ledger, linked workspace → 409;
  GET to the route (also with the question in the query) → 404; PUT/DELETE/PATCH/HEAD/OPTIONS → 405. Valid →
  one connection, 303 to `…#asistente`, and a turn in the history. Request with `messages`, `system`, `findingId`,
  `summary`, `model`, `contexto` → the Provider receives the same as without them · closes `AC3`, `AC12` (ask)
  · test: V
- [x] **T12** — one question at a time and cut by the real server: cases first with `make_server` in a thread: with
  `gota` in progress, another question (another finding and another workspace) → 409 "hay una pregunta en curso" without a new connection to the Provider, and `GET /` responds in < 2 s (`AC6`); a client that sends the question and closes the socket at
  0.5 s → the Provider sees the close within 2 s and the history saves a `detenido` turn without proposals; emptying with a question in progress → 409; `ctx.restart` set with a hanging question → the thread ends within 2 s · closes `AC6`,
  `AC21` · test: V
- [x] **T13** — key: cases first with the canary: it appears only in the `Authorization: Bearer` header the Provider
  receives; it is in no body nor response header of the module (success, each error of T10,
  403/404/409/413), nor in the history, nor in the ledger, nor in `/proc/<pid>/environ` of the module; with `401` the page
  says "el Provider rechazó la clave" and does not repeat it; a real module launched with `serve` and stderr to a file, after
  a question with an invalid key (with a newline) and another with `401`: the canary is not in that file. The case
  of REQ-RPT-012 (`findings_web.py:2697`) adds `GEKKO_PROVIDER_KEY=CANARY` to the environment of `ensure` · closes `AC7` ·
  test: V
- [x] **T14** — failures: for each row of the table in plan §2 (no env, URL outside D3, connection refused —closed port—, `401`, `500`, `302`, `json-malo`, `vacio`, `enorme`, `colgado`): code from the table, notice in Spanish, "no se escribió nada en el ledger", sha256 of the ledger equal, the question (with a `HOSTILE` value) escaped in the `<textarea>`, no new turn in the history; the next question does not carry the error text in the context · closes `AC20` · test: V
- [x] **T15** — answer and proposals in the panel. Cases first: an answer with `<script>`, `onerror=`,
  `javascript:`, `[x](https://e.example)`, `![i](https://e.example/a.png)`, ESC, U+202E → the page meets the controls of REQ-RPT-007 (`findings_web.py:2195-2210`) and carries no new `<a` nor `<img`; proposal blocks for `summary`, `impact`, `remediation` → "Propuesta para ‹campo›" with "Aplicar" (or "Sustituir" + "Ahora en el ledger" if the field has text); for `status`, `corroboration`, `blocker`, `evidence`, `severity`, `id`,
  `cvss`, `cwe`, an unknown field, an empty value or only U+200B, a marker mid-line → text without a button;
  an answer that says "ya lo apliqué" and proposes the three fields → sha256 of the ledger equal after the question and
  after reloading. If the panel already paints "Asistente", in this task the case of REQ-RPT-016
  (`findings_web.py:1986-1988`) is adjusted: it stops requiring "sin Asistente"; it requires that it be this spec's and without `<script`), red recorded
  before; if any earlier task already paints it, it is adjusted there · closes `AC9`, `AC10`, `AC11` · test: V
- [x] **T16** — apply (`…/chat/aplicar`). Cases first: the defences of T11 applied to this route (token bound to the proposal id: a token of another proposal → 403); POST with `valor`, a different `campo`, `status=confirmed`,
  `summary=x` → the saved proposal is written and nothing else; accepted → only that field and `updated` change, the
  other rows byte for byte equal, 303; row changed since it was shown → 409, without writing, the proposal keeps
  its button; the same POST twice → one write; non-existent proposal → 404; proposal planted by hand in
  the history with an empty value → 422 without writing · closes `AC12` (apply), `AC13` · test: V
- [x] **T17** — web/CLI parity: for each field of `CHAT_FIELDS` and values (one line, multiline, `HOSTILE`,
  invisibles, empty, only spaces, only U+200B), apply through the web (proposal written in the history) and
  `findings.py set --<campo> <valor>` as a subprocess over copies of the same ledger → both refuse, or the rows are
  equal except `updated` (`REQ-RPT-032`) · closes `AC14` · test: V
- [x] **T18** — undo (`…/chat/deshacer`). Cases first: the defences of T11 applied to this route (also the apply
  token of the same proposal used in undo → 403); undo after apply on a field that had text → the text comes back; on one that did not exist → the key disappears (D5 a); the row changed since the apply (a `set` of another field) → 409 without writing; second submission → 409, a single write; undo of a proposal not applied → 409; a row with `summary` `""`, `"   "`, `7` or `["a"]` (written by hand) → the proposal warns "no habrá Deshacer" (there will be no Undo), apply works, after applying there is no "Deshacer" button and a POST to undo → 409 without writing
  (plan §2, "Deshacer") · closes `AC12` (undo), `AC15` · test: V
- [x] **T19** — mark "vía chat · hora". Cases first: after applying, the field's section carries the mark with the event's time; after undoing, or after `findings.py set --<campo>` from the CLI, it disappears; `render_md` and the three downloads (`reporte.md`, `.html`, `.pdf`) are byte for byte equal with and without history (file deleted) · closes
  `AC16` · test: V
- [x] **T20** — concurrency: with `make_server` in a thread, 10 applies on different rows (each with its proposal in the history) launched at the same time as 10 `findings.py add` → 10 changes, 10 new rows,
  `findings.py list` exits 0; three rounds · closes `AC17` · test: V
- [x] **T21** — history: cap and emptying. Cases first: a history survives a new `Ctx` (restart); another
  row or another workspace do not see foreign turns; the index, the list and the report do not open the file (wrapper of
  `web_open` that counts calls: zero); a row without id or with a repeated id has no panel; with `HISTORY_MAX` lowered,
  a question that does not fit → 409 "vacía la historia" without contacting the Provider and without touching the file; emptying
  (valid token) deletes the file and no GET shows its text again; the defences of T11 applied to emptying
  (also the undo token used in emptying → 403), each with the file intact; an invalid line in the
  history → the panel says so and does not allow asking nor applying. Extension of the sweep of T6 (`REQ-RPT-028`): with
  `socket.create_connection` and `socket.socket.connect` wrapped, an apply, an undo and an empty **accepted** (303) → zero calls and zero connections to the fake Provider · closes `AC5` (part), `AC12` (emptying), `AC18`, `AC19`
  · test: V
- [x] **T22** — full panel (`chat_panel`) and layout. Cases first: editable row with Provider → header
  with `host:puerto` and the model (without `http://`, without the key), the exact list of fields, `≈N tokens`, switch off with link to `?salida=1#asistente`, the number of neutralised patterns equal to that of T9, the four shortcuts,
  the composer and the note about "Detener"; the folded `<pre>`, after `html.unescape`, equals the `system` + prefix that
  the Provider receives when asking, with the switch off and on, also over a row whose title,
  summary and output carry U+202E, U+200B and `\x85` and with a previous turn that carries them; no env or non-editable row → the reason and no `<form` with action `…/chat`; layout (plan §2, "Panel"): with panel, `detail-layout
  con-asistente` contains `.detail-main` (with `.detail-card` and then `aside.detail-side` with "Estado del hallazgo"
  and the 016 form) followed by `#asistente`; without panel (row without unique id) the `.detail-layout` markup is today's; CSS with `.detail-layout.con-asistente` at `minmax(0,1fr) minmax(0,1fr)` and `#asistente:target` below
  1280 px; "Asistente" link in the detail · closes `AC1`, `AC2` · test: V
- [x] **T23** — brand and CSP. Cases first: the four base64 constants have the sha256 of the files in
  `.claude/tools/brand/` and each is ≤ 8 KB; the served CSS uses the `oscuro` variant in the dark block and `claro` in
  the light one (also with each theme cookie); in no page does `re.search(r'class="brand-mark"[^>]*>\s*G\s*<',
  body)` match (today's markup is `<span class="brand-mark" aria-hidden="true">G</span>`, `:449`, `:467`), nor
  `<img`; the only `<svg` remains the gear; the CSP is exactly today's plus `img-src data:`, without `script`,
  `connect-src` nor the Provider's origin; the contrast of REQ-RPT-014 stays ≥ 4.5:1 · closes `AC8`, `AC22` (gate) ·
  test: V
- [x] **T24** — static writer test: in the module, `set_row` is only called inside `post_state` and
  `set_fields` only inside `post_chat` (apply/undo branches; 019a adds `post_edit`); no call to `_save`, `_locked`, `cmd_add`,
  `cmd_set` (the case at `findings_web.py:1615-1637` is extended, tested against synthetic fragments); outside
  `cmd_selftest`, `create_connection`, `getaddrinfo`, `ssl` and `HTTPSConnection` only appear in
  `resolve_host`/`PinnedConnection`/`ask_provider`, and `HTTPConnection` also only in `probe` (`:1241`, loopback
  of `ensure`) and `http_request` (`:1327`, helper of the selftest); the dynamic case of T6 (`:2156` already wraps
  `create_connection` this way) is the one that tests the behaviour; the docstring says what it writes and that it asks the
  Provider · closes `AC5` (part), `AC13` (part) · test: V
- [x] **T25** — existing cases that 018 changes and that were not already adjusted (REQ-RPT-011 because of the import goes in T9 and
  REQ-RPT-016 in T15): REQ-RPT-007 (the case at `:2202` adds the exact `img-src data:` to the CSP); REQ-RPT-011 (with a hanging question the restart stays within ≤ 5 s); review that T9 and T15 left their reds in the record · closes
  `AC8` (part), `AC23` (part) · test: V

## Wave 4 — Real process and hooks
- [x] **T26** — `tools/report-test.sh`, red first: `check` of the sanitiser's selftest (Z); a fake Provider in the background (a Python script written in `$W`, not in the repo) and `$W/root/.gekko-state/env` with the canary key;
  with `curl`: detail → `visto`/`ficha` → ask (303) → the proposal appears → apply (303, the field changed in the ledger) → undo (303, field restored); false token → 403; GET to the action → 404; the canary is not in any `curl` output (bodies and headers) nor in `$W/serve.err`; `git -C "$REPO" check-ignore -q
  engagements/demo-ws/.gekko-web/chat/x.jsonl` · closes `AC7`, `AC12`, `AC13`, `AC15`, `AC18` (real process) ·
  test: W
- [x] **T27** — `.githooks/pre-commit` (`:85-97`): the trigger of `tools/report-test.sh` includes
  `.claude/tools/sanitize_target_content.py`; `.githooks/test.sh` adds `pc_rt "saneador + spec, stub falla blocked"
  block 1 yes .claude/tools/sanitize_target_content.py "$S"` in red first · closes `AC23` (part) · test: K

## Wave 5 — Reconciliation, docs and regression
- [x] **T28** — version `.claude/tools/brand/` (4 PNG + `README.txt` with the origin) without changing them: the agent only confirms that `git status` lists them and that T23 reads them · closes `AC22` (part) · test: V
- [x] **T29** — `docs/pi-hitl.md` §4c: the detail asks the Provider configured in `.gekko-state/env` (default profile,
  fixed model), what data goes out and that the evidence output is off by default, how to apply/undo, where the history lives and that it falls under the engagement's retention, "Detener" = Esc, `GEKKO_CRED_ENV` does not apply to the module; the proxy notice adds "preguntar y aplicar" (ask and apply). `CLAUDE.md` and `AGENTS.md` (twins, same change in both): the "Report module" line and the merged-specs list add 018 · no AC · test: review
- [x] **T30** — living spec `specs/SECURITY-GUARDRAILS-SPEC.md`, in the same change as the code: REQ-RPT-025…034
  new with MUST, WHEN/THEN, "Código:" (Code) with functions that exist and "Límite:" (Limit) (those of plan §5); rewritten
  REQ-RPT-007, -008, -012, -016, -022, REQ-LED-001 and REQ-LED-007; limits of REQ-RPT-009 and REQ-RPT-011; §3.15 says that
  the module opens an outbound connection only when asking. Each new `ok("REQ-…")` has its heading · closes
  `AC23` (part) · test: S (trace without failures)
- [x] **T31** — regression: L, Z, V, W, S, K, P and U green at the same time after the last change; review of AC1–AC23 one by
  one against the record; `Estado` of spec/plan/tasks remains `APROBADO` (T34 changes it); `bash -n
  tools/toolbox-test.sh` (the run with Docker is done by the operator in T33) · closes `AC23` · test: the eight commands +
  `bash -n`

## Wave 6 — Operator
- [x] **T32** `[operador]` — independent security review of the diff (read-only: `code-auditor` or
  `/codex:review`), focused on network output, the key, `set_fields` and the files of `.gekko-web/`; each finding is
  fixed with a case first or noted as a limit in the living spec · test: its report + L, Z, V, W, S green afterwards
- [x] **T33** `[operador]` — real run (§7 of the spec) with `tools/pi-hitl.sh` and the real Provider on a
  test workspace with synthetic data: ask, apply and undo a remediation; a row with injection in the summary (see the counter and the answer); Provider off; invalid key; a question while the agent uses the model
  (time and whether it evicts); Esc during a question (does Firefox cut the POST?); screenshots in both themes at
  1500 and 760 px (no lab data in the repo); `bash tools/toolbox-test.sh` with Docker (the copied module
  starts with the sanitiser) · closes §7 · test: screenshots + record
- [x] **T34** `[operador]` — commit in `report-module` (the `pre-commit` runs gitleaks, `report-test.sh` and the living-spec
  rule); `Estado` of spec, plan and tasks → `IMPLEMENTADA`; tell 019a what it reconciles on top · test: real commit + L, Z, V, W, S, K green

## AC → tasks map
| AC | Tasks | AC | Tasks |
|---|---|---|---|
| AC1 | T22 | AC13 | T4, T16, T24, T26 |
| AC2 | T22 | AC14 | T2, T17 |
| AC3 | T9, T11 | AC15 | T4, T18, T26 |
| AC4 | T5, T9 | AC16 | T19 |
| AC5 | T6, T8, T10, T21, T24 | AC17 | T20 |
| AC6 | T10, T12 | AC18 | T7, T21, T26 |
| AC7 | T13, T26 | AC19 | T21 |
| AC8 | T23, T25 | AC20 | T14 |
| AC9 | T15 | AC21 | T10, T12 |
| AC10 | T2, T15 | AC22 | T23, T28, T33 |
| AC11 | T15 | AC23 | T9, T15, T25, T27, T30, T31 |
| AC12 | T11, T16, T18, T21, T26 | | |

## Open questions
1. Does Firefox close the socket when Esc is pressed with a POST pending? If not, "Detener" reduces to `CHAT_TOTAL_S` (T33).
2. Does `qwen3.8-flash-next` respect the `[[PROPUESTA campo]]` format with the system prompt in English and the answer in
   Spanish? T33 measures it; if not, `CHAT_SYSTEM` is adjusted (outside the boundary: the parser does not change).

## Verification record
| Task | Command | Result | Date |
|---|---|---|---|
| F1/F2 | baseline before changing code: guard, `findings.py selftest`, `findings_web.py selftest`, `report-test.sh`, `.githooks/test.sh`, `ws-test.sh`, `tui-test.sh` | GREEN (hooks 46, report 47, ws 184, tui 55) | 2026-11-17 |
| T1–T4 | `python3 .claude/tools/findings.py selftest` (cases `validate_field`, `set_row(drop=)`, `set_fields`, `web_open`/`web_unlink`; red obtained by running the new cases against a copy of HEAD) | GREEN, 78 `ok` lines | 2026-11-17 |
| T5 | `python3 .claude/tools/sanitize_target_content.py --selftest` (`sanitize_counted`/`wrap_counted`; red against HEAD) | GREEN | 2026-11-17 |
| T6–T22 | `python3 .claude/tools/findings_web.py selftest`: `SelftestProvider` and `selftest_chat` (REQ-RPT-025…034). Honest note: in the web tasks the code was written before the cases; the red was exercised with mutations (token without action, extended fields, all addresses allowed, no sanitiser, open validation), all killed by a case | GREEN, 225 `ok` lines | 2026-11-17 |
| T23–T25 | same selftest: brand/CSP (`img-src data:`, PNG = files of `brand/`), AST of writers and connections, REQ-RPT-007/008/011/012/016 adjusted | GREEN | 2026-11-17 |
| T26 | `bash tools/report-test.sh` (fake Provider in the background: ask 303, proposal, apply 303, undo 303, false token 403, GET 404, canary absent, 0600 + `check-ignore`) | GREEN, 55 passed, 0 failed | 2026-11-17 |
| T27 | `bash .githooks/test.sh` (new `pc_rt` of the sanitiser; red 46 passed 2 failed before the change in `pre-commit`) · `bash -n tools/toolbox-test.sh` | GREEN, ALL GREEN 48 checks · syntax ok | 2026-11-17 |
| T28 | `git status` does not list `.claude/tools/brand/` (already versioned in 73f7440); T23 reads it | GREEN | 2026-11-17 |
| T29 | `docs/pi-hitl.md` §4c, `CLAUDE.md` and `AGENTS.md` | done | 2026-11-17 |
| T30 | `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` | GREEN, `REQ trace: 169 requirements, 2054 cases` (previous red: ids RPT-025…034 unknown) | 2026-11-17 |
| T31 | guard · findings · findings_web · report-test 55 · hooks 48 · ws-test 184 · tui-test 55 | GREEN all | 2026-11-17 |
| T32-fix 1 | `findings_web.py selftest` case "a 1 MB hostile row…" (REQ-RPT-027); red: `sanitize_counted("<system "*32768)` 5.92 s, `"Contents of /"*20000` 17.4 s (the full selftest did not finish in 180 s) | GREEN: detail 0.22 s and question 0.10 s with 1 MB; sanitiser 0.04–0.14 s; "valores recortados" announced; sanitiser selftest green (with new time case) | 2026-11-17 |
| T32-fix 2 | case "a state ticket is refused by the chat and a chat ticket … by /estado" (REQ-RPT-032); red: AssertionError before the change | GREEN: `estado`/`chat` domains in both tickets, 403 in both directions | 2026-11-17 |
| T32-fix 3 | `findings.py selftest` case `O_NOCTTY` (REQ-LED-007, `os.open` recorded); red: AssertionError before the change | GREEN, 79 `ok` lines | 2026-11-17 |
| T32-fix 4 | text of REQ-RPT-026 aligned with the code's order; test row with `cvss` and `cve` | GREEN: the order `repro, cvss, cwe, cve, kb` is checked | 2026-11-17 |
| T32-fix 5 | REQ-RPT-030 without the empty `environ` check; REQ-RPT-007 against the served header; REQ-RPT-034 `.gitignore` with `skip` line if there is no git | GREEN | 2026-11-17 |
| T32-gates | guard `169 requirements, 2058 cases` · findings 79 ok · web 228 ok · report-test 55 passed · hooks ALL GREEN 48 · ws-test 184 passed · tui-test 55 passed | GREEN | 2026-11-17 |
