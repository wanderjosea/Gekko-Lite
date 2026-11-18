# Tasks 016 — Change a finding's state from the web

> Status: `IMPLEMENTADO` (2026-11-16) · `APROBADO` — operator, 2026-11-16.
> Spec: [`spec.md`](spec.md) (`APROBADA`, 2026-11-16, 16 AC) · Plan: [`plan.md`](plan.md) (`APROBADO`, 2026-11-16)
> Each task closes ≥1 criterion and names its test. The checkbox is marked ONLY with the test green and its row in the record.

**Tests:** **L** = `python3 .claude/tools/findings.py selftest` · **V** = `python3 .claude/tools/findings_web.py selftest` ·
**W** = `bash tools/report-test.sh` (runs L and V + HTTP checks against the real module) ·
**S** = `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` (gate and `REQ ↔ case` trace) ·
**K** = `.githooks/test.sh` · **P** = `bash tools/ws-test.sh` · **U** = `bash tools/tui-test.sh`

**Who:** the code, its tests, the living spec and the docs are written by **Codex** (profile `.claude/agents/coder.md`) in
this worktree. Its sandbox has no tmux, docker nor `.git`: the tasks marked **`[operador/sesión principal]`** (operator/main session) it skips, and the main session does them afterwards. The main session reviews each delivery against the AC list.

**Rules for Codex:** do not commit or push · do not read or write in `engagements/` (the tests use a temporary root with fictitious data) · do not use port 4355 (own free port) · stop only processes whose command line names the temporary root · touch only the files in the table of plan §3 · each task with new logic starts with the case that fails and records its red in the record before the fix.

**Coexistence with 017** (built at the same time in another worktree and touches `respond`, `detail_page` and REQ-RPT-008):
016 puts its logic in its own functions (`post_state`, `state_form`, `saved_notice`, `editable_reason`) and touches
those three points minimally: **one** new branch in `respond` (the POST to `/w/<ws>/f/<n>/estado`, after the REQ-RPT-009 controls and before the GET dispatch), **one** block inserted in `detail_page` between the notices and the section navigation (plus the signature that receives ledger and line), and in REQ-RPT-008 only the write sentence and its case. The new `REQ`s of 016 are 018–020 and those of 017 are 021–024 (plan of 017 §3): they do not clash. Expected merge point: `report-module`; whichever arrives second resolves the conflicts in those three areas (T19).

## Wave 0 — Falsifiers (before changing code)
- [x] **F1** — L green; V and W blocked by the sandbox. Baseline: 13 `REQ-LED-003` cases, 13 `REQ-LED-004` and 6
  `REQ-RPT-008` reached before the loopback failure. The full baseline could not be completed · no AC · test: record
- [x] **F2** — `node` and `curl` exist; Python cannot create a socket nor bind `127.0.0.1` (`PermissionError: [Errno 1] Operation not permitted`). V, W and S are left to the main session · no AC · test: record

## Wave 1 — Ledger (`.claude/tools/findings.py`)
- [x] **T1** — new cases in `cmd_selftest`, in red: `fingerprint` the same for the same row with keys in another
  order and different if one byte changes; `set_row(..., expect=<old fingerprint>)` raises `Refusal` with `.kind == "stale"` and
  the ledger stays byte for byte equal (`REQ-LED-007`); each refusal of today raises `Refusal` with its `kind`
  (`no_corroboration`, `no_blocker`, `not_unique`, `corrupt`); via subprocess, `findings.py set` still exits 1 with
  the same text on stderr · test: L (red recorded)
- [x] **T2** — `Refusal(SystemExit)` with `.kind`; `_load` and the refusals of `cmd_set` raise it with the same message
  · the cases of REQ-LED-003 and REQ-LED-004 run **without touching them** · closes `AC3` (part), `AC4` (part) · test: L
- [x] **T3** — `fingerprint(row)` (sha256 of the canonical JSON, sorted keys) and `set_row(ledger, fid, *, status,
  corroboration, blocker, extra, artifact, expect) -> (estado_anterior, fila)` with the body of `cmd_set` moved as is;
  `expect` is compared **with the lock taken** and before `_save`; `cmd_set` remains: arguments → `set_row` →
  `F-0001 -> <estado>` · closes `AC3` (part), `AC8` (part) · test: L (same number of F1 cases + those of T1)

## Wave 2 — Module (`.claude/tools/findings_web.py`), in this order: a single file
> The new cases use `ok("REQ-RPT-018"|"019"|"020", …)`: until T15 the gate S stays red due to an unknown id.
> That is the expected red; V and W must be green when closing each task.

- [x] **T4** — in red: the table of `AC3` (initial row × requested state × corroboration × blocker: the five states,
  with and without text, whitespace only, row that already carries corroboration or blocker, unknown state, no state). Each case saves via `respond("POST", "/w/ws/f/<n>/estado", …)` and runs `findings.py set` as a subprocess on a copy of the
  same ledger: both refuse, or both rows are equal except `updated`. Plus the cases of `AC4`, `AC6` and `AC7`
  (below) · test: V (red recorded)
- [x] **T5** — `post_state`: imports `set_row`, `Refusal`, `fingerprint`; reads `estado`, `corroboracion`, `bloqueo`,
  `visto`, `ficha` with strict UTF-8 decoding (400 if it fails, never `errors="replace"`); `estado` exactly in
  `STATUSES` or 400; `\r\n` → `\n` and nothing else; only those three values reach `set_row` (any other field, including
  `title`, `severity`, `summary`, `cvss`, `artifact`, `id`, is ignored); `Refusal.kind` → notice in Spanish that says what
  is missing and that nothing was saved, 422 with the operator's text in both fields and the state the row still has;
  accepted → 303 built by the module with validated ws and line (without `safe_back`) · closes `AC3`, `AC4`, `AC6` · test: V
- [x] **T6** — size: the `Handler` marks `Ctx.too_long` if `Content-Length` exceeds `MAX_BODY` and `post_state`
  responds 413 stating the maximum, without calling `set_row`. Case first in red with a body of `MAX_BODY + 1` that today
  is truncated and saved · closes `AC7` · test: V
- [x] **T7** — who can write, forgery cases first: `SECRETO` (32 bytes from `secrets` at start) in
  `Ctx.secret`; `ficha = HMAC-SHA256(SECRETO, "<ws>\n<n>\n<visto>")` compared with `hmac.compare_digest`; order of
  controls of plan §2 (`Host`/user → method and route → `Sec-Fetch-Site` → size → UTF-8 and fields → ws and line
  exist → token → editable row → `set_row(expect=visto)`). Cases: `Sec-Fetch-Site` `cross-site`/`same-site`/`none`
  → 403; no header and no token, invented token, from another finding or from another workspace → 403; valid token with and without
  header → accepted; `Host: localhost:<p>` or `peer_ok=False` → the fixed 403 without writing; GET to the action (also
  with the fields in the query) → 404; PUT, DELETE, PATCH, HEAD, OPTIONS → 405; non-existent ws or line → 404 without
  creating anything; two workspaces, the other's sha256 does not change; workspace directory that is a link → 409 without writing.
  The existing case of REQ-RPT-008 («tras todas las rutas, `/actualizar` y `/tema` nada cambia» — after all routes, nothing changes) still passes and adds the
  new action to the list of routes walked by GET · closes `AC11`, `AC12`, `AC13`, `AC14` · test: V
- [x] **T8** — `editable_reason(ledger, row)`: row without id, repeated id, ledger with bad line or `findings.jsonl` not
  regular → the detail does not offer a form and says why; a POST sent anyway → 409 and equal sha256. Case first ·
  closes `AC2` · test: V
- [x] **T9** — two writers: saving with an old `visto` after another `set_row` → 409, the page shows the
  current values and keeps the operator's text; the same form submitted twice → a single write; GET to the notice URL,
  repeated → no write. Case first · closes `AC8`, `AC9` (part) · test: V
- [x] **T10** — form and notice in `detail_page` (receives ledger and line): `state_form` with `<details id="estado">`
  "Cambiar estado", folded except when responding to a rejection; five radios with the `STATUSES` token as is and untranslated,
  the current one marked; two `<textarea>` with the row's text; "Guardar estado" and a "Cancelar" link to the finding itself;
  hidden fields `visto` and `ficha`. `saved_notice`: "Estado guardado: `<anterior>` → `<actual>` · `<updated>`"
  only if `guardado` carries one of the five states and the fingerprint of the **current** row; state and time come from the row.
  New CSS rules inside `CSS` (the CSP hash is recalculated automatically). Cases: no `<script`, same CSP,
  `form-action 'self'`; after saving `confirmed` with a new corroboration on a `confirmed` row without it, the
  "sin corroboración" mark disappears from the list and the detail · closes `AC1`, `AC5`, `AC9` · test: V
- [x] **T11** — hostile content: corroboration and blocker with each value of `HOSTILE` and invisible characters remain
  in the ledger as is and come out escaped in list, detail, form (textarea) and success notice; the rejection notice does not repeat as HTML any value of the request. Case first · closes `AC15` · test: V
- [x] **T12** — static case: the module does not call `_save`, `_locked`, `cmd_add` nor `cmd_set` (only `set_row`), and
  the docstring stops saying «read-only» / «never a writer» and says what it writes · closes `AC6` (part), `AC11` (part)
  · test: V

## Wave 3 — Real process (`tools/report-test.sh`)
- [x] **T13** — HTTP checks against `serve` on the temporary root: request the detail, take `visto` and `ficha` out of the
  HTML and save with `curl` with and without `Sec-Fetch-Site: same-origin` (303 and changed row); a rejection (422, equal sha256);
  false token (403); GET to the action (404); body of `MAX_BODY + 1` (413 with the maximum); follow the 303 and
  reload (a single write). Red first: today the POST gives 405 · closes `AC9`, `AC11`, `AC12` (real process) · test: W
- [x] **T14** — concurrency: 10 saves on different rows and 10 `findings.py add` launched at once → 10
  changes, 10 new rows and `findings.py list --ledger …` exits 0. Repeat 3 rounds · closes `AC10` · test: W

## Wave 4 — Reconciliation and gates
- [x] **T15** — living spec `specs/SECURITY-GUARDRAILS-SPEC.md`, in the same change as the code: REQ-RPT-008
  rewritten («a single route writes, and only `status`, `corroboration`, `blocker` and `updated`, via `set_row`»; its limit stops
  saying that the module does not import `_save` by reading code: now the case of T12 proves it); REQ-RPT-018
  (same rule as `set`), REQ-RPT-019 (who can write), REQ-RPT-020 (two writers), REQ-LED-007 (`expect`);
  limit of REQ-RPT-009 (a forwarder outside loopback or a rootless container with host network can now also
  change a state, decision 1; the token is invalidated when the module restarts); note in REQ-LED-003 (the web uses the same
  rule and does not make it more demanding). Each "Código:" (Code:) names functions that exist. The AC12 of 012 is marked as replaced
  by AC11 and AC12 of this spec (see open question 2) · closes `AC16` (part) · test: S (trace without failures)
- [x] **T16** — `docs/pi-hitl.md` §4c: the warning about proxies outside loopback says that a state can now also be
  changed · no AC (decision 1) · test: review
- [x] **T17** — L, V, W and S green at the same time after the last change (S only if F2 allows it; if not, the main session) · closes `AC16` (part) · test: L, V, W, S
- [x] **T18** `[operador/sesión principal]` — K: `.githooks/test.sh` green and `.githooks/pre-commit` keeps running
  `tools/report-test.sh` when the commit touches `findings.py` or `findings_web.py` (needs `.git`) · closes `AC16` · test: K
- [x] **T19** `[operador/sesión principal]` — merge with 017 in `report-module`: resolve `respond`, `detail_page`
  and REQ-RPT-008 keeping the two new routes and the write sentence; confirm that the `REQ`s do not clash
  (016: 018–020, 017: 021–024) and renumber if they changed; repeat L, V, W, S, K · no new AC · test: the five
- [x] **T20** `[operador/sesión principal]` — independent security review of the diff (agent `code-auditor`,
  read-only, needs `git diff`); each finding is fixed with a case first or recorded as a limit in the living spec
  · test: its report + L, V, W, S green afterwards
- [x] **T21** `[operador/sesión principal]` — real run by the operator in their browser with `tools/pi-hitl.sh`
  (tmux): confirm with corroboration, a rejection, and a save on a row the agent changed in the meantime;
  screenshots in both themes (without lab data in the repo) · closes spec §7 · test: screenshots + record
  - 2026-11-16, partial run by the operator in their browser on the integrated module (016+017+visual redesign); no failures reported. The state steps (409/422) were not recorded one by one.
- [x] **T22** `[operador/sesión principal]` — regression and commit: L, W, K, S, P and U green at the same time; review of
  AC1–AC16 one by one against the record; commit in `report-module` (the `pre-commit` runs gitleaks and
  `tools/report-test.sh`); `Estado` of spec, plan and tasks → `IMPLEMENTADA` and 016 in the list of merged specs of
  `CLAUDE.md` and `AGENTS.md` (twins) · test: the six commands + real commit

## AC → tasks map
| AC | Tasks | AC | Tasks |
|---|---|---|---|
| AC1 | T10 | AC9 | T9, T10, T13 |
| AC2 | T8 | AC10 | T14 |
| AC3 | T1–T5 | AC11 | T7, T12, T13 |
| AC4 | T2, T5 | AC12 | T7, T13 |
| AC5 | T10 | AC13 | T7 |
| AC6 | T5, T12 | AC14 | T7 |
| AC7 | T5, T6 | AC15 | T11 |
| AC8 | T3, T9 | AC16 | T15, T17, T18 |

## Open questions
1. Resolved by F2: `node` and `curl` exist; the sandbox denies IPv4 sockets, and the Node selftest cannot enumerate
   interfaces. Full V, W and S are left for the main session.
2. Resolved in T15: AC12 of 012 is replaced by AC11 and AC12 of this spec.

## Verification record
| Task | Command | Result | Date |
|---|---|---|---|
| F1 | `L; V; W` | L: `selftest OK`; V/W baseline reached `PermissionError: [Errno 1] Operation not permitted` when opening loopback. Previous outputs: 13 `ok REQ-LED-003`, 13 `ok REQ-LED-004`, 6 `ok REQ-RPT-008`. | 2026-11-16 |
| F2 | `command -v node; command -v curl; python3 -c 'import socket; socket.socket().bind(("127.0.0.1", 0))'` | `/usr/bin/node`, `/usr/bin/curl`; bind: `PermissionError: [Errno 1] Operation not permitted`. | 2026-11-16 |
| T1 | `L` | Initial red: `NameError: name 'fingerprint' is not defined`; final green: `selftest OK`, with fingerprints, stale, refusal classes and CLI output. | 2026-11-16 |
| T2–T3 | `L` | `selftest OK`; the pre-existing REQ-LED-003/004 cases pass unchanged and `cmd_set` still produces the same CLI refusal. | 2026-11-16 |
| T4 | `V` | Initial red: `AssertionError: REQ-RPT-018 valid state form saves through the shared ledger rule` (the route still answered 405); web/CLI pairs of states and refusals pass before the bind. V then stops when opening loopback. | 2026-11-16 |
| T5 | `V` | Strict UTF-8, shared rule, allowed fields, 422 rejection and 303 covered in the pure section; full gate pending due to loopback. | 2026-11-16 |
| T6 | `V` | Body `MAX_BODY + 1` gives 413 without writing in the pure section; real test of the `Handler` pending due to loopback. | 2026-11-16 |
| T7 | `V` | Pure cases of token, origin, host/peer, route, linked workspace and non-editable state pass; full gate pending due to loopback. | 2026-11-16 |
| T8 | `V` | Pure cases of duplicate id, corrupt ledger and linked ledger pass; full gate pending due to loopback. | 2026-11-16 |
| T9 | `V` | Pure cases of stale fingerprint, double POST and GET reload pass; full gate pending due to loopback. | 2026-11-16 |
| T10 | `V` | Form, exact states, CSP, success notice and disappearance of the alert pass in the pure section; full gate pending due to loopback. | 2026-11-16 |
| T11 | `V` | Hostile content stored without alteration and escaped on the page/form; the rejection shows escaped text; full gate pending due to loopback. | 2026-11-16 |
| T12 | `V` | AST case verifies the module uses only `set_row` as writer and the docstring describes the action; full gate pending due to loopback. | 2026-11-16 |
| T13–T14 | `W; bash -n tools/report-test.sh` | Shell syntax correct. W ends with `BLOCKED: HTTP checks require a loopback port; this sandbox denied the bind`; HTTP and concurrency pending. | 2026-11-16 |
| T15 | `S` | Blocked before the REQ gate: Node 22.22.2 fails with `uv_interface_addresses returned Unknown system error 1`. | 2026-11-16 |
| T16 | review of `docs/pi-hitl.md` §4c | Proxy warning updated to include reading and changing editable states. | 2026-11-16 |
| T17 | `L; V; W; S` | L green. V/W/S blocked by the environmental errors recorded above; combined gate pending. | 2026-11-16 |
| T18 | — | Omitted: marked `[operador/sesión principal]`. | 2026-11-16 |
| T19 | — | Omitted: marked `[operador/sesión principal]`. | 2026-11-16 |
| T20 | — | Omitted: marked `[operador/sesión principal]`. | 2026-11-16 |
| T21 | — | Omitted: marked `[operador/sesión principal]`. | 2026-11-16 |
| T22 | — | Omitted: marked `[operador/sesión principal]`. | 2026-11-16 |
| T13–T22 (main session) | outside the Codex sandbox, on `3e53e37`: `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` · `bash tools/report-test.sh` · `bash .githooks/test.sh` · `bash tools/tui-test.sh` | GREEN: trace 142 requirements / 1436 cases; `report-test` 47 passed, 0 failed (HTTP and concurrency included); hooks 46; TUI 48. T19 (merge with 017) and T20 (independent review) closed earlier with the FixLedger/FixWeb branches (`82ca1b0`, `dad7356`, merge `de0e1de`) | 2026-11-16 |
| T21 | real run by the operator in their browser (`127.0.0.1:4355`, a lab workspace) | GREEN according to the operator: state change `confirmed → triaged` with a saved blocker and the "Estado guardado" notice in the detail (screenshot seen by the main session, not versioned: it carries lab data). The rejection and the 409 for a changed row were not recorded one by one | 2026-11-16 |
