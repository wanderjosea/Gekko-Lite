# Technical plan 016 — Change a finding's state from the web

> Status: `IMPLEMENTADO` (2026-11-16) · `APROBADO` — operator, 2026-11-16.
> Spec: [`spec.md`](spec.md) (`APROBADA`, 2026-11-16) · `report-module` branch, base `89bb535`
> Coding: Codex (a coding agent) with the profile `.claude/agents/coder.md`, in its own worktree; verification and integration are done by the main session.

## 1. Approach
The rule of `set` is taken out of `cmd_set` into a `findings.py` function (`set_row`) that raises its refusals as an exception with a code, and the web calls that same function: there is no second copy of the rule (AC3). The web adds a single write route, `POST /w/<ws>/f/<n>/estado`, protected by a token that the module puts in the form and by the fingerprint of the row the operator saw. No JavaScript, no dependencies, no new files: everything fits in the two Python files that are already on the boundary.

## 2. Contracts

**`findings.py`**
```python
class Refusal(SystemExit):           # .kind: "no_corroboration" | "no_blocker" | "not_unique" | "corrupt" | "stale"
fingerprint(row) -> str              # sha256 of the canonical JSON of the row (sorted keys)
set_row(ledger, fid, *, status=None, corroboration=None, blocker=None, extra=None, artifact=None,
        expect=None) -> (estado_anterior, fila)
```
- `Refusal` inherits from `SystemExit` and carries the same message as today: for the terminal `raise Refusal(kind, msg)`
  is identical to `sys.exit(msg)` (same text on stderr, same exit 1), so the cases of REQ-LED-003 and
  REQ-LED-004 do not change. The web catches `Refusal` and reads `.kind`; it never compares texts.
- `set_row` is the current body of `cmd_set` (lock, `_load`, the two refusals, `_save`), moved as is.
  `cmd_set` remains: read arguments → `set_row` → print `F-0001 -> confirmed`.
- `expect`: if passed and `fingerprint(fila) != expect`, `Refusal("stale")` **with the lock taken** and without
  writing. The terminal does not pass it.
- `_load` raises `Refusal("corrupt", …)` instead of `sys.exit` (same message).

**`findings_web.py`**

| Request | Response |
|---|---|
| `POST /w/<ws>/f/<n>/estado`, accepted | 303 to `/w/<ws>/f/<n>?guardado=<estado anterior>.<huella nueva>` |
| same, the `set` rule denies it | 422, finding page with the notice, the form open and the operator's text |
| same, the row changed since the form was served | 409, finding page with the current values and the operator's text |
| same, `estado` not one of the five, body not UTF-8 or without the fields | 400, does not write |
| same, request larger than `MAX_BODY` (65536 bytes) | 413, the page states the maximum, does not write |
| same, `Sec-Fetch-Site` present and other than `same-origin`, or token absent or invalid | fixed 403, does not write |
| same, row without id or with repeated id, ledger with bad line or not regular, workspace directory that is a link | 409, states the reason, does not write |
| `GET` to that route | 404 (matches no page, like `GET /tema`) |
| other method | 405 (rule that already exists) |

Form fields (`application/x-www-form-urlencoded`): `estado`, `corroboracion`, `bloqueo`, `visto`
(fingerprint of the row when the page was served) and `ficha` (token). Any other field is ignored: `set_row` only receives the first three
(AC6). The `\r\n` line breaks that a `<textarea>` sends are converted to `\n` before saving; nothing else is trimmed.

**Token (AC12).** `ficha = HMAC-SHA256(SECRETO, "<ws>\n<n>\n<visto>")` in hexadecimal. `SECRETO` is 32 random bytes
created at process start, in memory only. It is bound to the workspace, the line and the version of the row: a token from another finding or from another workspace is not valid. It is compared with `hmac.compare_digest`.
A page from another origin cannot read the form (there is no CORS and `frame-ancestors 'none'`), so it cannot obtain it even if the browser does not send `Sec-Fetch-Site`.

**Order of the controls in `respond`:** `Host` and user (REQ-RPT-009, already first) → method and route →
`Sec-Fetch-Site` → size → UTF-8 and fields → workspace and line exist (404) → token (403) → editable row (AC2)
→ `set_row(..., expect=visto)`.

**Form (AC1, AC2).** On the detail, between the notices and the section navigation:
`<details id="estado">` with summary "Cambiar estado" (Change state), folded by default and open when the page responds to a
rejection. Inside: five option buttons with the ledger token as is, the current one marked; two
`<textarea>` (corroboration, blocker) with the row's text; "Guardar estado" (Save state) and a "Cancelar" (Cancel) link to the finding itself. If the row cannot be changed, a note with the reason goes in that place and there is no form.

**Success notice (AC9).** The finding page shows "Estado guardado: `<anterior>` → `<actual>` · `<updated>`" (State saved)
only if the `guardado` parameter carries one of the five states and the fingerprint of the **current** row. The current state
and the time come from the row, not from the parameter.

## 3. Affected files
| File | Change | AC served |
|---|---|---|
| `.claude/tools/findings.py` | `Refusal`, `fingerprint`, `set_row` (extracted from `cmd_set`), `_load` raises `Refusal`; new selftest cases | AC3, AC4, AC8 |
| `.claude/tools/findings_web.py` | imports `set_row`, `Refusal`, `fingerprint`; `SECRETO`; `Ctx.secret` and `Ctx.too_long`; form and notice in `detail_page` (now receives the ledger and the line); `post_state`; route in `respond`; the handler marks the too-long request; CSS rules for the form; docstring («read-only», «never a writer») corrected; new cases | AC1–AC15 |
| `tools/report-test.sh` | HTTP checks against the real module: save, rejection, false token, GET to the action, 10 saves + 10 `add` at once | AC9–AC12 |
| `specs/SECURITY-GUARDRAILS-SPEC.md` | REQ-RPT-008 rewritten; new `REQ`; forwarder limit in REQ-RPT-009; note in REQ-LED-003 | AC16 |
| `docs/pi-hitl.md` §4c | the proxy warning says that a state can now also be changed | decision 1 |
| `specs/016-estado-desde-web/tasks.md` | written after this plan is approved | — |

Not changed: `.githooks/pre-commit` (it already runs `tools/report-test.sh` when the commit touches those two files),
`toolbox/gekko-guard.ts` (it already counts the `ok REQ-…` lines of the two selftests), the panel and the launcher.

**`REQ` in the living spec** (if 017 is merged first, they are renumbered):
- REQ-RPT-008 — goes from "read-only" to "a single route writes, and only `status`, `corroboration`, `blocker` and `updated`".
- REQ-RPT-018 — same rule as `set`: table of web-vs-terminal cases, explained refusal, text preserved.
- REQ-RPT-019 — who can write: token, origin, methods, size, UTF-8, a single workspace.
- REQ-RPT-020 — two writers: changed row, double submit, saves and additions at the same time.
- REQ-LED-007 — `set_row` with `expect`: if the row is not the one that was seen, it does not write.

## 4. Decisions (resolves the open ones in the spec)
- **One rule, not two: shared function**, not a separate process. A `subprocess` per save would force free text through
  arguments and interpreting the refusal by its text. With this the module stops importing only the reader:
  it imports `set_row`, which is the only write. A case checks that the module does not use `_save` nor `cmd_add` on its own.
- **Refusals with a code** (`Refusal.kind`), translated into Spanish on the web. The terminal's English messages are not touched.
- **Changed row: fingerprint of the whole row**, not `updated`. It also detects a manual edit that does not touch
  `updated`, so that limit of the spec disappears. It is checked with the lock taken.
- **Double submit:** no own logic is needed. The first save changes the row, so the second brings an old
  fingerprint and is rejected. If the first changed nothing material and both fall in the same second, the second
  writes the same bytes.
- **Maximum size:** that of the request, `MAX_BODY`. The handler today reads up to that cap and discards the rest; for
  this route it marks the request as too long and the response is 413 without touching the ledger.
- **Return with 303** and not responding the page directly to the POST: so that reloading does not resend the form and the
  address bar stays on the finding's page. The 303 address is built by the module with the workspace
  and the line already validated: it does not come from the request nor pass through `safe_back`.
- **Folded form** in a `<details>`: reading the finding does not change for whoever is not going to touch the state.
- **Workspace directory that is a link:** the write is refused (two lines, one case). Today `discover`
  accepts a directory that is a link to **another** workspace of `engagements/`; through there a save would change
  another workspace's ledger (AC14). Fixing `discover` and the launcher is a separate change, pending since 010.

## 5. Risks and mitigation
- The refactor of `cmd_set` changes a rule by accident → the current cases of REQ-LED-003 and REQ-LED-004 run without
  being touched before and after; they are the first falsifier.
- The token is invalidated when the module restarts («Buscar actualizaciones» — check for updates): a form open at that moment
  receives 403 and you have to go back to the finding. The browser keeps the text when going back. It is recorded as a limit.
- `SECRETO` lives in the process memory: a process of the same user can request the page and obtain a
  valid token. It is the limit the spec already accepts (that process can write the file).
- Between checking that `findings.jsonl` is a regular file and opening it there is a window (a limit REQ-RPT-008 already
  has for reading). `_save` replaces by renaming and never follows a link, and the fingerprint rejects a row
  different from the one seen: in that window nothing is written outside the workspace.
- The parameter `guardado` allows building a link that shows the notice with a false "previous state", only if
  whoever builds it knows the fingerprint of the current row. The current state and the time cannot be falsified.
- A request that is too long is cut off without being read whole: the browser may see the connection closed instead of the
  413 page. The HTTP case uses a body just above the cap, which does get the response.
- AC10 depends on each server thread taking its own lock: `_locked` opens one descriptor per call,
  so two threads of the same process exclude each other. The concurrency case checks it.

## 6. Order of attack
1. **Cheapest falsifier:** extract `set_row` and `Refusal` and run `python3 .claude/tools/findings.py selftest`
   without touching any case. If something fails, the refactor changed the rule.
2. New ledger cases in red and then in green: `expect` with a changed row (REQ-LED-007), `fingerprint`.
3. The table of AC3 (web against terminal over copies of the same ledger), in red: there is still no route.
4. Route, `post_state` and `respond` controls until AC3, AC4, AC6 and AC7 are green.
5. Token and origin (AC11–AC14), with the forgery cases first.
6. Form and notice in the detail (AC1, AC2, AC5, AC9, AC15) and its CSS rules.
7. HTTP and concurrency checks in `tools/report-test.sh` (AC10).
8. Living spec, `docs/pi-hitl.md`, and the three gates green at the same time.
9. Independent security review of the diff (agent `code-auditor`) before merging: it is boundary code.
10. Real run by the operator with screenshots in both themes.
