# Spec 016 — Change a finding's state from the web

> Status: `IMPLEMENTADA` (2026-11-16: real run by the operator in their browser, T21) · `APROBADA` (operator, 2026-11-16) · the four decisions of the first draft are in §8.
> Date: 2026-11-16 · Design source: mockups `04a-estado-confirmar` and `04b-estado-rechazo` of
> [`015`](../015-reportes-rediseno/spec.md) (marked NOT BUILT) + decision 4 of [`012`](../012-report-module/spec.md) §8
> `report-module` branch. It loosens the boundary (REQ-RPT-008 stops being "read-only"): it goes through the long flow.

## 1. Problem (one sentence)
The operator sees a finding in the reports module but cannot change its state there: the module rejects every POST other than `/actualizar` or `/tema` (`.claude/tools/findings_web.py:567`, REQ-RPT-008), so they have to go to the terminal and type `findings.py set --ledger … --id … --status … --corroboration "…"` by hand.

## 2. Goal (one sentence)
From a finding's page the operator moves it to any of the five states and writes the corroboration or the blocker, with exactly the rules of `findings.py set`: the web cannot reach any state that the command rejects, changes nothing beyond those three fields, and a page from another origin cannot trigger the write.

## 3. Context / why now
Spec 012 left this function for "later" (§8, decision 4) and 015 drew the form without building it. Read in the code (`report-module` branch, `89bb535`):
- The rule already exists and has a `REQ`: `cmd_set` (`.claude/tools/findings.py:187`) denies `confirmed` without corroboration and `needs_validation` without a blocker (REQ-LED-003), takes the directory lock and saves by renaming (REQ-LED-005, REQ-LED-006), and aborts if the ledger has a bad line (REQ-LED-004) or if the id does not appear exactly once. Its refusals are `sys.exit` with a message in English meant for the terminal.
- The module already has two POST forms without JavaScript (`/tema`, `/actualizar`) and the content policy allows submitting forms only to the module itself (`form-action 'self'`, `findings_web.py:281`).
- The origin defence of those two POSTs lets through a request **without** a `Sec-Fetch-Site` header (`findings_web.py:570`). For the theme and the update the worst case was harmless (limit of REQ-RPT-011); for a ledger write it is not: a page from another origin open in the operator's browser could confirm a finding.
- The detail is addressed by ledger line number (`/w/<ws>/f/<línea>`), and `set` by id. A row without an id or with a repeated id is visible on the web but `set` rejects it.
- The agent writes to the same ledger while the operator looks at the web: between opening the page and saving, the row may have changed.
- The body of a request is read truncated at `MAX_BODY` (65536 bytes, `findings_web.py:30`): today what exceeds it is silently discarded.
- The model can already run `findings.py set` (it is the contract's flow): as long as the web applies the same rule, it gives the model no new capability.

## 4. Scope
**In:**
- On the detail page, an inline form (no modal and no JavaScript) with the five states, a corroboration field and a blocker field, and the save and cancel buttons. The evidence stays in view while writing.
- One write action per finding. It changes only `status`, `corroboration`, `blocker` and `updated` of that row.
- Refusal explained on the page: what was missing, that nothing was written, and the operator's text preserved.
- Success notice with the previous state, the new one and the time.
- A stricter origin defence than that of `/tema` for this action.
- Refusal when the row changed since the form was shown.
- Reconciliation on merge: REQ-RPT-008 rewritten ("writes only these three fields, by the `set` rule"), a new `REQ` for the action, and criterion AC12 of 012 replaced by AC11 and AC12 of this spec.

**Out (explicit, anti scope-creep):**
- Editing any other field from the web (title, severity, target, evidence, summary, impact, remediation, CVSS, CWE, CVE, artifact, steps, KB). They remain `findings.py set` in the terminal.
- Creating or deleting findings from the web.
- Deleting a corroboration or blocker already written: as in `set`, they are only replaced (limit of REQ-LED-001).
- Changing several findings at once, and changing the state from the list.
- Change history in the ledger (who, when, from what to what). See §6.
- The "equivalent command" the mockup draws under the form. See §6.
- Module authentication (login, token). See §6, decision 1.
- Per-finding chat, report download (spec 017) and density and date settings.
- Live update of the page without reloading.
- Changes to `findings.py` beyond what is needed for the web to use the same rule (no rule is changed).

## 5. Acceptance criteria (testable)
> Tests: **W** = `bash tools/report-test.sh` (existing: runs the selftests of `findings.py` and `findings_web.py`
> and hits the real module over HTTP on a temporary root). **H** = `.githooks/test.sh`.
> **G** = the gate (`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`).
> "Save" = submit the state change form. "Does not write" = the sha256 of the ledger and the listing of the workspace directory are the same before and after. All cases run on temporary ledgers with
> fictitious data; none reads `engagements/`.

| # | Criterion (observable) | Test |
|---|---|---|
| **Form** | | |
| AC1 | The detail page of a row with a unique id, in a ledger without bad lines, carries a form with the five states of `STATUSES` (`findings.py:40`), each with its ledger token as is (`hypothesis`, `triaged`, `confirmed`, `needs_validation`, `refuted`) and with no translated name, the current one marked, a corroboration field and a blocker field with the text the row already has, and the save and cancel buttons. It works without JavaScript and without external resources; the response still does not contain `<script` and carries the same content policy. | W |
| AC2 | WHEN the row has no id, its id appears in more than one row, the ledger has a bad line, or `findings.jsonl` is not a regular file, THEN the page does not offer the form and says why; a save sent anyway does not write. | W |
| **Same rule as `set`** | | |
| AC3 | For each case of a table (initial row × requested state × corroboration × blocker: the five states, with and without text, whitespace-only text, a row that already carries corroboration or a blocker, a row with unknown state and a row without state), saving through the web and running `findings.py set` with the same values on a copy of the ledger give the same result: both refuse, or both leave the row identical except `updated`. | W |
| AC4 | WHEN `confirmed` is saved without corroboration (neither in the form nor in the row) or `needs_validation` without a blocker, THEN it does not write, and the page says in Spanish which field is missing and that nothing was saved, keeps the text the operator typed in both fields and shows the state the row still has. | W |
| AC5 | WHEN it is saved with the same state and a new corroboration on a `confirmed` row without corroboration, THEN the row gains the corroboration and the "sin corroboración" mark (REQ-RPT-004) disappears from the list and the detail. | W |
| AC6 | An accepted save changes only `status`, `corroboration`, `blocker` and `updated` of that row: the other fields of the row and all the other rows remain byte for byte equal, and the workspace directory gains no files. WHEN the request carries other fields (`title`, `severity`, `summary`, `cvss`, `artifact`, `id`), THEN they do not reach the ledger. | W |
| AC7 | WHEN the requested state is not exactly one of the five, the body is not valid UTF-8, or the request exceeds the maximum size, THEN it is rejected entirely and does not write: a truncated text or one with replaced characters is never saved. The size rejection states the maximum. | W |
| **Two writers** | | |
| AC8 | WHEN the row changed in the ledger between showing the form and saving (another `set`, from the agent or from the terminal), THEN it does not write; the page says the finding changed, shows the current values and keeps the operator's text. | W |
| AC9 | After an accepted save the browser returns to the finding's page, which shows the notice with the previous state, the new one and the time, and the state and corroboration up to date. WHEN the same form is submitted twice, or the notice page is reloaded, THEN the ledger is written only once. | W |
| AC10 | WHEN 10 saves on different rows and 10 `findings.py add` run at the same time on the same ledger, THEN the 10 changes and the 10 new rows remain, and the ledger passes `findings.py list` (no change lost, no broken line). | W |
| **Who can write** | | |
| AC11 | The write exists only as a POST to a finding's action: a GET to that address (also with the same parameters in the query) responds 404, PUT, DELETE, PATCH, HEAD and OPTIONS respond 405, and none writes. There is still no other route that writes to a workspace: after walking all routes with GET, pressing the update and changing the theme, no ledger nor workspace directory changes. | W |
| AC12 | WHEN the save arrives with `Sec-Fetch-Site` other than `same-origin`, or **without** that header and without the value the module put in the form it served, or with an invented form value, from another finding or from another workspace, THEN it receives 403 and does not write. A save made from the served form is accepted with and without the header. | W |
| AC13 | The controls of REQ-RPT-009 come first: a save with a `Host` that is not `127.0.0.1:<port>`, or from a connection that is not from the module's user, receives the fixed 403, without data and without writing. | W |
| AC14 | A save in one workspace changes no other: with two workspaces, after saving in one the sha256 of the other's ledger is the same. A save aimed at a workspace or a line that does not exist responds 404 and creates nothing. | W |
| **Hostile content** | | |
| AC15 | WHEN the saved corroboration or blocker carry the hostile content of 012 (§5) or invisible characters, THEN they remain in the ledger as written and all pages return them escaped (REQ-RPT-007 keeps being met with the form and the success notice on the page). The rejection notice does not repeat any value of the request as HTML. | W |
| **Gate** | | |
| AC16 | The new cases run in **W**; `.githooks/pre-commit` runs them when the commit touches `findings.py` or `findings_web.py` (it already does: it must not stop doing so), and the `REQ ↔ case` trace of the gate stays green with the reconciled `REQ`. | H + G |

## 6. Risks / open decisions
The four operator decisions (forwarders, state names, history, equivalent command) are in §8.

**For `plan.md`:**
- How the web uses `set`'s rule without copying it (AC3 fails if there are two rules): shared function or separate process.
  Spec 012 stated that "the module does not import `_save`" by reading the code; that stops being true and must be said.
- How `set`'s refusals (today `sys.exit` with English text) are translated into notices in Spanish without depending on comparing strings.
- What the "value the module put in the form" of AC12 is, and how AC8 detects that the row changed.
- The maximum size of AC7 and how a longer body is rejected instead of truncated.
- The action's address and its fit in `respond` and in `safe_back`.
- Whether the form is always visible or folded (`<details>`), and where it sits with respect to the three sections of the detail.

**Limits this spec accepts (they stay in the living spec when merged):**
- (Decision 1) There is no login. Whoever reaches an operator proxy listening outside loopback (Burp, ZAP,
  mitmproxy) or a rootless container with host network today can **read** the ledgers (limit of REQ-RPT-009); with
  this spec they can also **change a state**: they request the page, take the form value and save. Closing it
  requires authentication, which is left for a separate spec together with the read case.
- (Decision 3) The ledger does not record who changed a state nor what the previous one was. Through the terminal the command remains in the session history; through the web nothing remains except `updated`.
- Corroboration remains a non-empty text: neither `set` nor the web checks that it describes a second independent signal (limit of REQ-LED-003). The web makes the path to `confirmed` shorter; it does not make it more demanding.
- AC12 covers a page from another origin in the operator's browser. It does not cover a process of the same user, which can request the page and save; that process can already write the file.
- AC8 compares against what the page showed: a change made by hand in the JSONL that does not touch `updated` may go undetected (it depends on the design the plan chooses).
- A row with a repeated id or without an id cannot be changed from the web (AC2), just as with `set`.
- No live reload: the page does not warn by itself that the agent changed the finding; it says so when saving (AC8).
- AC3 compares against a table of cases, not against "any entry".

## 7. Signs of "done"
`bash tools/report-test.sh`, `.githooks/test.sh` and the gate
(`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`) green at the same time + the `tasks.md` checklist complete with its verification record + a real run by the operator in their browser (confirm with corroboration, a rejection, and a save on a row the agent changed), with screenshots in both themes.

## 8. Operator decisions (2026-11-16)
1. Forwarders: "aceptado" (accepted). The write inherits the read limit of REQ-RPT-009 and is documented; authentication goes in a separate spec.
2. Names of the states in the form: "solo token" (token only). No translated names (AC1).
3. Change history: out, "por ahora así, ya que no hay múltiples usuarios" (for now like this, since there are no multiple users).
4. Equivalent command: "escojo A, déjalo afuera" (I choose A, leave it out). The page does not show the equivalent terminal command.
5. Approval: "aprobadas ambas spec" (both specs approved) (2026-11-16).
