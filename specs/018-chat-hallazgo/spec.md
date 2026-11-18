# Spec 018 — Finding chat: ask the model and apply what it drafts

> Status: `IMPLEMENTADA` (operator, 2026-11-17: closed; real runs done by the operator; final regression in `66a7506`: guard 190/2245, L, WS, sanitizer, report-test 84/0, hooks 48, ws-test 184/0, tui-test 55/0 and toolbox-test with Docker green) · earlier (operator, 2026-11-17: "implementalo con tus recomendaciones" — "implement it with your recommendations"; decisions resolved in §8, without
> an intermediate gate on plan/tasks at the operator's request).
> Date: 2026-11-17 · Design source: [`015/design.md`](../015-reportes-rediseno/design.md) principle 8 ("the model drafts; it does not attest"), "Chat del hallazgo" (Finding chat), §6 (chat states), §3 (widths/drawer), §8.1–8.5, mockups
> `03-hallazgo-chat`, `03b-chat-aplicar`, `03c-chat-sin-provider` (marked NOT BUILT) + AC5 of the
> [`015/spec.md`](../015-reportes-rediseno/spec.md) (50/50 "when an approved assistant backend exists").
> Visual reference of the panel: the operator's V3 prototype (outside the repo, only what touches the chat; §4) and the brand kit.
> Branch: to be decided (§8, D11). **It loosens the boundary twice** — the module gains an outbound network path to the Provider and a second write to the ledger — and creates a new file per workspace (the history): it goes through the long flow.

## 1. Problem (one sentence)
The operator cannot ask the model about a finding from the reports module, nor take a draft of summary, impact or remediation into the ledger without the terminal: the module opens no outbound connections (a case of REQ-RPT-022 checks it), its content policy allows no scripts nor connections (`findings_web.py:398`), the only write is `/estado` (REQ-RPT-008), and 015 left the assistant out (AC5).

## 2. Goal (one sentence)
On a finding's detail the operator asks the configured Provider; the module builds the context from the ledger (sanitised and fenced as data), shows the answer as text, and a proposal for an allowed drafting field enters the ledger only when the operator presses "Aplicar" (Apply), through `set_row` with the defences of 016; the key never leaves the server and no data goes to any host other than the configured Provider.

## 3. Context / why now
Read in the code (`main`, `745d6f7`):
- The module is a `ThreadingHTTPServer` on `127.0.0.1` with user and `Host` control (REQ-RPT-009). CSP:
  `default-src 'none'; style-src 'sha256-…'; font-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`.
  REQ-RPT-007 requires zero `<img`, no script permission, and that the only `<svg>` is the gear.
- `ensure` launches the module with a minimal environment (`DETACHED_ENV`, `findings_web.py:35`) and a case of REQ-RPT-012
  checks with a canary that `GEKKO_LLM_KEY` **does not** reach the process. URL, keys and model live in
  `.gekko-state/env` (0600, gitignored, `setup.sh:175`): `GEKKO_LLM_URL`, `GEKKO_LLM_KEY`, `GEKKO_MODEL`,
  `GEKKO_PROVIDER="provider"`, `GEKKO_PROVIDER_KEY`. The default Pi profile uses the `provider` profile, not `GEKKO_LLM_KEY`.
- `set_row(extra=…)` writes any key without validating it; the validation of `cvss`/`cwe`/`cve` lives in
  `_optional_fields`, tied to `argparse`. `set` writes `summary`, `impact`, `remediation`, `cvss`, `cwe`, `cve`;
  it does **not** write `repro` (steps) nor `severity`, and does not delete a key (limit of REQ-LED-001).
- `sanitize_target_content.py` gives `sanitize`, `wrap` and `process`; it does not return how many patterns it neutralised. The module does not import it today.
- The Provider is OpenAI-compatible (`/chat/completions`), with a single resident model on a GPU shared with the agent: a request with another `model` triggers a model change (the first one pays the load) and can evict the model Pi works with.

## 4. Scope
**In:**
- On the detail, the "Asistente" (Assistant) panel of 015 with the V3 layout: header (Gekko isotype, Provider and model, state), "Contexto activo" (active context) line (which fields are sent, approximate tokens, evidence-output switch, neutralised patterns), question shortcuts ("¿Qué evidencia falta?" — What evidence is missing?, "Redactar impacto" — Draft impact, "Sugerir remediación" — Suggest remediation, "Explicar" — Explain), messages with their own scroll and a fixed composer at the bottom. ≥1280 px: 50/50 with the detail (AC5 of 015); below that, a dedicated view with a way back to the finding.
- One question at a time: the module builds the context **only** from the ledger, sends it to the Provider and saves the answer in the finding's history.
- Block "Propuesta para ‹campo›" (Proposal for ‹field›) with "Ahora en el ledger" (Now in the ledger), "Aplicar/Sustituir" (Apply/Replace) and "Deshacer" (Undo); mark "vía chat · hora" (via chat · time).
- History per finding under the workspace, with a cap and "Vaciar" (Empty).
- States: no Provider, Provider down, key rejected, timeout, invalid response, question in progress, stopped; retry without losing the question.
- Brand: the assistant's avatar and the header use the isotype / horizontal logo of the brand kit (colour or white variant on dark, black on light), a reduced local copy inside the repo, no remote requests (§8, D8).
- Reconciliation on merge: REQ-RPT-007, -008, -012 (if D1 = b), -016 rewritten; new `REQ`s for asking, applying, undoing, emptying and network output.

**Out (explicit, anti scope-creep):**
- From the V3, everything that is not the chat — candidates for **019**: inline editing of fields ("Editar hallazgo"), CVSS v3.1 calculator, Executive/Technical report builder with drafts, collapsible sidebar (and its compact mark), the "Impacto ejecutivo" field (it does not exist in the ledger).
- From the V3, explicitly **not adopted**: the contract `window.GEKKO_CHAT_ENDPOINT` with `{workspaceId, findingId, messages}` (the client does not declare context nor history), `localStorage` persistence of findings and drafts, demonstration answers without an endpoint, and painting with `innerHTML`.
- Chat outside a finding, over several findings or over the workspace; tool use from the chat (commands, reading artifacts, network towards the target); automatic triage.
- The chat writing `status`, `corroboration`, `blocker`, `evidence`, `severity`, `id`, `title`, `target`, `kb`, `cve`, `created`; creating or deleting findings. Applying to `repro`, `cvss` or `cwe`: see D4.
- Choosing the model from the web; several Providers; a Provider outside loopback/private network (D3).
- The browser talking to the Provider; module authentication (the limit of REQ-RPT-009 / decision 1 of 016 remains).
- The chat history inside the report, the downloads or the index.

## 5. Acceptance criteria (testable)
> Tests: **W** = `bash tools/report-test.sh` (selftests of `findings.py` and `findings_web.py` + real HTTP over a temporary root). **H** = `.githooks/test.sh`. **G** = the gate. **P** = fake Provider: a local server on `127.0.0.1:<free port>` from the selftest itself, which records each request and responds according to the case (normal, 401,
> 500, redirect, invalid JSON, huge response, drip-feed). No case uses a real model, network outside loopback nor real `engagements/`. "No escribe" (does not write) = sha256 of the ledger and listing of the workspace equal before and after.
> "Canario de clave" (key canary) = a unique fictitious key placed in the temporary `.gekko-state/env`.

| # | Criterion (observable) | Test |
|---|---|---|
| **Panel and context** | | |
| AC1 | The detail of an editable row (same rule as `editable_reason`) carries the panel with Provider (host, never the key) and model, the context line with the exact list of fields to be sent, approximate tokens, the evidence-output switch **off** by default and the number of neutralised patterns, the four shortcuts and the composer. WHEN no Provider is configured or the row is not editable, THEN the panel says why and offers no send. | W |
| AC2 | The page carries, folded, the exact text to be sent to the model; it is byte for byte what **P** receives (except headers). | W + P |
| **What goes out and where** | | |
| AC3 | The context is built on the server from the row re-read from the ledger. The browser request only contributes question, switch, `visto` and `ficha`; WHEN it also carries `messages`, `system`, `findingId`, `summary`, `model` or others, THEN they are ignored. **P** receives only the fields in the list (§8, D10) and the history of **that** finding; with canaries in another row, another workspace, `scope.txt`, the artifact file and the evidence output with the switch off, none reaches **P**. | W + P |
| AC4 | Every ledger value and every previous model answer that is fed back pass through `sanitize` and travel inside a single `TARGET-CONTENT` fence; the operator's question goes outside the fence. WHEN the row carries `<system>` tags, "ignore previous instructions" orders, fence closings and their obfuscated variants (REQ-FW-002), THEN **P** receives them neutralised inside the fence and the page counter matches. | W + P |
| AC5 | The module connects only to the host and port of the configured URL, over `http`/`https` and to `<base>/chat/completions`. WHEN **P** responds 3xx towards a second fake server, THEN that server receives zero connections and the page shows an error. WHEN the URL points outside the ranges of D3 (literal or a name that resolves outside), THEN it is rejected without opening any socket. Walking all the GET routes and the POSTs that are not "ask" opens zero outbound sockets. | W + P |
| AC6 | The Provider's response is bounded: byte cap, total time and time without data. WHEN **P** sends a response larger than the cap, drip-feeds or never ends, THEN the question ends in error within the total time, no proposal is saved from it, and meanwhile another page of the module responds in < 2 s. | W + P |
| **Key** | | |
| AC7 | With the key canary, **P** receives it only in `Authorization: Bearer`; it appears in no response (body nor headers, error ones included), in the history, in the ledger, in `report.log` nor in the environment of the module process (the case of REQ-RPT-012 stays green unless D1 = b). WHEN **P** responds 401, THEN the page says "el Provider rechazó la clave" (the Provider rejected the key) without repeating it. | W + P |
| AC8 | The CSP does not name the Provider's origin nor any other external origin; `script-src` and `connect-src` remain as D2 decides (with A: absent). The only CSP relaxation allowed apart from D2 is that of D8 (`img-src data:`). | W |
| **Answer and proposal** | | |
| AC9 | The model's answer is text: with `<script>`, event attributes, `javascript:`, Markdown links and images, ESC and bidi, the page carries no tag, attribute or link that escapes it, and meets the controls of REQ-RPT-007. | W + P |
| AC10 | Only a block in the fixed proposal format that names a field of the allowlist (D4) and whose value passes the same validation as `set` is painted as "Propuesta para ‹campo›" with "Aplicar" (or "Sustituir" and "Ahora en el ledger" if the field has text). WHEN the block names `status`, `corroboration`, `blocker`, `evidence`, `severity`, `id` or an unknown field, or the value does not validate, THEN it is shown as text without a button. | W + P |
| AC11 | Nothing is applied on its own: after any answer (also one that says "ya lo apliqué" — "I already applied it" — or carries proposals for all fields) the ledger does not change until a POST to apply from the operator. | W + P |
| **Apply and undo** | | |
| AC12 | Apply, undo, empty and ask are POSTs to a finding's routes with the defences of REQ-RPT-019 in the same order (Host and user, method and route, `Sec-Fetch-Site`, 413 over `MAX_BODY`, strict UTF-8, HMAC token bound to workspace, line, seen fingerprint and — for apply/undo — proposal id). GET to those routes: 404; other methods: 405; token absent, false, from another finding or from another workspace: 403; all without writing and, for ask, without contacting **P**. | W |
| AC13 | What is written is the saved proposal, not the request's text: WHEN the POST carries `valor` (value), a different `campo` (field) or other fields, THEN they are ignored. An accepted apply changes only that field and `updated` through `set_row(expect=…)` under the lock; the rest of the row and the other rows remain byte for byte equal. WHEN the row changed since it was shown, THEN 409, does not write, and the proposal remains available. | W |
| AC14 | For each applicable field, applying through the web and `findings.py set --<campo>` with the same value over copies of the ledger give the same result (both refuse, or rows equal except `updated`). | W |
| AC15 | "Deshacer" (Undo) leaves the field as it was before applying (also absent, according to D5) only if the row did not change since the apply; if it changed, 409 without writing. A second submission does not write twice. | W |
| AC16 | The mark "vía chat · hora" is seen in the section while the field's value is the applied one, and disappears if another writer (CLI, agent) changes it. `render` and the three downloads are byte for byte equal with and without chat history. | W |
| AC17 | 10 applies on different rows and 10 `findings.py add` at once leave the 10 changes and the 10 rows; `findings.py list` exits 0. | W |
| **History** | | |
| AC18 | The history lives per finding id under `engagements/<ws>/` (D6), in a regular file with mode `0600` opened without following links; it survives a module restart; it is not mixed between findings nor workspaces; it is covered by `.gitignore`; neither the index, the list nor the report reads it. A row without a unique id has no chat. | W |
| AC19 | WHEN the history reaches its cap, THEN a new question is rejected saying the history must be emptied (nothing is discarded silently). "Vaciar" deletes the file and no page shows its content again. | W |
| **Failures and concurrency** | | |
| AC20 | No Provider, connection refused, 401, 5xx, timeout, invalid JSON or empty response: the page says in Spanish what happened, that nothing was written to the ledger, keeps the question in the composer (escaped) for "Reintentar" (Retry), and the error is not fed back as context. | W + P |
| AC21 | Only one question in progress in the whole module: WHEN another arrives (any finding or workspace), THEN 409 "hay una pregunta en curso" (a question is in progress) without contacting **P**. Every request carries in `model` the model of D7 and never another. WHEN the browser cuts the request (or presses "Detener", according to D2), THEN the module closes the connection with **P** in ≤ 2 s and saves what was received marked "detenido" (stopped), without an applicable proposal. | W + P |
| **Brand** | | |
| AC22 | The assistant's avatar is the kit's isotype and the header the horizontal logo, in colour/white variant with the dark theme and black with the light one, from a reduced local copy versioned in the repo (with its origin noted); no page requests an external resource and the V3's generic "G" and its flash icon do not appear. The glyphs the kit does not bring (send, back) are text or Unicode (D8). | W + §7 |
| **Gate** | | |
| AC23 | The new cases run in **W**; `.githooks/pre-commit` runs them when touching `findings.py`, `findings_web.py` or `sanitize_target_content.py`; the `REQ ↔ case` trace stays green with the reconciled `REQ`s. | H + G |

## 6. Risks / limits this spec accepts
- **Data leaving the target.** The Provider is the operator's machine, not a third party, but it is another host: title, target, command and — with the switch — evidence output (which may carry secrets, limit of REQ-RPT-021) cross the network, in clear if the URL is `http` on a LAN. It is the same trust Pi already uses today; for a real client it clashes with the wording of `engagement-authorization.md` §2 ("client data never leaves this repo/host"): D10.
- **Non-exhaustive sanitising.** `sanitize` is pattern-based (REQ-FW-001): a new injection reaches the model. The defence that matters is that the answer executes and writes nothing without the operator's click (AC9–AC11).
- **The click does not prove a human read it.** The HMAC token is CSRF protection, not a human in the loop: a process of the same UID can request the page and apply (limit of REQ-RPT-019), and it could already write the file.
- **Shared GPU.** A question competes with the agent for the single resident model; the first one after a change pays the load. The total time of AC6 has to cover that load.
- **The applied text is the model's.** The mark "vía chat" lives outside the ledger (D9): the report does not say what the model drafted.
- AC4 tests the sanitiser's patterns, not "any injection"; AC9 tests the hostile values listed.

**For `plan.md`:** fixed proposal format and its parser; how a value is validated without duplicating `_optional_fields` (AC14 fails if there are two rules); counter of neutralised patterns; history, answer and time caps; how the browser's cut is detected; resolution of the Provider name and connection by IP; exact path of the actions and their fit in `respond`.

## 7. Signs of "done"
`bash tools/report-test.sh`, `.githooks/test.sh` and the gate green + `tasks.md` checklist with its record +
a real run by the operator with the actual Provider on a test workspace with synthetic data: ask, apply and undo a remediation, a row with injection in the summary, Provider off, invalid key, a question while the agent uses the model, and screenshots in both themes at 1500 and 760 px.

## 8. Operator decisions
**Resolved on 2026-11-17** ("implementalo con tus recomendaciones" — implement it with your recommendations): D1 (a), D2 A, D3 as proposed, D4 only
`summary`/`impact`/`remediation` (CVSS and CWE are written by the operator through 019, with the V3 aesthetic), D5 (a),
D6 as proposed (inside `.gekko-web/`, see 019 D8), D8 (a), D9 (a), D10 allowed with the evidence output switch
off by default, D11 `report-module`. **D7:** the default profile — URL `GEKKO_LLM_URL`, key `GEKKO_PROVIDER_KEY`,
fixed model (today it matches `GEKKO_MODEL`), one question in progress per module. The V3 is a demo without a backend that only contributes style: what is "not adopted" from it is the demo's behaviour, not a clash.

Original wording of the options:
1. **D1 · Where the module takes URL and key from.** (a) It reads `.gekko-state/env` on each question, with the key of the `GEKKO_PROVIDER` profile (today the default profile → its key variable; the other profile → `GEKKO_LLM_KEY`); REQ-RPT-012 intact.
   (b) Add the variables to `DETACHED_ENV`: loosens REQ-RPT-012 and leaves the key in `/proc/<pid>/environ`.
   **I recommend (a)**, and the same key/provider as Pi's default profile (CLAUDE.md names `GEKKO_LLM_KEY`).
2. **D2 · Transport.** (A) Without JavaScript: POST, the server waits for the whole response, 303 to the detail; CSP intact; no flow and no fine "Detener" (cutting = cancelling the request in the browser). (B) An own script with hash, `fetch` to the module with a streamed response, `textContent` always; loosens REQ-RPT-007 (`script-src`, `connect-src 'self'`) and the gate does not run a browser. (C) `<iframe>` with `meta refresh`: needs `frame-src`/`frame-ancestors 'self'` and loses scroll. **I recommend A** in this spec and B in its own. It departs from the design ("the flow is what I would not cut", design.md §8.1).
3. **D3 · Admitted hosts.** Only `127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16` and `100.64/10` (the CGNAT range, RFC 6598);
   a name is resolved once and connected to that IP; `http` admitted only in those ranges. **I recommend that.**
4. **D4 · Applicable fields.** The design says summary, impact, remediation, steps, CVSS, CWE. Clashes: CLAUDE.md "never guess a CVSS/CWE/CVE", and `set` does not write `repro`, so "steps" would be a capability the CLI does not have.
   **I recommend** only `summary`, `impact`, `remediation`; CVSS/CWE are discussed but without "Aplicar"; steps and blocker (question 4 of design.md §8.5), out.
5. **D5 · Undo on a field that did not exist.** (a) `set_row` gains deleting one of the applicable keys, only for undo, with `expect`. (b) `""` is left. (c) No "Deshacer" in that case. **I recommend (a).**
6. **D6 · History.** `engagements/<ws>/.gekko-chat/<sha256(id)>.jsonl`, `0600`, cap 256 KiB per finding, rejection when full; the retention of `AUTHORIZATION.md` applies to it. **I recommend that** (design.md §8.5 p. 8).
7. **D7 · Model.** Always `GEKKO_MODEL` (Pi's), no selector, so as not to evict the agent's model; one question in progress per module. **I recommend that.** The "responds / which model serves" state in Settings comes from the last question or from a "Probar" (Test) button, never from a GET (AC5).
8. **D8 · Brand.** The kit only brings PNG (isotype 1087×1007 px, 237–550 KB). With PNG the CSP **cannot stay the same**: (a) reduced PNGs (≤ 8 KB) as `data:` inside the hashed CSS, as with the font of REQ-RPT-017;
   the CSP gains only `img-src data:` and REQ-RPT-007 stops requiring "zero `<img`" if `<img>` is used. (b) Static path and `img-src 'self'`: new route. (c) Redraw the isotype in SVG: CSP intact, but it is no longer the kit's file.
   **I recommend (a)** for the avatar, the header horizontal logo and the favicon (not verified whether a `data:` favicon is governed by `img-src` in Firefox); the collapsible-bar mark goes with 019. Today the module brings no send/download/back icons: the only `<svg>` is the gear, so those glyphs would be text/Unicode or new SVG.
9. **D9 · "vía chat" in the report.** (a) Only on the web, saved in the history (it invalidates itself when the field changes). (b) A new key in the row and a line in the report. **I recommend (a).**
10. **D10 · What is sent.** Title, severity, state, target, summary, impact, remediation, steps, CVSS, CWE, CVE, KB, command, artifact path (never its content), corroboration, blocker; evidence output only with the switch; never the workspace name, `scope.txt` nor other rows. For real client engagements: is it allowed, or does the chat turn off while `AUTHORIZATION.md` exists? **I recommend** allowing it with the output switch off by default, and that you confirm it against §2 of `engagement-authorization.md`.
11. **D11 · Branch.** Precedent: `report-module`. **I recommend** that one, merging by the same path as 016/017.
