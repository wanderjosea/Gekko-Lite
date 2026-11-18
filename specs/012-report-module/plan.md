# Technical plan 012 — Report module (web viewer of findings)

> Status: `APROBADO` (operator, 2026-11-15). The coding is done by a Sonnet 5.5 agent (operator's decision).
> Spec: [`spec.md`](spec.md) (`APROBADA`, 2026-11-15, Amendment 1) · Feature branch, base `61bb445`
> Version 4 of the plan: Amendment 1 (one module on a fixed port, all workspaces) + Amendment 2 (only the
> operator's user reads it) + Amendment 3 (new code is picked up with a button, no polling).

## 1. Approach
Standard-library Python, no dependencies and no JavaScript. `findings.py` gains the fields, the lock and a single
reader (`_scan`) with two policies: the CLI aborts on a bad line, the module shows it. The module is a new file,
`.claude/tools/findings_web.py`, which only imports the reader: it never imports `_save`. It serves a
**root** (`<root>/engagements/*`), not a ledger: it discovers the workspaces on every request, so a new one appears
by itself, with no registration. All its logic is a pure function `respond(method, path, host, …) → (code, headers,
body)`; the socket only calls it. The launcher starts nothing on its own: it calls `ensure`, which detects the
active module and attaches, or starts it detached from the terminal.

## 2. Contracts

**Environment**
| Variable | Value | Set by |
|---|---|---|
| `GEKKO_REPORT` | `0`: the launcher neither starts nor attaches (default: on if there is a workspace) | operator |
| `GEKKO_REPORT_PORT` | fixed port; default `4355` | operator |
| `GEKKO_REPORT_URL` | `http://127.0.0.1:<port>/` (base URL); **absent** if there is no module | launcher (always deletes it on entry) |
| `GEKKO_WS_ROOT` | already existing test seam: alternative root (default: the repo's) | tests |

**`findings.py`**
```python
_scan(ledger) -> (rows, bad)   # rows: [(n_línea, dict)] · bad: [(n_línea, texto)] — no-JSON, no-objeto o no-UTF-8
_load(ledger) -> [dict]        # = _scan; si hay bad → exit "corrupt ledger … at line N" (AC30)
_locked(ledger)                # candado exclusivo (flock) sobre el directorio del ledger; envuelve leer→escribir
```
- `add` and `set` accept `--summary --impact --remediation --cvss --cwe --cve`. They are validated before touching the row.
  In the row they go at the top level and only if they were passed (`cvss` as a number).
- `add` rejects `confirmed` and `needs_validation` inside `cmd_add` (not in argparse: the selftest calls the function).
- The file is read as bytes and each line is strictly decoded: a non-UTF-8 line is `bad`, never
  rewritten with substituted characters.

**`findings_web.py`**
```
python3 .claude/tools/findings_web.py serve     # primer plano; imprime la URL; Ctrl-C lo apaga (comando suelto)
python3 .claude/tools/findings_web.py ensure    # lo usa el lanzador: se acopla o levanta; imprime la URL base
python3 .claude/tools/findings_web.py selftest
  --root <dir>  (por defecto $GEKKO_WS_ROOT o la raíz del repo)     --port N  (por defecto $GEKKO_REPORT_PORT o 4355)
```
| Route | Response |
|---|---|
| `GET /` | workspace index (reloads itself every 15 s) |
| `GET /w/<nombre>/` (`?q=<texto>&sev=<severidad>`) | the workspace's findings list |
| `GET /w/<nombre>/f/<n>` | detail of the row at line `n` of that ledger |
| `POST /actualizar` | takes the new code if it changed and compiles; responds with a result page that returns to the index after 2 s |
| any other method, or POST to another route | 405 |
| `POST /actualizar` with `Sec-Fetch-Site` present and different from `same-origin` | 403, does not change code |
| any other route, invalid or nonexistent name | 404 |
| `Host` different from `127.0.0.1:<port>` or `localhost:<port>` | 403, fixed body with no data |
| the other end is not the same UID as the module, or could not be determined | 403, fixed body with no data |

Headers on every response: `Content-Security-Policy: default-src 'none'; style-src 'sha256-<hash del CSS>';
form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and
`X-Gekko-Report: <16 hex de sha256(ruta real de la raíz)>.<12 hex de sha256(código cargado)>`.

**User of the other end (AC36)**
```python
peer_uid(tabla, puerto_cliente, puerto_servidor) -> int | None   # pura: busca la conexión 127.0.0.1:cliente → 127.0.0.1:servidor
```
On every request the module reads `/proc/net/tcp`, calls `peer_uid` and serves only if the result is its own
UID. No row, no file or a read error: 403.

**Code update (AC37–AC39)**
No thread and no polling. The header of every page carries a POST form to `/actualizar` with the
«Buscar actualizaciones» button. When building each page the module compares the hash of `findings_web.py` and `findings.py`
on disk with the one it loaded at startup; if they differ, it announces it next to the button (AC38). On receiving the POST:
- no changes → «is up to date» page;
- changes that do not compile (`py_compile`) → page with the file that fails; it continues with the loaded code;
- changes that compile → it responds with the «updated» page, finishes sending it, closes the server and the
  process replaces itself (`os.execv`, same PID, same arguments) and takes the port again.

**`ensure`** (exit 0 + URL on stdout, or exit 1 + reason on stderr)
| What it finds on the port | What it does |
|---|---|
| nobody listens | starts `serve` detached (own session, no terminal), waits ≤ 3 s for it to respond with its root |
| responds with `X-Gekko-Report` whose first part is **this** root | attaches: starts nothing |
| responds with something else, another root, or does not respond in time | exit 1: port occupied |
| the `serve` it started died (another launcher won the port) | probes again; if it is now this root's, attaches |

Errors of the detached module go to `<root>/.gekko-state/report.log`. It does not log requests.

## 3. Affected files
| File | Change | AC |
|---|---|---|
| `.claude/tools/findings.py` | fields + validation, `render`, `_scan`/`_load`, `_locked`, refusal in `add`, selftest with `REQ` cases | AC1–AC4, AC27, AC28, AC30 |
| `.claude/tools/findings_web.py` (new) | workspace discovery, `respond`, HTML/CSS templates, server on `127.0.0.1`, `peer_uid`, update action, `ensure`, selftest | AC5–AC16, AC22, AC29, AC32–AC39 |
| `tools/report-test.sh` (new) | the single command: runs the two selftests + process cases (standalone command, prompt `grep`) | AC22, AC25, AC26 |
| `tools/pi-hitl.sh` | delete `GEKKO_REPORT_URL`, call `ensure`, banner line with the workspace URL, warning if it fails | AC17–AC21 |
| `tools/ws-test.sh` | P cases; `GEKKO_REPORT=0` for spec 010's cases and its own free port for the new ones | AC17–AC21 |
| `toolbox/gekko-panel.ts` | `validReportUrl`, `PanelExtras.reportUrl`, `PanelIo.reportUrl()`, row in the card | AC23, AC24 |
| `toolbox/gekko-guard.ts` | `reportUrl: () => process.env.GEKKO_REPORT_URL`; the gate runs the two Python selftests and counts their cases | AC23, AC26 |
| `toolbox/gekko-panel-selftest.ts` | cases for the row and for `validReportUrl` | AC23, AC24 |
| `toolbox/gekko-workspace-selftest.ts` | static contract of the launcher (like REQ-WS-007) | AC17, AC19, AC20 |
| `.githooks/pre-commit` | boundary list + run `tools/report-test.sh` if the commit touches the ledger or the module | AC26, AC31 |
| `.githooks/test.sh` | hook cases with a fake `report-test.sh` in a disposable repo | AC26, AC31 |
| `specs/SECURITY-GUARDRAILS-SPEC.md` | §1 (two new files), §2a (Python sources), `REQ-LED-*`, `REQ-RPT-*`, `REQ-TUI-027`, limits | all |
| `.claude/agents/finding-analyzer.md`, `.claude/agents/exploit-developer.md`, `.pi/agents/finding-analyzer.md` | new fields + do-not-invent rule | AC25 |
| `docs/pi-hitl.md`, `tools/pi-hitl.env.example`, `CLAUDE.md`, `AGENTS.md` | the module, its variables, the standalone command and how to shut it down | — |

## 4. Decisions (resolves the spec's open ones)
- **New file for the module.** Its not importing `_save` makes the "read-only" property auditable with a `grep`; the
  cost is two lines in the boundary list.
- **The module serves the root and discovers workspaces on every request.** "Attaching" needs no registry: the
  new workspace is one more directory. Discovery rule = the launcher menu's (directory with
  `scope.txt`, valid name, real path inside `engagements/`).
- **The name rule is copied into Python and compared with the TypeScript one in a case** (AC35), just like the
  counters against `countFindings`. The validated name is the only thing of a workspace that goes into a URL.
- **Identity by header.** `ensure` only attaches if `X-Gekko-Report` matches the hash of its root. Another
  worktree on the same port counts as an occupied port (AC20): another root's module is never shown as one's own.
- **All the attach logic lives in `ensure` (Python), not in bash.** The launcher only calls it and exports the URL.
- **Detached module, no watchdog.** `ensure` starts it in its own session so it survives the closing
  of tmux and of the terminal. It is shut down with `pkill -f 'findings_web.py serve'` (documented); no subcommand and no
  PID file.
- **Two simultaneous starts are resolved at `bind`.** Both try to start; the system lets one win
  and the other, on seeing its process die, probes again and attaches.
- **No JavaScript.** Search and filter are a GET form resolved on the server: they are tested without a browser
  and the content policy can forbid all scripts.
- **CSS in the page, allowed by hash.** Avoids an extra route (AC15) and avoids `unsafe-inline`. No `style`
  attribute; classes come from a fixed list, never from a ledger value.
- **The detail is addressed by line number** (`/w/<nombre>/f/<n>`). AC10 forbids ledger strings in a
  link, and a hand-written row with a repeated or hostile id still has to have a detail. (Already covered in AC9.)
- **One reader, two policies** (`_scan`). The CLI and the module cannot diverge again on what a row is.
- **Lock on the directory, not on the file.** `_save` replaces the file by `rename`, so a
  lock on it does not protect the next process. The directory does not change and leaves no extra file among
  the evidence. Linux only (`fcntl`), like the rest of the repo.
- **The panel shows the base URL** and only accepts `http://127.0.0.1:<1–5 digits>/`; the URL with the workspace
  name (up to 57 characters) does not fit in 36 columns and goes in the banner. Measured: `redactSummary` leaves the
  base URL intact.
- **Reload:** the index reloads itself every 15 s (so the new workspace is "noticed"); list and detail are
  manual, so as not to lose the reading position.
- **Python cases in the gate trace.** Each case prints `ok REQ-<AREA>-<NNN> <description>`; the gate runs
  the two selftests and adds those lines to the same counters. A `REQ` without a case or an unknown id fail
  as today. Exit ≠ 0 of the selftest = red gate.
- **AC28 inside `findings.py selftest`**: launches 20 real `add` processes. `tools/report-test.sh` runs it.
- **W tests with Python's `http.client`** against the real module on a free port; `curl` only for the standalone command.
- **Design:** dark, system fonts, lime accent `#C0F425`, badges by severity, same structure
  as the screenshots (counters, table, detail cards) plus the index page. No light theme.
- **Hook:** runs against the working tree, not against what is staged for the commit. If `tools/report-test.sh`
  is missing and the commit touches the ledger or the module, it rejects.

- **Only the operator's user, by the other end's UID, not by token** (AC36). A token in the URL forces
  cookies and storing a secret, and does not fit in the panel; the UID changes nothing for the operator and leaves out
  the other system users and the root of a container with host networking. The `Host` check
  stays: it protects against the operator's own browser (DNS rebinding), which is of the same UID.
- **New code is taken with a button, not with polling** (Amendment 3). The module replaces itself:
  it keeps the PID and the port and does not need to know who started it. During the replacement (tenths of a second)
  the port does not respond; if `ensure` falls right there, it tries to start another and loses the `bind`, as in AC21.
- **The button is the only POST action.** There is still no JavaScript: it is a form, which the content
  policy already allows toward the same origin. It touches no workspace and does not go out to the network.
- **Rejection from another origin by `Sec-Fetch-Site`, not by token** (AC39). A hidden token is invalidated on every
  replacement and leaves old tabs with the button broken; the header keeps no state. The `Origin` header
  does not work here: with `Referrer-Policy: no-referrer` the browser sends it as `null` also from the same origin.
- **New-code notice when building the page** (AC38): two file reads per request, only when someone
  opens a page.
- **AC37's tests run on a copy** of the two files in a temporary directory: they never
  modify the repo's.

## 5. Risks and mitigation
- The second `bind` to the same port does not fail (socket reuse option) and two modules remain → falsifier: two
  `serve` in a row on the same port; the second must exit with an error.
- The detached module dies anyway when tmux closes → falsifier: P case that kills the tmux session and requests the URL again.
- `peer_uid` lets another real user through → falsifier: `docker run --rm --net=host gekko-toolbox:latest` requesting
  the URL (container root = UID 0 ≠ 1000) must receive 403; it is run before building the rest and is
  recorded in `tasks.md`. Already measured: for a client of our own `/proc/net/tcp` returns the correct UID.
- `peer_uid` rejects the operator themselves (different `/proc/net/tcp` format, sandboxed browser) → the real-connection
  case of the same user runs in W, and the real run with the browser confirms it.
- The replacement cuts the button's response or leaves the port taken → falsifier: on the copy, POST with a change
  and check that the result page arrives whole, that a single process remains with the same PID and that the
  next GET brings the new hash.
- The operator's browser does not send `Sec-Fetch-Site` and the button is always accepted or always rejected →
  checked in the real run with their browser.
- The URL row does not fit at 36 columns → falsifier: `renderRail` at 36 with the row; if it does not fit, the URL goes
  alone in the label.
- `flock` on a directory does not work on the workspace's filesystem → falsifier: the 20 `add` (today they give
  17 rows); if it fails, lock on a sibling `.lock` file.
- The tests touch the operator's real module on 4355 → all tests use a temporary root and their own free
  port, and shut down only processes whose command line names that root.
- Spec 010's cases in `ws-test.sh` start launching modules → they run with `GEKKO_REPORT=0`.
- A row with odd types (list title, text evidence, numeric status) takes down the page and hides everything →
  coercion to text in a single place + a case with a mixed-types row.
- A huge ledger slows the index (it reads all ledgers on every load) → not optimized; measured with
  20 workspaces of 200 rows and noted in `tasks.md`.
- The module's selftest depends on `node` to compare with `countFindings` and `validWorkspaceName` → if `node`
  is missing, the case fails (the gate already demands it).
- The hook is slow → measured at the end and noted in `tasks.md`; target < 5 s.
- An inherited `GEKKO_REPORT_URL` value (from the tmux server's environment) shows a URL nobody verified → the
  launcher always deletes it before deciding (P case, same pattern as AC13 of spec 010).

## 6. Order of attack
1. Six cheap falsifiers: another real user with docker (AC36), update button on a copy (AC37), second `bind`,
   detached module after closing tmux, row at 36 columns, directory `flock`.
2. `findings.py`: first the cases that fail today (AC27, AC28, AC30), then the fix, then the fields.
3. `findings_web.py`: discovery + `respond` + in-process selftest; then the socket; then `ensure`.
4. Launcher + P cases.
5. Panel + S cases.
6. Gate bridge, hook and `.githooks/test.sh`.
7. Prompts, docs and reconciliation in the living spec.
8. The five commands of the spec's §7 green at the same time; real run of `pi-hitl.sh` with two workspaces and
   screenshots of the module in the browser.

Steps 2–5 touch different files and only share the contract of §2: they can be split among agents
in `tasks.md`.

## 7. Deviations on implementation (2026-11-15)
- **Spec Amendment 4 (T26 audit).** The accepted `Host` is only `127.0.0.1:<port>` (§2 said `localhost` too).
  A pair from another user has its connection closed on accept (§2 said 403); the fixed 403 stays for
  a foreign `Host` and carries no `X-Gekko-Report`. `peer_uid` also receives the source address.
- **`ensure`** additionally checks that whoever listens on the port is of the same UID (`listener_uid`), does not read the body of
  the response and starts the module with a minimal environment.
- **`findings.py`**: `_scan` splits only on `\n` and also treats as a bad line oversized integers, extreme
  nesting and `NaN`/`Infinity`; `_save` creates the temp file exclusively and writes lone surrogates as an escape;
  `render` keeps on one line everything that goes outside a fence; a blank corroboration does not count.
- **G5 (hook) ran in wave 2**, in parallel with the module, because their files do not overlap.
- **No change:** the rest of §2–§4.
