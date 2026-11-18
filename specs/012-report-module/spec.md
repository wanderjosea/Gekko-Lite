# Spec 012 — Report module: web viewer of findings (all workspaces, read-only)

> Status: `IMPLEMENTADA` (operator's real run closed 2026-11-16; approved 2026-11-15) · **Amendment 1** (operator, 2026-11-15): a single module on a
> fixed port that shows all workspaces; a new session attaches to the one that is already active. The wording of the
> criteria the amendment changes (AC9, AC12, AC15–AC23, AC32–AC35) awaits the operator's approval.
> **Amendment 2** (operator, 2026-11-15): two limits of Amendment 1 become criteria — only the operator's user
> may read the module (AC36) and the module picks up new code without a manual restart (AC37).
> **Amendment 3** (operator, 2026-11-15): new code is picked up by pressing a «Buscar actualizaciones» button in
> the web page, not by periodic polling (AC37 rewritten, AC38, AC39; AC12 and AC15 adjusted).
> **Amendment 4** (2026-11-15, hardening after the T26 security audit; it only tightens, never loosens;
> the operator said to go with it on 2026-11-15): AC14 and AC36 stricter and AC40 new.
> **Amendment 5** (operator, 2026-11-15, after seeing the module in their browser): «Buscar actualizaciones» moves to a
> collapsible settings menu with a gear button, and the module gains a light and a dark theme (AC41, AC42; AC12, AC15
> and AC38 adjusted).
> Date: 2026-11-15 · Design source: the «Vulnerabilities» view of Pentest Copilot (list + detail, operator's screenshots of
> 2026-11-13) + operator decisions of 2026-11-15 (§8) · Feature branch, base `61bb445`

## 1. Problem (one sentence)
The operator only sees findings as six integers in the HALLAZGOS card (`toolbox/gekko-panel.ts:960`; by design,
REQ-TUI-018 forbids a row field from reaching the panel) or as `findings.py list|render` text in the
terminal, and the ledger stores no summary, impact, remediation, CVSS, CWE or CVE (`.claude/tools/findings.py:74-85`).

## 2. Goal (one sentence)
The operator opens a fixed local URL and browses all workspaces: for each one they see the findings list and the
detail page with narrative and classification, without the module being able to change a ledger or show a status
different from the one the ledger says; a new workspace appears there without starting another server.

## 3. Context / why now
Spec 010 left one ledger per workspace (`GEKKO_FINDINGS = <workspace>/findings.jsonl`, `tools/pi-hitl.sh:116`),
so there is already one source per workspace to show. Read in the code (base `61bb445`):
- `findings.py selftest` does not run in any gate: only `PORTING.md:97` names it, as a manual step. The
  corroboration rule (`findings.py:108`) has no `REQ` in the living spec. This spec adds fields and a new reader
  over that file, which is on the boundary (§1 of the living spec).
- The ledger reader (`_load`, `findings.py:42`) aborts on a line that is not JSON; the panel counts that same
  line under `otros` (`countFindings`). Today the two readers give different answers for the same file.
- `evidence.output`, `title` and `target` carry text that comes from the target. Showing it in a browser is a new
  path: unescaped HTML runs in the operator's browser.
- In Full VPN mode the operator's host is on the VPN: a server listening on all interfaces publishes the findings
  to that network (`scope.md`: target data does not leave the host).
- `pi-hitl.sh` allows two simultaneous launches of different workspaces (`:140`, one prompt per workspace).
- A workspace is a directory of `<root>/engagements/` with `scope.txt` and a name that satisfies REQ-WS-001; the
  launcher menu already lists with that rule (REQ-WS-005). The root is the repo's (`toolbox/gekko-workspace.ts:329`),
  and each worktree has its own `engagements/` (gitignored): two worktrees are two roots.
- `engagement-authorization.md` §2 asks not to mix one client's data with another's.

Measured on 2026-11-15 on a temporary ledger (base `61bb445`):
- `findings.py add --status confirmed` without a second signal exits 0 and leaves the row `confirmed`; likewise
  `--status needs_validation` without a blocker. The refusal only exists in `set`. All prompts use
  `add --status hypothesis`.
- With a broken line, `list`, `render` and `add` exit 1: nothing more can be registered until it is repaired by hand.
- A line that is valid JSON but not an object (`42`) passes `_load` and breaks `list` and `add` with a traceback.
- 20 simultaneous `add` left 17 rows: three findings lost with exit 0 (read–modify–write without a lock).
- No hook or CI runs a selftest: `.githooks/pre-commit` runs none and there is no `.github/workflows`.
- Port 4355 is free on the operator's machine and outside Linux's ephemeral range (32768–60999).
- The operator's home has `710` permissions: another system user cannot read `engagements/`, but can
  connect to a loopback port. Without a check, the module would give other users (and a container
  with host networking, which runs as root: docker is rootful) an access the files do not give.
- `/proc/net/tcp` reports the owner UID of the other end of a live loopback connection (tested: it returns
  1000 for a client of our own; for an already closed socket it returns 0).

## 4. Scope
**In:**
- **Ledger:** six new optional fields per finding: `summary`, `impact`, `remediation`, `cvss`, `cwe`, `cve`.
  They are loaded with `add` and corrected with `set`. `cvss`, `cwe` and `cve` validate format. Old rows stay valid.
- **Ledger, hardening** (risk review, AC27–AC30): `add` stops accepting `confirmed` and
  `needs_validation`, simultaneous adds do not lose rows and a line that is not an object is treated as a
  corrupt ledger.
- **Hook:** `.githooks/pre-commit` runs the ledger and module cases when the commit touches those files (AC31).
- **`render`** (the report) shows the new fields of the findings it projects.
- **Prompts** of the agents that write to the ledger: they ask for the new fields and forbid inventing CVSS/CWE/CVE.
- **Report module** (Amendment 1): one server per root, on a fixed port (4355 by default), with three
  pages: workspace index, a workspace's findings list (counters, search, severity filter)
  and a finding's detail. It shows all statuses. Read-only, loopback only, no external resources.
- **Startup** (Amendment 1): `pi-hitl.sh` starts it if it is not active and, if it already is, attaches to the existing one.
  The module does not die with the session: it stays up until the operator shuts it down. A standalone command is left to
  start it without Pi.
- **Panel:** the HALLAZGOS card adds a row with the module URL when it is available.
- **Gate:** the ledger and module cases run in one command with exit 0/≠0, and their criteria are reconciled
  into the living spec on merge (`REQ-…`).
- **Docs:** `docs/pi-hitl.md` and `tools/pi-hitl.env.example` name the module, its variables and how to shut it down.

**Out (explicit, anti scope-creep):**
- Downloading the report from the web, per-finding chat and changing status from the web: next specs (§8).
- Serving files: evidence artifacts, `loot/`, `findings.jsonl` itself. The artifact path is shown as text.
- Access from another machine and login. Loopback only; viewing it remotely is an operator SSH tunnel.
- «Exploited» mark, CVSS vector, service/endpoint split and lifecycle (remediated/accepted).
- Listing findings in the TUI or changing the panel's counts and bar.
- Searching or mixing findings across workspaces: each page belongs to a single workspace.
- Automatic shutdown of the module and a dedicated subcommand to shut it down (the system command is documented).
- Showing in the index which workspaces have a live session.
- Filling in the new fields on already registered findings.
- The other launchers: `tools/gekko-toolbox.sh` and the autonomous experiment runner (not included in Lite).

## 5. Acceptance criteria (testable)
> Tests: **L** = `python3 .claude/tools/findings.py selftest` (existing, extended). **W** = `bash tools/report-test.sh`
> (new: starts the real module over a temporary root and hits it with an HTTP client; loopback only). **P** =
> `bash tools/ws-test.sh` (existing: real launcher with a fake `pi`). **S** = panel selftest
> (`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`).
> «Hostile content» = the values `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`,
> `</pre><svg onload=alert(1)>`, `javascript:alert(1)` and an ANSI escape sequence.
> **(E1)** = criterion new or changed by Amendment 1.

| # | Criterion (observable) | Test |
|---|---|---|
| **Ledger** | | |
| AC1 | `add` stores `summary`, `impact`, `remediation`, `cvss`, `cwe` and `cve` when they are passed, and `set` changes them on an existing finding; a row created without them keeps working in `list`, `render` and `set`. | L |
| AC2 | `cvss` only accepts a number from 0.0 to 10.0, `cwe` the form `CWE-<digits>` and `cve` the form `CVE-<4 digits>-<4 or more digits>`. WHEN the value does not comply, THEN the command exits ≠ 0, the message names the field and the ledger stays byte-for-byte the same. | L |
| AC3 | `render` shows the six fields of each finding it projects; a value with backticks or line breaks does not break the code block (same rule as the evidence today). | L |
| AC4 | Today's two refusals hold when the same `set` carries new fields: `confirmed` without corroboration and `needs_validation` without a blocker exit ≠ 0 and write nothing, not even the new fields. | L |
| AC27 | WHEN `add` receives `--status confirmed` or `--status needs_validation`, THEN it exits ≠ 0 and writes nothing: those two statuses are only reached with `set`, which demands corroboration or a blocker. | L |
| AC28 | WHEN 20 `add` processes run at once over the same ledger, THEN 20 rows with 20 distinct ids remain. | W |
| AC30 | WHEN a line is valid JSON but not an object (`42`, `[]`, `null`, `"x"`), THEN `list`, `render`, `add` and `set` exit ≠ 0 with the corrupt-ledger message and the line number, without a traceback. | L |
| **Workspaces (E1)** | | |
| AC32 | (E1) The index lists each workspace of the root (directory of `engagements/` with `scope.txt` and a valid name per REQ-WS-001) with its name, total, criticals, highs, confirmed/total and date of the last change; it does not show the title, target or evidence of any finding. A workspace without `findings.jsonl` appears with zeros. | W |
| AC33 | (E1) WHEN a workspace is created with the module already up, THEN it appears on the next index load without a restart; WHEN it is deleted, THEN it disappears and its pages respond 404. | W |
| AC34 | (E1) Each list and detail page shows findings of a single workspace: with two workspaces loaded, no page of one (list, search, detail) contains data from the other. | W |
| AC35 | (E1) A name that does not satisfy REQ-WS-001, a directory without `scope.txt` and a symbolic link that leaves `engagements/` do not appear in the index and their addresses respond 404. The module's name rule accepts and rejects the same as `validWorkspaceName` (`toolbox/gekko-workspace.ts`) over a list of test names. | W |
| **List** | | |
| AC5 | A workspace's list shows one row per finding of its ledger, in any status, with id, severity, title, target, status, CVSS, CWE and update date; ordered from `critical` to `info` and, at equal severity, the most recent first. | W |
| AC6 | The counters (total, criticals, highs and confirmed/total), in the list and in the index, come from the ledger; the confirmed/total pair equals the one `countFindings` gives (`toolbox/gekko-panel.ts`) over the same file, including a ledger with an unknown status, a row without status and a line that is not JSON. | W |
| AC7 | WHEN a row has an unknown status or no status, THEN it is shown with that text or as «sin estado» (no status), never as confirmed. WHEN a line is not a JSON object (broken text, `42`, `[]`, `null`), THEN the page warns above the list with the line number, shows that line's text escaped, says that the ledger accepts no adds or `render` until it is repaired, and keeps showing the other rows. | W |
| AC29 | WHEN a row is `confirmed` and carries no `corroboration`, THEN list and detail mark it «sin corroboración» (no corroboration); it still counts in confirmed/total, same as in the panel. | W |
| AC8 | WHEN I request the list with a search text, THEN only the rows containing it in title, target, CWE or CVE remain, case-insensitive; WHEN I request a severity, THEN only those of that severity; with no matches the page says so and the counters do not change. | W |
| **Detail** | | |
| AC9 | (E1) A finding's page shows severity, status, title, target, CVSS, CWE, CVE, summary, evidence (command, artifact path, output), corroboration, blocker, steps to reproduce, impact, remediation, KB and dates. An absent field is shown as «—». A finding or workspace address that does not exist responds 404. | W |
| **Module security** | | |
| AC10 | WHEN any field of a row (id, title, severity, status, target, summary, impact, remediation, evidence, steps, KB, corroboration, blocker, CWE, CVE) carries hostile content, THEN list and detail return it as escaped text: no ledger string appears as a tag, attribute or link destination. | W |
| AC11 | Every response carries a content policy that forbids running scripts and loading resources from another origin, and no page references an external origin (fonts, styles, images, scripts). | W |
| AC12 | (E1, E3, E5) The module does not write: after walking all routes with GET, pressing the update, changing the theme and trying PUT, DELETE and POST to any other route (which respond 405), the sha256 of each ledger is the same and no workspace directory has new files. | W |
| AC13 | The server listens only on `127.0.0.1`: a connection to another address of the same machine is rejected. | W |
| AC14 | (E4) WHEN the `Host` header is not exactly `127.0.0.1:<port>` (`localhost:<port>` is also rejected), THEN the response is an error and carries no data from any ledger nor the name of any workspace. | W |
| AC15 | (E1, E3, E5) Only the index, the list, the detail and two actions (update and choose theme) exist: `/findings.jsonl`, `/scope.txt`, `/loot/creds.md`, `/../scope.txt`, those same routes under a workspace and the artifact path respond 404; the artifact path in the detail is not a link. | W |
| AC36 | (E2, E4) WHEN the connection comes from a process of another system user (another UID, including the root of a container with host networking), or from an address that is not `127.0.0.1`, or the module cannot determine which user it comes from, THEN the request is rejected —connection closed or error— without any data from any ledger nor the name of any workspace. The owner is looked up by the exact connection (source address and port): another user who repeats the source port of a live operator connection from another loopback address is also rejected. A connection from the same user is served. | W + real run with docker (evidence in `tasks.md`) |
| AC40 | (E4) An anomalous row or file neither hides the rest nor leaves the workspace: WHEN `findings.jsonl` is not a regular file (symbolic link, FIFO, directory), THEN the module does not open it and says so; WHEN a row cannot be drawn, THEN the list marks it with its line number and shows the others; WHEN a status or severity is not exactly one of the known ones, THEN it is shown as «desconocido» (unknown), never with the bare word of a known one; WHEN a request carries a negative `Content-Length`, THEN the module responds without reading the body without limit. | W |
| AC16 | WHEN a ledger changes with the module up, THEN the next load reflects it without a restart. WHEN the file does not exist yet or is deleted, THEN the list says «sin hallazgos» (no findings) and shows those that appear later. | W |
| **Startup (E1)** | | |
| AC17 | (E1) With workspace X and no active module, `pi-hitl.sh` starts it on the fixed port; the banner carries a line with X's URL and that URL responds while Pi runs. | P |
| AC18 | (E1) WHEN Pi ends, THEN the module keeps responding. WHEN another session starts afterwards, THEN it uses the module that was already there: same process, no new one. | P |
| AC19 | WHEN `GEKKO_WORKSPACE=none`, or the module's shutdown variable is set, THEN the launcher neither starts it nor attaches, and there is no URL line in the banner. | P |
| AC20 | (E1) WHEN the fixed port is occupied by another program, or by a module serving another root (another worktree), THEN the launcher does not attach: the banner warns about it in one line, Pi starts anyway and no URL appears in the banner or in the panel. | P |
| AC21 | (E1) WHEN two launches with different workspaces start at once with no active module, THEN a single module process remains, both banners carry the same port and each workspace's URL shows only its ledger. | P |
| AC22 | (E1) A standalone command starts the same module without Pi and prints the URL; on interrupting it the port is left free. | W |
| AC37 | (E3) All pages carry a «Buscar actualizaciones» (check for updates) button. WHEN it is pressed and the module's file or `findings.py` changed on disk and compile, THEN within 5 s or less the module responds with the new code, on the same port and with nobody restarting it, and the browser returns to the index. WHEN they did not change, THEN the page says it is up to date. WHEN the new file does not compile, THEN the page says so and the module continues with the previous code. WHEN the files change and nobody presses the button, THEN the module keeps the loaded code: it does not check on its own in the background. The button downloads nothing: it only takes what is already on disk. | W |
| AC38 | (E3, E5) WHEN the code on disk differs from the loaded one, THEN all pages announce it next to the gear, visible with the menu collapsed, and also inside the menu next to the button; the comparison is made when the page is built, not in the background. | W |
| AC41 | (E5) All pages carry, on the right of the top bar, a gear button with the accessible name «Ajustes» (Settings) that opens and closes a menu; the menu comes collapsed and contains «Buscar actualizaciones» and the theme choice. It works without JavaScript and without external resources (the gear is a drawing inside the page). | W |
| AC42 | (E5) The module has a dark theme and a light theme. With no choice it follows the system preference. WHEN the operator chooses «Claro», «Oscuro» or «Automático» (Light, Dark, Automatic) in the menu, THEN it returns to the page they were on and the choice is remembered across pages and across visits. The stored value can only be one of those three: any other is ignored and does not appear in the page. In both themes the text, links and severity and status labels have a contrast of 4.5:1 or more. A theme-change request that arrives from a page of another origin is rejected. | W + screenshots in both themes |
| AC39 | (E3) WHEN the update request arrives from a page of another origin, or by a method that is not POST, THEN the module rejects it and does not change code. | W |
| **Panel** | | |
| AC23 | (E1) With the module available, the open HALLAZGOS card carries a row with its full base URL (`http://127.0.0.1:<port>/`), neither redacted nor truncated at the rail's minimum width. | S |
| AC24 | Without a module (`none`, shut down or unavailable) the card carries no such row; the published state still contains no field of a ledger row (REQ-TUI-018 does not change). | S |
| **Prompts and gate** | | |
| AC25 | The prompts that send agents to write to the ledger (`.claude/agents/finding-analyzer.md`, `.claude/agents/exploit-developer.md`, `.pi/agents/finding-analyzer.md`) name the six fields and say that CVSS, CWE and CVE are left empty if there is no basis to assert them. | W |
| AC26 | A single command runs **L** and **W** and exits ≠ 0 if either fails; `.githooks/pre-commit` treats the module's file as part of the boundary. | `.githooks/test.sh` |
| AC31 | WHEN the commit carries changes in `.claude/tools/findings.py` or in the module's file, THEN `.githooks/pre-commit` runs the AC26 command and rejects the commit if it fails; WHEN the commit does not touch them, THEN it does not run it. | `.githooks/test.sh` |

## 6. Risks / open decisions
**For `plan.md`:**
- Where the server lives: a `findings.py` subcommand (reuses `_load`, no dependencies) or a new file. A new
  file enters the boundary list (§1 of the living spec and its mirror in `.githooks/pre-commit`).
- How the Python cases enter the `REQ ↔ case` trace: today the gate only counts `req("…")` markers in the three
  TypeScript selftests.
- How the launcher recognizes that what answers on the port is the module of its same root (AC20) and how it
  resolves two simultaneous starts (AC21).
- How the URL reaches the banner and the panel.
- A tolerant reader for the module (AC7) versus the `_load` that aborts: one function or two.
- Manual or automatic reload of the pages (AC16 and AC33 only require that the next load be faithful).
- How long the AC31 hook takes and whether that is acceptable on every commit that touches the ledger.
- Visual design (dark, Gekko brand, no external resources).

**Limits this spec accepts (they are written into the living spec on merge):**
- (E2, E4) There is no login. While the module is up, processes of the operator's **same user** read it.
  Almost all of them can already read the files, but there are two cases in which the module DOES add access: (a) a
  same-user proxy listening outside loopback (Burp, ZAP, mitmproxy on all interfaces) forwards requests to the
  module, and whoever reaches that proxy —including the VPN network— reads all the ledgers; (b) a rootless
  container with host networking runs with the operator's UID even without the repo mounted. Closing (a) and (b)
  requires authentication (a secret the forwarder lacks): the operator decided on 2026-11-15 to leave it
  documented for now (decision 12; notice in `docs/pi-hitl.md` §4c). If Gekko runs as root, any
  root process passes AC36, including a container with host networking.
- (E4) The new-code notice covers `findings_web.py` and `findings.py`, not everything else Python loads from that
  directory (a sibling `json.py` or a planted `__pycache__` are loaded without notice). Whoever can write the checkout
  —a container with the repo mounted writable— can already change any script the operator runs.
- (E4) A finding's title no longer goes into the page title, but the workspace name and the search text
  (`?q=`) do stay in the browser history, and in its sync if enabled.
- (E2) The gate tests AC36 with a table of test connections and a real connection of the same user; the
  refusal of a real other user needs docker or sudo and stays as a run recorded in `tasks.md`, not in the gate.
- (E2) AC36 depends on `/proc/net/tcp` (Linux). Where it does not exist or cannot be read, the module rejects everything.
- (E1) The index shows the names and counts of all engagements together. AC34 prevents mixing findings
  in a page; it does not prevent whoever looks at the screen from seeing that the others exist.
- (E1) One port serves one root. With an active module from another worktree, the session starts without a module (AC20)
  until the operator shuts down the other or sets another port.
- (E3) AC37 checks that the new file compiles, not that it starts: a file that compiles and fails on startup
  leaves the module down until the next `pi-hitl.sh` start, which starts it or warns (AC20).
- (E3) Until someone presses the button, the module continues with the old code; AC38 announces it in the page, but
  only whoever opens it sees it. The `pi-hitl.sh` banner does not announce it.
- (E3) AC39 relies on the `Sec-Fetch-Site` header that current browsers send; a browser that does not send
  it is not covered. The worst that request achieves is that the module takes the code that is already on disk.
- The card's row says where the module was available at startup, not that it is still alive.
- CVSS, CWE and CVE are what the agent wrote. The format is validated; whether the value is correct is not.
- AC10 tests the five hostile values listed, not «any XSS».
- The module shows `evidence.output` as it is in the ledger: if an agent stored a secret there, it is visible.
- AC31 depends on the hooks being active (`git config core.hooksPath .githooks`, a manual step in a new
  clone) and is skipped with `--no-verify`. There is no CI that repeats it.
- A row written by hand into the JSONL skips all the CLI's rules. AC29 makes it visible; it does not prevent it.
- With a broken line the module stays up and the ledger is left without adds: AC7 says so in the page, it does not fix it.

## 7. "Done" signals
`python3 .claude/tools/findings.py selftest`, `bash tools/report-test.sh`, `bash tools/ws-test.sh`,
`.githooks/test.sh` and the gate (`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`)
green at the same time + `tasks.md` checklist complete with its verification log. In addition, at the
operator's request for every feature: a real run of `pi-hitl.sh` with screenshots of the module in the browser.

## 8. Operator decisions (2026-11-15)
1. New ledger fields: narrative (summary, impact, remediation) + classification (CVSS, CWE, CVE), all
   optional. No «Exploited» mark.
2. Startup: with `pi-hitl.sh` and, in addition, a standalone command.
3. TUI: only the module URL in the HALLAZGOS card.
4. v1 = read-only list + detail. Downloading the report, per-finding chat and changing status from the web
   «should come later».
5. Risk review: «apply all the mitigations». AC7 expanded, AC27, AC28, AC29, AC30 and AC31 come in
   (the hook runs the cases). All six tighten; none loosens.
6. **Amendment 1:** «the report module must let you browse and see the different workspaces […] a
   port is defined, that port is brought up and everything will be there»; a new session that detects the active module attaches to it, and
   from the web the new workspace is noticed. Replaces «one server shows one ledger» and «it shuts down on exit».
7. Shutdown: the module stays up until the operator shuts it down.
8. Default fixed port: 4355 (`GEKKO_REPORT_PORT` changes it).
9. **Amendment 2:** agreed with everything except two limits («any local process can read it […] nor does it
   remove it when the session closes» and «after updating the code it has to be restarted by hand»): «can you fix
   this?». AC36 and AC37 come in. The module still stays up (decision 7 does not change).
10. **Amendment 3:** «have the module in the web have some check for updates button and have that trigger that
    flow, so we are not doing it every 2 seconds». AC38 (new-code notice) and AC39 (rejection from another
    origin) were added by the author: they await approval.
11. **Amendment 4** (no new operator decision; it rests on decision 5 and on the living spec rule
    §2b: a fix that tightens enters with its test and its `REQ`). The independent audit (T26) found that the
    per-user check was bypassed by repeating the operator's source port from `127.0.0.2` (reproduced
    with a host-network container: it read a ledger), that `Host: localhost` let another user get into the
    same origin through `[::1]`, and that a `Content-Length: -1` made memory grow without limit
    (reproduced: from 28 MB to 2.8 GB in 2 s). Those three and the audit's other findings are fixed.
    One decision remains for the operator: authentication against forwarders (limit (a)/(b) of §6).
12. Authentication against forwarders (proxy outside loopback, rootless container): «for now leave it
    documented». No token or cookie is added in this spec; it remains a candidate for a later one.
    On the real run (T28) and Amendment 4: «I go with 2 and 3».
13. Real run done by the operator (2026-11-15): the list and the detail are seen in their browser with findings
    from a lab workspace. «It looks fine, yes, but I don't like it much».
14. **Amendment 5:** «don't put check for updates like that. Put it inside a collapsible settings menu
    […] with a gear button […] also add dark and light mode». Decided by the author, to be confirmed:
    the theme choice is stored in a browser cookie (without JavaScript there is no other way to remember it)
    and is changed with a second POST, `/tema`; with no choice the system preference applies.
15. Branches: the reports work lives in its own branch, it does not go straight to `main` («we cannot keep pushing
    straight to main»).
