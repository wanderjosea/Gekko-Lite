# Tasks 012 — Report module (web viewer of findings)

> Status: `IMPLEMENTADA` (approved by the operator, 2026-11-15: «hazlo» (do it); real run closed 2026-11-16). The authentication decision remains open (spec §6).
> Spec: [`spec.md`](spec.md) (`APROBADA`, Amendments 1–3, 39 AC) · Plan: [`plan.md`](plan.md) (`APROBADO`, v4)
> Each task closes ≥1 criterion and names its test. The checkbox is ticked ONLY with the test green and its row in the log.

**Tests:** **L** = `python3 .claude/tools/findings.py selftest` · **V** = `python3 .claude/tools/findings_web.py selftest` ·
**W** = `bash tools/report-test.sh` (runs L and V + process cases) · **P** = `bash tools/ws-test.sh` ·
**S** = `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` · **K** = `.githooks/test.sh`

**Who:** the code and its tests are written by a **Sonnet 5.5** agent per group (operator's decision). The main
session writes the living spec, the prompts and the docs, runs the final verification and reviews each delivery against
the AC list. At most two agents at a time, and only over different files.

**Rules for the agents:** do not commit or push · do not read or write in `engagements/` (the tests use a
temporary root) · do not use port 4355 or the operator's tmux server (own free port, own sockets) ·
shut down only processes whose command line names the temporary root · do not touch another group's files.

## Wave 0 — Falsifiers (done on 2026-11-15, before writing code)
- [x] **F1** — another real user is rejected · `AC36` · docker container with host networking
- [x] **F2** — the button replaces the process without cutting the response · `AC37`
- [x] **F3** — a second `bind` to the same port fails · `AC21`
- [x] **F4** — the detached module survives `tmux kill-server` · `AC18`
- [x] **F5** — the row with the URL fits whole at 36 columns · `AC23`
- [x] **F6** — lock on the directory: 20 parallel `add` leave 20 rows (btrfs and tmpfs) · `AC28`

## Wave 1 — in parallel (different files)
**G1 · Ledger — `.claude/tools/findings.py` (agent A)**
- [x] **T1** — write first the cases that fail today (AC27, AC28, AC30) in `cmd_selftest` and record the red · test: L
- [x] **T2** — `_scan` (bytes, strict per-line decoding, non-object = bad line) and `_load` on top of `_scan` · closes `AC30` · test: L
- [x] **T3** — `_locked` (flock on the directory) around read→write in `cmd_add` and `cmd_set` · closes `AC28` · test: L
- [x] **T4** — `cmd_add` rejects `confirmed` and `needs_validation` · closes `AC27` · test: L
- [x] **T5** — six fields in `add` and `set`, validation of `cvss`/`cwe`/`cve`, nothing is written if anything fails · closes `AC1`, `AC2`, `AC4` · test: L
- [x] **T6** — `render` projects the six fields with the fencing rule · closes `AC3` · test: L
- [x] **T7** — each case prints `ok REQ-LED-00n <description>` (001 fields, 002 render, 003 refusals, 004 corrupt ledger, 005 simultaneous adds, 006 row integrity) · closes `AC26` (part) · test: L

**G3 · Panel and gate bridge — `toolbox/gekko-panel.ts`, `toolbox/gekko-guard.ts`, `toolbox/gekko-panel-selftest.ts` (agent C)**
- [x] **T16** — `validReportUrl`, `PanelExtras.reportUrl`, `PanelIo.reportUrl()`, row `▸ visor <url>` in HALLAZGOS; the guard reads `GEKKO_REPORT_URL` · closes `AC23`, `AC24` · test: S
- [x] **T17** — cases under `req("REQ-TUI-027")`: full row at 36 columns, no row with an absent or malformed URL, REQ-TUI-018 canaries intact, without UI `io.reportUrl` is not called · closes `AC23`, `AC24` · test: S
- [x] **T18** — the gate runs L and V and adds their `ok REQ-…` lines to the counters; exit ≠ 0 from either = red gate · closes `AC26` (part) · test: S

**Main session, meanwhile**
- [x] **T23** — living spec: §1 (+`findings_web.py`, +`tools/report-test.sh`), §2a (Python sources), `REQ-LED-001…006`, `REQ-RPT-001…013`, `REQ-TUI-027`, GAP-73 and the limits of spec 012 · closes the reconciliation of all the AC · test: S (`REQ ↔ case` trace without failures at the end)

## Wave 2 — after G1
**G2 · Module — `.claude/tools/findings_web.py`, `tools/report-test.sh` (agent B)**
- [x] **T8** — workspace discovery, name rule and confinement; case that compares with `validWorkspaceName` via node · closes `AC33`, `AC35` · test: V
- [x] **T9** — `respond` and templates: index, list (order, counters, search, filter), detail; type coercion; warnings for broken line, no status and no corroboration; comparison with `countFindings` via node · closes `AC5`–`AC9`, `AC16`, `AC29`, `AC32`, `AC34` · test: V
- [x] **T10** — escaping and controls, content policy with CSS hash, zero external origins, `Host`, methods and routes · closes `AC10`, `AC11`, `AC12`, `AC14`, `AC15` · test: V
- [x] **T11** — server on `127.0.0.1`, `peer_uid` over `/proc/net/tcp`, `X-Gekko-Report` header · closes `AC13`, `AC36` · test: V
- [x] **T12** — `POST /actualizar`, new-code notice, `Sec-Fetch-Site`, process replacement (tested on a copy) · closes `AC37`, `AC38`, `AC39` · test: V
- [x] **T13** — `serve` and `ensure` (attach, detached start, race of two starts, occupied port or another root) · closes `AC20`–`AC22` (module part) · test: V
- [x] **T14** — each case prints `ok REQ-RPT-0nn <description>` (001 workspaces, 002 isolation, 003 list and counters, 004 faithful status, 005 search, 006 detail, 007 hostile content, 008 read-only and routes, 009 loopback/Host/UID, 010 live fidelity, 011 update, 012 attach) · closes `AC26` (part) · test: V
- [x] **T15** — `tools/report-test.sh`: L + V + standalone command with `curl` + `grep` of the three prompts · closes `AC22`, `AC25` (test), `AC26` · test: W

## Wave 3 — after G2, in parallel (different files)
**G4 · Launcher — `tools/pi-hitl.sh`, `tools/ws-test.sh`, `toolbox/gekko-workspace-selftest.ts` (agent D)**
- [x] **T19** — `pi-hitl.sh`: delete `GEKKO_REPORT_URL`, call `ensure`, export the URL only if it exited 0, banner line with the workspace URL, warning if it failed · closes `AC17`–`AC21` · test: P
- [x] **T20** — `ws-test.sh`: `GEKKO_REPORT=0` for spec 010's cases; new cases with temporary root and free port (starts, attaches, survives Pi, `none`/shutdown, occupied port, another root, two starts at once, inherited URL) · closes `AC17`–`AC21` · test: P
- [x] **T21** — static contract of the launcher under `req("REQ-RPT-013")`, like REQ-WS-007 · closes `AC17`, `AC19`, `AC20` · test: S

**G5 · Hook — `.githooks/pre-commit`, `.githooks/test.sh` (agent E)**
- [x] **T22** — boundary list with the two new files; run `tools/report-test.sh` when the commit touches the ledger or the module, reject if it fails or is missing; cases with a fake `report-test.sh` · closes `AC26`, `AC31` · test: K

## Wave 4 — main session
- [x] **T24** — the three prompts name the six fields and the do-not-invent-CVSS/CWE/CVE rule · closes `AC25` · test: W
- [x] **T25** — `docs/pi-hitl.md`, `tools/pi-hitl.env.example`, `CLAUDE.md` and `AGENTS.md` (twins): the module, its variables, the standalone command, how to shut it down · no AC · test: review
- [x] **T26** — independent security review of `findings_web.py` (`code-auditor` agent, read-only); each finding is fixed or noted as a limit · test: its report + L, V, W green afterwards
- [x] **T27** — measurements: hook duration (target < 5 s) and index with 20 workspaces × 200 rows · test: log
- [x] **T28** — real run: `pi-hitl.sh` with two lab workspaces, screenshots of the index, the list and the detail in the operator's browser, «Buscar actualizaciones» button pressed, and host-network container rejected against the real module · closes `AC36` (real run) and §7 of the spec · test: screenshots + recorded output
- [x] **T29 (regression)** — L, W, P, K and S green at the same time; one-by-one review of AC1–AC39 against the log · test: the five commands

## Wave 5 — Amendment 5 (after the operator's real run)
- [x] **T30** — collapsible settings menu with a gear containing «Buscar actualizaciones», and light/dark theme (automatic by system preference, choice stored in a cookie, `POST /tema`); code by a Sonnet agent · closes `AC41`, `AC42`, `AC38` (E5) · test: V, W, S + screenshots in both themes
- [x] **T31** — the operator confirms the menu and the two themes in their browser · closes the operator's part of `AC41`/`AC42` · test: their run

## Verification log
| Task | Command | Result | Date |
|---|---|---|---|
| F1 | test server with `peer_uid` + `docker run --rm --net=host --entrypoint curl gekko-toolbox:latest …` | green: `denied peer_uid=0`, `http=403`; same user `peer_uid=1000`, 200 | 2026-11-15 |
| F2 | file change + `curl -X POST …/actualizar` against the test server | green: complete response, same PID, new-code hash on the second attempt (0.2 s), a single process | 2026-11-15 |
| F3 | second test server on the same port | green: `OSError: [Errno 98] Address already in use` | 2026-11-15 |
| F4 | server launched with its own session from `tmux -L gkprobe`, then `kill-server` | green: still responds with the same PID; `pkill` shuts it down | 2026-11-15 |
| F5 | `renderRail` at 36 columns with the row `▸ visor http://127.0.0.1:65535/` | green: full row; `redactSummary` does not touch it | 2026-11-15 |
| F6 | 20 parallel `add` with `flock` on the directory, 3 rounds on tmpfs and 3 on btrfs | green: 20 rows and 20 ids in the 6 rounds (without lock: 17) | 2026-11-15 |
| T1 | L over the previous code | expected red: AC27 fails in the first new case; AC30 gives an `AttributeError` traceback; AC28 leaves 18 rows | 2026-11-15 |
| T2–T7 | `python3 .claude/tools/findings.py selftest` (6 runs) | green all 6: 30 cases (LED-001=5, 002=5, 003=8, 004=6, 005=1, 006=5), 0.2 s per run | 2026-11-15 |
| T16–T18 | `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` | guard, panel and workspace `all passed`; REQ-TUI-027 and REQ-LED-001…006 covered in the trace; expected red until wave 2: `findings_web.py` is missing and REQ-RPT-001…013 have no cases | 2026-11-15 |
| T16–T17 | `bash tools/tui-test.sh` | 45 passed, 0 failed (reported by the agent; repeated in T29) | 2026-11-15 |
| T24 | `grep` of the six flags and `never guess` in the three prompts | 7/7 in each file (by hand; the checkbox waits for W) | 2026-11-15 |
| T22 | `.githooks/test.sh` (3 runs) | green: `ALL GREEN — 46 checks` (34 previous + 12 new: 2 of boundary, 10 of the `report-test.sh` stub). Hook still to be measured with the real `report-test.sh` (T27) | 2026-11-15 |
| T8–T14 | `python3 .claude/tools/findings_web.py selftest` (5 runs: 3 by the agent, 2 own) | green: 60 cases `ok REQ-RPT-001…012`, 3.1 s; no module processes alive at the end | 2026-11-15 |
| T15, T24 | `bash tools/report-test.sh` | green: `27 passed, 0 failed`, 3.5 s (L, V, standalone command with `curl` and SIGINT, 21 prompt `grep`s) | 2026-11-15 |
| T8–T15 | `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` | guard, panel and workspace `all passed`; REQ-LED and REQ-RPT-001…012 covered; expected red until T21: REQ-RPT-013 without a case | 2026-11-15 |
| T8–T15 | review of `findings_web.py` (lines 1–590) by the main session | no `_save`/`_locked`/`cmd_*`, no JavaScript, every ledger value goes through `esc`; pending fixes: ledger that is a symbolic link or special file, and `_scan` facing an integer of more than 4300 digits or extreme nesting | 2026-11-15 |
| T19–T20 | `bash tools/ws-test.sh` (3 runs: 2 by the agent, 1 own) | green: `94 passed, 0 failed` (66 previous + 28 new for AC17–AC21 and inherited URL), 24 s; no module processes alive at the end | 2026-11-15 |
| T21 | `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` | green: three `all passed` + `REQ trace: 118 requisitos, 1148 casos`, exit 0 | 2026-11-15 |
| T27 | `time bash tools/report-test.sh` (what the hook adds to a commit that touches the ledger or the module) | 3.5 s (target < 5 s) | 2026-11-15 |
| T27 | real module over a temporary root with 20 workspaces × 200 rows (9.7 MB of ledgers), `curl` with timings | index 0.05 s · list 0.007 s · detail 0.005 s · search 0.006 s | 2026-11-15 |
| T26 | `code-auditor` agent (read-only) over `findings_web.py` and `findings.py` | verdict «fix before merging»: 2 critical, 6 warnings, 4 suggestions, 5 underestimated limits; escaping, routes, button CSRF and «read-only» without findings | 2026-11-15 |
| T26 | reproduction of critical 1: operator connection opened from `127.0.0.1:P` + `docker run --rm --net=host … curl --interface 127.0.0.2 --local-port P` | RED (before the fix): the container (UID 0) received 200 and the ledger canary. F1 did not cover it: it only tested a pair whose only row was its own | 2026-11-15 |
| T26 | reproduction of critical 2 (browserless part): `curl -H 'Host: localhost:<port>'` | RED (before the fix): 200 | 2026-11-15 |
| T26 | reproduction of warning 3: request with `Content-Length: -1` followed by 2 s of `/dev/zero` | RED (before the fix): module RSS from 28,688 kB to 2,810,596 kB | 2026-11-15 |
| T26 | Sonnet agent: 12 fixes in `findings_web.py` (W1–W12) and 6 in `findings.py` (L1–L6), test first in W1, W2, W3, W7, L1, L2, L6 | prior red of the seven recorded by the agent; afterwards L = 41 cases, V = 77 cases, green | 2026-11-15 |
| T26 | the three reproductions repeated after the fix (same method, temporary root, host-network container) | green: the container has its connection closed on the normal request and on the `127.0.0.2:P` one (no canary); `Host: localhost` → 403; with `Content-Length: -1` the RSS goes from 29,744 to 30,004 kB and the module keeps responding | 2026-11-15 |
| T23 | living spec rewritten against the delivered cases (REQ-LED-002/003/004/006, REQ-RPT-003/004/006/007/008/009/011/012, GAP-73) + gate | green: `REQ trace: 118 requisitos, 1176 casos`, exit 0; every function cited under «Código» exists | 2026-11-15 |
| T25 | review of `docs/pi-hitl.md` §4c, `tools/pi-hitl.env.example`, `CLAUDE.md` and `AGENTS.md` against the delivered behavior | up to date, including «only `127.0.0.1`», connection cut for another user and the warning about proxies outside loopback | 2026-11-15 |
| T28 | real module over a temporary root with three workspaces of synthetic data; screenshots with headless Firefox 152 (temporary profile) of the index, the list and the detail | seen: the style loads with the content policy, the hostile row comes out as text, «sin corroboración», `estado desconocido: «confirmed »` and the broken-line warning appear; the CSS of the CVSS/CWE/CVE boxes was fixed (the CWE was splitting into two lines) | 2026-11-15 |
| T28 | button on a real code change (the CSS fix) in that module: `curl -X POST -H 'Sec-Fetch-Site: same-origin' …/actualizar` | green: the page announced «Hay código nuevo» (new code available); the POST responded «Código actualizado» (code updated); 1.5 s later 200, no notice and a single process | 2026-11-15 |
| T28 | PENDING from the operator | real `tools/pi-hitl.sh` with two workspaces (banner, `visor` row in the card, URL in their browser) and the button pressed from their browser | — |
| T29 | L · `bash tools/report-test.sh` · `.githooks/test.sh` · gate · `bash tools/ws-test.sh` · `bash tools/tui-test.sh`, all in sequence after the last change | green: `selftest OK` · `27 passed` · `ALL GREEN — 46 checks` · `REQ trace: 118 requisitos, 1176 casos` (exit 0) · `94 passed` · `45 passed`; no module process alive | 2026-11-15 |
| T29 | review of AC1–AC40 against this log | every AC has a green case. Not checked end to end: the banner and the card in a real Pi session, the button from a real browser (tested with `curl`), the automatic return to the index after updating and the hook on a real commit (K uses a fake `report-test.sh`) | 2026-11-15 |
| T29 | real commit `eac0dde` on the feature branch | the `pre-commit` ran `gitleaks` (no leaks) and `tools/report-test.sh` (green) and let the commit through: the hook is proven on a real commit | 2026-11-15 |
| T28 | operator's real run: `tools/pi-hitl.sh` from the worktree with a lab workspace, module open in their browser (Brave) | the list and the detail are seen with real findings («it looks fine, yes»); the look did not convince them → Amendment 5. Not confirmed: card `visor` row and button pressed | 2026-11-15 |
| T30 | V · `bash tools/report-test.sh` · gate · `.githooks/test.sh` after the change | green: `selftest OK` (21 new cases of REQ-RPT-014) · `27 passed` · `REQ trace: 119 requisitos, 1198 casos` · `ALL GREEN — 46 checks`; minimum contrast measured 5.65 (dark) and 5.03 (light) | 2026-11-15 |
| T30 | real module over a temporary root with synthetic data, headless Firefox 152 | seen: dark theme by system preference, light theme by system preference, dark theme forced by the cookie, and the menu open in both themes (gear on the right, groups TEMA and MÓDULO). The open menu was captured over the served HTML with `open` added: without JavaScript it cannot be pressed from the command line | 2026-11-15 |
| T28 | operator's real run with tree `89bb535` (Atlas redesign included): `tools/pi-hitl.sh` from the worktree, lab workspace, local model | reported by the operator: «the test passed. the model started the server and updated the findings in the reports module on the web». Corroborated by the session, without reading the ledger content: module on `127.0.0.1:4355` served from the worktree (up since 17:02), index 200 and no new-code notice; two `pi-hitl.sh` sessions alive with different workspaces; the test workspace's ledger has 4 rows and changed at 22:57:51Z. Not confirmed: card `visor` row, «Buscar actualizaciones» button pressed from the browser, and the menu with the two themes (T31) | 2026-11-16 |
| T28 | three screenshots from the operator's browser (Brave) over the real module, lab workspace: the list and the detail of a finding at `#resumen` and at `#evidencia` | seen by the session: list with 4 findings written by the model (statuses `confirmed`, `needs_validation` and `refuted`; the `refuted` carries the time of the ledger's last change), detail with «Por validar · bloqueo» (To validate · blocker) notice, command, artifact and corroboration. Defects seen: the date in the Cambio column splits into three lines; Resumen, Impacto, Remediación and Pasos para reproducir come out «—» (the model did not load them). The screenshots are not kept in the repo: they carry lab data. Not captured: the index | 2026-11-16 |
| T28 | `docker run --rm --net=host --entrypoint curl gekko-toolbox:latest -s -m 10 http://127.0.0.1:4355/` against the real module, and the operator's `curl` right after | green: the container has its connection closed (`http=000`, 0 bytes, exit 52); the operator receives 200 | 2026-11-16 |
| T28 | `tmux capture-pane` of the live rail of a real `pi-hitl.sh` session (only the searched row) | green: `▸ visor  http://127.0.0.1:4355/` | 2026-11-16 |
| T28, T31 | operator's confirmation of their real run | pressed «Buscar actualizaciones» from their browser; opened the gear menu and saw the two themes. Not captured: the index (the list and the detail were) | 2026-11-16 |
