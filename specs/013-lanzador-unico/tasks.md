# Tasks 013 — One launcher, shells on the OS or in the toolbox

> Status: COMPLETED — T1–T18 verified; final regression and AC1–AC17 reconciliation closed on 2026-11-16.
> Spec: [`spec.md`](spec.md) (`APROBADA`, Amendments 1 and 2, 17 AC) · Plan: [`plan.md`](plan.md) (`APROBADO`)
> Each task closes ≥1 criterion and names its test. The checkbox is marked ONLY with the test green and its row in the record.

**Tests:** **S** = `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` · **P** =
`bash tools/ws-test.sh` · **H** = `toolbox/tests/handler-harness.ts` (run as its header says: from
`toolbox/`, with `node_modules` linked to the Pi install) · **D** =
`bash tools/toolbox-test.sh` (real docker + `gekko-toolbox:latest`; if they are missing it is skipped with a warning and does not count as
green) · **K** = `.githooks/test.sh`

**Who:** the operator authorized direct implementation, without subagents. T16 requires independent review and is not self-certified.

**Rules for the agents:** do not commit or push, and nothing of `git stash/checkout/restore/reset` · do not read or write in `engagements/` (temporary root) · containers, networks and tmux servers of their own and with test names;
never touch the operator's · do not use port 4355 · do not touch files of another group nor `specs/015-*`.

## Wave 0 — Falsifiers (done on 2026-11-15, disposable container and tmux)
- [x] **F1** — tmux on the host with `docker exec -it` in the pane leaves the container's `bash` alive when closing · discards that route for `AC9`
- [x] **F2** — tmux inside the container, driven with `docker exec <c> tmux …`: it is born in the requested directory, reports its real path, and with `--init` no process remains on closing · `AC9`
- [x] **F3** — shared ledger: alternating additions and 10 + 10 simultaneous from host and container leave 23 of 23 rows · `AC16`
- [x] **F4** — without ACL the operator cannot delete what root creates in a subdirectory; with default ACL he reads, adds, creates alongside and deletes (he cannot read a file the container leaves at 600) · `AC14`
- [x] **F5** — `.claude/tools` mounted read-only and `findings.py` records from inside · `AC7`, `AC15`
- [x] **F6** — the image ships tmux 3.7c and python3; a `docker exec … tmux` call takes 0.06 s · (supporting)

## Wave 1
**G1 · Core — `toolbox/gekko-workspace.ts`, `toolbox/gekko-workspace-selftest.ts` (agent A)**
- [x] **T1** — workspace mode: `parseExecMode`, `exec` file, `mode` command, `new --exec`; no file = `os`, invalid content = error · closes `AC3`, `AC4`, `AC5` · test: S
- [x] **T2** — the menu asks for the mode when creating a workspace (Enter = OS) and saves it · closes `AC2` · test: S (flow with injected I/O)
- [x] **T3** — container: `toolboxName`, `toolboxRunArgs` (only the workspace writable + `.claude/tools` read-only, `--init`, `NET_ADMIN`, `/dev/net/tun`, optional `.ovpn`), `toolboxPlan` (create, start, reuse, refuse), `toolbox` command with injectable docker and default ACL · closes `AC7`, `AC10` · test: S
- [x] **T4** — `tmuxCommand` (`docker exec` prefix in toolbox mode) and `ledgerCliOnly` (recognizes an exact invocation of the ledger CLI; with cases of attempts to get around it) · closes `AC9` (part), `AC8` (part) · test: S
- [x] **T5** — prompt block per mode (where shells are born, what `bash` is for, how to attach) · closes `AC6` · test: S

## Wave 2 — after G1, in parallel (different files)
**G2 · Shells and guard — `toolbox/shell-session.ts`, `toolbox/gekko-guard.ts`, `toolbox/gekko-panel-selftest.ts`, `toolbox/tests/handler-harness.ts` (agent B)**
- [x] **T6** — `session_*` and the guard's shell refresh invoke tmux through `tmuxCommand`; the `session_new` note says how to attach · closes `AC9` · test: H (real container), S
- [x] **T7** — `toolboxBashBlock` in the guard: in toolbox mode it blocks the `bash` that names an entry of `scope.txt` (not the local interfaces), except `ledgerCliOnly`; it runs after the scope, DoS and destructive decisions, which do not change · closes `AC8`, `AC12` · test: S
- [x] **T8** — the gate case now requires a single launcher (`REQ-PNL-005`) · closes `AC1` · test: S

**G3 · Launcher — `tools/pi-hitl.sh`, `tools/ws-test.sh`, `setup.sh`, delete `tools/gekko-toolbox.sh` (agent C)**
- [x] **T9** — `pi-hitl.sh`: read the mode, leave the container up in toolbox mode, export `GEKKO_EXEC` and `GEKKO_TOOLBOX`, banner line, notice of how to turn it off on exit; remove the mention of `gekko-hitl.sh` · closes `AC6`, `AC7`, `AC10`, `AC11`, `AC13` · test: P
- [x] **T10** — `ws-test.sh`: double Docker records calls; covers toolbox menu, saved/invalid mode, run/reuse/start/refuse, Docker absent, image/ACL failed and OS without Docker · closes `AC2`–`AC7`, `AC10`, `AC11`, `AC13` · test: P
- [x] **T11** — `tools/gekko-toolbox.sh` deleted; `setup.sh` detects `docker` and `setfacl` and warns that they are only needed for toolbox · test: P

## Wave 3 — after G2 and G3
**G4 · Real parity — `tools/toolbox-test.sh` (new) (agent D)**
- [x] **T12** — real Docker: exact mounts in a temporary root, shell/cwd, pane and process closed, shared and deletable artifact · closes `AC7`, `AC9`, `AC14` · test: D
- [x] **T13** — real Docker + local viewer over a temporary root: 10 concurrent additions per side, 20 rows/unique ids, and parity of ledger/viewer fields · closes `AC15`, `AC16` · test: D

## Wave 4 — main session
- [x] **T14** — living spec: `REQ-PNL-005`, REQ-TBX-001…006 with cases; the boundary and the hook mirror include `tools/toolbox-test.sh` · closes `AC1`, `AC17` · test: S, K
- [x] **T15** — docs updated for one launcher/two modes: runbook, prompt, Pi integration, KB, `CLAUDE.md`, `AGENTS.md`, `PORTING.md` · closes `AC17` · test: coherence review + S
- [x] **T16** — independent security review by a reviewer other than this session (guard rule, docker invocation, mounts); each finding is fixed or noted as a limit · test: its report + S, P, H, D green afterwards
- [x] **T17** — real operator run in each mode, with the reports module open · closes §7 of the spec · test: its run
- [x] **T18 (regression)** — S, P, H OS/toolbox, D, K, reports and TUI PASS; AC1–AC17 reconciled in [t18-verification.md](t18-verification.md).

## Amendment 2 (AC8), approved: affects T4 and T7
In toolbox mode the guard does not block a `bash` that is exactly an invocation of the ledger CLI, without chaining
anything. T4 delivers the pure function that recognizes that form (`ledgerCliOnly`), with cases of attempts to get around it;
T7 uses it inside the block, which lives in the guard next to the broker's host extractor.

## Verification record
| Task | Command | Result | Date |
|---|---|---|---|
| T1–T5 | `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` | PASS: 125 requirements, 1365 cases; REQ-TBX-001…006 cases of the core, CLI, creation flow, injected Docker and prompt. Verification run during the integration of T6–T9; not a new run. | 2026-11-15 |
| T10–T11 | `bash tools/ws-test.sh` | PASS: 113 passed, 0 failed; menu and saved toolbox mode, run/reuse/start/refuse, Docker absent from the PATH, image/ACL failed, OS without Docker and optional setup warnings. The state-dir was isolated under the temporary root because the first pass of the test used `.gekko-state` of the checkout; that path was not inspected nor cleaned. | 2026-11-15 |
| T12–T13 | `bash tools/toolbox-test.sh` | PASS final: exact temporary mounts, cwd/shell, closing of pane and process, artifact visible/deletable; 20 simultaneous additions (10 per side), unique ids, matching fields and local viewer. A previous attempt of the prefix selector `host-h1`/`host-h10` was corrected to require the full title. The host has no `/dev/net/tun`; no VPN nor the device was tested. | 2026-11-15 |
| T14 | `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`; `bash .githooks/test.sh` | PASS: 127 requirements, 1376 cases; REQ-TBX: 001=28, 002=14, 003=49, 004=5, 005=62 (55 parser + 7 handler), 006=12; hook ALL GREEN, 46 checks, includes `tools/toolbox-test.sh` in the boundary. | 2026-11-15 |
| T15 | Review of `docs/pi-hitl.md`, `docs/prompts/pi-hitl.md`, `docs/integration/pi.md`, `kb/tools/gekko-toolbox.md`, `CLAUDE.md`, `AGENTS.md`, `PORTING.md` and gate S | PASS: one launcher, workspace-based selection, location of bash/shells and containment limits coherent. | 2026-11-15 |
| T18 partial | `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` | PASS: 127 requirements, 1376 cases; guard, panel and workspace show `all passed`. It required local permissions because the sandbox blocked `uv_interface_addresses`. | 2026-11-15 |
| T18 partial | `bash tools/ws-test.sh` | PASS: 113 passed, 0 failed. It required local permissions for temporary loopback sockets. | 2026-11-15 |
| T18 partial | `cd toolbox && node --experimental-strip-types tests/handler-harness.ts`; `GEKKO_TEST_TOOLBOX=1 node --experimental-strip-types tests/handler-harness.ts` | PASS in OS and toolbox: `[PASS] handlers reales` in both; toolbox verifies creation, attach, cwd/workspace, artifacts and closing without residual bash. It required local permissions for tmux/temporary processes. | 2026-11-15 |
| T18 partial | `bash tools/toolbox-test.sh` | PASS: harness with temporary real Docker (result T12–T13 above); initial SKIP in a sandbox without daemon access, PASS when run with local access. | 2026-11-15 |
| T18 partial | `bash .githooks/test.sh` | PASS: ALL GREEN, 46 checks. | 2026-11-15 |
| T18 partial | `bash tools/report-test.sh` | PASS: 31 passed, 0 failed. | 2026-11-15 |
| T18 partial | `bash tools/tui-test.sh` | PASS: 45 passed, 0 failed. | 2026-11-15 |
| T18 sandbox limitation | `bash tools/report-test.sh`; `bash tools/tui-test.sh`; selftest S | The first runs without elevation could not open sockets/tmux servers (`PermissionError`/`Operation not permitted`); TUI stopped before 120 s. They were repeated with local permissions and passed in the rows above. | 2026-11-15 |
| T18 partial | `git diff --check`; `bash -n setup.sh tools/ws-test.sh tools/toolbox-test.sh` | PASS: no whitespace or shell syntax errors. | 2026-11-15 |
| T16 | Independent reviewer `code-auditor`; S/P/H/D/RPT/TUI/K | PASS after fixing two HIGH findings on Docker adoption; report in [t16-review.md](t16-review.md). S 127/1390, P 113/0, H and D PASS, RPT 31/0, TUI 45/0, K 46. | 2026-11-15 |
| T17 | Real Pi/model launcher OS and toolbox + Chromium | PASS on repetition with the operator's authentication: both exit 0; session_new/send/kill, cwd/hostname correct, artifacts readable/deletable and one synthetic finding per mode visible in the viewer's list/detail on port 45809. Resources and temporary configuration removed. The initial 401 remains as history in [t17-smoke.md](t17-smoke.md). | 2026-11-15 |
| T18 final | S, P, H OS/toolbox, D, K, reports, TUI; diff/syntax; AC1–AC17 review | PASS: S 127 requirements/1399 cases; P 115/0; H both PASS; D real Docker PASS; K 46; reports 31/0; TUI 45/0. AC6/AC12 cases added and CWE/CVSS check adjusted to the viewer detail. Full matrix in [t18-verification.md](t18-verification.md). | 2026-11-16 |
| T18 isolated commit | HEAD + prepared diff of 013 in a temporary copy, without 015 changes | PASS: S 125 requirements/1391 cases; P 115/0; H OS/toolbox and D PASS; K 46; reports 27/0; TUI 45/0. See the isolation section in [t18-verification.md](t18-verification.md). | 2026-11-16 |
| Independent audit H1 | `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` | Red before the fix (copy with the reading of `scope.txt` restored): 4 TBX-005 H1 cases fail (file deleted, unparseable line, mtime preserved, pure function). Green after deciding with the scope approved in memory: 130 requirements, 1492 cases, two runs. | 2026-11-16 |
| Independent audit H2/M3/L5/L6 | `bash tools/toolbox-test.sh` (real `toolbox` CLI against a temporary root) | Red with the previous code: 27 cases fail (mounts, `.pi-sessions` visible/writable, `exec`/`scope.txt`/`AUTHORIZATION.md` deletable and replaceable, ACL of `loot/`). Green after the fix: creates, reuses (same ID), refuses a foreign container with a published port and another without the tmpfs. New finding: `docker inspect` reports `CapAdd: ["CAP_NET_ADMIN"]` and `--tmpfs` does not appear in `Mounts` (`--mount type=tmpfs` does); with the previous code real adoption never reused. | 2026-11-16 |
| Independent audit selftest S | cases of `toolbox/gekko-workspace-selftest.ts` against the previous module | Red: 58 cases (TBX-001/003/006/007/008) fail; green with the fix. | 2026-11-16 |
| Independent audit P | `bash tools/ws-test.sh` | PASS: 122 passed, 0 failed (two runs); ID in `GEKKO_TOOLBOX`, `.pi-sessions` created before `docker run`, new mounts, relative `GEKKO_OVPN`, `exec` link/FIFO. | 2026-11-16 |
| Independent audit H | `cd toolbox && node --experimental-strip-types tests/handler-harness.ts`; `GEKKO_TEST_TOOLBOX=1 …` | PASS in OS and toolbox: hostile name, failure of "born in the workspace or not born" in toolbox, container replaced under Pi, socket directory with a symbolic link (L7), different `#{start_time}` (L8). | 2026-11-16 |
| Independent audit K/TUI | `bash .githooks/test.sh`; `bash tools/tui-test.sh` | ALL GREEN, 46 checks; 45 passed, 0 failed. | 2026-11-16 |
| F1 | own tmux (`-L`) on the host with `docker exec -it -w <ws> <c> bash`; `kill-session`; `pgrep bash` inside the container | the `bash` stays alive after closing the session: route discarded | 2026-11-15 |
| F2 | `docker exec <c> tmux new-session -d -c <ws>`; `display-message`; `send-keys 'sleep 300'`; `kill-session`; `ps` inside the container with `--init` | real workspace path, server and session ids available; after closing only the container's own process remains. Without `--init` zombies remained. Nonexistent directory: tmux starts in `/root` without error (the existing directory verification detects it) | 2026-11-15 |
| F3 | `findings.py add` alternated host/container on the same ledger; 10 + 10 at once | the three alternating additions pass; 23 rows and 23 ids | 2026-11-15 |
| F4 | container creates `recon/a.txt` as root; host tries to delete it; same with `setfacl -m d:u:<uid>:rwx,u:<uid>:rwx` | without ACL: `Permission denied`; with ACL: reading, adding, creating alongside and `rm -rf` work; a file at 600 cannot be read from the host | 2026-11-15 |
| F5 | `touch` on `.claude/tools` from the container; `findings.py add` from the container | `Read-only file system`; the addition is in the ledger | 2026-11-15 |
| F6 | `docker run … command -v tmux; tmux -V`; `time docker exec <c> tmux display-message` | tmux 3.7c, python3; 0.058 s | 2026-11-15 |

### Integration T6–T9 — 2026-11-15
- T6: `GEKKO_TEST_TOOLBOX=1 node --experimental-strip-types toolbox/tests/handler-harness.ts` — PASS, disposable real Docker: shell inside, correct cwd, shared artifacts, attach and closing without residual bash; OS regression of the same harness PASS.
- T7: `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` — 125 requirements, 1365 cases; includes real handler (toolbox, OS, ledger, explicit loopback in scope, external scope, DoS and session_send).
- T8: same selftest — PASS, requires pi-hitl and absence of the separate launcher. `.githooks/test.sh` — 45 checks, ALL GREEN.
- T9: `bash tools/ws-test.sh` — cases of the exported mode, simulated Docker creation, sockets derived from the workspace, Docker error, invalid mode, OS and exit notice; **102 passed, 0 failed**.
- Regression: `bash tools/report-test.sh` — 27/0; `bash tools/tui-test.sh` — 45/0.
- Independent review: detected explicit loopback blocked and inherited sockets outside the mount; both fixed with regression cases.
- Historical record; it does not replace the rows of the new verifications. T16 and H were verified afterwards; T17 passed afterwards with real Pi/model and the operator's authentication. VPN was not tested.
