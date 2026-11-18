# Tasks 010 — Mandatory workspace at launch

> Status: `COMPLETO` (2026-11-14). Spec `APROBADA` with Amendment 1; the operator set implementing it as the goal and
> authorized the tests. Code by four Sonnet agents according to `plan.md` §4; integration, review, stress and live validation
> by the orchestrator. Committed as `6bc7c5d` and merged into `main` on 2026-11-15 (`1d2dfbd`).

## Checklist
- [x] **T0. Preparation** — REQ-WS-001…008 and REQ-TUI-022/023 in the living spec; `gekko-workspace.ts` and its selftest in the boundary list (spec §1 and `.githooks/pre-commit`); `parseScopeLine` exported without behavior change; the gate loads the new selftest.
- [x] **T1. Core `toolbox/gekko-workspace.ts` + selftest (agent A)** — AC5–AC11 (logic), AC18, AC22, AC24 (block).
- [x] **T2. Panel (agent B)** — AC19, AC20, AC21.
- [x] **T3. Launcher, prompt and docs (agent C)** — AC1–AC6, AC9–AC15, AC22.
- [x] **T4. Shells (agent D)** — AC16, AC17.
- [x] **T5. Integration** — AC23. Line-by-line review and six corrections (see "Findings").
- [x] **T6. Subagents** — AC24, with a real subagent.
- [x] **T7. Live validation and stress** — against the lab web application target authorized by the operator (host and port
  in the local evidence, not here). Without flooding the target: 4 GET requests in total (DoS forbidden, `scope.md`).
- [x] **T8. Closing** — docs, skill and living spec up to date.

## Findings from the review, the stress and the live validation (all fixed and with proof)
1. **Live shell count broken** — the menu passed the name where the real `io` expected the path: it would never have shown a count. Proof: REQ-WS-005 (g) and `ws-test.sh` AC6.
2. **Mask like `/032` accepted** although the broker ignores it, and **an IP mistyped converted into a label** of the previous one. Proof: REQ-WS-002 (odd entries) + 60 000 random tokens in `ws-stress-pure.mjs`.
3. **Creating from the menu did not check symbolic links** leaving `engagements/`. Now a single point writes the scaffolding. Proof: manual run (0 files outside) + REQ-WS-001.
4. **Blank workspace indicator** with a name made only of spaces (found by stress). Proof: REQ-TUI-022.
5. **`session_new` read the workspace after an internal wait**: under simultaneous calls the last value won
   (found by stress). Now it is read on entry. Proof: "concurrency" harness + `ws-stress-shells.ts`.
6. **Prompt, banner and panel shared between launches**: with the common prompt file, 11 of 12 simultaneous launches
   received another workspace. They now carry the workspace name. Proof: `ws-stress.sh` §3.
7. **Pre-existing failure in `session_send`** (found in the test with real Pi): a text ending in a semicolon
   made the call fail (`unknown command: Enter`) and an `-exec` ending in backslash+semicolon arrived without the backslash. Fixed by reverse reconciliation: REQ-TMUX-010 + harness with real tmux.
8. **Old test unstable in the harness** (`#1b`, `#3`): a `new-session` right after `kill-server` fails ~4 % of the time
   (13/300 measured). It is retried until the foreign session exists; 25 consecutive runs without failure.

## Verification log (2026-11-14, UTC; all on the final code of the worktree)
| Task | Command | Result |
|---|---|---|
| T0–T5 | `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` | exit 0 · `REQ trace: 96 requisitos, 1039 casos` (before: 85 requirements) |
| T2, AC23 | `bash tools/tui-test.sh` | `45 passed, 0 failed` |
| T3 | `bash tools/ws-test.sh` | `66 passed, 0 failed` (3 runs) |
| T4 | `toolbox/tests/handler-harness.ts` (see its header) | `[PASS]`, 36 cases; 25 consecutive runs without failure |
| T7 stress | `node --no-warnings --experimental-strip-types toolbox/tests/ws-stress-pure.mjs` | `257927 comprobaciones, 0 fallos` |
| T7 stress | `toolbox/tests/ws-stress-shells.ts` | 13/13: 40 simultaneous creations, 40 alternating workspace, collision ×12, deleted workspace ×15, 82 closures |
| T7 stress | `bash tools/ws-stress.sh` | 14/14: 150 workspaces, 30 consecutive launches, 12 simultaneous without crossings, 18 hostile values rejected, scope of 500 entries |
| T7 live | real guard and `shell-session` with a fake `pi` against the authorized target | 12/12: workspace scope, neighboring IP blocked, shell in the workspace, real HTTP 200, file inside the workspace, output fenced |
| T6, T7 | real `tools/pi-hitl.sh` (Pi 1.5.0, real model, rail open) with `GEKKO_WORKSPACE` | shell in the workspace + HTTP 200; a real subagent printed `GEKKO_WORKSPACE`, `GEKKO_WORKSPACE_DIR` and `GEKKO_SCOPE` from the parent; 5 Pi sessions inside the workspace, 0 in the global directory |
| T7 visual | TUI screenshots converted to image and reviewed by eye | rail with card open, folded, auto-folded and without workspace; bar at 80 columns; real startup and real session |

Local evidence (git-ignored): `engagements/<lab-workspace>/validacion-spec010/` — screenshots, live test script and
`SHA256SUMS`. The Pi sessions of the test are in `engagements/<lab-workspace>/.pi-sessions/`.

## Re-verification after the merge (2026-11-15, UTC; on `main` at `c64272d`)
| What | Command | Result |
|---|---|---|
| Gate | `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` | exit 0 · `REQ trace: 98 requisitos, 1043 casos` (adds REQ-CFG-001 and REQ-CFG-002, from `setup.sh`) |
| Panel | `bash tools/tui-test.sh` | `45 passed, 0 failed` |
| Launcher | `bash tools/ws-test.sh` | `66 passed, 0 failed` (1 run) |
| Shells | `toolbox/tests/handler-harness.ts` | `[PASS]`, 36 cases (1 run) |
| Stress | `toolbox/tests/ws-stress-pure.mjs` | `257927 comprobaciones, 0 fallos` |
| Stress | `toolbox/tests/ws-stress-shells.ts` | 13/13 |
| Stress | `bash tools/ws-stress.sh` | `14 ok, 0 fallos` |
| Named subagent (before merging, on `1d488c6`; no target) | `pi -p --no-session -nc --tools Agent --model <provider>/<model-id> --mode json "<delegate to code-auditor>" < /dev/null` | `code-auditor` (`modelName: sub-128k`) returned `SUBAGENTE_OK`, `isError: false` |

Not repeated after the merge: the live validation against the lab target (T7), the real `tools/pi-hitl.sh` with the
rail, the screenshots, or `tui-test.sh --live`.

## Not verified / remaining limits
- Pi's resume selector: I did not check that it lists only the sessions of the workspace folder.
- The names of the engagements that already exist in the main repo: I did not list them; one that does not meet the naming rule will not appear in the menu.
- Two Pi processes at once on the SAME workspace share the panel state of that workspace.
- The workspace inheritance (AC24) was tested with the `general-purpose` subagent, not with a `.pi/agents/` role. The 401
  of the alias that prevented it was resolved (REQ-CFG-001; on 2026-11-15 `code-auditor` answered through the alias), but the
  inheritance test with a named role was not repeated.
