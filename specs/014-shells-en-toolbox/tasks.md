# Tasks 014 — Execution mode with Pi open

> Status: `APROBADAS` — together with spec and plan (operator, 2026-11-16; independent review: passes with fixes).
> Each code task leaves the text of its requirements in the living spec in the same change (the gate fails with a `req("REQ-…")` without a heading, and the pre-commit blocks a boundary change that does not touch the spec).
> Each task closes ≥1 criterion of [`spec.md`](spec.md) and names its test. Tick the checkbox ONLY with the test green.
> **G** = `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` · **H** = handler harness in `os` · **R** = real docker: the harness with `GEKKO_TEST_TOOLBOX=1` and `bash tools/toolbox-test.sh` (PASS, not SKIP) ·
> **P** = `bash tools/ws-test.sh` · **T** = `bash tools/tui-test.sh`.

- [x] **T1 — Workspace and launcher** (`toolbox/gekko-workspace.ts` + selftest, `tools/pi-hitl.sh`, `tools/ws-test.sh`):
      refuse a workspace directory that is a symbolic link (D11); `writeExecMode` in place (D6); prompt with
      both modes (D12); exit warning inside and outside tmux and banner "al lanzar" (D12); `socketDir` by place and
      by real path (D2) · closes `AC19`, `AC16`, `AC20`, part of `AC9` (G) and of `AC11` · test: G · P
- [x] **T2 — Pure functions and view** (`toolbox/gekko-panel.ts` + selftest, `toolbox/gekko-sidebar.mjs`,
      `tools/tui-test.sh`): type of `runtime.exec` and place per shell (D1, D2); "ejecución" block and its confirmation
      (D7); rail row and bar segment with their validators, and the text contract of the rail (D8);
      `mirrorWindowArgs` toward the container, detach argv and `mirrorDecision` without the toolbox exception
      (D10); pure `session_new` decision according to the state (D3) · closes `AC1` (rail and bar), `AC2`, `AC6`, `AC7`
      (text and keys), part of `AC4` (G) and of `AC18` (G) · test: G · T
- [x] **T3 — Shells** (`toolbox/shell-session.ts`, `toolbox/tests/handler-harness.ts`): place per shell, routing of each
      operation and socket directory by place (D2); `session_new` fails naming the state and compares the ID before
      creating (D3); mirror window of a toolbox shell with the host tmux forced, and its closing by detaching (D10); `lugar=`
      in the result (D12) · closes `AC4`, `AC9`, `AC12`, `AC18`, part of `AC1` and
      `AC3` · test: H · R
- [x] **T4 — Guard** (`toolbox/gekko-guard.ts`): initial state and periodic check (D1, D4); live switch through the
      launcher's CLI, with saving only on success (D5, D6); wiring of the overlay block (D7); shell refresh by place (D2);
      `/gekko-toolbox off` (D9) · closes `AC3`, `AC5`, `AC7` (create / start / adopt and retry), `AC8`, `AC10`, `AC11`, `AC13`, `AC14`, `AC15`, `AC17` · test: G · R
- [x] **T5 — Documentation and gaps**: `docs/pi-hitl.md`, `docs/prompts/pi-hitl.md`, `CLAUDE.md` and `AGENTS.md`
      (twins), `specs/README.md`; in the living spec, the new gap in §4 (the model can type into the Pi TUI)
      and the `Límite` of REQ-TBX-003 corrected (the ID is not eternal identity); does not close a criterion: it records what
      spec §6 admits · test: G (trace with no orphan REQ and no case without a REQ)
- [x] **T6 (regression)** — `AC21`: G, H, R, P, T, `bash tools/report-test.sh`, `bash .githooks/test.sh`,
      `toolbox/tests/mirror-stress.ts`
- [x] **T7 — Real run by the operator** (§7 of the spec): launch in `os`, switch to toolbox from `/gekko-policy`, see
      `levantando` and `lista`, request a shell, enter through its mirror window, stop the container with `docker stop` and
      see `caída`, retry, return to `os`, `/gekko-toolbox off`, and when leaving Pi with the container running see
      the warning.

## Verification record
> When closing each task: command run + result (green/red), like the ledger.

| Task | Command | Result | Date |
|---|---|---|---|
| T1 | G · `bash tools/ws-test.sh` · `bash tools/toolbox-test.sh` | green: `ws-test` 184 passed, 0 failed; `toolbox-test` PASS with real docker | 2026-11-16 |
| T2 | G · `bash tools/tui-test.sh` | green: 55 passed, 0 failed | 2026-11-16 |
| T3 | handler harness in `os` and with `GEKKO_TEST_TOOLBOX=1` (real docker) | green in both modes. One agent run (1 of ~11) failed the case "`docker stop` closes the mirror window"; not reproduced and the cause not found; that case's deadline went from 8 s to 20 s | 2026-11-16 |
| T4 | G · harness with `GEKKO_TEST_TOOLBOX=1`: guard cases (a)–(e) with real docker | green; the agent ran it 3 times in a row, 131 ok each time | 2026-11-16 |
| T5 | G (trace) | green: 150 requirements, 1862 cases; `GAP-78` noted in the living spec §4 | 2026-11-16 |
| T6 | G · H · R · P · T · `bash tools/report-test.sh` · `bash .githooks/test.sh` · `toolbox/tests/mirror-stress.ts` | green, run by the main session on the final tree: gate 150 requirements / 1862 cases; `ws-test` 184; hooks 46; `report-test` 31; `tui-test` 55; `toolbox-test` PASS; harness PASS in `os` and in toolbox; stress "all good" (25/25) | 2026-11-16 |
| T7 | real operator run with `./tools/pi-hitl.sh` in this worktree (`a9128d7`): the §7 steps in order | green according to the operator: all steps passed (`levantando`/`lista`, shell and mirror, `docker stop` → `caída` → retry, return to `os`, `/gekko-toolbox off`, warning on exit). No captures saved | 2026-11-16 |

**Not tested** (see the `Límite` of REQ-TBX-009 to 012, REQ-TUI-028 and REQ-TMUX-017): the 2 s cap of the mirror closing with a slow docker; a real VPN inside a container started live; two Pi on the same workspace. `GAP-78` (the model can type into the Pi TUI) remains open.
