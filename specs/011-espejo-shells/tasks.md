# Tasks 011 — Writable shell mirror

> Status: `APROBADO` — 2026-11-15, by the operator. Plan: [`plan.md`](plan.md) (`APROBADO`, 2026-11-15).
> Each task closes ≥1 acceptance criterion and names its test. The checkbox is marked ONLY with the test green,
> and each task starts with its cases in red. The REQ enters the living spec in the same task as its first case.

Commands (from the repo root):
- **gate:** `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`
- **harness:** `cd toolbox && ln -sfn <pi-install>/node_modules node_modules && node --experimental-strip-types tests/handler-harness.ts; rm -f node_modules`
- **stress:** same as the harness, with `tests/mirror-stress.ts`
- **launcher:** `bash tools/ws-test.sh` · **rail:** `bash tools/tui-test.sh` · **hooks:** `bash .githooks/test.sh`

- [x] **T1 — Pure mirror functions** in `toolbox/gekko-panel.ts`: `mirrorDecision`, `mirrorWindowArgs`,
      `mirrorWindowName`, `staleMirrors`, `sendSteps`; `REQ-TMUX-011` to `REQ-TMUX-014` in the living spec.
      · closes the G part of `AC1`, `AC2`, `AC3`, `AC6`, `AC7` · test: **gate**
- [x] **T2 — The shell is born with `IGNOREEOF=10`**: `newSessionArgs` in `toolbox/gekko-workspace.ts`; `REQ-WS-006`
      updated and `REQ-WS-010` new. · closes the G part of `AC8` · test: **gate**
- [x] **T3 — Wiring in `toolbox/shell-session.ts`**: open the mirror after the verified registration, turn on the mouse,
      exit copy-mode before sending, close the run's windows in `session_start` and `session_shutdown`.
      The harness stores the `on()` handlers and passes a fake `ctx`. · closes the H part of `AC1`, `AC3`, `AC4`, `AC6`,
      `AC7`, `AC8` · test: **harness** · depends on T1 and T2
- [x] **T4 — Check in `/gekko-policy`**: `PanelRuntime.mirror`, `viewRows`, `policyOverlayBody` in
      `toolbox/gekko-panel.ts`; the overlay in `toolbox/gekko-guard.ts` uses them; `REQ-TUI-024`. · closes `AC5` · test: **gate**
- [x] **T5 — Shortcuts and sweep in the launcher**: `navBindings` (`REQ-TUI-025`); modes `--keys` and `--keys-restore` in
      `tools/gekko-sidebar.sh`; `tools/pi-hitl.sh` marks its session, installs the shortcuts, waits for Pi inside tmux and on
      exit sweeps mirror windows of dead pids, removes the mark and returns the shortcuts. · closes `AC9` and the P part and
      the regex contract of `AC6` · test: **gate** + **launcher** · depends on T1
- [x] **T6 — Warning to the model and documentation**: line in `docs/prompts/pi-hitl.md` (`REQ-TMUX-015`); mirror section in
      `docs/pi-hitl.md`. · closes `AC10` · test: **gate**
- [x] **T7 (regression)** — none of the above breaks what exists. · closes `AC11` · test: **gate**, **harness**,
      **launcher**, **rail** and **hooks**, all five green in the same run
- [x] **T9 — Session change with a shell being created** (found by the stress test, 2026-11-15): a shell whose creation
      crosses a `session_start` is not adopted as own nor leaves a mirror window; `REQ-TMUX-016`. · reinforces `AC6`
      · test: **gate** + **harness** + **stress** (E6 at 0)
- [x] **T10 — Launcher killed by force** (found by the stress test): the session mark carries the launcher's pid and
      the marks of dead launchers are cleaned, so the operator's bindings are always returned. · reinforces `AC9`
      · test: **gate** + **launcher**
- [x] **T11 — Leave copy-mode and send in a single call to tmux** (found by the stress test): today it is two steps and between
      one and the other the send can be lost without notice. · reinforces `AC7` · test: **gate** + **harness** + **stress** (E5 at 0)
- [x] **T12 — Repeatable stress in the repo**: `toolbox/tests/mirror-stress.ts` (same way of running as the harness).
- [x] **T13 — The launcher also cleans up if it is closed abruptly** (found in the real run, step 9): the cleanup (mark, shortcuts, mirror windows of dead runs, rail) runs from an exit trap, also when the tmux session
      is closed or the launcher receives SIGHUP/SIGTERM. · reinforces `AC6` and `AC9` · test: **gate** + **launcher**
- [x] **T14 — Duplicate rails on resize** (found in the real run; previous defect of spec 008): the resize hook looks for the rail in the tmux session with the most recent activity, not in the window's; if it is
      another, it does not find it and opens one more every time. · test: **rail** (`tools/tui-test.sh`) + **gate**
- [x] **T8 — Real run** with Pi in the operator's environment (kitty + Herdr): the window appears without stealing focus,
      `Shift+→` / `Shift+←` go and come back, the wheel scrolls, `Ctrl+D` does not kill the shell, the check turns it off, and on
      exiting Pi no windows remain. The operator runs it. · closes §7 · when passed: `Estado:` → `IMPLEMENTADA`

## Verification record
> On closing each task: command run + result (green/red), like the ledger.

| Task | Command | Result | Date |
|---|---|---|---|
| T1 | gate | red before the code: the panel selftest did not load (the new exports were missing). Green: rc=0, `REQ trace: 106 requisitos, 1111 casos` (re-run by the main session, not only by the agent that wrote it) | 2026-11-15 |
| T2 | gate | red: 4 cases (the two rewritten `WS-006` and the two `WS-010`). Green: same run as T1 | 2026-11-15 |
| T4 | gate | red: same loading failure as T1. Green: same run as T1. Not tested: the overlay keys in a real TUI (left for T8) | 2026-11-15 |
| T3 | harness: `cd toolbox && ln -sfn ~/.pi/agent/install/releases/1.5.0/node_modules node_modules && node --experimental-strip-types tests/handler-harness.ts; rm -f node_modules` (path abbreviated; use the local Pi install) | red before the code: 10 new assertions (AC1 ×5, AC6 ×3, AC7, AC8). Green: rc=0, 59 ok, 0 FAIL, re-run by the main session; the agent ran it 5 times in a row without failures. The `Ctrl+D` case depends on the default shell being bash (it is here) | 2026-11-15 |
| T5 | gate + `bash tools/ws-test.sh` | red before the code: 7 checks of `ws-test.sh` (`@gekko_pi` mark, `S-Right`/`F3` did not change window, the raw key did not arrive in the session without the mark, the mirror window of a dead pid was not swept). Green: 87 passed, 0 failed. The keys are injected into a real client with `send-keys -K -c` (verified in tmux 3.6b). Not covered: a launcher killed by a signal does not clean the mark nor the shortcuts (harmless: without the mark the shortcut passes the key through) | 2026-11-15 |
| T6 | gate | red: `TMUX-015` and marker `REQ-TMUX-015` without REQ. Green: rc=0 | 2026-11-15 |
| T7 | gate, harness, `ws-test.sh`, `tui-test.sh`, `.githooks/test.sh`, in a single run of the main session | gate rc=0 (`REQ trace: 107 requisitos, 1126 casos`) · harness rc=0 (59 ok, 0 FAIL) · ws-test 87/0 · tui-test 45/0 · hooks 34 checks green | 2026-11-15 |
| T12 | stress (`toolbox/tests/mirror-stress.ts`), 4 runs | E1–E4, E7, E8 fine in all. **Red on E6:** of 21 session changes with a shell being created, 12–14 left the window open and 9–10 left the shell as own of the new session. **Red on E5:** with the pane entering copy-mode every 50 ms, of 25 sends 0, 1, 5 and 1 were lost silently. Separate probe: cancel and send chained in a single tmux invocation, with the pane entering copy-mode every 20 ms: 40 of 40 executed. Launcher probe: after a `kill -9`, its session stays marked and the following launches do not return the bindings until that session is closed | 2026-11-15 |
| T9 | gate + harness + stress | red before the code: in the harness, 4–5 leaked windows and 3–4 adopted shells out of 5 changes; in the stress test, the T12 row. Green: stress 4 runs of the main session, all four with 0 windows and 0 inherited shells out of 21 changes; harness 61 ok, 0 FAIL. `REQ-TMUX-016` | 2026-11-15 |
| T11 | gate + harness + stress | the harness case does NOT reproduce the old defect (it is probabilistic): the red test is the stress one (T12 row: 0, 1, 5 and 1 lost out of 25). Green: stress 4 runs, 25 of 25 executed and 0 silently lost in all four. `sendArgs` replaces `sendSteps`; `REQ-TMUX-013` rewritten | 2026-11-15 |
| T10 | gate + `bash tools/ws-test.sh` | red: 5 checks (mark without pid, and after `kill -9` of a launcher `list-keys -T root` did not return to being the same). Green: 94 passed, 0 failed. Not covered: an old mark with value `1` counts as alive (pid 1 exists); a pid recycled by another process keeps the mark | 2026-11-15 |
| T7 (repeated after T9–T11) | the five suites and the stress test, in a single run of the main session | gate rc=0 (`REQ trace: 108 requisitos, 1141 casos`) · harness 61 ok, 0 FAIL · stress rc=0, 0 failures · ws-test 94/0 · tui-test 45/0 · hooks 34 checks green | 2026-11-15 |
| T8 (partial) | real run by the operator, kitty + Herdr, ~20:08 | steps 1–8 as expected (window without stealing focus, `Shift+arrows` and `F2`/`F3`, typing, wheel, `Ctrl+D`, send with scroll, check with Alt+P, `/new` keeps the shells). Step 9 not closed: after exiting Pi the four shortcuts were still installed. The normal exit reproduced with a fake `pi` through the real path (relaunch, rail, server with other sessions) does return them; probable cause, not confirmed: the launcher ended by a signal → T13 | 2026-11-15 |
| T13 | gate + `bash tools/ws-test.sh` ×3 | red before the fix: 5 checks (after closing the tmux session, after SIGTERM and after SIGHUP, `list-keys -T root` did not stay the same and the mark remained). Green, run by the main session: `ws-test.sh` 108/0 in three consecutive runs · gate rc=0 (`REQ trace: 108 requisitos, 1144 casos`) · tui-test 45/0 · hooks 34 · harness 61 ok · stress 0 failures. `tools/pi-hitl.sh` was replaced by rename (there was a real live launcher). Not covered: a signal during startup, the rail part under a signal (the signal tests run without rail) and SIGKILL | 2026-11-15 |
| T14 (red) | main-session probe on a disposable server: two tmux sessions with one client each, rail open in `a`, last activity in `b`, and four resizes of `a`'s window | rails in `a`: 2, 3, 4 and 5 (one more per resize). Control with the last activity in `a`: stays at 1 | 2026-11-15 |
| T14 | `bash tools/tui-test.sh` + gate | red (new test against the old script): rails 2, 3, 4, 5 after four resizes and 5 rails with six `--fit` at once. Green, run by the main session: tui-test 48/0 in two runs (the agent, three more) · gate rc=0 (`REQ trace: 109 requisitos, 1148 casos`) · ws-test 108/0 · hooks 34 · harness 61 ok · stress 0 failures. `REQ-TUI-026`. Not covered: a `--fit` killed with SIGKILL between taking and releasing the lock leaves it taken | 2026-11-15 |
| T8 (complement) | main-session rehearsal: **real Pi 1.5.0** launched by the real `tools/pi-hitl.sh` on an isolated tmux server, with a simulated local model (no GPU nor the operator's Pi config) | `session_new` requested by the model → window `sh-e2e1` marked with Pi's pid, focus intact, writable client, `mouse on`, `IGNOREEOF=10` · real overlay: block «vista (no es una autorización)» ("view (not an authorization)"), `[x]` → space → `[ ]`, `c` does not touch it, `q` closes · check unchecked: shell created without window; re-checked: window · `/new`: 0 mirror windows and the 3 shells alive · **normal exit (Ctrl+D): 0 windows, 0 marks, 0 shortcuts, 0 rails, `list-keys -T root` the same as before, launcher rc=0** · rail with two clients and activity in another session: 1 rail after four resizes · **abrupt close (`kill-session` of Pi's session): same clean result**, the shell stays alive | 2026-11-15 |
| T8 | real run by the operator from the worktree for this spec (commit `25961f1`), kitty + Herdr, 21:07–21:14 | after exiting Pi: `tmux list-keys -T root \| grep -E 'S-Right\|S-Left\| F2 \| F3 '` prints nothing and `tmux list-windows -a -F '#{window_name}' \| grep '^sh-'` also prints nothing (output pasted by the operator). Also checked by the main session at that moment: 0 live Pi, 0 marks, 0 shortcuts, 0 mirror windows, 0 rails, and the shell `prueba1` still alive. With steps 1–8 of the previous run, closes §7 | 2026-11-15 |
