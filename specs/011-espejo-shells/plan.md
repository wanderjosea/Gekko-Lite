# Technical plan 011 — Writable shell mirror

> Status: `APROBADO` — 2026-11-15, by the operator. Rewritten that day against the approved spec.
> Spec: [`spec.md`](spec.md) (`APROBADA`, 2026-11-15)

## 1. Approach
Every new decision is a **pure function** in `toolbox/gekko-panel.ts` (where `creationResult`,
`sendKeysText` and `sidebarBindings` already live), covered by the gate. `shell-session.ts`, `gekko-guard.ts` and the scripts only
call them. The wiring is tested with real tmux in `toolbox/tests/handler-harness.ts` and `tools/ws-test.sh`.
No new tools for the model, no new extension, no new environment variable.

## 2. Affected files
| File | Change | AC served |
|---|---|---|
| `toolbox/gekko-panel.ts` | New pure functions: `mirrorDecision`, `mirrorWindowArgs`, `mirrorWindowName`, `staleMirrors`, `sendSteps`, `viewRows`, `policyOverlayBody`, `navBindings`. `PanelRuntime.mirror` (boolean, default `true`) | AC1–AC3, AC5–AC7, AC9 |
| `toolbox/gekko-workspace.ts` | `newSessionArgs` adds `-e IGNOREEOF=10` | AC8 |
| `toolbox/shell-session.ts` | `session_new`: turns on the mouse and opens the mirror after the verified registration. `session_send`: exits copy-mode before sending. `session_start` and `session_shutdown`: close the run's windows | AC1, AC3, AC4, AC6–AC8 |
| `toolbox/gekko-guard.ts` | The `/gekko-policy` overlay draws the "view" block and toggles `runtime.mirror`; the overlay body moves to `policyOverlayBody` | AC5 |
| `tools/pi-hitl.sh` | Inside tmux: marks its session, installs the shortcuts and stays alive while Pi runs (today it only does so with the rail). On exit: closes mirror windows of dead runs, removes the mark and returns the shortcuts | AC6, AC9 |
| `tools/gekko-sidebar.sh` | The installation and restoration of bindings (today only the three clicks) accepts a second set of keys: modes `--keys` and `--keys-restore` | AC9 |
| `docs/prompts/pi-hitl.md` | One line: what appears in a shell may have been typed by the operator | AC10 |
| `docs/pi-hitl.md` | Mirror section: shortcuts, check, scroll, `Ctrl+D`, "do not type secrets", limits | §7 |
| `toolbox/gekko-panel-selftest.ts`, `toolbox/gekko-workspace-selftest.ts` | G cases with `req("REQ-…")` | all |
| `toolbox/tests/handler-harness.ts` | H cases: the `mockPi` stores the `on()` handlers and `execute` receives a fake `ctx` (`mode: "tui"`) | AC1, AC3, AC4, AC6–AC8 |
| `tools/ws-test.sh` | P cases of the launcher | AC6, AC9 |
| `specs/SECURITY-GUARDRAILS-SPEC.md` | New REQs (§3) together with their first test; `REQ-WS-006` changes its text | all |

`tools/pi-hitl.env.example` does not change: there is no new variable (`GEKKO_SHELL_MIRROR` was discarded).

## 3. Decisions (resolve the open items of the spec)
- **How `shell-session.ts` knows there is a TUI:** through the fifth argument of `execute` (`ctx`), with `ctx.mode === "tui"`.
  Verified in Pi's types (`extensions/types.d.ts:514`) and it is the same test the guard already uses to publish the
  panel. It does not depend on the guard being loaded.
- **Where the window is born:** `tmux new-window -d` without `-S` and without `-t`, inheriting `$TMUX` and `$TMUX_PANE` from Pi's process.
  Verified today: it lands in Pi's session and the active window does not change. Without those two variables there is no mirror.
- **Where it attaches:** `env TMUX= tmux -S <socket_path> attach -t <session_id>`, in argv form. The `socket_path` is the one
  captured on creation; if tmux did not return it and there is no label, there is no mirror.
- **State of the check:** `runtime.mirror` in the shared singleton that both extensions already use. It is read as
  "different from `false`", so an absent guard or an old runtime leave the mirror on. `session_start` does not touch it.
- **What "this run" is:** the window is marked with `@gekko_mirror=<Pi pid>`. Pi closes its own by id (it keeps them in memory) in `session_start` and in `session_shutdown`, which Pi fires on exit and on changing session. The launcher,
  on exit, also closes the windows of its session whose pid is no longer alive: it covers a Pi that died without warning and never touches those of another live Pi.
- **Copy-mode:** `session_send` reads `#{pane_in_mode}`; if it is 1 it sends `send-keys -X cancel` (up to 3 times, for stacked modes) and only then the text. One more call to tmux per send.
- **Mouse:** `set-option -t <session_id> mouse on` after capturing the identity, on the shell's server. If it fails, it is ignored.
- **`IGNOREEOF`:** with `new-session -e`, verified today. `setup.sh` already requires tmux ≥ 3.2, which is the version that ships it.
- **Shortcuts:** the launcher marks its session with `@gekko_pi`. `navBindings` generates `bind-key -T root <key> if-shell -F
  '#{@gekko_pi}' <action> <previous binding, or send-keys <key>>`. Saving and restoring the previous binding: the
  mechanism `gekko-sidebar.sh` already has (`@gekko_prev_<key>`), generalized. They are returned when no session on the server keeps the mark.
- **Window name:** `sh-` + the name with everything that is not `[A-Za-z0-9_-]` replaced by `_`, cut to 32.
- **REQ numbering:** `REQ-TMUX-011` (mirror decision and argv: AC1, AC3, AC4) · `REQ-TMUX-012` (name: AC2) ·
  `REQ-TMUX-013` (copy-mode: AC7) · `REQ-TMUX-014` (window closing: AC6) · `REQ-TMUX-015` (warning in the prompt: AC10) ·
  `REQ-WS-010` (`IGNOREEOF` and mouse: AC8) · `REQ-TUI-024` (check: AC5) · `REQ-TUI-025` (shortcuts: AC9). AC11 is regression.

## 4. Risks and mitigation
- **`REQ-WS-006` today fixes the exact arguments of `newSessionArgs`.** They change on purpose: the REQ, its
  two cases and the harness case are updated in the same change.
- **The launcher changes shape inside tmux:** today it does `exec pi` when there is no rail; it will now wait for Pi always
  while inside tmux. Outside tmux the `exec` continues. Covered by the existing `ws-test.sh` cases plus the new ones.
- **The scripts are edited with Pi running from this same checkout.** bash reads the script in chunks: they are replaced by atomic rename (copy, edit, `mv`), as in the fix of `REQ-WS-009`.
- **`session_shutdown` on exit:** I do not know how long Pi waits for a handler; the closing uses synchronous calls with a short time limit. If it still does not arrive, the launcher's sweep remains.
- **Wiring outside the gate (GAP-27, GAP-76, GAP-77):** H and P are run and recorded in `tasks.md`; the REQs say so in their limit line.
- **Not verified:** injecting a key into a tmux client from the test (`send-keys -K`); if it does not work, the test uses a nested client, which worked today. The argv form in tmux 3.2 (tested on 3.6b).
- **Agent shells and a nested client on the same server:** it is the common case and the one tested by hand today.

## 5. Order of attack
Red tests before each block; the REQ enters the living spec with its first test.
1. **Pure mirror functions, copy-mode, name and closing** in `gekko-panel.ts` (AC1–AC3, AC6, AC7).
2. **`newSessionArgs`** with `IGNOREEOF` and `REQ-WS-006` up to date (AC8).
3. **Wiring in `shell-session.ts`** and H cases (AC1, AC3, AC4, AC6–AC8). Depends on 1 and 2.
4. **Check in the overlay** (`gekko-panel.ts` + `gekko-guard.ts`) (AC5).
5. **Shortcuts and closing in the launcher** (`navBindings`, `gekko-sidebar.sh`, `pi-hitl.sh`) and P cases (AC6, AC9).
6. **Prompt and docs** (AC10).
7. **Full regression** (AC11) and a real run with Pi in the operator's environment.

Blocks 1, 2, 4 and 6 touch different files and can go in parallel; 3 and 5 wait for 1.
