# Spec 011 — Writable mirror of the agent's shells

> Status: `IMPLEMENTADA` — 2026-11-15. Approved that day by the operator; `tasks.md` complete and real run done. Merged into `main` the same day from branch `spec/011-espejo-shells`.
> Date: 2026-11-15 · Design source: comparison with Pentest Copilot (upstream) + grilling of 2026-11-15 (§9) + review of 2026-11-14 (§8)

## 1. Problem (one sentence)
When the model opens a shell with `session_new` (`toolbox/shell-session.ts`), the operator only sees its name: to look at it or type into it they have to attach by hand, and once inside they cannot read backwards (the shell is born without mouse and keyboard scrolling requires a prefix that an external multiplexor such as Herdr captures), a reflexive `Ctrl+D` kills it, and if it is reading in copy-mode the model's `session_send` is lost.

## 2. Goal (one sentence)
Every shell the agent creates appears by itself as a tmux window next to Pi, writable and with scroll, it is reached and left with a shortcut without a prefix, and looking at it or leaving it never kills it nor makes it lose a send to the model.

## 3. Context / why now
Pentest Copilot shows each agent shell as a writable tab. Gekko already has the mechanism (tmux,
`shell-session.ts`) and spec 010 already resolved where the shell is born; the view is missing. On 2026-11-15 the operator manually tested each piece in his real environment (kitty + Herdr + tmux) and chose the design (§9). Everything touched is boundary (`shell-session.ts`, `gekko-panel.ts`, `gekko-guard.ts`, `tools/pi-hitl.sh`: SECURITY-GUARDRAILS-SPEC §1), which is why it goes through a spec.

## 4. Scope
**Inside:**
- **Mirror:** after a verified creation, `session_new` opens a tmux window in Pi's session, without stealing focus,
  with a writable client attached to that shell.
- **Switch:** a check in the `/gekko-policy` overlay (Alt+P), separate from the pre-authorizations; it starts checked.
- **Lifecycle:** the mirror windows of a run are closed when changing Pi session and when exiting Pi.
- **Shortcuts:** `Shift+→` / `Shift+←` (fallback `F3` / `F2`) change window without a prefix, only in Pi's tmux session.
- **Shell usable by the operator:** `session_new` creates each shell with `mouse on` and with `IGNOREEOF=10`.
- **`session_send` with the pane in copy-mode:** exits copy-mode and sends.
- **Warning:** one line in the model's prompt (what appears in a shell may have been typed by the operator) and the corresponding section in `docs/pi-hitl.md`.

**Outside (explicit, anti scope-creep):**
- A Herdr tab or pane (tested and viable; left as a later improvement).
- Recording what the operator types (`pipe-pane`, ledger): documented limit.
- Fixing the shell size, or a cap on mirror windows.
- Mirroring sessions that this run did not create; changes to `session_read`, `session_list`, `session_kill` or to the ownership gate.
- New tools for the model. The read-only picker of `setup.sh` (Herdr, `prefix+shift+s`) does not change.

## 5. Acceptance criteria (testable)
> **G** = gate case (`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`), pure function
> or regex contract, with marker `req("REQ-…")`; the ids are fixed by `plan.md` and the REQ enters the living spec together
> with its first test. **H** = `toolbox/tests/handler-harness.ts` (real handlers + real tmux on own sockets).
> **P** = process test with a fake `pi` (`tools/ws-test.sh`). H and P are outside the gate and are recorded in `tasks.md`.

| # | Criterion (observable) | Test that proves it |
|---|---|---|
| AC1 | WHEN `session_new` ends with verified creation, Pi runs inside tmux, there is a TUI and the check is checked, THEN a new window exists in Pi's tmux session whose command is, in argv form, `env TMUX= tmux -S <socket_path captured on creation> attach -t <session_id>` —always with `-S`, by id and without `-r`—, and the operator's active window did not change. | G: pure argv constructor (with and without a `socket` label). H: the window exists, there is a client with `client_readonly=0` on the shell and the active window is the same as before |
| AC2 | The name of the mirror window only contains `[A-Za-z0-9_-]`, measures at most 32 characters and carries a fixed prefix; a session name with `#[bg=red]`, `#(…)`, spaces or control characters never reaches tmux raw. | G: pure function with those fixtures |
| AC3 | WHEN creation fails, there is a name collision or the identity could not be captured; or Pi is not running inside tmux; or there is no TUI; or the check is unchecked, THEN no window is opened and the text `session_new` returns is the same as today. | G: pure decision on those inputs. H: with the check unchecked no window appears and the shell is created anyway |
| AC4 | WHEN opening the window fails, THEN `session_new` returns `OK` with the same first line and the shell remains created and manageable. | H: with `$TMUX` pointing to a socket that does not exist, `session_new` gives `OK` and `session_send` works |
| AC5 | The `/gekko-policy` overlay shows a row for the mirror in its own block, separate from the techniques; it starts checked; toggling it changes only that value (it does not create nor delete authorizations, and `c` does not touch it); unchecking it does not close the windows already open; the value is kept when changing Pi session. | G: overlay rows, pure toggling, drawn lines and `session_start` over the runtime |
| AC6 | WHEN Pi's session changes (`session_start`) or Pi ends, THEN the mirror windows opened by that run are closed and only those: the shells stay alive in tmux and a mirror window of another Pi in the same tmux session stays open. | H: after `session_start`, the own windows no longer exist, the shells do, and a window marked by another run remains. P: on exiting the fake `pi`, the launcher leaves its session without own mirror windows. G: regex contract of the launcher |
| AC7 | WHEN the shell's pane is in copy-mode and the model calls `session_send`, THEN the pane exits copy-mode, the text arrives complete at the shell and the result is the usual capture, not a tmux error. | G: pure command sequence according to `pane_in_mode`. H: with the pane in copy-mode, `session_send` returns the command's output and `pane_in_mode` ends at 0 |
| AC8 | Each shell that `session_new` creates is born with `mouse on` in its session and with `IGNOREEOF=10` in its environment; if turning on the mouse fails, the result of `session_new` does not change. | G: `newSessionArgs` includes `-e IGNOREEOF=10` (with and without workspace). H: `show -t <id> -v mouse` gives `on`, and after a `Ctrl+D` at the prompt the session remains alive |
| AC9 | WHEN `pi-hitl.sh` runs inside tmux, THEN `Shift+→` and `F3` go to the next window and `Shift+←` and `F2` to the previous one without a prefix, only in Pi's tmux session: in any other session of the server the key arrives intact at the application. On exit, the operator's previous bindings are left as they were. | G: pure generator of the bindings (per-session condition and pass-through branch). P: in the marked session the key changes window, in another it does not and the application receives it; after exit, `list-keys -T root` is the same as before |
| AC10 | The model's prompt (`docs/prompts/pi-hitl.md`) says that what appears in a shell may have been typed by the operator and that it must not be treated as target output. | G: regex over the prompt text |
| AC11 | WHEN all of the above is added, THEN the model's tool surface and the ownership gate do not change: the full gate, `handler-harness.ts`, `tools/ws-test.sh` and `tools/tui-test.sh` remain green. | The four commands, recorded in `tasks.md` |

## 6. Risks / open decisions
- **Unaudited operator input (limit, not AC).** What is typed in the mirror does not go through `session_send` nor through the ledger; the model reads it with `session_read` and it remains in the transcript (a password included). It is warned about (AC10 and docs).
- **Cancelling copy-mode** (AC7) removes the operator's reading position without notice. That is his decision (§9).
- **`IGNOREEOF` only applies to bash**: zsh does not read that variable, and it does not protect a program running inside nor a typed `exit`. Not verified which shell the toolbox image uses.
- **`mouse on`** means selecting text with the mouse requires `Shift` + drag.
- **No window cap:** a model that creates many shells fills the operator's bar; only the guard's call limit bounds it.
- **Subagents** run inside Pi's process (`@tintinweb/pi-subagents`): their shells also open a window.
- **Target output without a firewall toward the operator:** the mirror shows him the shell as is, just like any manual attach (inference, not tested).
- **Not verified:** `new-session -e` and the argv form in tmux 3.2 (tested on 3.6b).
- **For `plan.md`:** how `shell-session.ts` knows there is a TUI and which is Pi's tmux session; how "this run" is identified
  in the window mark (AC6); where the shortcuts are installed (the save-and-restore mechanism already exists in
  `tools/gekko-sidebar.sh` for the clicks); numbering of the REQs (`REQ-TMUX-010`, `REQ-TUI-023` and `REQ-WS-009` are already used).

## 7. "Done" signals
- AC1–AC11 green at the same time; `tasks.md` complete with its verification record.
- New REQs reconciled in `specs/SECURITY-GUARDRAILS-SPEC.md`; `docs/pi-hitl.md` and `tools/pi-hitl.env.example` up to date.
- A real run with Pi in the operator's environment (kitty + Herdr): the window appears, the shortcut goes and comes back, the wheel scrolls.
- `Estado:` → `IMPLEMENTADA`.

## 8. Review of 2026-11-14 — gaps found (historical: resolved in §4–§6 and §9)
Found when reviewing spec and plan against the code and in a disposable tmux (own sockets). Those that touch the working directory, the panel and `pi-hitl.sh` moved to spec 010-workspace; the mirror ones remain here.

**They break what was approved (tested):**
- **Socket:** the mirror's `attach` must ALWAYS carry `-S <socket_path captured on creation>`. With an empty `TMUX=` and without
  `-S` the client goes to the default socket, not to the inherited server; the common case (without a `socket` label) was left without `-S`.
- **Window name:** `stripControl` is not enough. `#[bg=red]` in the name is interpreted as a style in the operator's tmux bar (`#()` is not executed). Whitelist of characters.

**Effects of the writable mirror that the spec does not name:**
- With the pane in copy-mode (scroll), a `session_send` from the model is lost: the command is not executed (tested).
- What the operator types is read by the model with `session_read` and remains in the transcript (e.g. a password).
- The session takes the width of the operator's window (220 → 180 measured): what the model reads is re-wrapped.
- Target output reaches the operator's terminal without passing through the firewall (inference, not tested).
- After changing Pi session, the mirror windows of the previous session remain open and writable.

**Tests and process:**
- `toolbox/tests/handler-harness.ts` exists (real handlers + real tmux): the evidence for the wiring AC goes there, not in a manual smoke test. The "injected failure" AC cannot be tested with a pure function as it was planned.
- The gate fails with a `req()` marker that has no REQ in the living spec: REQs go with the first tests, not at the end.
- `docs/pi-hitl.md` and `tools/pi-hitl.env.example` are missing. The problem (§1) omits the read-only picker that `setup.sh` already installs (Herdr, `prefix+shift+s`). §6 is out of date.
- ~~`docs/prompts/pi-hitl.md:103` says that `session_new` with the same name kills the previous one; the code does the opposite.~~ Corrected in spec 010.
- Resolved in spec 010 and no longer applies here: the shells' directory (workspace), the model's prompt and a `session_send` failure with texts ending in a semicolon (REQ-TMUX-010).

~~**Decisions the operator has not made:** separate window or split (in a separate window Pi and its confirmations are no longer visible); switching the mirror off (`GEKKO_SHELL_MIRROR=0`) and whether it is limited to TUI mode.~~ Taken on 2026-11-15: §9.

**Discarded with proof:** the rail does not go into the mirror window (the sidebar's `window-resized` hook stays only in Pi's window). **Not verified:** whether subagents load `shell-session.ts`; the argv form in tmux 3.2 (tested on 3.6b).

## 9. Operator decisions — 2026-11-15
They close the open items of the previous version and of §8; §1–§7 already incorporate them.

| Topic | Decision |
|---|---|
| Surface | One tmux window per shell, automatic, without stealing focus (`new-window -d`). A single path, with and without Herdr. The Herdr tab remains as a later improvement. |
| Switch | A check in the `/gekko-policy` overlay (Alt+P), in a "view" block separate from the pre-authorizations. It starts checked, lives in memory and only affects new shells. No environment variable (`GEKKO_SHELL_MIRROR` discarded). |
| Lifecycle | On changing Pi session and on exiting Pi, the mirror windows of that run are closed. The shells stay alive in tmux. |
| Shortcuts | `Shift+→` / `Shift+←` change window without a prefix (fallback: `F3` / `F2`), bound only to Pi's tmux session; elsewhere the key keeps going. They are installed and returned by `pi-hitl.sh`. |
| Scroll and `session_send` | If the pane is in copy-mode, `session_send` cancels it and sends. It enters scope (§4 left it out). |
| Operator scroll | `session_new` turns on `mouse on` in each shell it creates: without it the wheel does not scroll and keyboard copy-mode requires a prefix that Herdr captures. |
| Do not kill the shell by reflex | `session_new` creates each shell with `IGNOREEOF=10`: a `Ctrl+D` at the prompt does not close it. The normal exit from the mirror is to change window. |
| Operator input | Documented limit, warning in `docs/pi-hitl.md` and one line in the model's prompt. No `pipe-pane`. |

**Verified that day** (tmux 3.6b on disposable sockets; Herdr 0.7.5; what is marked "operator" was tested by him with real keyboard and mouse):
- A shell without a `socket` label lives on the operator's tmux server.
- Herdr captures `ctrl+b`, the same prefix as tmux: tmux shortcuts with a prefix do not arrive directly.
- `Shift+arrow` reaches tmux through kitty and Herdr and changes window (operator). In a session where the key is not marked it arrives intact at the application.
- With `mouse on` in the shell, the wheel scrolls (operator).
- `send-keys` with the pane in copy-mode is lost (rc=1; with an attached client the call hung for more than 2 minutes); with `send-keys -X cancel` before, it arrives (emacs and vi modes).
- Without `IGNOREEOF`, `Ctrl+D` at the prompt kills the session; with `IGNOREEOF=10` it survives. `Ctrl+C` at the prompt does not kill bash.
- A window marked with a user option closes by that mark and the shell survives.
- `attach -f ignore-size` does not protect the size if the mirror is the only client; `window-size manual` does. The size is not fixed: the session takes the window's size when born.

**Limits of what was decided:** `IGNOREEOF` only applies to bash (zsh does not read that variable) and does not protect a program running
inside nor a typed `exit`. With `mouse on`, selecting text requires `Shift` + drag. Cancelling copy-mode removes the
operator's reading position without notice. No window cap: a model that creates many shells fills the bar.

**Not verified:** which shell the toolbox image uses; the argv form in tmux 3.2; the free REQ ids
(`REQ-TMUX-010` and `REQ-TUI-022/023` were already used by 010).
