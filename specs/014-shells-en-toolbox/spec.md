# Spec 014 — Execution mode with Pi open: live switch, visible state, toolbox mirror and shutdown

> Status: `IMPLEMENTADA` (2026-11-16: real run by the operator, T7, all steps green) · `APROBADA` — the operator approved it on 2026-11-16 conditioned on the independent review («si pasa la revisión estoy de acuerdo, implementala» — "if it passes the review I agree, implement it"); the third pass gave "passes with fixes" and the fixes are applied (§9).
> Date: 2026-11-16 (rewritten; the 2026-11-15 draft stays in the git history) · Design source: §8
> Builds on [`013-lanzador-unico`](../013-lanzador-unico/spec.md), which already implemented the mechanism, and on the mirror of
> [`011`](../011-espejo-shells/spec.md). It reimplements nothing from 013: it only adds what is missing.

## 1. Problem (one sentence)
With 013 the mode (`os` or `toolbox`) is decided at launch and cannot be changed with Pi open; the rail and the bar do not
say which mode is in use or whether the container is still alive; a toolbox shell has no mirror window (`mirrorDecision` refuses it with "modo toolbox"); and the container can only be stopped by hand with `docker`.

## 2. Goal (one sentence)
With Pi open the operator switches mode from `/gekko-policy` with confirmation, sees the mode and whether the toolbox is `levantando` (starting), `lista` (ready) or `caída` (down) in the rail and the bar, enters a toolbox shell through the mirror window, and stops the workspace container with `/gekko-toolbox off`.

## 3. Context / why now
- 013 left: the mode file `engagements/<ws>/exec`, the container `gekko-tb-<ws>` with its mounts and its adoption check (REQ-TBX-003, 007), tmux inside the container by ID (REQ-TBX-004, 008), the `bash` block (REQ-TBX-005) and the warning to the model (REQ-TBX-006). All of that is used as is.
- A second implementation existed on another branch (`spec/014-shells-en-toolbox`). The operator chose 013 and asked to add the four things that branch had and 013 did not (§8).
- It decides where the model executes and what the operator sees about it: it is a boundary (SECURITY-GUARDRAILS-SPEC §1).

## 4. Scope
**In:**
- **Visible state:** the rail and the bar show the mode and, in toolbox, the state. Each shell says where it lives, in the SHELLS card and in `session_list`. The rail still cannot change anything.
- **States:** `levantando` (starting), `lista` (ready), `caída` (down). With TUI the container is periodically checked to be still the same and still running. Leaving `caída` only happens through an operator action: retry, or `/gekko-toolbox off`.
- **Live switch:** an "ejecución" (execution) block in the `/gekko-policy` overlay, separate from the pre-authorizations and from "vista" (view). Switching asks for confirmation inside the overlay, in both directions. Switching to toolbox starts the container through the same path as the launcher, with the same workspace validation.
- **In-memory mode:** a running Pi has its mode in memory, and only the overlay and `/gekko-toolbox off` change it. The `exec` file is read at launch and never again.
- **Shells that already exist:** they are not moved or closed when the mode changes; they keep being handled where they were born.
- **Shutdown:** `/gekko-toolbox off` stops the container of this workspace, with confirmation, and leaves the mode at `os`.
- **Toolbox mirror:** a toolbox shell opens its window in the operator's tmux just like a host shell. The tmux client that attaches runs inside the container.
- **Launcher:** the "container active" warning on exit also applies inside tmux and for a container started live; the banner says the mode it shows is the one from launch.
- **Hardening found when comparing the two branches:** a workspace whose directory is a symbolic link is refused.

**Out (explicit, anti scope-creep):**
- Changing the 013 container: name, mounts, capabilities, adoption check, VPN.
- Moving a live shell from one place to the other; bringing the `bash` tool or the read tools into the container.
- A clickable control on the rail; a shutdown control in the overlay; deleting the container (`off` only stops it).
- Stopping the container of another workspace, or any container that is not `gekko-tb-<this workspace>`.
- Raising or lowering the VPN from Pi; checking that the toolbox reaches the target.
- Preventing the model, from its host `bash`, from using `docker` or writing the `exec` file (§6: remaining limits).
- Creating a workspace from inside Pi.

## 5. Acceptance criteria (testable)
> **G** = gate (`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`): pure functions and
> guard handlers with `docker` injected, with `req("REQ-…")`. **H** = `toolbox/tests/handler-harness.ts` in `os` mode.
> **R** = real docker and image `gekko-toolbox:latest`: the same harness with `GEKKO_TEST_TOOLBOX=1` (shell handlers and guard functions with the real executor) and `bash tools/toolbox-test.sh` (CLI); a SKIP does not count as green. **P** = `bash tools/ws-test.sh` (real launcher, inside and outside tmux). **T** = `bash tools/tui-test.sh`.

| # | Criterion (observable) | Test |
|---|---|---|
| AC1 | The rail and the status bar show `os`, or `toolbox` with its state (`levantando`, `lista`, `caída`); in `caída`, the rail shows the reason, trimmed and without control characters (it comes from `docker`: it is not trusted). The SHELLS card and `session_list` say where each shell lives. | G · H · R · T |
| AC2 | The rail process has no path that changes the mode, writes `exec` or invokes `docker`: a text contract over `toolbox/gekko-sidebar.mjs`, with cases that make it fail when one is added. | G · T |
| AC3 | WHEN the container stops running, or is no longer the one of the validated ID, while `lista`, THEN with TUI (`ctx.mode` is `tui`) the state becomes `caída` at the next periodic check (within 10 s at most). `session_new` does not wait for that check: before creating a toolbox shell it verifies that the validated ID still resolves to that same running container, and if not, it returns FAIL without creating anything anywhere. | G · R |
| AC4 | WHEN the mode is toolbox and the state is `levantando` or `caída` —also the `caída` of a failed start— THEN `session_new` returns FAIL naming the state, before invoking anything. | G · H |
| AC5 | Leaving `caída` does not happen on its own: the state only returns to `lista` when the operator activates again and the full adoption check passes. | G |
| AC6 | The `/gekko-policy` overlay shows an "ejecución" block with one row: the mode and, in toolbox, the state. It is not a pre-authorization: it does not create or delete authorizations, and `c` does not touch it. | G |
| AC7 | WHEN the operator asks to switch, THEN a confirmation opens inside the overlay; if it is rejected, or another key is pressed, nothing changes and nothing is started or stopped. Toward toolbox it names the workspace, the container, the real path of the directory that is mounted, whether it will carry VPN, and whether the container will be **created**, **started** (it exists stopped) or **adopted** (it is already running). Toward `os` it says that new shells are born on the host and that the `bash` block stops applying. In `caída` the row offers **retry** (it stays in toolbox, same confirmation as toward toolbox); from `caída` to `os` one goes through `/gekko-toolbox off`. | G |
| AC8 | WHEN the switch to toolbox is confirmed, THEN the state is `levantando` and the container is started once, through the same path as the launcher: workspace validation (including AC19), same arguments and same adoption check (REQ-TBX-003, 007). It moves to `lista` only with the validated ID. If it fails (invalid workspace, no docker, no image, foreign container, failed start), it stays in toolbox `caída` with the reason: it never moves to `os` on its own. | G · R |
| AC9 | WHEN the switch back to `os` is confirmed, THEN new shells are born on the host and the container stays up. The tmux socket of a host shell is kept outside the real directory of the workspace, even if Pi was launched in toolbox; if the only available directory falls inside, the shell with its own socket is refused. That of a toolbox shell is always under `<workspace>/.gekko-sockets`. | G · H · R |
| AC10 | The mode of a running Pi lives in memory: rewriting `exec` on disk and changing Pi session (`session_start`) does not change it, and it does not change the state or the validated ID either. | G |
| AC11 | Pi changes the mode saved in `engagements/<ws>/exec` only at two moments: when a step to toolbox reaches `lista` and when the return to `os` is confirmed. A failed start does not change the saved mode, and the next launch starts in the mode the file says, without asking. | G · P |
| AC12 | After a change, earlier shells stay alive where they were born, and `session_send`, `session_read`, `session_list` and `session_kill` keep reaching them. A new shell is born entirely in the mode that applied when the call started, even if the operator changes mode while it is being created, and its result says where. `session_new` refuses a name that already belongs to a live shell of its own in the other place. | H · R |
| AC13 | The `bash` block of REQ-TBX-005 follows the current mode from the moment of the change: it applies in toolbox, also in `levantando` and `caída`, and stops applying in `os`. | G |
| AC14 | The mode change and the shutdown exist only behind the overlay and `/gekko-toolbox`, which refuse when `ctx.mode` is not `tui`; no tool registered for the model invokes them. It is a text contract over the code (like AC2), with cases that make it fail: it does not prove who presses the key (§6). | G |
| AC15 | WHEN there is no workspace (`GEKKO_WORKSPACE=none`), THEN asking for toolbox or running `/gekko-toolbox off` does not invoke `docker` and says how to create a workspace. | G |
| AC16 | The model prompt describes both modes (where each thing runs in each one), says which one applies at launch, says that the operator can change it with Pi open, and that the result of `session_new` indicates where the shell was born. | G (regex over the text) |
| AC17 | WHEN the operator runs `/gekko-toolbox off`, THEN the container `gekko-tb-<ws>` is identified with a new `inspect`; if this session validated an ID and the one from `inspect` is another, that container is not touched. If it is running, or the mode is toolbox, it asks for confirmation with the name, the short ID, that **all** shells it holds die (and how many this session knows of), and that the mode goes to `os` and the `bash` block stops applying. After accepting: `docker stop` by ID only if it is running, mode `os` in memory and saved, and the toolbox shells are listed as closed. If `stop` fails it says so and does not change the mode. If `inspect` fails (no docker) or the ID is another, it does not stop anything, says so, and offers —with the same confirmation— to set the mode to `os`: from `caída` there is always a way out inside Pi. In `levantando` it refuses. Already stopped and in `os`: it says so and does not call `docker stop`. No other container is touched. With another argument it shows the state and the usage. | G · R |
| AC18 | WHEN a toolbox shell is born and the conditions of the 011 mirror are met, THEN its window is opened in the operator's tmux and what is typed there runs inside the container. The tmux client that attaches runs **inside** the container, by the validated ID: the window's command is never a host tmux pointing to a container socket (contract over the argv). Opening and marking the window go to the host tmux, never to the container's. With the check cleared it does not open; when switching session or leaving Pi, the client inside the container is detached, the window closes and the shell stays alive; if the detach responds in time no client is left hanging; if the container stops, the window closes by itself. | G · R |
| AC19 | WHEN the directory of a workspace (its last component) is a symbolic link, THEN the CLI and the launcher refuse it before reading its scope and before creating or reusing a container, and the live switch to toolbox does too (AC8). An existing workspace that is a link stops starting, with a message that says to replace it with the real directory. | G · P |
| AC20 | WHEN Pi ends and `gekko-tb-<ws>` is running, THEN the launcher warns that the container is still active and how to stop it, inside and outside tmux, also if it was started live. The banner says the mode it shows is the one from launch. | P |
| AC21 | Regression: the gate, the harness in `os`, `tools/ws-test.sh`, `tools/toolbox-test.sh`, `tools/tui-test.sh`, `tools/report-test.sh`, `.githooks/test.sh` and `toolbox/tests/mirror-stress.ts` stay green; in `os` and without touching the control, everything behaves as it does today. **They are replaced**, not kept, the cases that asserted that the mirror does not exist in toolbox (`toolbox/gekko-panel-selftest.ts`, `toolbox/tests/handler-harness.ts`). | The eight commands |

**Requirements of the living spec that this spec modifies:** `REQ-TMUX-011` and `REQ-TBX-004` (the mirror exception in toolbox falls), `REQ-TBX-001` (the mode is also saved from Pi, after confirmation), `REQ-TBX-005` (follows the current mode), `REQ-TBX-006` (prompt text), `REQ-TBX-008` (the socket directory leaves the place of each shell).

## 6. Risks, remaining limits and open decisions
- **Going back to `os` is the direction that loosens:** commands stop running in the container and the `bash` block stops applying. That is why it asks for confirmation, also inside `/gekko-toolbox off`.
- **Limit: the model has `bash` on the host.** From there it can write `exec` and change the mode of the **next** launch (already admitted in REQ-TBX-001; the banner shows the mode at launch), and it can use `docker` to stop, delete or recreate `gekko-tb-<ws>`. What this spec guarantees against that: the mode of the running Pi does not change (AC10), a recreated container is only used if the operator activates again and passes the adoption check (AC5, AC8), and the confirmation says that an existing one is adopted (AC7). That the content of an adopted container can be trusted is not guaranteed, and the three guarantees hold only while the model does not type into the TUI (next limit). Closing this requires vetoing `docker` and the writing of `exec` in the guard: another spec.
- **Limit: the model can type into the Pi TUI.** Pi runs inside the operator's tmux and the model's `bash` is a child of Pi: `tmux send-keys -t "$TMUX_PANE" …` writes to the same terminal as the operator. With that it can open the overlay or run `/gekko-toolbox off` and press the confirmation key, and thus return to `os`. The guard today lets it through. It is not specific to this spec: it applies equally to the confirmations that already exist (adding a host to the scope, AGGRESSIVE mode, `/gekko-policy`), and it is recorded as a gap in the living spec §4. Verified at the tmux and guard level, not in a live Pi. Gekko's confirmations stop a model that makes a mistake, not one that attacks its own harness. Reducing it requires vetoing in the guard the `tmux` that writes to foreign terminals: another spec, and it only tightens.
- **Limit: the ID is not eternal identity.** `docker` accepts a container whose **name** is the ID of another that was already deleted (tested on docker 29.6.1). The periodic check and the one in `session_new` detect it because they compare the ID that `inspect` returns (AC3); shells that already existed in the toolbox are not re-checked on every operation. The `Límite` of REQ-TBX-003 is corrected in the same direction.
- **Race in the confirmation:** "create / start / adopt" is determined when the confirmation opens and the container is started after the key; a `docker run` by the model at that instant gets adopted under a text that said "create". The adoption check applies anyway.
- **Not containment**, as in 013: the container runs as root with `NET_ADMIN` and the workspace mounted read-write.
- **Symbolic link:** the validation and the `docker run` are not atomic; a replacement at that instant is not seen. Only the last component is checked: an `engagements/` that is a link to another disk is an operator decision and is accepted.
- **VPN:** the container started live carries the VPN only if Pi was launched with `GEKKO_OVPN`. Two tunnels with the same `.ovpn` at once clash (CLAUDE.md, "VPN modes"): the confirmation says so, it does not prevent it.
- **Without TUI** there is no overlay and no periodic check: the state is the one from launch, it cannot leave `caída`, and `session_new` fails closed by ID.
- **Two Pi on the same workspace:** each has its mode in memory. The `off` of one kills the other's shells, which sees them as `caída` at its next check. Two simultaneous starts compete for the name: the loser stays in `caída` with a healthy container and is fixed by activating again.
- **Shell count on `off`:** it only knows the shells of this Pi session; after a session change, or with another Pi, there are shells inside that it does not count. That is why the confirmation says that **all** of them die.
- **Mirror window:** an operator `remain-on-exit` leaves the dead pane in view; if the window closes without going through Pi (the operator kills it, Pi dies suddenly), or the detach does not respond within the deadline when leaving, a tmux client stays attached inside the container. The detach removes **all** clients from that shell, including one the operator attached by hand. The panel file can be written by whoever has `bash` on the host (REQ-TUI-020): the truth in process is the bar and the overlay.
- **The confirmation is a single key** (`s`), and the wiring of the overlay is tested with a component driven from the gate, not with the keys of a real Pi (same limit as REQ-TUI-024).
- **Identifiers:** the other branch used `REQ-TUI-027`, `REQ-TUI-028` and `REQ-TBX-001` to `010` with other meanings. Here numbering continues from the ones free in this branch: `REQ-TUI-028`, `REQ-TBX-009`, `REQ-TMUX-017`, `REQ-WS-011`.
- **For `plan.md`:** how each shell stores its place and how each operation reaches the right place; who starts the container from Pi and with what deadline; frequency and call of the check; how the mirror window is assembled.

## 7. Signs of "done"
AC1–AC21 green at once + `tasks.md` complete with its record + a real run by the operator: launch in `os`, switch to toolbox from `/gekko-policy`, see `levantando` and `lista` in the rail, request a shell, enter through its mirror window and end up inside the container, return to `os`, and shut down with `/gekko-toolbox off`.

## 8. Operator decisions
**2026-11-15** (original request, still in force):

| Topic | Decision |
|---|---|
| Where the control goes | In the overlay; the rail shows it (the rail stays read-only). It must ask for confirmation. |
| What runs inside | Only the shells of `session_new`; the model keeps reading the KB from the host. |
| Container | One per workspace, alive until the operator shuts it down. |
| While starting or if it falls | `session_new` fails with a clear warning; it never creates the shell on the host as an alternative. |
| Going back to `os` | Asks for confirmation. |
| No workspace | "Si no hay workspace creado se pide crear uno." ("If no workspace has been created, creating one is requested.") |
| Shutting down the container | Not from the panel: "que haya un comando `/gekko-toolbox off`" ("there should be a `/gekko-toolbox off` command"). |

**2026-11-16:**
- Between the two implementations: "ok queda la 013" ("ok, 013 stays").
- "a la 013 agregale lo de /gekko-toolbox off" ("add the /gekko-toolbox off thing to 013"); "lo de cambiar de modo, espejo en toolbox y lo del estado visible tmb" ("the mode switch, the toolbox mirror and the visible state too").
- "revisalo con code-reviewer; si pasa la revisión estoy de acuerdo, implementala" ("review it with code-reviewer; if it passes the review I agree, implement it").

**Assumptions of the author, without an operator answer yet:**
- A failed start leaves the mode in toolbox `caída` in that Pi, but does not change the saved mode (AC8, AC11).
- `/gekko-toolbox off` stops the container without deleting it.
- The mode is still called `os`, as in 013, and not `host`.
- That the model can use `docker` and write `exec` from the host is left as a written limit, not vetoed here (§6).
- An existing workspace that is a symbolic link stops starting (AC19).
- That the model can type into the Pi TUI with `tmux send-keys` is left as a written limit and as a gap in the living spec; it is not vetoed in this spec (§6). **It is the decision the operator should look at most closely.**

## 9. Independent review (2026-11-16)
First version: **did not pass** (one blocker, eleven points to fix, all textual). What changed in the second:

| Finding | Change |
|---|---|
| S1 (blocker): "only the operator changes the mode" was false; the model writes `exec` from the host | AC10 and AC14 assert only what can be proven (in-memory mode); the rest moves to §6 as a limit |
| S2: the model handles the container with `docker` | AC5 (leaving `caída`), AC7 (create / start / adopt), limit in §6 |
| S3: the live start skipped the workspace validation | AC8 requires it; AC7 shows the real path; AC19 covers the live path |
| S4: socket of a host shell inside the workspace; mirror client on the host | AC9 and AC18 |
| S5: the mirror AC contradicted the regression | AC21 says which cases are replaced; list of modified requirements |
| S6: tests that could not demonstrate the criterion | test column redone; R includes the harness with real docker |
| S7: `levantando`, `caída` from a failed start and the call in progress were missing | AC4, AC12 |
| S8: same name in the two places | AC12 refuses it |
| S9: gaps in `off` | AC17 |
| S10: a failed start left the workspace unable to launch | AC11: the mode is only saved when the change succeeds |
| S11: prompt, banner and exit warning were out of date | AC16, AC20 |
| S12: without TUI, session change, two Pi | AC10 and §6 |
| M1 (from the merge): the exit warning was lost inside tmux | AC20 |

Second version: **did not pass** (one new blocker; plan and tasks, "passes with fixes"). What changed in the third:

| Finding | Change |
|---|---|
| N1 (blocker): the model can type into the Pi TUI with `tmux send-keys` | AC14 asserts only the contract over the code; limit in §6 and §8; gap in the living spec §4 |
| N2: a container named with the old ID resolves by ID | AC3: `session_new` compares the ID before creating; limit in §6 |
| N3: AC11 was absolute | «Pi escribe `exec` sólo en…» ("Pi writes `exec` only at…") → "Pi writes `exec` only at…" (wording made conditional) |
| N4: race between the confirmation and the start | limit in §6 |
| P2: closing the mirror window left a client inside the container | AC18: detach before closing |
| P3: no exit warning in `os` outside tmux | plan D12 |
| P4: retrying a `caída` went through `os` | AC7: direct retry |
| Edges of the socket directory | AC9 |

Third version: **passes with fixes** (spec, plan and tasks). Fixes applied: `/gekko-toolbox off` always leaves a way out to `os` (AC17); the socket directory in `os` falls back to the temporary one before refusing (plan D2); the detach of the mirror has a deadline (AC18, plan D10). What the review leaves open and is not part of this spec: gap GAP-78.
