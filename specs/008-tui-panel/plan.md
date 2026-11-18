# Technical plan 008 — Info panel as cards (rail + status bar)

> Written AFTER `spec.md` is approved. Translates the what/why into how.
> Status: `IMPLEMENTADA` (operator, 2026-11-17: closed; 12/12 tasks, merged into `main`) · previously `APROBADO` (operator, 2026-11-11) (rev. 2: incorporates the live falsifiers and the adversarial review of 2026-11-11)

## 1. Approach
The two processes of today are kept (guard inside Pi + sidebar in a tmux split). The contract
changes: the guard stops publishing text and publishes `panel.json` (data + color roles of Pi's
theme). All drawing and input interpretation are **pure functions** in
`toolbox/gekko-panel.ts`, which the sidebar imports and the selftest asserts. The sidebar stays a
thin I/O layer and treats the file as **hostile data**. The status bar is mounted with Pi's
standard API (`ctx.ui.setFooter`). No Pi internal is touched.

Measured before this plan:
- `gekko-sidebar.mjs` imports `gekko-panel.ts` directly with Node 22.22.2, no flags or warnings.
- `ctx.ui.theme.getFgAnsi(role)` and `.appearance` work from an extension and change with the theme.
  Pi roles: `accent`, `success`, `warning`, `error`, `dim`, `border`. There is no theme-change event.
- `setFooter` renders one row, updates ctx % after the turn, redraws on resize and does not fail
  without a TUI. It replaces Pi's two footer rows.
- tmux 3.6b bindings: `unbind -n` deletes; saving `list-keys -T root` and re-applying it restores identically.

## 2. Affected files
| File | Change | AC |
|---|---|---|
| `toolbox/gekko-panel.ts` | **Types and state:** `PanelState {v, ts, theme:{appearance, noColor, roles}, cards, bar}`; `buildPanelState(runtime, extras, now)`; `parsePanelState(text) → {ok,state}\|{ok:false,reason}`. **Drawing:** `renderRail(state, width, height, theme, ui, now) → {lines, hits}` (the width is the pane's; it does not know the 140 cutoff); `renderBar(state, width, railVisible, extStatuses) → string`. **Inputs:** `parseMouse(bytes)`, `handleKey(ui, key)`, `toggleAt(ui, hits, row)`; `panel.ui.json` reducer with defaults on corruption. **Theme:** `resolveTheme(state)`: accepts a role only if it matches `^\x1b\[(39\|38;2;N;N;N\|38;5;N\|(3\|9)[0-7])m$`; otherwise the fallback palette according to `appearance` (`"dark"\|"light"`); `noColor` forces none. **Sanitizing:** `stripControl` is extended (same function) to also strip `\t \r \n`, C1 (`\x80-\x9f`) and bidi/zero-width; `renderRail` and `renderBar` apply it to EVERY string before composing, and `buildPanelState` also when publishing. **New data:** block counters and ok/blocked/error tool counters in the runtime; HALLAZGOS count by the 5 statuses of `findings.py` + `otros`. **tmux:** `sidebarBindings(prev)` generates the three bindings wrapping the previous command. `panelDetailLines` is kept (`/gekko-panel` overlay). | AC1–AC5, AC7–AC14, AC18–AC20 |
| `toolbox/gekko-panel-selftest.ts` | `008-ACn:` cases; `ok()` counts by prefix in a `Map` and fails if an expected AC has zero. The assertions of `panel-layout-and-headless` from spec 001 are ported to the folded `renderBar`. | all G, AC17 |
| `toolbox/gekko-guard.ts` | `writePanelState` writes JSON (default `.gekko-state/panel.json`, lines 381 and 423). Periodic publishing with the shape of `refreshShellsLive` (lines 487–507): whole body in `try/catch` that drops `lastCtx`, does nothing if there is no TUI, timer with `unref()`. In that timer: republish every 2 s, re-read `ctx.ui.theme`, `NO_COLOR`, git and ledger. Mounts `setFooter` with `renderBar` (branch from `footerData.getGitBranch()`, model from `ctx.model`, ctx from `ctx.getContextUsage()`, states of other extensions from `footerData`); stops calling `setStatus("gekko")` and mounting the widget above the editor when the bar is mounted. `sidebarLive()` is kept and decides `railVisible`. `/gekko-sidebar` (lines 701–707): below 140 columns it warns that the state is in the bar. | AC1, AC9–AC11, AC13, AC21 |
| `toolbox/gekko-sidebar.mjs` | I/O layer: reads and validates with `parsePanelState`, calls `renderRail`, enables/disables SGR-1006, passes stdin through `parseMouse`/`handleKey`, saves the folding in `panel.ui.json`, keeps touching the empty heartbeat `.alive`. Path default → `panel.json` (line 10). | AC6, AC7, AC14, AC19 |
| `tools/gekko-sidebar.sh` | width 25 % bounded to 36–48 (replaces the defaults of lines 14–15); does not open below 140 columns (single constant); the `window-resized` hook (line 31) resolves the pane by `@gekko_sidebar`, closes it below 140 and reopens it on return. Installs the `sidebarBindings` bindings. Saves the previous binding of each key in a tmux server option (`@gekko_prev_<key>`), only if it does not exist. `--restore`: does nothing while an `@gekko_sidebar` pane remains on the server; if none remains, re-applies what was saved (or `unbind -n` if there was nothing) and deletes the option. Forwards `GEKKO_STALE_MS` to the pane (test knob). | AC6, AC10 |
| `tools/pi-hitl.sh` | default of `GEKKO_PANEL_STATE` → `panel.json` (lines 135, 144); also deletes `panel.ui.json` on launch (D12); removes the `GEKKO_SIDEBAR_WIDTH=16%` export (line 136); calls `gekko-sidebar.sh --restore` in the exit block (after closing the panes, lines 174–176). `tools/gekko-hitl.sh` does not change: it does `exec` and never returns. | AC6, AC19 |
| `tools/pi-hitl.env.example` | document `GEKKO_FINDINGS` | AC18 |
| `setup.sh` | require tmux ≥ 3.2 and node ≥ 22.19 (what Pi 1.5.0 declares); `GEKKO_SETUP_CHECK_ONLY=1` exits with 0 right after the prerequisites block, before installing or writing anything; version extracted with bash expansion. | AC16 |
| `tools/tui-test.sh` | create: process tests (nested tmux, dedicated sockets, polling up to 10 s). Covers AC6–AC10, AC14, AC19 and, as an optional mode, the live smoke. Endpoint and key only via environment variables. | P |
| `.claude/skills/tui-design/SKILL.md` | commit; register in `CLAUDE.md:46`, `AGENTS.md:64` and `:132`, `README.md:50` (7 skills) and `:98` | — |
| `docs/pi-hitl.md`, `AGENTS.md`/`CLAUDE.md` | new panel, keys, requirements, `panel.json` is a mirror and not an authority | — |
| `specs/001-pi-control-panel/tasks.md` | note: since 008 the surface of its AC14 is bar + rail | — |

## 3. Decisions
- **The renderer lives in `gekko-panel.ts`**: it is already the pure module with no Pi imports.
- **Heartbeat `.alive`:** kept as the ONLY sidebar → guard data. Only its modification time is read, and
  only chooses the bar layout (`railVisible`). Fresh = less than 2× the sidebar's polling. When in doubt
  (no heartbeat) the bar shows the essentials. It cannot carry mode, scope or policy.
- **The 140-column cutoff lives only in `gekko-sidebar.sh`.** `renderRail` does not know it; `renderBar`
  receives `railVisible`.
- **Trust:** the sidebar does not trust `panel.json`. It validates version and shape, validates each color
  role against the expression above and sanitizes all text when drawing, not only when publishing.
- **Theme:** roles from `state.theme.roles` (Pi) → fallback palette according to `appearance` → dark.
  `noColor` is published by the guard, which has the operator's environment. No `GEKKO_THEME` nor
  OSC 11 detection. The theme change reaches the rail in ≤ 2 s because the guard re-reads on every publish.
- **Dead guard = `ts` older than 10 s** (publishes every 2 s). The clock is a renderer parameter.
- **HALLAZGOS:** path via `GEKKO_FINDINGS`; without the variable, the card does not exist. Counted by the
  `status` field; glyph `✓` confirmed, `✗` refuted, `?` the rest, always with a word; unknown status
  or invalid line → `otros`. Read in the timer, never in the render. Only integers enter the state.
- **CAMBIOS:** `execFile` (no shell), 2 s timeout, no overlapping two runs, `GIT_OPTIONAL_LOCKS=0`,
  `git -c core.fsmonitor=false -c diff.autoRefreshIndex=false diff --no-ext-diff --no-textconv --shortstat`
  (and `--numstat` for 2 files), every 5 s. A failure leaves the card with its last value.
- **Keys `1`–`8`:** fixed card ids; not renumbered when HALLAZGOS appears or is missing.
- **Folding:** the sidebar's own file (`panel.ui.json`); the guard does not read it. Survives reopening
  the rail; deleted on relaunch (D12).
- **Mouse bindings:** the "outside the sidebar" branch is not written by hand: it is that key's previous
  command, captured from `tmux list-keys -T root`. The previous is saved in a tmux server option,
  never in a workspace file (the model could write it and tmux would execute it).
- **Bar (D11):** branch, mode, model, `ctx NN%/window (auto)`, turn. Pi does not expose to
  extensions whether automatic compaction is on: the guard reads `compaction.enabled` from
  `.pi/settings.json` (and, if missing, from the `settings.json` of `PI_CODING_AGENT_DIR`; default on) in the
  timer. Inferred, not measured: that Pi's live toggle persists there; checked in the smoke.
  Also: states of other extensions on the
  right if they fit, first to drop when width is lacking. The result is trimmed to the width.
- **"Subagents NOT instrumented"** (disclosure from spec 001): stays in the `alt+k` overlay, which already
  contains it; it stops being on the always-visible surface.
- **Minimum versions:** tmux 3.2 (only 3.6b tested) and node 22.19.
- **No gentle-shell code** (D10).

## 4. Risks and mitigation
- **Timer with a stale context** (a `/new` or reload replaces the `ctx`; using it throws and brings Pi
  down) → same shape as `refreshShellsLive`, and AC21 case.
- **Launcher dead without restoring** (kill -9, terminal closed) → conditional bindings remain that
  outside the sidebar run the previous command (cost: one `if` per click). `--restore` is idempotent
  and can be run by hand.
- **Two Gekko sessions on the same tmux server** → the previous is saved only once and
  restored only when no sidebar pane remains.
- **Pi themes with low contrast** → AC9 only requires contrast of the fallback palette; AC8 covers the rest.
- **Glyph widths** (`◌ ▰ ⎇`) → fixed 1-cell table in the selftest; if a real terminal draws them at
  2, they are replaced with safe glyphs in the final recapture.
- **Regression of spec 001** → `panel-layout-and-headless` asserts `widgetLines()`, not the mounted
  widget. Its assertions are ported to the folded `renderBar` at 80 columns: one row ≤ 80; mode and guard
  in text without color; turn visible. `widgetLines` and its test are kept until the bar smoke
  passes; they are deleted in the last task.
- **Not validated in a real terminal:** interaction with the operator's `~/.tmux.conf` and appearance on a
  light terminal. Goes in the final recapture, with the operator.

## 5. Order of attack
Almost everything touches `gekko-panel.ts`, so stages 1–5 go in sequence; each closes with the
gate green.
1. Contract and sanitizing: `PanelState`, `buildPanelState`, `parsePanelState`, extended `stripControl`,
   per-AC counter of the selftest (AC1, AC17, AC20, AC18).
2. `renderRail` + zone map + states (AC2, AC3, AC4, AC11, AC12).
3. `resolveTheme` + fallback palette + no color (AC8, AC9).
4. Inputs: `parseMouse`, `handleKey`, folding reducer (AC5, AC7, AC14, AC19).
5. `renderBar` and `sidebarBindings` (AC10, AC13, G part of AC6); port the spec 001 assertions.
6. In parallel, without touching `gekko-panel.ts`: `setup.sh` (AC16) · `gekko-sidebar.sh` + `pi-hitl.sh` ·
   `tools/tui-test.sh`.
7. Guard: publish JSON, timer, bar, remove widget (AC1, AC13, AC21).
8. Sidebar as I/O layer; process tests green (AC6–AC10, AC14, AC19).
9. Docs and skill registration; `grep panel.lines` empty.
10. Live smoke, recapture at the three sizes and new scoring with the `tui-design` skill.
