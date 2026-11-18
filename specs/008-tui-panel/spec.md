# Spec 008 — Info panel as cards (rail + status bar)

> Status: `IMPLEMENTADA` (operator, 2026-11-17: closed; 12/12 tasks, merged into `main`) · previously `APROBADA` (operator, 2026-11-11) · Amendment 1 approved (operator, 2026-11-11; see §8) · Amendment 2 approved (operator, 2026-11-12; see §8)
> Date: 2026-11-11 · Design source: [`design.md`](design.md) · Test plan: [`test-plan.md`](test-plan.md)
> Visual reference: gentle-shell (MIT). Method skill: `.claude/skills/tui-design/SKILL.md`.

## 1. Problem (one sentence)
The right-hand panel is a single plain-text box with no hierarchy, no theme and read-only
(15/40 in the critique in `design.md`): at 80 columns it loses the guard state, and if Pi dies
it keeps showing `guard ON`.

## 2. Goal (one sentence)
The operator sees the engagement state in a column of collapsible cards (click or key),
legible in light and dark themes, with a one-row status bar, without losing anything at 80 columns.

## 3. Context / why now
Spec 001 left the panel functional but flat. The research confirmed that the reference result
is reachable **without forking Pi**: the tmux sidebar is kept, the guard starts publishing
structured data and the drawing becomes a testable pure function. Today `gekko-sidebar.mjs`
has no automated test at all.

## 4. Scope
**In:**
- JSON contract guard → sidebar (cards + theme roles) instead of pre-rendered text.
- Pure renderer `(state, width, theme) → lines + clickable-zone map` in `toolbox/gekko-panel.ts`.
- Cards, in order: GUARD · SCOPE · TÉCNICAS · SHELLS · HALLAZGOS · KB · SESIÓN · CAMBIOS.
- Collapse/expand by clicking the header and by key; the collapse state persists within the session.
- Light and dark theme **following Pi's active theme**: the guard exports the roles (`accent`, `ok`,
  `warn`, `danger`, `dim`, `border`) in the JSON; the sidebar does not pick colors on its own.
- `setup.sh` verifies that tmux is installed (minimum version with SGR mouse) and fails with a clear
  message if it is missing: tmux is a hard requirement of the rail.
- One-row status bar (branch, mode, model, ctx %, turn/caps).
- Breakpoint: below 140 columns the rail is not drawn. **Whenever the rail is not drawn**
  (narrow terminal, outside tmux, `GEKKO_SIDEBAR=0` or rail closed) the essentials go to the bar.
- Card folding survives closing and reopening the rail within the session; it resets on relaunch.
- Dead-guard detection (stale state → visible warning).

**Out (explicit, anti scope-creep):**
- Forking or patching Pi internals (rail inside Pi): remains a possible evolution, same renderer.
- Clicks that **act** (mode/technique toggles like the `Alt+P` policy overlay): later phase,
  with its own spec. In this spec a click only collapses/expands.
- Cost in money, weekly usage, TODO list, effort: they have no data source today.
- Hover effects (they do not arrive under tmux). Rail without tmux.
- Instrumenting subagents beyond "one is running / none".

## 5. Acceptance criteria (testable)

Test levels: **G** = gate, `008-ACn:` cases in `runPanelSelftest` (runs inside
`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`). **P** = automatic
process test `tools/tui-test.sh` (nested tmux on dedicated sockets; complements the gate, does not
replace it). Every criterion has at least one **G** case.

| # | Criterion (observable) | Test that proves it |
|---|---|---|
| AC1 | The guard publishes a versioned JSON with the cards in fixed order: 7, or 8 if there is a ledger (`GEKKO_FINDINGS`); never a `0/0` card without a source. `parsePanelState` rejects invalid JSON or an unknown version; the rail keeps the last good frame and indicates it. | G |
| AC2 | The renderer is pure: same `(state, width, height, theme, ui, clock)` → same lines; no line exceeds the requested width at 36, 48 and 80 columns. | G |
| AC3 | Each card draws `▾ NOMBRE  conteo` expanded and `▸ NOMBRE  resumen` collapsed on one row; collapsing one does not alter the others. CAMBIOS starts collapsed. If the height is not enough they auto-collapse starting from the last; GUARD never yields, and in the AUSENTE/FALLÓ state it cannot be collapsed. | G |
| AC4 | The zone map returns, for each header row, the right card and only the `toggle` action; a click outside a header changes nothing. | G |
| AC5 | The SGR-1006 mouse parser recognizes press/release with coordinates and discards truncated or garbage sequences. | G |
| AC6 | A real click on the header collapses the card and keyboard focus does not leave the Pi pane, even with fast clicks (< 500 ms). Outside the sidebar, tmux click, double click and triple click behave the same as before installation. When the last Gekko session exits, `tmux list-keys -T root` for those three keys is identical to before. | G: the reducer toggles only the header's card + the three generated bindings wrap the previous command. P: 10 fast clicks, negative control, double click in a normal pane, `diff` of `list-keys` before/after |
| AC7 | With the rail focused, one key collapses/expands the cursor's card, another all of them, and `1`–`8` the card with that fixed id (a card that is not drawn does nothing). | G over `handleKey`. P: capture after sending keys |
| AC8 | Without color (`NO_COLOR` in Pi's environment), rail and bar come out without color SGR and every state remains distinguishable by glyph or word. | G. P: capture with `NO_COLOR` |
| AC9 | The rail colors come from the roles of Pi's active theme published in the JSON; if the JSON changes roles, the rail changes without restarting. Without valid roles it uses its own light/dark palette whose text roles (`dim`, `accent`, `ok`, `warn`, `danger`) have contrast ≥ 4.5:1 against the reference backgrounds in `test-plan.md`; `border` is decorative and exempt. | G (mapping + contrast). P: write roles A then B and check that the captured SGR changes |
| AC10 | When the rail is not drawn (terminal < 140 columns, outside tmux, `GEKKO_SIDEBAR=0` or rail closed) the bar shows mode, guard, scope, shells and the block marker; the guard state never disappears at 80 columns. | G: `renderBar(…, railVisible=false)` at 80 columns. P: 139/140 boundary with `resize-window` |
| AC11 | If the published state is more than 10 s old, the rail shows `guard ?` in the alert role instead of the last value. | G with injected clock |
| AC12 | Empty, long (1000 items) and error states: no card overflows or exceeds the height; finished items fold into a summary row; the render walks at most the per-card cap, not the 1000 items. | G |
| AC13 | The bar takes one row, trimmed to the width, and shows branch, mode, model, ctx % with window and the `(auto)` mark when automatic compaction is on, and turn; with the rail visible it does not repeat what is in the cards (except a guard that is not ON). | G over `renderBar` |
| AC14 | No sidebar event can change mode, scope or policy: the click and key reducers return only UI state, and the only thing the guard reads from the sidebar is the modification time of its heartbeat. | G. P: sha256 of `panel.json` and `scope.txt` equal before and after a burst of clicks and keys |
| AC16 | `setup.sh` exits with an error and says what to install if tmux or node is missing, or if tmux < 3.2 or node < 22.19; with valid versions it continues. | G: `GEKKO_SETUP_CHECK_ONLY=1` with a synthetic `PATH` and fake binaries (`tmux 3.1c`, `tmux 3.2a`, `tmux next-3.5`) |
| AC17 | The selftest prints, for each AC of this spec, how many `008-ACn:` cases it ran, and fails if any on the expected list has zero. | G |
| AC18 | HALLAZGOS contains from the ledger only integers per status (the five from `findings.py` + `otros`); never the path nor any field of a row. An unreadable ledger or one with invalid lines breaks nothing. | G: fixture with a canary in id/title/target/evidence → it appears neither in the JSON nor in the lines |
| AC19 | The folding survives closing and reopening the rail; a corrupt `panel.ui.json` falls back to defaults without breaking. | G over the reducer. P: reopen the pane |
| AC20 | Hostile content does not reach the terminal: a text or a color role with control sequences (`\r`, `\n`, OSC, `ESC[2J`, C1, bidi) never leaves the renderer, even if `panel.json` was written by a third party. Outside the GUARD card nothing is drawn as its header or as its `guard` row (a host, a shell or a foreign card named `guard…` come out quoted), and the reader rejects a state without a GUARD card or whose guard does not match between bar, header and row. It does not promise authenticity: a `panel.json` rewritten whole and coherently by a third party is drawn as is (§6: mirror, not authority). | G: hostile fixtures in host, shell, block reason and theme role (no file-name fixture: CAMBIOS only publishes three integers); every ESC sequence in the output belongs to the allowed list |
| AC21 | Without a TUI (`-p`, `--mode json`, rpc) the guard does not write `panel.json`, does not run git, does not read the ledger and does not mount a bar. | G |

*(AC15 of the approved version moves to §7: a smoke against the real model cannot be a gate.)*

## 6. Risks / open decisions

| # | Decision | Status |
|---|---|---|
| D1 | tmux hard requirement of the rail | Resolved (operator): yes; `setup.sh` verifies it (AC16). |
| D2 | Rail width | Approved: 36–48 columns (25 %), hidden < 140. |
| D3 | Accent | Resolved (operator): Pi's theme accent. Lime/`#3F6212` stays only in the fallback palette. |
| D4 | Theme selection | Resolved (operator): follows Pi's theme; no own toggle (`GEKKO_THEME` dropped). |
| D5 | HALLAZGOS | Approved: only counts per status; path via `GEKKO_FINDINGS` (AC18). |
| D6 | CAMBIOS | Approved: kept, collapsed by default. |
| D7 | TÉCNICAS | Approved: rows without data fold into a summary row. **Reverted by the operator on 2026-11-15:** one row per technique with its name, cap 10 (REQ-TUI-012). |
| D8 | Label language | Approved: Spanish. |
| D9 | Widget above the editor | Approved: removed when the bar is mounted (TUI only). |
| D10 | gentle-shell code | Approved: own implementation. |
| D11 | What the bar keeps from the Pi footer it replaces | Resolved (operator): branch, model, `ctx NN%/window` and the `(auto)` mark; states from other extensions if they fit. Context only changes place. The folder is lost. |
| D12 | Folding on relaunch | Resolved (operator): reset on every launch. |

Risks:
- **`panel.json` is a mirror, not an authority.** Any process of the operator's user —including
  the model with its tools— can write it. AC11 detects a dead guard, not an impersonated one.
  The authority surface is the bar inside Pi. The sidebar treats the file as hostile data (AC20).
- **Focus and tmux bindings** (AC6): measured. By default the click steals focus; conditional
  bindings avoid it (10 of 10). `unbind` deletes instead of restoring, and a hand-written conditional
  binding would break double/triple click outside the sidebar: that is why the previous command is
  wrapped and what was saved is restored.
- **Pi's footer is replaced entirely** (measured): two rows become one (D11).
- The selftest only prints `all passed`: it does not prove that a new case ran. AC17 closes that.
- The panel updates with a delay: the process tests poll, they do not sleep.
- Glyph widths (`◌ ▰ ⎇`) assumed to be 1 cell; revisited in the final recapture.
- Regression of spec 001: its AC14 is now covered by the bar (see `plan.md` §4).

## 7. "Done" signals
- `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` green, with the
  per-AC count of AC17.
- `tools/tui-test.sh` green (AC1, AC6–AC11, AC14, AC19).
- **Live smoke against the real model** (not a gate; explicit exception to the hard rule): after a
  prompt that runs a tool, the bar goes from turn N to N+1 and SESIÓN adds one tool.
  Recorded in `tasks.md`.
- Recapture at 180x50, 140x40 and 80x24 and new scoring with the `tui-design` skill (target ≥ 30/40).
- `grep -rn 'panel\.lines'` with no results outside `specs/`.

## 8. History
- 2026-11-11 — Approved by the operator. Decisions: tmux hard requirement in `setup.sh`; click only
  collapses/expands (acting goes in a later phase, with its own spec); Pi's theme; cost and weekly usage
  removed; "legible without color and usable at 80 columns" is kept (AC14 of spec 001).
- 2026-11-11 — **Amendment 1 (approved by the operator; D11 with the `(auto)` mark kept, D12 ok)**, after live falsifiers and an
  adversarial review of the spec and the plan: AC10 goes from "< 140 columns" to "rail not drawn"; AC6 requires
  not breaking double/triple click nor leaving different bindings; AC14 acknowledges the heartbeat; AC15 leaves the
  gate; AC16 adds node; AC17 counts per AC; new AC18–AC21; new decisions D11 and D12. Where
  `design.md` or `test-plan.md` contradict this spec or the plan, the spec and the plan rule.
- 2026-11-12 — **Amendment 2 (approved by the operator)**, on closing GAP-68 of the living spec: AC20 stops
  promising that a third party's `panel.json` cannot draw a false `guard ON` (there is nothing
  to authenticate the file against a process of the same user) and promises what the gate proves:
  guard coherence on reading and quotes around whatever imitates it outside its card. The risk stays in §6.
- 2026-11-12 — Post-closing review, no AC amendment: fixed defects against AC1, AC7, AC12 and
  AC21 (detail and evidence in `tasks.md`). The merge brought work outside §4, with no AC of its own: single
  launcher, `/gekko-sidebar --toggle`, loading of `.gekko-state/env` and the nvm branch of `setup.sh`; it is
  traced in GAP-75 to GAP-77 of the living spec.
