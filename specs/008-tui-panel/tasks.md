# Tasks 008 — Info panel as cards (rail + status bar)

> Status: `IMPLEMENTADA` (operator, 2026-11-17: closed; 12/12 tasks, merged into `main`) · previously `APROBADO` (operator, 2026-11-11: «continua con la implementacion» (continue with the implementation)) · Date: 2026-11-11 · Plan: `plan.md` rev. 2 (approved)

SDD hard rule: each task closes ≥1 acceptance criterion and names the test that proves it.

- **G** = `008-ACn:` cases in `runPanelSelftest`, inside the single gate:
  ```bash
  GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts
  ```
- **P** = `bash tools/tui-test.sh` (nested tmux on a dedicated socket).

Each task closes with the gate green and the per-AC count (AC17) showing its cases. T1–T5 touch
`toolbox/gekko-panel.ts` and go in sequence; T6–T8 are independent of each other (T7 goes after T5).

## Phase 1 — Pure logic (`toolbox/gekko-panel.ts` + `gekko-panel-selftest.ts`)

- [x] **T1. Contract, sanitizing and per-AC counter** — `PanelState`, `buildPanelState`, `parsePanelState`
  (rejects invalid JSON or unknown version), extended `stripControl` (`\t\r\n`, C1, bidi,
  zero-width) applied on publish, HALLAZGOS count with integers only, `ok()` that counts by
  prefix `008-ACn:` and fails if an expected AC has zero. → AC1, AC17, AC18, AC20 (publish part) ·
  G: `008-AC1:`, `008-AC17:`, `008-AC18:` (canary in id/title/target/evidence), `008-AC20:`.
- [x] **T2. `renderRail` + zone map + states** — cards in fixed order, header
  `▾ NOMBRE conteo` / `▸ NOMBRE resumen`, auto-collapse by height from the last, GUARD never yields,
  `guard ?` if `ts` > 10 s (injected clock), empty / 1000 items / error with cap per card, sanitizing of
  every string when drawing. → AC2, AC3, AC4, AC11, AC12, AC20 (draw part) · G: `008-AC2:` (36/48/80
  columns), `008-AC3:`, `008-AC4:`, `008-AC11:`, `008-AC12:`, `008-AC20:` (hostile fixtures in host,
  shell, block reason, file; ESC only from the allowed list).
- [x] **T3. Theme** — `resolveTheme`: role accepted only if it matches the plan's expression; light/dark
  fallback palette; `noColor` without color SGR. → AC8, AC9, AC20 (hostile role) · G: `008-AC8:`,
  `008-AC9:` (mapping + contrast ≥ 4.5:1 against the backgrounds of `test-plan.md`), `008-AC20:`.
- [x] **T4. Inputs** — `parseMouse` (SGR-1006), `handleKey` (cursor's card, all, `1`–`8` by fixed
  id), `toggleAt`, `panel.ui.json` reducer with defaults on corruption. The reducers
  return only UI state. → AC5, AC7, AC14, AC19 · G: `008-AC5:`, `008-AC7:`, `008-AC14:`, `008-AC19:`.
- [x] **T5. `renderBar` and `sidebarBindings`** — one row trimmed to the width: branch, mode, model,
  `ctx NN%/window (auto)`, turn; with `railVisible=false` adds guard, scope, shells and block marker;
  the three bindings wrap the previous command. Port to `renderBar` the assertions of
  `panel-layout-and-headless` from spec 001. → AC10, AC13, AC6 (G part) · G: `008-AC10:` (80
  columns), `008-AC13:` (with and without `(auto)`), `008-AC6:`.

## Phase 2 — Scripts (in parallel; they do not touch `gekko-panel.ts`)

- [x] **T6. `setup.sh`** — requires tmux ≥ 3.2 and node ≥ 22.19; `GEKKO_SETUP_CHECK_ONLY=1` exits after the
  prerequisites block without installing or writing. → AC16 · G: `008-AC16:` with synthetic `PATH` and
  fake binaries (`tmux 3.1c`, `3.2a`, `next-3.5`; node 22.18 / 22.19).
- [x] **T7. `tools/gekko-sidebar.sh` + `tools/pi-hitl.sh` + `tools/pi-hitl.env.example`** — width 25 %
  bounded to 36–48; does not open below 140 and the `window-resized` hook closes/reopens; installs the bindings
  from T5 (requires T5 done), saves the previous in
  `@gekko_prev_<key>`, idempotent `--restore`; `pi-hitl.sh` switches to `panel.json`, deletes
  `panel.ui.json` on launch (D12), removes the 16 % and calls `--restore` on exit; document
  `GEKKO_FINDINGS`. → AC6, AC10, AC19 · P (run in T10): 10 fast clicks, double click in a normal
  pane, `diff` of `list-keys`, 139/140 boundary.
- [x] **T8. `tools/tui-test.sh`** — process harness with polling (up to 10 s, no fixed `sleep`);
  endpoint and key only via environment variables; optional live smoke mode. → P of AC6–AC10,
  AC14, AC19 · validated against the old sidebar: it must fail red before T10 (proof that it measures).

## Phase 3 — Integration

- [x] **T9. Guard (`toolbox/gekko-guard.ts`)** — `writePanelState` publishes JSON; timer with the
  shape of `refreshShellsLive` (TUI only, `unref`, `try/catch` that drops `lastCtx`): republishes every
  2 s, re-reads theme, `NO_COLOR`, git (plan flags), ledger and `compaction.enabled`; mounts
  `setFooter` with `renderBar`; removes `setStatus("gekko")` and the widget when the bar is mounted;
  `sidebarLive()` decides `railVisible`. → AC1, AC9, AC10, AC11, AC13, AC21 · G: `008-AC21:` (without TUI
  it does not write, does not run git, does not read ledger, does not mount a bar) + whole gate green.
- [x] **T10. Sidebar (`toolbox/gekko-sidebar.mjs`)** — I/O layer: validates with `parsePanelState`,
  keeps the last good frame, `renderRail`, SGR-1006 on/off, stdin through `parseMouse`/`handleKey`,
  persists `panel.ui.json`, heartbeat `.alive`. → AC6, AC7, AC14, AC19 · P: `tools/tui-test.sh` entirely green
  (includes sha256 of `panel.json` and `scope.txt` after a burst of clicks and keys).

## Phase 4 — Closing

- [x] **T11. Docs and skill registration** — `docs/pi-hitl.md`, `AGENTS.md` and `CLAUDE.md` (twins),
  `README.md`, `.pi/agents/README.md` if applicable; register `tui-design`; note in
  `specs/001-pi-control-panel/tasks.md`; delete `widgetLines` and its test. → closing of AC10/AC13 as seen by
  the operator · verification: `grep -rn 'panel\.lines'` empty outside `specs/` and gate green.
- [x] **T12. Live smoke, recapture and scoring** (not a gate; §7 of the spec) — against the real
  Provider: turn N→N+1 and SESIÓN adds one tool; `(auto)` follows Pi's toggle; recapture at
  180x50, 140x40 and 80x24, new scoring with `tui-design` (target ≥ 30/40). With the operator:
  coexistence with their `~/.tmux.conf` and look on a light terminal.

## Evidence
*(filled in per task: gate output with the per-AC count, `tui-test.sh` output, captures)*

**T1** — gate (`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`), real tail:
```
gekko-guard selftest: all passed
gekko-panel 008 casos por AC: AC1=7 AC17=1 AC18=4 AC20=5
gekko-panel selftest: all passed
```
ACs expected today (`EXPECTED_008_ACS` in `gekko-panel-selftest.ts`): 1, 17, 18, 20. Each following task adds its own.

**T2** — gate, real tail:
```
gekko-guard selftest: all passed
gekko-panel 008 casos por AC: AC1=7 AC2=7 AC3=7 AC4=3 AC11=3 AC12=4 AC17=1 AC18=4 AC20=10
gekko-panel selftest: all passed
```

- **T3** (resolveTheme, AC8, AC9, AC20 hostile role) — gate tail:
  ```
  gekko-guard selftest: all passed
  gekko-panel 008 casos por AC: AC1=7 AC2=7 AC3=7 AC4=3 AC8=2 AC9=13 AC11=3 AC12=4 AC17=1 AC18=4 AC20=11
  gekko-panel selftest: all passed
  ```

**T4** — `parseMouse`, `toggleAt`, `handleKey`, `parseUi`/`serializeUi` (AC5, AC7, AC14, AC19), real gate tail:
```
gekko-guard selftest: all passed
gekko-panel 008 casos por AC: AC1=7 AC2=7 AC3=7 AC4=3 AC5=6 AC7=10 AC8=2 AC9=13 AC11=3 AC12=4 AC14=1 AC17=1 AC18=4 AC19=3 AC20=11
gekko-panel selftest: all passed
```

**T5** — `renderBar`, `sidebarBindings` (AC10, AC13, AC6 G part), real gate tail:
```
gekko-guard selftest: all passed
gekko-panel 008 casos por AC: AC1=7 AC2=7 AC3=7 AC4=3 AC5=6 AC6=5 AC7=10 AC8=2 AC9=13 AC10=7 AC11=3 AC12=4 AC13=4 AC14=1 AC17=1 AC18=4 AC19=3 AC20=12
gekko-panel selftest: all passed
```

**QA T1–T5** (independent pass; no new task) — fixed in `toolbox/gekko-panel.ts`: TÉCNICAS with count/summary and the `?` rows folded into one (D7); width in cells (CJK/emoji) and body rows at 0–3 columns; linear render in number of cards; future/NaN `ts` and NaN clock = expired; the guard is not lost in the bar at very short widths; `extStatuses` untrusted; `stripControl` strips LS/PS, tags and interlinear; card ids inherited from `Object.prototype`. 54 new `008-ACn:` cases (each seen failing against the previous code or against a mutation; AC14 now takes the snapshot of the `runtime` singleton at the start). Real gate tail:
```
gekko-guard selftest: all passed
gekko-panel 008 casos por AC: AC1=11 AC2=12 AC3=12 AC4=3 AC5=6 AC6=6 AC7=11 AC8=4 AC9=14 AC10=9 AC11=6 AC12=12 AC13=5 AC14=2 AC17=1 AC18=4 AC19=3 AC20=15
gekko-panel selftest: all passed
```
Not done / deferred: "the rail keeps the last good frame" (AC1) belongs to the sidebar's I/O layer, T10 (P test); AC17 (the printed count line) is inherent to a selftest that measures itself; the "file name" fixture (AC20) waits until CAMBIOS carries file rows (today only 3 integers). Not reproducible as a defect: a row of another card that imitates `guard ON` (it stays under its own indented header; no verified path from scope/shell to the glyph). `ui.open[id]` with hasOwn is defensive with no observable effect (inherited ids are truthy = default).

**T6** — gate, real tail:
```
gekko-guard selftest: all passed
gekko-panel 008 casos por AC: AC1=11 AC2=12 AC3=12 AC4=3 AC5=6 AC6=6 AC7=11 AC8=4 AC9=14 AC10=9 AC11=6 AC12=12 AC13=5 AC14=2 AC16=6 AC17=1 AC18=4 AC19=3 AC20=15
gekko-panel selftest: all passed
```

**T7** (nested tmux `-L gekko-impl-t7 -f /dev/null`, already closed): bindings installed (`if-shell -F -t = "#{@gekko_sidebar}" "send-keys -M" <previous>`),
previous ones in `@gekko_prev_<key>` (incl. `__unbound__`), `--restore` leaves `list-keys -T root` identical (3 keys and the whole root table with a
key previously unbound), `--restore` does nothing with a live sidebar, 139 cols does not open and the `window-resized` hook closes/reopens (139→closes, 140→36 cols,
200→48), `bash -n` ok on both scripts. Gate:
```
gekko-guard selftest: all passed
gekko-panel 008 casos por AC: AC1=11 AC2=12 AC3=12 AC4=3 AC5=6 AC6=6 AC7=11 AC8=4 AC9=14 AC10=9 AC11=6 AC12=12 AC13=5 AC14=2 AC16=6 AC17=1 AC18=4 AC19=3 AC20=15
gekko-panel selftest: all passed
```

**T8** — `tools/tui-test.sh` created (29 checks; opt-in `--live` mode via environment variables). Run against the old sidebar (T10 pending), real: `14 passed, 15 failed`, expected red on AC1/AC4-click/AC6 (mouse and click)/AC7/AC19/AC9/AC8 of the rail; green those that depend on T7 (boundary 139/140/80, `--restore`, focus). Gate tail:
```
gekko-guard selftest: all passed
gekko-panel 008 casos por AC: AC1=11 AC2=12 AC3=12 AC4=3 AC5=6 AC6=6 AC7=11 AC8=4 AC9=14 AC10=9 AC11=6 AC12=12 AC13=5 AC14=2 AC16=6 AC17=1 AC18=4 AC19=3 AC20=15
gekko-panel selftest: all passed
```

**T9** — gate, real tail:
```
gekko-guard selftest: all passed
gekko-panel 008 casos por AC: AC1=12 AC2=12 AC3=12 AC4=3 AC5=6 AC6=6 AC7=11 AC8=4 AC9=14 AC10=12 AC11=8 AC12=12 AC13=5 AC14=2 AC16=6 AC17=1 AC18=5 AC19=3 AC20=15 AC21=2
gekko-panel selftest: all passed
```

**T10** — `toolbox/gekko-sidebar.mjs` rewritten as an I/O layer (parsePanelState, last good frame, renderRail, SGR-1006, parseMouse/toggleAt/handleKey, `panel.ui.json`, `.alive` heartbeat). `bash tools/tui-test.sh`: `29 passed, 0 failed`. Gate, real tail:
```
gekko-guard selftest: all passed
gekko-panel 008 casos por AC: AC1=12 AC2=12 AC3=12 AC4=3 AC5=6 AC6=6 AC7=11 AC8=4 AC9=14 AC10=12 AC11=8 AC12=12 AC13=5 AC14=2 AC16=6 AC17=1 AC18=5 AC19=3 AC20=15 AC21=2
gekko-panel selftest: all passed
```
`tui-test.sh` checks fixed (they were wrong against the spec): AC7 `rm -f panel.ui.json` does not reset the in-memory folding (now reopens the rail); AC7 `z` collapses all, including GUARD with guard ON (AC3 only fixes it in AUSENTE/FALLÓ); AC6 negative control clicked x=100 but the outer client measures 180 columns (rail at x>=110, now x=150). No new G cases: the sidebar is I/O, the pure logic is already covered by T1–T5.

**T11** (2026-11-11) — docs: new `docs/pi-hitl.md` §9 (rail, bar, inputs, trust limits,
tests); `CLAUDE.md`/`AGENTS.md` (twins) and `README.md` list `tui-design` and spec 008;
`.pi/agents/README.md` does not apply (it lists no skills or panel); closing note in
`specs/001-pi-control-panel/tasks.md`. Code: `widgetLines` and its 3 assertions deleted (its AC14 already
lived ported in `008-AC10`); the guard's path without a mounted bar now shows the same row of
`renderBar` as a widget, so the guard is not lost. **Deviation from plan §4:** it said to keep
`widgetLines` until the bar smoke (T12) passed; it was deleted in T11 as this list commands — if T12
fails, it is recovered from `git show HEAD:toolbox/gekko-panel.ts`.
**Regression found and fixed:** `persistUi()` of `toolbox/gekko-sidebar.mjs` had an empty body (the
folding was not saved) → `tools/tui-test.sh` gave `27 passed, 2 failed` (the two AC19 ones).
Restored with a tmp+rename write. Verification, real:
```
$ grep -rn 'panel\.lines\|widgetLines' --exclude-dir=.git --exclude-dir=specs .   → empty
$ bash tools/tui-test.sh                                                          → 29 passed, 0 failed (x2)
gekko-guard selftest: all passed
gekko-panel 008 casos por AC: AC1=12 AC2=12 AC3=12 AC4=3 AC5=6 AC6=6 AC7=11 AC8=4 AC9=14 AC10=12 AC11=8 AC12=12 AC13=5 AC14=2 AC16=6 AC17=1 AC18=5 AC19=3 AC20=15 AC21=2
gekko-panel selftest: all passed
```

**T12** (2026-11-12, closed by operator decision — see «Cierre» (Closing) at the end) — live smoke on the operator's Kali
(Pi 1.5.0, tmux inside a terminal multiplexer, model `qwen3.8-flash-next`), by the operator's captures:
- Rail and bar draw live; turn 13 → 20 between captures; SESIÓN counts (`herramientas ok 18 ·
  con error 1`) after fixing that the guard did not increment the counters.
- `(auto)` visible in the bar (`ctx 34%/131k (auto)`); with the rail the bar does not repeat guard/scope.
- Out-of-scope block and scope extension rejected by the operator: reflected in GUARD.
- Click on a header folds the card (confirmed by the operator); `/gekko-sidebar` toggles.
- The rail follows Pi's theme without restarting (`/settings` → `light`).
- Width: 46 columns in a 184 window; stable after toggling and resizing (confirmed).

Defects found in the smoke and fixed: Debian/Kali node without TypeScript (detection + message),
launcher that died silently inside tmux, SESIÓN counters at 0, last block truncated (now
≤4 rows), resize hook installed late, and — in the recapture — the split block made
headers get lost at low height (now back to one row).

Recapture (real sidebar in tmux, synthetic state): 180x50 → rail 45 cols, 35 rows, no clipping;
140x40 → rail 36 cols, 35 rows, the block reason closes with `…`; 80x24 → no rail, bar
`DEFAULT · ctx 34%/131k (auto) · guard ON · scope 3 · shells 2 · ✗ bloqueo`.

`tui-design` scoring (before 15/40):

| Criterion | Score | Evidence |
|---|---|---|
| Hierarchy | 3 | Title in bold+accent, rows with glyph; GUARD fixed on top. |
| Density | 3 | No empty rows or boxes; HALLAZGOS spends 3 rows on zeros (`triaged 0`, `por validar 0`, `otros 0`). |
| Consistency | 3 | A single card format; `✗` serves both for "blocked" and "with error" (the word separates them). |
| State visibility | 3 | Guard, `guard ?` if expired, legible block reason; AGRESIVO is distinguished only by the word. |
| Legible without color | 4 | Every state carries a glyph or word; `NO_COLOR` covered in `tui-test.sh`. |
| Narrow width | 3 | At 80 the bar keeps mode, ctx, guard, scope, shells and block marker; it loses branch, model, turn and the reason. |
| Interaction discoverability | 2 | Click and keys work, but nothing on screen announces them except `▾`/`▸`. |
| Empty / error / overflow | 3 | `fail-closed (vacío)`, `—`, `… +N más`, expired; low height fixed this round. |
| Render cost | 4 | Pure render, O(cap per card), repaints only if the frame changes. |
| Task fit | 3 | Used in a real engagement by the operator; HALLAZGOS requires `GEKKO_FINDINGS` by hand. |
| **Total** | **31/40** | target ≥ 30 |

**Closing of T12** (2026-11-12): the operator confirmed live that `(auto)` follows Pi's effective
setting (the repo's `.pi/settings.json` fixed `compaction.enabled: true` and left the `/settings`
switch without effect; that line was removed). **Not verified, accepted as such by the operator:** the
look on a light terminal background — only Pi's light theme on a dark background was tried; the
contrast of the light fallback palette is covered by the gate (AC9), not by a real capture.

**Post-closing: GAP-61 and GAP-68** (2026-11-12, reverse reconciliation: failing case → fix → living spec).
- GAP-61 closed: `renderRail` receives the window (`staleMs`) and the sidebar passes it `Date.now()` without
  rescaling the `ts`. 3 new `008-AC11:` cases (all 3 failed before the fix) + 3 process checks
  in `tools/tui-test.sh` (`40 passed, 0 failed`; against the previous sidebar: `39 passed, 1 failed`,
  red on `AC11: panel.json con ts una hora adelante se dibuja guard ?`).
- GAP-68 closed (fix + Amendment 2 of AC20): `parsePanelState` rejects an incoherent or absent guard (2 cases
  `008-AC1:`) and `renderRail` quotes whatever imitates the guard outside its card (2 cases `008-AC20:`);
  the 4 failed before the fix. What remains —a `panel.json` rewritten whole and coherently by a third party draws
  `guard ON`— is an accepted limit: the operator amended AC20 (spec.md §8), which no longer promises authenticity.
- Review of the GAP-68 fix: "exactly one `guard` row" compared the raw label, and the rail draws the sanitized one:
  a second row `guard`+U+200B, `guard`+TAB, ` guard` or `Guard` validated and came out the same as
  the genuine one. `parsePanelState` now counts the rows with the same rule that quotes outside the
  card (`GUARD_LIKE`). 1 new `008-AC1:` case (failed before the fix) with 9 labels
  of a second row and 3 renames of the single row. Not covered: homoglyphs, letter-class padding and
  zero-width marks that `stripControl` does not remove (REQ-TUI-001, Limit).
- AC20 test column: the "file name" fixture was removed, which never existed (CAMBIOS only
  publishes three integers); GAP-65 no longer lists AC11 among the ACs without a process check.


**Post-closing: review of 008** (2026-11-12, same rule: failing case → fix → living spec).
- AC1, sidebar: with the frame as tall as the pane, `draw` erased its last row, which is where the
  warning `! último estado válido` goes when `panel.json` does not validate; under 41 columns the warning wrapped
  and shifted the rail. Fix in `toolbox/gekko-sidebar.mjs` (do not erase below a full pane; warning
  trimmed to the width). 4 new checks in `tools/tui-test.sh` at 12 rows (all 4 failed before).
- AC7, sidebar: Shift+Up and F6 folded SCOPE and SESIÓN (the digits of their sequence were read as
  keys). `onData` passes the whole CSI sequence as one key. 1 new check (failed before).
- AC12: expanded CAMBIOS never showed `borradas` (cap 2 for 3 fixed rows). `ROW_CAP.cambios`
  becomes 3. 1 new `008-AC12:` case (failed before).
- AC21: with a real Pi (1.5.0), `--mode rpc` gives `ctx.hasUI=true` and the guard wrote `panel.json`.
  `publish` now decides by `ctx.mode === "tui"`; the rpc client keeps the status row as
  a widget. 2 wiring cases in `toolbox/gekko-guard.ts` (REQ-TUI-021; the rpc one failed before) and
  manual check with a real Pi in rpc, `-p`, `--mode json` and TUI (living spec, Limit of REQ-TUI-021).
- The `008-AC11:` case that reads the sidebar text no longer depends on the working directory.
- Delivered in the merge outside §4 of the spec, with no AC or REQ with a case (single launcher that relaunches
  itself in tmux, `/gekko-sidebar --toggle`, loading of `.gekko-state/env`, nvm branch of `setup.sh`): it is
  traced as GAP-75, GAP-76 and GAP-77 of the living spec.
- Unchanged, by KISS decision: `tools/tui-test.sh` stays out of the hooks (the pre-commit does not
  run the gate either); running both before closing is the done signal of §7 (GAP-65).

Gate, real tail (2026-11-12):
```
gekko-guard selftest: all passed
gekko-panel 008 casos por AC: AC1=17 AC2=12 AC3=12 AC4=3 AC5=6 AC6=6 AC7=13 AC8=4 AC9=15 AC10=13 AC11=12 AC12=18 AC13=5 AC14=2 AC16=7 AC17=1 AC18=5 AC19=3 AC20=21 AC21=2
gekko-panel selftest: all passed
REQ trace: 85 requisitos, 908 casos
```
`bash tools/tui-test.sh`: `45 passed, 0 failed`.

**Live smoke** (2026-11-12; not a gate, §7 of the spec) — `bash tools/tui-test.sh --live` against the
Provider with `qwen3.8-flash-next-iq3_s` (the model it already had loaded; a model change was not forced):
`47 passed, 0 failed`, two runs in a row.
- The script's smoke did not get to measure anything: it launched Pi with `>/dev/null 2>&1`, and Pi 1.5.0 with stdout
  off the tty exits on its own (exit 0 in 1 s; same with HEAD's guard). The redirection was removed; the
  output stays in the disposable tmux pane, which nobody captures.
- By hand, full stack (Pi + guard + rail in tmux at 180x50) with the prompt `run: echo gekko-smoke`:
  bar `turno 0` → `turno 1` and `ctx 0%` → `4%`; SESIÓN `herramientas ok 0` → `1`; `guard ON`; the
  tool output arrives fenced as `<TARGET-CONTENT>`.
- Same prompt at 140x40: the rail opens (36 columns) with `guard ON`, `turno 1` and `herramientas ok 1`;
  the bar stays at branch, mode, model, ctx and turn. At 80x24 the rail does not open and the bar carries the
  state: `DEFAULT · ctx 4%/128k (auto) · turno 1 · guard ON · scope 0 · shells 0`.
- rpc mode with the real model (hand-driven JSONL client): the tool runs, the `gekko` widget goes from
  `… turno 0 · guard ON …` to `… turno 1 · guard ON …` and `panel.json` is not written (AC21). In rpc the
  row still has no branch or model and has `ctx ?`.
- Operator decision (2026-11-12): for now the Provider's model is not changed; the tests run
  only with the flash-next loaded. The second acceptance model (`qwen3.8-27b-q5-f16`) stays unrun.

**Pre-merge review** (2026-11-12; three independent readings of the diff —guard, panel and rail,
text against code— and each finding verified separately): no defects in the code. Two confirmed
findings, fixed before the commit:
- The `008-AC1:` case of the `guard` row did not fail when removing `stripControl` from the count nor when removing
  the exact-label requirement (mutations on a copy: the gate stayed green). An
  invisible inside the word and the rename of the single row were added; both mutations fail now.
- GAP-64 still said the `--live` smoke had not been run.
Refuted because already written as a limit: in rpc, with a live rail from another session, the widget yields
`guard ON` (REQ-TUI-010, GAP-67); a shell or host with a homoglyph comes out unquoted (REQ-TUI-020).
