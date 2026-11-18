# 008 — TUI panel test plan

> **Note (2026-11-11):** input document. Where it contradicts `spec.md` or `plan.md`, those rule. Known differences: there is no `GEKKO_THEME` (the theme enters as a parameter); case labels `008-ACn:`; rail width 25 % (36–48), not 16 %; the state file is `panel.json`; the 140-column cutoff lives in `gekko-sidebar.sh`, not in `renderRail`; the conditional bindings wrap the previous command and are restored with what was saved, not with `unbind`.

Labels: **[V]** measured in this session · **[I]** inferred · **[?]** unverified.
Levels: **L1** pure selftest (the `ok()` harness of `toolbox/gekko-panel-selftest.ts`) · **L2** process + tmux `capture-pane` ·
**L3** live smoke (Pi + real model) · **M** manual.

## 1. Measured facts

- **Baseline [V]:** `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` → rc 0, 0.49 s,
  outputs `gekko-guard selftest: all passed` and `gekko-panel selftest: all passed`. `ok()` only prints on failure: there is no
  count of passes (there are ~118 + ~186 `ok(` calls in the source). Node 22.22.2, tmux 3.6b.
- **Mouse through tmux [V]** (inner server `-L gekko-test`, `mouse on`, panes 79|40; client attached inside a
  second server `-L gekko-outer`; clicks injected with `send-keys -l` in the outer pane = real terminal bytes):
  - (a) The script receives SGR press **and** release; coordinates **relative to the pane** (injected x=100,y=5, pane at col 80 →
    received `x=20,y=5`, 1-based). Right button (b=2) and wheel (b=64) also arrive. Mode 1000 emits no drag (b=32 is lost);
    the release arrives with the final coordinates.
  - (b) With the default binding the click **moves focus** to the sidebar (`pane_active` %0:1 %1:0 → %0:0 %1:1).
  - (c) `tmux select-pane -t <left>` launched by the script on release: **20/20** restores focus (and the following keys
    land in the left pane). Clean alternative, **never** moving focus, **20/20**:
    ```
    for k in MouseDown1Pane DoubleClick1Pane TripleClick1Pane; do
      tmux bind -n $k if -F -t = '#{@gekko_sidebar}' 'send-keys -M' 'select-pane -t = ; send-keys -M'; done
    ```
    **Measured trap:** with only `MouseDown1Pane` redefined, fast clicks (<500 ms) are treated by tmux as Double/TripleClick
    and steal focus again (**2/10 and 2/20**). All three must be rebound. Clicks in the left pane still
    focus it (verified). `tmux set -p @gekko_sidebar 1` is already done by `tools/gekko-sidebar.sh`.
  - (d) If the app did **not** request mouse (`mouse_any_flag=0`): the script receives nothing, and tmux consumes the click and **moves
    focus** to the pane. With the app requesting it: `mouse_any_flag=1 mouse_sgr_flag=1`.
  - Caveat [V]: with `mouse off` on the server, the injected bytes still arrived; in a real terminal there would be no report
    because tmux would not have requested it from the outer terminal. Do not use `mouse off` as a "no events" test case.
  - Bindings are global to the server, not per session: the launcher must remove them on exit (`unbind -n`) or accept that the
    operator's server inherits them **[I]**. Enable only with an own `-L` in tests.
- **Live smoke [V]:** the current pipeline runs headless. Pi (1.5.0) + `gekko-guard.ts` + sidebar in tmux split +
  real `<model-id>`: `panel.lines` changed `turno 0 → turno 1` and the model ran `echo gekko-smoke` (output
  fenced by the firewall). 1 request, ~25 s. What was captured: `scratchpad/tui-test/panel.{before,after}.txt`.
  A capture at 3 s still showed `turno 0` (the panel lags by timer/poll, see §4).
  Pi's "Trust project folder?" prompt appears in a new worktree: `Down Down Enter` = "Trust (this session only)".

## 2. Reusable harness

Working dir: `<scratch>/tui-test/`
(`S` below). Always `-L <own socket>`; kill when finished (`tmux -L X kill-server`, and delete `/tmp/tmux-$UID/X`).

**Nested mouse** (`$S/mouse-spike.mjs`: enables `\e[?1000h\e[?1006h`, logs `ev b= x= y= press|release` to `$LOG`;
`MOUSE=0` does not request mouse; `REFOCUS=<pane>` does select-pane on release):
```
tmux -L gekko-test -f /dev/null new-session -d -s in -x 120 -y 30 "bash --norc"; tmux -L gekko-test set -g mouse on
tmux -L gekko-test split-window -h -d -l 40 "LOG=$S/ev.log node $S/mouse-spike.mjs"
tmux -L gekko-outer -f /dev/null new-session -d -s out -x 120 -y 31 "env -u TMUX tmux -L gekko-test attach -t in"
click(){ tmux -L gekko-outer send-keys -t out -l $'\e[<0;'$1';'$2$'M'; sleep .05
         tmux -L gekko-outer send-keys -t out -l $'\e[<0;'$1';'$2$'m'; sleep ${3:-.15}; }
click 100 5      # ABSOLUTE 1-based client x,y; the pane receives x-80
tmux -L gekko-test list-panes -F '#{pane_id}:#{pane_active}'
```
(The inner client measures 120x31 with the status line; the right pane occupies columns 81–120.)

**Live headless Pi** (`$S/smoke-launch.sh`, runs inside the pane; does not touch `~/.pi/agent`):
```
set -a; . <env with GEKKO_PROVIDER_KEY>; set +a                   # only referenced via env, never printed
# $S/piagent/models.json: provider provider, LITERAL baseUrl http://<endpoint>/v1,
#   apiKey "$GEKKO_PROVIDER_KEY", api openai-completions, models:[{id:"<model-id>",reasoning:false,...}]
# $S/piagent/settings.json: {"theme":"dark"} ; $S/scope.txt empty
export GEKKO_PANEL_STATE=$S/panel.lines GEKKO_SCOPE=$S/scope.txt PI_CODING_AGENT_DIR=$S/piagent \
       PI_CODING_AGENT_SESSION_DIR=$S/sess PI_TELEMETRY=0 PI_SKIP_VERSION_CHECK=1
tools/gekko-sidebar.sh >/dev/null            # right split 16% (28 cols at 180)
exec pi --provider provider --model <model-id> -e toolbox/gekko-guard.ts --no-session
```
Orchestration: `tmux -L gekko-smoke new-session -d -s s -x 180 -y 50 "bash $S/smoke-launch.sh"`; `sleep 6`;
`send-keys -t %0 Down Down Enter` (trust); `send-keys -t %0 -l '<prompt>'; send-keys -t %0 Enter`;
`capture-pane -p -t %0|%1` before/after and `diff`. For another width: `-x 140 -y 40` / `-x 80 -y 24` in `new-session`.
For L2 without a model: replace `pi` with a script that writes a synthetic `panel.json` (the sidebar reads it just the same).

## 3. Test matrix

L1 convention: functions in `gekko-panel-selftest.ts` with `ok(cond, "ACxx: …")`; the pure renderer
`renderRail(state,width,height,theme,ui) → {lines,hits}` receives fixtures without tmux. "visible width" = length without SGR,
counting 1 cell per glyph except as noted in §5.

| Capability | Level | Concrete assertion | Not automatable / why |
|---|---|---|---|
| Card render at 180/140/80 | L1 | For w∈{45,36}: every line has visible width ≤ w; the header matches `/^[▾▸] [A-ZÁÉÍÓÚ]+ ─+ /`; with the state of §4.4 the frame matches the design mockup (text snapshot). w<140 → `renderRail` returns `lines=[]` | Real look of font/glyphs |
| Rail at real size | L2 | `capture-pane -p` of the sidebar pane at 180x50 and 140x40: pane width = clamp(36, 25 %, 48)−border; no row exceeds the pane width; 80x24: no `@gekko_sidebar` pane exists | That the `window-resized` hook closes/reopens the pane on crossing 140 **[?]** (tested in L2 with `resize-window`, but today it is not implemented) |
| Collapse state | L1 | `ui={collapsed:{scope:true}}` → SCOPE without body rows and glyph `▸`; empty `collapsed` → all `▾`; `GUARD` with guard AUSENTE/FALLÓ ignores `collapsed` | — |
| Persisted collapse | L2 | After a toggle `panel.ui.json` exists with only UI keys; restarting the sidebar keeps the folding; corrupt JSON → all expanded without crash | — |
| Hit map | L1 | `hits` only with `action==="toggle"`; each `row` is a row whose text starts with `▾`/`▸`; number of hits = number of cards drawn; no hit on body rows | — |
| Mouse parser | L1 (pure function `parseMouse(buf)`) | `"\e[<0;20;5M"` → `{b:0,x:20,y:5,press}`; `m` → release; two events in one buffer; an event split across two `data` chunks is reassembled; garbage (`\e[<x`, `\e[<0;1;`) does not throw and is discarded; b=2/64 ignored; click = press+release on the same row | — |
| End-to-end mouse | L2 | With the nested harness: `click` on the header row → `capture-pane` shows `▸` on that card; click on a body row → no change; pane-relative coordinates match `hits` (measured [V]: x−80) | Mouse support of the operator's physical terminal (not tmux) |
| Focus after click | L2 | After N clicks (including fast <500 ms) `#{pane_active}` of Pi's pane == 1 in N/N. With the conditional binding of the 3 events [V 20/20]; without it must **fail** (negative control, [V 2/20]) | Focus behavior with other bindings of the operator's `~/.tmux.conf` |
| Rail keys | L1 over pure `handleKey(state, key)` + L2 | `j/k/↑/↓` move the cursor and saturate at the ends; `enter/space` toggles the cursor's; `1`–`8` toggles N (N>number of cards → nothing); `a`/`z` expands/collapses all except a failed GUARD; other keys change nothing. L2: `send-keys -t <sidebar> j Enter` → capture changes; `esc` → `pane_active` of Pi's pane; `C-c` → pane closed | Keys with modifier through the real terminal (extended-keys, Pi already warns it is off) |
| Theme tokens | L1 | Per theme dark/light/none: `GEKKO_THEME` > `state.theme` > dark; with `none` the output contains no `\e[3`/`\e[9`/`\e[38`/`\e[4[0-7]` (only `\e[1m`,`\e[2m`,`\e[0m` are allowed); the hex values of §4.5 are the expected ones; WCAG ≥4.5 computation of each text vs `#0D1117/#1E1E1E/#000` (dark) and `#FFF/#F6F8FA/#FDF6E3` (light) in the test (8-line luminance function) | Look on a real light terminal; OSC 11 autodetection under tmux **[?]** (not tested: dropped from scope unless decision Q5) |
| Legibility without color | L1 | With `theme=none`, for each state (`✓ auto`, `? pregunta`, `✗ bloqueo`, `● open`, `◌ stale`, `○ closed`) the line contains glyph **and** word; strip(SGR) of the themed render == `none` render except attributes | — |
| Stale guard detection | L1 | `state.ts = now-14s` → 1st row `⚠ sin datos hace 14s`, GUARD `? desconocido`, **no** `ON` in any line; `ts = now-9s` → no warning (10 s edge: 10.0 s no warning, 10.1 s with warning); future/NaN/missing `ts` → treated as stale. Injected clock, not `Date.now()` | — |
| In-process staleness | L2 | Write a fresh `panel.json`, wait without rewriting >10 s (real clock: use `GEKKO_STALE_MS=1500` in test) → capture contains `⚠`; kill the smoke's Pi process → no `guard ON` remains | No arbitrary sleeps: poll with `until grep` and a cap |
| Bar segments | L1 (`renderBar(state,width,theme)`) | w=134 with rail: contains branch, mode, model, `ctx` and `turno`; **not** scope/shells; guard only if ≠ ON. w=80 folded: contains mode, guard, `scope N`, `✗` block always; visible width == w (or ≤ w); drop order model→meter→`turno`→`t`→`sh`. Fallen guard + empty scope → it sees them at w=40 | `ctx.ui.setFooter` live (L3): `setFooter(factory)` exists in pi 1.5.0 `types.d.ts` **[V]**, real behavior **[?]**; L3 only checks the bottom row with `capture-pane` |
| Fold by breakpoint | L1 + L2 | L1: `layout(cols)` → `rail=false` for 139, `true` for 140 (exact boundary); L2: `resize-window -x 139` / `-x 140` and check the existence of the `@gekko_sidebar` pane and the bar content | `window-resized` hook does not exist yet **[?]** |
| JSON contract guard→sidebar | L1 | `panelState(runtime)` produces `{v,ts,theme,cards,bar}`; `JSON.parse(JSON.stringify(x))` is identical; unknown `v` or missing field → the consumer keeps the last frame + `⚠ estado ilegible` and paints **nothing** unparsed; atomic write (tmp+rename: the reader never sees truncated JSON — L2: reader/writer loop 1000 iterations without parse error). Hostile content: `\e]0;x\a`, `\e[2J`, `<TARGET-CONTENT` in a host/shell/KB → absent after `stripControl()` | — |
| Live contract | L3 | Smoke: after 1 turn `jq .v,.ts panel.json` and the SESIÓN card reflects `turno` and activity; the counter rises (measured today in `panel.lines`: 0→1 [V]) | Only with a reachable endpoint; does not run in CI |
| 1000 elements | L1 | 1000 hosts/shells/KB: `lines.length ≤ height`; header with the real total `1000 hosts`; row `… +994 más`; `renderRail` time < 50 ms (loose cap, not a benchmark) and independent of n (n=10 vs n=1000 same order) | — |
| Empty / error | L1 | No state → exactly 1 row `esperando pi…`; empty scope → `✗ vacío` + `fail-closed`; no shells/block/KB/changes → one row per card; no ledger → no HALLAZGOS card (not `0/0`); guard FALLÓ → `✗ FALLÓ` + not collapsed. Minimum width (w=1,2,10) and height 0/1 do not throw | — |
| Long text/Unicode | L1 | Long path truncates on the left (`…/active-directory.md`); IPv6 and 80-char host are not truncated before a word; CJK/emoji width 2 does not exceed w (needs `wcwidth`) | Cell width of `◌ ▰ ⎇` in real fonts **[?]** |
| Insufficient height | L1 | Height smaller than the content → auto-collapse from card 8 upward; GUARD never; reopening one collapses the next; `lines.length ≤ height` always | — |
| Write invariant | L1/L2 | No rail path (click/key) writes to `panel.json`, `scope.txt` or `runtime`; L2: `sha256` of both before/after a burst of clicks and keys | — |
| Regression | L1 | The existing selftest stays green (`all passed` ×2) | — |

## 4. Testability risks

1. **No passes counted:** `ok()` is silent on success; there is no proof that a new case ran. Add an assertion counter and
   require `>=N` (or print `N checks`) to detect tests that do not run.
2. **Focus:** `MouseDown1Pane` alone is not enough (Double/TripleClick); the focus test must include fast clicks or it passes by
   chance. The bindings belong to the whole server: always test on an own `-L` socket.
3. **Update delay:** the panel goes by guard timer + 400 ms poll; L2/L3 must poll (`until`), not sleep.
4. **Clock:** staleness and `hace Ns` require an injected clock; if the renderer calls `Date.now()` it is not testable in L1.
5. **Live model dependency:** L3 depends on the Provider's server being up and on the model (the model's output
   is not deterministic); only counters/structure are asserted, never model text.
6. **Minimal mocks:** the sidebar today mixes IO, reading and drawing (`gekko-sidebar.mjs`); if `handleKey`/`parseMouse`/`renderRail`
   are not extracted as pure functions, L1 cannot cover them and everything falls into L2 (slow, brittle).

## 5. What cannot be automated

- Real look on light/dark/16-color terminals, fonts and cell width of `◌ ▰ ⎇` (human visual review; the
  contrast is indeed computed in L1).
- OSC 11 autodetection under tmux **[?]** and the physical terminal's mouse support.
- That the operator perceives the rail as "not stealing keys" with their own `~/.tmux.conf`.
- Not verified: `ctx.ui.setFooter` in a real session (only its signature exists in the `.d.ts` of pi 1.5.0).
