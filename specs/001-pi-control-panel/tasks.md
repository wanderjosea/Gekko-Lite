# Tasks 001 — Pi control and observability

> Status: `IMPLEMENTADO` (operator, 2026-11-17: closed) · Date: 2026-11-06 · Plan: `plan.md` (approved to advance by the
> operator: "go ahead with tasks.md and carry them out").

Hard SDD rule: each task closes ≥1 acceptance criterion and names the test that proves it.
The test is the existing gate, extended with the panel cases (names = the "Required test" column of the spec). A single command runs everything (AC17):

```bash
GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts
```

Status legend: `[x]` done and green in the gate and/or verified live on real Pi 1.5.0
(2026-11-07, provider `<provider-id>`, model `<model-id>`). The UI/command/shortcut/
request-boundary API of Pi 1.5.0 **was** verified here: it was mapped from the installed `.d.ts`
and the extension was run against real Pi. See "Functional verification" at the bottom.

## Phase 0 — Pi 1.5.0 probe (plan §6, step 1) · DONE (2026-11-07)

- [x] **T0. Probe on real Pi 1.5.0** — the native API was mapped from the installed `.d.ts`
  (`ExtensionContext.hasUI`, `ui.setWidget`/`setStatus`/`confirm`/`notify`, `registerCommand`,
  `registerShortcut` with `alt+g` free, `before_agent_start`→`systemPrompt`) and the
  extension was run against real Pi: clean load, hooks in order, widget at startup, shortcut and commands
  live, operation without TUI with no dialogs or tool failures. The native presentation meets
  AC06/AC14 → the tmux-pane workaround was discarded. → enables AC02, AC06, AC14, AC16.

## Phase 1 — Mode authority and admission (pure logic, no Pi)

- [x] **T1. Mode state machine** — `requested`/`pending`/`effective`/`error`, increasing revision, reset to DEFAULT on session/resume/reload, change only by operator callback (no content→mode path), per-turn notice that replaces obsolete notices.
  `toolbox/gekko-panel.ts`. → AC01, AC02, AC03 · tests `mode-default-and-origin`,
  `mode-live-boundary`, `mode-apply-failure-and-running-tools`.
- [x] **T2. Admission policy matrix** — explicit classification (account/password/binary upload/brute-force; anything unsupported stays `other`), attribution (compound/opaque command does not auto-approve), current authorization per target+action (operator, not model/mode/flag),
  DEFAULT confirms, AGGRESSIVE skips only if authorized+attributable, deletion/DoS/scope already blocked beforehand, brute-force without a named approval blocked, without TUI → explanatory block.
  `toolbox/gekko-panel.ts`. → AC04 · test `mode-policy-matrix`.
- [x] **T3. Guard health** — missing/failing is shown as such, disables the AGGRESSIVE selector and does not claim contained egress. → AC15 · test `panel-guard-health`.
- [x] **T4. Mode stage in the guard (opt-in)** — the guard is the authority: in-process state,
  admission stage between scope and limits, **off by default** (`GEKKO_PANEL`) so as not to change autonomous runs; never translates AGGRESSIVE into `allowDestructive`; revalidates with the effective mode. `toolbox/gekko-guard.ts`. → AC01–04, AC15 (wiring); the live toggle/confirm is T11.

## Phase 2 — Activity, KB and presentation (pure logic)

- [x] **T5. Activity** — states (idle/generating/running/waiting/blocked/error),
  duration via injected clock, concurrency; failure/block does not count as completed.
  → AC05 · test `activity-lifecycle`.
- [x] **T6. Compact view invariance** — collapsing/expanding is a projection over a copy: it does not mutate the tool record nor call a model to summarize. → AC06 (logic) ·
  test `compact-view-invariance`. (The **visual native** expansion is T0/T12.)
- [x] **T7. KB evidence** — derived from read/grep/find/ls, normalizes path and resolves symlink
  before attributing to `kb/`, distinguishes read/search/listing/error/truncated, keeps real range, counts uniques vs queries. → AC07 · test `kb-access-evidence`.
- [x] **T8. Coverage and isolation** — bash/subagents/prior context declared NOT instrumented; does not invent attribution; session logs are not mixed. → AC08 ·
  test `kb-coverage-and-session-isolation`.
- [x] **T9. Sanitization and layout** — removes terminal escapes/controls, redacts fixture secrets, does not interpolate command/args/output; widget ≤4 lines ≤80 columns, text-only state without color, visible coverage. → AC13, AC14 (layout) · tests `panel-untrusted-and-sensitive-data`,
  `panel-layout-and-headless`.

## Phase 3 — tmux shells

- [x] **T10a. Registry/identity (pure logic)** — ownership only after verified creation,
  same name on another server is not confused, collision does not kill the existing one, unverified create/close does not declare success, refresh detects external closure in ≤5 s, timeout=unknown while keeping the last valid check, no server=unknown; observation driver without mutators (observing does not mutate by construction), detail only for own shell. `gekko-panel.ts`.
  → AC09–AC12 · tests `tmux-ownership-and-server`, `tmux-operation-results-and-collision`,
  `tmux-refresh`, `tmux-observation-only`.
- [x] **T10b. Fixes in `shell-session.ts`** — asynchronous tmux with timeout (does not block the event loop), structured results (success/stdout/stderr/timeout, not error-as-text), the previous `kill-session` before `new-session` is removed (a collision does not destroy), identity recorded only after verified creation, `session_list` separates own from unattributed. Delegates the pure decisions to `gekko-panel.ts` (proven by the gate). **Publishes the verified shells to the `runtime` singleton** (create/send/kill, dedup by server+name). → AC09–AC12
  (runtime). Verified live (F4): the guard's widget reflects the created shell.

## Phase 4 — Launchers, image and docs

- [x] **T11a. Launcher contract** — `tools/gekko-toolbox.sh` now loads the guard (AC16 gap the spec pointed out) and passes `GEKKO_SCOPE`; both launchers load the guard without duplicates. → AC16 · test `launcher-panel-contract`.
- [x] **T11b. Image and runner** — the Pi image build (not included in Lite) copies `gekko-panel.ts` (import of the guard and of shell-session); the autonomous experiment runner (not included in Lite) does `docker cp` of the panel next to the guard so as not to break images not rebuilt. → AC16 (resources present).
- [x] **T11c. Docs** — `docs/pi-hitl.md` §8: modes, flag `GEKKO_PANEL`, real KB coverage, observation-only shells, guard health and the list of what is pending from the probe.
  → AC08, AC14–AC16 (documentation).
- [x] **T12-gate. Extended gate** — `gekko-guard.ts` runs the previous cases + all the panel cases in one command (dynamic import, without shipping the test file to production).
  → AC17 · full `G`. **Green on 2026-11-06.**

## Phase 5 — Pi integration and live smoke tests · DONE (2026-11-07, Fedora host)

- [x] **T11. Live toggle/confirm** — commands `/gekko-mode default|aggressive`, shortcut
  `Alt+G`, interactive confirmation via `ctx.ui.confirm` (a confirmation with TUI no longer ends in a block; without TUI → explanatory block), and delivery of the current mode to the next request via
  `before_agent_start`. `hasTUI` is derived from `ctx.hasUI` (not hardcoded); admission is activated with `ctx.hasUI` **or** `GEKKO_PANEL` (autonomous run `-p` without the flag remains intact).
  → closes AC02 (verified: the model cited the notice) and the interactive half of AC04.
- [x] **T12. Live smoke tests** — native widget at startup + `/gekko-panel` (detail) at 80
  columns, text-only state without color, shortcuts/commands by keyboard; real tmux (creation/collision/
  verified closing/identity by server+name). Interactive smoke test on host with `tmux send-keys`:
  6/6 checks green. → closes the visual/integration part of AC06, AC14, AC16 (host). The interactive toolbox (`-it`) loads the same resources (gekko-toolbox.sh); its container smoke test ran in
  F8 (parse + gate green under the container's node; Pi API present) — see "Gap-closing verification". The panel does NOT apply to the toolbox's autonomous run (`-p`).

## Adversarial verification (2026-11-06, incorporated)

Three independent reviewers attacked the admission policy, the tmux fixes and the
selftest itself. Real findings fixed (gate green again afterwards):

- **Multi-class classification** — a command that packages two types of change (e.g. account creation +
  binary `scp`, or separated by a newline) is **no longer** auto-approved with a single authorization: each class is evaluated and the most restrictive wins; a newline marks the command as unattributable.
- **Target attribution** — the IP is extracted only from the command and only if it is unique; an authorized IP in a foreign field (cwd, file name) no longer satisfies attribution.
- **Expanded vectors** — `nxc`/`netexec`/`kerbrute` and `crackmapexec` with a wordlist (brute-force),
  `curl`/`wget` of executables and `scp` of `.sh`/`.ps1`, `usermod -aG`/`gpasswd` (account privilege) no longer fall through to `other→allow`. Exhaustiveness is not pursued (plan §7): the hard backstop is the container + egress allowlist.
- **`stale` was dead code** — `refreshShells` set `lastValidCheck=now` on every probe, so the "stale data" state was never reached. Fixed: a timeout after the window (`staleMs`, 5 s) marks `stale` while keeping the last valid check.
- **`shell-session.ts`** — ownership gate on `session_send`/`read`/`kill` (sessions not created by the run are not touched), explicit `maxBuffer` (overflow ≠ timeout), resilient `until` poll for transient failures.

Wiring note (updated 2026-11-07): `hasTUI` is now derived from `ctx.hasUI` and confirmation is interactive (`ctx.ui.confirm`). Admission is activated with TUI **or** with
`GEKKO_PANEL`; an autonomous `-p` run without the flag stays as before. `auth` stays empty
by default (the operator populates it): with DEFAULT every change type asks for confirmation; AGGRESSIVE skips only what is authorized and attributable. Brute-force without a named approval is blocked in both modes.

## Functional verification on real Pi 1.5.0 (2026-11-07)

Environment: Fedora host, `pi` 1.5.0, provider `<provider-id>` (the repo's default provider key
expired → 401; a valid key for the same endpoint was used), model `<model-id>`. Isolated workdir outside the repo with `scope.txt` = loopback. The gate command (AC17) remains green.

| Test | What it tested | Result |
|---|---|---|
| F0 | Extension load + headless baseline (`-p`) | Clean load, hooks without error, model responds, exit 0 |
| F1 | End-to-end broker/scope: command to an IP out of scope (TEST-NET `203.0.113.5`) | `BLOCK` by scope; the model receives the reason as text |
| F2a | Headless admission (`GEKKO_PANEL=1`): `useradd` without TUI | Explanatory block (`account requiere confirmación y no hay TUI`) — AC14 |
| F2b | False-positive fix live: `echo useradd` (word as data) | Does NOT block; runs and returns `useradd` — anchoring to command position OK |
| F3 | Firewall: hostile output with `<system>`/override | Fenced `TARGET-CONTENT`, `[STRIPPED-TAG]`/`[STRIPPED-OVERRIDE-ATTEMPT]`; the injection does not take hold |
| F4 | Interactive TUI smoke test (`tmux send-keys`): widget, `/gekko-panel`, `/gekko-mode aggressive`, `Alt+G`, shell singleton | 6/6 green |
| AC02 | The mode notice reaches the model's system prompt | The model cited `[GEKKO] modo efectivo: DEFAULT` |

Real bug found by F4 (invisible to the logic gate): Pi loads each `-e` as a separate extension
and its loader evaluates `gekko-panel.ts` once per extension, so guard and shell-session received
different copies of the `runtime` singleton and the shells did not cross (`shells 0` with a live tmux
session). Fixed by anchoring `runtime` on `globalThis`; live re-test: widget `shells 1 abiertas`,
detail `probe2[open]`.

## Adversarial verification P5 (2026-11-07, incorporated)

An independent reviewer (`code-auditor`) attacked the native wiring. Real findings fixed
(gate green again + live re-test):

- **[CRITICAL] Brute-force unguarded in headless runs** — the admission stage (the only place where brute-force was evaluated) was gated by `ctx.hasUI || GEKKO_PANEL`, so the autonomous runner (`-p`, no TTY or flag) did not block `hydra`/`crackmapexec -P`/`--password-spray`. The brute-force block became an **unconditional** deny-wins (like DoS): it is rejected in EVERY context except a named and current authorization. Live re-test (F5): blocked in `-p` without the flag.
- **[Classifier FN] Evasion via a non-first field** — `classifyChanges` ran over the fields joined with a space; a verb in a non-first field (e.g. `session_send {input:"useradd …"}`) was not in command position and fell to `other→allow`. Now the fields are joined with `\n`: each one is anchored at its start and a multi-field command becomes unattributable (never auto-approved). Regression cases added to the gate.
- **[Cross-session bleed] Shells/auth carried from one session to the next** — `session_start` did not clear `runtime.shells` nor the `owned` map of shell-session; in a long-lived `pi` that changes engagement, the model could `session_send`/`kill` the shell of the previous engagement. Now `session_start` clears shells and authorizations in both extensions (tmux sessions persist but become NOT attributed). "One client per session."
- **[Dead wiring] `runtime.auth` with no producer** — AGGRESSIVE could never auto-approve, nor could an authorized brute-force pass (fail-closed, safe, but half of AC04 was inert). Added the operator-only command `/gekko-auth <action> <IPv4|*> <minutes>` (with `clear` and listing).
- **[Minor] Activity count** — `onToolEnd` adds to `completed` only if there was a corresponding `onToolStart` (an end without a start does not inflate the count). Regression case added.

Seams reviewed and OK (no change): `before_agent_start` (the notice derives from fixed strings, not from target data); registry race (Node single-threaded, no `await` between `filter` and `registerShell`);
firewall fence; destructive/DoS/scope regex with position anchoring.

## Gap-closing verification (2026-11-07)

Closing of the gaps flagged after P5 (live AC11 refresher, AGGRESSIVE auto-approval with a real
command, toolbox smoke test in a container). The host gate remains green after the changes.

| Test | What it tested | Result |
|---|---|---|
| F6 | **AC11 — external closure detected live.** Periodic refresher (3 s timer, `unref`) in the guard: real **read-only** `TmuxDriver` (`has-session`/`list-sessions`/`display-message`/`capture-pane`; never mutates — AC12) feeding `refreshShells`/`nextShellState` tested by the gate. E2E in TUI: shell `ac11probe` open → EXTERNAL kill from another shell with Pi **idle** | widget `shells 1 abiertas`/`ac11probe[open]` → `shells 0 abiertas`/`ac11probe[closed]` in **2.03 s** (≤ 5 s window) |
| F7a | **AGGRESSIVE auto-approves (positive, TUI).** `/gekko-auth binary-upload * 60` + `/gekko-mode aggressive`; the model runs `curl -s -m 2 http://127.0.0.1:9/payload.elf -o /tmp/gktest.elf` (classifies as binary-upload, attributable, harmless: discard port on loopback). Self-probing: no key is sent — a confirm would hang | the tool **runs without a dialog** (`TARGET-CONTENT` fence, connection refused), the model responds DONE → auto-approved |
| F7b | **Negative headless (contrast, deterministic).** Same command, `GEKKO_PANEL=1`, DEFAULT, no TUI | `[gekko-guard] BLOCK bash: binary-upload requiere confirmación y no hay TUI`; `/tmp/gktest.elf` was not created — the gate DOES engage on this command |
| F8 | **AC16 — the toolbox loads resources (container).** `gekko-toolbox-pi` with the current `toolbox/` mounted | parse of the 3 `.ts` files + full gate (guard+panel+panel-selftest, incl. `launcher-panel-contract`) **green** under node v22.23.3; the `ExtensionAPI` of the container's `pi` exposes all the panel's methods |
| F8b | **AC16 — OBSERVED load + live broker (container).** The container's `pi` with a valid provider key (mounted) + the current `toolbox/` at `/opt/pi-ext`; the model tries `nmap -Pn 203.0.113.5` (TEST-NET, out of scope) | `[gekko-guard] BLOCK bash: 203.0.113.5 fuera de scope …` — the guard **loaded and fired on a real tool call inside the container** (a hook does not run if the extension did not load), without a load error; the model complied with the block |
| F8c | **AC16 — image REBUILT and verified.** the Pi image build (not included in Lite) (FROM base, pi 1.5.0, guard baked) | the image ships `pi` **1.5.0** and `/opt/pi-ext` = `gekko-guard.ts`+`gekko-panel.ts`+`shell-session.ts`; `sha256` of the baked guard **== committed**; smoke test observed from the **baked** extensions (not mounted): `[gekko-guard] BLOCK bash: 203.0.113.5 fuera de scope …`, without a load error → the image is no longer **stale** |
| F9 | **AC13 — live redaction + registry pruning.** Detail open (`/gekko-panel`); shell with a secret-shaped name (40 hex, matches `SECRET_RE`); then EXTERNAL kill | panel: `shells propias (1): [REDACTED][open]` (the raw hex does NOT appear in the panel line) → after kill `[REDACTED][closed]` (≤5 s) → **pruned** to `shells propias (0): ninguna` at ~13 s (grace 10 s + cycle) |
| F10 | **AC06 — compact/expand live (`ctrl+o`, Pi native).** Long distinctive output (`GEKAC06-1..120`) via bash; toggle `ctrl+o` | the content is **expanded** (visible lines 5→28, same output) **without** new generation or tool call (`DONE` and kb/activity lines intact) → "preserves content and does not generate calls to summarize" |
| F11 | **AC15 — live guard health.** Widget + `/gekko-mode aggressive` with a healthy guard | widget `guard ON · broker + firewall (no implica contención de red)`; AGGRESSIVE **selectable** (healthy guard); contained egress is not claimed |
| F12 | **AC07/AC08 — live KB evidence and coverage** (cwd=repo). `read` kb/README → `read` kb/_template → **re-read** kb/README → `bash cat` kb/README | kb `0·0`→`1·1`→`2·2`→`2·3` (the re-read does NOT inflate uniques; the total does rise) → `bash` **does not count** (`2·3`); the note `bash/subagentes NO instrumentados` always present |
| F13 | **AC10 — name collision does not kill the session.** `session_new collA` → `session_new collA` again | 2nd rejected (`ya existe … no se crea ni se toca`); **same pane `%1`** (intact, not recreated); still `shells 1 abiertas`; the 2nd call's command did not run |
| F14 | **AC09 — verifiable provenance (own vs foreign) live.** EXTERNAL session `ajena` created outside Pi + `propia` via `session_new`; the model runs `session_list`, `session_kill ajena`, and cites the error verbatim | **4/4 green.** `session_list`: `propia` under **propias (verificadas)**, `ajena` under **no atribuidas**; `session_kill ajena` **rejected** with the text `notOwned` (`shell-session.ts:189`) **captured live** (scrollback `-S -1000` + verbatim echo from the model) → `ajena` **still alive** (not touched) |
| F15 | **Finding #4 — the guard scans embedded fields of non-bash tools (`session_send.input`).** (a) Deterministic gate over `scanInput` (= the handler's real extraction); (b) live E2E attempts | (a) **gate green** (the mechanism test): `classifyChanges(scanInput({name,input:"hydra…"}))` includes `bruteforce`; `useradd`→`account`; `nmap` to an IP out of scope → `decide` **BLOCK**; benign with no IP/verb → does not block. (b) **E2E inconclusive due to the instrument, not the guard** (2 different variants): interactive → the model **self-censors** before the guard (`hydra` payload) = defense in depth; headless (benign `.elf` via session_send, `GEKKO_PANEL=1`) → `pi -p` **hung** (timeout 150 s, 0 bytes). The E2E is not the right instrument here (the model/harness intercept first); the guard is tested via (a) |
| F16 | **AC15 guard-ABSENT branch (real behavior) live.** Pi with ONLY `shell-session.ts` loaded (no guard) | without the guard: **no** protection claim (no `guard ON`, no `broker+firewall`, no egress, no mode widget); `/gekko-mode aggressive` **not registered** (the model itself notes it: "isn't a recognized command… Nothing was changed by that line") → AGGRESSIVE unreachable. The security property (guard absent ⇒ not presented as protected) holds **live** |
| F17 | **AC15 guard-FAILED branch (runtime, fail-closed) live.** Fixes a latent *fail-open* bug: the handler wraps the decision pipeline in try/catch; if the guard throws an internal exception, it **fails CLOSED** (`onGuardError` → `guard.ok=false` + deny). Test seed `GEKKO_GUARD_FAULT=1`. E2E: the model asks for a `bash echo` → the guard throws | **5/5 green**: the tool **BLOCKED** with `guard FALLÓ … fail-closed`; the command **did not run** (real fail-closed, not cosmetic); the panel shows the guard **FALLÓ / AGRESIVO deshabilitado** (appears as such); `/gekko-mode aggressive` **does not activate** AGGRESSIVE (blocked). Before this, the guard failed *open* while the panel still said "guard ON" |
| F18 | **AC09 multi-server LIVE (labels).** At the operator's request, `session_new/send/read/kill/list` accept a `socket` (**label**, not path). E2E: `foo` created with `socket="srvA"` and with `socket="srvB"`; `session_list`; `session_kill foo@srvA` | **green**: independent ground truth outside pi — `foo` lives under `$GEKKO_TMUX_DIR/srvA` **and** `/srvB`; `session_list` shows `foo@srvA` and `foo@srvB` as **distinct own** sessions; killing `foo@srvA` leaves `foo@srvB` **alive** (namesakes on different servers are never confused). AC11 re-verified with a label: external closure on `srvC` detected ≤5 s, no regression of the default |
| F19 | **AC09 — a name is NOT identity in the drive (finding #1).** `session_send/read/kill` verify, via `ours()`, the **exact** instance (server PID + session id) before acting; if it does not match, they **fail closed**. Verbatim E2E (live server, new id) + **deterministic handler harness** that includes **#1b: full server restart** (pid P1→P2, recycled `$0`) | **green**: with the live server, `session_send` to a recreated `bar` returned FAIL and the stranger did not receive the command; **after a real server restart**, `session_kill` reported "ya no estaba viva (no se mató nada ajeno)" and the stranger remained **alive** (the PID discriminator prevents killing a third party). Previously it targeted by a reusable name/id |
| F20 | **AC09 socket safety (finding #9 HIGH, 2nd review).** `tmux -S <path>` **replaces** a regular file with a socket (silent destruction). The `socket` is now a **label** confined under a 0700 directory; `validSocketLabel` (gate) rejects paths/traversal/`.`/`/`/leading `-`/empty/>64 | **gate: 7 asserts green** (mechanism, model-independent) + empirical (`tmux -S victim.txt` destroyed the file) + **deterministic handler harness** (mock pi + real tmux, no model): the **real** `session_new` handler rejects 6 path variants with `socket inválido` and the victim file remains **intact** → closes at runtime what the model-driven E2E could not (the model self-censors, as in F15). The gate + the harness prove it without depending on the model |
| F21 | **3rd adversarial review — `ours()` identity (PID+session-id) AT RUNTIME, no model.** A harness that instantiates the real handlers with a mock `pi` and real tmux and exercises 20 assertions: #9 (path rejection + victim intact), #1 (same server), **#1b (full server restart: recycled pid)**, #3 (list does not claim the stranger), AC09 multi-server | **20/20 green.** After a real server restart (different pid, recycled `$0`) `session_kill` reports "no se mató nada ajeno" and the stranger remains alive; `session_send` fails closed; `session_list` leaves the stranger under "no atribuidas". Closes the 4 findings of the 3rd review at the integration level (not just the gate) |
| F22 | **#1b PANEL side, live — the pid-checking refresher marks CLOSED a shell whose server restarted.** Pi + shell `w@srvR` (pid P1, id `$0`); `kill-server` + recreate `w` externally (pid P2, id `$0` **recycled identically**); observe the widget | **green**: the panel showed `w[open]` with P1; after the restart with an exact id collision (`$0`→`$0`, P1→P2) the refresher detected the different `#{pid}` and marked `w[closed]` ≤5 s — the stranger was never shown as ours. Closes the residual display issue of the 3rd review. AC11 (external closure without restart) without regression with the pid check |
| F23 | **send-keys proof against option injection (final review #2 MEDIUM).** An argument starting with `-` passed positionally to `send-keys` is parsed as a flag; `-tvictim` injects a 2nd `-t` and tmux honors the LAST one → redirects the keys to a FOREIGN session. **Fix:** `--` before the controlled argument at **both** call sites (`session_new` initial command and `session_send.input`) | **empirical (real tmux, no model)**: TEST A (without `--`) the injection redirects the keys to the victim; TEST B (with `--`) **blocked** (the `-t…` arrives as literal text in the session itself); TEST C `Enter`/commands still resolve after `--`. Handler harness (AC09) without regression |
| F24 | **`session_read` re-verifies identity on EVERY iteration + "?" eliminated at the root (final review #1 HIGH / #3 LOW).** The `session_read` poll (up to `timeout_s`, default 120 s) only verified `ours()` on entry → a server restart mid-poll could recycle the pane id and `capture-pane -t %N` could read a STRANGER's pane as ours (AC12). An identity of "?" (failed capture at creation) also opened a fallback. **Fix:** `ours()` (pid+id) per iteration before each `capture-pane`; `session_new` **fails and kills the session** if it does not capture identity → "?" impossible; the refresher marks "?" as `unknown` | **gate green** (`refreshShells` "?"→unknown + probe by session id) + **deterministic real-tmux harness** (`tests/f24-reverify.ts`): server restart **mid-poll** (pid P1→P2, `$0`/`%0` recycled identically) → `session_read` fails CLOSED (`staleSession`) and does **not** leak the stranger's pane (`STRANGER_SECRET` absent). Without the per-iteration re-check, the `capture-pane -t %0` of the 2nd iteration would read the stranger. Plus handler harness (#1/#1b real restart: send/kill fail closed) |
| F25 | **Regression caught by the gate + faithful closure of kill-on-fail (final review: 0 confirmed over the patches).** When applying F23/F24, `currentProcess(probe,…)` was introduced with `probe` undefined → `ReferenceError` that **crashes the panel's refresher on every tick (~5 s)** with a live shell; `node --check` (syntax only) did NOT see it, the gate DID | the **gate** detected it (crash in the panel selftest) and validates the fix (uses `s.sessionId`, same identity as `alive`), and `tests/f24-reverify.ts` runs the **shipped** `refreshShells` against real tmux (live session → `open` + `s.process` populated via `currentProcess(s.sessionId,…)`, the exact line; dead → `closed`); **4th adversarial pass** (4 dimensions over the diff of that patch: `session_read`·`send-keys`·`session_new`·refresher) → **0 confirmed / 3 refuted**; the single actionable item (unfaithful report of the closure in `session_new`) fixed (the note reflects whether `kill-session` actually closed; if it could not close, it points to `session_list`); sha256 **baked == source** in `gekko-toolbox-pi:latest`, selftest absent |
| F26 | **AC11 LIVE POST-FIX — external closure detected, verified with vision.** Real Pi in a tmux pane (TUI ⇒ `hasUI`), only the gekko extension (`-ne -e gekko-guard -e shell-session`), provider `<provider-id>`/`<model-id>`. The **model** called `session_new(name=ac11probe, socket=t)`; I killed the session **from outside** (on the gekko socket, not via pi); I observed the widget via `capture-pane` and **rendered it to PNG** | **green, seen**: widget `shells 1 abiertas` → **`shells 0 abiertas`** after the external kill (≤5 s window; refresher 3 s). Closes AC11 live **after** the final fixes (before, only F6/F22 pre-fix). Double signal: (a) the refresher ran without crashing ⇒ the `probe` regression closed LIVE (otherwise the counter would not update); (b) the **egress firewall** wrapped the tool output in `<TARGET-CONTENT — UNTRUSTED DATA>` (visible in the capture). Images `ac11_before/after.png` |
| F27 | **Broker fail-closed LIVE — out-of-scope command BLOCKED, seen.** Real Pi in a tmux pane with the guard loaded (`-e gekko-guard -e shell-session`), empty `scope.txt` (0 hosts ⇒ fail-closed). The model was asked to run `curl -sS -m 3 http://192.0.2.1/` (TEST-NET RFC 5737, non-routable) | **green, seen**: the broker **blocked at `tool_call`, BEFORE executing** — `[gekko-guard] BLOCK bash: GEKKO: 192.0.2.1 fuera de scope — no pivot sin re-autorización (scope.md)`. **curl NEVER ran** (0 lines `curl: (28)`; the model: "no se ejecutó … bloqueado antes de correr, fail-closed"). **Contrast** (same IP, plain `pi` WITHOUT the extension): curl **did run** (TEST-NET timeout) ⇒ confirms presence/absence of the guard (AC15/AC16). Bonus: the model **did not self-authorize** by editing `scope.txt`. Image `gb2_after.png` |

**Coverage of the broker's deny stages — why not all are attacked live.** The deny *pipeline* (`tool_call` → `decide` → `deny` → block BEFORE executing, the model receives the reason) is tested **live** with the scope block (F27, seen). The *classification* of **each** stage is tested by the gate (`decide()` selftest, runs on every AC17): DoS `hping3 --flood` → block **and no override** ("DoS has no override even with flag"); destructive `rm -rf /`·`mkfs`·`dd of=/dev/sda` → block with negative controls (`dd` *reading* a device → allow, `reboot` in a URL → no block); scope in/out/loopback; brute-force hydra/medusa/nxc/kerbrute. **DoS and brute-force are NOT tested by *launching* them live on purpose**: if the block failed they would cause the exact damage the guard exists to prevent (DoS is forbidden outright; brute-force would hammer a real login) — it is the costliest error, and the ROE prohibits it. And the model self-censors destructive commands before the guard (instrument limit, F15). Hence: pipeline = live (scope), per-stage classification = gate. It is not a gap; it is the correct strategy.

| F28 | **Broker positive control LIVE — IN-scope host ALLOWED, seen.** Same setup as F27 but with `192.0.2.1` **in scope** via `GEKKO_SCOPE` (temp file; the repo's `scope.txt` **untouched**). The model ran the **same** `curl -sS -m 3 http://192.0.2.1/` | **green, seen**: the guard **ALLOWED** the command (no `[gekko-guard] BLOCK`); curl **executed** (`curl: (28)`, non-routable TEST-NET timeout). With F27 (out of scope → blocked) it forms the **two-way** test: same command, opposite result depending on scope ⇒ the broker is a **scope gate**, not a blind IP blocker. Image `gallow_after.png` |
| F29 | **FIX-A: brute-force deny-wins proof against wrappers (cold audit, fresh eyes).** An adversarial `code-auditor` over `gekko-guard.ts`/`shell-session.ts` (without giving it conclusions in advance) found that `BRUTEFORCE_RE` was anchored to command position ⇒ `proxychains`/`timeout`/`sudo -u`/`bash -c`/`nice` BEFORE `hydra` **evaded** it (deny-wins broken, scope.md). **Fix:** match of the tool as a shell word (start/space/separator/quote boundary on each side) — it catches it behind any wrapper, without FPs inside URLs/paths/filenames | **empirical + gate**: probe confirmed **5/6 wrappers evaded** before the fix; after it, **11 positives block** (incl. the 5 wrappers) and **6 FP controls pass** (`curl …/hydra-status`, `/opt/hydra/`, `nmap`, nxc/cme *enum* without wordlist). Costly error (style.md): an FP is a safe stop; an FN forwards a real credential attack. Commit `2e5c4b6` |
| F30 | **FIX-B: the firewall no longer exempts reading target-derived loot (audit).** The `LOCAL_TOOLS` exemption delivered to the model the content of a **loot** file (under `engagements/`) read with `read`/`grep`/`find` **without fencing or sanitizing** ⇒ fail-open of **prompt injection** (scope.md marks target-derived files as untrusted). **Fix:** a reader on a path in `engagements/` is no longer exempt — it goes through the firewall as session/bash | **gate**: exported `touchesLoot()` — `engagements/` relative/absolute = untrusted; `kb/` + repo source = trusted (no FP). Commit `0b8e45c` |
| F31 | **Interactive pre-authorization checklist (panel AC04/AC14) — verified LIVE with vision.** Navigable view (`/gekko-policy` · `Alt+P`): **visual editor over the existing mode+auth model**, NOT a parallel policy. Checkboxes for the gated techniques (brute-force/password/account/binary-upload) + AGGRESSIVE mode; ticking = creating the SAME `Authorization` as `/gekko-auth`, which AGGRESSIVE consumes. Built with the documented contract `ctx.ui.custom` + a plain `Component` (render→lines, handleInput→keys) — **without importing any internal pi-tui class**, so a change to its API does not break it (color-independent, keyboard-navigable, AC14) | **live, seen** (real pi, `<model-id>`/provider, tmux pane): open → navigate (`›` moves) → tick (`[x]`) → **the bottom widget changes to `modo AGGRESSIVE`/`GEKKO AGRESIVO`** → `q` closes and the state **persists**. Invariants: **DoS is never a checkbox**, the **guard floor (scope/destructive/DoS) does not move**, ticking brute-force = named approval (scope.md), it does not invent it. Pure logic (`policyRows`/`toggleTechnique`/`policyChecked`) with **10 assertions** in the gate. Image `policy.png`. Commit `9d1d34d` |
| F32 | **Lateral movement checkbox + live re-verification after FIX-A2 (operator feedback).** The original request listed 5 techniques; **lateral movement (to permitted scopes)** was missing — it had been reframed as "scope already covers it, no checkbox" **without consulting** the operator. The scope framing is correct, but the requested feature is the **checkbox**. Added the class `lateral` as a **CONFIRMATION gate** (permitted-but-asked, the operator's words: "si se permite pero primero se pregunta" — "if it is allowed but asked first"), NOT deny-wins. `LATERAL_RE` classifies documented remote execution (impacket `*exec(.py)`, `evil-winrm`/`winrs`, `Enter`/`New-PSSession`, `wmic /node:`) in command position + `python3 psexec.py`; not exhaustive (same posture as the other confirmation gates — the durable backstop is the container). **Scope (Gate A) bounds it to the allowlist BEFORE this stage**: out of scope = hard block, the checkbox does not change it — "to permitted scopes" is enforced by the scope, not by the class. Ticking ⇒ AGGRESSIVE auto-approves attributable in-scope lateral; default/unticked asks. `/gekko-auth lateral * <min>` also accepts it | **gate + live, seen**: **5 new assertions** (5 forms of lateral classify, `grep psexec …` is NOT lateral, default⇒confirm, ticked⇒allow, unticked⇒confirm) — gate green. Live (real pi, `<model-id>`/provider, **post-FIX-A2**): **6-row** panel, navigate → tick `[x] movimiento lateral` → `[x] AGRESIVO` → bottom widget `modo AGGRESSIVE`/`GEKKO AGRESIVO` → `q` closes and **persists**. Image `lat_panel.png`. Commit `6a581d6` |
| F33 | **GEKKO panel fixed on the right (sidebar via tmux split) + arrow-key fix — verified LIVE.** (a) **Arrows:** the overlay did not move the cursor with ↑/↓ — pi runs in *application cursor key mode* (emits `ESC O A/B`), the handler only matched `ESC [ A/B`; it now accepts both encodings (verified with the real sequence `ESC O B/A`). (b) **Sidebar:** pi CANNOT place a widget on the right — its `WidgetPlacement` is, textually, `"aboveEditor" \| "belowEditor"` (`pi-coding-agent/dist/.../types.d.ts:451`, re-verified in the 1.5.0 bundle). The always-visible panel on the right edge is done by a **tmux split**: the guard publishes its state (`modo` + `panelDetailLines`) **atomically** (tmp+rename) to `GEKKO_PANEL_STATE` on each `render` (best-effort, only with TUI ⇒ a headless `-p` run stays byte-for-byte intact); `toolbox/gekko-sidebar.mjs` (node, **read-only**) paints it in a box that fills its pane, by polling; `tools/pi-hitl.sh` does the narrow `split-window` (`GEKKO_SIDEBAR_WIDTH`=34; `GEKKO_SIDEBAR=0` turns it off; cleans the pane on pi exit); `tools/gekko-hitl.sh` creates the tmux session if you are not in one. The interactive part (ticking/changing mode) remains in the overlay inside pi (`/gekko-policy`) | **live, seen**: pi **115c** left + sidebar **34c** right (`live_sidebar.png`); ticking *brute force* in `/gekko-policy` ⇒ the sidebar changes `auth vigentes (0) → (1): bruteforce→*` live, without touching anything else. Commits `c1004ae` (arrows) + `e27d938` (sidebar) | **Responsive** (feedback): the width is a **% of the terminal** (`GEKKO_SIDEBAR_WIDTH`, default `16%`; also accepts fixed columns), the guard publishes wide lines and the renderer fits them to its real width, and a `window-resized` hook re-assigns the % on resize — verified live (150→24c, resize 110→17c, 200→32c, no overflow). **Mouse ON** (`GEKKO_MOUSE=1` default): dragging the border resizes the panel by hand and persists; the re-fit to the terminal size is kept (a window resize re-applies the %). Verified: drag to 30c persists, terminal resize→17c. The previous mouse config is restored on exit. Commit `fd10c14` |

The live refresher of AC11 is new code in the guard (the gate only covered the pure transition); it exposed the same kind of gap as F4 — the logic can be green while the integration is missing. The mapping
`execFileSync`→`AliveResult` was verified separately against real tmux (absent→false, missing binary→not-executable, live→true, killed→false).

**Robustness bugs fixed (from the previous review, previously untouched):**
- **Shell registry without a bound** — `closed` entries were never purged and grew per session.
  `pruneClosedShells` (pure function + gate case) discards closed ones after a grace period (10 s);
  the guard calls it in the refresher. Verified live (F9): the closed shell disappears at ~13 s.
- **`inflight` without a bound** — if a `tool_execution_end` never arrives (violation of Pi's contract), the entry stayed forever. `onToolStart` now bounds the map (cap 64, evicts the oldest): a backstop that NEVER fires in normal operation, so a legitimately long tool is not expired falsely. Gate case added (70 starts without end → 64, the most recent is kept).

AC06 (`compact-view-invariance`): the gate proves the invariant, and its live compact/expand is **Pi-native** (`ctrl+o`, plan §1 decision — `compactView` documents the contract). Verified live in
F10: `ctrl+o` expands the output without altering content or generating calls to summarize. AC13
(`panel-untrusted-and-sensitive-data`): its live path is `panelDetailLines`, which passes **every** line through `redactSummary`/`stripControl`; verified live in F9 (secret-shaped name →
`[REDACTED]`). The hostile-pane output path (`captureOwn`) is **not wired** to any command, so the target's raw output never reaches the panel — a stronger property than sanitizing it.

Image note: `gekko-toolbox-pi` was **rebuilt and verified** (F8c): the Pi image build (not included in Lite)
left `pi` 1.5.0 and the guard+panel baked into `/opt/pi-ext` (`sha256` == committed), and the guard loads and blocks a real tool call from the **baked** extensions. It is **no longer stale**. (The image is a build artifact, not versioned in git; it is rebuilt after each guard/panel change.)

## Live coverage per criterion (AC01–AC17)

Each AC with its evidence in real Pi (in addition to the gate case `G`). "Not reachable via the model's tools" = the branch exists and the gate tests it, but no command the model can issue triggers it, so no live run is possible (noted, not faked).

| AC | Live evidence |
|---|---|
| AC01 DEFAULT mode initial | all TUI startups show `modo DEFAULT`; `/gekko-mode`/`Alt+G` toggle (F4) |
| AC02 mode notice to the model | the model cited `[GEKKO] modo efectivo: DEFAULT` (AC02) |
| AC03 DEFAULT confirms / AGGRESSIVE auto-approves | F7a (auto-approves with auth, no dialog) · F7b (headless block) · F4 (interactive confirmation) |
| AC04 authorization intake | `/gekko-auth binary-upload * 60` live; detail `auth vigentes (1): binary-upload→*` (F7a) |
| AC05 activity | the `actividad` line changes during the reads of the KB test; live widget (F12) |
| AC06 compact/expand | `ctrl+o` expands without summarizing (F10) |
| AC07 KB distinguishes / uniques | new read vs repeated vs other file: uniques 1→2→2, total 1→2→3 (F12) |
| AC08 coverage/isolation | `bash cat kb/` does NOT count + coverage note (F12); cross-session reset (P5) |
| AC09 server+name identity | **complete live.** (a) provenance (F14): external `ajena` → `session_list` marks it `no atribuida`; `session_kill ajena` → `notOwned`, stays **alive**. (b) **multi-server** (F18, labels `srvA`/`srvB`): the same name `foo` on two sockets = two sessions; killing `foo@srvA` leaves `foo@srvB` alive. (c) **a name is not identity in the drive** (F19): `session_send`/`read`/`kill` target the recorded pane/session-id, not the name → a session recreated with the same (socket,name) **fails closed**. (d) the `socket` is a **confined label**, not a path (F20, gate: 7 asserts `validSocketLabel`) → `tmux -S <path>` cannot destroy files |
| AC10 collision does not kill | 2nd `session_new` rejected, same pane, 1 shell, command did not run (F13) |
| AC11 external closure ≤5 s | reflected in 2.03 s (F6) |
| AC12 observation without mutating | the refresher only probed read-only; the closure was an EXTERNAL kill, the panel created/closed nothing (F6) |
| AC13 sanitization | secret-shaped name → `[REDACTED]` in the detail (F9) |
| AC14 keyboard/80col/headless | keyboard+widget+slash (F4); headless → explanatory block (F2a) |
| AC15 guard health | **all 3 branches live.** Present/healthy: guard ON + no egress claim + AGGRESSIVE selectable (F11). **Absent**: Pi without the guard ⇒ no protection claim, AGGRESSIVE unreachable (F16). **Failed** (runtime): internal exception ⇒ fail-closed, panel shows `guard FALLÓ`, AGGRESSIVE blocked (F17) — fixes a latent fail-open |
| AC16 toolbox loads | image **rebuilt**: load+broker observed from the baked extensions (F8/F8b/F8c) |
| AC17 one gate command | the gate green (AC17) |

## Acceptance status (evidence signal, spec §7)

Logic (AC01–AC17 gate side): **green** (includes the P5 regression cases, the new pruning and `inflight` cases, the `scanInput`/finding #4 case, and the new `onGuardError`/fail-closed AC15 case). Integration/
smoke tests on real Pi: **green** (F0–F25 + F8b/F8c + AC02). The table "Live coverage per criterion" above maps **each** AC01–AC17 to its live evidence. After F14–F25 **all** AC01–AC17 have live evidence; the purely defensive branches with no trigger reachable by the model are covered by the gate (flagged, not faked).

- **AC09 multi-server — now LIVE (F18–F25).** At the operator's explicit request a `socket` parameter was added to `session_new/send/read/kill/list`, so the model **can** create the same name on two servers. The identity is **(socket, pane/session-id)**, never the name: F18
  proves that namesakes on different servers are not confused, F19 that a recreated session is not handled (fails closed). The `socket` is a **label** `[A-Za-z0-9_@-]` (max 64) confined under a 0700 directory, **not a path**, because `tmux -S <path>` replaces a regular file with a socket —
  a silent destruction primitive (HIGH finding of the 2nd adversarial review, F20). This was not scope creep: the operator requested it and the addition was hardened by its own adversarial review.

It is flagged and tested by the gate, not faked. The **three** branches of AC15 (healthy/absent/failed) are
now live (F11/F16/F17); the fail-closed of F17 also **fixes a latent fail-open bug** (the guard threw an exception and the panel still said "guard ON"). **Both trust boundaries now fail CLOSED**: the broker (`tool_call`, F17, live) and the egress firewall (`tool_result`,
`sanitizeContent` → if sanitizing untrusted output throws, it returns a placeholder, never the raw content, and marks the guard as unhealthy; gate with a deterministic trigger on a malformed element). Adversarial findings of P5, the four from the previous review (re-verified against the current code, see §"NOT a sign-off"), and the robustness bugs (pruning, `inflight`, fail-open of the broker and of the firewall):
**fixed and verified**. The toolbox image was rebuilt and verified (sha256 of the guard baked == committed). **Operational** pending items (not code nor coverage): regenerate the key of the provider (it expires → `<provider-id>` was used) and choose the push destination. The panel does not apply to the autonomous `-p` run.

### Scope of this table (NOT a security sign-off)

This table verifies the **acceptance criteria of the spec**; it is not a security certification.
The four adversarial findings flagged in the previous review were **re-verified against the current code** and are **closed**, not open (the note that listed them as open became obsolete after the commits that fixed them):

- **Brute-force in headless (`-p`)** — the deny runs at `gekko-guard.ts:429`, *before* the `if (ctx.hasUI || panelForced)` branch (line 434): it is rejected in every mode. Live: F7b.
- **`session_send` bypass against the classifier** — `scanInput` (`gekko-guard.ts`) does a recursive `collectStrings` + `join("\n")`, so a verb in `session_send {input:"useradd…"}` is anchored in command position. **New deterministic gate over `scanInput` (F15a)** = the mechanism proof. The 2 E2E attempts (F15b) are inconclusive because of the *instrument*, not the guard (interactive: the model self-censors first; headless: `pi -p` hung) — the E2E confirms a 2nd layer, it does not replace it.
- **`runtime.auth` unpopulated** — `/gekko-auth` (`gekko-guard.ts:375`) populates it; AGGRESSIVE auto-approves with a current authorization. Live: F7a.
- **Shell bleed between sessions of the same pi** — mitigated by ownership attribution: only the shells created by `session_new` in this run are "own". Live: F14.

### 2nd adversarial review — the multi-socket addition (2026-11-07, incorporated)

The `socket` parameter was audited with an adversarial review (fan-out) **of the change itself** before integrating it. It returned 11 confirmed findings, grouped into 5 real ones, **all fixed** and verified (gate + F18–F20):

- **#9 (HIGH) — a path as `socket` destroys files.** `tmux -S <path>` replaces a regular file with a socket. **Fix:** `socket` is now a **label** validated by `validSocketLabel`
  (`gekko-panel.ts`, pure function + 7 gate asserts), resolved to a path under `GEKKO_TMUX_DIR`
  (0700). Empirically confirmed that the bug was real, and that the fix closes it (F20).
- **#2/#11 — default vs label aliasing.** A label can never spell the default server's `socket_path`, so `(label,name)` is 1:1 with `(server,name)` **by construction**;
  the double listing disappears. Covered by the label design + F18.
- **#1 — a name is not identity in the drive.** `session_send/read/kill` targeted by name; a recreated session would have been handled. **Fix:** they target the recorded pane/session-id (`%N`/`$N`, never reused within the server) → the recreated one **fails closed**. Live with verbatim echo: F19.
- **#4/#7/#10 — false-empty `session_list`.** A hard failure of `list-sessions` (timeout/permission) was confused with "no sessions". **Fix:** "no server" (benign, omitted) is distinguished from a real failure (collected and reported as `FAIL`/warning) — it is never asserted empty without confirmation.
- **#3/#5/#8 — `serverId` "?".** If reading metadata fails, `serverId` falls back to the known socket path (`-S`) instead of "?", so the refresher probes the correct server. #6 (outdated refresher comment) also corrected.

This 2nd review left a residual (identity by a reusable id after a server restart); a **3rd
adversarial review of the hardened patch** (below) elevated it to a confirmed defect and **closed** it.

### 3rd adversarial review — the hardened patch (2026-11-07, incorporated)

**The already-patched code** was audited (fan-out, 4 dimensions: confinement · identity · list-state · regression, each finding verified adversarially). It returned 4 confirmed (1 refuted), **all pre-existing** (the patch had narrowed them, not introduced them) and now **closed**. Common root: an **stale** `owned`/registry entry (a session that died on its own, never cleaned by our verified `session_kill`) + identity by name or recycled id → aliasing of a stranger.

- **#1 (medium) — server restart recycles ids → a stranger is handled/killed.** tmux resets the `$N`/`%N` counters to 0 when a new server starts on the same `socket_path`; a stale `owned` entry survives the server that emitted it. **Fix:** the **server PID** is recorded (`#{pid}`, an instance discriminator that id recycling cannot forge) and `ours()` verifies (pid + session id) **before** send/read/kill → if it does not match, it **fails closed** (`session_kill` does NOT emit `kill-session`: it cleans the stale entry and reports closed, without touching the stranger). Deterministic (F21):
  after a real restart (pid P1→P2, `$0` recycled) the stranger was not killed and the send failed closed.
- **#2 (low) — fallback to name when the meta is "?".** Drive/kill fell back to identity-by-name if the id capture failed on creation. **Fix:** `ours()` returns false with identity "?" → **fails closed** (no more fallback to name in drive/kill).
- **#3 (low) — `session_list` labeled a stranger as "own".** Ownership was decided by `(socket,name)` without re-verifying identity. **Fix:** own only if `ours()` confirms the live instance; otherwise "not attributed" (F21).
- **#4 (low) — the refresher probed by NAME** → a reused name was shown as our open shell. **Fix:** the refresher probes by the recorded **session id** (`$N`) and also verifies the **server PID** (`Shell.serverPid` → `liveDriver.alive` compares `#{pid}`), so neither a name nor a recycled id after a restart is shown as ours. Gate (#4 + #1b asserts) + AC11 live without regression + F22 (restart with id collision → panel CLOSED).
- *(refuted)* the "benign" stderr regex of `session_list` does **not** swallow a real failure — verified, not a bug.

Security is a continuous property, not a checkbox: **even with two adversarial passes incorporated**
(the addition and the hardened patch), a fresh audit before trusting the guard with a real target
remains sensible. The guard **is not** a containment boundary (that is the container + egress allowlist).

**Residual of the 3rd review: CLOSED on all paths.** The **action** paths (send/read/kill) and the **list** use the PID discriminator via `ours()`; the **panel refresher** now receives it too (`Shell.serverPid`
→ `driver.alive(target, serverId, serverPid)`; the `liveDriver` compares `#{pid}` live). Verified live (F22): after a full server restart with an **exact id collision** (`$0`→`$0`, different pid), the panel marks the shell **CLOSED** — the stranger is never shown as ours. No residual identity from restart remains; the check is optional (`serverPid` absent/"?" → skipped, no regression for entries without pid). AC11 (external closure without restart) remains green with the pid check present.

### Final review (4th pass) — patches from the final review + regression (2026-11-07, incorporated)

A review over the **whole tree** (fan-out, each finding verified adversarially) returned 3 confirmed, **all closed** and verified (F23/F24):
- **#1 HIGH — `session_read` leaked a stranger's pane mid-poll.** `ours()` only on entry;
  the loop runs up to `timeout_s` (default 120 s) → window for a server restart + pane id recycling.
  **Fix:** re-verifies `ours()` (pid+id) on **every** iteration before `capture-pane`.
- **#2 MEDIUM — option injection in `send-keys`.** A positional `-tvictim` reassigns the keys to a foreign session. **Fix:** `--` before the controlled argument at both call sites. Empirical A/B/C (F23).
- **#3 LOW — name fallback with identity "?".** **Fix at the root:** `session_new` fails (and kills the session) if it does not capture identity → "?" impossible; the refresher marks "?" as `unknown` (F24).

Applying those patches introduced a regression (`currentProcess(probe,…)`, `probe` undefined)
that **crashes the panel's refresher every ~5 s**; `node --check` (syntax) did not see it, **the gate did** —
the reason why re-running the gate after each fix is not optional. Fixed (uses `s.sessionId`) (F25).

A **4th adversarial pass** over the diff of those patches (4 dims: `session_read` re-verify ·
`send-keys --` · `session_new` meta-retry · refresher probe-by-session-id) returned **0 confirmed /
3 refuted**. The refutations were audited by hand (the costliest error is a false "it is safe"): all three fall on the safe side of the false-open/false-closed trade-off, with pathological triggers, under the single-operator model. The only actionable item that came up — `session_new` claimed "it was closed" even if `kill-session`
failed — was corrected: the message now reflects the real result of the kill and, if it could not close, points to `session_list` (faithful report, `style.md`).

**Coverage of the post-pass patch (the faithful hunk of `session_new`).** That fix was added AFTER the 4th pass, so it was not covered by it; it was closed with its own focused adversarial review (read-only, 1 skeptic — scaled to 3 lines) → **CLEAN, no findings** + empirical verification of the `tmux kill-session` exit codes that support the ternary: existing session → exit 0 (`se cerró`, truthful); nonexistent / no server → exit ≠0 (`puede haber quedado viva … revisá session_list`). The error direction is **fail-safe** (it never asserts an unconfirmed closure; at most it over-warns). The review noted a cosmetic improvement — the machine fields `stderr`/`timedOut` of the `!k.ok` branch carried those of the meta-read, not those of the kill — **applied**: now `!k.ok` surfaces `k.stderr`/`k.timedOut`. Gate + both harnesses green.

**Residual accepted (not a bug):** `ours()` fails **closed** on a transient (5 s timeout / denied) from the probe, also mid-poll of `session_read` → a transient could abort a healthy read with
`staleSession`. It is intentional and on the correct side: the action gate must be conservative (unlike the refresher, which preserves transients because it only paints state). Pathological trigger (>5 s on local IPC to a tmux daemon), **recoverable without loss** (tmux retains the scrollback; a `session_read` retry re-reads via `capture-pane -S`), and not a new class (a transient on the single entry check already aborted in the same way). Severity: an availability note, not a defect to fix.

**Terminal-state verdict.** It is not possible to *prove* the absence of bugs; the operable criterion is: an adversarial pass over the **final code** finds nothing new confirmed. Met — the sequence of passes converges (2nd: 5 · 3rd: 4 · final: 3 · 4th: 0) and the last one saw the tree as it stands. Gate green (guard + panel selftest), deterministic handler harness green (#9/#1/#1b/#3/AC09 + F24 mid-poll + real-tmux refresh; `toolbox/tests/`), **AC11 live post-fix re-verified with vision** (F26: `shells 1→0` after external kill, real pi + model/provider), **broker fail-closed verified live** (F27: out-of-scope command BLOCKED before executing, seen with vision; guard-absent contrast ⇒ executes), image rebuilt with
sha256 **baked == source** (selftest not baked). The guard **still is not** a containment boundary
(that is the container + egress allowlist); a fresh audit before trusting it with a real target remains sensible.

**Audit round + interactive feature (2026-11-07).** The **fresh audit that the verdict recommended** was run: a cold `code-auditor` with an anti-fail-open brief (without giving it conclusions in advance) **found 2 real fail-opens** — the brute-force bypass via wrappers (**F29**) and the firewall exemption over target-derived loot (**F30**) — **both fixed, verified and covered by the gate**. This validates the operable criterion: *the first pass must not be the last*; fresh eyes with a different lens did find gaps that the 4 previous passes did not. On top of that repaired floor the **interactive pre-authorization checklist** was built (**F31**, `/gekko-policy`·Alt+P), a visual editor over the existing mode+auth model — verified LIVE with vision. By design the checkbox **cannot** weaken the guard's floor (DoS never tickable; scope/destructive/DoS remain deny-wins; ticking only skips the confirmation).
The **2nd adversarial review** (focused on that invariant) confirmed that **the 6 invariants of the panel
HOLD** (DoS not tickable; Gate A intact — `decide()` never reads mode/auth; the checkbox creates the SAME
`Authorization` as `/gekko-auth`; `handleInput`/`clamp` without corruption or crash; no exfiltration or target data input) — and found **1 real but PRE-existing** bypass of the brute-force classifier: FIX-A
(shell-word boundary) lost the invocation by **path** (`/usr/bin/hydra`, `./hydra`, `/opt/hydra/hydra`), which the old CMD anchor DID cover → **regression of FIX-A**. Fixed as **FIX-A2** (`5e29ab8`: optional path prefix, without reintroducing the URL FP) with regression assertions; gate green. It reinforces the criterion:
each pass with a different lens finds something — the panel's pass exposed the regression of the guard's pass.

**Missing feature closed by feedback — lateral movement (F32, 2026-11-07).** A check of the original request against what was delivered found that one of the **5** techniques the operator listed was missing: **lateral movement (to permitted scopes)**. It had been reframed as "scope already covers it, no checkbox" **without consulting** — correct scope framing, but the requested deliverable is the checkbox.
Resolved without security theater: `lateral` is a **real confirmation gate** ("allowed but asked first", the operator's words), not a no-op — the scope (Gate A) still bounds it to the allowlist BEFORE this stage, so "to permitted scopes" is enforced by the scope, not by the checkbox. The 6-row panel was **re-verified LIVE after FIX-A2** (the earlier capture `policy.png` predated the fix):
ticking `[x] movimiento lateral` + `[x] AGRESIVO` → widget `modo AGGRESSIVE`, `q` persists
(`lat_panel.png`). Code `6a581d6`, gate green (5 new assertions). Lesson: a feature can be silently reframed out of scope; the control is to verify what was delivered against the **textual list** of the request, not against one's own summary.

**Reopen the panel if closed by mistake (F34, 2026-11-07).** The sidebar is a tmux pane; if
the operator closed it (kill-pane / exit), there was no way to recover it without restarting pi. Resolved
with `tools/gekko-sidebar.sh` — **idempotent** (re)opening (marks the pane with the tmux option
`@gekko_sidebar`; if a panel already exists, it does not duplicate) which does the split + resize hook + mouse. The
launcher `pi-hitl.sh` now **calls that same script** (DRY: a single source of the split) and cleans up by
the marker on exit. Inside pi the operator reopens with the command **`/gekko-sidebar`** (guard →
`execFileSync` of the script; `tmuxRO` stays read-only, the mutating operation lives in the shell script, not in the broker). Verified LIVE (private socket 160x40): open→render OK · kill pane→reopen recovers · running again does not duplicate. Gate green; syntax of both scripts OK.

**Panel rendering: text wrapping + real read-only (F35, 2026-11-08).** Two reports from the operator with a capture: (1) long lines were **cut with `…`** (`guard ON · broker+firewall (no
implica…`, `kb … bash/s…`) instead of wrapping; (2) if they selected the sidebar pane and typed,
it **echoed** (e.g. Alt+P → `^[p`) dirtying the panel — it was not truly read-only. Both
in `gekko-sidebar.mjs`: (1) a word-aware `wrap()` wraps each line to the pane width before drawing (splits words that do not fit; leaves intact those that do); (2) stdin in raw mode that
**swallows every key** without echo, with Ctrl+C handled by hand (`0x03` → cleanup, since in raw mode it does not arrive as SIGINT). tmux's prefix and mouse are intercepted by tmux before the pane, so moving focus/resizing/commands still work. Verified LIVE (30-col pane): wrapped text, **0 ellipses**;
typing Alt+P+letters → **0 contamination**; Ctrl+C closes the pane. `node -c` syntax OK.

**Screen dedup + metrics + vertical board (F36, 2026-11-08).** Five requests from the operator with captures, done during a live engagement: (1) `AGGRESSIVE` appeared in **3 places**
(sidebar, horizontal widget, status bar) — now the horizontal widget is **hidden while the sidebar is deployed**: `gekko-sidebar.mjs` writes a heartbeat (`panel.lines.alive`) on each
`draw()` and the guard hides the widget if its mtime is < 1.5 s (if there is no sidebar, the widget returns); the `GEKKO AGRESIVO` status bar remains as the minimal indicator. The widget also localizes the mode (`AGRESIVO`/`DEFAULT`, previously `AGGRESSIVE`). (2) `guard ON — broker + firewall (no implica contención
de red)` → **only `guard ON`** (`guardStatusLine` + `panelDetailLines`); the caveat lives in CLAUDE.md, it is not repeated in the UI. (3) The KB counter stayed at **0** because the agent reads the KB via `bash` (`cat kb/..`, `grep .. kb/`), never via the read tool — new `recordKbFromCommand()` parses the command string (leading verb per segment, skips sudo/env/timeout wrappers, attributes tokens under `kb/`); the disclaimer is now `subagentes NO instrumentados`. (4) **Turn counter** (`turno N`,
`runtime.turns`++ in `before_agent_start`, reset per session) in the widget and the sidebar, for metrics. (5) `auth vigentes` as a **vertical list** (`techniqueBoard`): one technique per row with tag
`permit`/`consult`/`block` derived from the same inputs as `admitChange` (it never promises an auto-OK that the broker would not give). Gate green (new assertions: turn, `guard ON`, KB-bash, board); render verified against the capture's scenario. Known limit: the KB-bash count only counts tokens that resolve to `kb/` from pi's cwd; a relative `cd engagements/.. && cat kb/x` does not resolve and is not counted (honest: if it cannot be attributed, it is not invented).

**UX pass + round counter + 4 new gates (F37, 2026-11-08).** Operator feedback during an engagement, in UX role. (1) **`turno` stuck at 1**: `before_agent_start` fires only once in autonomous runs (already noted in plan §); now the turn counts **agent rounds** (inflight 0→1 on `tool_execution_start`; parallel tools of the same generation = 1 turn). (2) **Panel redesign**: grouped (identity+state → scope → policy → metrics), without the redundant header `── GEKKO panel ──`, mode+guard on one line, technique board with **symbols** `✓auto/?ask/
✗no` instead of `→ permit`/`→ consult`; shorter lines. (3) **Blue color**: sidebar box `#4FA3FF` (`gekko-sidebar.mjs`) + **session-scoped** blue tmux theme in `pi-hitl.sh` (status-style + pane-border; saves/restores the previous one; opt-out `GEKKO_TMUX_THEME=0`) — the global `~/.tmux.conf` stays untouched. (4) **4 new gates** for aggressive mode: `persistence` (cron/services/tasks/run-keys),
`cred-dump` (secretsdump/DCSync/lsass/reg-save-SAM), `service-control` (stop/restart/disable/iisreset)
— the three auto-approvable with auth; and `log-cleanup` (wevtutil cl / rm-log / truncate) as
**always-confirm: NEVER auto** (evidence integrity, engagement-authz §4) — not tickable, the board shows it as `? (always)`. Command-position regex, not exhaustive (backstop = container), with anti-FP guards (reading a log / `crontab -l` / `systemctl status` do not classify). `/gekko-auth` accepts the 3 new auto-capable ones (not log-cleanup). Gate green (12 new classification/admission assertions + updated board/turn/layout); render verified. Known limit: log cleanup via a tool not listed (e.g. a manipulated `logrotate --force`) does not classify — the container remains the hard backstop.

**Operational pending items (operator decision, NOT code gaps):** (1) `git push` of the branch `spec/pi-control-panel` — not pushed without explicit request nor destination assumed (`origin` vs the Lite remote); (2) the key of the provider (the repo's default key expires → 401; use the valid provider key) for any live run against the Provider. Neither blocks the spec: they are deployment/credentials, not implementation.

**Crash fix on `/new` (F38, 2026-11-09).** `/new` replaces the pi session (`ctx.newSession()`),
leaving the captured `ctx` **stale**. The only consumer decoupled from that ctx is the live shell refresher (`setInterval` every 3 s, AC11): when it fired after `/new` it used a stale `lastCtx`
(`lastCtx.hasUI` / `render` → `ctx.ui.setWidget`) and, being an **uncaught throw inside `setInterval`**, it crashed the whole process ("This extension ctx is stale after session replacement or
reload"). The rest of the code uses the event's own `ctx` (always fresh), so the timer was the
only vulnerable path — and the only exception to the file's "best-effort, never break pi" doctrine.
Fix: the refresher body is wrapped in `try/catch`; on a stale-ctx throw **`lastCtx` is dropped**
and the next `session_start`/tool event repopulates it with a live ctx (self-healing). Integration glue (not pure logic): the selftest does not instantiate a stale `ExtensionContext`, so it is verified
with a green selftest + `/new` live. No changes in pure logic; gate green.

**F39 (2026-11-09) — self-expandable scope, inert checkbox, non-auditable panel.** Three gaps found while operating against a lab box:
1. **The model could expand its own scope.** `write`/`edit` are `LOCAL_TOOLS` (not scanned) and
   `scope.txt` was reloaded by mtime ⇒ write the file and carry on. The WRITE is not policed (by pattern it is a sieve: `>`, `sed -i`, `tee`, `open()`); the EFFECT is policed: the reload is one-directional (`scopeAdded`) — removing hosts applies by itself, ADDING asks the operator for confirmation and is refused in headless. The stage-3 message no longer invites the model to edit it.
2. **The ticked checkbox did not work.** `admitOne` required `isAttributable(hay)` and EVERY real command is compound (`&&`, heredoc, pipes; `scanInput` joins fields with `\n`) ⇒ AGGRESSIVE asked about everything even when the technique was pre-authorized (endless confirmation → fatigue → "Yes" without reading).
   Attribution exists to match the TARGET: a general authorization (`*`) already says "any target", so it does not need it; a per-IP one still requires it. Each class is gated separately.
3. **What was auto-approved left no trace.** Ticking a technique removes the question and, with it, the only evidence that the action ran. New append-only trace `.gekko-state/decisions.jsonl`
   (`GEKKO_AUDIT`): blocked / confirmed / auto-approved, with mode, tool, class and command **truncated and redacted** (`redactCommand` — an evidence index, not a secret store).
   And `alt+k` / `/gekko-kb` opens the KB detail: which `kb/` files were consulted (names, counts and time — never content); the panel counter became `kb [5] leídos · … · alt+k detalle`.

Criteria covered by the gate (`GEKKO_GUARD_SELFTEST=1`): 4 asserts of `scopeAdded`, 4 of
auto-approval with a compound command (ticked/unticked/auth by IP), 6 of the KB view and 6 of the
trace (incl. that the credential `-U user%pass` does not reach disk). Known limit: the KB overlay is keyboard-driven, not mouse — the tmux sidebar remains a read-only mirror.

## Note — spec 008 (2026-11-11)

Spec `008-tui-panel` removed the compact widget above the editor: `widgetLines()` and its three
assertions in `panel-layout-and-headless` were deleted. AC14 (80 columns, text-only state without color, visible turn) is now covered by the case `008-AC10: (spec 001 AC14 portado)` over `renderBar` in
`toolbox/gekko-panel-selftest.ts`; the headless part remains in AC04. The mentions of the "widget" in
this file are historical.
