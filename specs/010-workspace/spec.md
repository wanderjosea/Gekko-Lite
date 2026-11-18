# Spec 010 — Mandatory workspace at launch (one engagement = one directory that derives everything)

> Status: `IMPLEMENTADA` (2026-11-14) · approved by the operator on 2026-11-14 · Amendment 1 (operator, 2026-11-14): Pi's subagents inherit the workspace (AC24)
> Date: 2026-11-14 · Design source: comparison with Pentest Copilot (workspaces) + review of the former 010 (today [`011-espejo-shells`](../011-espejo-shells/spec.md) §8)

## 1. Problem (one sentence)
`tools/pi-hitl.sh` starts without an engagement: the scope comes by default from the root `scope.txt` (`:90`), the findings only exist if someone exports `GEKKO_FINDINGS`, Pi's sessions go to a global directory (`:84`),
the shells are born in the repo root (`:135`) and the `engagements/<codename>/` scaffolding is created by the model (`docs/prompts/pi-hitl.md:15-28`); nothing forces those pieces to belong to the same engagement.

## 2. Goal (one sentence)
Every start of `pi-hitl.sh` runs with exactly one workspace chosen by the operator — an
`engagements/<codename>/` — and the scope, the findings, Pi's sessions and the shells' directory all come from it;
the operator always sees it in the panel.

## 3. Context / why now
Pentest Copilot requires a workspace to be set and opens its shells there. Gekko already has the directory
(`engagement-init` creates `scope.txt`, `notes.md`, `AUTHORIZATION.md`, `loot/`), but the launcher does not read it: one can run with the scope of one engagement and the findings of another, which is exactly what `engagement-authorization.md` §2
prohibits for clients. An optional variable is not enough (review of 2026-11-14, all tested in disposable tmux):
- With a tmux server already alive, the session that `pi-hitl.sh` creates inherits the environment **of the server**: it sees the old value.
  The agent's shells keep that server alive between engagements.
- `tmux new-session -c <dir>` with the directory deleted or without permission starts in `$HOME` without an error.
- `loadScope` (`toolbox/gekko-guard.ts:95`) only counts IPv4 and CIDR; it ignores host names and `IP:port`.
- The firewall treats what lives under `engagements/` as untrusted (`touchesLoot`, `gekko-guard.ts:251`).
- `redactSummary` masks runs of 32+ characters: a long path in the panel comes out as `/[REDACTED]`.

## 4. Scope
**Inside:**
- At startup, the launcher asks for the workspace: it lists the existing ones, offers the last one used with Enter, or "new".
- "New" asks for a name and targets (zero or more), creates the standard scaffolding and never overwrites an existing file.
- Targets: IPv4 or CIDR; `IP name` keeps the name as a comment; a bare name is resolved only once and the IP is written only if the operator confirms.
- On entering an existing one, it shows its scope and lets the operator keep it or replace it before starting (a lab box can change its IP on each spawn).
- From the workspace come: scope, findings, Pi's sessions and the `session_new` shells' directory.
- Without an interactive terminal: `GEKKO_WORKSPACE=<name>`; `GEKKO_WORKSPACE=none` is the explicit escape (generic work).
- The panel always shows the workspace: rail (card open or folded) and status bar.
- The model's prompt names the real workspace and stops asking it to create one.
- The menu indicates how many live tmux shells were born in each workspace (an "active" signal, best effort).

**Outside (explicit, anti scope-creep):**
- A separate "sessions" level of its own: Pi's sessions are used, stored inside the workspace.
- Scope by host name in the guard (follows the limit GAP-12).
- The other launchers: `tools/gekko-toolbox.sh` and the autonomous experiment runner (not included in Lite).
- Requiring a filled `AUTHORIZATION.md` or the testing window (it is created, not verified).
- Switching workspace without restarting Pi.
- Moving the working directory of Pi or of the `bash` tool: they stay in the repo root (the `.pi/agents/` roster depends on that).
- Retiring the root `scope.txt`: it stays for `none`.
- The shell mirror: spec 011.

## 5. Acceptance criteria (testable)
> Tests: **S** = selftest (`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`, pure logic,
> with the marker `req("REQ-…")`). **P** = process test (`bash tools/ws-test.sh`, new: real launcher with a fake `pi` on the PATH that dumps environment, arguments and directory; tmux on dedicated sockets). **H** = `toolbox/tests/handler-harness.ts` (real `session_*` handlers against real tmux).

| # | Criterion (observable) | Test |
|---|---|---|
| **Selection** | | |
| AC1 | WHEN I start with a terminal and without `GEKKO_WORKSPACE`, THEN the menu appears and Pi does not start until I choose; Enter without typing chooses the last one used. | P |
| AC2 | WHEN there is no interactive terminal and `GEKKO_WORKSPACE` is not defined, THEN the launcher exits with a code ≠ 0, the message names the variable and Pi does not start. | P |
| AC3 | WHEN `GEKKO_WORKSPACE=<name>` names an existing workspace, THEN it starts with it without a menu; WHEN the name does not exist or is invalid, THEN an error and Pi does not start (it is not created silently). | P |
| AC4 | WHEN `GEKKO_WORKSPACE=none`, THEN it starts without a workspace with today's variables and default values, without any derivation. | P |
| AC5 | WHEN the last workspace used no longer exists, THEN it is not offered by default; WHEN it exists, THEN it is remembered between starts. | P |
| AC6 | The menu lists only the directories of `engagements/` that have `scope.txt` and shows how many live tmux shells were born in each; WHEN tmux does not respond, THEN the menu works the same, without the count. | P |
| **Creation** | | |
| AC7 | A name is valid only if it meets `[A-Za-z0-9][A-Za-z0-9._-]{0,30}`, does not contain `..` and is not `none`; the resolved workspace (real path) always stays inside `<repo>/engagements/`, and a symbolic link that leaves there is rejected. | S |
| AC8 | IPv4 and CIDR are accepted as targets; `IP name` keeps the name as a comment; `IP:port`, IPv6 and any other form are rejected with a message. Every non-comment line the launcher writes into `scope.txt` is an entry that `loadScope` counts. | S |
| AC9 | WHEN the operator gives only a host name, THEN the launcher resolves it once, shows the IP and writes it only if the operator confirms; without confirmation `scope.txt` does not change. | P |
| AC10 | "New" leaves `scope.txt`, `notes.md`, `AUTHORIZATION.md`, `loot/creds.md`, `scripts/` and `canaries/`; WHEN the directory already had any of those files, THEN it stays byte for byte the same (sha256 before = after). | P |
| AC11 | WHEN I enter an existing workspace, THEN I see its scope entries and can keep or replace them; on replacing, the previous ones remain in `scope.txt` as a dated comment and no other file changes. | P |
| **Derivation** | | |
| AC12 | With workspace X, Pi receives: scope = `X/scope.txt`, findings = `X/findings.jsonl`, sessions under X (not in `.gekko-state/pi-sessions`), `GEKKO_WORKSPACE` = name and `GEKKO_WORKSPACE_DIR` = path of X. | P |
| AC13 | WHEN a tmux server already exists whose environment carries another workspace, scope or findings, THEN Pi sees those of the chosen workspace in this start. | P |
| AC14 | WHEN there is a workspace and the environment carries a `GEKKO_SCOPE` or `GEKKO_FINDINGS` pointing elsewhere, THEN the workspace wins and the banner warns about it in one line. | P |
| AC15 | The startup banner shows the workspace name and the loaded scope entries (the first 6 and "+N más" (Spanish UI text, "+N more"), not just the count. | P |
| **Shells** | | |
| AC16 | With workspace X, a shell created with `session_new` starts in X: the directory tmux reports for it after creating it is X. | H |
| AC17 | WHEN X no longer exists or it cannot be entered when creating the shell, THEN `session_new` returns FAIL and no live session remains (today tmux would fall back to `$HOME` silently). | H |
| AC18 | With `none`, the arguments with which the tmux session is created are identical to today's. | S |
| **Panel** | | |
| AC19 | With a workspace, its name is seen in the rail with the card open **and** folded, without redacting even if it measures 31 characters. | S |
| AC20 | WHEN the rail is not drawn, THEN the status bar includes the workspace, and at 80 columns with realistic values it is not discarded. | S |
| AC21 | With `none`, rail and bar say "sin workspace" (Spanish UI text, "no workspace"); it is never left empty. | S |
| **Prompt** | | |
| AC22 | The prompt the model receives names the real path of the workspace, says that the shells start there and that `bash` runs in the repo root, and no longer asks it to create `engagements/<codename>/`; with `none` it names none. | P |
| **Subagents** | | |
| AC24 | WHEN the parent delegates to a Pi subagent, THEN the subagent works in the same workspace: its commands receive `GEKKO_WORKSPACE` and `GEKKO_WORKSPACE_DIR` with the parent's values, and the workspace block of the prompt tells the parent to pass the path when delegating. | S (prompt block) + P `--live` (a real subagent prints the variable) |
| **Regression** | | |
| AC23 | The full gate, `tools/tui-test.sh` (rail, spec 008) and `tools/ws-test.sh` are green; no existing REQ loses its cases. | S + P |

## 6. Risks / open decisions
- **`none` keeps today's behavior**, including the root `scope.txt`: the inconsistent path still exists, but
  it must be requested. A stricter alternative: `none` runs without targets (the guard blocks every IP). The operator decides.
- **Which file governs the scope changes** (from the root one to the workspace one). It does not loosen the broker — same rule, different
  file — but it is the most sensitive piece of the spec: it carries its own REQ and the banner shows what was loaded (AC15).
- **Previous limit not fixed here:** with `none`, an old `GEKKO_SCOPE` inherited from the tmux server can still slip in (same cause as AC13). It is documented.
- **Pi's sessions inside the workspace:** Pi supports the variable; **I did not verify** that its resume selector lists only those in that folder.
- **Existing names:** I did not list `engagements/`. A directory whose name does not meet AC7 will not appear in the menu;
  it must be reviewed when implementing.
- **31 characters** cap from `redactSummary`: redaction is avoided by construction instead of making an exception for the row.
- **Resolving a name** queries the system DNS: in a real client, the name goes out to the configured resolver.
- **Two working directories:** `bash` in the root and shells in the workspace. They are not unified; the prompt says so (AC22).
- **A single source of the scaffolding:** today it is copied in the `engagement-init` skill and in the prompt. `plan.md` decides how
  to avoid a third copy.
- **Where the menu runs** with respect to the relaunch inside tmux: `plan.md`.
- **Pi subagents (AC24):** `@tintinweb/pi-subagents` 0.23.2 runs them **inside the same process** of Pi (`agent-runner.js:1031`, `createAgentSession`; no child process), so they share `process.env` and the sessions directory (`agent-runner.js:984`). Inheriting the environment is by construction; inheriting the prompt depends on each adapter's `prompt_mode: append`, which is why the workspace block also orders the path to be passed when delegating. `.pi/agents/*.md` are not touched (they have uncommitted changes on `main`).
- **`none` and the root `scope.txt` (clarified with the operator):** with `none` that file still applies, as today.
- **Trust boundary:** it touches `tools/pi-hitl.sh`, `toolbox/shell-session.ts`, `toolbox/gekko-guard.ts`,
  `toolbox/gekko-panel.ts` and `setup.sh` (final usage text). New REQs in the living spec together with the first tests.

## 7. "Done" signals
- AC1–AC24 green at the same time; `tasks.md` complete with its verification log.
- New REQs reconciled in `SECURITY-GUARDRAILS-SPEC.md`; `docs/pi-hitl.md`, `tools/pi-hitl.env.example` and the
  `engagement-init` skill up to date; `Estado:` → `IMPLEMENTADA`.
