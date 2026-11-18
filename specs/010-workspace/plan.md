# Technical plan 010 — Mandatory workspace at launch

> Status: `EJECUTADO` — the operator approved the spec and set implementing it as the goal (2026-11-14) without its own gate for
> this plan. Deviations when implementing: §8. Review before committing.
> Spec: [`spec.md`](spec.md) (`APROBADA`, 2026-11-14, Amendment 1)

## 1. Approach
A new module with no Pi dependencies, `toolbox/gekko-workspace.ts`, contains ALL the logic (validation, targets, scaffolding, menu, session arguments) as pure functions with injected I/O, plus a minimal CLI. `tools/pi-hitl.sh`
only invokes it and exports paths. `shell-session.ts` and the panel read two environment variables. No duplicated logic in bash.

## 2. Environment contract (what the Pi process sees)
| Variable | Value | Who sets it |
|---|---|---|
| `GEKKO_WORKSPACE` | workspace name, or `none` | operator (input) / launcher (always exports it) |
| `GEKKO_WORKSPACE_DIR` | absolute path `<repo>/engagements/<name>`; **absent** with `none` | launcher |
| `GEKKO_SCOPE` | `<dir>/scope.txt` (with `none`: today's value) | launcher |
| `GEKKO_FINDINGS` | `<dir>/findings.jsonl` (with `none`: today's value) | launcher |
| `PI_CODING_AGENT_SESSION_DIR` | `<dir>/.pi-sessions` (with `none`: `.gekko-state/pi-sessions`) | launcher |
| `GEKKO_WS_ROOT` | test seam: alternative root (by default, the repo's). The workspace is always `<root>/engagements/<name>` | tests |

## 3. Contract of `toolbox/gekko-workspace.ts`
No imports of Pi nor of typebox (imported by the selftest and `shell-session.ts`). It exports:
```ts
export const WS_NONE = "none";
export function validWorkspaceName(name: string): boolean;            // ^[A-Za-z0-9][A-Za-z0-9._-]{0,30}$, no "..", != "none"
export function workspaceDir(root: string, name: string): string;     // join(root, "engagements", name)
export function confined(root: string, name: string, realpath: (p: string) => string): boolean; // real path inside realpath(root/engagements)
export type Target = { ip: string; label?: string };                  // ip = IPv4 or CIDR as it was typed
export function parseTargets(input: string): { targets: Target[]; names: string[]; rejected: { token: string; reason: string }[] };
//   separators: space or comma. After an IP/CIDR, the next token that is NOT an IP is its label.
//   A non-IP token with no IP in front is a name to resolve (names). IP:port, IPv6, octet >255 or with a leading zero → rejected.
export function scopeLine(t: Target): string;                         // "10.0.0.1  # web" | "10.0.0.0/24"
export function scopeFileText(name: string, targets: Target[]): string;
export function scopeEntries(text: string): string[];                 // non-comment lines, without the trailing comment
export function replaceScopeText(oldText: string, targets: Target[], isoDate: string): string; // old entries → "# (reemplazado <fecha>) <line>"
export function scaffoldPlan(name: string, targets: Target[]): { path: string; content: string | null }[]; // relative paths; null = directory
export function newSessionArgs(name: string, wsDir: string | undefined): string[]; // without wsDir: EXACTLY today's args
export function cwdVerdict(wsDirReal: string | undefined, paneCurrentPath: string): { ok: boolean; note: string };
export function workspacePromptBlock(name: string | null, dir: string | null): string; // markdown block for the model
export type PickIo = { readLine(prompt: string): Promise<string | null>; write(s: string): void;
  list(): string[]; lastUsed(): string | null; liveShells(dir: string): number | null; readScope(name: string): string;
  create(name: string, targets: Target[]): void; replaceScope(name: string, targets: Target[]): void;
  resolve(host: string): Promise<string | null>; };
export async function pickFlow(io: PickIo): Promise<string | null>;   // the complete menu; null = aborted (EOF)
```
CLI (`node --no-warnings --experimental-strip-types toolbox/gekko-workspace.ts <cmd>`; messages to stderr, result to stdout):
- `pick` — interactive menu (reads stdin line by line, writes to stderr); prints the chosen NAME; exit 1 if aborted.
- `check <name>` — exit 0 and prints the absolute path if the name is valid, exists, has `scope.txt` and is confined; otherwise exit 1.
- `new <name> [target…]` — creates without asking (skill and tests); never overwrites; prints the path.
- `scope <name>` — prints the scope entries, one per line (banner).
- `prompt <name|none>` — prints `workspacePromptBlock`.
- `touch <name>` — records the last one used in `<root>/.gekko-state/last-workspace`.
Live shells: `tmux list-sessions -F '#{session_path}'` on the default server and on each socket of `GEKKO_TMUX_DIR`
(or `<tmpdir>/gekko-sockets`), 2 s cap, any error = no count.

## 4. Affected files and owner
| File | Change | AC | Owner |
|---|---|---|---|
| `toolbox/gekko-workspace.ts` (new) | module + CLI (§3) | AC1, AC5–AC11, AC18, AC22, AC24 | agent A (core) |
| `toolbox/gekko-workspace-selftest.ts` (new) | `runWorkspaceSelftest(counts, deps)` with `req("REQ-WS-…")` | idem | agent A; static launcher cases: agent C |
| `toolbox/gekko-panel.ts`, `toolbox/gekko-panel-selftest.ts` | `PanelExtras.workspace`, `PanelBar.workspace`, row + summary in SESSION, bar segment, `PanelIo.workspace()` | AC19–AC21 | agent B (panel) |
| `toolbox/gekko-guard.ts` | real `io.workspace()` (agent B). Before, orchestrator: `parseScopeLine` exported and wiring of the new selftest | AC8, AC19–AC21 | orchestrator + agent B |
| `tools/pi-hitl.sh` | selection, derivation, clean relaunch, banner, generated prompt | AC1–AC4, AC12–AC15, AC22 | agent C (launcher) |
| `tools/ws-test.sh` (new; `tools/tui-test.sh` is not touched) | process tests with a fake `pi`, tmux on its own sockets and a temporary `TMUX_TMPDIR` | AC1–AC6, AC9–AC15, AC22 | agent C |
| `docs/prompts/pi-hitl.md`, `docs/pi-hitl.md`, `tools/pi-hitl.env.example`, `setup.sh` (one usage line), `.claude/skills/engagement-init/SKILL.md` | base prompt without its own scaffolding; documentation; the skill calls `new` | AC22, closing | agent C |
| `toolbox/shell-session.ts`, `toolbox/tests/handler-harness.ts` | `-c`, real directory verification, closed FAIL | AC16, AC17 | agent D (shells) |
| `specs/SECURITY-GUARDRAILS-SPEC.md`, `.githooks/pre-commit` | REQ-WS-001…008, REQ-TUI-022/023; the two new files join the boundary list | all | orchestrator (before launching agents) |

## 5. Decisions
- **The menu runs BEFORE the relaunch in tmux** (in the operator's terminal). The relaunch passes the explicit name and starts tmux with `env -u GEKKO_WORKSPACE -u GEKKO_WORKSPACE_DIR`, so that the server does not capture a value that another window would later inherit (cause of the "old workspace" gap, AC13).
- **The derived paths are recomputed inside** from the name: whatever the environment carries for `GEKKO_SCOPE` /
  `GEKKO_FINDINGS` is overwritten and, if it was different, the banner warns about it (AC14).
- **Interactive = `[ -t 0 ] && [ -t 2 ]`**; otherwise `GEKKO_WORKSPACE` is required (AC2).
- **Generated prompt:** `.gekko-state/pi-hitl.prompt.md` = `docs/prompts/pi-hitl.md` + block from `prompt <ws>`; it is what is passed
  to `--append-system-prompt`. The base stops telling it to create `engagements/<codename>/`.
- **Subagents (AC24):** they run in the same process (pi-subagents 0.23.2), so they inherit the environment and the sessions directory.
  The prompt block names `$GEKKO_WORKSPACE_DIR` and orders the path to be passed when delegating. `.pi/agents/*.md` are not touched.
- **Shells (AC16/17):** prior check (exists, is a directory, can be entered) → FAIL without creating; after creating, `#{pane_current_path}` is compared with the real path and, if it differs, the session is killed and FAIL.
- **Panel:** the name (≤31, sanitized) goes first in the SESSION summary (visible when folded) and as a row; in the bar only
  when there is no rail, with priority right after guard and mode.
- **A single source of the scaffolding:** `scaffoldPlan`; the `engagement-init` skill now invokes `new`.
- **`none`:** everything as today (root `scope.txt` included).
- **REQ:** WS-001 name/confinement · WS-002 targets · WS-003 scaffolding does not overwrite · WS-004 scope replacement ·
  WS-005 menu · WS-006 shell in the workspace · WS-007 launcher contract (static cases, written by the orchestrator when integrating; the real behavior in
  `tools/ws-test.sh`) · WS-008 prompt block · TUI-022 rail · TUI-023 bar.

## 6. Risks and mitigation
- **`main` has uncommitted changes** in `docs/pi-hitl.md`, `setup.sh`, `AGENTS.md`, `CLAUDE.md`, `.pi/agents/*`: this worktree branches from `HEAD`, so a manual merge will be needed. Mitigation: in those files, minimal and localized edits.
- **A `.bashrc` that does `cd`** would make every `session_new` with a workspace fail (AC16 requires it that way). It is documented.
- **Pi's resume selector** may list sessions from other folders: not verified.
- **Live test:** target authorized by the operator (a lab web application; host and port in the local evidence). The guard
  does not understand ports: the scope carries the IP and the test is limited to that port.

## 7. Order of attack
1. Orchestrator: REQs in the living spec + boundary list; `parseScopeLine` and selftest wiring in `gekko-guard.ts`.
2. In parallel: agent A (core) and agent B (panel) — they do not share files.
3. Agent C (launcher) and agent D (shells) start in parallel against the contract of §3 and wait for A's module to test.
4. Orchestrator: full gate, `tui-test.sh`, harness, and live test against the authorized target.

## 8. Deviations when implementing (2026-11-14)
- **State files per workspace:** `.gekko-state/pi-hitl.prompt.<ws>.md`, `banner.<ws>.ans` and, with a workspace,
  `panel.<ws>.json`. With a shared one, simultaneous launches of different engagements overwrote each other's prompt.
- **`session_new` reads `GEKKO_WORKSPACE_DIR` on entry**, before the first wait, and checks the directory before the collision check.
- **`PickIo.liveShells` receives the name**, not the path; the real `io` translates it.
- **Process tests in `tools/ws-test.sh`** (its own file) and three reusable stress tests:
  `toolbox/tests/ws-stress-pure.mjs`, `toolbox/tests/ws-stress-shells.ts`, `tools/ws-stress.sh`.
- **Outside the original scope, by reverse reconciliation:** `sendKeysText` (REQ-TMUX-010) and the retry in two old cases of the harness. Detail in `tasks.md`.
- The four pieces were written in parallel by four Sonnet agents; C and D started against the contract of §3 without
  waiting for A.
