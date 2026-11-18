# Technical plan 013 — One launcher, shells on the OS or in the toolbox

> Status: `APROBADO` (operator, 2026-11-15: variant B, 013 implements the mechanism, minimal mounts).
> Spec: [`spec.md`](spec.md) (`APROBADA`, 2026-11-15, Amendment 1) · Branch `report-module`

## 1. Approach
Pi, the guard, the ledger, the reports module and the `bash` tool always stay on the host. The mode only decides where the tmux server of the model's shells lives: on the host (OS) or **inside** the workspace's container (toolbox). There is a single seam: the function that invokes tmux, which in toolbox mode prepends `docker exec <container>`. Everything else in `session_*` —shell identity, directory verification, verified closing, panel refresh— stays the same, now against the container's tmux. The logic goes in `toolbox/gekko-workspace.ts` (pure functions + CLI), as in 010; `pi-hitl.sh` only calls and exports.

## 2. Contracts

**Environment**
| Variable | Value | Who sets it |
|---|---|---|
| `GEKKO_EXEC` | `os` or `toolbox` | launcher (always; with `none`, `os`) |
| `GEKKO_TOOLBOX` | container name; **absent** in OS mode | launcher |
| `GEKKO_OVPN` | path of an `.ovpn` mounted when creating the container (optional) | operator |
| `GEKKO_TOOLBOX_IMAGE` | image; default `gekko-toolbox:latest` | operator / tests |

**Workspace:** file `engagements/<ws>/exec` with one word, `os` or `toolbox`. No file = `os`. Other
content = error (AC5).

**`toolbox/gekko-workspace.ts`**
```ts
export type ExecMode = "os" | "toolbox";
export function parseExecMode(text: string | null): ExecMode | null;   // null (no file) → "os"; invalid text → null
export function toolboxName(ws: string): string;                       // "gekko-tb-" + ws
export function toolboxRunArgs(o: { name: string; image: string; root: string; wsDir: string; ovpn?: string }): string[];
export function toolboxPlan(state: "absent" | "stopped" | "running", mountsOk: boolean): "run" | "start" | "reuse" | "refuse";
export function tmuxCommand(mode: ExecMode, container: string | undefined, args: string[]): { file: string; args: string[] };
export function ledgerCliOnly(command: string, root: string): boolean; // is it only an invocation of findings.py? (Amendment 2)
// `toolboxBashBlock` (the AC8 block) lives in gekko-guard.ts: it uses the broker's host extractor and `ledgerCliOnly`.
export function workspacePromptBlock(name: string | null, dir: string | null, mode: ExecMode): string;
```
New CLI: `mode <ws>` (prints the mode; exits 1 if invalid) · `new <ws> [--exec os|toolbox] [target…]` ·
`toolbox <ws>` (leaves the container up and prints its name; exits 1 with the reason). `pick` asks for the mode when creating.

**Container** (one per workspace, `gekko-tb-<ws>`)
```
docker run -d --init --name gekko-tb-<ws> --cap-add=NET_ADMIN --device=/dev/net/tun \
  -v <wsDir>:<wsDir> -v <root>/.claude/tools:<root>/.claude/tools:ro \
  [-v <ovpn>:/vpn/target.ovpn:ro] -w <wsDir> gekko-toolbox:latest sleep infinity
```
When toolbox is chosen the launcher applies a default ACL to the workspace for the operator's user
(`setfacl -m d:u:<uid>:rwx,u:<uid>:rwx <wsDir>`).

## 3. Affected files
| File | Change | AC |
|---|---|---|
| `tools/gekko-toolbox.sh` | delete | AC1 |
| `toolbox/gekko-workspace.ts` | mode, question on creation, container name and arguments, `tmuxCommand`, `toolboxBashBlock`, prompt block, CLI | AC2–AC10 |
| `tools/pi-hitl.sh` | read the mode, leave the container up, export, banner line; remove the mention of `gekko-hitl.sh` | AC2–AC7, AC10, AC11, AC13 |
| `toolbox/shell-session.ts` | `tmux()` goes through `tmuxCommand`; the `session_new` note says how to attach | AC9 |
| `toolbox/gekko-guard.ts` | shell refresh goes through `tmuxCommand`; `bash` block in toolbox mode; "single launcher" case | AC1, AC8, AC12 |
| `toolbox/gekko-workspace-selftest.ts` | S cases of the pure parts and launcher contract | AC2–AC10, AC12 |
| `tools/ws-test.sh` | a fake `docker` on the PATH + P cases | AC2–AC7, AC10, AC11, AC13 |
| `toolbox/tests/handler-harness.ts` | real `session_new`/`session_kill` against a container's tmux | AC9 |
| `tools/toolbox-test.sh` (new) | D cases with real docker; skipped with a warning if missing | AC7, AC9, AC14–AC16 |
| `docs/prompts/pi-hitl.md`, `docs/pi-hitl.md`, `kb/tools/gekko-toolbox.md`, `CLAUDE.md`, `AGENTS.md`, `PORTING.md` | one launcher, two modes | AC6, AC17 |
| `specs/SECURITY-GUARDRAILS-SPEC.md`, `.githooks/pre-commit` | `REQ-PNL-005` replaced, new requirements, boundary list | AC1, AC17 |
| `setup.sh` | detect `docker` and `setfacl` and warn: they are only needed for toolbox mode | — |

## 4. Decisions (with what was measured on 2026-11-15, disposable container and tmux)
- **The shells' tmux runs inside the container, not on the host.** Measured: with tmux on the host and
  `docker exec -it` in the pane, when the session is closed the container's `bash` stays alive; with tmux inside, the shell is born in the requested directory, tmux reports its real path and on closing no process remains.
- **`--init` in the container.** Without it, the processes of a closed shell remain as zombies.
- **Minimal mounts, not the whole repo** (Amendment 1 of the spec, approved). Only the workspace (writable) and
  `.claude/tools/` (read, so that `findings.py` can be called from a shell), at the same paths as
  on the host. The KB is not mounted: the model reads it from the host; the toolbox is only for running. The container does not
  see the credentials in `.gekko-state/`, nor other workspaces, nor can it change the code the operator runs. Measured: `.claude/tools` is read-only and `findings.py` records to the ledger from inside.
- **Registering a finding names the target, and AC8 blocks every `bash` that names a host from the scope.** As written, in toolbox mode `findings.py add --target <IP>` from `bash` would be blocked, also for the subagents that register and verify findings. **Amendment 2 of the spec (approved):** AC8 does not block a `bash`
  that is exactly an invocation of the ledger CLI (`.claude/tools/findings.py add|set|list|render …`, without
  `;`, `&`, `|`, `$`, backticks, redirections or line breaks). The text part is a pure function,
  `ledgerCliOnly`, in `gekko-workspace.ts`; the block (`toolboxBashBlock`) lives in `gekko-guard.ts`,
  next to the host extractor the broker already uses, so as not to duplicate it.
- **Default ACL on the workspace.** The container writes as root. Measured without ACL: the operator cannot delete what root creates inside a root directory. With the ACL: reads, adds, creates alongside and deletes. Measured limit: a file the container leaves at mode 600 cannot be read from the host (it can be deleted).
- **The shared ledger works as it is.** Measured: alternating host/container additions and 10 + 10 simultaneous leave the 23 rows with 23 ids (the lock from 012 holds between the two sides).
- **Own container network**, with `NET_ADMIN` and `/dev/net/tun`: it is the "restricted VPN" mode of `CLAUDE.md`.
  The `.ovpn` is mounted only if `GEKKO_OVPN` is given when creating the container; the VPN is raised from a shell,
  as today. The content of the `.ovpn` is never stored.
- **The container stays up on exiting Pi** (AC11): the shells stay alive. It is turned off with
  `docker rm -f gekko-tb-<ws>`; the launcher says so on exit.
- **A container with that name and other mounts is not adopted**: the launcher exits with an error (AC10).
- **AC8 blocks only the `bash` tool**, and only when it names an entry of `scope.txt`; the local interfaces that the guard always admits do not count (the model must be able to ask for `127.0.0.1`).
- **How the operator attaches to a shell:** `docker exec -it gekko-tb-<ws> tmux attach -t <name>`. The
  `session_new` note and the prompt say so.
- **Tests:** P with a fake `docker` that records how it is called (no real docker); D with real docker and the
  image, which is skipped with a warning and does not count as green.
- **The `event.input` / `spawnHook` route** is no longer used (decision 4 of the spec).

## 5. Risks and mitigation
- Spec 011's shell mirror (in progress on `main` by another session) assumes tmux on the host → coordinate before `tasks.md`; if it does not arrive in time, in toolbox mode the mirror is left out and that is said.
- `main` has uncommitted changes on `pi-hitl.sh`, `ws-test.sh`, the workspace selftest and the living spec
  → the changes of this spec go in new, short blocks; a manual merge will be needed.
- The filesystem does not support ACL or `setfacl` is missing → the launcher says so when toolbox is chosen and does not start in that mode.
- The user cannot use docker → same path as AC10.
- The guard's shell refresh is blocking and now goes through `docker exec` → measured 0.06 s per call;
  it keeps its 3 s cap.
- Container restart: its shells die → the record already marks them closed (REQ-TMUX-003/005).
- The model attacks by host name from `bash` → AC8 does not see it (limit of the spec: the guard recognizes IPv4).
- The image lacks `tmux` or `python3` in another version → measured in `gekko-toolbox:latest`: tmux 3.7c and python3.

## 6. Order of attack
1. Falsifiers already run (decisions of §4). One is missing: the real `session_*` handlers with the prefix.
2. `gekko-workspace.ts`: the pure parts, the CLI and their S cases.
3. `shell-session.ts`, the guard's refresh and the AC8 block, with S and H.
4. Launcher and P cases with the fake `docker`.
5. D cases with real docker.
6. Delete `gekko-toolbox.sh`, replace `REQ-PNL-005`, docs and `setup.sh`.
7. Full regression and a real run by the operator in each mode, with the reports module open.

The code is written by a Sonnet 5.5 agent per group, as in 012.
