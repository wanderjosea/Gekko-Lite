# Spec 013 — One launcher: `pi-hitl.sh`, with the model's shells on the OS or in the toolbox depending on the workspace

> Status: `IMPLEMENTADA` (2026-11-16: T1–T18 closed, operator's real run T17 green; spec 014 runs on top) · `APROBADA` (operator, 2026-11-15: "I approve the spec"; the toolbox-mode variant, confirmed separately: decision 4 of §8).
> Date: 2026-11-15 · Design source: operator requests of 2026-11-15 (§8) · Branch `report-module` (formerly `report-module`)

## 1. Problem (one sentence)
There are two launchers and only one provides workspace, findings and the reports module: with `tools/gekko-toolbox.sh` Pi runs
inside the container, without a workspace, without the repo mounted and without a ledger on the host; and with `tools/pi-hitl.sh` using the
toolbox is an improvisation by the model (`make vpn` inside a shell), which nothing records or guarantees.

## 2. Goal (one sentence)
A single launcher remains, `tools/pi-hitl.sh`; when creating a workspace the operator chooses whether the model's shells are born on the
OS itself or in the toolbox, and in both modes the workspace, the guard, the findings and the reports module behave the same.

## 3. Context / why now
Read in the code (branch `report-module`, `eac0dde`):
- `tools/gekko-hitl.sh` no longer exists; two mentions remain (`docs/pi-hitl.md:266`, `tools/pi-hitl.sh:96`).
- `tools/gekko-toolbox.sh` runs `pi` with `docker exec` inside a container created by hand, without the repo `-v`, with the scope at `/opt/gekko/scope.txt`: it does not go through the workspace (spec 010) nor through the reports module (spec 012).
- `REQ-PNL-005` of the living spec requires that both launchers exist.
- `toolbox/Makefile` mounts the repo at `/work` (`make shell`, `make vpn`): that is why today, with `pi-hitl.sh` on the host,
  what the model writes from the toolbox appears in the workspace and the reports module shows it. The path
  changes: `/work/…` inside, the repo's one outside.
- `docs/prompts/pi-hitl.md` tells the model that it runs "natively on this Kali host" and names the toolbox as an
  option; no file says which of the two is used by a workspace.
- Pi 1.4.0 (types read, not executed): a `tool_call` handler can change `event.input`, and the `bash` tool supports a `spawnHook` that adjusts command, directory and environment before executing.
- The autonomous experiment runner (not included in Lite) also runs Pi inside its own container.
- The toolbox container runs as root: what it writes in the mounted repo is owned by root.

## 4. Scope
**Inside:**
- Delete `tools/gekko-toolbox.sh` and the mentions of `gekko-hitl.sh`. `pi-hitl.sh` is the only launcher.
- When creating a workspace from the menu, the launcher asks where commands run: **OS** or **toolbox**.
  The choice is saved in the workspace. A workspace that does not have it starts on OS.
- The mode is shown in the banner and the model's prompt says it.
- Toolbox mode: the launcher leaves up the container of that workspace, with the workspace mounted at the same path
  as on the host (Amendment 1: not the whole repo), and the `session_new` shells are born inside. The `bash` tool and the model's read tools stay on
  the OS, so that it reads the repo and the KB; the guard blocks in this mode every `bash` that names a host from the scope and
  tells it to use a shell (decision 4, §8).
- OS mode: everything as today.
- In both modes the guard decides on the command the model wrote.
- Reports parity: a finding registered in either mode is seen the same way in the module.
- Living spec (`REQ-PNL-005` and the new items), `docs/pi-hitl.md` §5 and the model's prompt.

**Outside (explicit, anti scope-creep):**
- The panel button to choose or change the mode: another spec (operator's decision), spec 014, today in draft in the main checkout.
- Changing mode with Pi open.
- The autonomous experiment runner (not included in Lite) and the image with Pi inside (`gekko-toolbox-pi`): they stay for autonomous experiments.
- Turning `scope.txt` into an output list of the container (still pending, as `docs/pi-hitl.md` §5 says).
- Detonating untrusted samples: that still goes to a disposable container without mounts (`scope.md`), not to this one.
- Building the image: it is still `make -C toolbox build`.

## 5. Acceptance criteria (testable)
> Tests: **S** = gate (`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`). **P** =
> `bash tools/ws-test.sh` (real launcher, fake `pi` and, new, a fake `docker` on the PATH that records how it is called). **H** = `toolbox/tests/handler-harness.ts` (real `session_*` handlers). **D** = new case with
> real docker and the image `gekko-toolbox:latest`; if they are missing, it is skipped with a warning and does not count as green.

| # | Criterion (observable) | Test |
|---|---|---|
| **One launcher** | | |
| AC1 | `tools/gekko-toolbox.sh` does not exist and no file in the repo names it as a way to launch; nor does any mention of `gekko-hitl.sh` remain. The gate checks one launcher, which references the guard once. | S |
| **Mode choice** | | |
| AC2 | WHEN I create a workspace from the menu, THEN before starting Pi the launcher asks whether the model's shells are born on the OS or in the toolbox; Enter without typing chooses OS. | P |
| AC3 | The choice is saved in the workspace: the following starts use it without asking again. | P |
| AC4 | WHEN the workspace has no saved choice (the older ones, or one created without the menu), THEN it starts on OS. | P |
| AC5 | WHEN the saved value is neither OS nor toolbox, THEN the launcher exits with an error, says so and Pi does not start. | P |
| AC6 | The banner shows the workspace's mode and the model's prompt says where its shells are born; in toolbox mode it also says that `bash` runs on the OS, serves the repo and the KB, and that whatever goes against the target goes through a shell. | P |
| **Toolbox mode** | | |
| AC7 | (Amendment 1) WHEN I start a workspace in toolbox mode, THEN its container is up before Pi and sees, at the same absolute paths as the host, only the workspace directory (writable) and `.claude/tools/` (read-only): not the rest of the repo, nor `.gekko-state/`, nor other workspaces. If it was already up it is reused: another one is not created. | P · D |
| AC8 | In toolbox mode the model's `bash` tool keeps running on the OS and reads the repo and the KB as in OS mode; WHEN that `bash` names a host from the scope, THEN the guard blocks it before executing and the reason tells it to use a `session_new` shell. (Amendment 2) Exception: a `bash` that is exactly an invocation of the ledger CLI (`.claude/tools/findings.py add|set|list|render …`) without chaining anything is not blocked; any command that adds `;`, `&`, `|`, `$`, backticks, redirections or a line break is not the exception. In OS mode that same command is decided as today. | S |
| AC9 | A `session_new` shell is born inside the container, in the workspace directory; if it cannot, it returns FAIL and no live shell remains. | H · D |
| AC10 | WHEN I choose toolbox and docker, the image or the permission to use it is missing, THEN the launcher says so and Pi does not start: it never runs the commands on the OS on its own. | P |
| AC11 | WHEN Pi ends, THEN the container stays up (the workspace's shells stay alive) and the launcher says how to turn it off. | P |
| **What does not change between modes** | | |
| AC12 | The guard decides on the command the model wrote, not on the wrapped one: a command outside scope, a DoS one and a destructive one are blocked the same in both modes, and a command that names the container does not avoid the decision. | S |
| AC13 | In OS mode the launcher does not invoke docker and the commands run as today. | P |
| AC14 | Pi's file tools and `findings.py` see the same paths in both modes: an artifact written from a toolbox shell exists on the host at the path the model used. | D |
| **Reports** | | |
| AC15 | A finding registered from a toolbox shell and another registered in OS mode appear in the reports module with the same fields. | D |
| AC16 | After an addition made from the container, the ledger still accepts additions from the host, and vice versa; 10 additions from each side at once leave 20 rows. | D |
| **Docs and living spec** | | |
| AC17 | `docs/pi-hitl.md` describes one launcher and two modes; the living spec replaces `REQ-PNL-005` and gains the requirements of this spec, each with its case. | S |

## 6. Risks / open decisions
**For `plan.md`:**
- How a shell is born inside the container (`session_new` over `docker exec`) and how it is verified that it landed in the workspace directory. The `event.input` / `spawnHook` route for taking `bash` into the container is no longer needed (decision 4, §8).
- How the guard knows the current mode to apply the block of AC8, and its limit: it recognizes hosts by pattern, like the rest of the broker; a target that the guard does not recognize as a host slips through.
- Where the choice is stored inside the workspace and how the container is named.
- The VPN: today `make vpn` raises it by hand inside a shell. Options: keep it that way, or have the launcher ask for the `.ovpn` path in toolbox mode and mount it at startup (its content is never stored).
- Container network: its own (restricted VPN) or the host's (full VPN). It affects what it reaches and what it exposes.
- File owner: the container writes as root in the workspace. AC16 must be measured before designing.
- `main` has uncommitted changes from another session on `pi-hitl.sh`, `ws-test.sh` and the living spec.

**Limits this spec accepts:**
- Toolbox mode is not containment: the workspace is mounted writable, the container runs as root with
  `NET_ADMIN` and the guard is still a pattern filter. Real containment is still the container without mounts plus the egress list, which does not exist yet.
- AC9 and AC14–AC16 depend on real docker: on a machine without docker they remain untested.
- A workspace created in one mode is not converted to the other from the launcher; the saved value is edited by hand.

## 7. "Done" signals
The gate, `bash tools/ws-test.sh`, the handler harness and the real-docker case green at the same time + the `tasks.md` checklist
with its record. In addition, a real run by the operator in each mode with the reports module open.

## 8. Operator decisions (2026-11-15)
1. "Generate a plan so that the reports module works just as it does today using the toolbox, but
   using the host itself. Removing gekko-hitl once and for all and leaving only pi-hitl. Both
   will work the same."
2. The panel button to indicate OS or toolbox: "don't do this, it will go in another spec".
3. "When we launch pi-hitl, if the workspace is new, the user should already be asked whether they want to use the toolbox or
   the own OS to run the commands […] because we won't always want to use the toolbox."

4. In toolbox mode only the shells go to the container: the `bash` tool stays on the OS, so that the model reads
   the repo and the KB, and the guard blocks in that mode every `bash` that names a host from the scope. History of this
   decision: the text was written in this file by the session that drafts 014, from what the operator told it there ("the model must be able to keep reading the KB, but if we tell it to use the toolbox, the shells
   are created in the toolbox"); that session later recorded that editing this file had been an error. The operator
   had approved on a summary with the other variant ("`bash` and the shells run inside the container"). With
   both variants placed side by side, the operator chose this one in the session for 013: "B". It replaces the original AC8 and
   touches the title, §2, §4, AC2, AC6, AC14, AC15 and §6.

5. The spec was approved with these assumptions by the drafter in view: the autonomous experiment runner (not included in Lite) stays; the default mode is OS; the container does not shut down on exiting Pi.
6. The branch: it is renamed to `report-module`, it stays on the remote and with its worktree, "because we will surely keep working on several things here for a while". This spec goes on that branch.
7. The mechanism of the toolbox shells (container per workspace, tmux inside, question when creating the workspace) is implemented by this spec: "013". Spec 014 only adds the panel button on top.
8. **Amendment 1 (AC7):** minimal mounts instead of the whole repo: "yes, even so the model will be able to read kb, techniques and
   everything, and the toolbox is only for running commands". The model reads the repo and the KB from the host; the container only sees the workspace and the ledger CLI.
9. **Amendment 2 (AC8):** the exception for the ledger CLI: "yes, do it with that exception, approved. That way both in toolbox and
   using Gekko with one's own OS we will be able to use the reports module". `tasks.md` approved.
10. **Amendment 3 (2026-11-16, after the second independent audit of commit `d98ae88`; it only tightens).**
    The audit gave "fix before closing". Reproduced: the `bash` block of AC8 stopped applying when `scope.txt` was deleted, empty or had an unreadable line. Operator's decisions ("yes, launch the batch with those three decisions"): (a) the workspace's `.pi-sessions` folder is hidden inside the container with an empty mount,
    so that it cannot read or alter Pi's transcript; (b) `exec`, `scope.txt` and `AUTHORIZATION.md` are mounted read-only inside the container, so that it cannot change the mode or the scope; (c) the guard blocking a container's own address (its `tun0`) stays as a documented limit: the operator adds it to the scope. AC7 now includes those mounts. The spec remains `APROBADA`, not `IMPLEMENTADA`, until the batch of fixes is verified and the operator does his real run.
