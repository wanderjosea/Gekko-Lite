# Spec 001 — Pi control and observability in Gekko

> Status: `IMPLEMENTADA` (operator, 2026-11-17: closed; 18/18 tasks, merged into `main`) — advanced to the plan authorized by the operator on 2026-11-06.
> Date: 2026-11-05
> Origin: operator request to switch modes during execution, summarize
> activity, identify KB queries and see the agent's tmux shells.

## 1. Problem

The TUI shows conversations and long outputs, but it offers no compact view that
brings together the effective mode, the current activity, the queries to `kb/`
and the tmux sessions attributable to the agent.

## 2. Goal

Let the operator switch between DEFAULT and AGGRESSIVE (`AGRESIVO` in the UI)
during a run, and understand at a glance what Pi is doing, what documentation it
received and which shells it keeps open, with verifiable states and without
losing the detail available.

## 3. Verified context

- `toolbox/gekko-guard.ts` evaluates each call and reloads the scope, but it
  captures the destructive permission and the limits at startup; there is no mode
  selector.
- `toolbox/shell-session.ts` exposes `session_new`, `session_send`, `session_read`,
  `session_list` and `session_kill`. The list does not attribute sessions to a run.
  Some results announce creation/closing without checking tmux's success; creating
  a session first tries to close another one with the same name.
- `tools/pi-hitl.sh` loads guard, shells and banner. `tools/gekko-toolbox.sh` loads
  shells, but does not declare the guard in its current invocation. Equivalence
  between launchers cannot be assumed, nor can protection be announced without
  checking it.
- A Pi image build (not included in Lite) pins Pi 1.5.0. The compatibility of the investigated
  packages with that version and with the existing extensions is not yet tested
  locally.

## 4. Scope and expected behavior

### 4.1 Mode selector

- Control visible and operable by keyboard during agent activity, with a
  command-based alternative. A click is desirable if the TUI supports it; the
  function must be available without a mouse. The concrete key is resolved in the plan.
- DEFAULT requests specific confirmation before modifying users or passwords, or
  uploading binaries to the target. AGGRESSIVE allows those actions without
  confirming each one, when they are included in the applicable targets and
  authorizations of the engagement. No authorization is presumed for accounts or
  systems outside the scope, nor for changes other than those authorized.
- The selector expresses the operator's operational preference for the session;
  it does not replace the authorizations required by the engagement rules.
  For clients, the corresponding written authorization and active window are required.
  Both modes prohibit DoS and deleting things; neither enables brute-force without
  specific authorization nor modifies rate limits or budget.
- **Explicit conflict:** the initial request "aggressive allows everything" is not
  compatible with `CLAUDE.md` and `.claude/rules/scope.md`. This proposal keeps
  those limits; it does not represent or implement an unrestricted mode.
- If both modes allow the same actions under the current authorizations, the panel
  says so; it does not promise a permission change that does not exist.
- After the change is confirmed, the next tool call not yet admitted uses the new
  mode. Before the next request to the model, the model receives the current mode.
  Restarting Pi or waiting for the whole task to finish is not required.
- Tools already admitted and tmux processes continue. Returning to DEFAULT does not
  cancel processes, revert actions or retry calls blocked earlier.
- The mode distinguishes requested, pending, effective and error. Every new session,
  resume or reload starts in DEFAULT; it does not silently inherit AGGRESSIVE.
- Only an explicit operator action changes the mode. The model, tool outputs and
  file contents cannot activate it.

### 4.2 Summarized activity

- Compact persistent view: mode, current activity, duration, KB summary and
  number of verified shells. The operator can expand details and return.
- Distinguishable states: idle, generating response, running tool, waiting for
  result, blocked, error and status source unavailable.
- The summary describes observed events, for example "reading documentation" or
  "waiting for shell output"; it does not invent goals, progress or thoughts.
- If there is simultaneous activity, it shows the number of operations and lets
  the operator see them. A persistent tmux process is not confused with the tool
  currently active.
- Long outputs are collapsed without deleting or altering the transcript/evidence.
  The compact mode does not require an additional call to a model.
- Without a TUI, the tools keep working and no dialogs are opened.

### 4.3 KB queries

- Per-session history with a path relative to `kb/`, access type, time, tool and
  originating agent when its identity is available.
- A successful read records the range actually returned, if known. A search records
  its query/scope safely and distinguishes files with matches from files read.
  Listing a directory is not the same as reading it.
- Failed, truncated or partial reads are identified. Unique files and total queries
  are shown separately; repeating a read does not inflate the first.
- "Consulted" means content delivered to the agent, not comprehension or use
  demonstrated in its reasoning. Unknown ranges are labeled as such.
- Coverage must be declared: native tools, Bash, subagents and prior context.
  An access that cannot be attributed or observed is shown as unknown/not
  instrumented; "complete history" is never shown when those gaps exist.
- No automatic exploration of engagements, other sessions or the whole KB is done
  to build this view. Only accesses of the observed session are used.

### 4.4 Agent's tmux shells

- View of the shells created by the current session through Gekko's tools, verified
  against the tmux server corresponding to the host/container.
- Each entry identifies the tmux session and pane, known origin/owner, creation time
  if recorded, last observed interaction, current process when available and the
  date of the last check.
- Minimum states: open, closed, unknown, error and stale data. "Open" does not mean
  a callback was received, authentication succeeded or the task concluded.
- Updated after create/send/read/close, and on manual refresh. With the view open,
  a session closed externally must be reflected within five seconds when tmux
  responds; a timeout produces unknown state, not a false success.
- Sessions that belong to others do not appear as one's own. If sessions without
  attribution are shown, they are separated and labeled; their panes are not
  inspected automatically. Those created by Bash/subagents are attributed only
  with verifiable evidence.
- The detail view allows querying recent output of one's own shell by explicit
  action, and returning to the summary. It is shown locally as untrusted content.
- The view is observational: opening or refreshing it sends no keys, closes no
  sessions, creates no shells and runs no commands inside them. No close button is added.
- A name collision must not close an existing session. Creation and closing are
  announced as successful only when the result is verified.
- Without a tmux server, "no sessions" is shown; absence of the executable,
  permission denied and timeout are distinguished from an empty list.

### 4.5 Presentation, privacy and integration

- Operator-facing text in Spanish; state understandable without depending on color.
  Keyboard and narrow terminal still allow consulting all details.
- Names, paths and outputs are treated as untrusted data; they cannot inject
  terminal controls or change the mode. The summary omits full arguments,
  credentials, tokens, flags, file contents and pane outputs.
- No data is exported to external services, and no operational history is versioned.
  The state of another session/engagement does not appear when switching sessions.
- The panel reports the real state of the guard. If it is missing or failing, it
  does not offer AGGRESSIVE nor present the session as protected. Seeing a guard
  does not imply network containment.
- Delivery covers the interactive host and toolbox launchers, the tmux tools, the
  usage instructions and the tests. The non-interactive runner keeps its controls
  and must not depend on the interface.
- No static screen is presented as finished: any preview is labeled `NOT BUILT` and
  sits behind an explicit option, outside the normal flow.

**Out of scope:** web dashboard, model switching, administration of permissions
on the host running Pi (other than the changes authorized on the target), new
offensive techniques, remote control of shells, exhaustive filesystem
instrumentation, history across engagements, summaries produced by another LLM,
and disabling the guard or its immutable limits.

## 5. Acceptance criteria

All cases in the table are **tests to be implemented**, not verifications already
passed. `G` represents the real command of the existing gate:

```bash
GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts
```

The gate will be extended with deterministic cases and simulated dependencies for
the new behaviors. It requires no network, model, target or real tmux server.
The names are identifiers of required cases, not existing CLI flags.
The visual and real-tmux check complements the gate; it does not replace it.

| ID | Observable criterion | Required test |
|---|---|---|
| AC01 | A new session/resume/reload starts in DEFAULT; activating AGGRESSIVE requires an operator action. | G: `mode-default-and-origin` with fake tool and file content. |
| AC02 | Switching during a run changes the next admission and reaches the next model request; rapid changes end at the last mode selected. | G: `mode-live-boundary` with a controlled event sequence. |
| AC03 | Pending/effective/error reflect the real application; a failed application does not show success; processes are not canceled and blocks are not retried. | G: `mode-apply-failure-and-running-tools`. |
| AC04 | DEFAULT confirms changes to users, passwords and binary uploads; AGGRESSIVE allows them without individual confirmation only if authorized. Both block deletion, DoS, out-of-scope and unauthorized brute-force, and respect the limits and authorizations in force. | G: `mode-policy-matrix`, with examples of each action, absence/expiry of authorization and both modes. |
| AC05 | Activity, duration and concurrency follow real events; a failure/block does not appear as completed. | G: `activity-lifecycle` with a simulated clock. |
| AC06 | Collapsing/expanding preserves tool content and result; it does not modify the model's context nor generate calls to summarize. | G: `compact-view-invariance`. |
| AC07 | KB distinguishes read, search, listing, error and truncation; keeps real ranges and counts uniques separately. | G: `kb-access-evidence` with synthetic fixtures. |
| AC08 | Bash, subagents and prior context have explicit coverage; no attribution is invented and no data from another session is incorporated. | G: `kb-coverage-and-session-isolation`. |
| AC09 | Own and foreign shells are distinguished by verifiable provenance and server; the same name on another server is not confused. | G: `tmux-ownership-and-server`. |
| AC10 | Failed create/close do not produce success; collisions do not kill existing shells. | G: `tmux-operation-results-and-collision`. |
| AC11 | Refresh detects external closures within the window and shows empty/error/stale correctly. | G: `tmux-refresh` with simulated clock and responses. |
| AC12 | Observing/refreshing does not mutate shells; recent output is obtained only when requesting detail of an own shell, and stays local. | G: `tmux-observation-only` verifying the operations emitted. |
| AC13 | The summary does not expose fixture secrets; hostile text cannot control the terminal or permissions. | G: `panel-untrusted-and-sensitive-data`. |
| AC14 | The panel supports keyboard, 80 columns and text-only state without color; without a TUI there are no dialogs or tool failures. | G: `panel-layout-and-headless`; complementary visual smoke test. |
| AC15 | A missing/failed guard appears as such and blocks the AGGRESSIVE selector; contained egress is not claimed. | G: `panel-guard-health`. |
| AC16 | Host and toolbox load compatible resources without duplicate controls; the runner keeps its behavior; no unlabeled previews exist. | G: `launcher-panel-contract` with invocation fixtures; interactive smoke test in both environments. |
| AC17 | The previous guard tests keep passing alongside all new cases. | Full G, without omitting existing cases. |

## 6. Risks and decisions the plan must resolve

- Choose between reusing `pi-compact-tools` and Pi's native presentation according
  to verified compatibility; do not install several competing renderers for the
  same view. `pi-footer` is optional, not a requirement.
- Evaluate `pi-permission-modes` as a reference for interaction; do not assume its
  YOLO mode satisfies Gekko's policies. The source of authority must be single.
- Define how the mode is communicated and applied while tools are pending, without
  depending on the model correctly interpreting a visual label.
- The written brute-force policy is not equivalent to full current enforcement.
  AC04 requires identifying and testing the necessary coverage; that criterion must
  not be declared met based only on instructions to the model.
- Attribution of shells surviving restarts, subagents and Bash commands: prefer
  "unknown" over inventing ownership or inspecting other sessions.
- Choose the minimum local retention for history and the rules for sanitizing labels
  without altering the original evidence. Summarizing must not hide errors or blocks.
- Validate refresh and shortcuts during long calls, key conflicts, the cost of tmux
  queries and the behavior of the Pi version pinned by the repo.

Researched references (documented capabilities, not approved dependencies):

- [Pi extensions API](https://pi.dev/docs/latest/extensions).
- [pi-permission-modes](https://github.com/wynainfo/pi-permission-modes).
- [pi-compact-tools](https://github.com/nedleeds/pi-compact-tools).
- [pi-footer](https://pi.henry.wang/extensions/pi-footer/).

## 7. Evidence signals and gate of this stage

The feature will be considered implemented when AC01–AC17 are green, the approved
checklist is complete, and the verification log includes commands/results and
TUI/tmux smoke tests on host and toolbox with synthetic data. A drawing or
state tests without validation of the integration are not enough.

The spec was approved to move to the plan on 2026-11-06. The technical plan stays
in DRAFT until the operator reviews it; there is no implementation or new tests yet.
