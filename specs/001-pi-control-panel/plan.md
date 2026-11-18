# Technical plan 001 — Pi control and observability

> Status: `IMPLEMENTADO` (host) · Date: 2026-11-06 · Live verification: 2026-11-07
> Spec: `spec.md`, approved to advance to the plan.
>
> Resolution of the two open decisions (see `tasks.md` §Functional verification):
> 1. **Native Pi presentation** (not `pi-compact-tools`): the 1.5.0 API supports widget +
>    `setStatus` + `registerCommand` + `registerShortcut` + `ctx.ui.confirm`; run against
>    real Pi → meets AC06/AC14. The tmux-pane workaround was discarded.
> 2. **State shared between extensions**: Pi's loader evaluates `gekko-panel.ts` once per
>    `-e`, so the `runtime` singleton is anchored on `globalThis` (one object per process),
>    not on a module. Without this, the `shell-session` shells did not reach the guard's widget.

## 1. Review and approach

The review found two points that condition the design: the current guard does not
classify account changes or binary uploads, and its patterns do not guarantee
detecting every arbitrary operation. In addition, `shell-session` uses synchronous
tmux calls and does not propagate its errors correctly. A widget alone does not
solve any of those problems.

A single guard will remain as the authority. The panel will be part of its extension,
with state logic that can be checked without Pi. The TUI and Pi's native expansion
controls will be reused; pi-permission-modes, pi-footer and pi-compact-tools will not
be incorporated initially. The first probe must demonstrate that the native
presentation meets AC06; if it does not, this decision will be reviewed before
implementing an alternative renderer. No packages will be installed in advance.

The spec clarified that the administration of Pi's host permissions is out of scope,
not the changes authorized on the target. Its status was also updated.

## 2. Components and files

| File | Planned change | Criteria |
|---|---|---|
| `toolbox/gekko-guard.ts` | Mode authority, admission and confirmations; UI registration; invocation of the extended gate. | AC01–04, AC15, AC17 |
| `toolbox/gekko-panel.ts` (new) | State, compact projection, KB history and shell registry; no Pi imports in the pure logic. | AC05–09, AC11–14 |
| `toolbox/shell-session.ts` | Real errors, asynchronous tmux execution, session ownership and lifecycle events. | AC09–12 |
| `toolbox/gekko-panel-selftest.ts` (new) | Plan cases, Pi/tmux doubles, clock and synthetic fixtures. Run by the existing gate. | AC01–17 |
| `tools/pi-hitl.sh`, `tools/gekko-toolbox.sh` | Coherent loading, explicit scope and no duplicates. | AC15–16 |
| Pi image build (not included in Lite) | Copy the new modules and keep the pinned version. | AC16 |
| `docs/pi-hitl.md` | Shortcuts, permissions, coverage, shells and real limitations. | AC08, AC14–16 |
| Autonomous experiment runner (not included in Lite) | Review loading and compatibility; edit only if the shared change requires it. | AC16–17 |

There will be no history exports, web service or dependency on an LLM to summarize.
The Pi type imports will remain removable for the selftest.

## 3. Mode and authorization

- Proposed commands: `/gekko-mode default|aggressive` and `/gekko-panel`.
  Proposed shortcut `Alt+G`, subject to the collision probe on Pi 1.5.0.
- The state lives in the guard process, associated with the session and with an
  increasing revision. The model has no tool to modify it. The operator's callbacks
  are the only valid input; messages/events coming from tools are not accepted as
  mode orders.
- The change first updates the admission policy. The next request to the model
  receives a description of the current mode through the per-turn context mechanism
  verified in the probe. The effective mode is distinguished from the pending notice
  to the model. Successive changes replace obsolete notices.
- Do not rely exclusively on `before_agent_start`: it may not run between two
  autonomous iterations. Verify the real request boundary in Pi 1.5.0.
- DEFAULT asks before the three agreed types of change. AGGRESSIVE skips that question
  only when an applicable and current authorization exists for the type of change and
  target. Absence of authorization produces a rejection in both modes.
- The authorization comes from explicit operator input and, for clients, from the
  required contract/window; not from model claims or target output. Keep in memory the
  target, action and validity, without secrets. Do not infer a permission from the
  `GEKKO_ALLOW_DESTRUCTIVE` variable alone nor from the mode.
- The plan does not introduce a new format of client authorization. Before coding, it
  will be specified with fixtures how the operator's confirmation references the
  authorized scope. If that cannot be verified, self-approval is blocked.
- Admission order: prohibitions → scope/authorization → confirmation according to mode
  → existing limits → execution. Revalidate mode, scope and validity when resolving a
  pending confirmation; do not execute with a decision that became obsolete.
- Separate deletion/DoS from permitted changes; never translate AGGRESSIVE into
  `allowDestructive=true`. Include deletion of accounts, files and equivalent
  destruction in the rejection matrix. Do not confuse closing an own shell with
  deleting target data.
- The Bash paths and `session_send` go through the same decision. Compound commands,
  opaque scripts, unknown tools or unattributable remote context are not self-approved
  as authorized changes. A regex does not demonstrate semantic safety: the supported
  cases must be explicit and the uncertainty visible.
- Without a TUI there are no questions: an action that requires confirmation returns
  an explanatory block; it is not left hanging. Non-interactive use is kept for actions
  that do not require confirmation. New session/reload/resume resets to DEFAULT.

## 4. Activity, KB and presentation

- Widget of up to four lines above the editor: mode/guard, activity/duration,
  KB and shells. Detail under `/gekko-panel`, keyboard navigation and exit with Esc.
  The probe will decide whether the visible control supports a click; the shortcut is mandatory.
- Correlate calls and results by ID, with monotonic times. The start of a tool does not
  imply that the guard admits it: blocks have their own state.
- KB is derived from the results of `read`, `grep`, `find` and `ls`, normalizing paths
  against the repository and resolving symlinks before attributing them to `kb/`.
  Do not count as read what was only requested or appeared as a match.
- Unknown range if the tool does not allow reconstructing what was returned; explicit
  truncation. Bash/subagents/prior context: initially uninstrumented coverage.
  Do not add general shell parsers to fake exhaustiveness.
- History in memory during the session; on reload, a coverage reset is declared. Do not
  reconstruct or explore other transcripts. The panel shows since when it observes,
  unique counts and paginated detail.
- Summary with controlled labels and sanitized paths; do not interpolate commands,
  arguments or raw output. Remove terminal escapes/controls from visible data. The
  output detail uses sanitized, bounded text, separate from the original evidence.
- Without a TUI, no visual widget or refresh timer is registered. The tool registry
  does not depend on the UI. The panel failing does not change permissions or enable AGGRESSIVE.

## 5. tmux shells

- Replace the helper that returns errors as text with a structured result (success,
  stdout, stderr, timeout) and asynchronous calls with a timeout. Do not block the event
  loop: the operator must be able to toggle the mode during long waits.
- Remove the `kill-session` before `new-session`. The collision fails without modifying
  the existing session. Verify creation/closing with a result and real identity.
- Record server/socket, session ID, pane ID and Pi session ID only after verified
  creation. A name is not identity nor proof of ownership.
- The panel receives events from its own tools and queries tmux metadata through
  separate arguments, without shell interpolation. It does not accept events as permissions.
- Refresh every two seconds while the view is shown, with a two-second timeout and a
  single concurrent query; an additional refresh after operations. Timeout/error marks
  unknown and keeps the date of the last valid observation.
- Get the current process without its arguments. Capture output only when requesting
  detail of an own pane, verifying its identity again. Do not send keys from the UI.
- Previous or external sessions lack attribution after a restart: they are shown
  separately as unknown if listed; their output is not captured automatically.
- Timers and listeners are removed when the view is closed, the session changes or the extension is unloaded.

## 6. Tests and execution order

1. Local probe of Pi 1.5.0 with synthetic data: shortcut during a slow tool, boundary
   between requests, native expansion, hook order, reload and operation without TUI.
   Record results; do not treat the `latest` documentation APIs as verified.
2. Policy matrix AC01–04/15: authorized/unauthorized accounts, passwords and uploads;
   deletion, DoS, scope, brute-force, expired and revoked permissions, fake prompts,
   compound commands and mode change with a pending confirmation.
3. State/renderer/KB AC05–08/13–14 with synthetic clock and events, including errors,
   concurrency, truncation, symlinks, escapes and marker secrets.
4. tmux AC09–12: empty/absent server, creation failure, collision, external closure,
   recycled identity, timeout, ownership and verification of the absence of mutating
   operations when observing. Smoke test with an isolated tmux server, without the
   operator's sessions.
5. Launchers AC16: coherent scope and guard, single loading, Docker resources present;
   host and toolbox smoke tests. Do not reach targets nor use real evidence.
6. Full gate AC17 and UI review: empty/error/stale states, 80 columns, keyboard,
   detail and absence of falsely functional previews.

Common command, extended to invoke the new cases:

```bash
GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts
```

The complementary smoke tests will be documented with reproducible commands in
tasks.md when the plan is approved. Total coverage will not be declared merely by passing fixtures.

## 7. Risks and acceptance limits

The biggest risk is promising exhaustive classification of arbitrary shell. This plan
requires rejecting self-approval when attribution is missing, keeps the repository's
policy and documents that the in-process guard is not a security boundary. Not even an
egress allowlist by itself prevents destructive changes inside the permitted target.
If the probe does not allow meeting a criterion, that criterion is reviewed with the
operator again before being marked as met.

No evidence is modified and no extensions are installed at this stage. This plan
requires approval before generating tasks.md or product code.
