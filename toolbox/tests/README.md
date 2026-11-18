# toolbox/tests — model-independent integration harnesses (spec 001)

Deterministic tests of the real `session_*` handlers and the panel refresher against **real tmux**,
with a mock `pi` object — no model, no network. They close findings the model-driven E2E could not
(the open-weight model self-censors before the guard, so a payload never reaches it). Each test's
assertions are the evidence cited by the F-rows in `specs/001-pi-control-panel/tasks.md`.

| File | Covers | tasks.md |
|---|---|---|
| `handler-harness.ts` | #9 socket-path destruction · #1 kill→recreate aliasing · #1b full server restart (pid recycle) · #3 list never claims a stranger · AC09 multi-socket | F19–F21 |
| `f24-reverify.ts` | F24 `session_read` re-verifies `ours()` **every** poll iteration (server restart mid-poll → fail closed, stranger pane NOT leaked) · shipped `refreshShells` vs real tmux (the `currentProcess(s.sessionId,…)` line that regressed) | F24, F25 |

Run: see the header of each file. `@sinclair/typebox` must resolve from `toolbox/node_modules`
(symlink it to your Pi install's `node_modules` for the run, then remove it — it is not committed).
The pure gate (`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`) needs
none of this; these are the real-tmux layer on top of it.
