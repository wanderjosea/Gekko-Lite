# T16 — Independent security review, 2026-11-15

Reviewer: separate `code-auditor` agent (`review_integration`). Scope: current spec 013 integration, Docker adoption/mounts, launcher, guard, shell handlers and supporting tests. No engagement data inspected.

## Findings and disposition

1. **HIGH — Container adoption checked only mounts.** A same-name container with matching binds could use another image, host networking or elevated privileges. Fixed before ACL/start/reuse: compare immutable image ID and HostConfig (default/bridge network, non-privileged, init, only NET_ADMIN, only TUN:rwm, isolated PID/Userns, private IPC, no additional SecurityOpt, rprivate binds).
2. **HIGH — Additional networks/device rules still accepted.** Fixed: require empty DeviceCgroupRules and exactly one bridge network. Docker 29 observation confirmed NetworkMode=bridge; default is also accepted subject to the same single bridge requirement.

Regression-first evidence: six injected cases failed before the first fix (`/tmp/t16-failing.log`); two additional cases failed before the second (`/tmp/t16-failing-extra.log`). Final injected cases reject differences before ACL/start. Separate reviewer rechecked both fixes and approved T16.

## Executed validation

- Guard: 127 requirements, 1390 cases, all passed.
- Workspace launcher: 113 passed, 0 failed.
- Real handlers with GEKKO_TEST_TOOLBOX=1: PASS, including OS regression.
- Docker T12/T13: PASS, exact temporary mounts, shell/cwd/closure/artifact and concurrent ledger/viewer checks.
- Reports: 31/0; TUI: 45/0; hooks: 46 checks, ALL GREEN.
- git diff --check and shell syntax: PASS.

## Limits

Docker daemon/operator access is trusted; this does not authenticate the daemon or prevent an operator from changing a container after inspection. A pre-existing lstat-to-open race in the viewer remains outside spec 013; it was not introduced or fixed here. No VPN tested. T17 is separate and was not credited by this review.
