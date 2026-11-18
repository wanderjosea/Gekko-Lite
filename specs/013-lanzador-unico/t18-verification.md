# T18 — Final regression and acceptance reconciliation

Date: 2026-11-16 (local time). Branch: report-module.
Scope: spec 013 only; existing unrelated changes and specs/015 were preserved. All test workspaces were temporary; no real engagements or target tests were used.

## Commands and results

| Test | Command | Result |
|---|---|---|
| S | `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` | PASS: guard/panel/workspace all passed; 127 requirements, 1399 cases |
| P | `bash tools/ws-test.sh` | 115 passed, 0 failed |
| H OS | `node --experimental-strip-types toolbox/tests/handler-harness.ts` | PASS, real handlers and tmux |
| H toolbox | `GEKKO_TEST_TOOLBOX=1 node --experimental-strip-types toolbox/tests/handler-harness.ts` | PASS, real handlers and disposable Docker container |
| D | `bash tools/toolbox-test.sh` | PASS, real Docker; not SKIP |
| K | `bash .githooks/test.sh` | ALL GREEN, 46 checks |
| Reports | `bash tools/report-test.sh` | 31 passed, 0 failed |
| TUI | `bash tools/tui-test.sh` | 45 passed, 0 failed |
| Static checks | `git diff --check`; `bash -n setup.sh tools/pi-hitl.sh tools/ws-test.sh tools/toolbox-test.sh` | PASS |

The commands ran with local permissions needed for Docker, interface discovery, tmux and loopback sockets. No inference credential was needed or reused for this regression.

## Issues found while reconciling acceptance

- AC12 had incomplete direct-handler coverage for matching denial reasons across modes. Added nine assertions covering outside-scope, DoS and destructive strings in both OS/toolbox, with the container name included. The strings are supplied only to the guard decision handler; they are never executed. S passes with all nine assertions.
- AC6 now also asserts the launcher banner and generated prompt in both modes in P.
- D initially failed on `CWE-79`: the current viewer lists findings without classification fields. Updated D to assert CWE/CVSS in the actual finding detail, alongside the other fields. No viewer/product code was changed. D passed after this correction.

## AC1–AC17 evidence matrix

| AC | Evidence | Outcome |
|---|---|---|
| AC1 | S REQ-PNL-005: single launcher; removed toolbox launcher. Text search in current docs/tools/setup/contracts/KB found no obsolete launch instructions. Historical specs and absence-check tests retain historical names intentionally. | PASS |
| AC2 | P menu flow, toolbox choice; S REQ-TBX-002 covers Enter/OS and invalid/EOF choices. | PASS |
| AC3 | P stored-mode launch without another question; S REQ-TBX-001 mode CLI/file checks. | PASS |
| AC4 | P legacy/default OS launch, no Docker calls; S absent exec file defaults OS. | PASS |
| AC5 | P invalid saved mode blocks Pi; S invalid mode CLI and prompt fail. | PASS |
| AC6 | P explicit banner/generated prompt checks in OS and toolbox; S REQ-TBX-006 prompt contract. | PASS |
| AC7 | P run/reuse/start/refuse; D exact temporary bind mounts; S REQ-TBX-003 mount/image/isolation rejection cases. T17 also used the launcher-created toolbox. | PASS |
| AC8 | S REQ-TBX-005 real tool_call handler: target bash blocked, strict ledger exception, loopback allowed, session_send allowed, OS bash retained; parser rejects chained/hostile forms. Bash remains host-side by launcher/extension wiring. | PASS |
| AC9 | H toolbox and D: shell inside expected workspace, identity/cwd and verified closure; shared H failure-path checks reject invalid cwd and close unmanaged shells. T17 independently corroborated real-model shell hostname/cwd. | PASS |
| AC10 | P Docker missing/failing, image missing, ACL failure and no Pi execution; S permission-denied Docker case and refusal before start. | PASS |
| AC11 | P exit notice and no removal path; T17 independently found the toolbox container still alive after Pi exited, before explicit cleanup. | PASS |
| AC12 | S new direct-handler checks compare identical denial reasons for scope, DoS and destructive commands in both modes, including a container-name token. | PASS |
| AC13 | P OS launch makes no Docker calls and clears inherited toolbox state; H OS passes. | PASS |
| AC14 | D shared absolute artifact path and host deletion; T17 model-created artifacts were read/deleted from host in both modes. | PASS |
| AC15 | D matching fields checked in ledger and viewer detail for host/container findings; T17 browser verified both real-model synthetic findings. | PASS |
| AC16 | D 10+10 concurrent additions, 20 rows and unique IDs; earlier recorded F3 alternating host/container additions remain historical supporting evidence. | PASS |
| AC17 | S REQ-PNL-005 and REQ-TBX-001…006; K spec/boundary checks; current runbook/prompt/integration/contracts document one launcher and two modes. | PASS |

Independent security review and fixes: [t16-review.md](t16-review.md). Real Pi/model runs and browser evidence: [t17-smoke.md](t17-smoke.md).

## Limits

No VPN or live-target test; these are outside spec 013 acceptance. Pattern-based host recognition and Docker/operator trust limits remain as documented in the living spec and T16. This regression does not review or certify the unrelated spec 015 changes. No commit or push performed.


## Commit isolation check — 2026-11-16

Before committing, a disposable copy of HEAD plus the exact staged spec 013 diff was tested, excluding the unrelated spec 015 viewer changes, its requirements and report tests. Only the local installed node_modules was reused for test dependencies.

- S: 125 requirements, 1391 cases; guard/panel/workspace all passed.
- P: 115/0; H OS and toolbox: PASS; D Docker real: PASS.
- K: 46 checks ALL GREEN; reports: 27/0; TUI: 45/0.
- Staged diff whitespace and credential/scope checks: PASS.

These are the counts for the isolated spec 013 commit. The larger earlier counts (127/1399 and reports 31/0) describe the shared working tree including uncommitted viewer requirements; they are retained as historical execution evidence, not attributed to the isolated commit. Temporary snapshot removed after validation.
