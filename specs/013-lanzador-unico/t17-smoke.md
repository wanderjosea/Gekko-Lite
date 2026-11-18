# T17 — Smoke test, 2026-11-15 (local time)

Status: PASS after the repeat below. T16 independent review was completed and recorded before starting T17. The initial failed attempt is retained as history.

## Pi launcher (real model path)

Two disposable workspaces (`t17-os`, `t17-toolbox`) were scaffolded under a private temporary root, with their respective exec modes. The real launcher used an isolated Pi configuration and local installed Pi 1.5.2; extension discovery/MCP/skills and built-in tools were disabled for this narrowly scoped synthetic test, while launcher extensions remained explicit. The visor ran separately on 127.0.0.1:57215, not 4355.

Both launches returned 401 authentication_error (`missing or wrong API key`) before any model tool execution. Toolbox creation itself succeeded. No credential guessing or repeated attempts were performed. Therefore an end-to-end Pi/model run is NOT credited.

## Complementary real-handler and browser verification

Commands: `python3 /tmp/gekko-t17-run.py` (launcher/server orchestration), `node --experimental-strip-types /tmp/t17-handlers.ts` with each workspace mode (direct invocation of real registered handlers), Playwright CLI session `gekko-t17` against the local visor.

- OS: session_new/session_send/session_kill PASS; cwd matched the disposable OS workspace. Shell hostname independently matched host hostname.
- Toolbox: same handlers PASS against the actual launcher-created container. Cwd matched the disposable toolbox workspace and hostname independently matched docker exec hostname.
- Each shell wrote an artifact and registered one synthetic hypothesis through findings.py. Both artifacts were read and deleted from the host successfully.
- Real Chromium navigation verified the workspace index, each workspace listing and both finding detail pages. Titles T17-SYNTHETIC-OS and T17-SYNTHETIC-TOOLBOX appeared with hypothesis status. No real finding, target, CVSS or vulnerability claim was introduced.
- Browser closed, toolbox container removed, temporary viewer stopped, port 57215 confirmed closed, and temporary workspace/config root removed. Only this test's browser snapshots were removed.

## Initial remaining acceptance (resolved below)

The initial run required valid inference authentication before it could be credited. No VPN or live-target testing was performed.


## Repeat with operator-provided authentication — PASS

Executed 2026-11-15 (local time; browser timestamps 2026-11-16 UTC). The operator supplied an inference endpoint and credential for this test. The credential was used only in the process environment/private temporary Pi configuration, excluded from reports, and removed with the temporary root. Log checks confirmed the credential was absent from both Pi output logs.

Procedure: `python3 /tmp/gekko-t17-run.py` using the supplied inference configuration, real `tools/pi-hitl.sh`, installed Pi 1.5.2 and registered model `<model-id>`. Isolated discovery settings were retained as described above. These were real noninteractive Pi/model runs authorized by the operator, not mocked model or handler invocations.

| Mode | Pi exit | Model tools | Workspace/host identity | Artifact | Ledger |
|---|---|---|---|---|---|
| OS | 0 | session_new, session_send, session_kill | cwd exactly OS workspace; hostname matched host | written by model shell, readable and deletable by operator | one T17-SYNTHETIC-OS hypothesis |
| Toolbox | 0 | session_new, session_send, session_kill | cwd exactly toolbox workspace; hostname matched docker exec hostname | written by model shell, readable and deletable by operator | one T17-SYNTHETIC-TOOLBOX hypothesis |

Both sessions were independently checked closed with tmux has-session after Pi completed. No direct handler fallback was used in this repeat.

A real Chromium browser (Playwright CLI session `gekko-t17`) opened the visor on 127.0.0.1:45809. Both workspace listings and both `/f/1` detail pages displayed the expected title, hypothesis status and synthetic summary. The first viewer process ended with its orchestration process; it was restarted on the same temporary root/port for the final browser checks. No production port or real engagement was used.

Pi output log SHA-256 values (logs were temporary and removed at cleanup):
- OS: `4d7220205e3dd60db7ca29f143a31feba1a641b990fa227caf375ddf9af4bbd8`
- Toolbox: `485115ddb193dc25a162ec4569d265ebbd3f284f5ea18387ca786dfd8a0cc52c`

Cleanup PASS: browser closed; test container removed; viewer terminated and port 45809 verified closed; temporary roots/workspaces/configuration (including credential) removed. No VPN, live-target test or interactive TUI acceptance was performed. This closes the requested OS/toolbox real-model smoke criterion; T18 final reconciliation remains separate.
