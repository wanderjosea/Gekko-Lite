# Real Client Engagements — Authorization, Confidentiality & Production Safety

This layer applies **on top of `scope.md`** whenever the target belongs to a
paying client (not a lab/CTF). `scope.md` still governs; where they overlap the
**more restrictive wins**. Labs/CTF skip the signed-order parts, but everything
here is safe to apply to labs too.

## 1. Authorization gate — no artifact → no active testing
- Before ANY active action (scan, connect, exploit) against a client asset,
  `engagements/<codename>/AUTHORIZATION.md` MUST exist, be filled, and reference a
  **signed** authorization (scope, dates, signatory). Verbal/chat approval is NOT
  sufficient for a real client. I enforce the *artifact check*; the signed paper is
  the operator's legal cover, not mine — I cannot verify its legal validity for you.
- **Testing window:** act only inside the authorized date/time window. Outside it →
  stop, even mid-chain. A found-but-out-of-window action waits for the window.
- **Exact allowlist:** hosts/IPs/ports/URLs/accounts as listed — nothing else. A
  "related" asset (subdomain, linked service, same ASN) is out until the client
  adds it **in writing** (re-authorization). No pivot beyond the allowlist without it.
- **Emergency stop:** if the client or the emergency contact in AUTHORIZATION.md
  says stop, I stop immediately and record the current state.

## 2. Client confidentiality & isolation
- **Codename every client.** Real org name, personnel names, and any PII NEVER
  enter the KB, git commits/messages, committed filenames, or any external service.
  Use `engagements/<codename>/` + generic descriptors.
- **One client per session.** Never mix or cross-reference client A's data, creds,
  or notes with client B. Do not load another engagement's context alongside.
- **Client data never leaves this repo/host.** Reinforces `scope.md`: no client
  IP/host/cred/hash/dump/PII to WebFetch, WebSearch, published Artifacts, Notion or
  any external MCP, cloud/remote subagents, or telemetry. A URL lifted from client
  output is the same leak path — resolve it only inside the toolbox.
- **Retention & destruction.** At close, follow the retention line in
  AUTHORIZATION.md: keep only what the contract requires, only as long as it
  requires, then securely delete (shred) the rest. Record what was kept/destroyed.

## 3. Production safety — assume it is a live business system
- **Non-destructive by default.** No action risking outage, data loss, or account
  lockout without explicit **written** approval — and prior client notification
  where the contract requires it. (DoS stays forbidden outright, no exceptions.)
- **No persistence** — backdoors, new accounts, scheduled tasks, implants — unless
  that is an authorized objective. Anything created for a test is temporary.
- **Cleanup is MANDATORY and DOCUMENTED.** Every change to a live system's state
  (config, cert template, account, file, service) is reverted and recorded:
  what changed, when, and the exact rollback. A change with no recorded rollback is
  a bug. (Model: restoring the ADCS template + deleting the temp machine account.)
- **Least-intrusive proof.** Stop at demonstrating impact; do not exfiltrate more
  client data than needed to prove the finding.

## 4. Evidence integrity (chain of custody)
- Every proof artifact gets a recorded **sha256 + UTC timestamp + the command** that
  produced it; the findings ledger (`findings.py`) is that index. Work on copies;
  never mutate captured evidence.
- The deliverable is a projection of **confirmed** findings only (see `report-writer`).

## Intake I need per engagement (give me once, in `engagements/<codename>/`)
- **AUTHORIZATION.md** — signed-order ref, exact scope, testing window,
  allowed/denied techniques, rate limits, emergency contacts, change-control /
  notify rules, retention policy.
- **Real technical targets** (IPs, hostnames, hashes, endpoints) — these must be
  REAL to work; only the client identity/PII is codenamed. Do not hand me fake IPs.
- **creds vault** — provided/discovered credentials with provenance, in
  `loot/` (gitignored), never committed.
