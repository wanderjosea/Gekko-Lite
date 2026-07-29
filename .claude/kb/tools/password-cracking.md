---
title: Password Cracking (Hashcat + identification)
slug: password-cracking
category: tools
updated: 2026-07-01
summary: "Hashcat modes, hash identification, app hash locations, base64url decode"
tags: [hashcat, hash, cracking, hashid, ntlm, kerberos]
sensitive: false
---

# Password Cracking (Hashcat + identification)

## When to use
Tienes un hash capturado (NTLM, TGS, AS-REP, bcrypt, MD5, SHA1…) y quieres texto claro.
Primero identifica el formato, elige el modo hashcat correcto, lanza con rockyou.

## Identificar formato
```bash
hashid 'HASH'
hash-identifier
hashcat --example-hashes | grep -B1 -A2 "MODE: 13100"
```

## Modos hashcat frecuentes
| Modo | Formato | Cuándo aparece |
|------|---------|----------------|
| 0 | MD5 | Webs PHP antiguas, SQLite apps |
| 100 | SHA1 | General |
| 110 | sha1($pass.$salt) | Salt AL FINAL |
| 120 | sha1($salt.$pass) | Salt AL PRINCIPIO — OFBiz ⭐ |
| 500 | MD5-crypt ($1$) | Cisco enable secret 5 |
| 1000 | NTLM | Windows/AD — el más común |
| 1800 | sha512crypt ($6$) | /etc/shadow Linux |
| 3200 | bcrypt | Webs modernas |
| 5600 | NTLMv2 (Net-NTLMv2) | Responder captures |
| 13100 | Kerberos TGS (Kerberoasting) | hashcat -m 13100 |
| 13400 | KeePass | Gestores de contraseñas |
| 18200 | Kerberos AS-REP (ASREPRoast) | hashcat -m 18200 |
| 22000 | WPA2 | Redes WiFi |

## Comandos esenciales
```bash
# NTLM (AD)
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt --force -O --hwmon-disable

# Kerberoasting TGS
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --force

# AS-REP Roasting
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --force

# NTLMv2 (Responder)
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt --force

# sha1($salt.$pass) — OFBiz  (salt primero)
hashcat -m 120 'HEXHASH:SALT' /usr/share/wordlists/rockyou.txt --force -O --hwmon-disable

# sha1($pass.$salt) — salt al final
hashcat -m 110 'HEXHASH:SALT' /usr/share/wordlists/rockyou.txt --force -O --hwmon-disable

# sha512crypt Linux
hashcat -m 1800 shadow_hash.txt /usr/share/wordlists/rockyou.txt --force

# Cisco enable secret 5 (MD5-crypt)
echo '$1$mERr$WpAg9kQAnJsh/9WzETcjd1' > /tmp/ena.txt && hashcat -m 500 /tmp/ena.txt /usr/share/wordlists/rockyou.txt --force

# Cisco Type 7 (NO es hashcat — reversible)
# Ver: https://www.ifm.net.nz/cookbooks/passwordcracker.html  o script python
```

## Dónde buscan hashes las apps
| App | BD típica | Ruta del hash |
|-----|----------|---------------|
| OFBiz | Derby (.dat) | `/opt/ofbiz/runtime/data/derby/ofbiz/seg0/` |
| WordPress | MySQL | `wp-config.php` → credenciales DB → wp_users |
| Jenkins | XML | `/var/lib/jenkins/users/*/config.xml` |
| GitLab | PostgreSQL | `/etc/gitlab/gitlab.rb` → credenciales |
| Tomcat | XML | `tomcat-users.xml` |
| SQLite genérico | archivo .db | `sqlite3 file.db .dump \| grep -iE pass\|user` |

## Buscar hashes en binarios / archivos
```bash
grep -rao '\$SHA\$[^[:space:]]*' /ruta/         # OFBiz $SHA$salt$b64
grep -rao '\$apr1\$[^[:space:]]*' /ruta/         # Apache htpasswd
grep -rao '[0-9a-f]\{32\}' /ruta/               # MD5 hex 32 chars
grep -rao '[0-9a-f]\{40\}' /ruta/               # SHA1 hex 40 chars
```

## Convertir base64url → hex (OFBiz)
```python
# OFBiz usa base64 url-safe (- y _ en lugar de + y /)
python3 -c "
import base64
h='uP0_QaVBpDWFeo8-dRzDqRwXQ2I'
print(base64.urlsafe_b64decode(h+'==').hex())
"
# Output hex → usar como HEXHASH:SALT en hashcat -m 120
```

## Gotchas
- OFBiz formato: `$SHA$salt$base64url_hash` → modo 120 (salt primero), NO 110.
- Si 110 da Exhausted, probar 120 y viceversa — el orden del salt es ambiguo hasta que uno craquea.
- `--hwmon-disable` evita pausas de temperatura en VMs sin GPU dedicada.
- Cisco Type 7 es XOR reversible, NO hashcat: usar script o web online.
- `grep -rao` (flag -a) fuerza lectura de binarios como texto — `strings` puede perder datos.
- hashcat --example-hashes muestra el formato exacto de cada modo para comparar.

## References
- Relacionado: [[password-spray]], [[active-directory-attacks]], [[netexec-crackmapexec]], [[gtfobins-binaries]], [[web-app-attacks]]
- Notas internas de cracking de contraseñas.
- Notas de lab web.
- Notas de lab interno (host DMZ).
