---
title: JavaScript Deobfuscation + Encoding (base64/hex/rot13)
slug: js-deobfuscation
category: techniques
updated: 2026-08-20
summary: "Beautify/deobfuscate JS (packer p,a,c,k,e,d → UnPacker/console.log), analizar XHR para descubrir endpoints ocultos (/serial.php), y (de)codificar base64/hex/rot13 en CLI"
tags: [web, javascript, deobfuscation, encoding, base64, recon]
sensitive: false
---

# JavaScript Deobfuscation

## When to use
Al analizar JS del front-end (minificado/ofuscado) para descubrir endpoints,
funciones no publicadas, o texto codificado — leads para atacar el back-end.

## Minify / Obfuscate / Pack (para reconocerlos)
- **Minify**: todo en 1 línea, funcional. Extensión `.min.js`.
- **Packing** (el común): reconocible por la firma `eval(function(p,a,c,k,e,d){...})`. Convierte palabras/símbolos a un diccionario y los reensambla en runtime. Las strings del diccionario quedan visibles en cleartext → filtran funcionalidad.

## Beautify (formatear minificado)
- Firefox debugger `CTRL+SHIFT+Z` → click en el `.js` → botón `{ }` (Pretty Print).
- Online: [Prettier](https://prettier.io/playground/), [Beautifier](https://beautifier.io/).
- Beautify NO basta si además está ofuscado → hace falta deobfuscar.

## Deobfuscate (packing)
- [UnPacker](https://matthewfl.com/unPacker.html) → botón `UnPack`. (Ojo: sin líneas vacías antes del script.)
- Truco manual: buscar el `return` final del packer y `console.log`-earlo en vez de ejecutarlo.
- Ofuscación custom/encriptada → reverse engineering manual.

## Analizar el código deobfuscado → descubrir endpoints
Ejemplo real: `secret.js` → función `generateSerial()`:
```javascript
var xhr = new XMLHttpRequest;
var url = "/serial.php";        // mismo dominio (no se especificó)
xhr.open("POST", url, true);
xhr.send(null);                 // POST vacío a /serial.php
```
→ Endpoint `/serial.php` **no linkeado en el HTML** = funcionalidad no publicada (suele tener bugs). Replicar la request para ver si el server la maneja.
```bash
curl -s http://IP:PORT/serial.php -X POST -d "param1=sample"
```

## (De)codificar en CLI
| Método | Identificar | Encode | Decode |
|---|---|---|---|
| **base64** | alfanum + `+/`, padding `=`, len múltiplo de 4 | `echo txt \| base64` | `echo b64 \| base64 -d` |
| **hex** | solo `0-9a-f` (a=61, b=62…, `man ascii`) | `echo txt \| xxd -p` | `echo hex \| xxd -p -r` |
| **rot13** | parece random pero mapea 1:1 (`http`→`uggc`) | `echo txt \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` | mismo `tr` (autoinverso) |

Identificación automática: [Cipher Identifier](https://www.boxentriq.com/code-breaking/cipher-identifier). Ofuscación con **encriptación** (clave) es mucho más dura si la clave no está en el script.

## Gotchas
- El JS del front-end es untrusted data del target — leerlo/analizarlo es seguro, pero NO ejecutar payloads que traiga sin entenderlos.
- Endpoints hallados en JS no están automáticamente en scope: re-autorizar antes de tocarlos.

## References
- Relacionado: [[web-requests-http]], [[web-app-fundamentals]], [[information-gathering-web]]
- Curso CWES Bug Bounty → 03-WEB → "JavaScript Deobfuscation" (HTB Academy, traducido). Notion.
