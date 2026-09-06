---
title: Web App Fundamentals (arquitectura, front/back, OWASP Top 10)
slug: web-app-fundamentals
category: techniques
updated: 2026-08-20
summary: "Mapa mental de app web para pentest: modelos de infra, 3-tier, front/back, view-source (sensitive data exposure), HTML injection, y los OWASP Top 10 → módulos profundos"
tags: [web, recon, owasp, architecture, methodology]
sensitive: false
---

# Web App Fundamentals

## When to use
Primer contacto con una app web: entender su arquitectura, dónde vive cada
vulnerabilidad, y qué revisar primero (low-hanging fruit) antes de ir a fondo.

## Modelos de infraestructura
| Modelo | Nota de seguridad |
|---|---|
| Client-Server | Base; front-end (browser) + back-end (server) |
| One Server | "Todos los huevos en una cesta": comprometer 1 app = todo el server |
| Many Servers – One DB | Segmentación: comprometer un web server no toca los otros; SQLi en DB no toca la app directamente |
| Many Servers – Many DB | Mejor postura: segmentación + redundancia (load balancers) |
| Serverless / Microservicios | Contenedores stateless; cada micro puede estar en distinto lenguaje; comunicación stateless |

## Arquitectura 3-tier
- **Presentación** → HTML/CSS/JS (client-side).
- **Aplicación** → procesa requests, checa authz/privilegios/datos.
- **Datos** → dónde se almacenan/acceden los datos.
Vulnerabilidad puede venir de **error de diseño** (falta de RBAC → user llega a admin), no solo de código.

## Front-end vs Back-end
- **Front-end** = client-side (HTML/CSS/JS interpretado por el browser). Atacarlo pone en riesgo al **usuario** (no daño directo al core), pero puede escalar a admin → comprometer el server.
- **Back-end** = server, web server (Apache/NGINX/IIS), DB (MySQL/MSSQL/Oracle/PostgreSQL/Mongo), frameworks (Laravel/PHP, ASP.NET/C#, Spring/Java, Django/Python, Express/Node).
- **Whitebox** = con código fuente (front siempre; back si open-source o vía LFI). **Blackbox** = sin código.

## Sensitive Data Exposure (primer low-hanging fruit)
Datos sensibles en texto plano en el **código fuente del front-end**.
```
Ctrl+U  |  clic derecho → View Page Source  |  view-source:https://target/
```
Buscar en HTML/comentarios/JS externo: `<!-- TODO: remove test creds test:test -->`, hashes, endpoints/directorios ocultos, params de debug, funcionalidad oculta. **Primer paso en todo assessment web.** Deshabilitar clic-derecho NO protege (Ctrl+U / proxy). Devs mitigan con packing/ofuscación de JS.

## HTML Injection
Input de usuario sin sanitizar renderizado en la página (recuperado de DB o mostrado directo por JS front-end). Impacto: phishing (form de login falso que exfiltra creds), defacement.
```html
Nombre: <style> body { background-image: url('//attacker/x.svg'); } </style>
```
Si es puro front-end, refrescar revierte. Es el paso previo natural a **XSS** (ver [[xss]]).

## Vulnerabilidades comunes (ejemplos rápidos)
| Vuln | Ejemplo |
|---|---|
| Broken Auth / Access Control | `College Management System 1.2` login bypass: email `' or 0=0 #` + cualquier pass |
| Malicious File Upload | WP `Responsive Thumbnail Slider 1.0`: doble extensión `shell.php.jpg` (módulo MSF) |
| Command Injection | WP `Plainview Activity Monitor 20161228`: `| COMMAND...` tras el valor `ip` |
| SQL Injection | `$query="select * from users where name like '%$searchInput%'"` sin sanitizar |

## Flujo de vulnerabilidades públicas
1. **Identificar versión** de la app (source code, `version.php`, repo si open-source).
2. Buscar exploits: [Exploit-DB](https://www.exploit-db.com/), [Rapid7 DB](https://www.rapid7.com/db/), Google. Priorizar **CVSS 8-10 / RCE**.
3. Incluir componentes externos (plugins) en la búsqueda.
- **CVSS**: Base (0-10) + Temporal + Environmental. V3 severidad: None 0 / Low .1-3.9 / Med 4-6.9 / High 7-8.9 / Crit 9-10. NVD solo da Base.
- Back-end público crítico = web server (accesible por TCP), p. ej. Shellshock (Apache ≤2014 vía HTTP). DB/back-end suelen explotarse post-acceso local.

## OWASP Top 10 (2021) → módulos profundos
1. Broken Access Control → [[web-app-attacks]]
2. Cryptographic Failures
3. Injection → [[sql-injection]], [[command-injection]], [[xss]]
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable/Outdated Components → vulns públicas (arriba)
7. Identification & Auth Failures → [[broken-authentication]]
8. Software/Data Integrity Failures
9. Logging & Monitoring Failures
10. SSRF → [[server-side-attacks]]

## References
- Relacionado: [[web-requests-http]], [[xss]], [[sql-injection]], [[web-app-attacks]], [[information-gathering-web]]
- Curso CWES Bug Bounty → 03-WEB → "Introduction to Web Applications" (HTB Academy, traducido). Notion.
