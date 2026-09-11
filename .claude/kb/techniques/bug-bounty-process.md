---
title: Bug Bounty Process (programas, reporte, CVSS, interacción)
slug: bug-bounty-process
category: techniques
updated: 2026-08-20
summary: "Proceso BBP: private/public/VDP vs BBP, leer policy+scope+safe harbor, anatomía de buen reporte (título/CWE/CVSS/PoC/impacto/remediación), calculadora CVSS 3.1, cómo interactuar con triage"
tags: [bug-bounty, reporting, cvss, cwe, methodology, disclosure]
sensitive: false
---

# Bug Bounty Process

## When to use
Metodología y comunicación en bug bounty / disclosure: elegir programa, mantenerse
en scope, y escribir un reporte que se triee rápido. Deriva del framework Gekko-Lite:
el reporte real es proyección de findings confirmados (ver report-writer / findings.py).

## Tipos de programa
- **Private BBP**: solo por invitación (según track record / historial de violaciones; a veces background check).
- **Public BBP**: abierto a toda la comunidad.
- **Parent/Child**: pool de recompensas compartido entre matriz y filiales.
- **VDP ≠ BBP**: VDP solo da guía de cómo reportar (sin recompensa monetaria); BBP incentiva con pago. No confundir.

## Antes de testear — leer la policy (scope es ley)
Un programa incluye: SLAs, Access (cómo crear cuentas de research), Eligibility, Responsible Disclosure, **Rules of Engagement**, **Scope / Out of Scope** (IPs/dominios/vulns), Reporting Format, Rewards, **Safe Harbor**, T&C legales, contacto.
- Leer meticulosamente policy + código de conducta → cumplir expectativas, evitar idas y vueltas.
- Directorio de programas: HackerOne Directory. Respetar scope y out-of-scope al pie (mismo principio que [[scope]] del engagement).

## Anatomía de un buen reporte
| Elemento | Nota |
|---|---|
| **Título** | tipo de vuln + dominio/param/endpoint + impacto |
| **CWE + CVSS** | lenguaje común (CWE) + severidad estándar (CVSS); en cadena, elegir el CWE de la vuln inicial |
| **Descripción** | causa raíz, entendible (traducir a términos de negocio si la org es menos madura) |
| **PoC** | **pasos exactos para reproducir**, claros y concisos — lo más importante |
| **Impacto** | qué logra el atacante + impacto de negocio / daño máximo |
| **Remediación** | opcional en BBP, buena de tener |
Reporte legible = menos tiempo de reproducción y triage. Corrobora antes de reportar (bar del framework: nada entra como confirmado con una sola señal, ver [[web-app-fundamentals]] / style).

## CVSS 3.1 — Base metrics (calculadora FIRST)
- **Attack Vector**: Network (remoto) / Adjacent (misma red/VPN) / Local / Physical.
- **Attack Complexity**: Low (sin prep) / High (requiere condiciones fuera de control).
- **Privileges Required**: None / Low (user) / High (admin).
- **User Interaction**: None / Required.
- **Scope**: Unchanged / Changed (afecta componentes fuera de la autoridad del vulnerable — ej. XSS: server→browser).
- **C / I / A**: None / Low / High cada una.
Ejemplos: RCE preauth expuesto a internet ≈ 9.8 Crítica (N/L/N/N/U/H/H/H). Stored XSS en panel admin (admin→admin) ≈ 5.5 Media (N/L/H/N/**C**/L/L/N).

## Interacción con el equipo de triage
1. Tras enviar, **no molestar** — dar tiempo (respetar SLA), no spamear.
2. Sin respuesta razonable → Mediación de la plataforma.
3. Cuando respondan, anotar el username del triager y etiquetarlo; solo canales oficiales (nunca redes sociales).
4. Desacuerdo de severidad/recompensa: justificar cada métrica CVSS, contrastar contra policy/scope, y si no → mediación. Comunicación profesional siempre.

## Gotchas
- El historial de violaciones del hunter pesa → adherir al código de conducta sí o sí.
- Out-of-scope no se toca ni "para demostrar impacto" salvo que la policy lo permita.

## References
- Relacionado: [[web-app-fundamentals]], [[web-app-attacks]], [[information-gathering-web]]
- HackerOne (policy/scope/CVSS calc FIRST). Curso CWES Bug Bounty → 03-WEB → "Bug Bounty Proceso" (HTB Academy). Notion.
