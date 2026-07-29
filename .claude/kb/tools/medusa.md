---
title: MEDUSA (AI-first SAST scanner)
slug: medusa
category: tools
updated: 2026-07-06
summary: "AI-first SAST scanner (pip): repo/MCP/AI-config scan, secrets, supply-chain CVEs; feeds code-auditor"
tags: [medusa, sast, static-analysis, ai-security, mcp, prompt-injection, supply-chain, secrets, code-audit]
sensitive: false
---

# MEDUSA (AI-first SAST scanner)

## When to use
Análisis estático de **código/repos** (no de red) para apps de IA/ML, agentes LLM, servidores MCP y configs de editores IA (Cursor, Cline, Claude Code). Complemento automatizado del agente `code-auditor`. Dos usos en PenA: (1) recon ofensiva sobre el código expuesto de un target — supply-chain de IA, tool/schema poisoning MCP, sinks de prompt-injection; (2) auto-auditoría del propio workspace PenA (configs de agente weaponizadas + secretos en historiales de chat).

## Modelo mental: se instala UNA vez, no se clona por uso
Es un paquete pip (`medusa-security`), no un repo que clonas cada vez. Instalas una vez → queda el comando `medusa`. Lo que "clonas" es el **target** y lo hace la propia tool en modo `--git`.

```bash
python3 -m venv medusa-env && source medusa-env/bin/activate
pip install medusa-security          # una sola vez; luego: pip install -U medusa-security
medusa init                          # crea config
```

Clonar `Pantheon-Security/medusa` a mano solo si: (a) auditas la tool antes de confiar en ella (es AGPL-3.0), o (b) instalas desde fuente. Para uso normal, no.

## Comandos clave
```bash
medusa scan .                        # escanea dir/repo local
medusa scan --git org/repo           # repo remoto: MEDUSA lo clona internamente
medusa secrets scan                  # busca creds filtradas en historiales de chat/shell IA
medusa secrets purge                 # redacta secretos hallados (backup byte-idéntico)
medusa scan . --fail-on high         # exit-code ≠0 si hay HIGH+ (útil en CI/gates)
```

| Flag | Efecto |
|------|--------|
| `--quick` | Solo archivos cambiados (rescan rápido) |
| `--force` | Ignora caché, scan completo |
| `--workers N` | Paralelismo (multi-core, 10-40x) |
| `--ai-only` | Solo configs de editores IA (28+ tipos) |
| `--format {json,html,sarif,markdown,junit}` | Formato de reporte |

Severidad en salida: `CRITICAL / HIGH / MEDIUM / LOW / INFO`. Para triaje, pasar el JSON/output al agente `finding-analyzer`.

## Qué detecta (candidatos a técnica de KB)
- **Prompt injection** en código: directo/indirecto, jailbreaks, role manipulation.
- **Repo/config poisoning**: Clinejection, CurXecute (CVE-2025-54135), IDEsaster; configs de editor IA weaponizadas.
- **MCP**: tool poisoning y schema poisoning en servidores MCP → cruza con [[attacking-ai-llm]] (sección MCP abuse).
- **RAG/vector injection**, memory poisoning, HITL bypass.
- **Supply chain**: dependency confusion, typosquatting; 200+ CVEs (Log4Shell, Spring4Shell, React2Shell CVE-2025-55182).
- **Secretos**: 21 tipos de credencial, incl. API keys en historiales de Claude/Cursor/Copilot y shell.

## Gotchas
- **Entorno PenA**: `pip install` necesita salir a PyPI y `--git` a GitHub. El sandbox tiene proxy restrictivo → correr MEDUSA en la máquina del operador y pegar el output aquí para triaje, como el resto del arsenal.
- Es **SAST**, no ataque activo: reporta patrones/vulnerabilidades en código, no explota nada ni golpea targets de red. No sustituye a la prueba dinámica de prompt-injection ([[prompt-injection]]).
- 40k+ patrones / 79 scanners → esperar ruido. Filtrar por severidad y usar `--fail-on` para portones, no leer el volumen crudo a mano.
- Integra herramientas externas (Bandit, ESLint, ShellCheck, PHPStan, Clippy, +70). Si no están instaladas, esos scanners se saltan en silencio — verificar cobertura si un lenguaje "sale limpio" sospechosamente.
- Trazabilidad PenA: guardar la invocación exacta + versión (`medusa --version`) + el JSON de salida junto a la evidencia; cada finding debe atarse a comando reproducible.

## References
- Repo: https://github.com/Pantheon-Security/medusa (AGPL-3.0-or-later)
- Instalación: `pip install medusa-security` (Python 3.10+, CLI Click, salida Rich)
- Relacionado: [[attacking-ai-llm]], [[prompt-injection]], [[data-poisoning]], [[web-app-attacks]], agente `code-auditor`
