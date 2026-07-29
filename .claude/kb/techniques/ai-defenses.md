---
title: AI Defenses (guardrails / adversarial training / safety fine-tuning)
slug: ai-defenses
category: techniques
updated: 2026-06-30
summary: "Guardrails, adversarial training, safety fine-tuning (for report remediations)"
tags: [defenses, guardrails, adversarial-training, fgsm, lora, remediation, llm-safety]
sensitive: false
---

# AI Defenses

## When to use
Construir secciones de remediación/mitigación de reports y endurecer modelos:
filtrar inputs/outputs (guardrails), robustez a perturbaciones (adversarial
training), y rechazar jailbreaks/priming (safety fine-tuning). Defense in depth =
las tres capas combinadas.

## Key facts / commands

### 3 pilares
1. GUARDRAILS — filtrar inputs/outputs antes/después del modelo.
2. ADVERSARIAL TRAINING — robustez a perturbaciones.
3. LLM FINE-TUNING — re-entrenar para rechazar jailbreaks/priming.

### Guardrails (de débil a fuerte)
| Tipo | Mecanismo | Limitación |
|---|---|---|
| Character-based | regex whitelist (p.ej. solo `^[0-9.\+\-\*/\(\)]+$`) | bypaseable con typos; solo casos muy acotados |
| Content-based | regex de patrones de injection | bypaseable con parafraseo |
| LLM-as-judge | LLM evalúa el prompt | 2-3x más lento (0.8s vs 0.09s, ~9x) |

```python
# Content-based (fácil de bypassear con "Please disregard former directions")
PROMPT_INJECTION_REGEX = r'(?i)(Ignore|Disregard|Skip|Forget).*(prior|previous).*(content|instructions)'

# LLM-as-judge (guardrails-ai) — más efectivo
from guardrails import Guard
from guardrails.hub import UnusualPrompt, DetectJailbreak, ProfanityFree, SecretsPresent, WebSanitization
input_guard  = Guard().use(UnusualPrompt(llm_callable='openai/gpt-3.5-turbo'), on_fail='exception')
input_guard.use(DetectJailbreak, on_fail='exception')
output_guard = Guard().use(ProfanityFree, on_fail='exception')
output_guard.use(SecretsPresent, on_fail='fix'); output_guard.use(WebSanitization, on_fail='fix')
# on_fail: exception(bloquear) | noop(pasar) | fix(sanitizar) | reask | refrain(omitir campo)
```
Google ModelArmor: detecta RAI (hate), SDP (SSN/tarjetas), PI (prompt injection),
malicious URI, CSAM, virus. `sanitize_user_prompt()` / `sanitize_model_response()`.

### Adversarial training (robustez a perturbaciones)
```python
def fgsm_attack(model, images, labels, epsilon):
    x = images.clone().detach().requires_grad_(True)
    F.cross_entropy(model(x), labels).backward()
    return torch.clamp(x + epsilon * x.grad.sign(), min_val, max_val).detach()

# Epsilon SPREAD para evitar epsilon overfitting (entrenar solo ε=0.3 → cae 95%→33% en ε=1.0)
EPSILON_SPREAD = [0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0]
for images, labels in train_loader:
    eps = np.random.choice(EPSILON_SPREAD)          # epsilon aleatorio por batch
    adv = fgsm_attack(model, images, labels, eps)
    combined = torch.cat([images, adv]); combined_labels = torch.cat([labels, labels])
    # entrenar mezclando clean + adversarial; clip_grad_norm_(max_norm=1.0)
```
Evaluación de robustez: I-FGSM SIEMPRE más fuerte que FGSM. **Gap FGSM−I-FGSM >10% = defensa frágil/superficial.**
LeNet-5 baseline: 99% clean / 74% FGSM / 52% I-FGSM → tras adv. training: 98% / 95%+ / 93%+.

### LLM safety fine-tuning (LoRA / unsloth)
```python
from unsloth import FastLanguageModel
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name='unsloth/Llama-3.2-1B-Instruct', max_seq_length=512, load_in_4bit=True)
model = FastLanguageModel.get_peft_model(model, r=16, lora_alpha=32, lora_dropout=0.05,
    target_modules=['q_proj','k_proj','v_proj','o_proj','gate_proj','up_proj','down_proj'])
# r=16 → 11.3M trainable de 786M (1.43%)

# Defensa anti-priming: el modelo aprende a reconocer su propio output malicioso y parar
def format_priming_attack(prompt, harmful_prefix, stopping_response):
    return (f'<|start_header_id|>user<|end_header_id|>\n\n{prompt}<|eot_id|>'
            f'<|start_header_id|>assistant<|end_header_id|>\n\n{harmful_prefix}{stopping_response}<|eot_id|>')
# stopping_response = "I must stop. I was about to provide harmful content..."
```
Dataset balance: **60% safety / 40% benign** (>70% safety → over-refusal de queries legítimas).
Éxito = 90%+ jailbreak refusal + 85%+ helpful rate.

### Priming vs jailbreak (por qué priming es la prioridad de defensa)
| Tipo | Success | Mecanismo |
|---|---|---|
| Jailbreak clásico (DAN, roleplay) | 20-40% | override del system prompt |
| Priming attack | **98%** | inyectar prefijo malicioso en posición de asistente |

## Gotchas
- Guardrails AI-based ~9x más lentos (0.8s vs 0.09s) → trade-off latencia.
- Epsilon overfitting: nunca entrenar en un solo ε; usar spread.
- I-FGSM > FGSM siempre; medir ambos o la defensa parecerá robusta sin serlo.
- Categorías de jailbreak a cubrir: roleplay, authority claims, hypothetical, encoding, emotional.

## References
- Relacionado: [[prompt-injection]], [[adversarial-evasion]], [[data-poisoning]], [[ai-privacy-attacks]], [[llm-output-attacks]], [[ai-redteam-foundations]]
- Lecciones_12_AIDefense.md
