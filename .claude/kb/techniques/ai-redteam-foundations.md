---
title: AI Red-Team Foundations (ML basics + threat model + workflow)
slug: ai-redteam-foundations
category: techniques
updated: 2026-06-30
summary: "ML/DL basics, OWASP ML/LLM Top 10, SAIF, GenAI attack surfaces"
tags: [fundamentals, ml-basics, owasp-ml, owasp-llm, saif, threat-model, infosec-ml]
sensitive: false
---

# AI Red-Team Foundations

## When to use
Primer de referencia rápida antes de un assessment de AI: conceptos ML/DL,
taxonomías de amenazas (OWASP ML/LLM, SAIF), superficies de ataque, y modelos de
ML usados en infosec. Punto de partida para clasificar un hallazgo.

## Key facts / commands

### ML basics
- **Supervised** → clasificación/regresión (datos etiquetados).
- **Unsupervised** → clustering (K-Means), reducción dim (PCA).
- **Reinforcement** → agente+entorno+recompensa. `Q(s,a) += α[r + γ·max Q(s',a') − Q(s,a)]`.

| Arquitectura | Uso |
|---|---|
| CNN | imágenes |
| RNN | secuencias |
| LSTM/GRU | secuencias largas (evita vanishing gradient) |
| Transformer | atención multi-cabeza; base de LLMs |
| GAN | generación (Generator vs Discriminator, minimax) |
| Diffusion | denoising iterativo (imágenes) |

Fórmulas: Sigmoid `1/(1+e^-z)`; Softmax `e^zᵢ/Σe^zⱼ`; Cross-Entropy `-Σ yᵢ log ŷᵢ`; Gini `1-Σpᵢ²`.
Métricas: Precision `TP/(TP+FP)`, Recall `TP/(TP+FN)`, F1 `2PR/(P+R)`, AUC-ROC (0.5 random, 1.0 perfecto).
Overfitting (train>>test) → memoriza → **vulnerable a MIA**. Mitiga: L1/L2, dropout.

### Threat model — OWASP ML Top 10
| ID | Nombre | Resumen |
|---|---|---|
| ML01 | Input Manipulation | adversarial examples |
| ML02 | Data Poisoning | corromper training data |
| ML03 | Model Inversion | reconstruir training data desde outputs |
| ML04 | Membership Inference | ¿estuvo X en training? |
| ML05 | Model Theft | extraer/replicar modelo vía API |
| ML06 | Supply Chain | modelos/datasets de terceros comprometidos |
| ML07 | Transfer Learning | backdoors heredados del modelo base |
| ML08 | Model Skewing | sesgar predicciones |
| ML09 | Output Integrity | manipular outputs |
| ML10 | Model Poisoning | comprometer pipeline de training |

### Threat model — OWASP LLM Top 10
| ID | Nombre |
|---|---|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Info Disclosure |
| LLM03 | Supply Chain |
| LLM04 | Data & Model Poisoning |
| LLM05 | Improper Output Handling (→ XSS/SQLi/RCE) |
| LLM06 | Excessive Agency (→ Rogue Actions) |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector/Embedding Weaknesses (RAG) |
| LLM09 | Misinformation (hallucinations) |
| LLM10 | Unbounded Consumption (DoS) |

ML Top 10 = modelos ML en general; LLM Top 10 = específico de LLMs.

### Superficies de ataque GenAI + SAIF
4 superficies: **MODEL** (adversarial, theft, inversion) · **DATA** (poisoning,
trojan, label flipping) · **APPLICATION** (prompt injection, XSS via output,
function call abuse) · **SYSTEM** (RCE por deserialization, CVEs en frameworks,
misconfig). Despliegue: `[User] → [App: web/API/plugins/RAG] → [LLM/Model] → [Data/Tools]`.
Google SAIF 4 áreas: Data, Infrastructure, Model, Application.

**Training-time vs inference-time** (distinción clave): poisoning/trojan/label-flipping
= training; adversarial examples / prompt injection = inference.

```python
# Label flipping (data poisoning, training-time). 60% flip → desplaza decision boundary
idx = np.random.choice(len(y), size=int(len(y)*0.6), replace=False)
y_poisoned = y.copy(); y_poisoned[idx] = 1 - y_poisoned[idx]
```

### ML aplicado a infosec (modelos que verás como targets)
| Dominio | Técnica | Dataset | Submit |
|---|---|---|---|
| Spam | Naive Bayes + CountVectorizer(ngram 1-2) | SMS Spam (UCI) | `.joblib` :8000 |
| Network anomaly | Random Forest (n=100) | NSL-KDD (Normal+4 ataques) | `.joblib` :8001 |
| Malware | ResNet50 transfer learning (fc→25) | Malimg (PE→grayscale 32x32) | `.pth` :8002 |

## Gotchas
- `torch.load(..., weights_only=True)` SIEMPRE → evita RCE por deserialization (ML08/SYSTEM).
- Transfer learning hereda backdoors del modelo base (ML07) y reutiliza capas, solo se
  reemplaza la capa de clasificación final.
- Excessive Agency (LLM06): LLM con más permisos de los necesarios → Rogue Actions.
- Q-learning es model-free (no requiere modelo del entorno).

## References
- Relacionado: [[prompt-injection]], [[data-poisoning]], [[adversarial-evasion]], [[ai-privacy-attacks]], [[attacking-ai-llm]], [[ai-defenses]]
- Lecciones_01_FundamentalsOFAI.md
- Lecciones_02_ApplicationsOfAIInInfosec.md
- Lecciones_03_IntroductionToRedTeamingAI.md
