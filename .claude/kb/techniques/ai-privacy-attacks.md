---
title: AI Privacy Attacks (MIA / Inversion / Extraction) + DP defenses
slug: ai-privacy-attacks
category: techniques
updated: 2026-06-30
summary: "Membership inference, model inversion/extraction; DP-SGD/PATE defenses"
tags: [mia, membership-inference, model-inversion, differential-privacy, dp-sgd, pate, owasp-ml]
sensitive: false
---

# AI Privacy Attacks

## When to use
Evaluar fuga de privacidad en modelos ML: determinar si un sample estuvo en el
training set (MIA), reconstruir datos (inversion), o robar el modelo (extraction).
Incluye defensas DP para las secciones de remediación. OWASP: ML03 (inversion),
ML04 (membership inference), ML05 (model theft).

## Key facts / commands

| Ataque | Pregunta / objetivo | Root cause / oracle |
|---|---|---|
| Membership Inference (MIA) | ¿estuvo X en training? | overfitting: train_acc >> test_acc |
| Model Inversion (ML03) | reconstruir training data desde outputs | confianza/gradientes filtran rasgos |
| Model Extraction (ML05) | replicar modelo vía API | query API → entrenar clon |

MIA — Attack Advantage = `accuracy - 0.5` (cuánto mejor que random).
Gap 0% → adv ≈ 0; gap 10% → adv ≈ 0.10. **>5% serio, >10% crítico.**

### Confidence-threshold MIA (más simple)
```python
# max(softmax) como proxy de membresía: members tienen mayor confianza
member_conf    = get_max_confidence(model, X_members, device)   # F.softmax(logits).max(1)
nonmember_conf = get_max_confidence(model, X_nonmembers, device)
all_conf   = np.concatenate([member_conf, nonmember_conf])
all_labels = np.concatenate([np.ones(len(member_conf)), np.zeros(len(nonmember_conf))])
best_acc = 0.0
for t in np.percentile(all_conf, np.linspace(0, 100, 1000)):  # threshold óptimo
    acc = np.mean(((all_conf >= t).astype(int)) == all_labels)
    best_acc = max(best_acc, acc)
advantage = best_acc - 0.5
```

### Shadow model MIA (más sofisticado)
```python
# 1. Entrenar N shadows en subsets conocidos (subset_size = n//2)
# 2. Attack model binario. Features = [predict_proba + one_hot(label)]
attack_features = np.concatenate([probs, np.eye(num_classes)[labels]], axis=1)
attack_model = LogisticRegression().fit(scaler.fit_transform(X_attack), y_attack)
# 3. Aplicar a target: target_model.predict_proba(X_eval) → mismas features
```
Falla si: arquitectura / distribución / fine-tuning del target difieren del shadow.

### Defensa — Differential Privacy
`(ε, δ)-DP: P[M(D)∈S] ≤ e^ε · P[M(D')∈S] + δ`  (D, D' difieren en 1 sample).
ε pequeño = más privacidad; δ ≈ 1e-5 = prob. de fallo de la garantía.

**DP-SGD** (no requiere datos públicos; privacidad crece con epochs):
```python
from opacus import PrivacyEngine
from opacus.validators import ModuleValidator
model = ModuleValidator.fix(model)          # BatchNorm → GroupNorm (BatchNorm INCOMPATIBLE)
privacy_engine = PrivacyEngine(accountant='rdp')  # RDP da bounds más tight
model, optimizer, train_loader = privacy_engine.make_private_with_epsilon(
    module=model, optimizer=optimizer, data_loader=train_loader,
    target_epsilon=10.0, target_delta=1e-5, epochs=20, max_grad_norm=1.0)  # clip
# Opacus: per-sample grad → clip → Gaussian noise. ε final: privacy_engine.get_epsilon(1e-5)
```
| ε | Ruido | Accuracy (CIFAR) | MIA adv |
|---|---|---|---|
| ∞ (sin DP) | ninguno | 77% | 1.9% |
| 10 | bajo (mult ~1.2) | 58% | 0.8% |
| 3 | alto (mult ~3.8) | 53% | 0.4% |

**PATE** (requiere datos públicos; privacidad crece con queries):
```python
# 250 teachers en particiones DISJUNTAS de datos privados → votan en datos públicos
def noisy_argmax(votes, noise_scale=20.0):           # per-query ε = 2/noise_scale = 0.1
    return np.argmax(votes.astype(float) + np.random.laplace(0, noise_scale, votes.shape), 1)
def confident_aggregation(votes, threshold=200, noise_scale=20.0):
    confident = votes.max(1) >= threshold            # ~85% aceptación con 200/250
    # queries rechazadas consumen 0 presupuesto. Student entrena en pseudo-labels
# Advanced composition (NO naive k·ε): 5K queries, noise_scale=20 → ε≈8.81 (vs naive 500)
```

| Aspecto | DP-SGD | PATE |
|---|---|---|
| Datos públicos | No | Sí |
| Privacidad crece con | epochs | queries |
| Restricción | No BatchNorm | partición disjunta |
| Accuracy típica | 53-58% (CIFAR) | ~88% (MNIST) |
| MIA advantage | 0.4-0.8% | ~3% |

### Submission (assessment)
```python
from safetensors.torch import save_file
state = model._module.state_dict() if hasattr(model,'_module') else model.state_dict()
save_file(state, 'dp_model.safetensors')   # .safetensors, NO .pth
requests.post(f'{BASE_URL}/validate', files={'model':('dp_model.safetensors', open('dp_model.safetensors','rb'),'application/octet-stream')})
# Devuelve {passed, accuracy, mia_advantage, flag}. Criterio: acc>=70%, mia_adv<=3% (≥40% reducción)
```

## Gotchas
- `ModuleValidator.fix()` SIEMPRE antes de `make_private_with_epsilon()`.
- DP-SGD wrappea el modelo en Opacus → guardar `model._module.state_dict()`.
- Submit `.safetensors`, no `.pth`. Endpoint DP-SGD `/validate`, PATE `/submit`.
- PATE information bottleneck: 150MB datos privados → ~2.5KB labels (limitación fundamental).
- Shadow MIA: si target difiere en arquitectura/distribución/fine-tuning, falla.

## References
- Relacionado: [[data-poisoning]], [[adversarial-evasion]], [[ai-defenses]], [[ai-redteam-foundations]], [[attacking-ai-llm]]
- Lecciones_11_AIPrivacy.md
- 08_AI_PRIVACY_ATTACKS_CHEATSHEET.md
