---
title: Adversarial Evasion (FGSM/PGD/MI-FGSM, JSMA/ElasticNet, GoodWords)
slug: adversarial-evasion
category: techniques
updated: 2026-06-30
summary: "GoodWords; FGSM/I-FGSM/PGD/MI-FGSM/DeepFool; JSMA/sparsity; badge/digit classifier pipeline"
tags: [ml-security, evasion, adversarial-examples, fgsm, pgd, jsma, elasticnet, goodwords, owasp-ml01]
sensitive: false
---

# Adversarial Evasion

## When to use
Engañar a un clasificador ML en inferencia sin tocar el entrenamiento: spam/Naive
Bayes (GoodWords), imágenes/CNN (FGSM, I-FGSM, PGD, MI-FGSM, DeepFool, JSMA,
ElasticNet). Patrones típicos: **clasificador de badge** (visitor→admin con
MI-FGSM) y **clasificador de dígitos** (sparsity/JSMA-ElasticNet). OWASP ML01 Evasion.

## Normas de perturbación
| Norma | Fórmula | Pixels modif. | Ataque |
|---|---|---|---|
| L∞ | max(|δᵢ|) | ~100% | FGSM, PGD, MI-FGSM |
| L2 | √Σδᵢ² | ~50-70% | DeepFool, ElasticNet |
| L1 | Σ|δᵢ| | sparse | ElasticNet |
| L0 | count(δᵢ≠0) | ~20-40 | JSMA |

Conversión epsilon (clave): `epsilon_pixel = std * epsilon_norm`. MNIST std=0.3081
→ eps_pixel 0.25 = 0.81 norm. CIFAR-10 típico: `8/255`.

---

## GOODWORDS (Naive Bayes spam)
Vulnerabilidad: NB en log-space es ADITIVO (`log P(D|C)=Σ log P(wᵢ|C)`) y asume
independencia → añadir palabras "ham" al spam sube P(ham) sin incoherencia.

White-box (acceso a `feature_log_prob_`):
```python
clf = joblib.load('spam_model.joblib')
vec, cls = clf.named_steps['vectorizer'], clf.named_steps['classifier']
ham_log, spam_log = cls.feature_log_prob_[0], cls.feature_log_prob_[1]
scores = [(w, np.exp(ham_log[i])/(np.exp(spam_log[i])+1e-10))
          for i,w in enumerate(vec.get_feature_names_out())]
scores.sort(key=lambda x:-x[1])           # top: 'lor'(50), 'meeting'(29), 'thanks'(25)
msg = spam + ' ' + ' '.join(w for w,_ in scores[:15])   # 15-20 palabras → 96%+ evasión
```
Black-box (solo `predict_proba`, 1000 queries split 40-40-20):
```python
# Fase1 explorar 400 / Fase2 explotar 400 (eps→0.1) / Fase3 combinar 200
alpha=0.3                                  # EMA
word_scores[w] = (1-alpha)*word_scores.get(w,0) + alpha*(baseline - augmented)
# epsilon-greedy: 80% mejor palabra, 20% nueva; UCB alt: avg + c*sqrt(ln(t)/n)
```
Curva sigmoid: 0-5 pal=6→41%, 5-15=41→96% (colapso), 15-20=96→100%. Threshold=0.5.
Buscar sinergias (pares 'meeting'+'tomorrow' > suma individual).
```bash
curl -s $BASE_URL/challenge | jq '.base_message,.max_added_words'
curl -X POST $BASE_URL/submit -d '{"augmented_text":"BASE w1 w2 ..."}'   # max 25 words
```

---

## FIRST-ORDER (imágenes, L∞/L2)
```python
# FGSM — 1 paso, sign del gradiente
def fgsm(model, x, y, eps, mean, std):
    xi = x.clone().detach().requires_grad_(True)
    F.cross_entropy(model(xi), y).backward()
    adv = xi + eps * xi.grad.sign()
    return torch.clamp(adv.detach(), (0-mean)/std, (1-mean)/std)
# Targeted: adv = x - eps*sign(∇ L(x, y_target)). L∞ óptimo: ε·sign(g)

# I-FGSM/BIM — iterativo, PROYECTAR respecto al ORIGINAL (no al paso anterior)
def i_fgsm(model, x, y, eps, steps=10, mean=0.1307, std=0.3081):
    alpha = eps/steps; adv = x.clone().detach(); orig = x.clone().detach()
    for _ in range(steps):
        adv.requires_grad_(True)
        F.cross_entropy(model(adv), y).backward()
        adv = adv.detach() + alpha*adv.grad.sign()
        pert = torch.clamp(adv - orig, -eps, eps)              # epsilon-ball vs original
        adv = torch.clamp(orig + pert, (0-mean)/std, (1-mean)/std)
    return adv
# PGD = I-FGSM + random start: x + uniform_(-eps,eps), + restarts (L∞ más fuerte, Madry)
```
Resultados MNIST: FGSM eps=0.8 → conf 98→39%, SR 68%. I-FGSM 10it → SR 100%.
Gap FGSM vs I-FGSM >10% = defensa frágil.

DeepFool (mínima perturbación L2, ~3 iter, overshoot 2%):
```python
# dist_k = |f_k - f_true| / ||∇f_k - ∇f_true||₂ ; elegir k mínimo
# r = (1+overshoot) * (|f_k|/||grad_k||²) * grad_k   ; overshoot=0.02 cruza boundary real
# MNIST: L2 medio 4.87 (0.60-7.72)
```

---

## SPARSITY (L0/L1)
```python
# JSMA — Jacobian Saliency Map (L0). Jacobiana = M backward passes (uno por clase)
def jacobian(model, x_flat, C=10):
    jac = torch.zeros(C, x_flat.numel()); xv = x_flat.clone().requires_grad_(True)
    logits = model(xv.view(1,1,28,28))           # USAR LOGITS, no probabilidades
    for c in range(C):
        model.zero_grad(); xv.grad and xv.grad.zero_()
        logits[0,c].backward(retain_graph=True); jac[c] = xv.grad.flatten()
    return jac
def saliency(jac, target, mask):
    alpha = jac[target]; beta = jac.sum(0) - jac[target]
    cond = (alpha>0) & (beta<0) & mask           # subir target, bajar competidores
    return np.argmax(alpha * np.abs(beta) * cond)
# pairwise (α_pq=α_p+α_q): top_k=128 → O(n²)→O(k²), SR ~90%
# eliminar saturados: (x<=clip_min+eps)|(x>=clip_max-eps) → quitar de search_space
```
```python
# ElasticNet/EAD (L1+L2): minimize c·L_adv + ||δ||²₂ + β·||δ||₁  (FISTA + binary search c)
def soft_threshold(z, t):                         # operador proximal L1 → EXACTOS ceros
    return torch.sign(z) * torch.clamp(torch.abs(z) - t, min=0)
def ead_fista(model, x0, target, c=0.1, beta=0.01, lr=0.01, max_iter=200):
    y = x0.clone(); t_old = 1.0; x_adv = x0.clone()
    for k in range(1, max_iter+1):
        yv = y.clone().requires_grad_(True); logits = model(yv.unsqueeze(0))
        loss = c*(-logits[0,target] + torch.logsumexp(logits[0],0)) + torch.sum((yv-x0)**2)
        loss.backward()
        x_new = soft_threshold(yv.detach()-lr*yv.grad - x0, lr*beta) + x0
        x_new = torch.clamp(x_new, 0., 1.)
        t_new = (k+3)/3                            # Nesterov k/(k+3): 0.25→0.97
        y = x_new + ((t_old-1)/t_new)*(x_new-x_adv); x_adv, t_old = x_new, t_new
    return x_adv
# Binary search c: éxito→bajar upper; fallo→subir lower; c=(lower+upper)/2
```

---

## MI-FGSM TARGETED PIPELINE (patrón badge-classifier — white-box completo)
Badge classifier (visitor/employee/admin), tienes modelo+pesos, convertir a admin
imperceptible. Seis piezas ausentes en tutoriales básicos:
1. **MI-FGSM** momentum 0.9 (escapa mínimos locales).
2. **STE** (Straight-Through Estimator) para gradientes a través de uint8/PNG.
3. **Margin loss** (cross-entropy satura cuando prob→1).
4. **Protected region mask** (watermark/región protegida intocable).
5. **Proyectar respecto al ORIGINAL** en cada step.
6. **Verificación post-PNG** (recargar y re-check antes de submit).
```python
def target_margin(logits, t):                     # admin_logit - max(otros)
    other = torch.cat([logits[:,:t], logits[:,t+1:]], dim=1)
    return logits[:,t] - other.max(dim=1).values
loss = -target_margin(logits, target_class).mean()

def straight_through_quantize(cand, orig, mask, eps_u8):
    hard = uint8_project(cand, orig, mask, eps_u8)  # round*255, clamp eps, restaurar mask
    return cand + (hard - cand).detach()           # backward = identidad (round bloquea grad)

# MI-FGSM step:
grad_norm = gradient.abs().mean(dim=(1,2,3), keepdim=True).clamp_min(1e-12)
momentum = 0.90*momentum + gradient/grad_norm
adversarial = adversarial - alpha * momentum.sign() * allowed_mask   # solo pixels permitidos
delta = torch.clamp(adversarial - original, -epsilon, epsilon)       # proy. vs ORIGINAL
adversarial = torch.clamp(original + delta*allowed_mask, 0, 1)
# restarts>=5, steps~500, margin_goal=0.25 early-stop si argmax==target
```
Preprocesar EXACTO como el servidor (error aquí = funciona local, falla en submit):
blanquear región protegida ANTES de grayscale; grayscale BT.601 (`0.2989/0.5870/0.1140`,
NO BT.709); resize `mode='nearest'` (NO bilinear); normalización exacta `(x-0.5)/0.25`.

## Verificación de constraints (antes de submit)
```python
delta = adv - orig
print(f"L0={(delta!=0).sum()} L1={delta.abs().sum():.2f} L2={torch.norm(delta):.2f} "
      f"Linf={delta.abs().max():.4f} elastic={torch.norm(delta)**2 + beta*delta.abs().sum():.2f}")
# El challenge valida VARIAS normas a la vez (elastic <= elastic_max, l2, l1)
```

## Gotchas
- I-FGSM/PGD: proyectar respecto al ORIGINAL tras cada paso, no al paso anterior.
- JSMA/ElasticNet: gradientes en LOGITS, no probabilidades (softmax acopla clases → señal contaminada).
- PNG guarda uint8 → `round()` mata gradientes: usar STE. Y verificar SOBRE el PNG recargado, no el tensor.
- Margin loss > cross-entropy en targeted cuando la brecha entre clases es pequeña.
- soft_threshold crea ceros EXACTOS (≠ clamp) → sparsity real en ElasticNet.
- Tras submit exitoso: reusar `requests.Session()`; el endpoint admin suele venir en `next_step` del JSON (cookies heredadas).
- Black-box imagen: entrenar surrogate con queries y atacar el surrogate (transferabilidad).
- JSMA inviable en ImageNet (1000 clases × backward × iters) → MNIST/CIFAR-10.

## References
- Relacionado: [[data-poisoning]], [[ai-defenses]], [[ai-privacy-attacks]], [[ai-redteam-foundations]]
- Lecciones_08_AIEvasion.md, Lecciones_09_AIEvasionFirstOrderAttack.md,
  Lecciones_10_AIEvasionSparsityAttacks.md, 05_AI_EVASION_CHEATSHEET.md
