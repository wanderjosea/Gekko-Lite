---
name: engagement-init
description: >
  Scaffold a new engagement working directory under engagements/ with the Gekko-Lite
  standard layout (AUTHORIZATION.md + notes.md skeleton, scripts/, canaries/,
  loot/creds vault). Use when starting a new authorized target ("new engagement",
  "set up the box", "scaffold a new target"), before recon begins. Creates only the
  folder structure — does not touch the target.
---

# Engagement init (scaffold)

Create the standard workdir for a new authorized target. Confirm the target is in
scope (`scope.md`) before creating anything. For a **paying client**, use a
**codename** as `<NAME>` (real org/PII never lands in a committed path) and fill
`AUTHORIZATION.md` before any active testing — see `rules/engagement-authorization.md`.

## Layout
```
engagements/<codename>/
├── AUTHORIZATION.md  # client: signed-order ref, scope, testing window, contacts, retention
├── notes.md          # central log — numbered phases (see pentest-cycle skill)
├── scripts/          # numbered, reproducible phase scripts: 01_recon.sh …
├── canaries/         # callback/canary test files (optional, web/print targets)
└── loot/             # captured creds/hashes/dumps — creds.md vault (stays in this private repo)
```

## Scaffold command
Replace `<ip>` and `<NAME>`; for a client use a **codename** as `<NAME>`. Pick the
VPN mode from CLAUDE.md.
```bash
IP=<target-ip>; NAME="<CODENAME>"
D="engagements/$NAME"
mkdir -p "$D"/{scripts,canaries,loot}
cat > "$D/notes.md" <<EOF
# $NAME — $IP — Notas de engagement

Modo VPN: <Full | Restricted>  (ver CLAUDE.md / toolbox/vpn-modes.md).
Workdir: \`$D/\`.

## 0. Autorización (scope) — llenar ANTES de tocar el target
Regla efectiva = la más restrictiva (ver \`scope.md\`). Fuera de esto → parar y pedir.
- Activo(s):            <nombre/rol del sistema>
- IP / hostname:        <$IP / fqdn>  (allowlist exacta, no "y relacionados")
- Puertos / protocolos: <p.ej. 80,443 tcp>
- Rutas / API en scope: <paths, endpoints; N/A si no aplica>
- Ventana temporal:     <YYYY-MM-DD HH:MM–HH:MM TZ>
- Origen permitido:     <IP/VPN desde la que se autoriza atacar>
- Cuentas autorizadas:  <usuarios/credenciales provistas; N/A>
- Técnicas EXCLUIDAS:   <brute-force salvo aprobación; DoS SIEMPRE prohibido; …>
- Límites de tasa:      <req/s, threads, lockout a respetar>

## 1. Recon
## 2. Vectores descartados (auditoría de negativos)
## 3. Foothold
## 4. Privesc
## 5. Lateral / AD
## 6. Loot / objetivo
## 7. Cleanup (revertir + documentar cada cambio en el target)
EOF

# Client engagements: authorization record (fill BEFORE any active testing)
cat > "$D/AUTHORIZATION.md" <<EOF
# $NAME — Autorización (llenar y confirmar ANTES de tocar el target)

Regla dura (\`rules/engagement-authorization.md\`): sin este archivo lleno + ventana
vigente, NO hay testing activo. Verbal/chat NO alcanza para un cliente real.

- Cliente (codename):     $NAME   (nombre real/PII fuera de todo path commiteado)
- Orden firmada (ref):    <doc/ID/fecha de la autorización escrita + firmante>
- Alcance (allowlist):    <IPs/hosts/URLs/puertos/cuentas exactos>
- Fuera de alcance:       <lo explícitamente vedado>
- Ventana de testing:     <YYYY-MM-DD HH:MM–HH:MM TZ>   (actuar solo dentro)
- Técnicas permitidas:    <…>   |  Vedadas: <brute-force salvo OK; DoS SIEMPRE no>
- Límites de tasa/lockout: <req/s, threads, umbral de lockout>
- Prod / notificación:    <acciones que requieren aviso previo al cliente>
- Contacto emergencia:    <nombre + canal para parar / incidentes>
- Retención/destrucción:  <qué se guarda, cuánto, y borrado seguro al cierre>
EOF

# Creds vault (provenance-tracked; gitignored; never committed)
cat > "$D/loot/creds.md" <<EOF
# $NAME — creds vault (procedencia obligatoria; NO se commitea)
| usuario | secreto | tipo | procedencia (cómo/dónde) | verificado |
|---|---|---|---|---|
EOF
echo "Scaffolded $D  (llená AUTHORIZATION.md antes de testear)"
```

## Next
- Verify reachability: `nmap -Pn <ip>` (no `ping` in the toolbox image).
- Drive the engagement with the `pentest-cycle` skill.
- `loot/` and creds never leave this repo (`scope.md`); never commit `.ovpn`.
