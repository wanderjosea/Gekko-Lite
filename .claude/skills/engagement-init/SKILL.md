---
name: engagement-init
description: >
  Scaffold a new engagement working directory under engagements/ with the PenA
  standard layout (notes.md skeleton, scripts/, canaries/). Use when starting a
  new authorized target ("new engagement", "set up the box", "scaffold a new
  target"), before recon begins. Creates only the folder structure — does
  not touch the target.
---

# Engagement init (scaffold)

Create the standard workdir for a new authorized target. Confirm the target is in
scope (`scope.md`) before creating anything.

## Layout
```
engagements/<name>/
├── notes.md          # central log — numbered phases (see pentest-cycle skill)
├── scripts/          # numbered, reproducible phase scripts: 01_recon.sh …
├── canaries/         # callback/canary test files (optional, web/print targets)
└── loot/             # captured creds/hashes/dumps (stays in this private repo)
```

## Scaffold command
Replace `<ip>` and `<NAME>`; pick the VPN mode from CLAUDE.md.
```bash
IP=<target-ip>; NAME="<BOX>"
D="engagements/$NAME"
mkdir -p "$D"/{scripts,canaries,loot}
cat > "$D/notes.md" <<EOF
# $NAME — $IP — Notas de engagement

Modo VPN: <Full | Restricted>  (ver CLAUDE.md / toolbox/vpn-modes.md).
Workdir: \`$D/\`.
Autorización: en scope (\`scope.md\`). Sin brute-force/(D)DoS salvo aprobación.

## 1. Recon
## 2. Vectores descartados (auditoría de negativos)
## 3. Foothold
## 4. Privesc
## 5. Lateral / AD
## 6. Loot / objetivo
## 7. Cleanup
EOF
echo "Scaffolded $D"
```

## Next
- Verify reachability: `nmap -Pn <ip>` (no `ping` in the toolbox image).
- Drive the engagement with the `pentest-cycle` skill.
- `loot/` and creds never leave this repo (`scope.md`); never commit `.ovpn`.
