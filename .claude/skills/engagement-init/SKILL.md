---
name: engagement-init
description: >
  Scaffold a new engagement working directory under engagements/ with the Gekko
  standard layout (AUTHORIZATION.md + notes.md skeleton, scripts/, canaries/,
  loot/creds vault). Use when starting a new authorized target ("new engagement",
  "set up the box", "scaffold a new target"), before recon begins. Creates only the
  folder structure — does not touch the target.
tags: [engagement, scaffold, setup, authorization, scope]
---

# Engagement init (scaffold)

Create the standard workdir for a new authorized target. Confirm the target is in
scope (`scope.md`) before creating anything. For a **paying client**, use a
**codename** as `<NAME>` (real org/PII never lands in a committed path) and fill
`AUTHORIZATION.md` before any active testing — see `rules/engagement-authorization.md`.

## Layout
```
engagements/<codename>/
├── scope.txt         # machine-readable allowlist: host/CIDR/host:port, one per line (# comments)
├── AUTHORIZATION.md  # client: signed-order ref, scope, testing window, contacts, retention
├── notes.md          # central log — numbered phases (see pentest-cycle skill)
├── scripts/          # numbered, reproducible phase scripts: 01_recon.sh …
├── canaries/         # callback/canary test files (optional, web/print targets)
└── loot/             # captured creds/hashes/dumps — creds.md vault (stays in this private repo)
```

`scope.txt` is the ONE machine-readable definition of scope: the toolbox
launcher parses it into the container's **egress allowlist** (real network boundary in
toolbox mode). `notes.md §0` / `AUTHORIZATION.md` keep the human/legal detail. Keep them
consistent — `scope.txt` holds exactly the hosts/ports authorized there, nothing "related".

## Scaffold command
Replace `<CODENAME>` and the targets (IPv4 or CIDR; `IP label` keeps the label as a
comment); for a client use a **codename**. Pick the VPN mode from CLAUDE.md. The CLI is
the single source of the scaffold: it never overwrites an existing file and prints the path.
```bash
node --no-warnings --experimental-strip-types toolbox/gekko-workspace.ts new "<CODENAME>" <ip…>
```
Then fill `AUTHORIZATION.md` before any active testing.

## Next
- Verify reachability: `nmap -Pn <ip>` (no `ping` in the toolbox image).
- Drive the engagement with the `pentest-cycle` skill.
- `loot/` and creds never leave this repo (`scope.md`); never commit `.ovpn`.
