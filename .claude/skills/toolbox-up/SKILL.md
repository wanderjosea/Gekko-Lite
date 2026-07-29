---
name: toolbox-up
description: >
  Bring up the PenA Kali toolbox and pick the right VPN mode (Full vs Restricted)
  to reach a live target. Use when asked to "start the toolbox", "connect the
  VPN", "reach the target", or before any live-target tool run when it is unclear
  where the tunnel/tools run. Covers build, run, VPN selection, and reachability
  check.
---

# Toolbox up + VPN mode

The default arsenal is `toolbox/` (see `[[pena-toolbox]]`). One image, two run
contexts, two VPN modes. Pick a mode per session — never run both on the same
`.ovpn` at once (fixed-IP tunnels fight and flap).

## Build / basic run
```bash
cd toolbox/
make build                            # pena-toolbox:latest (+ :YYYYMMDD)
make shell                            # interactive, repo mounted at /work
make run CMD='nmap -sV 10.10.10.10'   # one-shot tool
make versions                         # /opt/tool-versions.txt (audit trail)
```

## Choose the VPN mode (decide first)
| | **Full VPN** | **Restricted VPN** |
|---|---|---|
| OpenVPN runs on | operator's host | inside the container |
| Who reaches target | operator (Claude has **no** target access) | **Claude**, directly |
| Bring up | `docker run --rm -it --net=host -v "$PWD":/work -w /work pena-toolbox:latest bash` | `make vpn OVPN=~/target.ovpn` |
| Use when | sandbox can't hold the tunnel / operator wants hands-on | autonomous work, contain blast radius to container |

- **Full** → Claude designs payloads, operator runs them and pastes results back.
- **Restricted** → needs docker + `/dev/net/tun` + `NET_ADMIN` (verify per session).
  The `.ovpn` is mounted at runtime, **never** baked in or committed (`*.ovpn` is
  gitignored; it's a session secret).

## Verify reachability (both modes)
No `ping` in the image — prove the target is up with:
```bash
nmap -Pn <target-ip>
```

## Gotchas
- ligolo binaries are `ligolo-proxy` / `ligolo-agent`, not `ligolo-ng`.
- metasploit DB needs `msfdb init`; `msfvenom` works without it.
- Live-target work respects `scope.md` (allowlist, no brute/DDoS w/o approval).
