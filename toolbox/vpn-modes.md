# Toolbox VPN modes — network diagrams

Two ways the engagement VPN can be up. Pick one per session (see CLAUDE.md).
Generic on purpose — no engagement-specific IPs.

Diagrams rendered from the `.dot` sources in this dir:
`dot -Tpng vpn-full.dot -o vpn-full.png` (graphviz + fonts-dejavu-core).

## Full VPN mode  (operator-driven)

OpenVPN runs on the operator's PC; the whole host is on the VPN. The toolbox
container shares the host network (`--net=host`), so its tools use the host's
`tun0`.

![Full VPN mode](vpn-full.png)

- Reaches target: the operator (host is on the VPN).
- Claude: target **is** reachable — gated by ROE / rules guardrails, not by routing.

## Restricted VPN mode  (Claude-driven — host is NOT on the VPN)

OpenVPN runs INSIDE the toolbox container (bridge net, its own network
namespace). Only the container reaches the target; the operator's host has no
route to it. Claude runs recon/enum directly and reports back.

![Restricted VPN mode](vpn-restricted.png)

- Reaches target: Claude (via container `tun0`, isolated netns).
- Operator host: no route.
- Note: encryption is not a boundary vs the host owner — operator is root and can
  `tcpdump -i tun0` inside the container to read the decrypted traffic.

## Do not mix
A dedicated/VIP `.ovpn` has a fixed IP. Running both modes on the same file at
once makes the two connections fight (one kicks the other → flapping). One
tunnel per session: operator's host **or** the container, never both.
