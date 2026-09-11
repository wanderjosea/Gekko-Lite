---
title: Gekko-Lite toolbox (arsenal Kali dockerizado)
slug: pena-toolbox
category: tools
updated: 2026-08-01
summary: "Default arsenal: Kali-headless + KB tools in one Docker image; hybrid local/live-target run; `make` wrapper"
tags: [docker, kali, arsenal, toolbox, netexec, impacket, ligolo, metasploit, medusa, hybrid]
sensitive: false
---

# Gekko-Lite toolbox (arsenal Kali dockerizado)

## When to use
El arsenal por defecto. Imagen Docker única (`kali-linux-headless` + las tools que
este KB referencia) que corre en **dos contextos**: análisis local aquí sobre
artefactos ya traídos, y target vivo en la máquina del operador. Vive en
`toolbox/`. Target-agnóstica: el objetivo se pasa en runtime, nunca se hornea.

## Key facts / commands
```bash
cd toolbox/
make build                            # pena-toolbox:latest y :YYYYMMDD
make shell                            # shell interactiva, repo montado en /work
make run CMD='nmap -sV 10.10.10.10'   # una tool suelta
make versions                         # /opt/tool-versions.txt (auditoría)
make save                             # export para llevar a la máquina del operador
# en la máquina del operador: gunzip -c pena-toolbox.tar.gz | docker load
```

| Contexto | Dónde | Para qué |
|---|---|---|
| Análisis local | sandbox (aquí) | parsing, cracking (`hashcat`/`john`), RE, triaje offline |
| Target vivo | máquina del operador | `nmap`, `nxc`, `sqlmap`, pivoting — todo lo que toca la red |

### Detonación de código no confiable (untrusted samples)
`scope.md` exige detonar SOLO en contenedor desechable: static-first (`file`,
`strings`, `sha256sum`) y recién entonces, si hace falta correrlo, un contenedor
**sin red, sin root, rootfs de solo lectura, con límites y sin bind mounts** del
repo/`$HOME`. La invocación canónica (contrasta con `make shell`, que SÍ monta el
repo — acá **nunca**):
```bash
# 1. contenedor endurecido y aislado (detached, para poder meterle la muestra)
cid=$(docker run -d --network=none --user 65534:65534 \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  --memory 1g --cpus 1 --pids-limit 256 \
  --cap-drop=ALL --security-opt no-new-privileges \
  pena-toolbox:latest sleep 3600)
# 2. transferencia por docker cp — NO bind mount (-v) del repo ni de $HOME
docker cp ./sample "$cid:/tmp/sample"
# 3. detoná y observá
docker exec -u 65534:65534 "$cid" sh -c 'cd /tmp && ./sample'
# 4. quemá el contenedor (tratalo como comprometido)
docker rm -f "$cid"
```
- `--network=none` (no `--net=host`), sin socket Docker montado, sin `--cap-add`,
  `no-new-privileges` → sin escalada de caps; `--pids-limit`/`--memory`/`--cpus`
  acotan fork-bombs y agotamiento. `/tmp` es el único writable (tmpfs efímero).
- Si necesita red controlada (C2 lab propio), usá una red Docker interna dedicada,
  jamás `--net=host` ni la VPN del engagement.

### Inventario por función
Base **`kali-linux-headless`** (suite CLI estándar de Kali: netcat, dnsutils,
whatweb, etc.) + estas tools que el KB referencia explícitamente. El inventario
autoritativo y versionado está en `/opt/tool-versions.txt` (`make versions`).

| Categoría | Tool | Binario / uso clave | Para qué |
|---|---|---|---|
| Recon / web | `nmap` | `nmap -sVC -Pn <ip>` | escaneo puertos/servicios/scripts |
| | `ffuf` | `ffuf -w … -u …/FUZZ` | fuzzing web (dirs, params, vhost) |
| | `feroxbuster` | `feroxbuster -u …` | content discovery recursivo |
| | `gobuster` | `gobuster dir/dns/vhost` | brute de dirs/DNS/vhosts |
| | `wpscan` | `wpscan --url …` | enum/vulns WordPress |
| | `sqlmap` | `sqlmap -u … --batch` | SQLi automatizado → dump/RCE |
| AD / Windows | `netexec` (`nxc`) | `nxc smb/winrm/ldap/mssql …` | spray + enum + secrets (ex-CME) → `[[netexec-crackmapexec]]` |
| | `impacket-scripts` | `secretsdump.py`, `psexec.py`, `wmiexec.py`, `GetUserSPNs.py`, `getST.py`, `ntlmrelayx.py` | todo el flujo AD/Kerberos → `[[active-directory-attacks]]`, `[[rbcd-to-domain-admin]]` |
| | `bloodhound.py` | `bloodhound-python -c All …` | colector de grafo AD (ingestor Python) |
| | `evil-winrm` | `evil-winrm -i … -u … -p …` | shell WinRM post-auth |
| | `kerbrute` (pin v1.0.3) | `kerbrute userenum/passwordspray` | enum usuarios / spray pre-auth Kerberos → `[[password-spray]]` |
| | `responder` | `responder -I <iface>` | envenenamiento LLMNR/NBT-NS/mDNS → captura hashes |
| | `smbclient` / `ldap-utils` | `smbclient -L`, `ldapsearch -x` | clientes SMB / LDAP para enum → `[[ad-credential-looting]]` |
| Exploitation | `metasploit-framework` | `msfconsole`, `msfvenom` | framework de exploits + generación de payloads |
| | `hydra` | `hydra -L … -P … <proto>://…` | brute de logins de red (¡ver ban de brute-force en scope.md!) |
| Pivoting | `ligolo-ng` | `ligolo-proxy` / `ligolo-agent` | túnel inverso / pivoting por interfaz → `[[network-pivoting]]` |
| | `chisel` | `chisel server/client` | túnel TCP/UDP sobre HTTP |
| Cracking | `hashcat` | `hashcat -m <mode> …` | cracking GPU → `[[password-cracking]]` |
| | `john` | `john --wordlist=… hash` | cracking CPU (JtR), formatos raros |
| Code / IA | `medusa` (pipx) | `medusa scan …` | SAST AI-first, **no** brute-forcer → `[[medusa]]` |
| Wordlists | `seclists` | `/usr/share/seclists/` | datos, no binario (rockyou, discovery, etc.) |

## Gotchas
- Egress del sandbox varía por sesión. Dos modos VPN (ver CLAUDE.md): **Full**
  (VPN en la PC del operador, `--net=host`, Claude sin acceso al target) y
  **Restricted** (`make vpn OVPN=…`, VPN dentro del contenedor, Claude llega
  directo). Los dos túneles conviven: el del contenedor no quita la VPN propia
  del operador si la tiene levantada.
- No hay `ping` en la imagen → usar `nmap -Pn` para probar reachability.
- ligolo-ng instala binarios `ligolo-agent` / `ligolo-proxy`, no `ligolo-ng`.
- `medusa` = SAST de IA (pip `medusa-security`), no un brute-forcer; ver `[[medusa]]`.
- `metasploit`: la DB Postgres no arranca sola en el contenedor → `msfdb init`
  (o correr sin DB). `msfvenom` sirve igual sin DB para generar payloads.
- `seclists` no es binario: vive en `/usr/share/seclists/` (rockyou está gzip →
  `gunzip` antes de usar). Es la fuente de wordlists para `ffuf`/`gobuster`/`hydra`.
- Base rolling → sin pin reproducible; la traza es `/opt/tool-versions.txt`
  (build date + versiones exactas). `kerbrute` sí va pinneado (v1.0.3).
- Imagen ~12.6 GB en disco. `make save` genera tarball (~3 GB, gitignored).

## References
- Relacionado: [[service-enumeration]], [[netexec-crackmapexec]], [[network-pivoting]], [[medusa]], [[gtfobins-binaries]]
- toolbox/ (Dockerfile, Makefile, README.md)
