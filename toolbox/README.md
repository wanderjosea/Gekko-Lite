# Gekko toolbox

Docker image with the Kali suite (`kali-linux-headless`) plus a set of specific
offensive tools. One image, **target-agnostic**: the target changes per session and
is passed at run time, never baked into the image.

## Hybrid model

Run the same image in two contexts:

| Context | Where it runs | What for |
|---|---|---|
| Local analysis | a sandbox without target access | parsing, cracking (`hashcat`/`john`), RE, triage of artifacts you already pulled back |
| Live target | the operator's machine | everything that touches the target network (`nmap`, `nxc`, `sqlmap`, pivoting...) |

The agent generates the command; for live targets the operator runs it inside the
container and pastes the output back. Nothing about the target is fixed in the image.

## Usage

```bash
make build                              # builds gekko-toolbox:latest and :YYYYMMDD
make shell                              # interactive shell, repo mounted at /work
make run CMD='nmap -sV 192.0.2.10'      # a single tool
make versions                           # version manifest (audit)
make save                               # export the image to carry it to another machine
```

On another machine: `make build` (the Dockerfile is portable) or load the export:
`gunzip -c gekko-toolbox.tar.gz | docker load`.

## Tools

`kali-linux-headless` (hundreds of tools) plus explicit ones: metasploit,
netexec, impacket, bloodhound.py, evil-winrm, responder, seclists, chisel,
ligolo-ng, ffuf, feroxbuster, gobuster, wpscan, sqlmap, hydra, nmap, john,
hashcat, smbclient, ldap-utils, kerbrute (pinned binary) and `medusa`
(AI SAST, via pipx).

## Reproducibility

`kali-rolling` is a rolling release; for traceability the image stores
`/opt/tool-versions.txt` with the build date and the exact version of each
package (`make versions`). `kerbrute` is pinned by version in the Dockerfile.
