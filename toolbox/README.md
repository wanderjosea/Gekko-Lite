# Gekko-Lite toolbox

Imagen Docker con la suite de Kali (`kali-linux-headless`) más las herramientas
concretas que el KB de Gekko-Lite referencia. Una sola imagen, **target-agnóstica**: el
objetivo varía por sesión y se pasa en runtime, nunca se hornea en la imagen.

## Modelo híbrido (por qué existe así)

El sandbox de Gekko-Lite **no tiene salida de red a los targets** del engagement (el
proxy bloquea hosts no-allowlisted). Por eso la misma imagen se usa en dos
contextos:

| Contexto | Dónde corre | Para qué |
|---|---|---|
| Análisis local | aquí, en el sandbox | parsing, cracking (`hashcat`/`john`), RE, triaje sobre artefactos que ya trajiste |
| Target vivo | tu máquina | todo lo que toca la red del objetivo (`nmap`, `nxc`, `sqlmap`, pivoting…) |

Yo genero el comando según el KB; en "target vivo" lo corres tú dentro del
contenedor y pegas la salida. Nada del objetivo queda fijado en la imagen.

## Uso

```bash
make build                              # construye pena-toolbox:latest y :YYYYMMDD
make shell                              # shell interactiva, repo montado en /work
make run CMD='nmap -sV 10.10.10.10'     # una herramienta suelta
make versions                           # manifiesto de versiones (auditoría)
make save                               # exporta la imagen para llevarla a tu máquina
```

En tu máquina: `make build` (el Dockerfile es portable) o carga el export:
`gunzip -c pena-toolbox.tar.gz | docker load`.

## Herramientas

`kali-linux-headless` (cientos de tools) + explícitas del KB: metasploit,
netexec, impacket, bloodhound.py, evil-winrm, responder, seclists, chisel,
ligolo-ng, ffuf, feroxbuster, gobuster, wpscan, sqlmap, hydra, nmap, john,
hashcat, smbclient, ldap-utils, kerbrute (binario fijado), y `medusa`
(SAST de IA, vía pipx).

## Reproducibilidad

`kali-rolling` es rolling; para trazabilidad la imagen guarda
`/opt/tool-versions.txt` con la fecha de build y las versiones exactas de cada
paquete (`make versions`). `kerbrute` va pinneado por versión en el Dockerfile.
