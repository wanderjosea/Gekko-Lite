---
title: Information Gathering — Web Edition (recon pasivo/activo)
slug: information-gathering-web
category: techniques
updated: 2026-08-20
summary: "Recon web: whois, dig (records/zone-transfer AXFR), subdomain brute-force (dnsenum/amass), vhost fuzzing (gobuster), CT logs (crt.sh+jq), fingerprinting (curl -I/whatweb/wafw00f/nikto)"
tags: [web, recon, dns, subdomains, osint, fingerprinting]
sensitive: false
---

# Information Gathering — Web Edition

## When to use
Fase de recon de un target web: mapear dominios/subdominios/infra y fingerprint
del stack antes de atacar. Pasivo primero (whois, CT logs, archivos) → activo
(brute-force DNS, vhost fuzzing) con autorización.

## WHOIS
```bash
sudo apt install whois -y
whois facebook.com     # registrar, creation/expiry, registrant org, name servers, abuse contact
```
Señales OSINT: dominio registrado hace días + registrant oculto + bulletproof hosting → phishing/C2. Combinar con otras técnicas (no basta solo).

## DNS — dig
```bash
dig domain.com A|AAAA|MX|NS|TXT|CNAME|SOA   # tipo de registro
dig @1.1.1.1 domain.com          # servidor DNS específico
dig +trace domain.com            # ruta completa de resolución
dig -x 192.168.1.1               # reverse lookup (PTR)
dig +short domain.com            # solo la respuesta
dig +noall +answer domain.com    # solo answer section
dig domain.com ANY               # todos (muchos servers ignoran ANY, RFC 8482)
```
Cuidado: rate-limits; algunos servers bloquean queries excesivas. Autorización antes de recon extenso.

## Zone Transfer (AXFR) — mina de oro si mal configurado
```bash
dig axfr @nsztm1.digi.ninja zonetransfer.me
```
Copia completa de la zona → todos los subdominios + IPs + records. La mayoría de servers modernos lo restringen a secundarios de confianza, pero intentarlo siempre (barato, revela postura). `zonetransfer.me` = lab de práctica.

## Subdomain brute-force (activo)
Wordlists (SecLists): `/usr/share/seclists/Discovery/DNS/subdomains-top1million-{20000,110000}.txt`
```bash
dnsenum --enum inlanefreight.com \
  -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
```
Tools: `dnsenum`, `fierce`, `dnsrecon`, `amass` (mejor data sources), `assetfinder`, `puredns`. `-r` = recursivo.

## Virtual Hosts (vhost fuzzing)
Descubre sitios servidos por la misma IP vía header `Host` (incluye subdominios NO públicos, sin record DNS). Si no hay DNS, mapear en `/etc/hosts`.
```bash
gobuster vhost -u http://inlanefreight.htb:81 \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
# flags: -t threads, -k ignora cert SSL, -o output. --append-domain requerido en gobuster nuevo
```
Tipos de vhost: name-based (header Host, el común), IP-based, port-based. Genera tráfico → detectable por IDS/WAF.

## Certificate Transparency logs (pasivo, sin brute-force)
Registro público append-only de todo cert SSL/TLS emitido → subdominios históricos, incluidos caducados/no-usados (posible software viejo vulnerable).
```bash
curl -s "https://crt.sh/?q=facebook.com&output=json" \
  | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```
UIs: [crt.sh](https://crt.sh/) (gratis, sin registro), [Censys](https://search.censys.io/) (filtrado avanzado + API).

## Fingerprinting del stack
Técnicas: banner grabbing, análisis de headers (`Server`, `X-Powered-By`), sondeo de respuestas, análisis de contenido.
```bash
curl -I inlanefreight.com          # Server: Apache/2.4.41 (Ubuntu); seguir redirects (301→WordPress vía X-Redirect-By)
wafw00f inlanefreight.com          # detecta WAF (ej. Wordfence/Defiant) ANTES de sondear
whatweb inlanefreight.com          # DB de firmas: CMS/frameworks
nikto -h inlanefreight.com -Tuning b   # -Tuning b = solo módulos de software ID
```
Otras: Wappalyzer/BuiltWith (browser), Netcraft, Nmap NSE. `wafw00f` primero: un WAF cambia toda la estrategia.

## Recon adicional (pasivo)
- `robots.txt`, `sitemap.xml`, well-known URIs (`/.well-known/`) → rutas que el sitio revela.
- **Crawling/spidering** (Burp, ZAP, `hakrawler`, `gospider`) → endpoints, params, comentarios.
- **Search engines** (Google dorks: `site:`, `inurl:`, `filetype:`) + **web archives** ([Wayback Machine](https://web.archive.org/), `waybackurls`) → rutas/params históricos que ya no linkean.
- Automatización: `amass`/`subfinder` + `httpx` + `nuclei` como pipeline.

## Gotchas
- Pasivo (whois, CT logs, archives, search engines) no toca el target → hacerlo primero.
- Un subdominio/vhost en scope NO autoriza tocar los que descubras: parar y re-autorizar (ver [[scope]] del engagement).

## References
- Relacionado: [[web-app-fundamentals]], [[web-fuzzing]], [[web-requests-http]], [[service-enumeration]]
- Curso CWES Bug Bounty → 03-WEB → "Information Gathering - Web Edition" (HTB Academy, traducido). Notion.
