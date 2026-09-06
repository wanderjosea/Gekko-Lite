---
title: Web Fuzzing (ffuf / gobuster / feroxbuster / wenum)
slug: web-fuzzing
category: techniques
updated: 2026-08-20
summary: "Fuzzing de dirs/archivos/params/vhosts/API con ffuf (FUZZ, -e, -recursion, -mc/-fc/-fs/-fw), gobuster, feroxbuster, wenum; filtrado de salida por code/size/words/lines/regex"
tags: [web, fuzzing, ffuf, gobuster, feroxbuster, wordlists, recon]
sensitive: false
---

# Web Fuzzing

## When to use
Descubrir contenido oculto (dirs/archivos/backups/params/endpoints) no linkeado
en una app web. Amplía la superficie de ataque. Requiere wordlist externa + la
keyword `FUZZ` como placeholder.

## Herramientas
```bash
go install github.com/ffuf/ffuf/v2@latest              # ffuf: fuzzer rápido (Go)
go install github.com/OJ/gobuster/v3@latest            # gobuster: dir/dns/vhost
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash -s $HOME/.local/bin  # recursivo (Rust)
pipx install git+https://github.com/WebFuzzForge/wenum # wenum = fork mantenido de wfuzz (params)
```
Ninguna trae wordlist: usar **SecLists** (`/usr/share/seclists/`, minúsculas en pwnbox).

## Wordlists (SecLists)
| Wordlist | Uso |
|---|---|
| `Discovery/Web-Content/common.txt` | Propósito general, buen punto de partida |
| `Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt` | Directorios, más profundo |
| `Discovery/Web-Content/raft-large-directories.txt` | Campañas exhaustivas |
| `Discovery/Web-Content/big.txt` | Dirs + archivos, red amplia |
| `Discovery/DNS/subdomains-top1million-{20000,110000}.txt` | Subdominios / vhosts |

## ffuf — dir / file fuzzing
```bash
# Directorios
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://IP:PORT/FUZZ
# Archivos con extensiones
ffuf -w .../common.txt -u http://IP:PORT/dir/FUZZ -e .php,.html,.txt,.bak,.js -v
# Backups reveladores: config.php.bak (db creds), test.php (script viejo)
```

## ffuf — recursivo
```bash
ffuf -w .../directory-list-2.3-medium.txt -ic -v -u http://IP:PORT/FUZZ -e .html -recursion
# -recursion: fuzzea cada dir hallado (admin → /admin/FUZZ). -ic: ignora comentarios (#) en wordlist
# Responsable: -recursion-depth 2 -rate 500 -timeout N  (no saturar el server → IDS/perf)
```

## Fuzzing de parámetros y valores
GET en URL (`?a=1&b=2`), POST en body (`application/x-www-form-urlencoded` o `multipart/form-data`).
```bash
# GET value fuzzing (wenum)
wenum -w .../common.txt --hc 404 -u "http://IP:PORT/get.php?x=FUZZ"
# POST value fuzzing (ffuf: -d = body)
ffuf -u http://IP:PORT/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w .../common.txt -mc 200 -v
```
Manipular params expone IDOR (cambiar product_id → pedidos ajenos), funciones ocultas, XSS/SQLi.

## Filtrado de salida (clave para no ahogarse en 404)
**ffuf** (default matchea 200-299,301,302,307,401,403,405,500):
| Match | Filter (excluir) | Por |
|---|---|---|
| `-mc 200` | `-fc 404,302` | status code |
| `-ms 3456` | `-fs 0-1023` | size (bytes) |
| `-mw 5-10` | `-fw 219` | word count |
| `-ml 20` | `-fl 10` | line count |
| `-mt >500` | — | TTFB (ms), detecta lentas |

`-mc all` inunda de 404 → siempre filtrar.
```bash
ffuf -u http://ex.com/FUZZ -w wl.txt -mc 200 -fw 427 -ms 500     # combinar
```
**gobuster** (solo modo dir): `-s 200,301` (incluir), `-b 404` (excluir), `--exclude-length 0`.
**wenum**: `--sc`/`--hc` (code), `--sl`/`--hl` (lines), `--sw`/`--hw` (words), `--ss`/`--hs` (size), `--sr`/`--hr "regex"`.
**feroxbuster**: `-s 200,301` (allowlist), `-C 404,500` (denylist), `-S` size, `-W` words, `-N` lines, `-X "regex"`, `--filter-similar-to error.html`, `--dont-scan /uploads`.

## Vhost fuzzing
Ver [[information-gathering-web]] (`gobuster vhost --append-domain`). ffuf: fuzzear header `Host`.

## API fuzzing
Tipos: parámetros, formato de datos (JSON/XML), secuencias (race, IDOR, authz bypass).
```bash
# 1. Descubrir spec: http://IP:PORT/docs (Swagger) — pero puede haber endpoints NO documentados
# 2. Fuzzear endpoints ocultos con wordlist
git clone https://github.com/PandaSt0rm/webfuzz_api.git && cd webfuzz_api && pip3 install -r requirements.txt
python3 api_fuzzer.py http://IP:PORT
# 405 Method Not Allowed en /items → endpoint real, método HTTP equivocado
```
Ver [[api-attacks]] para explotación (BOLA/BFLA/SSRF).

## Gotchas
- Fuzzing genera mucho tráfico → detectable por IDS/WAF; throttle (`-rate`) y autorización.
- Un endpoint/vhost descubierto NO está en scope por hallarlo — re-autorizar antes de tocarlo.

## References
- Relacionado: [[information-gathering-web]], [[web-proxies]], [[api-attacks]], [[web-app-fundamentals]]
- Curso CWES Bug Bounty → 03-WEB → "Web Fuzzing" (HTB Academy, traducido). Notion.
