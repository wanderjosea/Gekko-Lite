---
title: Per-service enumeration after a port scan
slug: service-enumeration
category: tools
updated: 2026-11-18
summary: "Recon commands per open service (FTP, SSH, DNS, HTTP, SMB, LDAP) after a port scan"
tags: [recon, enumeration, nmap, smb, ldap, http, dns, ftp]
sensitive: false
---

# Per-service enumeration after a port scan

## When to use
After the initial port scan shows open services. Run the matching section for
every open port; do not stop at the first interesting one.

## Initial scan
```bash
nmap -sV -sC -p- --min-rate 3000 -T4 TARGET -oN full_scan.txt
nmap -sU --top-ports 100 TARGET -oN udp_scan.txt
```

## Per service
```bash
# FTP (21): anonymous login, then list and fetch
ftp TARGET                       # try: anonymous / anonymous, or empty password
nxc ftp TARGET -u anonymous -p ""

# DNS (53): try a zone transfer, with and without a prefix on the domain
dig axfr @TARGET DOMAIN.local
dig -x 192.0.2.10 @TARGET

# HTTP/HTTPS (80/443): fingerprint, then check common leak paths
whatweb http://TARGET
curl -sI http://TARGET
curl -s http://TARGET/robots.txt

# SMB (445): null session, then guest, then authenticated share listing
nxc smb TARGET -u "" -p "" --shares
nxc smb TARGET -u guest -p "" --shares

# LDAP (389/636): anonymous base query
ldapsearch -x -H ldap://TARGET -b "DC=DOMAIN,DC=local"

# NFS (2049): list exports, mount read-only first
showmount -e TARGET
```

## Gotchas
- A zone transfer can fail for `domain.local` and succeed for the bare domain.
  Try both.
- Enumerate services bound to localhost too (`ss -tlnp` on a compromised host).
  Internal-only services are often the most useful ones.
- Virtual-host fuzzing is still needed even when a zone transfer lists hosts.
- Check which account each application runs as (`ps aux`): a shell inside an
  internal app is a shell as that account.

## References
- Related: [[sql-injection]], [[kerberoasting]]
- Generic service checklist; no target data.
