# Codex adapter

This directory adapts PenA to Codex without duplicating its canonical policy.

- `config.toml` makes Codex discover `CLAUDE.md` as the repository contract and
  limits subagent concurrency.
- `agents/*.toml` registers Codex-native custom agents. Each adapter loads the
  matching canonical role from `.claude/agents/*.md` before acting.
- `.claude/rules/scope.md` remains the highest-priority PenA policy. Do not copy
  its contents here: duplicated safety rules drift.

Project-local Codex configuration and agents load only when the repository is
trusted.

## Model mapping

| Workload | Model | Reasoning |
|---|---|---|
| High-volume triage and curation | `gpt-5.6-luna` | `medium` |
| Balanced writing and review | `gpt-5.6-terra` | `medium` / `high` |
| Finding verification and exploit development | `gpt-5.6-sol` | `high` / `xhigh` |

## Mechanical scope enforcement

`hooks.json` registers a fail-closed `PreToolUse` policy. There are two named
operating modes:

- **Enforcement Mode** (default): no target reachability and no Docker socket.
- **Direct Interaction Mode (Permissive)**: the legacy Restricted VPN topology;
  only a labelled, guarded Kali toolbox can reach the signed target through its
  own `tun0`.

The policy enforces the following:

- local read-only commands are allowed and not logged;
- every denial is logged as compact, secret-free JSONL;
- direct network commands and arbitrary `docker exec` are denied;
- MCP/connectors are denied while an engagement scope is active;
- policy, hook, and signed-scope files cannot be edited during the session;
- target commands must pass through `hooks/pena_guard.py exec` with an
  operator-signed scope;
- target writes, brute force, DoS, redirects and proxy/routing overrides remain
  mechanically blocked. They are not inferred from conversation text.

The guard initially supports narrowly constrained `curl`, `openssl s_client`,
and `nmap`. Its `max_actions` and `requests_per_second` limits count wrapper
invocations; packet-level limits still belong in the Direct Interaction toolbox.

### Create and sign a scope

Copy `policy/scope.example.json` into the named engagement and replace every
example field with the exact authorized values. Generate the signing key outside
the repository; never place the private key under PenA:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /SAFE/operator-scope-private.pem
openssl pkey -in /SAFE/operator-scope-private.pem -pubout -out /SAFE/operator-scope-public.pem
openssl dgst -sha256 -sign /SAFE/operator-scope-private.pem \
  -out engagements/NAME/scope.json.sig engagements/NAME/scope.json
```

Launch **Enforcement Mode** (the default), which disables hosted web search,
Docker access, and target reachability:

```bash
bash .codex/bin/pena-codex engagements/NAME/scope.json \
  /SAFE/operator-scope-public.pem
```

For **Direct Interaction Mode (Permissive)**, first start the guarded toolbox.
The OpenVPN profile stays outside the repository; the helper verifies the signed
scope, pins the VPN endpoint, and installs a default-drop firewall before the
agent can use it:

```bash
python3 ~/.codex/pena-hooks/pena_guard.py start \
  --scope engagements/NAME/scope.json \
  --public-key /SAFE/operator-scope-public.pem \
  --ovpn /SAFE/target.ovpn

bash .codex/bin/pena-codex --mode direct-interaction \
  --container pena-NAME-SCOPEHASH engagements/NAME/scope.json \
  /SAFE/operator-scope-public.pem
```

`start` prints the exact container name. Stop it at the end of the session:

```bash
python3 ~/.codex/pena-hooks/pena_guard.py stop \
  --scope engagements/NAME/scope.json \
  --public-key /SAFE/operator-scope-public.pem
```

In Direct Interaction Mode, run an authorized read through the structured gate.
Placeholders are mandatory; redirects are intentionally disabled:

```bash
python3 .codex/hooks/pena_guard.py exec \
  --host 192.0.2.10 --port 443 --action read --tool curl -- \
  curl --max-redirs 0 https://\{HOST\}:\{PORT\}/health
```

The launcher stores audit records outside the workspace under the user's state
directory (`$XDG_STATE_HOME/pena/audit/`, or its standard local-state fallback).
They rotate at 25 MiB and store hashes rather than commands or target values.

### Trust boundary

The checked-in hook is an immediate project guardrail and Codex re-requires
trust when its hash changes. The stronger user-level copy lives at
`~/.codex/pena-hooks/pena_guard.py` with `install/hooks.json` installed as
`~/.codex/hooks.json`; it detects PenA's marker files and remains inactive in
other repositories. It is outside the workspace sandbox but is not an
administrator/MDM-managed policy; review and trust its exact hash with `/hooks`.
Use the installed guard for structured target commands:

```bash
python3 ~/.codex/pena-hooks/pena_guard.py exec \
  --host 192.0.2.10 --port 443 --action read --tool curl -- \
  curl https://\{HOST\}:\{PORT\}/health
```

Direct Interaction Mode is deliberately permissive only at the Codex permission
layer: it exposes the Docker socket solely to reach the labelled toolbox. The
toolbox independently enforces the signed IPv4/port/protocol allowlist with a
default-drop firewall, and the host retains no VPN route.
