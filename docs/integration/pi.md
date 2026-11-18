# Using Gekko with Pi

> Status: agent-harness runbook. Pi uses its native tools; Gekko does not insert a
> gateway of its own.

## Configuration

From the cloned repository:

```bash
cd Gekko-Lite
export GEKKO_LLM_URL="http://<endpoint-host>:<port>/v1"
read -rsp 'API key: ' GEKKO_LLM_KEY && export GEKKO_LLM_KEY && echo
./setup.sh
```

`setup.sh` writes the Pi provider config. The provider id is `provider` and it must
look like:

```json
{
  "baseUrl": "http://<endpoint-host>:<port>/v1",
  "apiKey": "${GEKKO_PROVIDER_KEY}",
  "api": "openai-completions"
}
```

**Important:** Pi does **not** interpolate environment variables in `baseUrl` (only
in `apiKey` and headers). `baseUrl` must be a **literal URL** — a `${GEKKO_LLM_URL}`
there stays unresolved and Pi fails with "url invalid". The key can stay as a
`${GEKKO_PROVIDER_KEY}` placeholder (interpolated at runtime, never written to the
file). `GEKKO_PROVIDER_KEY` defaults to `GEKKO_LLM_KEY`.

The model id is whatever your endpoint serves (`GEKKO_MODEL`, `<model-id>`).

The key stays in the environment. It is not passed through argv or written to the repo.

## HITL

Start Pi from the repo root so it discovers `AGENTS.md` and the rest of the project
context:

```bash
./tools/pi-hitl.sh
```

Pi keeps `bash`, `read`, `edit` and `write`; HITL means the operator is present, not
that Pi asks for confirmation before every tool call. The operator talks to the model
and can open another terminal on the same machine. For interactive processes use tmux
or the optional extension:

```bash
pi --provider provider --model <model-id> \
  -e toolbox/shell-session.ts
```

## One launcher, two shell modes

`tools/pi-hitl.sh` keeps Pi, `bash`, the guard and the report module on the host.
When creating a workspace the operator chooses OS (Enter/`o`) or toolbox (`t`). That
choice is stored in `engagements/<name>/exec`; workspaces without the file use OS.

In toolbox mode the `session_*` shells use tmux inside `gekko-tb-<name>`. Only the
workspace (writable) and `.claude/tools/` (read-only) are mounted, at their absolute
host paths. Pi's `bash` and read tools stay on the host; the guard blocks from `bash`
the commands that name scope hosts, except an isolated invocation of the ledger CLI.
The toolbox does not configure an egress allowlist and is not declared containment.

Build the image: `make -C toolbox build`. To attach:
`docker exec -it gekko-tb-<name> tmux attach`. The container stays up when Pi exits;
stop it with `docker rm -f gekko-tb-<name>`.

## OS mode

In `os` mode the persistent shells are also born on the host and have the operator
user's privileges. The guard is a pattern filter, not a containment barrier; the
operator must keep supervision and an explicit scope.

## Security limits

Native tool output reaches Pi directly. It does not automatically go through the
quarantine path. Treat banners, pages and target files as hostile data; use the
sanitizer deliberately when the workflow requires it. General immunity to prompt
injection is not claimed.

In pentesting the local model may need to see and use credentials. The operator
controls that decision. Secrets are not committed, do not enter the KB and are not
published in shared transcripts.

## Updating Pi

1. Change the pinned Pi version in your Pi image build.
2. Rebuild the image.
3. Verify discovery of `AGENTS.md` and the native tools.
4. Test with and without `shell-session.ts`.
5. Run a smoke test against your model before adopting the version.
