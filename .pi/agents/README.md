# .pi/agents/ — Gekko specialist subagents for Pi

Project-scoped agent definitions for the Pi coding agent (pi.dev). Mirror of the
role prompts in `.claude/agents/` (Claude Code) and `.codex/agents/*.toml`
(Codex). These load as discovery priority 1 when Pi starts from the Gekko
checkout — launch from the repo root so their adapters can resolve the canonical
prompts and repository rules by relative path.

## Single source of truth

Each file here is a thin adapter: frontmatter (`name`, `description`, `tools`,
`model`) + a short body that points Pi back to the canonical prompt in
`.claude/agents/<name>.md`. Do **not** duplicate the full prompt here — edit the
role in `.claude/agents/` and every runtime (Claude / Codex / Pi) follows it.

## Activation

1. **Install the subagents extension**: `pi install npm:@tintinweb/pi-subagents`. It
   registers in `~/.pi/agent/settings.json` and auto-loads. `.pi/agents/<name>.md` is
   discovery priority 1 (project authority).
2. **Config dir must match at runtime.** The extension plus `models.json` /
   `modealias.json` live in `PI_CODING_AGENT_DIR` (default `~/.pi/agent` of the
   launching user). Install and launch as the **same user**. `setup.sh` writes the
   Pi provider config (provider id `provider`).
3. **Spawn via the `Agent` tool**: `Agent({ subagent_type: "finding-analyzer",
   prompt: "…", run_in_background: false })` — foreground only. Also `@finding-analyzer …`
   mentions and `/agents`.

## Local-model constraints (why these differ from the Claude/Codex mirrors)

- **One resident model, fixed 128k contexts, model-agnostic alias.** Subagents never
  name the model directly: every role pins `modealias/sub-128k` (context window
  131072). The alias targets the active model; the parent runs that same model via
  `GEKKO_MODEL`, so there is no hot-swap or reload. The model id lives in two places
  only — the alias `target` and `GEKKO_MODEL` — never in an agent file.
- **One subagent at a time:** `maxConcurrent: 1`, `maxConcurrentForeground: 1`,
  nested delegation disabled with `maxSubagentDepth: 0`. Subagents are
  **foreground-only**: every role pins `run_in_background: false` and
  `subagents.json` sets `backgroundByDefault: false`. Parent and subagent share one
  GPU/model, so the parent waits instead of competing for context slots.

## Context budgets: parent 128k, every subagent 128k

The per-agent context cap is NOT a frontmatter field — it is model metadata on an
**alias**:

> `maxTokens` caps the WHOLE generation (reasoning + answer), not just the answer.
> Keep it larger than reasoning plus the expected answer (24576 leaves about 16k for
> output).

- **`~/.pi/agent/models.json`** — the parent model at its full window, for example
  `{ "id": "<model-id>", "contextWindow": 131072, "maxTokens": 24576 }`.
- **`~/.pi/agent/modealias.json`** — one stable alias the subagents reference.
  Requires the `pi-modealias` extension (`pi install git:github.com/GoodDingo/pi-modealias@v0.1.0`,
  then `/reload`):
  ```json
  { "aliases": [
    { "id": "sub-128k", "target": "provider/<model-id>", "contextWindow": 131072, "maxTokens": 24576, "reasoning": true }
  ]}
  ```
- **Frontmatter (these files).** Every role pins `model: modealias/sub-128k`. If
  `pi-modealias` is NOT installed, the aliased roles fall back to the parent's model
  silently — no crash, but the alias is not independently enforced.
  `inherit_context: false` keeps each agent fresh. `prompt_mode: append` is set
  deliberately: the subagent **inherits CLAUDE.md + AGENTS.md** (scope.md rules
  travel with it) — a safety requirement for a red-team tool. Cost: about 8k of
  inherited context per spawn. `tools:` is a comma-separated string (Pi's format),
  NOT a YAML array.

### Switching the model
Change the **parent** model from inside Pi with `/model`. The **subagents** follow the
`sub-128k` alias, whose `target` `setup.sh` sets to `provider/<GEKKO_MODEL>`; to point
them elsewhere, edit that `target` in `~/.pi/agent/modealias.json` and `/reload`. The
target id must exist in `models.json`.

### Server sizing (orchestrator + 1 subagent)
`llama-server` splits context equally across slots (`-c TOTAL -np N`, slot = TOTAL/N)
and reserves KV for the full `-c` upfront; a slot must be at least the largest
request. For the operator plus **one** subagent, each up to 128k: `-np 2 -c 262144`.
Do not add slots for more subagents without an explicit decision to change the
one-subagent limit.

## Not yet in a spec

No spec describes this subagent flow. Per the spec-anchored hard rule, wiring the
extension and config into the launchers wants an acceptance criterion tied to a test
(a new spec) before it becomes a product path. These definition files are the data.
