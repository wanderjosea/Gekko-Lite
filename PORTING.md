# Porting PenA to other agents (Codex, Gemini, any LLM)

PenA is not a Claude-only product. It is a set of **rules, restrictions and
methodology** that profile any capable LLM coding agent into a disciplined
pentest operator. Most of it is vendor-neutral markdown and scripts. This guide
says exactly what ports for free, what is Claude-Code-specific, and how to run
PenA on OpenAI Codex CLI, Gemini CLI, or anything that reads an instructions file.

> The mental model is correct: PenA ≈ 90% vendor-neutral. The Claude-Code-specific
> 10% is **orchestration** (subagents + skills) and **part of the enforcement**
> (permission prompts / plan mode). The doctrine travels; some of its *mechanical*
> enforcement does not — see Step 3, it is the safety-critical part.

## Vendor-neutral core — works under any agent, change nothing

| Piece | What it is |
|---|---|
| `.claude/rules/scope.md` | Rules of engagement / scope / ROE — the hard law |
| `.claude/rules/style.md` | Reasoning doctrine (evidence-first, hypothesis, verify) |
| `.claude/kb/` | Knowledge base — plain markdown cheatsheets |
| `.githooks/` | Leak + AI-attribution guards — **git-level, fire under any agent** |
| `.claude/tools/findings.py` | Findings ledger — a Python CLI, agent-agnostic |
| `toolbox/` | Kali-headless Docker + VPN modes — agent-agnostic |
| The pentest-cycle methodology | Phased loop; the *content* is generic even if the skill wrapper is not |

None of these know or care which model runs them.

## Claude-Code-specific layer — needs a mapping

| Piece | Why it does not port 1:1 |
|---|---|
| `.claude/agents/*.md` | Subagent roster with Claude frontmatter (`model:`, `tools:`, `@agent-…`, auto-delegation). Codex uses TOML subagents in `config.toml` (hub-and-spoke); Gemini differs. |
| `.claude/skills/` | The `Skill` invocation is a Claude Code mechanism. |
| Permission prompts / plan mode | Claude Code's *supervised autonomy*. Other tools have their own (often weaker or off-by-default) gating. |

## Step 1 — make the contract load (entry-point filename)

Each tool auto-reads a **different** file. If the file name is wrong, the doctrine
never loads.

| Tool | File it reads |
|---|---|
| Claude Code | `CLAUDE.md` |
| Codex CLI, Cursor, Copilot, Aider, Zed… | `AGENTS.md` |
| Gemini CLI | `GEMINI.md` (2026 builds also read `AGENTS.md`) |

Quick path — one contract, symlinked so every tool sees it:

```bash
ln -s CLAUDE.md AGENTS.md      # Codex & the AGENTS.md ecosystem
ln -s CLAUDE.md GEMINI.md      # Gemini CLI
```

Caveat: `CLAUDE.md` names `@agent-…` and skills that only exist in Claude Code.
As prose it is harmless — a non-Claude agent just reads it as description — but see
Step 2 for how to reinterpret it. Cleaner (more work): write a trimmed `AGENTS.md`
that drops the roster table and points at the rules instead. The symlink is enough
to start.

## Step 2 — reinterpret the agent roster

On a tool without native subagents, each `agents/*.md` is a **persona prompt** you
run inline or in a fresh session — its body is already a self-contained system
prompt.

- `finding-analyzer`, `finding-verifier`, `code-auditor` → read-only review passes.
- `exploit-developer`, `report-writer`, `knowledge-curator` → producing passes.

Run them sequentially by pasting the agent's `.md` as the role/system prompt. If
you want real delegation: Codex can declare them as TOML subagents in
`~/.codex/config.toml`; Gemini as custom commands/extensions. Both optional —
sequential personas work on day one.

## Step 3 — replace the missing enforcement (safety-critical)

This is where "runs on any LLM" stops being free. Claude Code gates writes and
live actions with permission prompts + plan mode. Elsewhere you must supply that
gate yourself.

- **Git hooks already protect commits/pushes** (leak + attribution). Verify they
  are active under the new tool: `git config core.hooksPath .githooks` then
  `.githooks/test.sh`. These fire regardless of which agent staged the change.
- **Codex: do NOT run full-auto.** Codex leans to unsupervised autonomy; its
  full-auto mode executes without approval gates. PenA's *read-only-by-default*
  and *scope gating* only hold if a human approves the writes and live-target
  actions. Run Codex in an approval/suggest mode.
- **Any tool:** `scope.md` is only as binding as the tool lets it be. Treat it as
  hard law and gate every live-target action manually. The rule "no active
  testing without a named in-scope target" is a human checkpoint, not something
  the model enforces on itself.

## Step 4 — verify the port

1. Ask the agent to recite the scope rule and the no-AI-attribution rule → proves
   the contract loaded.
2. `.githooks/test.sh` → proves the leak/attribution guards work.
3. `python3 .claude/tools/findings.py selftest` → proves the ledger works.

If all three pass, the vendor-neutral core is live on the new tool.

## Honest limits

- Doctrine ports cleanly; **mechanical enforcement is uneven**. On Codex/Gemini
  part of PenA's "safe by construction" degrades to "safe if the operator gates
  it." Budget for that — do not assume the new tool refuses out-of-scope actions
  on its own.
- **No subagent auto-delegation outside Claude Code.** You orchestrate the roster
  manually, or via that tool's own subagent system, and keep the personas in sync
  yourself.
- Keep one source of truth. If you maintain a trimmed `AGENTS.md`, generate it
  from `CLAUDE.md` — do not hand-maintain two contracts that will drift.
