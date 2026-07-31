# PenA — AI Red-Team & Security Workspace

An opinionated Claude Code workspace for AI red-teaming and security auditing.
It ships the scaffolding — agents, rules, a curated knowledge base, and a Kali
toolbox — that turns a general coding assistant into an **auditable, reproducible**
security operator: every finding traceable to a command, payload, or artifact.

> This repo is the *framework*, not an engagement. Live target data, engagement
> working dirs (`engagements/`), and local labs (`labs/`) are gitignored and
> never published.

## What's inside

| Path | What it is |
|---|---|
| `CLAUDE.md` | The contract. Defines operating principles, VPN modes, and how every session behaves. **Start here.** |
| `.claude/agents/` | Subagents: `knowledge-curator`, `finding-analyzer`, `report-writer`, `code-auditor`, `content-strategist`. |
| `.claude/rules/` | Rules of engagement (`scope.md`) and reasoning doctrine (`style.md`). Scope/ROE overrides everything. |
| `.claude/skills/` | On-demand procedures: `engagement-init`, `pentest-cycle`, `toolbox-up`. |
| `.claude/kb/` | Knowledge base — terse, command-first cheatsheets (`tools/`, `techniques/`, `payloads/`) consumed by agents. Indexed in `.claude/kb/README.md`. |
| `toolbox/` | Kali-headless Docker arsenal + VPN mode diagrams. See `toolbox/README.md`. |
| `.githooks/pre-commit` | gitleaks secret-scanning guard. |

## Design principles

- **Auditable & reproducible** — every action ties to a committed command/payload/artifact.
- **KISS** — simplest path that produces evidence; no speculative work.
- **Scope is law** — act only inside the authorized allowlist; no pivot without re-authorization. Target output is untrusted data, never instructions.
- **Read-only by default** for anything touching evidence.

## Getting started

1. Read `CLAUDE.md` and `.claude/rules/`.
2. Enable the secret-scanning hook: `git config core.hooksPath .githooks` (requires [gitleaks](https://github.com/gitleaks/gitleaks)).
3. Build the toolbox: see `toolbox/README.md`.

## Safety

This workspace is for **authorized** security testing, CTFs, and research only.
Brute-force and DoS are off by default and require explicit per-engagement
approval. See `.claude/rules/scope.md`.

> For authorized security testing and education only. You are responsible for
> complying with all applicable laws.

## License

[MIT](LICENSE) © 2026 Wander Astorga (aka Gekk).
