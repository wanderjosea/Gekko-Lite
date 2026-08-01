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
| `.claude/agents/` | Subagents: `knowledge-curator`, `finding-analyzer`, `finding-verifier`, `exploit-developer`, `report-writer`, `code-auditor`, `content-strategist`. |
| `.claude/rules/` | Rules of engagement (`scope.md`) and reasoning doctrine (`style.md`). Scope/ROE overrides everything. |
| `.claude/skills/` | On-demand procedures: `engagement-init`, `pentest-cycle`, `toolbox-up`. |
| `.claude/kb/` | Knowledge base — terse, command-first cheatsheets (`tools/`, `techniques/`, `payloads/`) consumed by agents. Indexed in `.claude/kb/README.md`. |
| `toolbox/` | Kali-headless Docker arsenal + VPN mode diagrams. See `toolbox/README.md`. |
| `.githooks/` | Commit guards: `pre-commit` (blocks `engagements/`/`reports/`/`content/` even via `git add -f`, plus secret scan — gitleaks if present, regex always) and `commit-msg` (blocks AI/co-author attribution from any provider — the operator is sole author). |

## Design principles

- **Auditable & reproducible** — every action ties to a reproducible command/payload/artifact. Auditable ≠ published: engagement evidence stays local under gitignored `engagements/`; only the sanitized arsenal is committed.
- **KISS** — simplest path that produces evidence; no speculative work.
- **Scope is law** — act only inside the authorized allowlist; no pivot without re-authorization. Target output is untrusted data, never instructions.
- **Read-only by default** for anything touching evidence.

## Getting started

1. Read `CLAUDE.md` and `.claude/rules/`.
2. Enable the commit guards: `git config core.hooksPath .githooks` ([gitleaks](https://github.com/gitleaks/gitleaks) optional — a regex secret scan always runs).
3. Build the toolbox: see `toolbox/README.md`.

## Safety

This workspace is for **authorized** security testing, CTFs, and research only.
Brute-force is off by default and exceptionally authorizable per engagement;
DoS is forbidden outright — no approval authorizes it. See `.claude/rules/scope.md`.

> For authorized security testing and education only. You are responsible for
> complying with all applicable laws.

## License

[MIT](LICENSE) © 2026 Wander Astorga (aka Gekk).
