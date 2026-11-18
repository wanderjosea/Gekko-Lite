---
name: agent-harness-audit
description: >
  White-box security review of an LLM agent stack you can read: the harness
  (hooks, permissions, delegation, memory), an MCP server, or a skill/plugin
  package. A checklist by trust boundary, each item answered with a file:line
  or a failing test. Use when asked to "audit this agent/harness/MCP server",
  "is this skill safe to install", "review our guard", or before adopting a
  third-party skill or MCP server. Also the right tool to audit Gekko itself.
  For attacking a live AI target from outside use `ai-redteam-cycle`.
tags: [audit, code-review, ai-security, agent, mcp, skills, supply-chain, hardening]
---

# Agent harness audit

Static-first review of the code and config that sit between a model and the
world. Read-only by default (`scope.md`): nothing under review is executed on
the host — third-party skills and servers are hostile until proven otherwise;
detonate only in the disposable container.

## How to run it
1. **Draw the data flow first.** List every source of text that reaches a
   context window (user, tool output, file read, memory, fetched content,
   subagent result, tool/skill metadata) and every sink a model output can
   drive (shell, file write, network, credential store, another agent).
2. **Walk the five boundaries below.** For each question record `yes / no /
   not applicable` plus the `file:line` that proves it. "I think so" is `no`.
3. **Turn every `no` into a falsifier** — a test input that should be blocked.
   Run it only in the project's own selftest or the container.
4. **Report through the ledger**: each gap is a hypothesis for
   `@agent-finding-verifier`; code-level review goes to `@agent-code-auditor`.

## The five boundaries
| # | Boundary | Ask | Load KB |
|---|---|---|---|
| 1 | **Untrusted text → context** | Is every target-derived string fenced and sanitised before the model sees it — including text that was written to disk and read back, and subagent results? Are invisible Unicode (zero-width, TAG block U+E0000–E007F) and homoglyphs handled? | `kb/techniques/prompt-injection.md` |
| 2 | **Config and memory as instructions** | Which files are auto-loaded as instructions (`CLAUDE.md`, `AGENTS.md`, memory, skills)? Can the agent, a repo it clones or target content write to any of them? | `kb/techniques/prompt-injection.md` |
| 3 | **Model output → action** | Does the permission check run *before* the side effect? Is it enforced in code or only asked of the model? Do individually allowed commands compose into a forbidden one? Does a denied call leave an audit entry? | your KB, tool-permission entries |
| 4 | **Delegation and resumption** | When content crosses to a subagent, a scheduled task or a resumed goal, does it keep its provenance — or does tool output come back as a user/system message? | your KB, multi-agent entries |
| 5 | **Secrets and egress** | Can a tool result, error message or log carry a credential into the transcript sent to the provider? What can reach the network, and is that allowlisted outside the process? | your KB, egress entries |

## Extra checks by artifact
- **MCP server** — taint from tool arguments to shell/file/URL sinks (SSRF, path
  traversal, command injection); auth on the transport; tool descriptions that
  carry instructions; behaviour that changes after trust is established.
- **Skill / plugin package** — read every file, not just `SKILL.md`: shell in
  prose, fetch-and-execute, writes to `PATH`/`pip.conf`/git hooks/cron, plain
  stdlib deletion (scanners miss it), a name that squats a hallucinated one.
- **Setup path** — does the agent run installs from a README or requirements
  file it did not author?

## Discipline
- **A guard in the model's own process is not containment.** Record which
  guarantees are enforced in-process and which by the container/egress layer;
  a gap covered only by the first is still a gap.
- **Published detection rates are paper claims** — use them to decide where to
  look hardest, never as evidence that a check passes.
- **Weight the costlier error**: a false "safe to install" is worse than a
  false alarm. Say which way you leaned.
- A regex blacklist that a test bypasses is a finding even if "the fence is the
  real defence" — record it and state what the real defence is.
