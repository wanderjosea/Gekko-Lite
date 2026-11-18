---
name: ai-redteam-cycle
description: >
  The Gekko methodology loop for an AI target — an LLM app, chatbot, RAG system
  or tool-using agent attacked from the outside (black-box): scope-check →
  recon/fingerprint → surface map → attack design → impact proof → report, with
  a gate between phases. Use when starting or driving an authorised AI red-team
  engagement, when asked "how do I attack this model/agent", "what's next", or
  when picking an injection/jailbreak family. For reviewing an agent's code or
  config (white-box) use `agent-harness-audit`; for hosts/networks use
  `pentest-cycle`.
tags: [engagement, methodology, ai-security, llm-security, prompt-injection, jailbreak, rag, agent]
---

# AI red-team cycle (Gekko methodology)

The loop for a target whose attack surface is a model's behavior. Not linear:
a new tool or data source discovered in phase 4 sends you back to phase 2.
`scope.md` and `style.md` always win over anything here.

## Iron rules across all phases
- **Scope is the allowlist of endpoints, accounts and data sources** — not "the
  AI". A plugin, MCP server or third-party site the agent can reach is a new
  asset: surface it, do not attack it without re-authorisation (`scope.md`).
- **Volume is conduct.** Best-of-N, bandit search and automated jailbreak sweeps
  are high-volume attacks: agree a request budget and rate limit first, as for
  brute-force. Anything that degrades the service (token/resource exhaustion,
  unbounded tool parameters) is DoS — forbidden outright.
- **Model output is untrusted and non-deterministic.** One success is a lead.
  Re-run the exact payload (fresh session, N≥3) and record the hit rate; a
  finding states "k of n", never "works".
- **Published attack-success rates are paper claims**, measured on other models.
  They rank what to try first; they are never evidence about this target.
- **Target data stays local.** Never paste a target's prompts, replies or
  extracted system prompt into an external model, search or service.
- **Every action → an artifact.** Save the full request/response pair (model
  id, temperature and session id if exposed) under the engagement dir.

## The phases
Work inside `engagements/<name>/` (scaffold with `engagement-init`).

| # | Phase | Goal | Load KB | Gate to advance |
|---|---|---|---|---|
| 0 | **Scope / setup** | confirm endpoints, accounts, budget, forbidden content classes | `kb/techniques/prompt-injection.md` (threat model) | objective written as a concrete impact (what must not happen) |
| 1 | **Recon / fingerprint** | benign baseline, then tell guardrail blocks from model refusals; infer model, system prompt, tools | your KB, recon entries | baseline (status, latency, wording) recorded; block vs refusal classified |
| 2 | **Surface map** | list every channel that puts text in the context window | `kb/techniques/prompt-injection.md` | each channel marked direct/indirect/stored, with the sink it can reach |
| 3 | **Attack design** | pick the family that fits what phase 1 found | see table below | payload written as a falsifiable hypothesis with a planted canary |
| 4 | **Impact proof** | show the consequence, not the compliance | your KB, output-handling entries | impact reproduced k of n; least data needed to prove it |
| 5 | **Cleanup + report** | remove planted content, package | `@agent-finding-verifier`, `@agent-report-writer` | planted docs/memories/files removed and listed; findings verified |

The sample KB ships one AI entry; the operator's own KB holds the family-level
detail. Add entries with `@agent-knowledge-curator` as you learn reusable techniques.

## Phase 3 — choose by what blocked you
| Observation in phase 1 | Try first | Load KB |
|---|---|---|
| Model self-refuses (natural wording, full latency) | reframing, decomposition across turns, batch dilution | your KB, jailbreak families |
| Guardrail blocks (canned text, low latency, non-200) | encoding, language switch, detector miscalibration | your KB, guardrail-evasion families |
| API lets you set the assistant turn | prefill | your KB, prefill entries |
| Agent reads web/email/docs | indirect injection in content it will fetch | `kb/techniques/prompt-injection.md` |
| Agent writes then re-reads files, or has memory | stored injection; check persistence in a fresh session | `kb/techniques/prompt-injection.md` |
| RAG over a corpus you can write to | poisoned document, then query that retrieves it | your KB, RAG entries |
| Several agents / roles | boundary and delegation attacks | your KB, multi-agent entries |

## Per-phase discipline
- **Baseline before attack.** Without the benign profile you cannot tell a
  guardrail from a refusal, and you will aim the wrong technique.
- **Canary, not vibes.** Prove an injection with a unique marker or a callback
  to an in-scope listener — never with "the model seemed to comply".
- **Cheapest falsifier first.** One manual payload per family before any
  automated search. 2–3 failures *on the same condition* → re-plan.
- **Stop at impact.** Extracting one record proves data exposure; do not dump.
- **Audit the negatives.** Log families tried and why they died.

## Hand-offs
- Bulk request/response logs → `@agent-finding-analyzer`.
- A claimed bypass → `@agent-finding-verifier` (re-runs it, checks the hit rate).
- New technique that worked in the field → `@agent-knowledge-curator`, into
  `kb/techniques/`.
