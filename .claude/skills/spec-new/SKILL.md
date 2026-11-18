---
name: spec-new
description: Drive Gekko's spec-driven development flow (spec → plan → tasks → implement) for a new or in-progress feature. Use when starting a new feature, when the user says "new spec", "spec this feature", "let's spec X", or when asked what to build next under SDD. Enforces the hard rule — no product code without an acceptance-criterion-backed test.
tags: [development, sdd, spec, planning, testing, feature]
---

# spec-new — spec-driven development driver

Gekko builds features spec-first. The convention lives in `specs/README.md`; read
it if unsure. This skill drives the flow and enforces the gate at each step.
User-facing output follows the language of the request; spec artifacts are written
in English.

## When this applies (spec-anchored)

Use this flow for work that touches the **trust boundary** (what the model may do, or
what the operator sees about security state — list in `specs/SECURITY-GUARDRAILS-SPEC.md`
§1) or when the operator asks for a spec. KB, prompts, docs, experiments and layout are
explored without a spec. A tightening fix found while exploring may land code-first
(failing test → fix → REQ in the living spec, same commit); anything that loosens the
boundary uses this flow. When a feature merges, reconcile its boundary criteria into the
living spec as `REQ-<AREA>-<NNN>` with a `req("…")` marker on their selftest cases.

## The flow (one HITL gate per stage — never skip a gate)

1. **spec.md** — what & why + testable acceptance criteria. NO technical design.
2. **plan.md** — technical design, affected files, resolved open questions, risks.
3. **tasks.md** — executable checklist; each task closes ≥1 acceptance criterion
   and names its test.
4. **implement** — write code, gated by the tests the criteria name.

**STOP after each stage and get operator approval before generating the next.**
Do not write plan.md until spec.md is approved; do not write tasks.md until plan.md is
approved; do not write product code until tasks.md is approved.

## The hard rule (enforce it, do not negotiate it)

- No product code without an acceptance criterion ↔ test. Each criterion maps to the
  `gekko-guard` selftest
  (`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`), or a
  `unittest` for any Python tooling in the repo.
- The spec is the source of truth. If code and spec diverge, fix one — never let
  them drift silently.
- A task's checkbox is checked ONLY with a green test behind it, recorded in the
  tasks.md verification log.

## Starting a new feature

1. Pick the next incremental number `NNN` (three digits) — check existing
   `specs/*/` folders.
2. Create `specs/NNN-slug/` and copy the three files from `specs/_template/`.
3. Fill `spec.md` first. Ground every acceptance criterion in the actual code
   (read it — criteria must be able to fail, and must name a real test command).
4. Present spec.md, stop at the gate.

## Continuing a feature

Read the feature's current stage from which files are filled and their `Status:`
line. Move to the next stage only if the prior one is `APPROVED`.
When implementing, run each acceptance criterion's test and record it in the
tasks.md verification log before checking the box.

## Definition of done

All acceptance criteria green at once + tasks.md checklist complete with its
verification log + no regression in the existing gate
(`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`). Then flip the spec
`Status:` to `IMPLEMENTED`.
