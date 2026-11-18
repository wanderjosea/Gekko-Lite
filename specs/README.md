# Spec-anchored development (spec-anchored) — Gekko

Two speeds, split by the **trust boundary**: everything that decides what the model
may do, or what the operator sees about the security state. It is a trust boundary,
not a file-type boundary (listed in `SECURITY-GUARDRAILS-SPEC.md` §1).

| | Inside the boundary | Outside (KB, prompts, docs, experiments, layout) |
|---|---|---|
| Method | spec first (SDD, this document) | direct exploration with the agent |
| Source of truth | `SECURITY-GUARDRAILS-SPEC.md` (living) | the artifact itself |
| Evidence | `REQ-…` ↔ case executed in the gate | a test wherever new logic appears |
| Approval | HITL gate per stage | the one at commit |

## The living spec: `SECURITY-GUARDRAILS-SPEC.md`

It states what the boundary guarantees **today**. Each requirement has a stable id
`REQ-<AREA>-<NNN>`, a `MUST` sentence, a `WHEN/THEN` scenario and at least one case
executed in the selftest (marked with `req("REQ-…")`). The gate fails if a requirement
has no cases, if a marker names an id that is not in the spec, or if a case runs
without a requirement. The `NNN-slug/` folders are the **record of a change**; when
merged, their criteria are reconciled into the living spec (an AC that touches the
boundary ends up as a `REQ`).

## Reverse reconciliation

An edge case or a gap found while exploring may be fixed code-first **only if it
tightens** the boundary, in this order: failing test → fix → `REQ` in the living spec,
**all in the same commit**. Anything that **loosens** the boundary (allows something
that was previously blocked) always takes the long flow, with operator approval.
`.githooks/pre-commit` rejects a commit that touches the boundary without touching the
living spec (`GEKKO_SPEC_UNCHANGED=1` for a change with no behaviour change).

## Features inside the boundary (SDD)

The discipline for building features that touch the boundary. Lightweight, native,
no new dependencies. It reuses what already exists: the test gate (the `gekko-guard`
selftest, or a `unittest` for Python tooling) **is** the acceptance criterion.

## Why

We already had the external layers of SDD: the "what/why" and the design contract
in planning documents. What was missing was the middle layer: a **per-feature spec
with verifiable acceptance criteria that block implementation**, and the mapping
`spec → task → test`. This closes it.

## Flow (with a HITL gate at each step)

```
spec.md  →  [approve]  →  plan.md  →  [approve]  →  tasks.md  →  implement
 what/why                technical design        checklist        code
 + criteria              + files                 1 task →         gated by
   of acceptance         + risks                 ≥1 criterion     the tests
```

1. **`spec.md`** — what and why. No technique. Its heart is the **testable acceptance
   criteria**. Do not move on to `plan.md` until the spec is approved by the operator.
2. **`plan.md`** — technical design: where the code lives, affected files, open
   decisions resolved, risks. Do not move on to `tasks.md` without approval.
3. **`tasks.md`** — executable checklist. Each task closes **≥1 acceptance criterion**
   and names the **test** that proves it.

## The hard rule (what makes it *driven*)

- **No boundary code without an acceptance criterion ↔ test.** Each criterion maps to
  the `gekko-guard` selftest (or a `unittest` for Python tooling).
- **The spec is the source of truth.** If the code diverges from the spec, one of the
  two gets corrected — it is never left to diverge silently (same as the findings
  ledger: nothing "confirmed" without evidence).
- **The state of the feature is auditable**: the box ticked in `tasks.md` + the green
  test that backs it. Not "I think it's done".

It fits `.claude/rules/style.md` ("evidence before assertion", "hypothesis, not hope")
and KISS: the simplest spec that yields verifiable criteria.

## Structure

```
specs/
├── README.md            ← this file
├── SECURITY-GUARDRAILS-SPEC.md  ← living spec of the trust boundary
├── _template/           ← templates (copy for each feature)
│   ├── spec.md
│   ├── plan.md
│   └── tasks.md
└── NNN-slug/            ← one folder per feature (NNN incremental)
    ├── spec.md
    ├── plan.md
    └── tasks.md
```

## How to start a feature

Invoke the `/spec-new` skill (or copy `_template/` to `specs/NNN-slug/` by hand).
Incremental three-digit numbering; short kebab-case slug.
