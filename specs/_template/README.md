# SDD — Non-negotiable rules

These rules are NOT optional. No matter the urgency, the size of the change,
or who asks for it. Skipping any of them invalidates the feature.

## 1. No boundary code without an approved spec
- These rules apply to what touches the trust boundary (`../SECURITY-GUARDRAILS-SPEC.md` §1);
  outside it you explore without a spec (see `../README.md`).
- Every boundary feature starts in `spec.md`. The **what** and the **why** are written
  before touching a single line of code.
- The spec does not move on to `plan.md` without explicit operator approval.
- The plan does not move on to `tasks.md` without explicit operator approval.
- **Three gates, three approvals. None of them are skipped.**

## 2. Every acceptance criterion has a test
- If it has no test, it is not a criterion — it is a wish.
- The test must be able to **fail**. A test that always passes proves nothing.
- The mapping `criterion → test` is declared in `spec.md` and fulfilled in
  `tasks.md`. No orphan criteria and no tests without a criterion.

## 3. The spec is the source of truth
- If the code diverges from the spec, one of the two gets corrected.
- **Never** let it diverge silently. Silent divergence is invisible technical debt —
  the worst kind.
- Changing the spec after implementing is valid (specs evolve), but the change is
  documented and the tests are updated.

## 4. One task = one verifiable criterion
- Each task in `tasks.md` closes **at least one** acceptance criterion.
- The box is ticked **only** when the test passes green.
- "I think it's done" does not count. The green test counts.

## 5. Regression is a task
- The last task of every spec is: "do not break what already works".
- The existing test suite must keep passing. If it breaks, it is fixed
  before closing the spec.

## 6. The state is auditable
- Ticked box + green test + verification log = done.
- Without a verification log, the box has no backing.
- Anyone must be able to reproduce the verification with the commands
  from the log.

## Anti-patterns (we have fallen into these — do not repeat)
- **Implementing "fast" and writing the spec afterwards.** A post-hoc spec always
  justifies what was done, not what should have been done.
- **Vague criteria.** "It should work well" is not a criterion. "The endpoint returns
  200 with a valid payload and 422 with an invalid payload" is.
- **Giant spec.** If the spec has more than 10 criteria, it is more than one feature.
  Split it.
- **Skipping the plan.** Without a plan, technical decisions get made improvised during
  implementation. The plan is where they get resolved.
- **Tests that are never run.** A test written but never executed does not exist.
  The verification log proves it was run.
