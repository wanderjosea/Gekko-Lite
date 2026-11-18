# Spec 015 — Reports UI redesign

> Status: IMPLEMENTED for this reading stage — visual correction and local font verified.
> AC10 closed with prior evidence from the coding agent and `shots/font-local/verificacion.md`.
> Later authorized exception: Space Grotesk WOFF2 embedded and CSP font-src data:;
> see `font-local.md` and REQ-RPT-017. It does not declare readiness or deployment.
> Scope: presentation of the read capabilities already existing in module 012.

## Problem and goal

The current console presents the work queue, the evidence and the ledger warnings with little emphasis. The goal is a
more legible lab-atlas interface for listing real workspaces, finding findings and reviewing their detail, keeping intact
the data model, the states, the report eligibility and the server constraints.

The layout indicated by the operator prevails: with the assistant open on desktop (width ≥1280 px), the detail and the
assistant take equal halves and the layout reaches both edges; closed, the detail is centred with a comfortable width. At
smaller widths the assistant takes a dedicated view and allows returning to the finding.

## Audited real capabilities

- `findings_web.py` reads workspaces under the configured root, validates name,
  `scope.txt`, type and confinement of the directory; it lists figures on the index.
- The real routes are index, list per workspace and detail per ledger line.
  The list accepts search `q` and severity filter `sev`; both are GET.
- The detail shows the finding's existing fields; ledger values are escaped as text. Invalid lines are reported
  individually; an unreadable ledger is represented as an error without showing its content.
- The only current web write is choosing the theme. The manual update loads the code that is already on disk. The
  module does not serve JavaScript or static files.
- Today there are no state filters nor section navigation; AC2 and AC3 add them as GET controls and native reading
  links. There are no state changes, chat, model connections or web export; they remain outside this spec.

## Acceptance criteria

Each criterion will be verified with `bash tools/report-test.sh` and new cases of the `findings_web.py` selftest; the cases
will test the output of `respond()` with temporary ledgers and fictitious data, without reading real `engagements/`.
Browser tests and screenshots will be defined in `plan.md` after this stage is approved.

| ID | Criterion | Required test |
| --- | --- | --- |
| AC1 | The index only lists workspaces that meet the current rules and keeps its contract of not showing titles, targets or finding evidence. It does not include a fixed demonstration workspace. | `tools/report-test.sh` |
| AC2 | The list keeps search and severity filter as GET; it adds a native state filter only if it can be derived from valid ledger rows. The intersection of filters preserves query and theme, and an unknown state is not grouped with a valid one. | `tools/report-test.sh` |
| AC3 | The detail separates Summary, Evidence and corroboration, and Record in accessible navigation; the warnings for block, lack of corroboration, broken line and unreadability remain visible even when the section changes. | `tools/report-test.sh` |
| AC4 | The evidence output is shown literally as escaped text, with collapsible presentation and without interpreting HTML, controls or bidi values; artifacts remain text, not served links. | `tools/report-test.sh` |
| AC5 | The layout of the closed detail has a centred reading width; the open assistant remains absent from the normal flow, marked NOT BUILT in preview if shown as a proposal, and does not imply a connection. The 50/50 distribution can only be activated together with a real assistant in a later spec. | `tools/report-test.sh` |
| AC6 | The report remains the existing read-only output, with its eligibility unchanged. No export controls appear in the normal flow while no supported web exporter exists. | `tools/report-test.sh` |
| AC7 | Light/dark theme, keyboard navigation, visible focus, reduced motion and reading without JavaScript work on the reading pages. | process/browser test defined in `plan.md` |
| AC8 | Missing/empty ledger, unreadable, with broken lines, unknown data and the view with reloaded data keep truthful messages; no UI change hides a warning or claims an unfinished operation. | `tools/report-test.sh` |
| AC9 | The index, list and detail keep serving only the allowed routes and methods; the UI does not add writing, chat, connections, download or CSP relaxations. Theme and update keep their current validations. | `tools/report-test.sh` |
| AC10 | The views are reviewed at 390, 760, 1024 and 1500 px in both themes, compared with the approved references; product screenshots and a Pass/Fail/Not verified matrix are attached. | visual/browser test defined in `plan.md` |

## Out of scope

- Writing the ledger, changing state, corroboration form or blocking.
- Chat, connection to the Provider/model, streaming, prompt sanitisation or copying of model proposals.
- Web export/download, artifact generation or new endpoints.
- Modifying CSP to enable scripts, open connections or serve new resources.
- Changing states, meanings, counters or eligibility of `findings.py render`.
- Using workspaces, titles, targets or operational evidence in tests or screenshots.

## Risks and pending decisions for the plan

- The view exposes security data of a real operator workspace, so the HTML, routes, warnings and states stay inside the trust boundary.
- The previous visual spec assumed simulated interactions and a static served prototype; the current product is server-rendered and without JavaScript. The plan must choose progression without scripts or propose new capabilities in a separate spec.
- The tab navigation contract must be usable without depending on JS; if the pattern requires JS, all sections must remain available in the HTML.
- The 50/50 assistant stays as a requirement for a future stage, when an approved assistant backend exists; it will not be pretended to be implemented in this delivery.
