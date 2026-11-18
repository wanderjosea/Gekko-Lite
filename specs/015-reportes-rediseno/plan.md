# Technical plan 015 — Reports UI redesign

> Written after `spec.md` was approved (approval received: "avanza" — "go ahead").
> Status: IMPLEMENTED — corrective comparison completed with the local font exception
> authorized in `font-local.md`. AC10 closed; additional evidence in
> `shots/font-local/verificacion.md`. Prior font restrictions are excepted only for that embedded WOFF2 and font-src data:, with no new paths or network.

## 1. Approach

Keep the Python server and the server-rendered responses. Adjust the inline HTML/CSS of `findings_web.py` and the GET forms to give hierarchy to index, list and detail, without JavaScript or new resources. The index remains limited to the authorised figures; search, severity filter and state filter will use validated parameters and data from the same ledger. The detail will use internal links with fragments and CSS `:target` as navigation without JavaScript; the security warnings stay outside the selectable panels and always visible.

There is no assistant backend nor web report/export route. No fictitious buttons or destinations are added to the product. The assistant, including the 50/50 split, is deferred; the closed detail is centred. The report of `findings.py render` remains an existing CLI operation, not a new web screen.

## 2. Affected files

| File | Change | AC served |
|---|---|---|
| `.claude/tools/findings_web.py` | Reorganise shell, index, list and detail; add exact GET state filter; order detail into Summary/Evidence and corroboration/Record; collapsible literal output; responsive CSS; keep escaping, CSP, routes, theme and existing actions. | AC1–AC9 |
| `.claude/tools/findings_web.py` (selftest) | Cases with temporary root and fictitious ledgers for combined filters/unknown states, persistent warnings, fragments, hostile evidence, broken rows, absence/empty/unreadability, and allowed responses/methods. | AC1–AC4, AC6, AC8–AC9 |
| `tools/report-test.sh` | Keep the current gate and extend it only for the HTTP walk of list, filters, detail, theme and routes; workspaces are created inside `mktemp`. | AC1–AC4, AC8–AC9 |
| `specs/SECURITY-GUARDRAILS-SPEC.md` | Reconcile the 015 UI requirements as new `REQ-RPT-*` and keep each MUST linked to executed cases; document visual verification limits. | AC1–AC9 |
| `specs/015-reportes-rediseno/tasks.md` | Checklist with one task per criterion, commands and Pass/Fail/Not verified record; to be written after this plan is approved. | AC1–AC10 |
| `specs/015-reportes-rediseno/shots/` | Screenshots of the product served from temporary fixtures, both themes and the requested widths. Do not replace or move mockup screenshots. | AC10 |

`mockups/_src/`, the generated HTML of the mockups, `findings.py`, launchers, engagement data, CSP configuration for scripts/connections, and the server's routes/methods will NOT be modified. If development reveals that a section requires a new capability, it will be split into another spec and not incorporated into this implementation.

## 3. Decisions

- **State in GET filter:** accept only exact values of `findings.py STATUSES`. The empty value means "Todos" (All). Unknown states remain visible under "Todos", are shown as unknown and are not associated with a known option. Counters and eligibility are not altered.
- **Native filters:** `q`, `sev` and `status` share a GET form. The options show only known valid states; the unknown parameter is normalised to "Todos" and is not reflected as HTML. The additional filter does not search other workspaces or evidence.
- **Tabs without scripts:** native links to `#resumen`, `#evidencia` and `#registro` with tab appearance; CSS `:target` selects the section. They are link navigation, not `role="tablist"`, which would require the keyboard interaction that ARIA tabs demand. Without a fragment, Summary is shown; warnings and status stay outside the content that is hidden.
- **Literal evidence:** keep the existing `esc()` and sanitisation. The output goes into `<details><pre>` and the artifact stays as text. No copy button depending on JavaScript is added.
- **Workspace and report:** the index keeps its real discovery rule and no fixed demonstration row. No "Reporte" navigation is added: there is no web route nor preview served by the module. Export stays out.
- **Assistant:** it is not rendered in the product. Therefore the 50/50 distribution has no implementation until a spec for the assistant's backend and UI. No connection label or NOT BUILT preview is shown in the normal flow.
- **Responsive:** list with reduced columns and target under the title at small widths; detail with centred reading and tables inside the viewport and no horizontal document overflow. Keep the product's token mechanism and map its visual values to Atlas according to matrix V of `tasks.md`; do not keep the previous palette as a substitute for the rework. No fonts downloaded and no CSP capabilities altered. Font/isotype differences require resolving their applicable authorization, not declaring automatic equivalence with the current resources.
- **Tests:** `tools/report-test.sh` is the product gate; selftests with temporary folders. Firefox 152 is installed for headless screenshots; Selenium, Playwright and geckodriver are not available. Screenshots alone do not count as interaction tests: GET/POST interactions will be covered against the real process; keyboard and visual reading will be recorded as manual or Not verified if no interactive session is available. Do not install dependencies.

## 4. Risks and mitigation

- **Filter makes a new state look absent.** "Todos" keeps rows of unknown state; it is tested next to nearly matching values (`confirmed `, uppercase and non-text types) to prevent false classification.
- **CSS tabs hide warnings or content without JavaScript.** Persistent warnings live outside the panels; each link leads to a navigable section, and HTML responses are tested with the three panels plus screenshots of each fragment.
- **Narrow CSS makes data unreadable or shifts the page.** Test 390, 760, 1024 and 1500 px in light/dark with fictitious ledgers including long values. The document will have a 72ch limit when any assistant panel is closed.
- **Visual change loosens the existing boundary.** Do not add scripts, fonts, destinations, methods or actions; the capabilities allowed by CSP remain unchanged. The `style-src` hash is recalculated from the final CSS through the existing mechanism; verify that it matches the served block. Run the selftest and `tools/report-test.sh`, and review HTTP responses and the hashes of the temporary ledgers before closing.
- **Interactive verification may remain incomplete in this environment.** Headless Firefox allows screenshots but does not prove keyboard navigation. The record will distinguish evidence from screenshots, HTTP walk and manual check; no criteria will be marked Pass by static inspection.
- **Difference from the mockup:** there will be no web report screen nor assistant while real capabilities do not exist; this will be documented in the checklist and the delivery without inventing messages, hashes or eligibility.

## 5. Order of attack

1. First add failing cases for state filters and untrusted text, using exclusively ledgers in temporary folders; run `python3 .claude/tools/findings_web.py selftest`.
2. Implement the validated filter and the list changes; repeat the selftest and verify the combined parameters over HTTP in `tools/report-test.sh`.
3. Reorder detail, warnings, panels per fragment and collapsible output; add tests for escaping, warning persistence, references and broken line.
4. Apply responsive layout to index/list/detail and review screenshots generated from the server with temporary fixtures against the reference `mockups/shots/`.
5. Update the living requirements; run `bash tools/report-test.sh`, the gate `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` and `.githooks/test.sh`. Record results per AC; any interaction not executed stays Not verified.

## 6. Review clarifications for the checklist

- `tasks.md` is the canonical name; do not create a second checklist `task.md`.
- Verify the browser tools available at implementation time. The list of tools in §3 describes the previous audit; do not install dependencies nor treat the previous absence as an obstacle to current checks.
- HTTP tests verify HTML and contracts, but not what `:target` hides. Check in the browser: initial section, the three fragments, unknown fragment, back/forward and persistent warnings. Without a browser: Not verified, never static Pass.
- Native link navigation, not incomplete ARIA tabs; printing must allow reading all sections. Do not add artifact URLs or copy promises.
- Resolve before implementing the phrase «No existen filtros de estado web, pestañas […] No forman parte de esta spec» ("There are no web state filters, tabs […] They are not part of this spec") of `spec.md`: it correctly describes the current situation, but AC2/AC3 do authorise a state filter and section navigation at this stage. Clarify that wording without expanding the approved scope.
- The 50/50 assistant layout is expressly deferred (AC5), even though it appears as a visual reference from the operator. This stage does not constitute the migration of all the simulated capabilities of the twelve mockups.
