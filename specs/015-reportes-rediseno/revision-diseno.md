# Layout review — proposal, NOT BUILT

This proposal complements `design.md`; it does not approve product features.
For recreating the mockups, the detailed contract at the end of this file prevails over the earlier visual decisions in `design.md` and over the conceptual summary of this review. The repository's security contracts always prevail.
Visual review of the existing list and detail screenshots in dark and the report in light, and reading of their generators, CSS and JavaScript. No engagements were consulted.

## Diagnosis

The identity works; the hierarchy still demands too much reading to decide.
The list repeats the same figures in navigation, summary and filters. The detail reserves 440 px for the chat before the operator needs it. The report dedicates 400 permanent px to controls that are used when preparing the delivery, while narrowing the document.

Do not solve this by reducing fonts or turning the table into cards: the main unit of work is still a finding, and comparing rows is what matters.

## Visual direction

Keep Space Grotesk for navigation and reading; reserve JetBrains Mono for IDs, commands, paths and hashes. Labels in sentence case, without monospace by default.
Proposed scale: title 26 px, section 18 px, reading 16 px, table 14 px, metadata 12 px.
Text aligned left; detail body of 65–75 characters per line.

Conceptual palette for dark: background `#090F0C`, surface `#121B16`, text `#EDF3EE`, secondary `#A9B7AD`, action `#C8F31D`, attention `#F5BF55`. Reuse the existing semantic tokens for severity, errors and light theme; verify contrast before implementing these values. Spacing of 8/16/24/32 px, separators only between groups.

The distinctive feature is the relationship between evidence and corroboration. Keep it visible with explicit names; the two squares are support, not substitutes for the explanation.
Lime is kept for the main action and focus. Do not add entry animations.

Review of the concept: discard a new global sidebar and more metric cards. Both would add structure without helping this task. Keep the top navigation.

## List: choose what to review

```text
GEKKO   Workspace                 Hallazgos   Reporte          Ajustes

Hallazgos 12                          2 por validar · 1 sin corroboración

[Buscar hallazgos........................] [Estado ▾] [Severidad ▾]
Filtros activos, sólo cuando existan                  Limpiar filtros

Severidad   Hallazgo / objetivo                 Estado          Cambio
Alta        F-0002 · Título completo...          Por validar     hace 4 min
            Objetivo / ruta
```

- Suppress the strip of five metrics; severity distribution goes inside the filter.
- Keep the two actionable notices visible. Their groups may overlap: do not add them up to invent a total of pending items.
- Five columns: severity, finding (ID integrated), target if it fits, state and change.
  In smaller windows, target under the title; then remove its independent column.
- Take the summary, CWE and CVSS out of the default view. They remain available in the detail and in search where applicable. Titles of up to two lines before truncating.
- No results: show the applied filters and an action to clear them. Unreadable ledger, broken lines and stale data keep explicit notices and their restrictions.

## Detail: understand and verify

```text
‹ Hallazgos                          Anterior / siguiente     Abrir asistente

F-0002 · Alta                                      Por validar
Título del hallazgo
Objetivo
Falta corroboración                                Revisar estado

[Resumen] [Evidencia y corroboración] [Registro]

Resumen / impacto / remediación
```

- Compact, persistent header with state and block. The full text of the block must be consultable without opening the assistant.
- Summary opens first for reading; a "Revisar evidencia" (Review evidence) action opens the signals section directly when arriving from the validation queue.
- Evidence and corroboration together; literal output in an expandable block. Never hide that a signal is missing, even when the section is not selected.
- Record groups hashes, dates, ledger line and technical classification.
- Assistant closed initially. When opened, a side panel of 360–400 px only if it leaves enough width for the document; on mobile, a dedicated view with a return and focus restoration.
- The context sent and the option to include output stay visible before sending; tokens and latency move into details. Keep questions when there are connection errors.
- State change in a contextual panel, with the evidence accessible. One main action and a cancel exit; technical details of the command in collapsible sections.

## Report: review the delivery

```text
Reporte                          4 incluidos / 12          Exportar…
1 confirmado excluido: falta corroboración                 Revisar

                    Documento centrado
                    ancho de lectura cómodo

Opciones de exportación: panel sólo al solicitarlo
```

The numbers are from the existing synthetic mockup, not from operational data.
Do not confuse "confirmed" with "included": there are five of the former and four of the latter. Checks that block or exclude content remain visible; options, format and hashes are consulted on demand. The panel must show the effective selection before exporting. If the ledger changes, mark the view as stale.

## Interaction and polish review

Locations relative to `mockups/_src/`. The changes in the "Después" (After) column are proposals.

| Severity | Location | Before | After | Principle / impact |
| --- | --- | --- | --- | --- |
| HIGH | `build.py:462` | Confirmed says "entran al reporte" (enter the report), including an excluded one | Differentiate state and eligibility | Honest information: avoids misreading the delivery |
| HIGH | `app.js:193`, `base.css:430` | Closing the chat on desktop hides the panel; `showChat(true)` does not remove `hidden` or `nochat`, and the external button is hidden | Opening/closing with a single state and an always-accessible button | Recoverable interaction: the assistant must be reopenable |
| HIGH | `app.js:25` | Copy shows feedback without waiting for `writeText` | Confirm only when resolved; readable error if it fails | Truthful feedback: do not signal success without copying |
| MEDIUM | `build.py:458`, `build.py:468` | Repeated counts and twelve visible chips | Two filters and only active selections | Hierarchy: fewer elements competing for attention |
| MEDIUM | `base.css:266`, `base.css:433` | Chat and report controls occupy permanent columns | Panels on demand | Layout: recover space for evidence and document |
| LOW | `base.css:33`, `base.css:436` | Small labels, capitals and mono | Sans labels in sentence case | Typography: distinguish information from metadata |

**Block** to consider these interactions ready for the product. The HIGHs are static-inspection findings, still without browser reproduction.

## Technology

Proposal: keep Python as server and data source; HTML/CSS for the interface, and small JavaScript to open panels, filters and assistant behaviour.
Visual quality is determined by layout and CSS: Python does not force a poor interface.
The mockups themselves already combine a Python generator with CSS and JS.

Introducing React or changing backend is not justified just for this redistribution. Separate templates and resources from the server code when implementing, respecting its security contract. The current server is read-only and declares that it does not serve JS: adding resources, writing or chat requires the spec-first path and its tests.

## Scope and pending validation

The mockups and the product were not modified. This review proposes the layout; it does not certify all the screens in the catalogue. Any new mockup must carry a visible `NOT BUILT` and stay out of the product's navigation.

Not verified: interactive browser, hover/focus/active, keyboard, loading, empty and error states at runtime, mobile, contrast of the proposed palette, transitions and reduced motion.
No build or tests were run because only this review document was added.
Before implementing: validate the three proposed views at 1500, 1024, 760 and 390 px, test the previous states, and do a review against the repository's UI gate.

## Recreation contract for the coding agent

### 1. Assignment and exact limits

Recreate **the twelve existing pages** of `mockups/` with the layout fixed here.
The result is a local, self-contained prototype with synthetic data. Do not implement the reports backend, endpoints, model calls, ledger writes or connections.
Do not open `engagements/`. The existing laboratory names are generator fixtures.
Do not add dependencies, remote fonts, icon libraries, React or external services.

Edit the sources and regenerate the HTML; never edit the generated HTML by hand.
Keep the current routes so that the references in `design.md` keep working.
Do not touch changes by others that are present in git when starting.

| File | Responsibility and required change |
| --- | --- |
| `mockups/_src/build.py` | HTML structure, shared components, fixtures, initial states, links between mockups and the NOT BUILT notice |
| `mockups/_src/base.css` | Layout, typography, breakpoints, visual states and accessibility |
| `mockups/_src/app.js` | Local simulated interactions, filters, panels, tabs, copy and error states |
| `mockups/_src/shots.sh` | Reproducible screenshots at the four widths and states indicated below |
| `mockups/_src/check-ui.*` | A small behaviour test with the available tools; choose the extension according to the local runner, do not install one without need |
| `mockups/*.html` | Regenerated output of the twelve pages |
| `mockups/shots/` | New screenshots; preserve the previous ones as reference in `shots/antes/` before replacing them |
| `design.md` | Update visual architecture, screenshot table and component descriptions to reflect the result, without presenting it as an implemented product |
| `revision-diseno.md` | Add final evidence and limitations; do not mark criteria as approved without running them |

Search for all consumers of classes, IDs and attributes before changing them. In particular,
`#chat`, `#ask`, `#stslot`, `#stbtn`, `#stnow`, `#sig2`, `#f-remediation`, `#f-impact`,
`#view-doc`, `#view-md`, `[data-ask]`, `[data-apply]`, `[data-copy]` and `[data-quick]`.
Keep them if they serve; if they are replaced, update generator, JS, screenshots and tests together.

### 2. Closed style decisions

**Final colours for this iteration:** reuse `TOKENS` of `build.py` in full, in both themes. The conceptual palette above is discarded to avoid a second source of truth. Do not modify severities nor their meanings.

| Use | Specification |
| --- | --- |
| Interface typography | Local Space Grotesk, weight 400; buttons and titles 600 |
| Technical data | Local JetBrains Mono, weight 400; never for paragraphs nor form labels |
| Page/finding title | 26 px / 34 px; below 640 px, 22 px / 30 px |
| Section title | 18 px / 26 px |
| Detail/report reading | 16 px / 26 px; maximum width 72ch |
| Table, navigation and controls | 14 px / 20 px |
| Secondary metadata | 12 px / 18 px; essential information never smaller than 14 px |
| Spacing | 8 px inside controls; 16 px inside groups; 24 px between groups; 32 px between sections |
| Radii | Controls 4 px; panels 12 px with 16 px padding; document 6 px. Do not nest decorative boxes |
| Controls | Minimum height 40 px on desktop, 44 px below 640 px; icons 16 px inside a clickable area of that height and width |
| Borders | 1 px with `--line` only on separators and controls; focus 2 px with `--focus`, offset 2 px |
| Hover | Background `--raised`; do not move or scale rows |
| Pressed button | `transform:scale(.96)` only while `:active`; 100 ms; remove transform with reduced motion |
| Transitions | Color and background-color 120 ms; transform 100 ms; curve `cubic-bezier(0.2,0,0,1)`; never `all` |
| Page/panel entry | Instant, no stagger, no fade or displacement |
| Icons | Reuse the sprite, `currentColor`, 1.5 px stroke next to regular text. Avoid icons next to semibold text to keep a single weight |

Labels in sentence case. No automatic capitals, gradients, new indicator cards, decorative charts or new global menus. Tabular numbers in counts.
Keep the existing isotype. Do not use the confirmation green as the brand colour.
When changing theme, suppress transitions during the change and restore them on the next frame.

### 3. Shell and adaptive behaviour

All measures are CSS px. Main container `width:100%; box-sizing:border-box`.

| Viewport width | Side margins | List | Detail with assistant open | Report |
|---|---|---|---|---|
| ≥1280 | 32 | 5 columns | Flexible document + 384 px panel, gap 24 | Centred paper up to 880 px |
| 960–1279 | 24 | 4 columns; target under title | Dedicated assistant view | Centred paper up to 880 px |
| 640–959 | 24 | 3 columns; no Change | Dedicated assistant view | Fluid paper |
| <640 | 16 | 2 columns; severity and target inside Finding | Dedicated assistant view | Fluid paper, internal padding 16 |

Maximum width of the work area: 1440 px, centred. The table takes all the available width.
Detail without assistant: central column of at most 960 px; paragraphs limited to 72ch.
With assistant on desktop: use the whole work area, without reserving an empty column.

Shell in DOM order:

1. Skip-to-content link.
2. Persistent preview band of at least 28 px: **«NOT BUILT · Maqueta con datos sintéticos · Sin conexión al ledger»** (NOT BUILT · Mockup with synthetic data · No connection to the ledger).
3. Global header of 56 px: isotype/link to Workspaces, workspace selector,
   links Hallazgos and Reporte, "Conexión simulada" (simulated connection) indicator, Ajustes.
4. Screen-specific `main`.
5. 32 px provenance footer, in normal flow, not covering content; full path details and shortcuts under a "Procedencia y atajos" (Provenance and shortcuts) drop-down.

On mobile, a two-row header: brand/workspace/settings on top; Hallazgos/Reporte below.
Do not compress all controls into a single row. Band and header in normal flow;
only the detail subheader may be sticky on desktop, with `top:0`.
Below 960 px, the whole document uses page scroll and the subheader is not sticky.
Do not hide integrity, exclusion or lost-connection alerts in menus or tooltips.

### 4. List: exact structure and filters

Order: title → actionable notices → search/filters → active chips → integrity alert (if applicable) → table → results counter. Separation between layout rows: 16 px.
Title "Hallazgos" with a discreet count to its right, not another large indicator.
The notices "2 por validar" and "1 sin corroboración" are buttons with text and figure,
without cards. Aligned to the right of the title at ≥960 px; below it and wrapping at smaller widths.
A notice with a zero count does not appear. Do not mix both states nor add them up.

Filter bar ≥960: flexible search, minimum 280 px; State 200 px; Severity 180 px.
Between 640 and 959: search on a full row; the two selects share the second row.
Below 640: search and each select on its own full-width row.
Use a native `<select>` with a visible label. Do not build a custom select.

State options: Todos (All), Hipótesis (Hypothesis), Triado (Triaged), Por validar, Confirmado (Confirmed), Refutado (Refuted), and, only
when it exists in the fixture, Fuera de esquema (Out of schema). Severity: Todas (All), Crítica (Critical), Alta (High), Media (Medium),
Baja (Low), Info and Sin clasificar (Unclassified) when it exists. Include counts from the original set of the
page in the options; do not recalculate them according to the other filters.

Logic: search AND state AND severity AND the without-corroboration notice. Search by title, target, ID, CWE and CVE; keep those data even if they are not columns.
Textual comparison, case-insensitive; fuzzy search is not needed.
"Por validar" selects that state. "Sin corroboración" activates its filter and sets State to Todos to avoid an impossible combination with the previous notice; it keeps search and severity. Clicking the same notice again deactivates it. Reflect the selection with
`aria-pressed` and a removable chip. Clearing filters resets all of them, including search.
Do not use `press()` on all the `[data-st]` or `[data-sev]`: limit it to controls,
without adding button attributes to data rows.

Desktop columns: Severity 104 px, Finding flexible, Target 240 px,
State 176 px, Change 104 px. No independent column for ID, CVSS, CWE or arrow.
Cell padding 12 px vertical / 16 px horizontal; rows of automatic height.
Title up to two lines; ID before the title in secondary text. No summary shown.
Target moves under the title below 1280 px. Change is hidden below 960 px. Severity moves above the title below 640 px; State measures 112 px and allows wrapping.
The title link has native focus and complete accessible text; clicking the rest of the row may open it, but selecting text or using buttons must not navigate.
On mobile the title is not truncated. No horizontal page scroll at 390 px.

Table footer: "Mostrando N de T hallazgos" (Showing N of T findings). With zero matches: "No hay hallazgos
con estos filtros" (No findings with these filters) and "Limpiar filtros", keeping the controls. Do not confuse this state
with empty workspace or unreadable ledger.

### 5. Detail: content, tabs and actions

Top order: back/previous/next/open assistant → ID and severity → title →
copyable target → state and "Revisar estado" → notice → tabs → selected panel.
The title is never truncated. State is always visible even when switching tabs.
Compact notice: icon, "Falta corroboración" or "Confirmado sin corroboración", a "Revisar evidencia" button and a `<details>` "Ver bloqueo completo" (See full block). The text of the original block is kept intact. Open it automatically in rejection/confirmation states.

| Tab | Content, in order |
| --- | --- |
| Resumen (Summary) | Summary, Impact, Remediation; one column, no cards for each field |
| Evidencia y corroboración (Evidence and corroboration) | Evidence: command, artifact path, output; Corroboration: text or explicit absence; Steps to reproduce |
| Registro (Record) | CVSS/CWE/CVE, KB references, created/updated, ledger line and path, registered hashes; "Sin registrar" for absences |

Do not invent hashes, classifications or tests. The artifact path stays next to evidence; its hash is shown in Record to avoid duplication.
Literal output closed initially with the summary "Ver salida de evidencia" (View evidence output). When opened, maximum 320 px height with internal scroll, `pre-wrap`, copy and line wrap. Never interpret it as HTML.
The two signals stay in the same tab, separated by 24 px and with clear headings.

Tabs with `tablist`, `tab`, `tabpanel`, `aria-selected`, `aria-controls`, roving tabindex;
left/right arrows and Home/End. Only the active panel is visible/focusable.
Stable and unique IDs. The three controls fit with wrapping at 390 px; no horizontal scroll.
`?seccion=evidencia` opens that section; an unknown value falls back to Resumen. Preserve `tema` and filters when returning to the list. Do not accidentally carry one finding's tab over to another.

Changing state opens an inline form after the tabs and before their content;
it selects Evidencia y corroboración, with no modal or overlay that hides the signals.
Single-column form: select of the five states, conditional field, equivalent command inside details, and buttons "Simular cambio" (Simulate change) and "Cancelar" (Cancel).
Confirmed requires corroboration text; Por validar requires a block. Do not change these existing rules.
Empty: inline alert and focus on the invalid field; do not modify the state.
Success: "Cambio simulado: Confirmado. No se escribió en el ledger" (Simulated change: Confirmed. Nothing was written to the ledger). Update the DOM coherently; do not leave the old notice nor turn all states into confirmed.
Cancel closes without applying and returns focus to "Revisar estado".

### 6. Assistant: minimal state machine

Single source of truth `chatOpen` (boolean). A render function synchronises `hidden`,
layout, button and `aria-expanded`. Do not toggle independent classes that might diverge.
Opening must be idempotent; closing too. Resizing changes presentation, does not erase the conversation nor change `chatOpen`. External button "Abrir asistente" always available when closed; when opened it changes to "Cerrar asistente" (Close assistant).

At ≥1280: 384 px panel on the right side, own header/composer and log scroll.
Below: temporarily replace the detail area with the assistant view,
keeping the shell and a "Volver al hallazgo" (Back to finding) button. Hide and remove the detail from the tab order;
do not make it a floating modal. On closing, restore tab, scroll and trigger focus.
Closing does not delete messages or the draft. Escape closes the most recent panel or popover first, never several at once. Shortcuts do not act while typing nor with Ctrl/Alt/Meta.

Header: "Asistente de F-0002" (Assistant of F-0002), simulated connection state and close. Visible context: "Se enviaría: este hallazgo" (Would send: this finding) and checkbox "Incluir salida de evidencia" (Include evidence output). Tokens, latency and model name inside "Detalles del modelo" (Model details); sanitisation notices visible.
Remove the permanent row of five suggestions: use a "Ayuda con…" (Help with…) select with
Explicación, Evidencia, CVSS, Remediación, Reporte; choosing one prepares a draft, it does not send.
"Preguntar sobre este campo" (Ask about this field) also opens and prepares a draft. Sending requires an explicit action and is labelled "Simular respuesta" (Simulate response). Do not send anything over the network.

During a response: "Respuesta simulada en curso" (Simulated response in progress) and "Detener"; on stopping keep the partial text and show "Respuesta detenida" (Response stopped). Do not start streaming in the background with the panel closed. Provider down: question kept, textual state, "Simular reintento" (Simulate retry).
Proposal: target field, current text if any, proposal, "Aplicar en maqueta" (Apply in mockup) and "Copiar" (Copy). Applying reveals Resumen and the affected field; feedback "Aplicado en esta maqueta" (Applied in this mockup) and Deshacer (Undo). Undo restores the exact text and empty state; it does not duplicate markers.
Do not apply to evidence/corroboration/state. Keep the prototype's existing allowlist for other fields, without expanding the product's capabilities.

### 7. Report and sample export

Header: "Reporte", "4 incluidos de 12" (4 included of 12) and "Exportar…" (Export…). Below, visible warnings:
"1 confirmado excluido: falta corroboración" (1 confirmed excluded: corroboration missing) with a link to the corresponding fixture and
"1 incluido sin remediación" (1 included without remediation). A drop-down "Ver exclusiones" (View exclusions) lists the remaining
7 unconfirmed; do not label the 8 excluded as unconfirmed.

Document/Markdown view in 40 px controls above the paper. Paper of maximum 880 px, padding 48 px at ≥960, 24 px between 640–959 and 16 px on mobile. No permanent sidebar.
The Markdown view keeps literal text and wrapping, without a new syntax highlighter.
Provenance and hashes in details below the paper; warnings that block remain visible.

Export opens a panel in flow, between warnings and the view, with maximum width 880 px centred.
Order: "Exportación de muestra" (Sample export), effective counts, options, format, action, cancel.
Reuse the existing sample Markdown. Offer only Markdown as downloadable; HTML/PDF appear disabled and labelled "NOT BUILT". Options not connected to the sample (annex and include output) are shown disabled with "No disponible en esta maqueta" (Not available in this mockup). Do not simulate that they change the file. Do not generate new exporters.
Fixed text: "Descarga una muestra sintética; no es un reporte completo" (Downloads a synthetic sample; it is not a complete report).
Button "Descargar muestra .md" (Download sample .md), file name `muestra-hallazgos.md`; revoke the Object URL after starting the download. Cancel closes and returns focus to Exportar.

Broken ledger: do not show an enabled download; explain the block next to the action.
Stale view: keep the document, show "Vista desactualizada" (Stale view) and block the download until "Simular actualización" (Simulate update); do not show live nor real success.
Copy Markdown uses the same sample text that is downloaded. Resolve the promise
before announcing "Copiado" (Copied); on rejection or absent API show "No se pudo copiar. Selecciona el texto y cópialo manualmente" (Could not copy. Select the text and copy it manually). Message in `role=status`, no green success.

### 8. Coverage of the twelve pages

| File | Initial state and required difference |
| --- | --- |
| `01-workspaces.html` | Existing cards simplified: name/mode, total, por validar, alerts. Remove severity distribution. Grid of 3 columns ≥1280, 2 ≥640, 1 below; gap 24. No titles nor finding targets |
| `02-hallazgos.html` | List of 12, without filters, notices 2 por validar and 1 sin corroboración; new table |
| `03-hallazgo-chat.html` | Summary and closed assistant. `?chat=abierto` opens the response-in-progress scenario; starts only on opening |
| `03b-chat-aplicar.html` | Summary and open assistant with proposal and comparison against current text; test apply/undo |
| `03c-chat-sin-provider.html` | Open assistant, provider unavailable, draft kept and simulated retry |
| `04a-estado-confirmar.html` | Evidence selected, form open and fixture's corroboration preloaded; assistant closed |
| `04b-estado-rechazo.html` | Same layout; empty field, visible error and state unmodified |
| `05-reporte.html` | Document, export panel closed, 4 included, warnings visible |
| `06-ajustes.html` | List with settings open and simulated new-code notice. Theme functional; density/dates not implemented are disabled and marked NOT BUILT |
| `07a-estados-lista.html` | Keep the defective fixture and the broken JSON row; the alert does not hide it; do not reinterpret invalid lines as valid findings |
| `07b-estados-hallazgo.html` | Evidence selected, confirmed without corroboration, explicitly excluded; assistant closed; sanitisation warning visible when opened |
| `08-workspace-vacio.html` | No metrics nor empty table; title "Sin hallazgos todavía" (No findings yet), explanation and synthetic path in details; "Espera de datos simulada" (Simulated data wait), never claim real listening |

Add states via query on existing pages, not new navigation screens:
`02?...&escenario=sin-resultados`, `05?...&escenario=ledger-roto` and
`05?...&escenario=desactualizado`. Validate values against an allowlist; never insert the query as HTML. Preserve `tema=claro|oscuro`, `vista=md`, `chat=abierto` and the scenarios
`demo=aplicar|guardar|porvalidar`; update their selectors if the DOM changes.

### 9. Accessibility, emptiness and honesty

- Every control has an accessible name; do not depend on `title`, colour or icon alone.
- Visible focus in both themes; reading order equal to the visual one; nothing hidden receives focus.
- Empty field state: "Sin registrar" (Not recorded), never invented text. Load error different from zero results. Notices keep their content when tabs change or a panel opens.
- Long technical text wraps; copying keeps the original fixture text, not labels.
- Respect reduced motion also in `scrollIntoView`: instantaneous behaviour.
- Chat log does not announce each character; announce the start and end of the response.
- Simulated functions always carry a local label in addition to the global band when the message could be mistaken for a real write, connection or export.
- Without JS: reading content accessible; show the detail sections in flow and hide the exclusively simulated actions. Do not leave the page empty because it depends on the script.

### 10. Execution order and mandatory tests

1. Record `git status --short` and read the sources. Preserve previous screenshots.
2. Implement shell/typographic tokens and the list. Review the 1500 and 390 screenshots before continuing; fix overlaps and clipping before the detail.
3. Implement the detail, tabs, assistant and form with their states. Test closing, reopening and resizing before moving on to the report.
4. Implement the report, workspace selector and settings; go through the twelve pages.
5. Regenerate HTML, run checks and screenshots, update documentation and evidence.

Existing commands, from the repo root:

```bash
python3 specs/015-reportes-rediseno/mockups/_src/build.py
python3 specs/015-reportes-rediseno/mockups/_src/build.py --tokens
node --check specs/015-reportes-rediseno/mockups/_src/app.js
bash specs/015-reportes-rediseno/mockups/_src/shots.sh
```

Adapt `shots.sh` for 1500×950, 1024×950, 760×950 and 390×844, light and dark,
across the twelve pages. Also capture the table states below. Names: `<pagina>-<tema>-<ancho>[-<estado>].png`. Do not confuse a headless screenshot with an interaction test: use available browser automation for the transitions.
If there is no interactive runner, do a manual review and declare what was not run;
do not approve checks just because code exists that seems to implement them.

| ID | Action / preparation | Verifiable result |
| --- | --- | --- |
| AC-01 | Open the twelve pages in both themes | NOT BUILT band visible, local fonts, no external calls |
| AC-02 | Measure at 390, 760, 1024 and 1500 | No horizontal overflow of the document; no overlap nor clipped controls |
| AC-03 | Initial list | No metrics strip, no 12 chips; target/CWE/CVSS do not compete with the title |
| AC-04 | Filter State + Severity + search | Correct intersection; visible counter matches rows; Clear restores the set |
| AC-05 | Search a CWE/CVE that exists in the fixture | Matches even though classification is not a visible column |
| AC-06 | Zero matches and empty workspace | Different messages; only the first offers clearing filters |
| AC-07 | Switch tabs with the keyboard | Arrows/Home/End work; hidden content does not receive focus; notice persists |
| AC-08 | Open/close/reopen assistant 3 times | Always works; draft and conversation kept |
| AC-09 | Assistant open, resize 1500→760→1500 | Panel/view changes without duplicates, loss of text or incoherent state |
| AC-10 | Proposal: apply and undo twice | Original and empty text restored; no duplicate markers nor real write |
| AC-11 | Confirm without corroboration | Error and focus on field; previous state intact |
| AC-12 | Confirm with valid fixture / cancel | Success explicitly simulated and signals coherent / cancel changes nothing |
| AC-13 | Successful copy, rejected API and absent API | Success only after resolving; readable error in the other two cases |
| AC-14 | Initial report | 4 included, 1 confirmed excluded and 7 unconfirmed; never "5 entran" (5 enter) |
| AC-15 | Export sample | `.md` matches the visible sample; HTML/PDF and unsupported options disabled |
| AC-16 | Broken ledger or stale view | Visible notice and download blocked; existing document not deleted due to staleness |
| AC-17 | Provider down and stop response | Draft or partial response kept; correct textual feedback |
| AC-18 | Change theme / reduced motion | Theme without global transition; no smooth scroll nor scaling with reduced motion |
| AC-19 | Disable JS | Reading data available, no misleading simulated buttons |
| AC-20 | Tab through the whole screen at 390 px | Focus always visible and recoverable, including closing the panel and cancelling export |

The small test must automate at least filters (AC-04/05), the assistant cycle (AC-08/09), rejected copy (AC-13) and counts/export (AC-14/15) if a browser is available. Do not replace those tests with searching strings in the code. Keep the existing contrast checks and extend them if colour combinations are added.

### 11. Expected delivery and closing condition

Deliver local links to the twelve pages, representative screenshots of list/detail/
report on desktop and mobile, commands executed with results and an AC matrix with
Pass/Fail/Not verified. Attach a review against the UI gate: preview only, synthetic data,
no false real operations nor functionality announced as built.
Do not declare "listo para producción" (ready for production): this delivery can only approve the mockup.
If a HIGH remains, close with **Block** and its reproduction. If they were resolved and verified,
**Approve — sólo maqueta** (Approve — mockup only), listing separately any unverified coverage.

Handover prompt to copy to the agent:

> Recreate the twelve mockups of `specs/015-reportes-rediseno/mockups/` following the
> section "Recreation contract for the coding agent" of `revision-diseno.md`. Read it in full
> before editing. Its visual decisions prevail over `design.md`; the repository's
> security rules prevail over both. Implement only the local prototype: fonts in `_src`,
> regenerated HTML and screenshots. Use the existing fixtures, without opening
> engagements or modifying the product. Run the acceptance matrix, record evidence and
> report honestly what was not verified. Do not replace the measures, states or
> interactions specified with your own decisions.

## Final evidence of this recreation

### Legibility redesign requested with better-ui

The detail was reorganised into Resumen / Evidencia y corroboración / Registro (Summary / Evidence and corroboration / Record), with keyboard navigation,
fallback to Resumen and readable sections without JavaScript. The block remains visible and its full explanation is consulted via details. The literal output also unfolds on demand.
The technical classification was removed from the header and the distributions from the workspace cards;
provenance and shortcuts move into an in-flow drop-down. The document uses page scroll and
16/26 px reading; the assistant takes 384 px on desktop and a dedicated view at smaller widths.

Build, the built-in contrast check, node --check and check-ui.js were run. The latter includes a test of
selection, visibility, focus and tab fallback in a minimal DOM; it is not equivalent to a browser.
Firefox outside the sandbox does work: the screenshots of the twelve pages were generated at four widths and both themes. The detail at 1500 and 390 px and the list at 390 px were visually inspected; the inspection detected and corrected narrowing of titles and an overlapping search icon.
Not verified: complete interactive walk, real clipboard, all state variants and reproduction of the transitions at 10 %. The previous matrix does not constitute approval of these cases.

Execution date: 2026-11-15. `python3 mockups/_src/build.py`,
`python3 mockups/_src/build.py --tokens`, `node --check mockups/_src/app.js`,
`node mockups/_src/check-ui.js` and `bash -n mockups/_src/shots.sh` were run. The generator produced the
12 pages; the token check found no pairs under its thresholds, and the local check verified
the `NOT BUILT` band, the filter/report routes and the absence of external hosts other than
the synthetic fixtures and the SVG namespace.

Summary matrix: AC-01 static Pass (12 HTML, embedded fonts and visible band); AC-03 Pass by HTML/CSS inspection (no strip nor chips, native filters); AC-14/15 static Pass (4 included,
1 confirmed excluded, 7 unconfirmed, Markdown-only download on demand); AC-16 static Pass
for the broken/stale ledger notices; AC-18 Pass by CSS/JS (`prefers-reduced-motion` and theme);
AC-02, AC-04/05, AC-06/07, AC-08/09, AC-10/11/12/13, AC-17, AC-19 and AC-20 **Not verified** in an
interactive browser.

`shots.sh` was updated to the four contractual widths and the reference in
`mockups/shots/antes/` was preserved. Firefox 152.0 headless ended with `Segmentation fault` (rc 139) even
in a single screenshot, so it is not claimed that the new screenshots were generated, nor is visual approval declared. `engagements/` was not opened and the product was not modified.
