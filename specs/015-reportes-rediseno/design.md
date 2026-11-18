# 015 — Redesign of the reports console

> **What this is:** a design proposal with mockups, not a spec with criteria. It is the input for `/spec-new`.
> Nothing is implemented and no product file changed. All mockup data is synthetic.
> Mockups: `mockups/*.html` (open with a double click, no network). Screenshots: `mockups/shots/`.

## 1. Critique of the current console

In order of impact. What makes it look poor is not a colour: it is that it does not establish hierarchy.

1. **Everything weighs the same.** Eight columns with the same size and colour; the title — the only thing the operator reads — is an underlined lime link, split across three lines, while `2026-11-15T23:42:33Z` takes 160 px per row.
2. **What decides is not visible.** `needs_validation` is one more pill, but it is the operator's work queue; its block only appears in the detail. "No corroboration" is a second loose pill. There is no state filter.
3. **Wasted space, low density.** Four large boxes for four figures; a 1200 px column centred with air on both sides; in a half-screen window the table overflows horizontally.
4. **The detail is a stack of identical cards**, including the empty ones ("Block —"). Evidence and corroboration — the reason the ledger exists — have the same weight as "Dates".
5. **Borrowed colour.** It is the GitHub palette with lime on top. Lime acts as brand, link and button, so it signals nothing. The severity pills, saturated and round, compete with everything else.
6. **Typography without a system.** System font, almost a single size, labels in capitals everywhere; the target's monospace is cut mid-token.
7. **Form interaction.** "Filtrar" (Filter) button, full reload, only the title is clickable, no keyboard, no previous/next in the detail.
8. **No brand.** "GEKKO · reportes" as text. It does not look like part of the same product as the terminal panel.

## 2. Direction

**A evidence instrument, a neighbour of the terminal.** Black-green surfaces from the brand kit, thin lines instead of shadows, Space Grotesk for reading and JetBrains Mono for everything that is data. Square geometry: the pixel of the logo becomes the language of the interface (severity square, signal meter, distribution bar).

Principles:

1. **Two signals.** A finding is read as *evidence* + *corroboration*. The meter `■■ / ■□ / □□` accompanies the state in the list, in the header and in the detail. "Confirmed" with `■□` cannot pass as healthy.
2. **Lime is action.** Only the button that commits something (save, ask, download, update), focus and selection. Never a state: confirmed is mint, attention is amber, rejection is red.
3. **Honest before pretty.** The unknown is shown literally and it is said to be unknown; the broken line has its own row; what is missing is named ("Sin registrar: CVE" — "Not recorded: CVE") instead of painting an empty card.
4. **Captured text is text.** Nothing from the ledger or the model is interpreted. No ligatures, controls and bidi shown as `�`, `overflow-wrap:anywhere` in every data container, long blocks capped with scrolling.
5. **Dense with hierarchy.** One row = two lines (title + summary). 12 findings fit in 950 px of height.
6. **Keyboard first.** `j`/`k`, `⏎`, `/`, `e` (state), `c` (chat), `?`. The bottom bar recalls the shortcuts and says which file was read and when.
7. **What crosses workspaces shows no content.** The index only has figures (it is already REQ-RPT-001): the screen can be shared without showing titles from another client.
8. **The model drafts; it does not attest.** The chat proposes text for drafting fields. Evidence, corroboration and state are set by the operator.

## 3. Information architecture

```
/                      Workspaces        cards with figures; never titles or targets
/w/<ws>/               Findings          figure strip · search and filters · table
/w/<ws>/f/<n>          Finding           document (left) + chat (right); state change inline
/w/<ws>/reporte        Report            checks and options (left) + preview (right)
Settings               gear popover, on all pages
```

- **Top bar (48 px):** logo · "Reportes" / workspace selector with its mode (`OS` | `toolbox`) · tabs *Hallazgos N* and *Reporte* · on the right: "Código nuevo · Actualizar" (only if applicable), "en vivo" (live), gear.
- **Bottom bar (28 px):** ledger path · lines · reading time · screen shortcuts.
- **Between findings:** `‹ 2 / 12 ›` in the detail header respects the order and the filter of the list.
- **Widths:** ≥1180 px document + fixed 440 px chat. Below that the chat is a drawer opened with "Chat" or `c`. Below 900 px the table moves the target under the title and drops CVSS, CWE and date; the report stacks.

## 4. Screens

| Screen | Mockup | Screenshot that best represents it |
|---|---|---|
| Workspaces | `01-workspaces.html` | `01-workspaces-oscuro.png` |
| Findings | `02-hallazgos.html` | `02-hallazgos-oscuro.png` · filter: `02-hallazgos-oscuro-filtro.png` · half window: `02-hallazgos-claro-760.png` |
| Finding + chat (response in flow) | `03-hallazgo-chat.html` | `03-hallazgo-chat-oscuro.png` · whole document: `03-hallazgo-chat-claro-alto.png` |
| Apply a proposal to a field | `03b-chat-aplicar.html` | `03b-chat-aplicar-oscuro.png` → `03b-chat-aplicar-claro-aplicado.png` |
| Chat without Provider | `03c-chat-sin-provider.html` | `03c-chat-sin-provider-claro.png` |
| State change: confirm | `04a-estado-confirmar.html` | `04a-estado-confirmar-claro.png` → `04a-estado-confirmar-oscuro-guardado.png` |
| State change: rejection | `04b-estado-rechazo.html` | `04b-estado-rechazo-oscuro.png` |
| Report | `05-reporte.html` | `05-reporte-oscuro.png` · `05-reporte-oscuro-markdown.png` |
| Settings and "código nuevo" (new code) | `06-ajustes.html` | `06-ajustes-oscuro.png` |
| Honest states, list | `07a-estados-lista.html` | `07a-estados-lista-oscuro.png` |
| Honest states, finding | `07b-estados-hallazgo.html` | `07b-estados-hallazgo-oscuro-alto.png` |
| Empty workspace | `08-workspace-vacio.html` | `08-workspace-vacio-oscuro.png` |

Each mockup has a screenshot in dark and light at 1500 px and at 760 px (`-760`). `?tema=claro|oscuro` fixes the theme; the gear also changes it.

**Workspaces.** One card per workspace: name, mode, activity ("activo · hace 20 s"), severity distribution bar with five fixed columns (compared at a glance), findings, confirmed/total, *por validar* (what awaits the operator) and warnings: confirmed without corroboration, ledger with broken line, unreadable ledger.

**Findings.** The top strip replaces the four boxes: total, distribution, confirmed, por validar, without corroboration; the last three are one-click filters. Below, search (`/`) and two groups of chips with counts: severity and state. The whole row opens the finding. Relative date; the absolute one goes in the `title`.

**Finding.** Fixed header: severity, id, title, copyable target, state button, CVSS/CWE/CVE. Body, in the order it is needed:
1. *Action notice* if there is one: the block of "por validar", or "confirmed without corroboration", with its two exits.
2. *Summary.*
3. *Signals*: ① Evidence (command, artifact with sha256, literal output with cap, line wrap and copy) and ② Corroboration (the text, or "falta" — missing — and why it matters).
4. *Steps to reproduce*, *Impact* | *Remediation*, *References* (CWE, KB), *Record* (created, updated, ledger line) and the line "Sin registrar: …" (Not recorded).

**Finding chat.** Header with the model and its state; context line (what is sent, approximate tokens, switch to include the evidence output, and how many embedded instructions were neutralised). Question shortcuts: explain, evidence, CVSS, remediation, report; each section of the document also has "Preguntar" (Ask). The response arrives in flow with a cursor and "Detener" (Stop). When it proposes text for a field, a **Propuesta para ‹campo›** (Proposal for ‹field›) block appears: if the field has text, it shows "Ahora en el ledger" (Now in the ledger) above the proposal; "Aplicar/Sustituir" (Apply/Replace) writes, marks the section "vía chat · hora" (via chat · time) and leaves "Deshacer" (Undo). History per finding; "vaciar" (empty) clears it.
*Applicable only to:* summary, impact, remediation, steps, CVSS, CWE. *Never to:* evidence, corroboration, state.

**State change.** The state button (or `e`) opens an *inline* panel below the header, not a modal: while the corroboration is being written, the evidence must remain visible and the chat must be askable. Five options with their name, their ledger token and what they mean; "Confirmado" requires corroboration and "Por validar" the block. Below, the equivalent command (`findings.py set F-0002 --status confirmed --corroboration "…"`): what the web does is auditable. **"Guardar" (Save) is never disabled**: if something is missing, the ledger rejects it and the rejection is explained — what happened, that nothing was written, what to do, and the literal message. On save: a notice with the time, state and signal ② updated.

**Report.** On the left: how many enter and how many stay out; *checks* before delivering (legible ledger, confirmed without corroboration, empty fields in what enters, what stays out); options (annex "por validar", include output, format); download and copy; *provenance* (sha256 of the ledger and of the generated report). On the right, preview in two modes: Document and raw Markdown. It is read-only: the finding is corrected.

**Settings.** Still the gear. Appearance (theme, density, dates), chat (Provider and model, informational only), module (hash loaded, hash on disk, update), shortcuts.

## 5. Components

| Component | Use | Note |
|---|---|---|
| Top / bottom bar | all | the bottom one says which file was read and when |
| Workspace selector + mode label | top bar, cards | `OS` terminal, `toolbox` hexagon |
| Severity label | list, header, report | square + name in mono; never a filled pill |
| State + signal meter | list, header, state panel | refuted uses ✕; out of schema, dotted `?` |
| Integrity notice (`flag`) | list, cards, chat | "sin corroboración", "línea ilegible" (unreadable line) |
| Distribution bar + legend | cards, strip | proportional to the count; dotted gap if there is nothing |
| Figure strip | list | three of its cells filter |
| Filter chips, search | list, index | `aria-pressed`; without JS they are GET links |
| Findings table | list | sticky header, clickable row, broken-line row |
| Notice (`notice`) and callout (`callout`) | broken ledger; pending action in the finding | amber = your turn, red = blocks |
| Signals panel | finding | the central block of the design |
| Literal output block | evidence, report | height cap, wrap, copy |
| State change panel + rejection | finding | inline; also valid for "bajar a triado" (downgrade to triaged) |
| Chat: message, proposal, error, context, composer | finding | the proposal is the only point that writes |
| Checklist | report | ✓ / ⚠ / ✕ / ⓘ |
| Settings popover, segmented control, `kbd` | all | `<details>`, works without JS |
| Empty state | workspace without findings | says the path and that it is listening |

## 6. States

| State | Where it is seen | How |
|---|---|---|
| Confirmed without corroboration | card, strip, row, header, finding, report | meter `■□` in amber + "sin corroboración"; callout with "Escribir la corroboración…" (Write the corroboration…) / "Bajar a triado" (Downgrade to triaged); excluded from the report |
| Por validar (to validate) | strip, row, finding | amber; the block is the first thing in the document, with "Ya lo comprobé: confirmar…" (I already checked it: confirm…) |
| State or severity out of schema | row, header, chips, bar | literal value between «», dotted frame, "desconocida" (unknown); goes last; chip "Fuera de esquema" (Out of schema) |
| No state / no severity | row | "sin estado", "sin severidad", same dotted frame |
| Broken ledger line | card, strip, notice, own row, bottom bar | line number, raw text trimmed, and what it blocks (adds, changes, report); the rest is listed |
| Unreadable ledger | card | "No se pudo leer el ledger" (The ledger could not be read); nothing from it is shown |
| Empty workspace | card, list | dotted gap; expected path; "escuchando el ledger" (listening to the ledger) |
| New code on disk | top bar and settings | amber button "Código nuevo · Actualizar" always visible; in settings, the two hashes |
| New finding live | strip and row | "1 nuevo hace 20 s" (1 new, 20 s ago), label `nuevo` (new); never moves focus nor scroll |
| Change rejected | state panel | red block + marked field + literal message; nothing written |
| Chat: typing / stopped / without Provider | chat | cursor and "Detener"; "detenido" in the signature; error with "Reintentar" (Retry), the question is not lost |
| Hostile text | all | literal, escaped, `�` for controls; one-line title with ellipsis in the list, complete in the detail |

Designed but **not mocked up** (they reuse a component that is mocked): report blocked by a broken line (✕ in checks, the download is replaced by the reason); model loading on the first question ("cargando el modelo… 14 s" in the signature); finding changed on disk while being edited (rejection: "cambió a las 14:05:40Z; recarga y revisa" — changed at 14:05:40Z; reload and review); no connection to the module ("sin conexión" with a hollow dot where "en vivo" goes; the bottom bar keeps the time of the last read).

## 7. Tokens

Single source: `TOKENS` in `mockups/_src/build.py`. The build fails if a text pair drops below 4.5:1.

### Colour

| Token | Dark | Light | Role |
|---|---|---|---|
| `bg` | `#090D0C` | `#F2F5F0` | canvas |
| `surface` | `#121816` | `#FFFFFF` | panels, table, chat, bars |
| `raised` | `#1A221F` | `#E9EEE7` | hover, row with cursor, active control |
| `sunken` | `#050807` | `#EDF1EA` | literal output blocks |
| `overlay` | `#161D1A` | `#FFFFFF` | popover |
| `field` | `#050807` | `#FFFFFF` | text fields |
| `line` / `line-strong` | `#222D28` / `#2E3D36` | `#DDE3DB` / `#C2CBC2` | dividers / control borders |
| `text` / `text-2` / `text-3` | `#F2F6F3` / `#A5B1A9` / `#84928A` | `#0B110F` / `#45524B` / `#5E6B64` | primary / secondary / labels |
| `accent` + `on-accent` | `#C0F425` + `#090D0C` | same | fill of the button that commits |
| `accent-text` / `focus` | `#C0F425` | `#3B6600` | lime as text, border and focus |
| `accent-soft` | `#202A17` | `#EEF8D0` | selected, just changed |
| `ok` / `ok-bg` / `ok-line` | `#6AE28B` / `#12241A` / `#245538` | `#14724A` / `#E6F4EA` / `#A9D5B9` | confirmed with two signals |
| `attn` / `attn-bg` / `attn-line` | `#F5B74A` / `#2A2110` / `#6B5220` | `#8A5300` / `#FFF4D6` / `#E3C275` | your turn; integrity |
| `danger` / `danger-bg` / `danger-line` | `#FF7B72` / `#2D1715` / `#7A3632` | `#C4252B` / `#FDECEA` / `#EDB4AF` | rejection, broken ledger |
| `sev-critical` … `sev-info` (text) | `#FF6E6E` `#FF9D52` `#F2C744` `#62C0FF` `#A5B1A9` | `#C4252B` `#B24A06` `#7F5B00` `#0A5FB4` `#45524B` | severity name |
| `fill-critical` … `fill-info` (non-text) | same as `sev-*`; info `#7C8982` | `#D93036` `#EE7A1A` `#E3AC00` `#2B86E3` `#8A968F` | squares and bars |

Blacks, surface, line, graphite, white, lime and mint come from the brand kit. Lime does not change between themes; on light it is never text (1.3:1): there `accent-text` replaces it.

### Contrast of the text pairs (minimum per group, dark / light)

| Text | On | Dark | Light |
|---|---|---|---|
| `text` | all surfaces | ≥ 14.9 | ≥ 16.2 |
| `text-2` | all surfaces and `accent-soft` | ≥ 6.7 | ≥ 7.0 |
| `text-3` | all surfaces and `accent-soft` | ≥ 4.6 | ≥ 4.7 |
| `accent-text` | `bg`, `surface`, `raised`, `overlay`, `accent-soft` | ≥ 11.5 | ≥ 5.8 |
| `on-accent` | `accent` | 15.1 | 15.1 |
| `sev-*` | `bg`, `surface`, `raised`, `accent-soft` | ≥ 5.5 | ≥ 4.6 |
| `ok` / `attn` / `danger` | `bg`, `surface`, `raised`, `overlay`, their `-bg` | ≥ 9.9 / 8.9 / 6.4 | ≥ 5.0 / 5.4 / 4.9 |
| `text`, `text-2` | `ok-bg`, `attn-bg`, `danger-bg` | ≥ 7.1 | ≥ 7.2 |
| `surface` (meter number) | `text-2`, `ok` | ≥ 8.1 | ≥ 5.9 |
| `focus` (non-text, 3:1) | `bg`, `surface`, `raised` | ≥ 12.5 | ≥ 5.8 |

Full pair-by-pair table: `python3 mockups/_src/build.py --tokens`. The `fill-*` tokens are not text: they always go with their name.

### Typography

Space Grotesk (text and titles) and JetBrains Mono (data, labels, code): both from the brand kit, OFL, packaged locally (Latin subset, 25 + 19 KB in woff2). No ligatures anywhere.

| Role | Font · size/line-height · weight |
|---|---|
| Label | Mono · 11/1.3 · 500 · capitals · +0.07 em |
| Data (id, target, CVSS, hash) | Mono · 12–13/1.55 · 400–500 |
| Secondary | Grotesk · 12/1.45 · 400 |
| Interface | Grotesk · 13–14/1.45 · 400–500 |
| Finding prose · lead paragraph | Grotesk · 15/1.6 · 16/1.55 |
| Block title | Grotesk · 14/1.3 · 600 |
| Finding title | Grotesk · 22/1.25 · 600 · −0.012 em |
| Page title · figure | Grotesk · 20–24/1.2 · 600 · 30/1 for the report figure |

### Spacing, radii, elevation, measures

- **Spacing:** 4 · 8 · 12 · 16 · 20 · 24 · 32 · 40 px.
- **Radii:** 2 (labels, meter) · 4 (controls) · 6 (panels) · 10 (popover). Nothing is a pill.
- **Elevation:** level 0 = 1 px line (everything). Level 1 = popover and chat drawer: `0 12px 32px` black 55 % / 16 % in light. There are no other shadows.
- **Measures:** top bar 48 · bottom bar 28 · chat 440 · document ≤ 960 · page ≤ 1560 · row ≈ 55 px.
- **Breakpoints:** 1180 (chat becomes a drawer, no CWE) · 900 (target under the title, strip 4+1, report stacked) · 620.
- **Motion:** only the flow cursor and the "just changed" flash; both are cancelled with `prefers-reduced-motion`.

## 8. For the architect

### 8.1 What truly needs JavaScript

| Interaction | Without JavaScript |
|---|---|
| **Chat response in flow** and "Detener" | Possible without JS with the chat in its own `<iframe>` reloaded every 1–2 s while it generates; it loses scroll on each reload and there is no fine "Detener". It is what I would not cut |
| **Live arrival** of findings | `meta refresh` as today, only on index and list; never on the finding (it would erase a corroboration being typed) |
| **Keyboard** (`j k ⏎ / e c ?`) | Tab and links; speed is lost |
| **Copy** to clipboard | Select by hand |
| Apply/undo a proposal without losing the thread | POST form and reload; "deshacer" becomes another form |
| Instant filter and search | GET links and form (as today): works entirely |
| State panel, settings, chat drawer, line wrap | `<details>`, `:target` and CSS checkbox: work entirely |
| State change and its rejection | POST form; the rejection comes back painted on the same page with the panel open |
| Theme | Cookie + POST as today |

**Recommendation:** server-rendered pages as today and **one** own script, without framework or build step (the whole mockup is 210 lines), as progressive enhancement. Hard rule for the script: ledger or model text only through `textContent`/text nodes, never `innerHTML` (the mockup already complies).

**If it had to be done without JS, I would cut:** the character-by-character flow (reload every 2 s), the shortcuts, the copy buttons, live arrival in the finding and the immediate "deshacer". The rest of the design holds up.

### 8.2 Living requirements this design touches (everything is a boundary: spec-first)

- **REQ-RPT-008 (read-only, three pages and two actions):** deliberately broken. New routes: report, state change, chat, apply field. The module starts writing the ledger and saving the chat history. **It loosens** the boundary → operator approval. Every write should go through the same rules as `findings.py set`.
- **REQ-RPT-007 (no scripts, only `<svg>` the gear, no `style` attributes):** CSP needs `script-src` (hash or `'self'`) and `connect-src 'self'`; there are own SVG icons; the mockup uses `style="flex:N"` in the bars — in the product, fixed classes `.fx-1…100` or `<rect>` so as not to reopen `style`. Fonts: `font-src data:` inside the hashed CSS (it does not serve files) or a static path.
- **REQ-RPT-014 (settings without JavaScript):** kept as is (`<details>`, gear, theme cookie).
- **REQ-RPT-006 ("—" for what is absent):** changes to a line "Sin registrar: …" and to "—" only in CVSS/CWE/CVE.
- **REQ-RPT-001 / 003:** compatible; they add mode, *por validar*, *sin corroboración* and distribution. The order is the same.
- The limit of REQ-RPT-014 "below ~700 px the table overflows" disappears.

### 8.3 Data per screen

| Screen | Needs |
|---|---|
| Workspaces | name, **mode** (spec 013), ledger mtime, count by severity and "sin clasificar" (unclassified), total, confirmed, **por validar**, **confirmed without corroboration**, broken lines with their number, read error |
| Findings | per row: everything today + line number, is there evidence?, is there corroboration?; broken lines (number, text ≤ 300); path, lines and read time; what is "new" |
| Finding | the full row; position and neighbours according to order and filter; **sha256 and time of the artifact** (today they are not in the ledger); chat history; Provider and model state; approximate context tokens |
| State change | `POST {id, status, corroboration \| blocker, updated_visto}` → done, or rejection `{code, literal message}` |
| Chat | `POST question` → flow; history per finding; number of patterns neutralised by sanitisation; `POST apply {id, field, value, updated_visto}` |
| Report | the Markdown of `render`, counts, checks, sha256 of the ledger and of the report, options |
| Settings | theme cookie; hash loaded and on disk; Provider host, whether it responds and which model it serves |

### 8.4 Security the design takes for granted

- The finding text travels to the model sanitised (`sanitize_target_content.py`) and delimited as data; the interface shows how many patterns were neutralised. The model's response is also untrusted text.
- The model cannot change state, evidence or corroboration: it only proposes, and the operator presses.
- The Provider key does not reach the browser: the module acts as intermediary.
- The new POSTs need the same origin defence as `/tema` (`Sec-Fetch-Site`) or more: they now write evidence.

### 8.5 Open questions

**For the operator**
1. Names in Spanish ("Por validar", "Triado") with the token visible when changing state, or raw tokens as today?
2. A confirmed finding without corroboration: does it stay out of the report (proposed), block the download, or enter marked?
3. `render` today writes the labels in English; the mockup shows them in Spanish. Language of the deliverable?
4. Can the chat propose the **block**? Proposed: yes as a draft; corroboration and evidence, never.
5. Formats besides Markdown (self-contained HTML, PDF by printing)? The mockup has them as an option.
6. Packaged brand fonts (proposed) or system font?
7. What is "new": since your last visit, or the last N minutes?
8. Where does the chat history live and for how long? It is engagement data: the retention policy applies to it.

**For the architect**
1. Live channel: SSE or polling? The current server is synchronous.
2. Two writers on the ledger (agent and web): file locking and rejection by a stale `updated`.
3. sha256 of the artifact: is it added to the ledger or computed by reading the file (today the module does not open artifacts)?
4. Script and fonts: inline with hash (no file served) or a static path with `'self'`?
5. Huge evidence output: truncation for the model's context and for the page (the mockup puts a height cap).
6. More than ~200 findings: pagination? The table does not need it before then.
7. Catalogue of ledger rejections → Spanish text: today there are only English messages for the terminal.

## 9. Core and optional

**Core:** the five surfaces of §3; signal meter; strip and filters by severity and state; state panel with an explained rejection; chat with flow, history and apply-to-field; report with checks, preview and Markdown download; all the states of §6; both themes; basic keyboard.

**Optional, with reserved place:** live arrival without reloading (the indicator already exists) · compact density · HTML/PDF formats · "por validar" annex · engagement *Summary* tab (third tab) · artifact viewer (the artifact moves from text to link) · command palette and shortcut sheet (`?`) · drop-down workspace selector.

## Status of the recreated prototype

Legibility redesign: the detail opens on Summary and distributes the information across three tabs
The operator's later adjustment replaces the fixed 384 px panel: with the assistant open on desktop (≥1280 px), the area uses the whole viewport in two equal halves, detail on the left
and the assistant up to the right edge. Closed, it returns to the centred reading width.
(Summary, Evidence and corroboration, Record). Classification and hashes are in Record; literal output and the full block use details. The notices remain visible. The severity distributions in the workspace cards were removed and provenance/shortcuts were grouped in the footer. On mobile, severity and target share the Finding cell to recover reading space.

The recreation of this iteration lives only in `mockups/_src/` and in the regenerated HTML/screenshots. It keeps the local Space Grotesk and JetBrains Mono, the `build.py` tokens, the persistent `NOT BUILT` band, the native list filters, the centred report document and the on-demand sample export. The twelve HTML files remain self-contained synthetic data; they do not represent the product nor connect to a ledger, provider or engagement.

The reproducible capture attempts 1500, 1024, 760 and 390 px in light and dark through `_src/shots.sh`; the previous screenshots are kept in `mockups/shots/antes/`. The acceptance matrix and its limits are recorded in `revision-diseno.md`.

## 10. Mockups

```bash
python3 specs/015-reportes-rediseno/mockups/_src/build.py   # regenerates the .html files (checks the contrast)
bash    specs/015-reportes-rediseno/mockups/_src/shots.sh   # screenshots with Firefox headless; accepts prefixes: 03 07a
```

`_src/` contains the generator, the stylesheet, the script and the resources (fonts in a subset with their OFL, reduced isotype). Each `.html` carries everything inline: zero requests. `?demo=aplicar|guardar|porvalidar` leaves a mockup in the state after the action (this is how the `-aplicado`, `-guardado` and `-filtro` screenshots were taken).
