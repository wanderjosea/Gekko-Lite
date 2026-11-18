# Visual pass 2026-11-16 — redesign according to the operator's prototype

The operator discarded the Atlas aesthetic and asked for the one from the operator's own prototype
(`gekko-reportes-prototipo.html`, outside the repo). Only the presentation of `findings_web.py` changes: routes, ledger reading, escaping, CSP and headers stay the same.

- Frame: sidebar (brand «G», current workspace, navigation) + top bar with route and gear icon.
- List: header with a lime label, 4 metric cards over the entire ledger (REQ-RPT-015 updated), "Inventario de hallazgos" panel with GET filters and table, rail with review progress (`<progress>`), "Requiere seguimiento" ("Requires follow-up") notice and count by severity.
- Detail: ID + badges, title, objective/update/workspace line, warnings and tabs Summary/Evidence/Record inside a panel; Impact and Remediation in cards.
- Presentation hooks: `list_actions` (list header) and `detail_actions` (detail header).
- Deliberate differences from the prototype: no chat and no fake export, no SVG icons (CSP and the selftest only admit the gear icon), Space Grotesk embedded instead of Inter, status/severity values as they are in the ledger.
- Selftest: the REQ-RPT-015 assertion that required omitting the metrics strip now requires the metrics to count the entire ledger with an active filter.

## Integration with 016 and 017 (report-module merge)

- `list_actions` → lime "Reporte" ("Report") button to `/w/<ws>/reporte`; the sidebar adds "Reporte".
- `detail_actions` → secondary "Reporte" button; the 016 status form (`state_form`, with no changes to fields, hidden inputs, labels or texts) goes in a side panel "Estado del hallazgo" ("Finding status") to the right of the tabs (below them at widths < 1280 px). `saved_notice` still follows the warnings.
- The 017 report page is wrapped in `.report` and styled only by CSS; its markup does not change.
