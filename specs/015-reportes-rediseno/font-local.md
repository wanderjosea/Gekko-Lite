# Correction V02 — Space Grotesk, local

Status: AUTHORIZED for implementation by the operator: "hazlo tu" ("do it yourself"), in response
to the proposal to incorporate Space Grotesk locally with the minimal CSP change and
its tests. This document specifies the requirement, plan and tasks of that change.
Execution: IMPLEMENTED and verified; `shots/font-local/verificacion.md` contains
the red/green result, gates, real glyph loading and 24 browser screenshots.

Requirement: the product MUST load the Space Grotesk WOFF2 of the local prototype from its CSS authorised by hash, without additional HTTP requests. Its font source MUST be limited to `data:`; scripts, external connections, routes and writes keep their prohibitions. WHEN the browser opens the pages with CSP active, THEN Space Grotesk actually loads at 400/600, without CSP violations and without remote traffic.

Plan: embed a base64 copy of the trusted WOFF2 in `findings_web.py`, with `@font-face`, range 300–700 and font-display swap. Keep the CSS_HASH computation over the complete CSS. Package the OFL notice next to the module. Do not read fonts from a workspace or depend on the mockups folder at run time. Change only `font-src data:` in CSP; do not allow 'self', https: or remote origins. Ledger data does not take part in CSS, base64 or CSP. JetBrains Mono keeps the existing local fallback; this correction authorizes only Space Grotesk.

Tasks: regression test on font/CSP → incorporation → selftest/gates → real browser (font loaded, weights, CSP, network, four widths/both themes) → V02, T07/T09 and AC10 evidence. Do not approve AC10 without reviewing the final comparison.

Risk/limit: `font-src data:` authorises the scheme, not a single binary; the hashed CSS fixes the module's only @font-face. It does not add permission for arbitrary styles. The HTML grows because of the embedded font; there is no separate font cache.
