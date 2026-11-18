# Tasks 021 — Configurable report templates

> Estado: `IMPLEMENTADA` (2026-11-18) · previously `APROBADO` (operator, 2026-11-17: «start 021 with the coding agent»; implemented by a coding agent, the main session runs the socket tests and commits) · Date: 2026-11-17
> Spec: [`spec.md`](spec.md) (`APROBADA`, 2026-11-17, 18 AC; amendments to AC6/AC8/D3 and to the per-template brand —AC5, AC6, AC8, AC13–AC18—, approved by the operator on 2026-11-17) · Plan:
> [`plan.md`](plan.md) (`APROBADO`, 2026-11-17) · Feature branch, base `66a7506`.
> Each task closes ≥1 criterion (or is a falsifier with no AC) and names its test. The checkbox is ticked ONLY with the test green
> and its row in the log.

**Tests:** **L** = `python3 .claude/tools/findings.py selftest` · **WS** = `python3 .claude/tools/findings_web.py selftest` ·
**W** = `bash tools/report-test.sh` (runs L and WS + real HTTP over a temporary root) ·
**G** = `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` (gate and `REQ ↔ case` trace) ·
**K** = `bash .githooks/test.sh`

**Who:** the code, its tests, the living spec and the docs are written by an agent in this worktree. The tasks marked
**`[sesión principal]`** and **`[operador]`** are skipped by it; the main session reviews each delivery against the
textual AC list and commits.

**Rules for the agent:** do not commit or push · do not read or write in `engagements/` or `.gekko-state/` (the
tests use temporary roots with fictitious data) · do not use port 4355 · every server a test starts is
shut down by its numeric PID, never by pattern (`pkill`/`pgrep -f`) · touch only the files in the plan §3 table ·
do not touch `specs/023-*` (another session is drafting it in this worktree) · each task with new logic starts with the case that
fails and leaves its red in the log before the fix · the existing REQ cases do not change what they assert; only
their setup where the plan §3 lists it (`DRAFT_FIELDS` → `DRAFT_KEYS`/template fields) · the new cases use
the ids REQ-RPT-055/056/057 (T2) and REQ-RPT-058 (T12a) that remain in the living spec, so G does not stay red · every message to the operator in Spanish.

## Wave 0 — Falsifiers and baseline (before changing the engine)
- [x] **T0** — clean `git status` on `.claude/tools/findings.py` and `findings_web.py` (if another session has changes there,
  stop and report it); relocate the plan's citations by function name (they are from `66a7506`); measure
  `len(CSS.encode())` (expected 96 403) and `len(DOWNLOAD_CSS)` (5 834); L, WS, W, G and K green; note the number of
  `ok REQ-…` per id (especially LED-002, RPT-021…024, RPT-045…052) and the `N passed` of W · no AC · test: L, WS, W, G, K
- [x] **T1** — AC1 baseline with the engine **untouched**: in `selftest_reports` (`findings_web.py`) the case
  «021-AC1» with the plan §4 fixture (rich rows and rows with no included × `tecnico`/`ejecutivo` × `es`/`en` × no
  draft / complete draft, workspace `ws-base`) and an empty dict of 32 sha256; run WS, which fails and prints the
  32 values; paste them as literals; WS green **on the old code**. Marked with `REQ-RPT-046` (technical) and
  `REQ-RPT-047` (executive), which already exist. No other change in the file · closes `AC1` (baseline) · test: WS, G
- [x] **T1b `[sesión principal]`** — commit of T1 only with `GEKKO_SPEC_UNCHANGED=1` (no behavior change);
  note the hash in the log. No following task starts without this row · no AC · test: log

## Wave 1 — Spec first and templates
- [x] **T2** — living spec: add REQ-RPT-055, -056 and -057 with their MUST/WHEN/THEN from plan §5 (still no cases: G
  stays red because of «REQ sin caso» (REQ with no case) until T4/T6; this is the expected red and it is noted) and the §1 hook
  paragraph with `.claude/tools/report-templates/` · prepares `AC2`, `AC12` · test: G (expected red recorded)
- [x] **T3** — create `.claude/tools/report-templates/tecnico.json` and `ejecutivo.json` exactly as plan §2.1
  (texts copied from `DOC`, `findings.py:932-953`) · prepares `AC1`, `AC3` · test: L (in T4)
- [x] **T4** — in red: the invalid-templates table from plan §4 (AC5 row) against `load_templates` in temporary
  folders, plus: the two from the repo load with their sha256; 17 files → warning with the surplus ones; templates
  folder that is a link → none and an error; `tecnico.json` missing → error «falta la plantilla incorporada» (the built-in template is missing);
  `aviso`/`notice` as a key → rejection. Then `TEMPLATES_DIR`, caps, `ACCENTS` (the ten from plan §2.6),
  `DRAFT_KEYS`, `Plantilla`, `validate_template`, `load_templates` (plan §2.2–2.5) · closes `AC5` (L part), `AC9`
  (rejection) · test: L (red recorded → green)

## Wave 2 — Engine (`findings.py`)
- [x] **T5** — `report_fields(row, lang, keys=None)`, `_md_finding(…, keys=None)`, `_md_short`, `report_model` /
  `render_report` / `validate_draft` with `plantillas=None` (plan §2.5); `DOC` keeps `notice`, `sev`, `status`;
  `DRAFT_FIELDS` is deleted; adjust the setup of the cases that name it (plan §3). The 16 `render_report` sha256
  from T1 green before continuing; the REQ-LED-002 cases untouched · closes `AC1` (Markdown), `AC2` (L part) ·
  test: L, WS
- [x] **T6** — CLI: `--tipo` without `choices`; `cmd_render` loads once, invalid name → exits ≠ 0 with the valid ones
  and no report; `--borrador` against that template. Cases first in L: `render --tipo prueba` with `SELFTEST_TEMPLATE`
  written in a temporary folder (via a copy of the code in `tmp`, like `cmdline_server(code=…)`), `--tipo otro`,
  `--tipo tecnico.json`, `--tipo ../x` exit ≠ 0; the cases at `findings.py:1358-1362` stay the same · closes `AC3`
  (CLI), `AC5` (CLI) · test: L
- [x] **T7** — L invariant cases with `SELFTEST_TEMPLATE` and with «everything» (all sections, columns and fields):
  AC4 (default texts and values es/en, section order, CWE column, `remediation` present; canaries of
  `command`, `artifact`, `evidence.output`, `repro`, `corroboration`, `summary` absent, present in `tecnico`);
  AC6 (each «line» text with each hostile one; spans and fences removed, no forged `<`, `![`, `](`, heading, quote or
  table); AC7 (ledger with the five statuses, confirmed without corroboration, canary `kb`: only `included` ids,
  no KB; `report_model` with exactly one `included(rows)`); AC8 (`inspect.getsource` with no `eval(`, `exec(`,
  `format_map`, `Template(`, `importlib`, `.format(`; load and render with `socket.socket` patched to fail); AC9
  (exact `DOC` notice in every `.md`) · closes `AC4`, `AC6`, `AC7`, `AC8`, `AC9` (L part) · test: L, G

## Wave 3 — Web module (`findings_web.py`)
- [x] **T8** — in red: for each of the ten accents, the `ACCENT_CLASS` class in `report_html` and the `<style>`
  of its variant (`grafito` = today's bytes); contrast of each pair in the plan §2.6 table against its threshold (line
  3:1, number and band 4.5:1). Then `ACCENT_CSS` (variables, plan §2.6), `ACCENT_CLASS`, `CSS += ACCENT_CSS` after
  `DOC_CSS`, the two variants of `DOWNLOAD_CSS`/hash/`PRINT_CSP`, `finding_html(keys=)`, `short_html`,
  `report_body_for`/`report_html` with `plantillas=` and the class. The 16 `report_html` sha256 from T1 green;
  `len(CSS.encode())` ≤ 100 000 (expected 96 924: note the real one) · closes `AC1` (HTML), `AC4` (color), `AC8` (CSS)
  · test: WS
- [x] **T9** — `Ctx.templates`; `report_route` with one snapshot per request: selector in order (built-ins first,
  escaped `etiqueta`), warnings for the rejected ones, `tecnico` missing or invalid → warning with no preview or downloads,
  Provenance with the template's name and sha256, links with `plantilla=`; download with a different `plantilla=` → 409
  with no file; no `plantilla=` → the current one (P1); non-empty unknown `tipo` → 404; drafts (`read_draft`,
  `save_draft`, `post_draft`, `draft_form`) with the template's fields and their placeholders; out go `REPORT_TYPES` and
  the `DOC`/`DRAFT_FIELDS` imports. Cases first in WS (in process, temporary folder): each branch above; a
  `tecnico.json` draft with today's format gives the same `.md`; `post_draft` with `tipo` outside the snapshot → 400 without
  creating `borradores/` · closes `AC5` (page), `AC10` (in process), `AC11` (in process) · test: WS, G
- [x] **T10** — WS page cases: AC6 (hostiles in page, preview, download and `.imprimir`: no `<script`,
  `<img`, `<a `, events or `</style>`; with canary texts, no header, `href`, `action` or `<style>` contains it);
  AC8 (page CSP header identical with and without extra templates and equal to the `CSS_HASH` formula;
  `.html`/`.imprimir` with their directives and the hash of their `<style>`); AC9 (notice in the HTML of every valid template);
  AC7 (no KB or ids outside `included` in the page's sheet) · closes `AC6`, `AC7`, `AC8`, `AC9` (WS part) ·
  test: WS, G

## Wave 4 — Real HTTP and hooks
- [x] **T11** — `tools/report-test.sh`: copy `findings.py`, `findings_web.py`, `sanitize_target_content.py` and
  `report-templates/` to `$W/code`, write `prueba.json` from `SELFTEST_TEMPLATE` with a `python3 -I -c` and a
  second `serve` from the copy on a free port (numeric PID in `cleanup`). Checks: AC3 (order Técnico,
  Ejecutivo, Prueba; Técnico by default; `.md`/`.html`/`.imprimir` × es/en with `demo-ws-reporte-prueba-<language>.<ext>`;
  CLI of the copy = `.md`), AC4 (`acento acento-azul` in page and `.html`), AC5 (warning for an invalid one; invalid
  `tipo` → default page, download 404, `POST …/borrador` 400 without changing the tree; broken `tecnico.json` in the
  copy → warning), AC6 (`a"b.json` and `ñ.json` do not load; `tipo=../x` does not open a file), AC10 (three templates × es/en:
  the six Provenance sha256 = `sha256sum`; `prueba.json` rewritten between page and download → 409 without
  `Content-Disposition`), AC11 (`borradores/prueba.json` only with its fields; `tecnico` form in `prueba` → 403;
  removing `prueba.json` leaves its draft intact and it shows again when it returns). The existing checks do not change · closes
  `AC3`, `AC4`, `AC5`, `AC6`, `AC10`, `AC11` (W part), `AC2` · test: W
- [x] **T12** — `.githooks/pre-commit:87` adds `.claude/tools/report-templates/*` to the `case` for `tools/report-test.sh`;
  `.githooks/test.sh` adds `pc_rt "plantilla sola, stub falla blocked" block 1 yes .claude/tools/report-templates/x.json`
  and `pc_rt "plantilla sola, stub ok allowed" allow 0 yes .claude/tools/report-templates/x.json` (without the spec: it is not a
  boundary, D6) · closes `AC12` (hook) · test: K

## Wave 4b — Per-template brand (amendment 2026-11-17, D4 c; insert after T12 and before T13)
> Design: `plan.md` §2.8; criteria: `spec.md` AC5, AC6, AC8 (amended) and AC13–AC18. Same rules for the agent
> as the rest of `tasks.md`; additionally: test logos and names are **fictitious**, generated in temporary roots by
> `selftest_png`/`selftest_jpeg`; `.claude/tools/report-templates/marcas/` is never created in the repo; no
> built-in template gets `marca` (AC1); the test hexes with a brand (`#2B5D8C`, `#7A3E9D`) are not in `ACCENTS` (`#1F6AA0`
> is `azul`). Citations from `2938e0a`.

- [x] **T12a** — living spec: add REQ-RPT-058 with its MUST/WHEN/THEN and its Limit («Límite») from plan §5 (still no cases: G
  stays red because of «REQ sin caso» (REQ with no case) until T12b; this is the expected red and it is noted) · prepares `AC13`–`AC18` · test: G (expected
  red recorded)
- [x] **T12b** — in red: **at module level**, next to `SELFTEST_TEMPLATE` (`findings.py:1148`), the generators
  `selftest_png(ancho, alto, chunks=…, cola=b"")` and `selftest_jpeg(ancho, alto, segmentos=…, componentes=3, cola=b"")`
  (only `zlib`/`struct`; outside the `selftest` function so that WS and the `python3 -I -c` of T12h can import them); in
  `selftest`, the plan §4 AC13 table against `validate_image` (accepted; rejected with their reason, including
  those for PNG chunk length/count/position and for `DQT`/`DHT`/JPEG markers, 65 `SOS` and `APP14` transform 0; byte
  and side caps), the robustness case (2000 truncated and bit-flipped inputs, fixed seed: only a tuple or `Refusal`) and
  against `strip_image_metadata` (canary outside `tEXt`/`zTXt`/`iTXt`/`eXIf`/`tIME`/private and outside `COM`/`APP1`,
  revalidates, idempotent, `IDAT` and scan data intact); the static AC8 case (no `decompress`/
  `decompressobj`, `eval(`, `exec(`, `importlib`); `contrast_ratio` with `#777777` 4.478, `#767676` 4.542 and `#c0f425`
  1.296 (±0.001). Red with stubs; then `import zlib, base64`, `IMAGE_MAX_BYTES`, `IMAGE_MAX_SIDE`, `IMAGE_TYPES`,
  `validate_image` (every parse failure → `Refusal("invalid_image", …)`), `strip_image_metadata` (PNG whitelist,
  every `APPn`/`COM` out in JPEG) and `contrast_ratio` (plan §2.8). Cases with `REQ-RPT-058`. It is the validator that
  023 will import: plan signature, not copied · closes `AC13` (L part), `AC15` (formula), `AC8` (static for
  image) · test: L (red recorded → green), G
- [x] **T12c** — in red: `marca` rows of AC5 (plan §4) against `validate_template` and `load_templates` in temporary
  folders (unknown/missing key; types `"marca": []`, `"logo": null`, `"logo": ""`, `"logo": "x\n"`,
  `"color": 123`, `"pie": "x"`; slugs `../x`, `/etc/x`, `x/y`, `ñ`, `A`, `x.png`; logo missing, double `.png`+`.jpg`,
  link to a file outside the root, FIFO, directory, `marcas/` link, over the cap, mismatched extension; `color`
  `red`, `#fff`, `#12345g`, `#000000;}body{`, `"#000000\n"`, `#777777` with «4,47:1» in the message;
  `nombre`/`pie` over the cap (121 characters) or charset; `autor` with «GEKKO» in a template with `marca`), each
  with `marca.<key>` (or `textos.<language>.autor`), with no exception other than `Refusal`, and the other templates intact;
  precondition: `#2b5d8c` and `#7a3e9d` are not in `CSS`, `DOWNLOAD_CSS` or `ACCENT_CSS`; `#2B5D8C` is normalized to
  `#2b5d8c`; `Plantilla.marca.limpio` = the clean copy and `Plantilla.marca.sha256` = sha256 of the single read;
  `render_report` of `SELFTEST_MARCA` (with its own `autor`) = the same template without `marca` (es/en, with and without
  draft) and without «gekko». Then `Marca`, `Plantilla.marca = None` by default, `marca` in `validate_template` (with
  `isinstance` per key and the contrast truncated in an f-string), `_read_regular(dir_fd=)`, logo resolution in
  `load_templates` (steps 1–6 of plan §2.8: `fd` of `marcas/` with `O_DIRECTORY|O_NOFOLLOW`, everything relative to it,
  catching `(Refusal, OSError, ValueError)`), `"brand"` in `report_model`, `SELFTEST_MARCA` at module level. The 32
  sha256 of AC1 and the three-argument constructions stay green · closes `AC5` (brand, L part), `AC14`
  (Markdown), `AC15` (validation) · test: L (red recorded → green), WS
- [x] **T12d** — in red: WS cases for AC14 (plan §4) **directly on `report_body_for(…, logo="css")` and
  `report_body_for(…, logo="img")`** and on `report_html`: `aria-label`/`alt` = `esc(nombre)` without «GEKKO ·
  Offensive Security»; `<tfoot>` = classification · name · footer in es and en, and without `pie` classification · name; hostile name and
  footer escaped in the body, `.html` and `.imprimir`; no `content:` with the footer; `.html` of `SELFTEST_MARCA`
  without «gekko» outside the `data:` URLs. The `alt` cases in the page and the preview go in T12f, once
  `report_route` already passes `logo="img"`. Then `report_body_for(…, logo="css")` with the three header forms and the
  `<tfoot>` of `report_html` (plan §2.8). The 16 `report_html` sha256 of AC1 stay green (no brand, today's bytes)
  · closes `AC14` (WS part) · test: WS, G
- [x] **T12e** — in red: WS cases for AC15 (`acento-marca` and its rule `.acento-marca{--al:#2b5d8c;--an:#2b5d8c}` in
  `.html`/`.imprimir` with `color`; `ACCENT_CLASS[acento]` without `color` and always in the preview, without the hex), for amended AC6
  (with PNG and with JPEG: the `<style>` is `download_css(p)[0]`; removing once the `.acento-marca` rule at the
  end and replacing the whole token `url(data:<mime>;base64,<b64>)` with `GEKKO_LOGO_URL`, what remains is byte for byte
  `DOWNLOAD_CSS + ACCENT_CSS` or `DOWNLOAD_CSS_BY_ACCENT[acento]`) and for AC8 in downloads (CSP meta and `.imprimir`
  header with the hash of its own `<style>`; a single `data:` URL in `.html` with a brand, its own). Then
  `GEKKO_LOGO_URL` with its `assert` on import, `download_css` (`replace(…, 1)`), `print_csp`, `report_html` and the
  `.imprimir` branch of `report_route` with them (plan §2.8) · closes `AC6` (CSS), `AC8` (downloads), `AC15` (WS part) ·
  test: WS, G
- [x] **T12f** — in red: WS cases for AC16 (in the `GET` and in the `POST …/borrador` response with
  `accion=previsualizar`: exactly one `<img`, which matches **entirely** by `re.fullmatch` with the exact form, inside
  `.doc-head`, base64 = `Plantilla.marca.limpio`, `alt` = `esc(nombre)` also with a hostile name; Markdown view,
  `tipo=tecnico` and other pages with no `<img`; the REQ-RPT-007 cases at `findings_web.py:3710` unchanged in what
  they assert) and for AC8 in the page (of each response —usual directory, two templates with a brand, one with a rejected
  brand, `GET` and `POST …/borrador`— exactly one `<style>` served, byte for byte `CSS`, no `style=`, CSP
  header byte for byte the same; `.dmarca` in `CSS` and not in `DOWNLOAD_CSS`). Then the `.dmarca` rule after `ACCENT_CSS` and
  `logo="img"` in the preview. Note `len(CSS.encode())` (expected ~97 010, cap 100 000) · closes `AC16` (WS
  part), `AC8` (page) · test: WS, G
- [x] **T12g** — in red: WS cases for AC17 (plan §4): two templates A and B with a brand (`#2B5D8C`/`#7A3E9D`) and the
  built-in ones; in `.html`/`.imprimir` of A and in the `.doc-head` of its preview, without the base64 of B or of Gekko; in the
  page of A, without the base64 of B anywhere and that of Gekko only inside the `<style>`; the color of A by its rule
  `.acento-marca`; and vice versa; one `data:` URL per `.html` (A its own, `tecnico` that of Gekko, `:4224` case unchanged);
  Provenance of A with `Logo` and `Logo SHA-256` = sha256 of the file; links with `logo=<sha256>`; old or non-hex
  `logo=` → 409 «La marca cambió» (the brand changed) without a file; B's logo broken (also a PNG truncated to 20 B) → B in a warning and A and the
  built-in ones with the same output sha256; AC6: the link parameters are exactly `tipo`, `idioma`,
  `ledger`, `borrador`, `plantilla`, `logo`. Then Provenance with `Logo`/`Logo SHA-256`, `logo=` in the links and its
  409 in the download (plan §2.8) · closes `AC17` (WS part), `AC6` (URL) · test: WS, G
- [x] **T12h** — `tools/report-test.sh`: **extends the existing brand check** (`:279`, Gekko's logo as `data:`
  in `ejecutivo.html`, which does not change) with its pair for a template with a brand: in the T11 copy (`$W/code`), write
  with a `python3 -I -c` that imports the copy (`selftest_png` and `SELFTEST_MARCA`, at module level since T12b/T12c)
  `marcas/marca-prueba.png` (with a canary `tEXt`) and `marca-prueba.json` (with `color` `#2B5D8C`), plus
  `marca-rota.json` with `marca.logo` `../x`. Checks: AC16 (one `<img class="dmarca" src="data:image/png;base64,` with
  escaped `alt`; canary absent in the page and in the decoded PNG; CSP header of `tipo=marca-prueba` = that of
  `tipo=tecnico`), AC14 (name and footer in the `<tfoot>` of `.html` and `.imprimir`), AC15
  (`.acento-marca{--al:#2b5d8c;--an:#2b5d8c}` in the `<style>`; the CSP of `.imprimir` with the `sha256` of that `<style>`,
  recomputed in the script), AC17 (`tecnico.html` without the brand's base64 and with Gekko's; Provenance `Logo SHA-256` =
  `sha256sum` of the copy's PNG; rewrite the PNG between page and download → 409 without
  `Content-Disposition`), warning for `marca-rota.json`. Server by numeric PID, never 4355 · closes `AC18`, `AC16`
  and `AC17` (W part) · test: W
- [x] **T12i** — `.githooks/test.sh`: add `pc_rt "logo solo, stub falla blocked" block 1 yes
  .claude/tools/report-templates/marcas/x.png` and `pc_rt "logo solo, stub ok allowed" allow 0 yes
  .claude/tools/report-templates/marcas/x.png` and check that the T12 `case` (`.claude/tools/report-templates/*`)
  already covers them (in `case`, `*` also matches `/`); if not, widen the pattern · closes `AC12` (logos) · test: K

## Wave 5 — Reconciliation and closure
> **Brand amendment (2026-11-17), adds to these tasks:**
> - **T13** (reconcile the living spec) includes the brand: REQ-RPT-058 with its cases; REQ-RPT-007 (the only admitted
>   `<img>`, plan §5), RPT-023 (the CSS URL may be the template's logo), RPT-052 (CSS per template and hash per
>   document with `marca`), RPT-055 (`marca` keys, `marcas/` folder, `autor` without Gekko with `marca`) and RPT-056 (the
>   AC6 exceptions; page `<style>` and CSP equal with and without a brand).
> - **T14** (`docs/pi-hitl.md` §4c), rewritten in `tasks.md`: adds the brand paragraph from plan §3 (where the logo goes,
>   keys, caps, which metadata is removed, that when copying `tecnico.json` `autor` must be changed, and that the brand belongs to the
>   issuer, never to the client).
> - **T15**, rewritten in `tasks.md`: compares against the textual list of the **18** AC; the `code-auditor` looks especially at
>   `validate_image` and `strip_image_metadata` (boundary that 023 will reuse) and at the opening of `marcas/` by `dir_fd`.
> - **T16** adds to the operator's run the brand test template from `spec.md` §7 (fictitious PNG and JPEG, preview
>   and PDF: logo on the cover, footer on every page next to the number, color in lines and numbers) and then deletes it
>   with its logo.

- [x] **T13** — living spec: rewrite REQ-RPT-045…052, RPT-021…024, RPT-007 and LED-002 per plan §5 (includes
  fixing the «Código» (Code) entries with `executive_body` and `draft_head_html`, which do not exist); the new cases already count for
  055/056/057 · closes `AC2`, `AC12` (trace) · test: G
- [x] **T14** — `docs/pi-hitl.md` §4c: where the templates live, how to add one (copy `tecnico.json`), what it
  validates, the palette (strong and light), and that changing a built-in one requires updating the AC1 baseline · no AC ·
  test: reading
- [x] **T15 `[sesión principal]`** — L, WS, W, G and K together green; compare what was delivered against the textual list of
  the 18 AC; `code-auditor` on the diff; CSS measured against the cap · closes `AC2` · test: L, WS, W, G, K
- [x] **T16 `[operador]`** — real run (spec §7): the two templates in the page; downloads with `sha256sum`
  against Provenance; a test template copied by hand that appears without touching code and is then deleted; an
  invalid one with its warning; the PDF printed from `.imprimir` viewed in a viewer, with a strong accent and a light one · test:
  log
- [x] **T17 `[sesión principal]`** — commit (living spec in the same commit); `Estado` of spec, plan and tasks →
  `IMPLEMENTADA`; 021 in the list of merged specs in `CLAUDE.md`/`AGENTS.md` (twins) · test: the hook

## Verification log
> On closing each task: command run + result (green/red), like the ledger.

| Task | Command | Result | Date |
|---|---|---|---|
| T0 | `git status --short -- .claude/tools/findings.py .claude/tools/findings_web.py`; Python measurement of `CSS`/`DOWNLOAD_CSS`; L, WS, W, G, sanitizer, `.githooks/test.sh`, ws-test, tui-test, toolbox-test (main session) | Clean in both `.py` files; CSS 96 403 bytes, `DOWNLOAD_CSS` 5 834 bytes. Main session: G OK (190 requirements, 2 245 cases), L/WS/sanitizer OK, W 84/0, K 48 checks green, ws-test 184/0, tui-test 55/0, toolbox-test PASS. Plan citations checked against current functions; no movement in the two modules since `66a7506`. | 2026-11-17 |
| T1 / T1b | `python3 .claude/tools/findings_web.py selftest` (main session) | GREEN on the untouched engine: 17 «021-AC1» cases (fixture with 5 pinned included + 2 excluded controls; 16 combinations × sha256 of `.md` and `.html`); guard `REQ trace: 190 requisitos, 2262 casos`. Control mutation: «sujeto a revisión.» → «revision.» in `findings.py` turns the AC1 case red (AssertionError), restored and checked with no diff. Code: a coding agent; tests and commit: main session | 2026-11-17 |
| T2 | Edit of `specs/SECURITY-GUARDRAILS-SPEC.md` (G not run) | Added MUST/WHEN/THEN and limits for REQ-RPT-055/056/057, plus the templates directory in the hook paragraph. The G trace is expectedly red for new REQs without cases for RPT-056/057 until later tasks. | 2026-11-17 |
| T3 | Review of the two JSON files against `plan.md` §2.1 | Added `tecnico.json` and `ejecutivo.json` with the planned texts, draft fields, order and vocabulary; no rendering changes. | 2026-11-17 |
| T4 | `REQ-RPT-055` cases in `findings.py:selftest`; `validate_template` and `load_templates` | Cases added before the loader (red on stub pending confirmation); strict validation implemented. No tests run by the coding agent; main session runs L/WS/W/G. | 2026-11-17 |
| T4 fix | Review of the L failure reported by the main session; `findings.py:selftest` (not run here) | The selftest now checks each entry separately and requires file + expected path; the validator locates unknown/missing keys and translates JSON/filesystem errors into Spanish. Main session must repeat L and G. | 2026-11-17 |
| T4 fix 2 | `REQ-RPT-055` unavailable-directory case and `invalid.json` template with a `kb` key | Added the load case that requires `invalid.json` + `raíz.kb`; `load_templates` now keeps the validator's error and adds the missing built-in warnings even if it cannot list the directory. No tests run by the coding agent. | 2026-11-17 |
| T5/T6 | `findings.py`: `report_fields`, `_md_finding`, `_md_short`, `report_model`, `render_report`, `validate_draft`, `cmd_render`, parser; selftest cases (not run) | The engine takes text/sections/fields from the template; the CLI resolves formats once, rejects invalid names without a report and validates the draft against the selected file. `DRAFT_FIELDS`/`DOC` are kept for the existing web callers until their T9 migration; HTML was not modified. L/WS/W/G pending from the main session. | 2026-11-17 |
| T6 fix / T7 | `findings.py:selftest` (not run) | The `prueba` CLI case now compares `--lang es` with `--lang en`. Added `REQ-RPT-057` cases to load SELFTEST_TEMPLATE/everything, visible values and titles, order/columns/field selection/counts; `REQ-RPT-056` for statuses and exact inclusion, KB canary, a single call to `included`, D1 notice, hostile text in spans, no evaluation and sockets. L/WS/W/G pending from the main session. | 2026-11-17 |
| T7 fix | Review of the main session's failure: `todo template` case | Engine: renders the selected table before the full cards when a section declares both, as §2.2 orders. Fixture: no longer expects `CANARY-BLOCKER` in included findings; REQ-LED-002 forbids showing the historical blocker of a confirmed row. An additional case checks that `blocker` is a known field in `report_fields` for `needs_validation`, while that non-included row does not appear in the report. No tests run by the coding agent. | 2026-11-17 |
| T7 fix 2 | Review of the hostile-texts selftest reported by the main session | Replaced the generic-punctuation search with unique markers; each line field prints the marker only inside a span/fence. For `subtitulo` and the section title the test checks acceptance/rejection exactly against the label charset; newline, U+2028 and control remain mandatory rejections. The engine was not changed. No tests run by the coding agent. | 2026-11-17 |
| T8 | Pure import of `findings_web` for sizes; WS cases added (not run) | Fixed palette/classes/sheets and hashes per accent; line contrast ≥3:1 and number/band ≥4.5:1. Page CSS: 96 933 B; accent CSS: 530 B; downloads: grafito 5 834 B, accented 6 364 B. CSP header and class derive from the validated name through a fixed map. L/WS/W/G pending from the main session. | 2026-11-17 |
| T8 fix | WS failure reported by the main session in `report_body_for` | Fixed the call to the one-argument `shown` lambda. Reviewed the other calls changed in the diff: `finding_html` uses a two-argument lambda; `short_html` too; the `shown` of `report_body_for` receives one. I did not run tests. | 2026-11-17 |
| T9 | Static review; `ast.parse` of `findings_web.py`; inspection of callers and `tools/report-test.sh` checks (tests not run) | `Ctx.templates`, single snapshot in the report route and snapshot shared with POST/response; ordered/escaped selector, visible errors, provenance with sha, downloads pinned by `plantilla` (409 on change, absent accepts the current one, unknown type 404), draft fields/files by name and 400 rejection before creating a folder. `REQ-RPT-057` and `REQ-RPT-048` WS cases added. Living spec adjusted in RPT-045/048/049/050. AST and `git diff --check` OK; no tests run by the coding agent. The HTTP script keeps its checks: print links allow an additional query and the hashes remain extractable; manual downloads without `plantilla` are covered by P1. L/WS/W/G pending from the main session. | 2026-11-17 |
| T2–T4 (main session) | L, WS, G | GREEN: `findings.py selftest` OK with 38 REQ-RPT-055 cases; `findings_web.py selftest` OK (AC1 intact); G: only RPT-056/057 «sin caso» (no case) (expected until T7/T9). Red first checked with stubs in place and restored (cmp): `load_templates`→`({}, [])` fails «the two built-in template files load…»; a permissive validator for non-built-ins fails the invalid matrix. Two defects found in review and fixed by the coding agent: inverted file-name assertion and messages without a key/in English; `load_templates` not warning about missing built-ins and discarding the validator's diagnosis | 2026-11-17 |
| T5–T7 (main session) | L, WS, W, G | GREEN: `findings.py selftest` OK; `findings_web.py selftest` OK (17 AC1 cases: Markdown and HTML identical with the new engine); `report-test.sh` 84 passed 0 failed; G `REQ trace: 193 requisitos, 2314 casos` (RPT-055/056/057 covered). Control mutation: `report_model` letting `hypothesis` rows through turns «all sections and fields still show only included IDs and never KB» red; restored (cmp). Review: one real engine defect found by the `todo` case (table + card in the same section only drew the card) and fixed; three badly posed tests fixed (CLI without `--lang es`, blocker in non-included row, hostiles without a marker) | 2026-11-17 |
| T8 (main session) | L, WS, W, G | GREEN: L OK; WS OK (AC1: 16 identical HTML with `grafito`); `report-test.sh` 84/0; G `193 requisitos, 2336 casos`; page CSS 96 933 B (cap 100 000). Control mutation: the `lima-claro` line changed to the brand lime `#c0f425` turns «accent lima-claro meets line, section-number and table-band contrast ratios» red; restored (cmp). Two runtime errors fixed after the run (`shown` arity, `ACCENTS["grafito"] = None` in the contrast loop) | 2026-11-17 |
| T9 (main session) | L, WS, W, G | GREEN: L and WS OK; `report-test.sh` 84/0; G `193 requisitos, 2339 casos`. Control mutation: ignoring the `plantilla=` parameter in the download turns the REQ-RPT-057 case red (409 for old template); restored (cmp). Review: the case found a real page defect (selector ordered Ejecutivo, Técnico, … by an extra `sorted` in `report_route`; now Técnico, Ejecutivo and the rest by name, same order as `load_templates`) and a test regex that did not admit `aria-current` | 2026-11-17 |
| T10 | New cases in `selftest_reports` (not run); `ast.parse` of `findings_web.py`; `git diff --check` | Added temporary template with printable hostile texts and `REQ-RPT-056` cases: page/preview/Markdown/HTML/print inject no markup or canaries into headers, links, actions or CSS; the sheet shows only included ids and not KB; page CSP matches `CSS_HASH` and does not depend on extra templates; CSP/hash of HTML and print match their style; fixed notice in every valid template and in both languages. REQ-RPT-056 updated. AST and diff check OK; tests not run. WS/G pending from the main session. | 2026-11-17 |
| T10 (main session) | L, WS, W, G | GREEN: L and WS OK; `report-test.sh` 84/0; G `193 requisitos, 2343 casos`. Two runtime errors fixed after the run (`BUILTIN` not imported; local variable `html` shadowing the module). Control mutation: removing `esc()` from the selector label is NOT detected, because the validator already rejects `<>&` in the label (the real barrier); the escape is defense in depth with no case → a case that injects an unvalidated `Plantilla` is added in T11 | 2026-11-17 |
| T10 fix / T11 | `ast.parse`, `bash -n tools/report-test.sh`, `git diff --check` (no tests run nor servers started) | WS: `REQ-RPT-056` case passes an unvalidated `Plantilla` directly to the route, preview, HTML and body; `etiqueta` and `textos` contain `<script>x</script>&"`; requires that the original not appear and the escaped form does. Preview fixed to use `ACCENT_CLASS` and WS case `REQ-RPT-052` added; RPT-052 updated. W: added server in a copied tree and an isolated temporary workspace, `prueba.json` comes from `SELFTEST_TEMPLATE`; covers selector/aria-current, accent, invalid and names, fallback/404/POST without writes, broken built-in template, three formats in two languages and hashes/names, CLI, stale pin and per-template draft. Static review: arities/regex and local names checked; the HTTP tests remain for the main session. | 2026-11-17 |
| T11 (main session) | L, WS, W, G | GREEN on the first try: L and WS OK; `report-test.sh` 104/0 (before 84); G `193 requisitos, 2345 casos`; only the operator's 4355 listener remains. Control mutation: removing `esc()` from the selector label now turns the new REQ-RPT-056 case red «even an unvalidated Plantilla … escapes etiqueta and textos» (T10 gap closed); restored (cmp). The coding agent also found that the preview did not apply the accent (fixed, WS assertion) | 2026-11-17 |
| T12 | Static review of `.githooks/pre-commit` and `.githooks/test.sh` (hooks not run) | The `case` runs `tools/report-test.sh` for `.claude/tools/report-templates/*`. Added `pc_rt` with failing stub (blocks and confirms it ran) and successful stub (allows and confirms it ran); the existing foreign-file case checks that it does not run. No tick or commit; K pending from the main session. | 2026-11-17 |
| T12 (main session) | K, G | GREEN: `.githooks/test.sh` ALL GREEN 52; G `193 requisitos, 2345 casos`. Control mutation: removing `.claude/tools/report-templates/*` from the `pre-commit` `case` turns the three «plantilla sola» cases red; restored (cmp) | 2026-11-17 |
| T12a–T12c | `ast.parse` of `findings.py`; `git diff --check`; static review of parser, validation and loading (no selftests) | Added REQ-RPT-058; `findings.py` incorporates PNG/JPEG generators, structural validation without decompression, whitelist cleaning, contrast, `marca` shape and logo loading by `dir_fd` with `O_DIRECTORY|O_NOFOLLOW`; L cases cover AC5 rejections, missing/ambiguous/non-regular/linked/over-cap/wrong-format logos, cleaning, isolation, SHA of the single read and unchanged Markdown. Reds observed before the fix: `AssertionError: validate_image PNG mínimo: NameError: name 'validate_image' is not defined`; `AssertionError: marca clave desconocida: Plantilla 'invalida.json': raíz.marca: clave desconocida`. A later L run went through the image cases and reached the existing Unix socket test, where the sandbox rejected `server.bind(str(socket_path))` with `PermissionError: [Errno 1] Operation not permitted`; the first T12c row failed because the vocabulary still rejected `marca` at the root. No tests were run in this delivery; L/WS/G pending from the main session. No ticks or commit. | 2026-11-17 |
| T12a–T12c (main session) | L, WS, W, G | GREEN on the first try: L and WS OK; `report-test.sh` 104/0; G `194 requisitos, 2436 casos`. Control mutations: keeping `tEXt` in PNG cleaning turns «PNG metadata is removed by whitelist…» red; keeping `COM` (0xFE) in JPEG turns «JPEG APP and COM metadata is removed…» red; restored (cmp) | 2026-11-17 |
| T12d–T12g | Pure import of `findings_web`; `ast.parse`; `git diff --check`; static review (no selftests) | WS cases extend brand/print (REQ-RPT-024), download sheet and hash per logo/accent (REQ-RPT-052), the exact single `<img>` and invariant page CSP/CSS (REQ-RPT-007/056), A/B isolation, provenance and logo pin (REQ-RPT-057/058); REQ-RPT-007/023/024/052/056/057/058 reconciled. Reds of T12d–g before the fix: `T12d RED: TypeError: report_body_for() got an unexpected keyword argument 'logo'`; `T12e RED: download_css absent`; `T12f RED: brand preview image absent`; `T12g RED: stale logo pin returned 200`. The first review import failed on `assert DOWNLOAD_CSS.count(GEKKO_LOGO_URL) == 1` because the expected token included quotes absent from the real CSS; token fixed. Final static check: AST and diff check OK; pure import OK; `CSS=97010`, `DOWNLOAD_CSS=5834` bytes. Selftests not run; L/WS/W/G pending from the main session. No ticks or commit. | 2026-11-17 |
| T12d fix | WS (main session), review of AC14 assertion | WS: only `REQ-RPT-058 AC14...` fails because `hostile_escaped` required the footer in `report_body_for`; the test was fixed to require the escaped name in body/HTML/print and the escaped footer only in HTML/print. The check that raw values are absent in the three outputs is kept. No product changes; WS pending to repeat. | 2026-11-17 |
| T12e fix | WS (main session), grep of locals in `selftest_reports` | The AC15 case called the local `download_css` (a CSS string) as if it were the function; renamed to `accent_download_css` and its uses updated. The AST review of `download_css`, `print_csp`, `report_html`, `report_body_for`, `report_route`, `load_templates`, `read_ledger`, `esc`, `html`, `json` and `re` finds no locals hiding them. Tests not run; WS pending to repeat. | 2026-11-17 |
| T12f fix | WS (main session), review of AC16 assertion | CSS_HASH is now compared with the CSP header of `brand_page_response`; the exact comparison of that header with `CSP` is kept. Only the test changed. Tests not run; WS pending to repeat. | 2026-11-17 |
| T12g fix | WS (main session), audit of draft pins in T12d–g | Downloads of built-in templates now use the current digest from `read_draft`; temporary templates also obtain it through a helper. `built_html_response` and `broken_builtin_response` must answer 200. The test no longer confuses a 409 from a current draft with HTML output; only the test changed. Tests not run; WS pending to repeat. | 2026-11-17 |
| T12d–T12g (main session) | L, WS, W, G | GREEN: L and WS OK; `report-test.sh` 104/0; G `194 requisitos, 2446 casos`. Four test failures fixed after the run (footer required in the preview, which has no `<tfoot>`; local `download_css` shadowing the function; CSS hash looked up in the body and not in the CSP header; Técnico download with `borrador=ninguno` on a workspace with a draft → 409, now with the current draft and an explicit `== 200`). Control mutation: ignoring `logo=` in the download turns AC17 red (changed logo → 409); restored (cmp) | 2026-11-17 |
| T12h–T12i | `bash -n tools/report-test.sh`, `bash -n .githooks/test.sh`, `git diff --check` (no server/tests run) | Extended the HTTP test on the T11 ephemeral second server: generates PNG with tEXt and JPEG with APP1 from `selftest_png`/`selftest_jpeg` only in `$W/code`, derives fictitious templates from `SELFTEST_MARCA`, and checks page, HTML/print, clean logo, color, footer, CSP/hash, Provenance and current/stale pin. Added two `pc_rt` for `.claude/tools/report-templates/marcas/x.png`; the hook pattern already covers the subdirectory. Socket tests not run; W/K pending from the main session. No ticks or commit. | 2026-11-17 |
| T15 fix | Static review; `ast.parse` of both modules; `git diff --check` | Fixed the `tabla`-only projection in Markdown/HTML/print: it adds no cards or fields; `ficha:corta` without `tabla` does not invent a table. REQ-RPT-056 cases cover canaries of `impact`, `evidence.output`, `command`, `repro` and `corroboration` in the three formats, and a short card without columns. Added checks AC4 corroboration, AC5 missing executive and individual errors (`invalid.json`, `extra.json`, `large.json`, `fifo.json`, `link.json`), AC11 pre-021 Técnico draft and AC13 DAC `0xFFCC`. Removed per-render revalidations, `PRINT_CSP_BY_ACCENT`, the redundant `S_ISDIR` and validation duplicates; without changing the optional pin or the palette. T15 now compares the 18 AC. AST and `git diff --check` passed; selftests/gates not run, L/WS/W/G/K pending from the main session. No ticks or commit. | 2026-11-17 |
| T12h–T12i (main session) | L, WS, W, G, K | GREEN on the first try: L and WS OK; `report-test.sh` 110/0 (before 104); G `194 requisitos, 2446 casos`; K ALL GREEN 56; `report-templates/` without `marcas/` in the repo. Control mutation: ignoring `logo=` turns the HTTP check «T12h AC17: pin logo obsoleto da 409 sin archivo» red; restored (cmp) | 2026-11-17 |
| T13–T14 | Review against code/tests; `git diff --check`; G attempt | Reconciled REQ-RPT-007, 021–024, 045–052, 055–058 and LED-002: generic types, AC1 baseline of 32 hashes, HTML titles derived from template/draft, palette/styles per brand, image/CSS/CSP exceptions and `plantilla`/`logo` pins; references to nonexistent functions fixed and brand status updated. §4c now explains paths, template creation, palette, brand keys/caps, PNG/JPEG cleaning, AC1 baseline and that the brand belongs to the issuer. `git diff --check` passed. G did not reach the trace: Node failed in `os.networkInterfaces()` (`uv_interface_addresses returned Unknown system error 1`) during `loadScope`; G rerun pending in the main session. No ticks or commit. | 2026-11-17 |
| T13–T14 (main session) | G | GREEN: `194 requisitos, 2446 casos` after reconciling LED-002, RPT-007, RPT-021…024, RPT-045…052 and RPT-055…058; manually checked that RPT-007 admits only `<img class="dmarca" src="data:…">` from the preview of a validated brand; `docs/pi-hitl.md` §4c with templates and brand | 2026-11-17 |
| T15 (main session) | L, WS, W, G, K, ws-test, tui-test + audit | All green before the fixes (110/0, `194 requisitos, 2446 casos`, K 56, ws 184, tui 55). Independent audit (code-auditor, proportional criterion R1–R3) + review of the 18 AC: 12 met, 6 partial only for missing tests. Fixed: a table-only section of a custom template put all evidence fields into the `.html`/`.imprimir` (real, client deliverable); a short card without a table added a table with `target` in the `.md`; dead code removed; one-line tests added (AC4, AC5, AC11, AC13). After the fixes: L and WS OK, `report-test.sh` 110/0, G `194 requisitos, 2450 casos`. Control mutation: drawing all fields again in the table-only section turns «table-only sections expose only their table…» red; restored (cmp). The optionality of `plantilla=`/`logo=` is not changed (operator's P1) | 2026-11-17 |
| T16 (operator + Playwright) | real run | Operator, on the branch's module over their real workspaces (`:4356`): Técnico and Ejecutivo, `.md`/`.html` downloads with `sha256sum` = Provenance — OK. The rest was delegated («hazla tú y usa Playwright» (do it yourself and use Playwright)): headless Chromium over a copy of `.claude/tools` and a synthetic workspace (8 confirmed, 192.0.2.x). Preview: a single `<img class="dmarca">` `data:image/png`, naturalWidth 400, escaped `alt`, without the `tEXt` canary; JPEG with hostile name `Empresa JPG <b>&` → escaped `alt`, without COM/APP1. Page CSP identical to Técnico. `.imprimir`: own CSP, logo on the cover (`pdfimages`), footer with the number on 17/17 pages (`pdftotext`), color `rgb(43,93,140)` in header, `h2` and numbers. Downloads of prueba-marca, prueba-jpg and tecnico: sha256 = Provenance; the `.md` without logo or footer; Técnico only with Gekko's logo. `rota.json` warned by name and the other templates 200. Light/dark screenshots at 1500 and 420 px checked by eye: no overlaps or clipping. No code changes | 2026-11-18 |
| T17 (main session) | hook | `Estado` → IMPLEMENTADA in spec, plan and tasks; 021 in the list of merged specs in `CLAUDE.md`/`AGENTS.md` | 2026-11-18 |
