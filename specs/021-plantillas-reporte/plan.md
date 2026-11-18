# Technical plan 021 — Configurable report templates

> Status: `IMPLEMENTADA` (2026-11-18) · formerly `APROBADO` — operator, 2026-11-17, with the answers in §9 (P1 yes, P2 yes and AC6/AC8 amended in
> `spec.md`, P3 no, P4 yes plus light tones, §2.6).
> **Amendment 2026-11-17 (per-template brand, operator decision; D4 → (c), D3 extended):** new §2.8; §2.2, §3,
> §4, §5, §7 and §8 updated. Amendment citations: from `2938e0a` (T12 done).
> Spec: [`spec.md`](spec.md) (`APROBADA`, 2026-11-17, 12 AC, D1–D7 resolved; amendments of the same day, the brand one
> adds AC13–AC18) · Branch
> the feature branch, base `66a7506` (`c9422bc` + the simplified status form, which does not touch the report code).
> `file:line` citations: from `66a7506`.
> Falsifier already run (session scratchpad, outside the repo): a prototype of the §2 engine with the two templates
> of §2.1 gave, **byte for byte**, the output of `render_report` and `report_body_for` from `c9422bc` (identical in `66a7506`) in 72 cases (3 sets of
> rows, among them hostile ones, with no id, unknown severity, `impact` blank and numeric, evidence as text ×
> 2 types × 2 languages × 3 drafts × 2 workspaces). It is a signal, not the proof: the proof is AC1 (T1).

## 1. Approach
`report_model` no longer has `if tipo ==`: it receives an already validated template (a dict from a JSON) and builds the cover,
sections and cards only with what it names; today's renderers (`render_report`, `report_body_for`)
now walk the closed vocabulary of §2.2, which has exactly one code path per piece, and that path is
today's code moved elsewhere. Loading and validation live once in `findings.py` (the CLI needs them; the web
imports them, like `validate_draft`). Each request reads the directory once (no cache) and uses that snapshot for the page, the
sha256 values and the downloads. No template text enters CSS, URLs, headers or file names; the color is a
name from a fixed palette whose precomputed CSS is already signed. The two templates in the repo are files and AC1 ties
them to today's output with sha256 values captured **before** touching the engine. Amendment (§2.8): a template with `marca`
(brand) adds a logo, a name, a footer and its own hex; only the base64 of the validated, cleaned logo and the
validated hex reach the CSS of its **downloads**; the page keeps fixed CSS and CSP and shows the logo as a module-generated `data:` `<img>`.

## 2. Contracts

### 2.1 The file: `.claude/tools/report-templates/<nombre>.json`
All keys are mandatory and no others are valid (the engine has no default values: copying
`tecnico.json` and editing it is the way to create another). Full `tecnico.json`:
```json
{
 "etiqueta": "Técnico",
 "acento": "grafito",
 "borrador": ["titulo", "cliente", "periodo", "version", "autor", "clasificacion",
              "resumen", "alcance", "metodologia", "limitaciones", "recomendaciones"],
 "textos": {
  "es": {"antetitulo": "Informe técnico", "subtitulo": "Informe técnico de pentesting",
         "titulo": "Evaluación de seguridad", "cliente": "Cliente no definido", "autor": "GEKKO Offensive Security",
         "periodo": "Pendiente de definir", "version": "0.1 · Borrador", "clasificacion": "CONFIDENCIAL · BORRADOR",
         "rotulos": {"cliente": "Preparado para", "autor": "Preparado por", "periodo": "Período de evaluación", "version": "Versión"},
         "conteo": {"critical": "Críticas", "high": "Altas", "medium": "Medias", "low": "Bajas"}},
  "en": {"antetitulo": "Technical report", "subtitulo": "Technical penetration testing report",
         "titulo": "Security assessment", "cliente": "Client not defined", "autor": "GEKKO Offensive Security",
         "periodo": "To be defined", "version": "0.1 · Draft", "clasificacion": "CONFIDENTIAL · DRAFT",
         "rotulos": {"cliente": "Prepared for", "autor": "Prepared by", "periodo": "Assessment period", "version": "Version"},
         "conteo": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}}
 },
 "secciones": [
  {"titulo": {"es": "Resumen ejecutivo", "en": "Executive summary"}, "prosa": "resumen"},
  {"titulo": {"es": "Alcance", "en": "Scope"}, "prosa": "alcance"},
  {"titulo": {"es": "Metodología", "en": "Methodology"}, "prosa": "metodologia"},
  {"titulo": {"es": "Limitaciones", "en": "Limitations"}, "prosa": "limitaciones"},
  {"titulo": {"es": "Hallazgos", "en": "Findings"}, "conteo": true,
   "hallazgos": {"ficha": "completa", "campos": ["summary", "impact", "remediation", "cvss", "cvss_vector",
                 "cvss_justification", "cwe", "cve", "corroboration", "blocker", "command", "artifact",
                 "evidence.output", "repro"]}},
  {"titulo": {"es": "Recomendaciones", "en": "Recommendations"}, "prosa": "recomendaciones"}
 ]
}
```
`ejecutivo.json` = the same with `"etiqueta": "Ejecutivo"`, `borrador` without `metodologia`, `antetitulo`/`subtitulo`
«Informe ejecutivo» / «Informe ejecutivo de pentesting» / «Executive report» / «Executive penetration testing
report», and:
```json
 "secciones": [
  {"titulo": {"es": "Resumen ejecutivo", "en": "Executive summary"}, "prosa": "resumen"},
  {"titulo": {"es": "Alcance", "en": "Scope"}, "prosa": "alcance"},
  {"titulo": {"es": "Hallazgos por severidad", "en": "Findings by severity"}, "conteo": true},
  {"titulo": {"es": "Hallazgos", "en": "Findings"},
   "hallazgos": {"tabla": ["id", "title", "severity", "target"], "ficha": "corta", "campos": ["impact"]}},
  {"titulo": {"es": "Limitaciones", "en": "Limitations"}, "prosa": "limitaciones"},
  {"titulo": {"es": "Recomendaciones", "en": "Recommendations"}, "prosa": "recomendaciones"}
 ]
```
The keys of the default values (`titulo`, `cliente`, `autor`, `periodo`, `version`, `clasificacion`) are the
same as the draft's: the engine takes `borrador[k]` if it has text and otherwise `textos[idioma][k]`, with no translation table.
They weigh ~2.4 KB each.

**A third format with no code** (it is the `prueba` template of the selftest, AC3/AC4; it lives only in `SELFTEST_TEMPLATE`
inside `findings.py` and is written to temporary roots, never to `report-templates/`): a remediation plan for
the client, accent `azul`, `borrador` = the six cover ones + `resumen` + `recomendaciones`, its own es/en texts and
```json
 "secciones": [
  {"titulo": {"es": "Prioridades", "en": "Priorities"}, "conteo": true},
  {"titulo": {"es": "Recomendaciones", "en": "Recommendations"}, "prosa": "recomendaciones"},
  {"titulo": {"es": "Hallazgos y remediación", "en": "Findings and remediation"},
   "hallazgos": {"tabla": ["id", "severity", "cwe"], "ficha": "corta", "campos": ["remediation"]}},
  {"titulo": {"es": "Resumen", "en": "Summary"}, "prosa": "resumen"}
 ]
```
It changes order, selection, columns, fields, texts and color; it does not remove evidence, steps or corroboration.

### 2.2 Closed vocabulary (what `validate_template` validates)
| Key | Accepted value |
|---|---|
| root | exactly `etiqueta`, `acento`, `borrador`, `textos`, `secciones`, plus optional `marca` (§2.8: the only optional key; without it, today's Gekko brand) |
| `etiqueta` | «label» text (§2.4), ≤ 24 characters |
| `acento` | a name from `ACCENTS` (§2.6): `grafito`, `lima`, `verde`, `azul`, `ambar`, `lima-claro`, `verde-claro`, `azul-claro`, `ambar-claro`, `gris-claro` |
| `borrador` | list with no repeats ⊆ `DRAFT_KEYS` (today's eleven, `findings.py:893-896`) |
| `textos` | exactly `es` and `en`; each exactly `antetitulo`, `subtitulo`, `titulo`, `cliente`, `autor`, `periodo`, `version`, `clasificacion`, `rotulos` (exactly `cliente`, `autor`, `periodo`, `version`), `conteo` (exactly `critical`, `high`, `medium`, `low`) |
| `secciones` | list of 1 to 12 sections; at least one with `hallazgos` (a template cannot produce a report without the block of included findings) |
| section | `titulo` (exactly `es` and `en`, labels) and **either** `prosa` **or** at least one of `conteo`/`hallazgos` |
| `prosa` | a `borrador` field that is not single-line (`ONE_LINE`, `findings.py:896`); the section is omitted if the draft has no text (as today) |
| `conteo` | exactly `true` |
| `hallazgos` | keys ⊆ {`tabla`, `ficha`, `campos`}; at least `tabla` or `ficha`; `campos` if and only if there is `ficha` |
| `tabla` | 1–7 columns with no repeats from `id`, `title`, `severity`, `target`, `cvss`, `cwe`, `cve` |
| `ficha` | `completa` (header severity · status · target; the fields of `report_fields`) or `corta` (header severity only; text fields that have a value) |
| `campos` of `completa` | no repeats ⊆ the 14 of `report_fields`: `summary`, `impact`, `remediation`, `cvss`, `cvss_vector`, `cvss_justification`, `cwe`, `cve`, `corroboration`, `blocker`, `command`, `artifact`, `evidence.output`, `repro` |
| `campos` of `corta` | no repeats ⊆ the 7 text ones: `summary`, `impact`, `remediation`, `cvss_vector`, `cvss_justification`, `cwe`, `cve` |

- **The order of `campos` does not count**: they are drawn in the order of `report_fields` (`findings.py:831-850`); the template
  only chooses. A free order per field is a new feature nobody asked for and would break equivalence with today.
- **What does not exist** and therefore no template can request: `kb`, comments, `status` as a filter or column,
  `show_all`, any row set other than `included(rows)`, the unconfirmed-findings notice (D1: fixed text in `DOC`),
  field labels (`LABELS`), fonts, CSS, HTML, languages other than `es`/`en`; the brand and the logo change
  only through `marca` (§2.8), never through another key.
- **No special cases:** Técnico and Ejecutivo are told apart only by their data (today's two pieces —a full
  block with count cards vs. a count section + table + short card— are two combinations of the same
  vocabulary). The engine names `tecnico` only twice: as the default value and as the first in the page order.
- **Empty:** if a section has `hallazgos` and there are no included findings, `LABELS[idioma]["empty"]` (md) /
  `empty_text` (HTML) comes out once in place of the table and cards (today, `findings.py:1002-1003`, `findings_web.py:2219-2220`);
  the count cards of that section are drawn anyway (with zeros).
- **Order inside a section** (today's): prose | count → table → cards.

### 2.3 Limits
| What | Limit | Why |
|---|---|---|
| bytes per file | `TEMPLATE_MAX_BYTES = 16384` | today's weigh ~2.4 KB; 6× margin; read via `_read_regular` (`findings.py:93`) with that limit |
| templates | `TEMPLATES_MAX = 16` `*.json` files looked at per request | `tecnico` and `ejecutivo` first, then the rest by name; the excess ones are named in a warning and not read |
| name | `[a-z][a-z0-9-]{0,23}` + `.json` | it travels in the URL, the download name, `borradores/<nombre>.json` and the ticket |
| sections | 1–12 | `%02d` and a readable page |
| label | 1–80 characters | today's longest has 36 |
| line | 1–120 characters | today's longest has 24 |
| JSON | repeated keys, `NaN`/`Infinity` (`_reject_constant`, `findings.py:60`), absurd nesting (`RecursionError`), non-UTF-8 → rejection | a repeated key would make `git diff` show one value while the engine uses another |

Measured cost: `json.loads` of `tecnico.json` = 11 µs; 16 files of 16 KiB per request, negligible.

### 2.4 Texts: two classes, and why there is no new escape (AC1 + AC6)
Today the `.md` emits **without a span** `subtitulo` (`findings.py:991`), the cover labels (`:992`, `- **{label}:**`), the
section titles (`:995`) and the count labels (`:1000`); the rest goes in `_code`. Decision: **charset, not
escape** (the spec's recommendation): an escape that does not change text without punctuation is a disguised `_code`, and
changing how those texts come out would break AC1.
- **Label** (comes out without a span in the `.md`): `subtitulo`, `rotulos.*`, `conteo.*`, `secciones[].titulo.*`, `etiqueta`.
  First character `isalpha()`; every character `isalnum()` or one of `` ,;:()¿?¡!'·«»-–—`` (space included). Excluded are
  `` ` * _ ~ [ ] < > & # | \ / . @ = + ``, line breaks, U+2028, control characters and non-ASCII spaces. Reason per character:
  `[]!<>&\`*_~#|` are CommonMark/GFM markup; without `/`, `.` or `@` there is no GFM autolink (`http://…`, `www.…`,
  email); starting with a letter prevents a list (`- `, `1.`), a quote (`> `), a heading or a code block. Today's texts
  all pass (checked: the two JSONs of §2.1); of the hostile list of AC6 only `javascript:alert(1)` passes, and it is
  inert text outside a link.
- **Line** (comes out in `_code` in the `.md`, escaped in HTML): `antetitulo` (the engine applies `.upper()` to it as today,
  `findings.py:980`), `titulo`, `cliente`, `autor`, `periodo`, `version`, `clasificacion`. `str.isprintable()` on
  all its characters: line breaks, U+2028/2029, Cc and Cf (bidi, zero width) and non-ASCII separators are excluded; `<script>`,
  `` ` ``, `|`, `](http://x)` pass and come out as text (AC6 tests it on each one).
- In HTML every template text goes through `esc` (`findings_web.py:141`), also `etiqueta` in the selector (today
  `pick` does not escape because `REPORT_TYPES` was a constant, `:2325`).

### 2.5 Engine in `findings.py`
```python
TEMPLATES_DIR = Path(__file__).resolve().parent / "report-templates"
TEMPLATE_MAX_BYTES = 16384; TEMPLATES_MAX = 16; DEFAULT_TEMPLATE = "tecnico"; BUILTIN = ("tecnico", "ejecutivo")
ACCENTS = {"grafito": None, "lima": ("#3b6600", "#3b6600", None), …, "gris-claro": ("#87918b", None, "#eef1ef")}  # (línea, número, franja), §2.6
DRAFT_KEYS = ("titulo", "cliente", "periodo", "version", "autor", "clasificacion",
              "resumen", "alcance", "metodologia", "limitaciones", "recomendaciones")   # sustituye a DRAFT_FIELDS
class Plantilla(NamedTuple): nombre: str; sha256: str; datos: dict    # no «Template»: AC8 lo busca en el código
validate_template(nombre: str, data: bytes) -> dict        # Refusal("invalid_template", "<archivo>: <ruta.de.clave>: <motivo>")
load_templates(directory: Path = TEMPLATES_DIR) -> tuple[dict[str, Plantilla], list[str]]   # válidas en orden de página, errores
report_fields(row, lang, keys=None)                        # keys=None: los 14 de hoy (render_md no cambia)
report_model(rows, lang, tipo, draft=None, workspace="", plantillas=None)
render_report(rows, lang="en", tipo="tecnico", draft=None, workspace="", plantillas=None)
validate_draft(tipo, data, plantillas=None)                # claves ⊆ plantillas[tipo].datos["borrador"]
```
- **`plantillas=None` loads** `load_templates()` at call time: this way the CLI and the ~40 existing cases that call
  `render_report(rows, lang, "tecnico", …)` do not change (AC2). The web **always** passes the snapshot of its request. A `tipo`
  that is not in `plantillas` → `ValueError` (today, `findings.py:966-967`).
- **`load_templates`**: `os.lstat(directory)` must be a directory and not a link (otherwise: no template and one
  error); `os.scandir`, names ending in `.json` (the rest is ignored); `tecnico`, `ejecutivo` and then the rest
  sorted, up to 16; for each one: slug name → `_read_regular(dir / nombre, TEMPLATE_MAX_BYTES)` (it already rejects a link
  through `O_NOFOLLOW`, a FIFO and a directory through `fstat`, and the size, `findings.py:93-116`) → `validate_template` →
  `Plantilla(nombre, sha256(bytes), datos)`. A failure becomes an error in Spanish with the `repr` of the name (a
  name with control characters does not reach a terminal raw) and that template does not enter; the others continue. A missing
  one from `BUILTIN` is also an error («falta la plantilla incorporada tecnico.json»). No `eval`, no `exec`, no
  `format_map`, no `string.Template`, no `importlib`: `json.loads(…, object_pairs_hook=…, parse_constant=_reject_constant)`
  and checks against fixed tuples.
- **`report_model`**: `included(rows)` (a single call, no second argument), the template's sections filtering out
  the `prosa` ones without text, `cover` = the four `rotulos` with `borrador` or `textos`, `tiles` = `conteo`, `notice` =
  `DOC[idioma]["notice"]` (D1, from the code). `DOC` is left with `notice`, `sev` and `status` (`loc`, `findings.py:956`, does not
  change); eyebrow, subtitle, default values and labels come from the template.
- **Cards**: `completa` = `_md_finding(…, "###", True, keys=campos)` (`findings.py:853`, gains `keys`);
  `corta` = today's block (`findings.py:1011-1016`) moved to `_md_short(lines, row, lang, keys)` and walking
  `keys` in canonical order with today's rule (`not _blank` → `_field`). Table = today's (`:1008-1010`) with
  the template's columns (header from `LABELS`; severity with `loc`; default value `'(no title)'` for
  `title`, `'?'` for the rest).
- **CLI** (`cmd_render`, `findings.py:1020`): `--tipo` loses `choices` (`:2379`, they were `DRAFT_FIELDS`); `cmd_render`
  loads once and, if the name is not among the valid ones, exits ≠ 0 with «plantilla desconocida o inválida X: <error>;
  válidas: …» without printing a report. `--borrador` is validated against that template.

### 2.6 Web in `findings_web.py`
- **`Ctx.templates: Path = TEMPLATES_DIR`** (`findings_web.py:86`): in-process selftests point to a temporary
  folder with `dataclasses.replace`; the real server uses the code's. No environment variables.
- **Palette (D3, with the light tones the operator asked for).** Ten names. Each color paints only three things of
  `DOC_CSS`, chosen because they already exist and because their contrast can be measured: the **line** (the thick rule of
  `.doc-head` and the underline of each `h2`: graphics, WCAG 1.4.11, ≥ 3:1 against the `#fff` paper), the section
  **number** (`.num`: 11 px text, ≥ 4.5:1) and the **band** (background of the tables' `th`, with its `#16201c` text,
  ≥ 4.5:1). A **strong** tone colors line and number and leaves today's band; a **light** tone colors the line with
  a mid-tone that still passes 3:1, tints the band and leaves the number at today's `#6a756f` (4.79:1): a light tone
  never colors text. The unconfirmed-findings notice (`.doc-note`, D1) and the severity cards (`.t-*`) do not change
  with the accent: their color says something (attention, severity) and is not brand.

  | Name | Line (`#fff`, ≥ 3:1) | Number (`#fff`, ≥ 4.5:1) | `th` band (text `#16201c`, ≥ 4.5:1) | Origin |
  |---|---|---|---|---|
  | `grafito` (default) | `#16201c` 16.7 | `#6a756f` 4.79 | `#eef1ef` 14.68 | today, no new CSS |
  | `lima` | `#3b6600` 6.80 | `#3b6600` 6.80 | `#eef1ef` | `focus` of the light theme (`findings_web.py:316`) |
  | `verde` | `#14724a` 5.94 | `#14724a` 5.94 | `#eef1ef` | light `st-confirmed` |
  | `azul` | `#1f6aa0` 5.79 | `#1f6aa0` 5.79 | `#eef1ef` | `.t-low` of `DOC_CSS` |
  | `ambar` | `#8a6410` 5.37 | `#8a6410` 5.37 | `#eef1ef` | `.t-medium` of `DOC_CSS` |
  | `lima-claro` | `#799a17` 3.26 | `#6a756f` 4.79 | `#eef8d0` 15.09 | brand lime `#C0F425` darkened 37 %; band = light `accent-soft` |
  | `verde-claro` | `#4ba063` 3.23 | `#6a756f` | `#e3f6e8` 14.80 | dark `st-confirmed` `#6AE28B` −29 % |
  | `azul-claro` | `#4c96c7` 3.23 | `#6a756f` | `#e4f3fd` 14.74 | dark `sev-low` `#62C0FF` −22 % |
  | `ambar-claro` | `#b58737` 3.24 | `#6a756f` | `#fff4d6` 15.24 | dark `warn` `#F5B74A` −26 %; band = light `notice-bg` |
  | `gris-claro` | `#87918b` 3.26 | `#6a756f` | `#eef1ef` 14.68 | dark `sev-info` `#A5B1A9` −18 % |

  Measured on 2026-11-17 with the WCAG 2.x relative luminance formula (the one in `CONTRAST_PAIRS`). The light ones come
  from kit tokens darkened to the first value ≥ 3.2:1 (margin over 3:1); the bands, from light-theme tokens
  or a tint of the same hue. Excluded: the brand lime as is (1.3:1 on white, not even as a line), red
  and orange (they read as critical/high severity) and strong `gris` (with `#4a554f` it would be almost `grafito`). A
  WS case measures each pair in the table against the threshold of its column.
- **How it reaches CSS without any value entering**: `ACCENT_CSS` is generated at import from `ACCENTS` (a code
  constant), with variables so as not to repeat selectors: per color `.acento-azul{--al:#1f6aa0;--an:#1f6aa0}`
  or `.acento-azul-claro{--al:#4c96c7;--ab:#e4f3fd}`, and once `.acento .doc-head,.acento h2{border-bottom-color:var(--al)}
  .acento .num{color:var(--an,#6a756f)}.acento th{background:var(--ab,#eef1ef)}` (order after `DOC_CSS`, so
  it wins over `.doc h2`/`.doc th` with the same specificity; the page has no `h2`/`th` rules under `.sheet` or
  `.preview`). The template only chooses a name, which has already passed through `ACCENTS`; the class comes from `ACCENT_CLASS[nombre]`
  (`""` for `grafito`, `" acento acento-azul"`…), never from concatenating the file's text.
  - **Cost and budget**: `ACCENT_CSS` measures **521 bytes** (generated and measured in the scratchpad with the ten
    names). Page CSS: 95 972 bytes in `c9422bc`, **96 403** in `66a7506` (+431 from the status form),
    **96 924** with the palette → **3 076** remain under the cap of 100 000 (case at `findings_web.py:4147`). Spec 023
    will also need CSS: if ~3 KB is not enough for it, the cheap options are (1) remove `gris-claro` and `ambar-claro` (−80 B,
    little) or (2) look at where the real weight is, the two base64 fonts (Space Grotesk ~33 KB: a smaller
    glyph subset is the big cut); raising the cap is the operator's decision (it was already raised once, REQ-RPT-017).
    The palette is not what should be cut: it is 0.5 % of the CSS.
  - Page: `CSS += ACCENT_CSS` after `DOC_CSS` (`findings_web.py:567`). The page CSS is static: its hash
    changes **once** (on merge) and afterwards is the same with and without extra templates (AC8 amended).
  - Download and `.imprimir`: two precomputed variants, today's `DOWNLOAD_CSS` (`:2250`, 5 834 bytes) for `grafito`
    and `DOWNLOAD_CSS + ACCENT_CSS` (6 355) for the other nine, each with its hash and its `PRINT_CSP` (`:2251-2253`).
    `report_html` (`:2256`) picks the variant by name and puts the class on `<main class="doc…">`; the preview
    puts it on `<div class="preview sheet doc…">` (`:2346`). With `grafito` not one byte changes (AC1). When printing,
    `print-color-adjust:exact` (already in `PRINT_CSS`) preserves lines and bands.
  - The `.md` has no color.
- **Page** (`report_route`, `findings_web.py:2289`): one snapshot `plantillas, errores = load_templates(ctx.templates)`
  per request. `tipo` absent, empty or unknown → `tecnico` (today, `:2294-2295`); the selector lists the valid ones in
  order (`etiqueta` escaped); each error appears in a warning; if `tecnico` is not among the valid ones and it falls back to it, the
  page says which one is missing or why it is not valid and draws no preview or downloads (it does not invent another; the others stay
  in the selector). «Procedencia» (Provenance) adds `Plantilla: <code>tecnico</code>` and `Plantilla SHA-256: <code>…</code>`
  (sha256 of the bytes read in this snapshot) to today's four (`:2349-2350`).
- **Downloads** (`:2356-2374`): the page's links also carry `plantilla=<sha256>`. If the parameter is present and
  is not the sha256 of this snapshot's template → 409 «La plantilla cambió» without a file (mold of `:2357-2360`). If it
  is absent, the current one is accepted (the hand-made links from 017/019 and the checks of `tools/report-test.sh:51-54`
  and `:274` keep working, AC2; P1: yes). A non-empty `tipo` that is not a valid template → fixed 404 without a file
  (today it silently fell back to Técnico: tightens, AC5). Name: today's (`:2368`).
- **Drafts** (AC11): `read_draft`, `save_draft`, `post_draft`, `draft_form` (`:2098`, `:2118`, `:2384`, `:2271`)
  take `plantillas` and use `plantillas[tipo].datos["borrador"]` instead of `DRAFT_FIELDS[tipo]`; `post_draft`
  rejects with 400 a `tipo` outside the snapshot before opening anything (today, `:2390`), so no text outside the
  list reaches `borradores/<nombre>.json`. Form placeholders: `textos[idioma][clave]` (today
  `DOC[lang][defaults[key]]`, `:2274-2279`). The ticket remains `ticket("borrador", ws, nombre, visto)`
  (`:2285`): it already binds workspace and template by name; binding it to the sha256 as well would make a save return 403 after a template
  change that `validate_draft` already handles (422 if the draft carries a field the template no longer offers). The existing
  `tecnico.json`/`ejecutivo.json` are read the same way: same allowed fields. No new state (D7).

### 2.7 Hook (AC12)
`.githooks/pre-commit:87`: the `case` that runs `tools/report-test.sh` adds `.claude/tools/report-templates/*`. Templates
are **not** in the boundary list of §1 (D6 a): a new template only triggers the tests.
`.githooks/test.sh:100-105` adds two `pc_rt`: «plantilla sola, stub falla blocked» and «plantilla sola, stub ok allowed»
(without the spec: it is not boundary).

### 2.8 Per-template brand (amendment 2026-11-17, D4 c and D3 extended)
**The JSON.** An optional root key; `tecnico.json` and `ejecutivo.json` **do not** carry it (AC1). Example (fictional):
```json
 "marca": {"nombre": "Ejemplo Seguridad S.A.", "logo": "ejemplo",
           "pie": {"es": "Uso exclusivo del destinatario", "en": "For the addressee only"},
           "color": "#2B5D8C"}
```
| Key | Accepted value |
|---|---|
| `marca` | object with exactly `nombre` and `logo`, plus optional `pie` and `color`; any other key → rejection (AC5) |
| `nombre` | «line» text (§2.4: `isprintable`), 1–120 characters (the limits of the other texts, as the operator asked); it comes out escaped (`esc`) as `alt`/`aria-label` and in the footer |
| `logo` | slug `_SLUG` (`findings.py:992`): no extension, no `/`, no `..`, ASCII; it is a name, not a path |
| `pie` | exactly `es` and `en`, «line» 1–120 |
| `color` | `re.fullmatch(r"#[0-9a-fA-F]{6}", v)` (`fullmatch`, not `$`: `#000000\n` does not pass), normalized with `.lower()`, `contrast_ratio(v, "#ffffff") ≥ 4.5`; the error carries the contrast **truncated** to two decimals (`math.floor(r * 100) / 100`: 4.496 never says «4,50:1» and is rejected), with a decimal comma, built with an f-string (the AC8 case forbids `.format(` in `validate_template`): `#777777` → «4,47:1» |
| `textos.*.autor` (with `marca`) | does not contain `gekko` (`casefold`): with its own brand the default author cannot be Gekko's (it is the only mention of Gekko in the `.md` and in the cover, §2.8 «Markdown»); without `marca`, no change |

`nombre` and `logo` go together: a name without a logo would leave Gekko's logo with another company's name. Without `pie`, the
printed footer is today's plus the name; without `color`, the downloads use the palette `acento`. `acento` remains
mandatory (the preview uses it; there is no «closest color»). `validate_template` (`findings.py:1018`) validates the
shape of `marca` over the JSON's bytes (it stays pure: it opens no files); the contrast is measured there. Each key of
`marca` is checked with `isinstance` before use (`"marca": []`, `"logo": null`, `"color": 123`, `"pie": "x"` are
`Refusal` from `bad()`, never a `TypeError`).

**The files.** `.claude/tools/report-templates/marcas/<slug>.png` or `<slug>.jpg`. `load_templates`
(`findings.py:1109`) resolves the logo of each valid template with `marca`:
1. `fd = os.open(directory / "marcas", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` and `fstat(fd)` (the mold of
   `findings.py:438-457`): a link or something that is not a folder fails on open (`ELOOP`/`ENOTDIR`) and the template is
   rejected (`marca.logo: la carpeta marcas no es una carpeta regular`). No prior `lstat` by path: there is no window
   between checking and opening, and everything that follows is relative to that `fd`.
2. `os.lstat(f"{slug}.png", dir_fd=fd)` and `.jpg`: exactly one exists (none → «falta el logo»; both → «logo
   ambiguo»). The folder is not listed: only the name the template names is opened, already validated as a slug.
3. `_read_regular(nombre, IMAGE_MAX_BYTES, dir_fd=fd)` (`findings.py:94-117`, which gains `dir_fd: int | None = None`,
   passed to `os.open`: `O_NOFOLLOW` rejects the link —also to a file outside the repo—, `fstat` the FIFO and the
   directory, and the size, also if it grows while reading). That single read gives `raw`: the sha256 for «Procedencia», for the
   `logo=` link and for the 409 is that of `raw`, never of a second read by path.
4. `validate_image(raw)`; the detected type must match the extension (PNG in `.jpg` → rejection).
5. `limpio = strip_image_metadata(raw)`; `validate_image(limpio)` again (if it fails, rejection: a clean
   copy that does not validate is never served).
6. `Plantilla(nombre, sha256, datos, marca=Marca(...))`.
Any failure: `_template_error(nombre, "marca.logo", motivo)` (`findings.py:1004`), that template out and the others
continue (AC5). The logo step catches `(Refusal, OSError, ValueError)`, not only `Refusal` as the validation does
today (`findings.py:1135-1137`): an unexpected exception from the analysis never reaches the page nor takes the others down (AC17). `Plantilla` gains a fourth field with a default value, `marca: Marca | None = None`, so
the three-argument constructions in the cases (e.g. `findings_web.py:3915`) do not change. **The engine draws the brand
only from `Plantilla.marca`** (already validated and cleaned bytes), never from `datos["marca"]`: a `Plantilla` built
by hand with `datos["marca"]` and `marca=None` comes out without a brand.

**Validator and cleaning** in `findings.py` (not in the web: the CLI does not need them today, but spec 023 imports them as
the web imports `validate_template`, `findings_web.py:26`; with `import zlib` and `base64` added at `findings.py:35`):
```python
IMAGE_MAX_BYTES = 262144; IMAGE_MAX_SIDE = 2048; IMAGE_TYPES = ("image/png", "image/jpeg")
class Marca(NamedTuple): nombre: str; logo: str; archivo: str; mime: str; limpio: bytes; sha256: str; pie: dict | None; color: str | None
validate_image(data: bytes, max_bytes: int = IMAGE_MAX_BYTES, max_side: int = IMAGE_MAX_SIDE) -> tuple[str, int, int]
    # (mime, ancho, alto) o Refusal("invalid_image", motivo en español); nunca decodifica ni descomprime;
    # todo struct.error/IndexError/ValueError del recorrido se convierte en Refusal("invalid_image", …)
strip_image_metadata(data: bytes) -> bytes      # sólo sobre bytes que pasaron validate_image; ValueError si no
contrast_ratio(fg: str, bg: str) -> float       # WCAG 2.x, la fórmula del caso de findings_web.py:3899-3905
```
- **PNG.** 8-byte signature; each chunk `length(4) type(4) data crc(4)` with `length ≤ 2³¹−1` and within what remains
  of the file, 4-letter ASCII type, `zlib.crc32(type + data)` equal to the CRC; `IHDR` first, length 13, sides
  1…`max_side`, depth and color type from the standard's table, compression 0, filter 0, interlace 0 or 1, and a
  single `IHDR`; at least one `IDAT`, all consecutive; `IEND` last, length 0, and the file ends there (one byte or a ZIP
  after it → rejection); `acTL`/`fcTL`/`fdAT` (APNG) → rejection. **Each retained chunk is validated internally** (otherwise,
  rejection, it is never stripped): `gAMA` length 4, `cHRM` 32, `sRGB` 1, `pHYs` 9; `PLTE` a multiple of 3 between 3 and 768,
  mandatory with color 3 and forbidden with color 0 or 4; `tRNS` ≤ `PLTE` entries (color 3), 2 (color 0) or 6 (color 2),
  forbidden with color 4 or 6; each at most once and before the first `IDAT`, `PLTE` before `tRNS`. This way no
  chunk that is copied to the output carries free bytes (a 4000 B `pHYs` with HTML is a rejection).
  **Cleaning by allowlist**: `IHDR`, `PLTE`, `tRNS`, `gAMA`, `cHRM`, `sRGB`, `pHYs`, `IDAT`, `IEND` remain,
  copied with their CRC; everything else is removed (`tEXt`, `zTXt`, `iTXt`, `eXIf`, `tIME`, `iCCP`, `sPLT`, private, unknown).
  Allowlist and not denylist: a chunk nobody foresaw does not pass.
- **JPEG.** `FFD8` at the start; the markers of the **whole** file are walked (more than «up to `SOS`»: this way a `COM`
  between scans of a progressive file is also seen): each segment with length ≥ 2 and within the file; exactly one
  `SOF0`/`SOF1`/`SOF2` (any other `SOFn` → rejection) before the first `SOS`, with 1 or 3 components (CMYK out) and sides
  1…`max_side`; after each `SOS`, entropy data where `FF00` and `FFD0`–`FFD7` are data and any other `FFxx` opens the
  next marker (`DHT`, `DQT`, `DRI`, `SOS`, `APPn`, `COM` or `EOI`); `EOI` exactly in the last two bytes.
  **Cleaning**: all `APP0`–`APP15` and `COM` are removed, wherever they are; `SOI`, `DQT`, `DHT`, `DRI`, `SOF`,
  `SOS` with their data and `EOI` are copied. Removing `APP0` too is stricter than requested (`APP1`–`APP15`): the JFIF
  header can carry a thumbnail with arbitrary bytes and the browser does not need it.
  **Allowlist for validation as well**: `DQT` with the sum of its tables (1 + 64·(1+Pq), Pq ∈ {0,1}, Tq ≤ 3) = length − 2;
  `DHT` with the sum of (17 + Σcounts), Σcounts ≤ 256, Tc ≤ 1, Th ≤ 3, = length − 2; `DRI` length 4; `SOF` length 8 + 3·Nf;
  `SOS` length 6 + 2·Ns, 1 ≤ Ns ≤ Nf, with components from the `SOF`; `RSTn` only inside entropy data and only with `DRI`;
  at most 64 `SOS`, 16 `DQT` and 32 `DHT` (a bomb of progressive scans costs the browser CPU even if it weighs little).
  Any other marker (`DNL`, `DHP`, `EXP`, `JPGn`, `TEM`, `RES`, `DAC`, another `SOFn`), a second `SOI` or `FFFF`
  padding → rejection. A 3-component JPEG with `APP14` `Adobe` and transform 0 (RGB without YCbCr) → rejection («JPEG RGB
  sin YCbCr no admitido»): removing that `APP14` would silently change the colors; with transform 1 or without `APP14`, removing
  it does not change the decoding.
- **Invariants fixed by L**: `validate_image(limpio)` passes; `strip_image_metadata(limpio) == limpio`; the `IDAT` (PNG)
  and the data after `SOS` (JPEG) are byte for byte those of the original; no rejection of AC13 is «fixed» by cleaning; with
  2000 truncations and flipped bits (fixed seed) of the minimal files, `validate_image` only returns its tuple or raises
  `Refusal`. Neither `validate_image` nor `strip_image_metadata` decompresses (`zlib` only for `crc32`): a `zTXt` or an
  `IDAT` that would inflate to 1 GiB is never inflated (static case of AC8).
- **SVG, GIF, WebP, BMP**: they have no PNG signature or `SOI`; they fall at the first check. No `Content-Type` or
  extension decides the type.
- **Spec 023** (screenshots) reuses `validate_image` and `strip_image_metadata` with its own limits (`max_bytes`,
  `max_side` are parameters). Its D5 (decided) also cleans and adopts this list (no `APPn`, not `APP0`/`APP14` either,
  023 `spec.md` §4 and D5). Spec 023 announces that it hardens the validator, also for logos: the length and
  position rules for chunks and segments above are already part of that hardening; its `IDAT` decompressed as a stream with
  bounded output will replace, when it is planned, the static «no `decompressobj`» case of this spec. Changing the signature of
  these functions after merging 021 touches REQ-RPT-058 and 023.

**Engine (`findings.py`).** `report_model` (`findings.py:1172`) adds `"brand": templates[tipo].marca` (or `None`).
`render_report` ignores it: the `.md` carries no logo or `BRAND_LINE` today (`findings.py:1211-1216`) nor does it gain them (AC14).

**Web (`findings_web.py`).**
- **Header** (`report_body_for`, `:2236`) gains `logo: str = "css"`:
  - without a brand: today's `<span class="dlogo" role="img" aria-label="GEKKO · Offensive Security">` in both modes;
  - with a brand and `"css"` (`.html`/`.imprimir`): `<span class="dlogo" role="img" aria-label="{esc(nombre)}">`; the logo is
    put by the document's `<style>`;
  - with a brand and `"img"` (only the preview, `report_route` `:2367`):
    `<img class="dmarca" src="data:{mime};base64,{b64}" alt="{esc(nombre)}">`, with `mime` from `validate_image` (one of
    the two constants, never from the file or the template) and `b64 = base64.b64encode(limpio).decode()` (alphabet
    `A-Za-z0-9+/=`: it does not close the attribute).
- **Page CSS**: one fixed rule `.dmarca{display:block;max-width:170px;max-height:36px;width:auto;height:auto}`
  (77 B, the same box as `.dlogo`, `:375`) after `ACCENT_CSS` (`:586`) and **outside `DOC_CSS`** (putting it in
  `DOC_CSS` would change `DOWNLOAD_CSS` and break AC1). A class distinct from `.dlogo` so that a transparent logo is not
  drawn over Gekko's background. The page CSS changes once more with this amendment (before merging) and afterwards
  is the same with and without branded templates; the CSP already carries `img-src data:` (`:601`).
- **Download CSS per template**: `download_css(p: Plantilla) -> tuple[str, str]` (CSS, hash):
  - without a brand: `DOWNLOAD_CSS_BY_ACCENT[acento]`, `DOWNLOAD_CSS_HASHES[acento]` (`:2285-2287`), today's bytes (AC1);
  - with a brand: base = `DOWNLOAD_CSS + ACCENT_CSS + ".acento-marca{--al:<hex>;--an:<hex>}"` if there is `color`, otherwise
    `DOWNLOAD_CSS_BY_ACCENT[acento]`; then `base.replace(GEKKO_LOGO_URL, f"url(data:{mime};base64,{b64})", 1)` with
    `GEKKO_LOGO_URL = f"url(data:image/png;base64,{BRAND_PNG['horizontal-claro']})"` and an `assert` at import that it
    appears exactly once in `DOWNLOAD_CSS` (the `.dlogo` rule of `DOC_CSS`, `:375`; `ACCENT_CSS` and the `.acento-marca`
    rule carry no `url(`, so checking at import is enough): the branded `.html` has
    a single `data:` URL, its own, and not Gekko's; hash = `base64(sha256(css))`, per document;
  - class of `<main>`: `" acento acento-marca"` with `color`, otherwise `ACCENT_CLASS[acento]` (`:568`); the generic rules
    `.acento .doc-head,.acento h2{…var(--al)}` and `.acento .num{…var(--an,…)}` of `ACCENT_CSS` (`:581-582`) do the
    rest; without `--ab`, the band stays `#eef1ef` (the hex colors text and lines, not backgrounds);
  - the only thing derived from the template in that CSS: the base64 of validated, cleaned bytes and the validated hex; `mime` and the
    class name are code constants. An unquoted `url(` cannot be closed with that alphabet.
  - `report_html` (`:2295-2303`) uses `download_css`; `.imprimir` (`:2424-2426`) builds its CSP with
    `print_csp(hash)` (same text as `PRINT_CSP_BY_ACCENT`, `:2291`) instead of looking it up by accent.
  - It is computed on every request from the snapshot (no cache, §6): `download_css` only receives the chosen template, so
    another one's logo cannot sneak in (AC17).
- **Printed footer** (`:2303`): without a brand, today's `<td>{esc(clasificación)}</td>`; with a brand,
  `<td>{" · ".join(esc(x) for x in (clasificación, nombre, pie[idioma]) if x)}</td>`. It is text in the `<tfoot>`, which
  repeats on every printed page through `display:table-footer-group` (`PRINT_CSS`, `:2275`), with the page number on
  the right through `@page @bottom-right` (`:2271`, unchanged). Never a `content:` with template text.
- **Provenance** (`:2400`): with a brand adds `Logo: <code>marcas/<slug>.<ext></code>` and `Logo SHA-256: <code>…</code>`
  (sha256 of `raw`, the only read of that snapshot: the one `sha256sum` gives; the clean one is a deterministic function of it).
  The download links (`:2379`) add `logo=<sha256>`; on download (`:2407-2409`), a present `logo` that differs
  from the current sha256 → 409 «La marca cambió» without a file (a value that is not 64-char hex is different: same mold as
  `plantilla=`); absent → the current one (P1).

**Limits and cost.** `IMAGE_MAX_BYTES = 262144` (256 KiB) and `IMAGE_MAX_SIDE = 2048` px (the box is 170×36 CSS px;
2048 leaves more than 10× for printing at 300 dpi and bounds browser memory when decoding). Worst case per request:
16 templates with a 256 KiB logo → read, CRC, sha256 and base64 = **7.4 ms** (measured in the scratchpad on 2026-11-17 with
`os.urandom`; the chunk walk adds on and is linear). The base64 of 256 KiB measures 349 528 B: the `.html` of a
template with a brand grows to ~355 KB and the page with its preview the same, once.

**Markdown.** No logo, no `BRAND_LINE`, no name or footer: the `.md` carries no logo or `BRAND_LINE` today
(`findings.py:1211-1216`). The only mention of Gekko in the `.md` and in the HTML cover is the default value of `autor`
(`textos.<idioma>.autor` = «GEKKO Offensive Security», `tecnico.json:8,13`, `ejecutivo.json:7,12`; case
`findings.py:1749`, «Prepared by»), which is template text: `marca.nombre` does not replace it, and a template with
`marca` whose `autor` contains «gekko» is rejected (§2.8 table), so copying `tecnico.json` and adding `marca` without
changing the author does not mix two brands. AC14 tests it with the `.md` of a template with and without `marca` (its own `autor`
in both).

## 3. Affected files
| File | Change | AC |
|---|---|---|
| `.claude/tools/findings.py` | `TEMPLATES_DIR`, limits, `ACCENTS`, `DRAFT_KEYS`, `Plantilla`, `validate_template`, `load_templates`; `report_fields(keys=)`, `_md_finding(keys=)`, `_md_short`; `report_model`/`render_report`/`validate_draft` with `plantillas=`; reduced `DOC`; `cmd_render` and `--tipo` without `choices`; `SELFTEST_TEMPLATE`; cases | AC1 (md), AC4–AC9 |
| `.claude/tools/report-templates/tecnico.json`, `ejecutivo.json` | create (§2.1) | AC1, AC3 |
| `.claude/tools/findings_web.py` | `Ctx.templates`; remove `REPORT_TYPES` and the `DOC`/`DRAFT_FIELDS` imports; `ACCENT_CSS`, `ACCENT_CLASS`, two variants of `DOWNLOAD_CSS`/`PRINT_CSP`; `finding_html(keys=)`, `short_html`; `report_body_for`/`report_html` with `plantillas=` and accent class; `report_route` (snapshot, warnings, selector, Provenance, `plantilla=`, 404); drafts; cases (AC1 baseline) | AC1, AC5–AC11 |
| `tools/report-test.sh` | copy of the code to `$W/code` with its `report-templates/` + `prueba.json` and a second `serve` (numeric PID in `cleanup`); checks for AC3, AC4, AC5, AC10, AC11 | AC3–AC5, AC10, AC11 |
| `.githooks/pre-commit`, `.githooks/test.sh` | §2.7 | AC12 |
| `.claude/tools/findings.py` (amendment) | `import zlib, base64`; `IMAGE_MAX_BYTES`, `IMAGE_MAX_SIDE`, `IMAGE_TYPES`, `Marca`, `Plantilla.marca`; `validate_image`, `strip_image_metadata`, `contrast_ratio`; `marca` in `validate_template`; logo in `load_templates`; `"brand"` in `report_model`; `_read_regular(dir_fd=)`; `SELFTEST_MARCA` and generators `selftest_png`/`selftest_jpeg` at module level, next to `SELFTEST_TEMPLATE` (`findings.py:1148`), so that WS and W's `python3 -I -c` can import them (with optional chunks/segments); cases | AC5, AC13–AC15 |
| `.claude/tools/findings_web.py` (amendment) | `.dmarca` rule in `CSS`; `GEKKO_LOGO_URL` and its `assert`; `download_css`, `print_csp`; `report_body_for(logo=)`; `report_html` (CSS, class and `<tfoot>`); `report_route` (preview with `logo="img"`, logo Provenance, `logo=` and its 409, CSP of `.imprimir`); cases | AC6, AC8, AC14–AC17 |
| `.claude/tools/report-templates/marcas/` | **not** created in the repo with this spec (no built-in template has a brand); it exists only in temporary roots of L, WS and W | AC13, AC18 |
| `tools/report-test.sh` (amendment) | in T11's copy: `marcas/marca-prueba.png` and `marca-prueba.json` generated with `python3 -I -c`; AC18 checks | AC18 |
| `specs/SECURITY-GUARDRAILS-SPEC.md` | §5 | AC2, AC12 |
| `docs/pi-hitl.md` §4c | one paragraph: where templates live, how to add one (copy `tecnico.json`), what it validates, that changing a built-in requires updating the AC1 baseline; and (amendment) how to set a brand: `marcas/<slug>.png|.jpg`, the keys of `marca`, limits, which metadata is removed, that when copying `tecnico.json` the `autor` must be changed (with `marca` it cannot be Gekko's), that the brand belongs to the issuer and never to the client | — |

Unchanged: `.gitignore`, `toolbox/*`, the launcher, `LABELS`, `render_md`, `included`, the `report-writer`
prompts (`--tipo tecnico|ejecutivo` remains true). On merge: the specs line in `CLAUDE.md`/`AGENTS.md`.

**Existing cases that change only in how they are set up (not in what they assert):** those that name `DRAFT_FIELDS`
(`findings.py:1182`; `findings_web.py:3795, 3809, 3930, 3976, 4056, 4061, 4074, 4078`) move to
`DRAFT_KEYS`/the loaded template's fields; the CSP one (`:3639`) already compares against the computed `CSS_HASH`, so
it stays green. T0 lists any others that appear on relocation.

## 4. AC → test map
| AC | Test (file · case) | REQ |
|---|---|---|
| AC1 | **WS** `selftest_reports`: «021-AC1 línea base»: 16 cases (rows {rich: `cvss_vector`, evidence as dict and as text, steps, `impact` blank and numeric, no id, unknown severity, `HOSTILE` + the AC6 list} and {no included findings}) × `tecnico`/`ejecutivo` × `es`/`en` × {no draft, complete draft with one hostile field}, workspace `ws-base`; sha256 of `render_report` and of `report_html` compared with 32 literals. It goes in WS (which imports `render_report`), not duplicated in L | RPT-046, RPT-047 |
| AC2 | **W** + **G**: all the cases of LED-002, RPT-021…024, -045…-052 without touching their assertion | the same |
| AC3 | **W**: `$W/code` + `prueba.json`; page: order Técnico, Ejecutivo, Prueba and `aria-current` on Técnico without `tipo`; `.md`/`.html`/`.imprimir` × es/en with `Content-Disposition` `demo-ws-reporte-prueba-<idioma>.<ext>`; `python3 $W/code/findings.py render --tipo prueba` = `.md` (cmp) | RPT-057 |
| AC4 | **L**: `render_report` with `SELFTEST_TEMPLATE` in a temporary folder: es/en texts and default values, order of section titles, table header with CWE, `remediation` present; canaries of `command`, `artifact`, `evidence.output`, `repro`, `corroboration`, `summary` absent (and present in `tecnico`, control). **WS**: for each of the ten accents, `report_html` carries its class from `ACCENT_CLASS` and the `<style>` of its variant (`grafito`: today's bytes); each pair of the §2.6 table measures at least its threshold (line 3:1, number and band 4.5:1). **W**: `class="preview sheet doc acento acento-azul"` on the page and `class="doc acento acento-azul"` in the `.html` of `prueba` | RPT-057, RPT-052 |
| AC5 | **L**: table of invalid templates against `load_templates` in temporary folders (broken JSON, non-UTF-8, repeated key, `NaN`; unknown key/section/field incl. `kb`, `comentarios`, `__class__`, `aviso`; language `fr`; label with `` ` ``/`/`/`.`/line break/starting with `-`; line with U+2028; text of 81/121 characters; 13 sections; none with `hallazgos`; `prosa` of one line or outside `borrador`; repeated `campos`; `cvss` in `corta`; accent `#ff0000`/`rojo`; `A.json`, `a"b.json`, `ñ.json`, `x.y.json`; 16 385 bytes; link; FIFO; directory): each one an error in Spanish with file and key, that template out, the others with the same output sha256 as without it; 17 files → warning with the excess ones. **W**: warning on the page; `tipo=<invalid>` → default page, download 404, `POST …/borrador` 400 without writing (sha256 of the tree), CLI ≠ 0; `tecnico.json` deleted or broken → the page says so, without preview. **Amendment, L**: `marca` rows (unknown or missing key; `logo` `../x`, `/etc/x`, `x/y`, `ñ`, `A`, `x.png`; absent logo, `.png` and `.jpg` at once, link to a file outside the temporary root, FIFO, directory; `marcas/` a link; 262 145 bytes; side 2049; extension that does not match; `color` `red`, `#fff`, `#12345g`, `#000000;}body{`, `"#000000\n"`, `#777777` with «4,47:1» in the message (truncated, not rounded); `nombre` empty/121 characters/with a line break; `pie` with U+2028 or without `en`; wrong types `"marca": []`, `"logo": null`, `"logo": ""`, `"logo": "x\n"`, `"color": 123`, `"pie": "x"`; `textos.es.autor` = «GEKKO Offensive Security» with `marca`, and `textos.en.autor` = «by gekko»): each one with `marca.<clave>` (or `textos.<idioma>.autor`) in the error, with no exception other than `Refusal`, and the other templates intact; `#767676` and `#2B5D8C` pass (normalized `#2b5d8c`). The hex values of the test templates with a brand (`SELFTEST_MARCA` `#2B5D8C`, and AC17's A/B `#2B5D8C`/`#7A3E9D`, 6.89:1 and 6.99:1) are not from `ACCENTS`, and the case checks as a precondition that they do not appear (in lowercase) in `CSS`, `DOWNLOAD_CSS` or `ACCENT_CSS` (`#1f6aa0` is `azul` and appears 3 times) | RPT-055, RPT-058 |
| AC6 | **L**: each «line» text with each hostile string (the labels with those the charset admits): spans and fences removed (`_CODE_SPAN`), the `.md` carries no forged `<`, `![`, `](`, heading, quote or table (RPT-051 helper). **WS**: page, preview, download and `.imprimir` without `<script`, `<img`, `<a `, events or `</style>`; with canary texts, no header, `href`, `action` or `<style>` contains the canary. **W**: `a"b.json`, `ñ.json` in `$W/code/report-templates/` do not load; `tipo=../x`, `tipo=tecnico.json` open no file (404 / default page). **Amendment, WS**: with a template with a brand (with PNG and with JPEG), the `.html`'s `<style>` is exactly `download_css(p)[0]`; removing from the end, exactly once, the rule `.acento-marca{--al:<hex>;--an:<hex>}` (with `color`) and replacing the whole token `url(data:<mime>;base64,<b64>)` with `GEKKO_LOGO_URL`, what remains is byte for byte `DOWNLOAD_CSS + ACCENT_CSS` (with `color`) or `DOWNLOAD_CSS_BY_ACCENT[acento]` (without `color`): nothing else from the template reached the CSS, without substituting the hex across the whole text; the logo slug does not appear in headers, `href`, `action` or `<style>`; the parameters of the download links are `tipo`, `idioma`, `ledger`, `borrador`, `plantilla` and `logo`, and the last two match `[0-9a-f]{64}` | RPT-056, RPT-058 |
| AC7 | **L** + **WS**: ledger with the five statuses, a `confirmed` without corroboration and a canary `kb`; the two templates, `prueba` and «todo» (all sections, columns and fields): only ids from `included`, no KB in md/HTML/page; static case: `report_model` contains exactly one `included(rows)` call | RPT-056 |
| AC8 | **WS**: page CSP header equal with and without extra templates (and = the `CSS_HASH` formula); `.html`/`.imprimir` with their directives and the exact hash of their `<style>`; `len(CSS) ≤ 100000`. **L**: `inspect.getsource` of `validate_template`, `load_templates`, `report_model`, `render_report` (and WS of `report_body_for`, `report_html`) without `eval(`, `exec(`, `format_map`, `Template(`, `importlib`, `.format(`; load and draw with `socket.socket` patched to fail. **Amendment, WS**: from each page response (the usual directory, two templates with a brand, one with a rejected brand; `GET` and `POST …/borrador` response) what is served is extracted: exactly one `<style>`, byte for byte `CSS`; no `style=` attribute; CSP header byte for byte the same (comparing the `CSS`/`CSS_HASH` constants against each other cannot fail: they are computed at import); `.dmarca` present in `CSS` and absent from `DOWNLOAD_CSS`. **L**: `inspect.getsource` of `validate_image` and `strip_image_metadata` without `eval(`/`exec(`/`importlib`, without `decompress`/`decompressobj`, and without opening sockets | RPT-056, RPT-058 |
| AC9 | **L** + **WS**: `DOC[idioma]["notice"]` exact in md and HTML of every valid template; a template with `aviso` or `notice` is an AC5 rejection | RPT-055, RPT-056 |
| AC10 | **W**: for `tecnico`, `ejecutivo`, `prueba` × es/en: the six sha256 values of Provenance (template with the file's `sha256sum`, ledger, draft, `.md`, `.html`) = what was downloaded; rewriting `prueba.json` (valid, other text) between page and download → 409 without `Content-Disposition` | RPT-057, RPT-050 |
| AC11 | **W**: save in `prueba` → `borradores/prueba.json` only with its fields (a sent `metodologia` is ignored); a `tecnico` ticket used in `prueba` → 403; `tecnico.json`/`ejecutivo.json` drafts written in today's format are read and projected the same (sha256 of `.md` = that of 019); removing `prueba.json` leaves `borradores/prueba.json` intact (sha256) and when it returns the page shows it | RPT-048, RPT-057 |
| AC12 | `.githooks/test.sh` (two `pc_rt`) + **G** | — (hooks: §1 of the living spec) |
| AC13 | **L** `selftest`: table of images from `selftest_png`/`selftest_jpeg` against `validate_image` (accepted: minimal PNG and JPEG; rejected: SVG `<svg onload>` and HTML `<script>` named `.png`, `GIF89a`, `RIFF…WEBP`, `BM`, HTML + PNG signature, PNG + `\x00`, PNG + `PK\x03\x04…`, no `IEND`, `IDAT` before `IHDR`, CRC with one flipped bit, length that overflows, `acTL`, 2049×1; PNG with a 4000 B `pHYs` with `</title><script>LOGO-CANARY` and valid CRC, second `IHDR` 9000×9000, `gAMA` after `IDAT`, `tRNS` in color 6, `PLTE` in color 0; JPEG without `FFD8`, truncated segment, without `FFD9`, `FFD9` + bytes, 4 components, 1×2049, 60 000 B `DQT` with the canary, `DHT` whose sum does not add up, `FFF0` with HTML, double `SOI`, `FFFF` padding, 65 `SOS`, 3 components with `APP14` `Adobe` transform 0; 262 145 bytes), each with its reason; robustness: 2000 truncations and flipped bits (fixed seed) of the minimal PNG and JPEG → only a tuple or `Refusal`; cleaning: PNG with `tEXt`/`zTXt`/`iTXt` with `</title><script>LOGO-CANARY`, `eXIf`, `tIME` and a private chunk `prVt`, and JPEG with `COM` and `APP1` `Exif` with the canary → the clean one contains neither the canary nor those types, `validate_image(limpio)` passes, `strip(limpio) == limpio`, `IDAT`/scan data equal; and via `load_templates` the `Plantilla`'s logo is the clean one | RPT-058 |
| AC14 | **L**: `render_report` of `SELFTEST_MARCA` (with its own `autor`) = `render_report` of the same template without `marca` (es/en, with and without draft), and neither contains «gekko» (`casefold`). **WS**: `.html`/`.imprimir` of `SELFTEST_MARCA` without «gekko» outside `data:` URLs. **WS**: header with `aria-label`/`alt` = `esc(nombre)`, without «GEKKO · Offensive Security»; `<tfoot>` = classification · name · footer escaped, in es and en; name and footer with `<script>`, `"`, `&`, `</style>`, `<img src=x onerror=alert(1)>` come out escaped in page, preview, `.html` and `.imprimir`; no `content:` of the `<style>` contains the footer; without `pie`, `<tfoot>` = classification · name | RPT-058, RPT-056 |
| AC15 | **L**: `contrast_ratio` gives 4.478 for `#777777`, 4.542 for `#767676`, 1.296 for `#c0f425` (to ±0.001; the same values as the formula of the case at `findings_web.py:3899`); AC5 rows. **WS**: with `color`, `<main class="doc acento acento-marca">` and `.acento-marca{--al:#2b5d8c;--an:#2b5d8c}` in the `<style>` of `.html`/`.imprimir`; the preview carries `ACCENT_CLASS[acento]` and neither `acento-marca` nor the hex; without `color`, the downloads carry `ACCENT_CLASS[acento]` | RPT-058, RPT-052 |
| AC16 | **WS**: page with a template with a brand (`GET` and `POST …/borrador` response with `accion=previsualizar`): `re.findall(r"<img\b[^>]*>", page)` gives exactly one, and `re.fullmatch(r'<img class="dmarca" src="data:image/(png\|jpeg);base64,([A-Za-z0-9+/=]+)" alt="[^"<>]*">', tag)` matches the whole tag (an extra attribute, e.g. `onerror=`, does not pass), inside `.doc-head`, and its base64 decodes to `Plantilla.marca.limpio`; Markdown view without `<img`; the same page with `tipo=tecnico`, the workspace list, the detail and the rejections without `<img` (the RPT-007 cases, `findings_web.py:3710`, stay the same). **W** in AC18 | RPT-007, RPT-058 |
| AC17 | **WS**: two templates A and B with a brand (logos with different pixels, hex `#2B5D8C`/`#7A3E9D`) + built-ins: in the `.html`/`.imprimir` of A and in the `.doc-head` of its preview neither B's base64 nor that of `BRAND_PNG["horizontal-claro"]` is present; on A's page B's base64 is nowhere and Gekko's only inside the `<style>` (fixed CSS, AC8); A's color is checked by its rule `.acento-marca{--al:#2b5d8c;--an:#2b5d8c}` in A's `<style>`, not by the absence of B's hex; `re.findall(r"url\(([^)]*)\)", html_A)` gives one, A's; same for B; `tecnico.html` gives one, Gekko's (case at `:4224` unchanged), without bytes of A or B; A's Provenance with `Logo SHA-256` = sha256 of the file; download with an old `logo=` → 409 without a file; B's broken `logo` → B in a warning, A and the built-ins with the same output sha256 | RPT-058, RPT-057 |
| AC18 | **W** `tools/report-test.sh` (over T11's copy): checks of spec AC18 | RPT-058 |

## 5. New and rewritten `REQ`
**New:**
- **REQ-RPT-055 — Templates: strict loading and validation.** Regular file with no link, ≤ 16 KiB, slug name,
  JSON with no repeated keys or constants, vocabulary and limits of §2.2–2.4, palette; whole-file rejection with an error in
  Spanish that names file and key; the others continue; a missing or invalid built-in is warned about and not
  replaced; cap of 16; the unconfirmed-findings notice is not a key. Limit: a template's text may be
  false (spec §6); in `os` mode the model can edit it (sha256 in Provenance, `git diff`).
- **REQ-RPT-056 — No template changes the invariants.** Only `included`, never the KB, same `_code`/`_fence`/`esc`,
  fixed notice, template texts without markup (charset) or in a span, fixed page CSP and CSS, no template
  text in a URL, header, file name, selector or CSS property (the file's slug name does travel, and
  it is the identifier, not a value), no `eval`/sockets. Limit: choosing `evidence.output` in a format «for
  executives» is legal (REQ-RPT-023).
- **REQ-RPT-057 — Adding a format is adding a file.** The page lists the valid ones (built-ins first,
  Técnico by default), downloads `<ws>-reporte-<nombre>-<idioma>.<ext>`, `render --tipo <nombre>` = web,
  Provenance with the template's sha256 and 409 if it changed (when the link carries it), draft per template.
  Limit: a link without `plantilla=` takes the current template (P1, accepted by the operator).
- **REQ-RPT-058 — Per-template brand** (amendment 2026-11-17; free id: spec 023 does not reserve ids yet). A template
  with `marca` MUST name its logo by slug in `report-templates/marcas/`, read without links (file and folder), ≤
  256 KiB and ≤ 2048 px per side, PNG or JPEG validated by content (`validate_image`) and cleaned of metadata by allowlist
  (`strip_image_metadata`), each retained chunk or segment with the standard's length, count and position and
  with no markers outside the list, without decompressing, and the clean copy MUST validate again; only that copy MUST
  reach an output; every analysis failure MUST be a rejection of that template (`Refusal`). The
  name MUST replace «GEKKO · Offensive Security» as alternative text and enter the printed footer with its own
  footer, escaped; with `marca`, the default `autor` MUST NOT contain «gekko»; `marca.color` MUST be `#RRGGBB` with contrast ≥ 4.5:1 on white and paint only `.html` and
  `.imprimir` in `.acento-marca`; only the base64 of the clean bytes and the normalized hex MUST reach the downloads' CSS,
  with a per-document hash; the page MUST show the logo only as a `<img class="dmarca"
  src="data:image/png|jpeg;base64,…" alt="…">` in the preview, with page CSP and CSS unchanged; a template's logo,
  name, footer and color MUST NOT appear in another; without `marca`, today's Gekko brand; the
  `.md` carries no logo or `BRAND_LINE`. Provenance shows the logo's sha256 and a download with a different `logo=` MUST give 409.
  Limit: the validator is structural, it does not look at pixels: arbitrary bytes inside `IDAT` or the scan data
  come out as the base64 of an image, inert; a logo can impersonate another company (`git diff`, sha256 in
  Provenance); the brand belongs to the issuer and never to the client (codename, `engagement-authorization.md` §2), which the
  code cannot check.

**Rewritten** (replace «tipo» with «plantilla» and name the built-ins as files):
| REQ | Change |
|---|---|
| RPT-045 | the selector lists the loaded valid templates; unknown → default; `REPORT_TYPES` leaves the «Code» |
| RPT-046, RPT-047 | Técnico and Ejecutivo are `tecnico.json`/`ejecutivo.json`; their output is byte for byte that of the pre-engine base (`66a7506`; AC1 case, captured in T1); the old «Code» is corrected (`executive_body` does not exist) |
| RPT-048 | `borradores/<nombre>.json` with that template's fields; a name outside the list → 400 without opening |
| RPT-049 | `render --tipo <nombre>`; without `choices` |
| RPT-050 | parameter `plantilla` and its 409; unknown `tipo` on download → 404 |
| RPT-051 | template texts enter the list of what does not forge markup; the «Code» is corrected (`draft_head_html` does not exist) |
| RPT-052 | the accent class and the two variants of the signed download CSS; (amendment) with `marca`, the download CSS is generated per template (`download_css`) with the own logo as its only `data:` URL and `.acento-marca`, and its hash is computed per document; «a single `data:` URL, equal to the kit's PNG» remains for templates without a brand |
| RPT-055 | (amendment) `marca` is the only optional key; its keys, the logo slug, the `marcas/` folder without a link and the hex with contrast enter the validation; the rejection names `marca.<clave>` |
| RPT-056 | (amendment) the sole exceptions of AC6: (i) base64 of the clean logo and validated hex only in the downloads' CSS; (ii) the `data:` `src` of the preview's `<img class="dmarca">`; and in URLs, besides the slug, the module's hexadecimal sha256 values (`plantilla=`, `logo=`); served page CSP and `<style>` identical with and without branded templates |
| RPT-023 | (amendment) «the only URL in the CSS is the `data:image/png` logo of REQ-RPT-052» → «… Gekko's logo or, with `marca`, the template's (`data:image/png` or `image/jpeg`, REQ-RPT-058)» |
| RPT-021…024 | «tipo» → «plantilla»; RPT-023: the `<title>` is the document's title (draft or template value), not «fixed per type» (it already was so since UI-r3) |
| LED-002 | `render --tipo` takes a template from the directory |
| RPT-007 | the page CSS gains `ACCENT_CSS` and the fixed `.dmarca` rule; the header remains the `CSS_HASH` formula; (amendment) «no response contains `<img`» becomes «no response contains `<img` except, in the preview of the report page with a template with a brand, exactly one with the form `<img class="dmarca" src="data:image/(png\|jpeg);base64,…" alt="…">` generated by the module from the clean bytes (REQ-RPT-058)»; no `<img` comes from the ledger, the draft or a template text. Spec 023 (which cites RPT-007's prohibition) must start from this text |
| §1 (hook paragraph, living spec ~l. 1606) | `pre-commit` runs `tools/report-test.sh` also when touching `.claude/tools/report-templates/` |

## 6. Decisions (answers the spec §6 «For `plan.md`»)
- **Shape and vocabulary:** §2.1–2.2. Técnico and Ejecutivo are two combinations of the same vocabulary; the prototype
  checked it against today's code (72 cases, 0 differences).
- **Limits:** §2.3.
- **Charset, not escape:** §2.4. AC1 comes free (today's texts pass) and AC6 is met by construction.
- **Palette and contrast:** §2.6; ten names; the strong ones color text, the light ones only lines and bands.
- **No cache:** one snapshot per request. Reasons: the cost is negligible (§2.3); an mtime cache opens a window
  between the displayed sha256 and the bytes used, and an import-time cache would require a restart to see a new file
  (AC3: «appears on the page», without touching code). For that reason templates are not in `CODE_FILES`
  either (`findings_web.py:33`): adding one is not «code changed».
- **AC1 capture before the engine:** T1, first change on the branch (§8).
- **Template sha256 in Provenance and 409:** §2.6, «Page» and «Downloads».
- **Draft per template:** §2.6, «Drafts»; the ticket does not change.
- **D5 — confirmed (a).** A single loading path; if a built-in breaks or is deleted, the page says so and
  serves no other (fails closed). Accepted cost: the model in `os` mode can delete `tecnico.json` and leave without a
  report (denial without data loss, like a planted draft in REQ-RPT-050).
- **D6 — confirmed (a).** The boundary is the validator and the engine. A consequence worth knowing: changing the
  text of a built-in breaks the AC1 baseline, which lives in `findings_web.py` (boundary), so editing
  `tecnico.json` requires touching code and spec; adding a new template does not. A logo in `marcas/` does not enter §1 either:
  it is a template's data and `validate_image` validates it, which is boundary.
- **D4 — (c), amendment 2026-11-17:** §2.8. **D3 extended:** own hex only in downloads, §2.8.

## 7. Risks and mitigation
- **Equivalence fails at an edge** (presence of fields, `dash` vs `esc`, `?` vs `—`) → each piece keeps its current
  code (§2.5); prototype with edge rows; AC1 with 32 sha256 values is the falsifier and runs on every commit.
- **`report_fields(keys=)` touches a REQ-LED-002 function** → `keys=None` is today's path; the LED-002 cases
  run before and after without touching them.
- **The page CSP header changes once** (the CSS gains `ACCENT_CSS`) → accepted by the operator (P2, AC8
  amended). The existing case (`findings_web.py:3639`) compares against the formula and stays green.
- **CSS budget**: the palette costs 521 B and leaves 3 076 B under the cap; spec 023 competes for that margin → the
  100 000 case watches it and §2.6 says what to cut (the fonts, not the palette).
- **A light tone misused as text** (e.g. someone colors `.num` with a light tone's `--al`) → the WS case measures
  each pair against the threshold of its use: line ≥ 3:1, number and band ≥ 4.5:1.
- **Template directory swapped for a link** (e.g. to `engagements/<ws>/`, against D2) → `lstat` of the
  directory; case in AC5.
- **Removing a field from a template leaves a draft with that field** → `validate_draft` marks it invalid: warning and
  409 on downloads (REQ-RPT-050), without losing the file; documented in `docs/pi-hitl.md`.
- **A built-in edited in `os` mode is served with no runtime warning** (AC1 only fails at commit)
  → Provenance shows its sha256 and `git status` gives it away; an alarm with a sha256 pinned in the code is out of scope (P3: no).
- **Other sessions in the same worktree** (spec 023 is being drafted in parallel and will touch `findings_web.py`) → T0 requires a clean
  tree in `findings.py`/`findings_web.py`, relocates citations and re-measures the CSS; the AC1 baseline is
  captured on the `HEAD` of that moment; if 023 merges first, its CSS enters the count.
- **`--tipo` without `choices`** changes the CLI help → the error lists the valid ones; the case «unknown tipo exits ≠ 0»
  (`findings.py:1358-1362`) stays the same.
- **Brand (amendment 2026-11-17):**
  - *Download size.* A 256 KiB logo puts ~350 KB of base64 in the `.html`, in `.imprimir` and in the page's
    preview; the byte cap bounds it and the AC13 case with 262 145 bytes watches it. The `.html` sha256 in Provenance forces
    generating it on every page request (today it is already generated, `:2371`): ~1 ms more.
  - *Incorrect cleaning.* A badly done walk could leave a text chunk or segment, or cut the image →
    allowlist (PNG) and walk of the whole file (JPEG); the clean copy validates again on load; L fixes
    idempotence, absence of the canary and intact `IDAT`/scans, with one case for each chunk/segment of the list.
    What cannot be cleaned without re-encoding (bytes inside `IDAT` or the scan) is inert inside an image `data:` and
    remains as a limit of REQ-RPT-058.
  - *JPEG colors.* Removing `APP14` (Adobe) would change how the browser reads a 3-component JPEG with
    transform 0 (RGB) → that case is rejected on load (deterministic, AC13 row); CMYK too.
  - *An analyzer exception takes the page down.* `load_templates` only catches `Refusal` in validation → the
    validator turns every failure into `Refusal`, the logo step additionally catches `OSError`/`ValueError`, and the AC13
    robustness case (2000 broken inputs) pins it.
  - *Page CSS budget: unaffected.* The logo and the hex never enter `CSS`; the amendment only adds the fixed
    77 B of `.dmarca` (96 933 B measured in T8 → ~97 010; ~2 990 remain under the cap) and the CSP header changes
    once, before merging. The downloads' CSS has no cap (it is not the page's).
  - *`<img>` on the page.* First `<img` that REQ-RPT-007 admits → a single exact form, generated by the module,
    `src` only `data:` of validated bytes (and the CSP only admits `data:` in `img-src`); the case looks for it with an
    exact expression and counts exactly one.
  - *Client's logo in the repo.* The code cannot know whose a logo is → `spec.md` §4 Out of scope, REQ-RPT-058
    Limit and `docs/pi-hitl.md`: the brand belongs to the issuer; fictional test names and logos.
  - *Spec 023 depends on the validator.* If 023 is implemented before 021 merges, `validate_image` has to exist
    with this signature → T12b leaves it first, with its cases, and 023 imports it without copying it.

## 8. Order of attack
1. **T0 (no code):** clean tree in the two `.py` files; relocate citations from `66a7506`; measure CSS;
   run L, WS, W and G green as the gates baseline.
2. **T1 — AC1 baseline (the first thing that changes on the branch).** With `HEAD`'s engine untouched, add to
   `selftest_reports` the «021-AC1» case with its fixture and an empty literals dict; run WS, which fails and prints
   the 32 sha256 values; paste them as literals; WS green **on the old code**. Commit only that
   (`GEKKO_SPEC_UNCHANGED=1`: it does not change behavior) and note its hash in `tasks.md`. The case uses
   `REQ-RPT-046`/`-047`, which already exist, so the G trace stays green.
3. **T2:** `tecnico.json`, `ejecutivo.json`; `validate_template`/`load_templates` with the AC5 table red first
   (L), then green.
4. **T3:** engine in `findings.py` (`report_fields(keys=)`, `report_model`, `render_report`, `_md_short`,
   `validate_draft`, `DOC`, CLI); L green and the 16 `.md` sha256 values of AC1 green before continuing.
5. **T4:** web renderers, palette and CSS variants; the 16 `.html` sha256 values of AC1 green; CSS ≤ 100 000.
6. **T5:** `report_route`, downloads, drafts, Provenance; WS cases for AC5–AC9 and AC11.
7. **T6:** `tools/report-test.sh` (AC3, AC4, AC5, AC10, AC11); hooks (AC12).
7b. **Brand (amendment, `tasks.md` T12a–T12i, between T12 and T13):** REQ-RPT-058 in the living spec; `validate_image` and
   `strip_image_metadata` with their table red first; `marca` in the validator and the loader; header, footer, per-template CSS
   and preview in the web; isolation; W checks.
8. **T7:** living spec (§5), `docs/pi-hitl.md`; L, WS, W, G and `.githooks/test.sh` together; `code-auditor`; real run
   by the operator (spec §7); commit; `Estado` → `IMPLEMENTADA`.

## 9. Operator answers (2026-11-17)
- **P1 — Download link without `plantilla=`: yes, accepted with the current template.** The 017/019 links and
  the checks of `tools/report-test.sh:51-54, 274` do not change (AC2); the page always sends `plantilla=`, so
  the page → download flow stays bound (AC10).
- **P2 — AC8: yes.** The pages' CSP hash changes once because of `ACCENT_CSS` and afterwards is fixed with and without
  extra templates. `spec.md` amended (AC8, and AC6: the validated slug is the identifier that reaches the URL, file
  name and header).
- **P3 — Runtime alarm for the built-ins: no.** AC1 at commit time + sha256 in Provenance.
- **P4 — Palette: yes, more light tones.** Five honest light ones (line only ≥ 3:1 and band with dark text ≥ 4.5:1),
  table and budget in §2.6.
