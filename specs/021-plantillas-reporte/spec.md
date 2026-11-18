# Spec 021 — Configurable report templates

> Status: `IMPLEMENTADA` (2026-11-18) · before `APROBADA` (operator, 2026-11-17: D1, D2, D3 and D7 in (a); D4 in (a), replaced by (c) in the brand amendment; for now only the two templates of today,
> built so that others can be added easily when there is a format the operator likes; D5 and D6 keep their recommendation (a)
> unless `plan.md` finds a reason to change it)
> Amendment (operator, 2026-11-17, answers to the plan): AC6 clarifies that the validated slug is the identifier that reaches
> the URL, file name and header; AC8 accepts that the hash of the pages' CSP changes once because of the palette;
> D3 adds light tones (only in lines, ≥ 3:1, and bands with dark text, ≥ 4.5:1; table in `plan.md` §2.6).
> **AMENDED 2026-11-17 (brand per template, operator's decision; amendment APPROVED by the operator the same day, with Gekko's `autor` rejected in a template with `marca`)**, with T0–T12 done (`3c5935b`, `2938e0a`): D4 moves from
> (a) to (c) — own logo PNG/JPEG, company name and own footer per template — and D3 is extended with an own hex
> only for the downloads; AC5, AC6 and AC8 are amended, and AC13–AC18 are added (design in `plan.md` §2.8; tasks
> T12a–T12i between T12 and T13). A template without `marca` comes out with the Gekko brand as today (AC1 intact).
> Date: 2026-11-17 · Design source: proposal approved by the operator (2026-11-17): one template per data file, a single engine, no free template language. Branch: `report-module`. It builds on
> [`019`](../019-reportes-ui-v3/spec.md) (Technical/Executive types, drafts, UI-r3 cover, print view
> `.imprimir` of REQ-RPT-024: the PDF is made by the browser). **Loosens the boundary**: a new data file decides
> what goes out in the deliverable; it takes the long flow, like 016 and 019.

## 1. Problem (one sentence)
The report format is written in Python in several places — texts and default values in `DOC`
(`findings.py:932`), labels in `LABELS` (`findings.py:785`), sections and order in `report_model`
(`findings.py:962`), draft fields in `DRAFT_FIELDS` (`findings.py:894`), look in `DOC_CSS`
(`findings_web.py:371`) and the fixed list `REPORT_TYPES` (`findings_web.py:2080`) — so a new format requires touching boundary code in the two files.

## 2. Goal (one sentence)
Each report format is a data file in the repo that only chooses among known texts, sections and fields;
a single engine reads it and produces Markdown and HTML (and its print view, from which the browser gets the PDF) with the same guarantees as today; adding a format is adding a
file, and the report page lists the valid templates it finds.

## 3. Context / why now
Read in the code (`report-module`, `86309eb`):
- `report_model` already separates «what is shown» (cover, notice, numbered sections with `prose`, `tiles` and
  `findings: full|table`) from the renderers (`render_report`, `report_body_for`/`report_html`): the engine
  exists half-way; what is missing is that the list of sections and the texts come from data and not from an `if tipo ==`.
- The fields of a finding that the report knows are those of `report_fields` (`summary`, `impact`, `remediation`,
  `cvss`, `cvss_vector`, `cvss_justification`, `cwe`, `cve`, `corroboration`, `blocker`, `command`, `artifact`,
  `evidence.output`, `repro`) plus `id`, `title`, `severity`, `status`, `target`. `kb` is out on purpose
  (REQ-LED-002, case `KB-CANARY`); comments too (019 D3).
- `tipo` already travels validated against `DRAFT_FIELDS` on the page, the download, the draft `POST`, its HMAC token, the
  name of the file `borradores/<tipo>.json` and `findings.py render --tipo` (REQ-RPT-045, -048, -049, -050).
- In the report there are texts that today are constants and come out **without span or fence** in the `.md`: the subtitle, the notice
  (`> …`) and the section titles (`## 01 …`) (`findings.py:991-995`). When they become template data they become untrusted input.
- The pages' CSP is static (`CSS_HASH` of a fixed CSS, `findings_web.py:580`); the downloadable HTML signs its
  own `<style>` (`report_html`). A free color in a template would change the page's signed CSS.
- Today's brand (read in `2938e0a` for the amendment): the logo is a kit PNG in `BRAND_PNG`
  (`findings_web.py:340`) put as background of `.dlogo` in `DOC_CSS` (`:375`), which share the page's CSS (`:586`) and `DOWNLOAD_CSS` (`:2284`, variants and hashes per accent `:2285-2292`); the header is
  `<span class="dlogo" role="img" aria-label="{BRAND_LINE}">` (`:2236`, `BRAND_LINE` in `:2107`); the printed footer is
  `<tfoot class="print-foot">` with only the classification (`:2303`) and the page number comes from `@page` in `PRINT_CSS`
  (`:2271`). The page's CSS goes whole in a `<style>` of each response (`:688`), so the base64 of Gekko's logo is in every page. The `.md` carries no logo nor `BRAND_LINE` (`render_report`, `findings.py:1211-1216`); the
  only mention of Gekko in the `.md` and in the HTML cover is the default value of `autor`, «GEKKO Offensive
  Security» (`tecnico.json:8,13`, `ejecutivo.json:7,12`; case `findings.py:1749`), which is template text. The page's CSP already carries `img-src data:` (`:601`) and REQ-RPT-007 today prohibits any `<img` (case `findings_web.py:3710`).
- The model writes repo files with the same user in `os` mode; in `toolbox` mode `.claude/tools/` is mounted
  read-only in the container. Templates in the repo are versioned and visible in `git diff`.

## 4. Scope
**In:**
- One template per file `.claude/tools/report-templates/<nombre>.json` (name = file slug). It may define,
  and only that: visible label on the page; texts and default values in `es` and `en` (those of `DOC`: eyebrow,
  subtitle, title, client, author, period, version, classification, cover labels, section titles and those of the
  count cards); which draft fields it offers (subset of today's eleven); the ordered list of sections
  from a closed vocabulary (prose of a draft field, severity count cards, full findings,
  findings table with chosen columns, short card per finding); which finding fields enter each section
  (only from the list in §3); accent color (D3); whether the count cards appear; and, optional, a **brand** (D4 c):
  company name, own logo and es/en footer, plus an own `#RRGGBB` color for the downloads.
- **Brand per template** (amendment 2026-11-17). The logo is a PNG or JPEG saved in the repo next to the templates,
  `.claude/tools/report-templates/marcas/<slug>.png|.jpg`; the template names it only by slug, never by path. It is validated by **content** (PNG: signature, `IHDR` first, CRC of each chunk, `IEND` last and nothing after; JPEG: `SOI`,
  well-formed segments, `EOI` at the end and nothing after; allow-list of chunks and markers, each with the length and
  position from the standard), with a byte and side cap, regular file with no link; its metadata is
  removed structurally (standard library, no re-encoding) and the clean copy is validated again; it is the validator that [`023`](../023-capturas-evidencia/spec.md) will reuse. It comes out in the cover header (`.doc-head`, where Gekko's brand is today). The company name replaces «GEKKO · Offensive
  Security» (`BRAND_LINE`) as the logo's alt text and enters the printed footer (the default `autor` is template
  text: with `marca` it cannot remain Gekko's, AC5); the own footer (es/en) comes out on
  each printed page next to the page number. The own color paints lines and section numbers only in `.html` and
  `.imprimir`; the preview uses the palette accent that the template keeps naming.
- The page's preview shows the logo of a branded template as **one** `<img>` generated by the module
  with `src="data:image/png|jpeg;base64,…"` of the clean bytes; the CSP and the page's CSS do not change because of it.
- Only two templates in the repo: `tecnico.json` and `ejecutivo.json`, which reproduce today's output. A third one
  exists only as test data in a temporary root of the selftest, to show that adding a format is adding
  a file (operator: «por ahora solo deja 2 plantillas» — "for now just leave 2 templates").
- A single engine: `report_model` reads the template; `render_report` and `report_body_for`/`report_html` (and therefore
  `.imprimir`) draw what the model says. `validate_draft`, `draft_form`, `report_route`, `post_draft` and `cmd_render` take the list
  of valid templates instead of `DRAFT_FIELDS`/`REPORT_TYPES`.
- Strict validation on load: unknown key, section or field, wrong types, texts beyond the cap or with
  disallowed characters, non-regular file, link or too large → the template is rejected whole with an
  error naming file and key; the others keep working.
- The page's «Procedencia» (provenance) shows name and sha256 of the template used; the downloads are also bound to that
  sha256 (as to the ledger and the draft, REQ-RPT-050).
- Reconciliation on merge: REQ-LED-002, REQ-RPT-007, -021, -022, -023, -024, -045 … -052; new `REQ`s for template loading and
  validation and the invariants of §5 (block E), and REQ-RPT-058 for the per-template brand (block F).

**Out (explicit, anti scope-creep):**
- HTML, CSS or free template language (Jinja, `str.format`, expressions, conditionals, loops): it opens an injection path into the deliverable and forces a CSP change.
- Templates inside the workspace (D2), editing templates from the web (not trivial: writing to the repo from the module is another surface), a PDF generated on the server (the browser does it, REQ-RPT-024).
- Brand: SVG, GIF, WebP or other formats; re-encoding, resizing or decoding the image (PIL or similar); uploading or
  choosing a logo from the web; logos in the workspace (D2); logo in the `.md`; logo inside the page's CSS; a
  «similar» color from the palette for the own hex; more than one logo per template. **The brand is that of the report's issuer (the operator's company), never the client's**: the client's name or logo would go into a committed file and break the codename of `.claude/rules/engagement-authorization.md` §2.
- Changing `render_md` (`findings.py render` without `--tipo`): it remains the projection of REQ-LED-002, with no template.
- Changing the inclusion rule (`included`), the severity order, the field labels of `LABELS`, Gekko's brand in templates without `marca` (and in the bar and the module's pages), the languages (only `es`/`en`) or the UI outside the report format selector.
- Translating the content of findings or of the draft.
- More templates in the repo than today's two (they are added when the operator has a format they like).

## 5. Acceptance criteria (testable)
> Tests: **L** = `python3 .claude/tools/findings.py selftest`. **WS** = `python3 .claude/tools/findings_web.py selftest`.
> **W** = `bash tools/report-test.sh` (L + WS + real HTTP over a temporary root). **G** = the gate
> `GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts` (`REQ ↔ case` trace). «Hostile» =
> the `HOSTILE` values of 012's selftest plus `` ` ``, `|`, `## `, `](http://x)`, `![a](http://x)`, `</style>`,
> `<script>`, `x) Tj ET BT /F1 99 Tf (y\`, line breaks, U+2028 and controls. Fictitious data and templates in temporary roots; no case reads real `engagements/`.

| # | Criterion (observable) | Test |
|---|---|---|
| **A · Regression** | | |
| AC1 | The two templates reproduce today's output **byte for byte**: for a fixed set of rows (with and without included, with `cvss_vector`, evidence, steps and hostiles) × `tecnico`/`ejecutivo` × `es`/`en` × without draft / with full draft, the sha256 of `render_report` and `report_html` (= `.imprimir`) is equal to the one captured from the code before the engine (sha256 fixed in the selftest before refactoring). | L + WS |
| AC2 | The existing cases of REQ-LED-002, REQ-RPT-021 … -024 and -045 … -052 stay green without changing their text except where the reconciliation replaces «tipo» with «plantilla» (template). | W + G |
| **B · Adding a format is adding a file** | | |
| AC3 | A test template (only in a temporary root of the selftest; not published in the repo) copied to the templates directory, without touching code, appears on the page after Técnico and Ejecutivo, is downloaded (`.md`, `.html`, `.imprimir`) in both languages with name `<ws>-reporte-<nombre>-<idioma>.<ext>`, and `findings.py render --tipo <nombre>` gives byte for byte the `.md` of the web. Técnico remains the default value. | W |
| AC4 | The vocabulary is enough for formats other than today's two: the test template changes texts and default values (es/en), the order and selection of sections, the finding fields of each section (e.g. only remediation, no evidence: the canaries of `evidence.*`, `repro` and `corroboration` do not come out), the palette color and the count cards, and each change is seen in the output. | L + W |
| **C · Invalid templates** | | |
| AC5 | A table of invalid templates — broken JSON, unknown key/section/field (incl. `kb`, `comentarios`, `__class__`), language other than `es`/`en`, text beyond cap or charset, color outside the palette, name that is not a slug, file over the cap, link, FIFO, directory; and in `marca`
(amendment 2026-11-17): unknown or missing key, wrong type in each key (`"marca": []`, `"logo": null`,
`"logo": ""`, `"color": 123`, `"pie": "x"`), `marca.logo` `../x`, `/etc/x`, `x/y`, `ñ`, `A` or with extension,
logo missing or present at once as `.png` and `.jpg`, logo link (also to a file outside the repo), FIFO or
directory, `marcas/` folder that is a link, logo over the byte or side cap, the content rejections of AC13,
`marca.color` `red`, `#fff`, `#12345g`, `#000000;}body{`, `#000000` + line break and a valid hex with contrast
< 4.5:1 over white (the error says the measured contrast, truncated to two decimals: `#777777` → «4,47:1»),
`marca.nombre`/`marca.pie` empty, over the «line» cap (121 characters), with a break, U+2028 or a control, and a template with `marca` whose `textos.es.autor` or `textos.en.autor` contains «GEKKO» (case-insensitive) — is rejected whole with an error in Spanish naming file and key, never half-corrected. The page names it in a notice and does not offer it; the others give the same sha256 as without it. `tipo=<inválida>` (invalid): the page falls back to the default value; download and `POST …/borrador` give 4xx without writing; the CLI exits ≠ 0. If one of the two repo templates is missing or invalid, the page says so and does not invent another. | L + W |
| **D · Invariants no template changes** | | |
| AC6 | **Hostile content**: the hostile values in each text that the validator accepts come out as text in `.md` (without forged heading, quote, table, link or image; REQ-RPT-051 proof) and in the HTML of the page, the preview, the download and `.imprimir` (without `<script`, `<img`, `<a`, events or `</style>`; the only `<img` admitted
is the logo's in the preview of a template with brand, with the exact form of AC16). No value from inside a template reaches a URL, a file name, a header, a selector or a CSS property; the only things that reach the URL, the download name, `Content-Disposition` and `borradores/<nombre>.json` are the file name, validated as slug, which is the template's identifier and not a value, and the hexadecimal sha256 values computed by the module (`plantilla=`, `logo=`); no template text. A hostile file name (`../x.json`, `a"b.json`, unicode) does not load. **Single exceptions (brand, amendment 2026-11-17):** (i) to the CSS of `.html`/`.imprimir` — never
to the page's — of a template with `marca` only two things derived from it arrive: the base64 of the logo's bytes, already validated and clean (AC13), inside `url(data:image/png|jpeg;base64,…)` with the type detected by content and not written in the template, and the hex of `marca.color` validated and normalized to `#rrggbb` (AC15), as the value of a fixed class; (ii) the `src="data:image/(png|jpeg);base64,…"` of the `<img class="dmarca">` of AC16, from those same bytes and with the same detected type. The logo's slug does not reach any URL, header, file name or CSS. | L + WS + W |
| AC7 | **Only confirmed, never the KB, same escape**: with a ledger that has all statuses, a `confirmed` without corroboration and `kb` canary, no template — both the test one and a hostile one that asks for all sections and fields — shows any id other than those of `included` nor the KB in any format; there is no key that activates `show_all` or filters by status. The values of the ledger and of the draft come out through the same `_code`/`_fence`/`esc` as today. | L + WS |
| AC8 | **CSP and execution**: the CSP header of the pages is fixed: its hash changes only once with this spec (the signed CSS gains the precomputed palette classes, D3, and the fixed rule `.dmarca` of AC16) and afterwards is byte for byte
the same, as is the page's CSS, with and without extra templates **and with and without branded templates** (the logo and the own hex never enter the page's CSS; it is measured over what is served: each page response carries exactly one
`<style>`, byte for byte `CSS`, and no `style=` attribute); the `.html` and `.imprimir` keep their directives and their hash covers only
their `<style>` (in a template with brand, the `<style>` generated for that template and its hash computed per document);
the page's CSS remains ≤ 100 000 bytes. Loading and rendering a template opens no sockets and evaluates no text (static proof: `json.loads` and fixed lists; no `eval`, `exec`, `format_map`, `Template`, `importlib`; and the image validator does not decompress: no `decompress`/`decompressobj`, `zlib` only for `crc32`). | L + WS |
| AC9 | **Mandatory notice (D1)**: the notice about unconfirmed findings is in every template and format with the text from the code; a template that tries to remove or rewrite it is an AC5 rejection. | L + WS |
| AC10 | **Page = download**: for every valid template and both languages, the sha256 of «Procedencia» (template, ledger, draft, `.md`, `.html`) match what is downloaded; if the template changed between showing and downloading, the download gives 409 without a file. | W |
| **E · Selection and draft** | | |
| AC11 | The chosen template keeps its draft: `borradores/<nombre>.json` (rules of REQ-RPT-048) only with the fields that template offers, HMAC token bound to workspace and template, no new status (D7). The existing `tecnico.json`/`ejecutivo.json` drafts are read the same as today. `tipo` is valid only if it names a valid loaded template (page, download, `POST`, CLI); a name outside the list never opens a file with that text. A removed template leaves its draft intact, and it reappears when it returns. | W |
| **F · Brand per template (amendment 2026-11-17, D4 c)** | | |
| AC13 | **Logo: validate by content and clean.** `validate_image` accepts a minimal valid PNG and JPEG and rejects, each with a reason in Spanish that `load_templates` turns into an AC5 error (file + `marca.logo`): SVG and HTML renamed `.png`; GIF, WebP and BMP; HTML before the PNG signature; PNG with a byte or a ZIP behind `IEND`, without `IEND`, with `IHDR` that is not the first, with an altered CRC, with a chunk that runs past the file, animated (`acTL`) or with a side over the cap, with a chunk
kept outside its standard length (`pHYs` of 4000 B with canary HTML and valid CRC), repeated (second `IHDR`) or
out of place (`gAMA` after `IDAT`, `tRNS` in color 6); JPEG without `SOI`, with a truncated segment, without a final `EOI`, with
bytes behind `EOI`, CMYK or with a side over the cap, with a `DQT` or `DHT` whose content does not add up to its length (a `DQT`
of 60 000 B with canary HTML), with a marker outside the list (`FFF0`, `DAC`, a second `SOI`, `FFFF` padding), with
more than 64 `SOS`, or of 3 components with Adobe `APP14` with transform 0 (RGB without YCbCr); extension that does not match the content; file over the byte cap. **Cleaning:** a PNG with HTML in `tEXt`/`zTXt`/`iTXt`, `eXIf` and `tIME` and a JPEG with HTML in `COM` and `APP1` (Exif) are accepted, and the copy that comes out (page, `.html`, `.imprimir`) does not contain the HTML marker nor those chunks/segments in the decoded base64; the clean copy validates again and cleaning it again does not change a byte; the pixel image (`IDAT`, data after `SOS`) is the same. **Robustness:** 2000 truncations and flipped bits (fixed seed) of the minimal PNG and JPEG: `validate_image` only returns its tuple or raises `Refusal`, never another exception. The `.md` carries no logo. | L |
| AC14 | **Name and footer.** With `marca`, the logo's alt text (cover header, preview and downloads) is `marca.nombre` instead of «GEKKO · Offensive Security», and the printed footer (`<tfoot>` of `.html`/`.imprimir`, repeated on each page next to the number) is classification · name · `marca.pie[idioma]`, as escaped HTML text, never by CSS `content:`; with hostile values (`<script>`, `"`, `&`, `</style>`, `<img src=x onerror=…>`) in name and footer they come out as text (AC6). Without `marca`, header, footer and bytes are today's (AC1; `tecnico.json`/`ejecutivo.json` remain without brand). The `.md` of a template with brand is byte for byte that of that same template without `marca`: the `.md` carries no logo nor `BRAND_LINE`, and its only brand text is the template's `autor`, which with `marca` cannot be Gekko's (AC5); `SELFTEST_MARCA` defines its own `autor`, and neither its `.md` nor its `.html`/`.imprimir` (outside the `data:` URLs) contain «gekko» case-insensitively. | L + WS |
| AC15 | **Own color.** `marca.color` is valid only with `^#[0-9a-fA-F]{6}\Z`, is normalized to lowercase, and is rejected on load if its contrast over `#fff` is < 4.5:1 (it colors text: the section number), with the measured contrast in the error, truncated to two decimals (e.g. `#777777` «4,47:1», `#c0f425` «1,29:1»); `#767676` (4.54:1) passes. Only `.html` and `.imprimir` use it, for lines and section numbers (`.acento-marca`); the strip of the tables stays today's. The template keeps naming a palette `acento` (accent), which is the one the preview uses (no search for the «nearest» color); without `marca.color` the downloads use that accent. | L + WS |
| AC16 | **Preview with logo.** The report page with a branded template (the `GET` and the response of `POST …/borrador`, which redraws it) carries exactly one `<img>`, in `.doc-head` of the preview, and that tag matches **entirely** (`re.fullmatch`) `<img class="dmarca" src="data:image/(png\|jpeg);base64,[A-Za-z0-9+/=]+" alt="[^"<>]*">`, where the base64 decodes to the clean bytes of AC13 and `alt` is the escaped name; no other response (nor the same page with an unbranded template) carries `<img`. The CSP header and the page's CSS are byte for byte those of the page without branded templates (`img-src data:` is already there; the `.dmarca` rule is fixed, AC8); the Markdown view carries no logo. | WS + W |
| AC17 | **Isolation between templates.** With two branded templates A and B (different logos, names, footers and colors) and the built-in ones: the preview (the `.doc-head` fragment), `.html` and `.imprimir` of A carry only A's logo, name, footer and color (in `.html`/`.imprimir` neither B's base64 nor Gekko's logo appears, they have a single `data:` URL, its own, and A's color is seen in its `.acento-marca` rule; on the page, the fixed CSS still brings Gekko's logo per AC8, so it is tested that B's base64 does not appear anywhere in the response, that outside the `<style>` Gekko's is not present, and that the preview's `<img>` is A's), and vice versa; those of `tecnico` carry only Gekko's brand (one `data:` URL, today's) and no byte of A nor B. «Procedencia» also shows the logo used and its sha256 (= `sha256sum` of the file in `marcas/`, of the same bytes read once in that snapshot); changing the logo between showing and downloading gives 409 without a file (as AC10). A template rejected for its brand does not drag the others along. | WS + W |
| AC18 | **W run with a branded test template.** `tools/report-test.sh` adds to the copy from T11 a template `marca-prueba.json` (only in the temporary root) with its PNG logo generated in the test (with a canary `tEXt`) and its color, and checks by real HTTP: AC16 (one `<img>` of exact form, without the canary; page CSP equal to that of `tipo=tecnico`), AC14 (footer and name escaped in `.html`/`.imprimir`), AC15 (`.acento-marca` with the hex in the `<style>` and the CSP of `.imprimir` with that `<style>`'s hash), AC17 (no base64 of the brand in the `tecnico` downloads; Procedencia = `sha256sum`; 409 when the logo changes) and a template with `marca.logo` `../x` with its notice. The existing check of Gekko's brand in `ejecutivo.html` does not change. | W |
| **Cross-cutting** | | |
| AC12 | `.githooks/pre-commit` runs the tests when touching `findings.py`, `findings_web.py` or a file in `.claude/tools/report-templates/`; the `REQ ↔ case` trace stays green with the reconciled `REQ`s. | W + G |

## 6. Risks / open decisions
**Risks / limits this spec accepts:**
- *Persuasive text.* A template only chooses among known things, but its texts are free within the charset:
  it can write something false into the deliverable («sin hallazgos críticos» (no critical findings), «remediado» (remediated)). The defense is `git diff`, the
  sha256 of the template in «Procedencia» and AC1 for the built-in ones; there is no proof that the text tells the truth.
- *Same user.* In `os` mode the model can edit `tecnico.json` or add a template. AC1 makes the gate fail
  if a built-in one changes; a new one is visible in `git status`. A template that shows `evidence.output`
  in an «for executives» format is legal: choosing fields is the template author's call (evidence may
  carry secrets, limit of REQ-RPT-023).
- *Byte-for-byte regression vs. new escape.* The texts that today come out without span (subtitle, notice, section titles)
  must be safe without changing a byte of the built-in ones: the plan chooses between restricting the charset of those
  texts (rejection, recommended: today's texts pass) and a minimal escape that does not alter text without markup punctuation. AC1 and AC6 together decide.
- *PDF.* The PDF comes from printing `.imprimir` in the browser (REQ-RPT-024): a template customizes it to the same
  extent as the HTML; the exact look depends on the browser (Firefox without page number).
- *Directory traversal.* Each page lists and validates the templates: with a cap on number and bytes per file
  (AC5); the plan decides whether they are cached by mtime/sha256.
- *Orphan drafts.* A removed template leaves its draft inside the workspace and under its retention (AC11).
- *Brand (amendment 2026-11-17).* An image is untrusted input: the validator looks at the structure, not the pixels;
  arbitrary bytes can go inside the compressed data (`IDAT`, data after `SOS`) and come out as base64 inside an image `data:`,
  inert for the browser; what is removed is what a viewer or a tool shows as text (metadata). A logo can impersonate another company: the defense is the same as for the texts (`git diff`,
  sha256 of the logo in «Procedencia»). The `.html` grows with the logo (up to ~350 KB in base64 with the 256 KiB cap).
  A 3-component JPEG with Adobe `APP14` and transform 0 (RGB without YCbCr) is rejected, because removing `APP14`
  would silently change its colors; in the others, removing it does not change how it is decoded. A failure of the
  image analysis is always a rejection of that template, never an error that brings the page down.

**Operator decisions** (resolved 2026-11-17: D1, D2, D3, D4 and D7 = (a), approved by the operator, D4 later replaced
by (c); D5 and D6 = (a)
by recommendation, `plan.md` confirms them or proposes a change). **Amendment 2026-11-17:** D4 moves to (c) and D3 is extended):
1. **D1 · Notice about unconfirmed findings.** (a) Mandatory, fixed text from the code; the template does not remove or rewrite it.
   (b) Mandatory, the template may rewrite it. (c) Optional. **I recommend (a)**: it is a statement about the
   security status (what got in and what did not) and it is the only thing a reader sees of the `included` rule.
2. **D2 · Templates in the workspace.** (a) Only in the repo (`.claude/tools/report-templates/`). (b) Also in
   `engagements/<ws>/`. **I recommend (a)**: the workspace is gitignored, the model writes it freely in both
   modes and nobody sees a `diff`; in `toolbox` mode the tools repo is mounted read-only.
3. **D3 · Accent color.** (a) From a fixed palette in the code (e.g. the brand's lime, green, blue, amber, gray),
   with a precomputed CSS class per color in the signed CSS. (b) Free hex `#RRGGBB`. **I recommend (a)**: the CSP and
   the hash of the page's CSS stay static (AC8), the contrast over white paper is tested once per color
   and no template value enters CSS.
   **DECIDED (a), EXTENDED 2026-11-17 (operator):** the page and its preview still use only the palette (AC8); a
   template with `marca` may add `marca.color`, a `#RRGGBB` hex validated and with contrast ≥ 4.5:1 over white,
   which paints only the downloads (`.html`/`.imprimir`) in a fixed class with CSS generated per template and hash per
   document (AC6, AC15). The template keeps naming a palette `acento` for the preview.
4. **D4 · Logo per template.** (a) No: Gekko's brand of REQ-RPT-052 in every template. (b) Choose among the kit variants
   already embedded (`BRAND_PNG`). (c) Own image per template or client. **I recommend (a)** for now;
   (b) is almost trivial if requested; (c) brings untrusted images, decoding and PDF with images: separate spec.
   **DECIDED (c), 2026-11-17 (operator, replaces (a)):** per template, not per client (the brand belongs to the issuer,
   §4 Out): own PNG/JPEG logo in `report-templates/marcas/` named by slug, validated by content and without
   metadata (AC13), company name (AC14), own es/en footer (AC14), own color (D3, AC15) and the logo in the preview as a
   module `data:` `<img>` (AC16, amendment of REQ-RPT-007). Without decoding the image: the
   validation is structural and the PDF is still made by the browser. Without `marca`, today's Gekko brand.
5. **D5 · Built-ins as file or in code.** (a) `tecnico.json`/`ejecutivo.json` as files in the same directory, protected by AC1. (b) In code, and only the extras in files. **I recommend (a)**: a single loading path; if a built-in breaks, the page says so
   (AC5) instead of serving another report.
6. **D6 · Do templates enter §1?** (a) No: the boundary is the engine and its validator, not the data; the pre-commit
   only runs `tools/report-test.sh` when touching a template. (b) Yes: every new template requires touching the living spec.
   **I recommend (a)**: «adding a format = adding a file»; the invariants of E are guaranteed by the code.
7. **D7 · Remember the last template.** (a) No: the choice travels in the URL and stays with its draft (AC11).
   (b) One file per workspace with the last saved template, to open there. **I recommend (a)**: no new
   state.

**For `plan.md`:** exact form of the JSON and its vocabulary of sections (and how `tecnico`/`ejecutivo` express it
without special cases); caps (bytes per file, texts, sections, templates); charset or escape of the texts that
today come out without span; palette of D3 and its contrast; caching of the
loading; capture of the sha256 of AC1 before touching the engine.

## 7. Signals of "done"
**L**, **WS**, **W** and **G** green + checklist of `tasks.md` with its log + real run by the operator: the two
templates on the page, their downloads checked with `sha256sum` against «Procedencia», a test template
copied by hand that appears without touching code (and then deleted), an invalid template with its notice, and the PDF printed
from `.imprimir` looked at in a viewer; and (amendment 2026-11-17) a test template with brand — fictitious PNG and JPEG logos, own name, footer and color —
looked at in the preview and in the PDF (logo on the cover, footer on each page
next to the number, color in lines and numbers), and then deleted with its logo.
