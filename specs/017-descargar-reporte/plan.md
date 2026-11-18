# Technical plan 017 — View and download the report from the web

> Status: `IMPLEMENTADO` (2026-11-16) · `APROBADO` — operator, 2026-11-16.
> Spec: [`spec.md`](spec.md) (`APROBADA`, 2026-11-16) · `report-module` branch, base `89bb535`
> Coding: Codex (a coding agent) with the profile `.claude/agents/coder.md`, in its own worktree; verification and integration are done by the main session.
> **Operator decision (2026-11-16):** PDF with the own stdlib generator (§4, first decision).

## 1. Approach
A single projection in `findings.py` decides what enters and in which order, and delivers each finding as an ordered list of fields with its label in the requested language. Three thin printers consume it: Markdown (today's, in `findings.py`), HTML and PDF (in `findings_web.py`). This way the ids, the order and the fields match by construction (AC3, AC6) and there is a single label table (AC4). Everything is generated in memory when requested, with the standard library: no dependencies, no temporary files and no network.

## 2. Contracts

**`findings.py`**
```python
LABELS = {"en": {...}, "es": {...}}      # the table of spec §5; sole source of the labels
_scan_bytes(data) -> (rows, bad)         # today's reader over bytes; _scan(path) = _scan_bytes(path.read_bytes())
included(rows, show_all=False) -> rows   # confirmed with non-empty corroboration, sorted by severity
report_fields(row, lang) -> (id, título, [(tipo, etiqueta, valor)])
render_md(rows, lang="en", show_all=False) -> str
```
- `cmd_render` is left as: `_load` → `render_md` → write it. It gains `--lang en|es` (default `en`); an unknown language exits ≠ 0 without printing (also inside `render_md`, because the selftest calls the function).
- `tipo` is one of `linea` (severity, state, target), `campo` (text: inline or fenced), `bloque` (evidence output, always fenced), `pasos` (steps) and `kb`. The order is that of `render` today.
- `render_md` builds a list of lines instead of using `print`: capturing standard output does not work in a server with threads.

**`findings_web.py`**

| Request | Response |
|---|---|
| `GET /w/<ws>/reporte` (`?idioma=en|es`, `?vista=md`) | report page |
| `GET /w/<ws>/reporte.md`, `.html`, `.pdf` (`?idioma=…&ledger=<sha256>`) | the file, as an attachment |
| download with `ledger` absent, malformed or different from the current sha256 | 409, "the report changed", link to the page |
| page or download with a ledger with a bad line or not regular | the page warns and offers no downloads; the download responds 409 without report |
| PDF that exceeds `PDF_MAX_PAGES` or whose generator fails | the page says so next to the format; the download responds an error, never 200 |
| other method | 405 (rule that already exists) |

- `read_ledger` reads the file **once**: from those same bytes it takes the sha256 (`Ledger.digest`) and the rows.
  The page puts that sha256 in the three download links; the download compares it with that of the file it reads.
- `idioma` and `vista` are validated against their two values; any other falls back to the default and is not repeated on the page.
- Download headers: those of `response_headers` with the type changed (`text/markdown; charset=utf-8`,
  `text/html; charset=utf-8`, `application/pdf`) plus
  `Content-Disposition: attachment; filename="<ws>-reporte-<idioma>.<ext>"`. The workspace name already passed
  `NAME_RE`, which only admits letters, digits, `.`, `_` and `-`.

**Page.** Header "Reporte · N incluidos de T" (Report · N included of T). Below: what stays out (each `confirmed` without
corroboration with its id and link; counts by state for the rest); language and view links; the three download links with the retention notice; and a `<details>` "Procedencia" (Provenance) with the sha256 of the ledger, of the Markdown and of the HTML. Then the report: Document view (the same inner HTML as the `.html` file) or Markdown view (`<pre>` with the escaped text).

**Downloadable HTML.** A document with `<meta http-equiv="Content-Security-Policy" content="default-src 'none';
style-src 'sha256-…'">`, an own `<style>` and the same body as the Document view. No embedded fonts (it uses the system ones), no scripts, no links. Every value passes through `esc`, the function that already cleans controls
and invisibles. The document title is only "Findings" or "Hallazgos".

**PDF.** Own generator of about 100 lines: A4, standard fonts Courier and Courier-Bold with WinAnsi encoding, text split by number of characters (in a fixed-width font the cut is exact), uncompressed content, no date nor identifier, no annotations. What cp1252 does not have comes out as `?`.

## 3. Affected files
| File | Change | AC served |
|---|---|---|
| `.claude/tools/findings.py` | `LABELS`, `_scan_bytes`, `included`, `report_fields`, `render_md`; `cmd_render` over them; `--lang`; new cases and adjustment of those that today keep a `confirmed` without corroboration (lines 429, 444, 510 of the selftest) | AC1, AC3, AC4 |
| `.claude/tools/findings_web.py` | `Ledger.digest` and single read; `report_page`; `report_body`, `report_html`, `pdf_bytes`; routes in `respond`; download headers; "Reporte" link in list and detail; CSS rules of the document; docstring; new cases; the case of REQ-RPT-016 that requires 404 at `/w/ws/reporte` (line 1148) | AC2–AC21 |
| `tools/report-test.sh` | the check "no web destination for report" now requires only `/export` at 404; real downloads with `curl`, `sha256sum` against the page, and `pdftotext` over the PDF if installed (if not, it warns and continues) | AC8, AC10, AC12, AC15, AC22 |
| `specs/SECURITY-GUARDRAILS-SPEC.md` | REQ-LED-002 (exclusion and language), REQ-RPT-008 (new routes), REQ-RPT-016 (stops denying the report), new `REQ`s | AC22 |
| `.claude/agents/report-writer.md`, `.pi/agents/report-writer.md`, `.codex/agents/report-writer.toml` | name `--lang` and say that a `confirmed` without corroboration does not enter | AC1, AC4 |
| `docs/pi-hitl.md` §4c | the report page, the formats and the warning about where the file stays | AC21 |
| `specs/017-descargar-reporte/tasks.md` | written after this plan is approved | — |

Not changed: `setup.sh` (no new system requirement), `.githooks/pre-commit`, `toolbox/gekko-guard.ts`
(it already counts the `ok REQ-…` lines of the two selftests: that question of the spec has been resolved since 012), the panel and the launcher.

**`REQ` in the living spec** (if 016 is merged first, these numbers follow its own):
- REQ-LED-002 — `render` excludes the `confirmed` without corroboration and accepts a language; only the labels change.
- REQ-RPT-021 — report page: what enters, what stays out, two views, two languages, a single workspace.
- REQ-RPT-022 — downloads: Markdown equal to `render`, headers, changed report, broken ledger, read-only.
- REQ-RPT-023 — self-contained HTML with no active content.
- REQ-RPT-024 — PDF: it opens, same content, no active content, visible substitution.

## 4. Decisions (resolves the open ones in the spec)
- **PDF with own generator** (proposed; the operator decides). Tested on 2026-11-16 on this machine with a 20-line prototype: `pdftotext` opens it and returns the accents, the `ñ`, `¿` and `¡` correctly; characters outside cp1252 come out as `?`; two generations give the same sha256; the file does not contain `/URI`,
  `/JavaScript`, `/Launch` or `/EmbeddedFile`.
  - In favour: no dependencies, nothing to install in `setup.sh`, it does not process target text with a third-party engine, it opens no network nor temporary files, and it comes out the same on any machine (AC11 is reduced to "too large or internal error").
  - Against: typewriter look (a single fixed-width family) and cp1252 only: trees with box-drawing characters, Cyrillic, CJK or emoji in an evidence come out as `?`.
  - Alternative: WeasyPrint, which converts the report's HTML. It gives a PDF with the same look as the HTML and with Unicode. It is installed on the development machine but only in the user-local install directory; it would be the module's first dependency, it would have to be added to `setup.sh`, and it brings an HTML/CSS and font engine into the process on the boundary. A headless browser is ruled out: it is the heaviest dependency of the three, and Firefox 152 without an interface crashed inside the sandbox during 015 (it worked outside the sandbox).
- **Extracting the PDF text in the gate:** the selftest reverses its own generator (the content goes uncompressed), so it does not depend on any program. `tools/report-test.sh` additionally uses `pdftotext` when installed, as a second independent reader.
- **One projection and three printers** (§1). The falsifier of the refactor is comparing today's `render` output with the new one over a fixed ledger, byte by byte.
- **Changed report: sha256 of the ledger in the link.** Without that parameter the download delivers nothing, so a guessed address or one built from another page does not download a file either.
- **Single read of the ledger:** the sha256 and the rows come from the same bytes. Reading twice would leave a window in which the page promises one report and delivers another.
- **With zero included, the downloads are offered anyway:** the file says there are no confirmed findings, just as `render` does. One rule fewer.
- **The document's paper is always light**, also with the dark theme: the downloaded HTML and the view share the same style rules and the file does not know the module's theme.
- **PDF cap:** `PDF_MAX_PAGES = 2000`. Above it, the page says so and Markdown and HTML continue (AC11).
- **Default language `en`** in the terminal and on the web, as the spec approved.

## 5. Risks and mitigation
- The refactor of `render` changes one byte of the output that `report-writer` consumes → byte-by-byte comparison against today's output before touching anything else; the cases of REQ-LED-002 run unchanged except for the three that keep a `confirmed` without corroboration, which gain corroboration.
- Changing `_scan` breaks the panel or the reader → `_scan(path)` keeps its signature and its result; the cases of REQ-LED-004 and REQ-RPT-003 cover it.
- The downloaded HTML is opened without the module's headers → it carries its own policy inside, and there is nothing to block: no scripts, no links, no resources. Whether the viewer respects that policy is not verifiable (a limit of the spec).
- A PDF viewer can turn a URL-shaped text into a link even if the file has no links. It is the viewer's behaviour, not the file's; it adds to the limits.
- A large ledger generates the page, the Markdown and the HTML on each view (to show their sha256s) → it is linear work in memory; the PDF is generated only on request. It is measured with a 500-row ledger in the real run.
- The Document view adds rules to the signed CSS → the hash is recalculated automatically; the REQ-RPT-007 case that compares the served CSS with the signed one covers it.
- The two specs touch `respond`, `detail_page` and REQ-RPT-008 → the second one implemented starts from the branch with the first one already inside; they are not developed in parallel on the same base.

## 6. Order of attack
1. **Cheapest falsifier:** save today's `render` output over a fixed ledger, do the refactor to `report_fields` and `render_md`, and compare byte by byte. Nothing else proceeds without this being green.
2. AC1 in red and then in green (exclusion), adjusting the three cases that depended on the opposite.
3. Language: `LABELS`, `--lang`, and the case "only the labels change" (AC4).
4. `_scan_bytes`, `Ledger.digest` and the report page with its two views (AC2, AC5–AC7).
5. Markdown download with headers, changed report and broken ledger (AC8, AC12–AC14).
6. Downloadable HTML (AC9, AC15) and PDF (AC10, AC11), with the hostile values from the first case (AC16).
7. A single workspace, read-only, access controls and no network (AC17–AC20); link and notice (AC21).
8. `tools/report-test.sh`, living spec, `report-writer` prompts and `docs/pi-hitl.md`; the four gates green.
9. Independent security review of the diff (agent `code-auditor`) before merging.
10. Real run by the operator: the two views, the two languages, the three files opened and `sha256sum`.
