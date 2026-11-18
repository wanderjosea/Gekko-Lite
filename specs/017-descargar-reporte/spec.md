# Spec 017 — View and download the report from the web

> Status: `IMPLEMENTADA` (2026-11-16: real run by the operator, T31; T28 green on 2026-11-17) · `APROBADA` (operator, 2026-11-16). The four decisions of the first draft are in §8: two
> changed the scope —three formats and two languages— and the criteria were rewritten with them. The three points decided by the author (§6) were approved with the text; the operator did not comment on them one by one.
> Date: 2026-11-16 · Design source: mockup `05-reporte` of [`015`](../015-reportes-rediseno/spec.md)
> (marked NOT BUILT) and its contract in `revision-diseno.md` §7 + decision 4 of [`012`](../012-report-module/spec.md) §8
> `report-module` branch. It does not depend on [`016`](../016-estado-desde-web/spec.md); both rewrite REQ-RPT-008,
> so the second one merged is reconciled over the first.
> It adds routes to the module (REQ-RPT-008 today lists three pages): it goes through the long flow.

## 1. Problem (one sentence)
The report — the projection of the confirmed findings — only exists as the output of `findings.py render` in the terminal, in Markdown and with labels in English: the module has no report page (`/w/<ws>/reporte` answers 404, case of REQ-RPT-016 in `.claude/tools/findings_web.py:1148`), so the operator cannot see from the web what would enter the deliverable nor take it away as a file.

## 2. Goal (one sentence)
For each workspace the operator opens a page that says which findings enter the report and which stay out and why, reads it as a document or as Markdown, in Spanish or English, and downloads it in Markdown, HTML or PDF; the three files carry the same findings, the Markdown is byte for byte what `findings.py render` gives for that ledger, and the module serves no file from disk nor writes to the workspace.

## 3. Context / why now
012 left the download for "later" and 015 drew the page without building it (its AC6 forbids export controls "while no supported web exporter exists"). Read in the code (`report-module` branch, `89bb535`):
- `cmd_render` (`.claude/tools/findings.py:258`) projects the `confirmed` rows, sorted by severity, and fences the values with backticks (REQ-LED-002). Its output carries no date: the same ledger always gives the same bytes.
- `render` includes a `confirmed` row **without** corroboration (a row written by hand; `set` does not let it be created, REQ-LED-003). The contract says nothing enters a deliverable as confirmed on a single signal; today the module marks that row (REQ-RPT-004) but `render` projects it anyway.
  Measured on 2026-11-16 on a temporary ledger with two `confirmed` rows, one without corroboration: `render` brings both, and two consecutive runs give the same sha256.
- `render` aborts on a ledger with a bad line (REQ-LED-004); the module keeps showing the other rows.
- `render` writes its labels in English (`Severity`, `Status`, `Summary`…) and has no language option; the module is in Spanish.
- Outside a fence `render` only removes line breaks: a title with Markdown syntax (a link, an image) is written as is (limit of REQ-LED-002). Titles and evidence come from the target.
- All the module's responses are `text/html` with the same content policy (`response_headers`, `findings_web.py:285`); there is no response that the browser saves as a file.
- The module and `findings.py` only use the Python standard library, and that library does not generate PDF: the PDF is the first function of the module that needs its own generator or an external program.
- A downloaded HTML is opened from disk, without the module's headers: the content policy that today protects the pages does not travel with the file.
- The agent `report-writer` builds the final deliverable from `render` (`.claude/agents/report-writer.md:19`): this spec's file is that projection, not the assembled deliverable.

## 4. Scope
**In:**
- **Report page** per workspace, linked from the list and the detail: how many findings enter out of how many, which stay out and why, and the report in two read-only views — Document (default) and Markdown (`?vista=md`, the literal text of the file).
- **Report language:** Spanish or English, selectable on the page; applies to both views and to the three downloads. It changes the labels, not the values (table in §5).
- **Download** in three formats, generated from the ledger when requested: Markdown, self-contained HTML and PDF.
- **Provenance** on the page: sha256 of the ledger read and sha256 of the Markdown and HTML files.
- **`render`**: stops projecting by default a `confirmed` row without corroboration (adjustment of REQ-LED-002; `--all` does not change) and gains the language choice.
- Reconciliation on merge: REQ-RPT-008 (new routes, the module still does not write to workspaces), REQ-LED-002, the case of REQ-RPT-016 and the check of `tools/report-test.sh` that today require 404 at `/w/<ws>/reporte`, and new `REQ`s for the report.

**Out (explicit, anti scope-creep):**
- Translating the content of the findings (title, summary, impact, remediation, evidence, steps): it comes out in the language in which it was written. Severity and state tokens are not translated either.
- The module's interface in English: the pages remain in Spanish; the language is that of the report.
- Other languages and other formats (DOCX, JSON, CSV).
- Cover page, index, logo, summary table, page numbering and any layout of the PDF or HTML beyond showing the same fields in the same order as the Markdown.
- Producing HTML or PDF from the terminal: `render` only gains the language (the plan may offer it; it is not required).
- Export options: "por validar" annex, including or not the evidence output, `render --all` from the web.
- Completeness checks (included findings without remediation, impact or summary).
- "Copy Markdown" button and keyboard shortcuts (they need JavaScript). The text of the Markdown view is selected.
- Saving the report inside the workspace (`reports/`): this spec writes to no workspace.
- Serving evidence artifacts, `loot/` or `findings.jsonl`: they remain without a route (REQ-RPT-008).
- A report joining several workspaces.
- A date or the workspace name inside the file (decision 4 of §8).
- The assembled deliverable (report + scripts + ZIP): it remains the agent `report-writer`'s.
- Editing the report from the web: the finding is corrected, not the document.

## 5. Acceptance criteria (testable)
> Tests: **L** = `python3 .claude/tools/findings.py selftest`. **W** = `bash tools/report-test.sh` (runs **L**, the selftest of `findings_web.py` and hits the real module over HTTP on a temporary root). **H** = `.githooks/test.sh`.
> **G** = the gate (`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`).
> "Enters" = the row that `render` projects by default. "The three files" = the Markdown, HTML and PDF downloads.
> All cases run on temporary ledgers with fictitious data; none reads `engagements/`.
>
> **Labels by language** (the only thing that changes between `en` and `es`; `CVSS`, `CWE`, `CVE` and `KB` are the same):
>
> | `en` (today) | `es` |
> |---|---|
> | `Findings` | `Hallazgos` |
> | `Severity` · `Status` · `Target` | `Severidad` · `Estado` · `Objetivo` |
> | `Summary` · `Impact` · `Remediation` | `Resumen` · `Impacto` · `Remediación` |
> | `Corroboration` · `Blocker` | `Corroboración` · `Bloqueo` |
> | `Command` · `Artifact` · `Evidence` · `Repro` | `Comando` · `Artefacto` · `Evidencia` · `Reproducción` |
> | `_No confirmed findings._` | `_Sin hallazgos confirmados._` |

| # | Criterion (observable) | Test |
|---|---|---|
| **What enters** | | |
| AC1 | `render` without `--all` projects only the `confirmed` rows with a non-empty corroboration: a `confirmed` row without `corroboration`, or with one of only spaces, does not appear. `render --all` still brings all rows. | L |
| AC2 | The report page of a workspace says how many findings enter and the total ("N incluidos de T", N included of T), and lists separately what stays out with its reason: each `confirmed` without corroboration with its id and a link to its detail, and the count of the other rows by state, with unknown states and "sin estado" (no state) counted as such. The counts add up to T. | W |
| AC3 | On the same ledger, the Document view, the Markdown view and the three files, in both languages, carry exactly the same ids, in the same order, and they are the ones that enter according to AC1. | W (the PDF, extracting its text) |
| **Language** | | |
| AC4 | `render` accepts the language `en` or `es`. Without choosing, or with `en`, the labels are today's; with `es`, those of the table, and no English label of the table remains as a label. Between the two languages only the labels change: the values of each row — including the severity and state tokens — are identical. The rules of REQ-LED-002 apply in both (a single `## ` line per finding, fences longer than the value). WHEN the language is neither of the two, THEN `render` exits ≠ 0 without printing a report. | L |
| AC5 | The page offers both languages; the choice applies to both views and to the three files, and is kept when switching view. Without a choice, or with an unknown value, the default language applies; the received value never appears on the page. The module's pages remain in Spanish with either of them. | W |
| **Views** | | |
| AC6 | The Document view shows, for each finding that enters, the fields that `render` projects (title, severity, state, target, the six fields of REQ-LED-001, corroboration, command, artifact, output, steps and KB), only the ones the row carries and with the labels of the chosen language. `?vista=md` shows the text of the Markdown file as literal text; an unknown `vista` value falls back to Document. Both views work without JavaScript. | W |
| AC7 | WHEN no row enters, THEN the page says so and does not confuse that case with a workspace without findings nor with an unreadable ledger; what stays out is still listed (AC2). | W |
| **The three formats** | | |
| AC8 | **Markdown.** The file is byte for byte the output of `findings.py render --ledger <that ledger>` with the same language. | W |
| AC9 | **HTML.** The file is a single document that is read without network and without the module: it references no external origin (fonts, styles, images, scripts), it contains no `<script` nor event attributes, and it carries inside a content policy that prohibits scripts and external resources. Every ledger value is escaped, without control or invisible characters (those of REQ-RPT-007), and none appears as a label, attribute or link target. It shows the same fields as the Document view. | W |
| AC10 | **PDF.** The file is a PDF that a reader opens (it starts with `%PDF-` and a text extractor goes through it without error). It contains no JavaScript, launch actions, links nor embedded files. Ledger values come out as text: the accents, the `ñ` and the signs `¿` `¡` read correctly, and a character the generator cannot draw is shown replaced by a mark, never silently omitted. | W (extracting its text) |
| AC11 | WHEN this machine cannot generate the PDF (what the generator needs is missing, or it fails, or the report exceeds its page cap), THEN the page says so next to that format, with the reason, and keeps offering Markdown and HTML; the PDF address responds with an error, never a 200 with an empty or half-written file. | W |
| **Every download** | | |
| AC12 | Each download arrives as an attached file with the type of its format (Markdown in UTF-8, HTML, PDF), with `X-Content-Type-Options: nosniff`, the module's content policy and `Cache-Control: no-store`. The file name is built only from the workspace name (which already meets REQ-WS-001), the language and the extension: no ledger value reaches a header. | W |
| AC13 | WHEN the ledger changed between showing the page and pressing download, THEN no file is delivered, in any format: the response says the report changed and links to the up-to-date page. The operator never receives a file different from the one the page showed them. | W |
| AC14 | WHEN the ledger has a bad line or `findings.jsonl` is not a regular file, THEN the page warns with the line number or the reason, offers no download and shows no partial report, and the three download addresses respond with an error without report body. | W |
| AC15 | Two consecutive downloads of the same ledger and the same language give the same bytes in Markdown and in HTML; the page shows the sha256 of those two files and that of the ledger read, and they match those of the downloaded files. | W |
| **Security** | | |
| AC16 | WHEN the fields of the rows that enter carry the hostile content of 012 (§5) and invisible characters, THEN both views return them escaped and REQ-RPT-007 keeps being met on the report page (no `<script`, no event attributes, no external origins, the artifact path is not a link); in the Markdown the values go inside their fence as today; the HTML meets AC9 and the PDF AC10 with those same values. | W |
| AC17 | The report and the downloads belong to a single workspace: with two workspaces loaded with different markers, neither the page nor any file of one carries a datum of the other. A workspace that does not exist responds 404. | W |
| AC18 | The report and the downloads only read: they are requested by GET, any other method responds 405, and after opening both views in both languages and downloading the three files, the sha256 of each ledger and the listing of each workspace directory are the same, and no temporary file of the module with a ledger's content remains. `/findings.jsonl`, `/scope.txt`, `/loot/creds.md`, those paths under a workspace and the path of an artifact keep responding 404. | W |
| AC19 | The controls of REQ-RPT-009 apply to the new routes: with a `Host` that is not `127.0.0.1:<port>`, or from a connection that is not from the module's user, the page and the downloads receive the fixed 403, without data from any ledger. | W |
| AC20 | Generating a report takes no data out of the host: during the three downloads the module opens no connection that is not loopback, not even when a ledger value carries a URL or an image tag. | W |
| **Navigation and notice** | | |
| AC21 | The list and the detail of a workspace carry a "Reporte" link to that workspace's page; the index does not (there is no multi-workspace report). Next to the downloads the page says that the downloaded copy stays outside the workspace and that the engagement's retention does not reach it. | W |
| **Gate** | | |
| AC22 | The case of REQ-RPT-016 and the check of `tools/report-test.sh` that required 404 at `/w/<ws>/reporte` are changed to those of this spec; `/export` keeps responding 404. The new cases run in **L** and **W**, and the `REQ ↔ case` trace of the gate stays green with the reconciled `REQ`s. | W + H + G |

## 6. Risks / open decisions
**Decided by the author, to be confirmed by the operator:**
- **Default language: English**, in the terminal and on the web. It is what `render` gives today, so nothing that already consumes it (`report-writer`, the cases of REQ-LED-002) changes without asking. Alternative: Spanish as the default on the web.
- **"Spanish and English" are the labels**, not the content: a finding written in Spanish comes out in Spanish in the English report too. Translating content would need a model and is out of scope.
- **If the PDF cannot be generated on this machine**, the module says so and continues with the other two (AC11), instead of refusing to start.

**For `plan.md`:**
- **How the PDF is generated.** It is the expensive decision of this spec and the operator takes it at the plan's gate. The known outputs: an own generator (no dependencies, but text only and with a limited character set unless a font is embedded), a headless browser that prints the HTML (a system dependency, and a browser processing text from the target), or a new library. Whichever adds a system requirement writes it in `setup.sh`. AC10, AC11, AC18 and AC20 apply to the one chosen.
- How the PDF text is extracted in the gate (AC3, AC10) without the gate depending on a program that may be missing.
- How the web obtains the output of `render` without copying it (AC8 fails if there are two projections) and how the Document view, the HTML and the PDF decide what enters with the same rule (AC3).
- Where the labels of the two languages live so that there is a single table (AC4) and not one per format.
- The addresses of the page and of the downloads, and how a download knows which report the operator saw (AC13).
- How the new Python cases reach the `REQ ↔ case` trace.
- Size and time: a large ledger with long evidence outputs on a page, in a file and in a PDF.
- Style of the Document view within the signed CSS, and the style of the downloaded HTML inside the file itself.

**Limits this spec accepts (they stay in the living spec when merged):**
- The downloaded files stay where the browser saves them, outside `engagements/`: they are not gitignored by location nor reached by destruction at engagement close. AC21 warns about it; it does not prevent it.
- The Markdown carries target text: outside a fence, a title with a link or an image is written as is (limit of REQ-LED-002). Opening it in a Markdown viewer that loads remote images can make a request to a host the target chose. The HTML and the PDF have no such path (AC9, AC10); the Markdown view does not either.
- The content policy inside the downloaded HTML depends on the program that opens it respecting it.
- The report includes `evidence.output` as it is in the ledger: a secret stored there comes out in the three files.
- The PDF does not promise the same bytes in two downloads (a PDF usually carries a date and an identifier): the page shows sha256 only of Markdown and HTML (AC15).
- AC10 checks the text and the absence of active content, not the appearance: that the PDF looks right is checked in the real run, not in the gate.
- There is no login: whoever can read the module (the two forwarder cases of REQ-RPT-009) can also download the report. It adds no data beyond what they already read on the detail pages.
- AC1 requires a non-empty corroboration, not one that describes a second independent signal (limit of REQ-LED-003).
- AC13 compares against the ledger that the page read; a report opened hours ago is rejected even if the change touches no row that enters (depends on the design the plan chooses).
- AC16 tests the hostile values listed, not "any XSS".

## 7. Signs of "done"
`python3 .claude/tools/findings.py selftest`, `bash tools/report-test.sh`, `.githooks/test.sh` and the gate
(`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts`) green at the same time + the `tasks.md` checklist complete with its verification record + a real run by the operator in their browser: open the report of a lab workspace in both views and both languages, download the three files, open each one, and check with `sha256sum` that the Markdown and the HTML match what the page shows, with screenshots in both themes.

## 8. Operator decisions (2026-11-16)
1. A `confirmed` without corroboration stays out of the report, in `render` itself: "ok" (AC1, AC2).
2. Formats: "permite los 3" (allow all 3) — Markdown, HTML and PDF (AC8–AC11). It replaces the proposal of Markdown only.
3. Language: "hay que aceptar español e inglés" (both Spanish and English must be accepted) (AC4, AC5). It replaces the proposal of keeping only today's English.
4. No "Generado …" line nor workspace name inside the file: "ok".
5. Approval: "aprobadas ambas spec" (both specs approved) (2026-11-16).
