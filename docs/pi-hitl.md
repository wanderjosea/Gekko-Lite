# Pi with Gekko in HITL mode

This is the initial path with the operator present. Pi opens the repository, loads
`AGENTS.md`/`CLAUDE.md`, consults the KB and uses the models of your Provider (any
OpenAI-compatible endpoint). The launcher keeps Pi's native tools (`bash`, `read`,
`edit`, `write`) and loads the tmux extension for persistent processes.

**HITL here means an operator who is present and able to observe/intervene.** Pi
does not ask for human approval before each
tool call. Commands may run on the host with the user's privileges. This profile is not
a security boundary and must not be confused with the contained toolbox.

## 1. Requirements

- Git, Node.js, npm, tmux and the Pi agent.

**Shortcut (new box):** from the repo root, `./setup.sh` gets everything ready — it
detects the config dir (`PI_CODING_AGENT_DIR` or `~/.pi/agent`), pins Pi to 1.5.0,
installs the extensions (pi-subagents + modealias) and configures `models.json`,
`modealias.json` and `subagents.json` (foreground/background slots at one, subagents
foreground-only and nested delegation disabled). It leaves other providers intact and
makes a backup before changing an existing file. The `.pi/agents/` roster is not
copied: it is discovered when Pi is launched from the repo root. Credentials are kept
in `.gekko-state/env` (0600, gitignored) and `./tools/pi-hitl.sh` loads them at each
launch, without `source`: they fill in what is missing, and what is already exported in
your shell wins.
The initial model can be changed with `GEKKO_MODEL=<model-id>` before running the
setup, or by editing that variable in `.gekko-state/env`. Inside Pi, the orchestrator
model is changed in the TUI with `/model`; subagents follow the engine configured by
the setup (alias `sub-128k` in `modealias.json`). The model catalog for Pi comes from
`toolbox/models.json`.
- Network access to an OpenAI-compatible endpoint (the Provider).
- A model served by that endpoint (`<model-id>`).
- An authorized engagement with explicit scope.

```bash
npm install -g --ignore-scripts @earendil-works/pi-coding-agent
pi --version

git clone https://github.com/wanderjosea/Gekko-Lite.git
cd Gekko-Lite
git config core.hooksPath .githooks
```

## 2. Provider

```bash
export GEKKO_LLM_URL="http://<endpoint-host>:<port>/v1"
read -rsp 'API key: ' GEKKO_LLM_KEY && export GEKKO_LLM_KEY && echo
export GEKKO_MODEL="<model-id>"
```

Check connectivity:

```bash
curl --fail --silent --show-error \
  -H "Authorization: Bearer $GEKKO_LLM_KEY" \
  "$GEKKO_LLM_URL/models"
```

Pi's config (provider `provider`, `models.json`, `modealias.json`, `subagents.json` and
the extensions) lives in the operator's own config dir (`PI_CODING_AGENT_DIR`, default
`~/.pi/agent`) — that way `pi install` and the subagents load. The `.pi/agents/` roster
is project-level: Pi discovers it when started from the Gekko root, and its adapters
read the canonical prompts by path relative to the checkout. `models.json` references
`${GEKKO_PROVIDER_KEY}` (Pi interpolates it at runtime; the value is not stored).
`tools/pi-hitl.sh` does **not** generate or overwrite that file: it only redirects the
**sessions** to `.gekko-state/pi-sessions/` (gitignored) via `PI_CODING_AGENT_SESSION_DIR`.

`subagents.json` sets both pool limits to one and `maxSubagentDepth` to zero.
Subagents run **foreground-only**: each role in `.pi/agents/` pins
`run_in_background: false` (the frontmatter wins over the call) and `subagents.json`
carries `backgroundByDefault: false` for types without a file. Parent and subagent share
one GPU and model, so the parent waits instead of competing for context. If scheduled
tasks were enabled in Pi, disable them in `/agents` → **Settings** → **Scheduling**,
since scheduled triggers can bypass the concurrency queue.

## 3. Engagement

Create `engagements/<codename>/` with the `engagement-init` skill and fill in at least:

- `scope.txt`: IP or CIDR, one per line (the guard ignores hostnames and `host:port`: such a line authorizes NOTHING);
- `AUTHORIZATION.md` when it is a client;
- window, restrictions, brute-force and rate limits.

`scope.txt` guides the agent, but on the host it does not enforce egress. A discovered
hostname or address stays out of scope until explicitly authorized.

## 4. Start Pi HITL on the host

```bash
./tools/pi-hitl.sh
```

You can also pass the first message:

```bash
./tools/pi-hitl.sh \
  "Engagement: <codename>. Read engagements/<codename>/scope.txt and start recon."
```

The launcher loads `docs/prompts/pi-hitl.md`, `toolbox/shell-session.ts`,
`toolbox/gekko-guard.ts` (which imports the panel logic `gekko-panel.ts`) and the banner.
Pi can use Bash directly and can create persistent tmux sessions for listeners, SSH,
evil-winrm or callbacks. The human can watch from another terminal with tmux.

Keep this mode for supervised, low-risk work. Confirm the scope manually before every
host change and stop the session if dubious behaviour appears.

## 4b. Workspace

`tools/pi-hitl.sh` is the only HITL launcher and does not start Pi without a workspace (`engagements/<name>/`, with `scope.txt`):

- With a terminal and no `GEKKO_WORKSPACE`, it shows a menu (pick an existing one, create a new one, change its scope; Enter picks the last used).
  Hostnames are resolved once and written only if you confirm. Creating never overwrites existing files.
- Without a terminal you must export `GEKKO_WORKSPACE=<name>`, or `GEKKO_WORKSPACE=none` for generic work without a workspace (everything as before).
- From the workspace are derived `GEKKO_WORKSPACE_DIR`, `GEKKO_SCOPE` (`<dir>/scope.txt`), `GEKKO_FINDINGS` (`<dir>/findings.jsonl`) and the
  Pi sessions (`<dir>/.pi-sessions`, no longer `.gekko-state/pi-sessions`). A previous `GEKKO_SCOPE`/`GEKKO_FINDINGS` in the environment is
  overridden and the banner says so.
- When creating a workspace, the menu asks where shells are born: Enter/`o` = OS; `t` = toolbox. The choice is stored in `engagements/<name>/exec`; if the file is missing, OS is used. Existing workspaces are not asked again.
- In OS mode, `session_*` shells are born on the host. In toolbox mode, `tools/pi-hitl.sh` creates or reuses `gekko-tb-<name>` and the shells are born inside it, in the workspace. The container mounts only that workspace (writable) and `.claude/tools/` (read-only); `bash` and Pi's read tools stay on the host to reach the repo and KB. The guard requires using a shell for bash commands against scope hosts; the `findings.py` CLI has a strict exception.
- The container stays up when Pi closes, and the launcher says so on exit if it is still running. To stop it from Pi: `/gekko-toolbox off` (§5); to delete it: `docker rm -f gekko-tb-<name>`. If it was created with `GEKKO_OVPN`, keep that same path exported on relaunch so the existing mount is validated.
- The model prompt (`.gekko-state/pi-hitl.prompt.<workspace>.md`; the banner also carries the workspace name, so two engagements launched at once do not clash) describes both modes and says which one rules at launch (the operator can change it with Pi open, §5; the banner shows the mode "at launch"). Panel state is per launch (`.gekko-state/panel.<workspace>.<pid>.json`): two Pi sessions on the same workspace each have their own rail, and what a dead launch leaves behind is deleted by the next one.
- The shell mirror (§10) works in both modes: a toolbox shell's window drops you inside the container.
- A workspace whose directory is a symbolic link does not start: replace it with the real directory.
- Docker and `setfacl` are only needed for toolbox. `./setup.sh` warns if they are missing; OS remains available.
- Process tests: `bash tools/ws-test.sh`.

## 4c. Report module (spec 012)

A local web server to view the findings of **all** workspaces under the root: workspace index → findings list (counters, search, severity filter) → detail → per-workspace report. From the detail you can change a finding's status (spec 016) and ask the Provider about it (spec 018); the rest is read-only.

- **Where:** `http://127.0.0.1:4355/` (`GEKKO_REPORT_PORT` changes the port). Loopback only; from another machine, an SSH tunnel.
- **Startup:** `tools/pi-hitl.sh` starts it if it is not running and uses it if it is (`findings_web.py ensure`). The banner carries
  the workspace URL (`…/w/<name>/`) and the FINDINGS card the base URL. With `GEKKO_REPORT=0` or `GEKKO_WORKSPACE=none` it neither
  starts nor uses it.
- **It stays up** when Pi and tmux close. To stop it: `pkill -f 'findings_web.py serve'`.
- **Without Pi:** `python3 .claude/tools/findings_web.py serve` (foreground, Ctrl-C stops it) or `… ensure` (background).
- **New workspace:** it shows up in the index by itself, which reloads every 15 s. Nothing to register.
- **Report:** from the list or the detail open `/w/<name>/reporte`. Switch between Technical/Executive, Document/Markdown and English/Spanish; from there download Markdown or self-contained HTML, or press "Export PDF": it opens the print view in another tab (the same bytes as the HTML, no server-side PDF) and you save with Ctrl+P → Save as PDF, unchecking "Headers and footers". Downloads land wherever your browser saves files, outside the workspace and the engagement's retention. The CLI accepts `--lang en|es` and by default omits `confirmed` findings without non-empty corroboration.
- **Who can read it:** only processes of your own system user; others, and a container with host networking, get the connection cut. There is no login. Always use `127.0.0.1`: `localhost` is rejected.
- **Mind the proxies:** if you have Burp, ZAP or mitmproxy listening outside loopback (all interfaces, the VPN one),
  anyone who can reach that proxy can request the module from it, read all ledgers, change the status of any editable finding, ask the Provider and apply proposals.
  Keep the proxy on `127.0.0.1` or switch the module off (`pkill -f 'findings_web.py serve'`) while it is open.
- **Settings:** the gear at the top right opens a menu with the theme (auto, light or dark; remembered in a
  browser cookie) and "Check for updates".
- **New code:** after updating the repo, "Check for updates" makes the module pick up the code already on
  disk; the page flags it next to the gear when there is some. It downloads nothing.
- **One port, one root:** each worktree has its own `engagements/`. If the port is taken by another worktree's module (or another
  program), the banner says so and Pi starts without the module: stop the other or set another `GEKKO_REPORT_PORT`.
- **Ledger fields:** `findings.py add|set` accept `--summary --impact --remediation --cvss --cwe --cve` (optional, with
  validated format). `add` only creates hypotheses: `confirmed` and `needs_validation` are reached with `set`.
- **Assistant (spec 018):** the detail's "Assistant" panel asks the Provider (profile `provider`: `GEKKO_LLM_URL` and
  `GEKKO_PROVIDER_KEY` from `.gekko-state/env`, which the module reads as data and never executes; `GEKKO_CRED_ENV` does not apply).
  The panel shows what is sent: that finding's fields (title, severity, status, target, summary, impact,
  remediation, steps, CWE/CVE/CVSS, KB, command and evidence path, corroboration, blocker), sanitized and fenced; the
  **evidence output is off** and only travels if you switch it on. Only a Provider on private networks is accepted
  (127/8, 10/8, 172.16/12, 192.168/16, 100.64/10). One question at a time; **Esc** or closing the tab stops it.
  A reply never writes on its own: if it proposes `summary`, `impact` or `remediation`, an "Apply" appears; "Undo"
  restores the previous value. Those fields are marked "via chat" only on the web (the report does not change).
- **Chat history:** `engagements/<ws>/.gekko-web/chat/<hash>.jsonl`, one per finding, 0600, outside git. It may
  contain finding data: "Clear" deletes it; its retention is up to you.
- **Editing and comments (spec 019a):** "Edit" in the detail (`?editar=1`, no JavaScript) changes summary, impact,
  remediation, CWE, CVE, CVSS v3.1 vector and justification; the score is computed by the server (`findings.py --cvss-vector`),
  severity is not touched and emptying a field is rejected. If the score's band differs from the severity a
  justification is required. Comments are internal operator notes (`findings.py comment add|edit|delete|list`), live in
  `engagements/<ws>/.gekko-web/comentarios.jsonl` (0600, outside git; deleting hides them but the text remains until
  retention) and never enter the report.
- **Report by template, drafts and sidebar (spec 019b/021):** templates live in
  `.claude/tools/report-templates/`; `tecnico.json` and `ejecutivo.json` are the built-in ones. To add one, copy
  `tecnico.json` to `<slug>.json`, change the label and the `textos.*.autor` values. If you add a `marca` (brand), those authors
  cannot say "Gekko". The brand represents the report's issuer, never the client.
  The palette has `grafito` by default, four strong tones (`lima`, `verde`, `azul`, `ambar`) for line and number,
  and five light ones (`lima-claro`, `verde-claro`, `azul-claro`, `ambar-claro`, `gris-claro`) for line and band, without
  colouring the number. An optional brand
  uses exactly `nombre` and a `logo` slug, plus optional `pie.es`/`pie.en` and `color`. Name and footer are
  printable, 1–120 characters; the colour is `#RRGGBB` with contrast ≥4.5:1. The logo must be the only
  `<slug>.png` or `<slug>.jpg` in `.claude/tools/report-templates/marcas/`, up to 256 KiB and 2048 px per side. PNG chunks
  outside the allowlist (including `tEXt`, `zTXt`, `iTXt`, `eXIf`, `tIME` and private ones) and JPEG segments APP0–APP15
  and COM are discarded. The JSON template
  is at most 16 KiB and the directory holds up to 16 templates. When you change a built-in one, update the AC1 baseline
  hashes.
  Each template has a draft at `engagements/<ws>/.gekko-web/borradores/<name>.json` (0600, outside git, within
  retention). "Preview" writes nothing; "Save draft" does. Downloads pin the sha256 of the ledger,
  draft and template, plus the logo's if there is a brand; a stale pin gives 409. `findings.py render --tipo <name> [--borrador F]`
  produces the same Markdown. The `.imprimir` view contains the same bytes as the HTML and is saved with
  Ctrl+P. The sidebar folds to 70 px with the `gekko_barra` cookie.
- **Attachments: screenshots per workspace (spec 023a):** the sidebar's "Adjuntos" section stores PNG/JPEG images in
  `engagements/<ws>/evidencia/<sha256>.png|jpg` (0700/0600, outside git) plus an append-only index
  (`evidencia/galeria.jsonl`). They are validated by content (≤ 5 MiB, side ≤ 16,384, ≤ 50 megapixels; never by name; SVG and
  HTML are rejected) and only reused inside the same workspace. They are uploaded in "Adjuntos" or when changing a
  finding's status ("Attach image", in any state) with caps of 4 files per submission, 8 per finding and 200 per gallery; "Remove from this finding" does not delete
  the file. **Deleting** an image (confirmation checkbox) removes it from every finding that uses it, records a removal in
  the index and deletes the file; the index keeps the removal. A screenshot corroborates nothing and does not yet enter the report, the
  chat or the Provider. Each view re-reads and re-checks the sha256 of every image. Limit: the same machine user (and container
  root) can forge file, entry and reference at once.
- **Remediated, comments with images and change warning (spec 024):** `remediated` is the status of a finding that was
  fixed and retested: only from `confirmed`, with a mandatory retest note
  (`findings.py set --status remediated --retest "…"`, or the status form field); if the retest fails it goes back to
  `confirmed`. The report includes it apart, after the open ones ("Remediated (N)") and only with corroboration and note. A
  comment can carry images from "Adjuntos" (picked or uploaded); deleting the image from "Adjuntos" removes it from the
  comments too. Comments remain internal notes (never in the report, the chat or the Provider). The report
  page warns before leaving with an unsaved draft (`beforeunload`, a single hash-pinned script; an aid, not a
  control) and lists under "Outside the report (N)" the confirmed or remediated findings that the report leaves out, with the reason.
- Tests: `bash tools/report-test.sh` (ledger + module) and `bash tools/ws-test.sh` (launcher).

## 5. Toolbox mode

Toolbox mode is chosen when creating the workspace and uses the same launcher `tools/pi-hitl.sh`.
With Pi open it is changed from `/gekko-policy` (Alt+P), "ejecución" (execution) block (spec 014). The TUI
strings are Spanish and are quoted as they appear:

- **Change:** the row shows `os` or `toolbox · levantando|lista|caída` (starting | ready | down). Space or Enter opens a
  confirmation inside the overlay; only `s` (sí) confirms. Towards toolbox it states the workspace, the container, the real path
  that gets mounted, whether it will carry a VPN and whether the container will be created, started or adopted. Towards `os` it
  warns that the `bash` block stops applying.
- **States:** `levantando` while it is being created; `lista` with the container validated; `caída` if it did not come up or
  stopped running (checked every few seconds, TUI only). In `levantando` and `caída`, `session_new` fails with the
  reason and **never** creates the shell on the host. You leave `caída` by retrying from the same row, or with
  `/gekko-toolbox off`.
- **Shells that already exist:** they are neither moved nor closed on change; each stays where it was born and the rail, the bar and
  `session_list` say where it lives.
- **What is stored:** the mode is saved in `engagements/<name>/exec` when the switch to toolbox reaches `lista` and when you
  confirm going back to `os`. A failed start does not change it.
- **Switch off:** `/gekko-toolbox off` stops (does not delete) this workspace's container, after confirming: every shell inside
  it dies, any VPN it carries goes down, and the mode becomes `os`.
- **VPN:** the container brought up live carries a VPN only if you launched Pi with `GEKKO_OVPN`. Do not use the same `.ovpn`
  in two tunnels at once.
- **Limits:** the model has `bash` on the host: it can write `exec` (changes the next launch's mode), use
  `docker`, and type into Pi's TUI with `tmux send-keys` (GAP-78 of the living spec). The confirmations stop a
  model that makes a mistake, not one that attacks its own harness.

To build the image: `make -C toolbox build`. The container keeps its own network and
supports restricted VPN with an optional `.ovpn` (`GEKKO_OVPN`, mounted only at creation).
The container and the guard are not an egress allowlist: do not claim scope containment;
that allowlist is the operator's to set up.

## 6. Evidence, secrets and injection

Native tools hand their output directly to the model. That output does not automatically
cross the sanitizer. Treat pages, banners and target files as hostile data. For a manual
flow, keep the capture under the engagement and use:

```bash
python3 .claude/tools/sanitize_target_content.py --wrap \
  < engagements/<codename>/evidence/raw/<capture>.txt \
  > engagements/<codename>/evidence/<capture>.sanitized.txt
```

The local model may see credentials when the work requires it. Do not commit them,
do not add them to the KB and do not share transcripts that contain them.

## 7. Models and updating

Pick the model your endpoint serves (`GEKKO_MODEL`); `toolbox/models.json` is the catalog
`setup.sh` registers for Pi. Run your own smoke tests before adopting a model.

To update Pi: change the pinned Pi version in your Pi image, rebuild, verify that
instructions/tools/tmux load, and repeat the smokes with your model.

## 8. Control panel and modes (spec 001)

Goal: switch DEFAULT/AGGRESSIVE during a run, summarize activity, see KB queries and the
agent's own tmux shells. The **authority** is the guard (`gekko-guard.ts`); the
state/admission/KB/shell logic lives in `gekko-panel.ts` as pure functions verified by the
gate — one command covers everything (AC17):

```bash
GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts
```

**Modes.** DEFAULT is the initial state of every session/resume/reload; it never silently
inherits AGGRESSIVE. DEFAULT **confirms** before account creation/removal, password changes
and binary uploads to the target. AGGRESSIVE skips that confirmation **only** if a current,
attributable authorization exists for that target+action; without it, it falls back to
confirming. No mode enables deletion, DoS, out-of-scope actions or brute-force without
named authorization, and AGGRESSIVE **never** translates to `GEKKO_ALLOW_DESTRUCTIVE`. Only
an operator action changes the mode: the model, tool output and file contents cannot
activate it.

**Activation and the `GEKKO_PANEL` flag.** With an interactive TUI (`pi` on the host, or in
the toolbox with `-it`) the panel and per-mode confirmation activate by themselves: a required
confirmation opens a dialog (`ctx.ui.confirm`) and, if the operator declines, it blocks. In
headless (`-p`) without the flag the admission stage is **off**, so autonomous runs do not
change behaviour. `GEKKO_PANEL=1` forces admission in headless too; without a TUI a required
confirmation returns an **explanatory block** (it does not hang).

**Brute-force and authorizations.** Brute-force without named approval is **rejected in every
context** (also in the autonomous `-p` run), like DoS — it does not depend on a TUI. The
operator grants a one-off authorization with `/gekko-auth <account|password|binary-upload|bruteforce>
<IPv4|*> <minutes>` (lets AGGRESSIVE auto-approve an attributable change and enables a named
brute-force); `/gekko-auth` without args lists the current ones and `/gekko-auth clear` deletes
them. Authorizations are per-session: they are cleared when a session starts or changes, like the
agent's own shells.

**KB.** Derived from `read`/`grep`/`find`/`ls`, normalizing paths and resolving symlinks
before attributing them to `kb/`. It distinguishes read from searched/listed, counts unique
files and queries separately, and declares coverage: **bash, subagents and prior context are
NOT instrumented** — "full history" is never shown.

**Shells.** Observation only: listing/refreshing sends no keys, closes nothing and creates
nothing. A name collision does not kill the existing session; creation and closure are announced
only when verified. Unattributable sessions are shown apart, not as the agent's own.
An **external** close (the operator kills the pane, the process ends) shows in the panel
within ~3 s even if Pi is idle: a periodic timer polls `tmux has-session` (read-only,
never mutates) and applies the same pure transition tested by the gate. Closed entries are
purged after a short grace, so the registry does not grow unbounded in a long session.

**Guard health.** If the guard is missing or fails, the AGGRESSIVE selector is disabled and
the session is not presented as protected. Seeing a guard does **not** imply network containment.

### Verified on a real Pi 1.5.0 (host)

The probe completed. The extension loads cleanly on `pi` 1.5.0; the widget appears at startup;
`/gekko-mode`, `/gekko-panel` and `Alt+G` respond; interactive confirmation works; the mode
notice reaches the model; and operation without a TUI neither opens dialogs nor fails tools. The
detail of the functional tests (F0–F4 + AC02, with commands and results) is in
`specs/001-pi-control-panel/tasks.md`, section "Verificación funcional en Pi 1.5.0 real".

## 9. Info panel: card rail + status bar (spec 008)

Replaces the four-line widget above the editor (spec 001) and the plain-text sidebar.
Spec, plan and evidence per AC: `specs/008-tui-panel/`.

**Rail (tmux sidebar).** A split on the right, 25 % of the width (36–48 columns), with seven or eight cards in
fixed order: GUARD, SCOPE, TÉCNICAS (techniques), SHELLS, HALLAZGOS (findings; only with a ledger), KB, SESIÓN (session), CAMBIOS (changes).
It hides itself under 140 columns and returns when the window grows; `GEKKO_SIDEBAR=0` turns it off. `tools/pi-hitl.sh` is the
only launcher: outside tmux it relaunches itself inside a new session and, if the rail does not open,
says why. `/gekko-sidebar` hides it if open and opens it if hidden (hidden by hand it does not reappear on resize). Folding resets on every launch.

| Input | Effect |
|---|---|
| click on a header | fold/unfold that card (focus does not leave Pi's pane) |
| `j`/`k` or arrows | move the cursor (with the rail focused) |
| `enter` / `space` | fold/unfold the card under the cursor |
| `a` / `z` | unfold / fold all |
| `1`–`8` | fold/unfold the card with that number |

**Status bar.** Replaces Pi's footer with one row: branch, mode, model, `ctx NN%/window`,
`(auto)` if automatic compaction is active, and turn. Without the rail (narrow terminal, outside
tmux, `GEKKO_SIDEBAR=0`) it adds guard, scope, shells and a block marker: the guard's state never
disappears at 80 columns. The folder that the original footer showed is lost.

**FINDINGS.** The card exists only if `GEKKO_FINDINGS` points to the engagement's `findings.jsonl`
(see `tools/pi-hitl.env.example`). It shows only counts per status: never the path or the fields
of a row. With the report module available it adds a `visor` row with its URL (§4c).

**Theme and colour.** Follows Pi's active theme; without valid roles it uses its own light/dark palette.
With `NO_COLOR` it emits no colour and each state is distinguished by glyph or word.

**Trust limits.** The rail is a read-only mirror of the launch's state file
(`.gekko-state/panel.<workspace>.<pid>.json`): no click or key changes mode, scope, policy or execution place.
That file can be written by any process of the operator (including the model), so the sidebar treats it as hostile data and **the
authority surface is the bar inside Pi**, not the rail. If the published state is older than 10 s the rail
shows `guard ?`: it detects a dead guard, not an impersonated one. Without a TUI (`-p`, json, rpc) the guard
neither writes that file nor mounts a bar; an rpc client receives the status row as a widget.

**Requirements and tests.** `setup.sh` requires tmux ≥ 3.2 and node ≥ 22.19 (`GEKKO_SETUP_CHECK_ONLY=1`
only verifies). The node packaged by Debian/Kali is compiled **without TypeScript support**
(`ERR_NO_TYPESCRIPT` even if the version suffices) and the rail imports `gekko-panel.ts` directly: you need
the official node (`nvm install 22` or nodejs.org) first in `PATH`. `setup.sh` detects it and offers to install it with nvm for
your user. After installing it you must **restart the shell** (new terminal) and close tmux (`tmux kill-server`): otherwise they still see
the old node. The mouse bindings the rail installs are restored on exit
(`tools/gekko-sidebar.sh --restore`).

```bash
GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types toolbox/gekko-guard.ts   # pure logic, count per AC
bash tools/tui-test.sh            # process: real sidebar in nested tmux, no model or network
bash tools/tui-test.sh --live     # + smoke against the Provider (GEKKO_LLM_URL/KEY, GEKKO_LIVE_MODEL)
```

Panel design changes: `tui-design` skill (`.claude/skills/tui-design/`) — critique on a
capture and cell-grid design before touching code.

## 10. Shell mirror (spec 011)

Each shell the agent opens with `session_new` shows up by itself as a tmux window next to Pi, without taking your focus,
and it is writable. Spec, plan and evidence per AC: `specs/011-espejo-shells/`. Only inside tmux and with a TUI.

- **Toolbox mode (spec 014):** a toolbox shell's window runs the tmux client **inside** the container
  (`docker exec -it`): what you type there executes inside. If the container stops, the window closes by itself.
- **Switching windows:** `Shift+→` / `Shift+←` (fallback `F3` / `F2`), no prefix, **only in Pi's tmux session**: in
  any other session the key reaches the application intact. The launcher installs them at start and restores your previous
  bindings on exit. `Shift+arrow` only arrives if your terminal sends it distinguishably (tested in kitty).
- **Switching it off:** the check in `/gekko-policy` (Alt+P), in the "vista" (view) block, separate from the pre-authorizations. It starts
  ticked, lives in memory and only affects new shells; windows already open are not closed.
- **Scroll:** each shell is born with `mouse on`: the wheel scrolls. Selecting text needs `Shift` + drag.
  If you are reading in scroll mode when the model does `session_send`, your scroll is cancelled and the text is sent.
- **`Ctrl+D`:** at the prompt it no longer closes the shell (`IGNOREEOF=10`; bash only, it does not protect a program running inside nor a
  typed `exit`). The normal way out of the mirror is switching windows.
- **Do not type secrets:** what you type in the mirror does not go through `session_send` or the ledger, the model reads it with
  `session_read` and it lands in the transcript.
- **Lifecycle:** mirror windows close when Pi's session changes and when Pi exits; the shells stay alive in tmux
  (reattach by hand with `tmux attach`). A Pi that died silently is swept by the launcher on exit.
