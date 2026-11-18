---
name: tui-design
description: Design, critique or redesign a Gekko terminal UI surface — the info panel/sidebar, cards, status bar, overlays, themes. Use when asked to "design the panel", "evaluate the TUI", "polish the sidebar/status bar", "make it look like X", or before implementing any change to `toolbox/gekko-panel.ts`, `toolbox/gekko-sidebar.mjs` or the banner. Produces a critique and a cell-grid design, never product code.
---

# TUI design (Gekko)

Original Gekko skill. Method inspired by gentle-shell's `tui-design` skill (MIT repo; skill
Apache-2.0, methodology credited there to pbakaus/impeccable). No text copied.

## Hard rules
1. **Judge from a capture, not from code.** Capture before and after every change:
   `tmux new-session -d -x <cols> -y <rows>` → run the surface → `tmux capture-pane -p -e`.
   Sizes: 180x50, 140x40, 80x24. A claim about how it looks without a capture is a guess.
2. **Operator's vocabulary.** An IDE/pentest operator must recognise every label. Familiar beats clever.
3. **Every row costs.** No blank rows, no nested boxes for hierarchy, no decoration that carries no state.
4. **One fact, one place** per screen. The status bar does not repeat a card.
5. **Readable without colour** and at 80 columns (spec 001 AC14 stays binding). State is never
   carried by colour alone: pair it with a glyph or word.
6. **Render is pure.** No I/O in a render path; a renderer is `(state, width, theme) → lines + hit map`
   so the selftest can assert it.
7. **The panel shows, the operator decides.** A click may collapse/expand or navigate. It must
   never change mode, scope or policy from outside Pi (authority stays in the guard's operator callbacks).
8. **A mockup must fit the cell grid.** Monospace, box-drawing, one glyph family (`● ○ ✓ ✗ ▸ ▾ …`), no emoji in chrome.

## Craft floor
- Type roles (max 4): title = bold, label = dim, value = normal, alert = accent+glyph.
- Card header: `▾ NAME  count`; collapsed: `▸ NAME  summary`. Finished items fold into one summary row.
- Group by proximity → then a rule → a box only if the region is interactive or scrolls.
- Rails truncate with `…`; only prose wraps. Key/value pairs align in one column.
- Colour = roles, not swatches: `accent`, `ok`, `warn`, `danger`, `dim`, `border`. One accent
  (brand lime `#C0F425` on dark). Light mode is designed, not inverted: check contrast on a pale background.
- Status bar: one row; stable left (branch, mode), volatile right (ctx %, turn/caps).
- Breakpoint: below it the rail is not drawn; its essentials fold into the status bar.

## Steps
1. **Target** — name ONE surface and ONE intent (shape · layout · quieter · bolder · colorize · harden · adapt).
2. **Capture** the current state at the three sizes.
3. **Critique** — score 0–4 each: hierarchy, density, consistency, state visibility, legibility
   without colour, narrow-width behaviour, interaction discoverability, error/empty/overflow states,
   render cost, fit to the operator's task. List findings as P0–P3 with the capture line that shows it.
4. **Design** — cell-grid mockups (dark and light, three sizes), role tokens, card list with the
   data source of every field (a field with no source is dropped, not faked), interaction map
   (click targets, keys), and the states: empty, long, 1000 items, error.
5. **Verify** (after implementation) — re-capture, re-score, at most three rounds.

## Output contract
Target · intent · captures (before/after) · score table · findings by severity (fixed/open) ·
mockups · tokens · data-source table · interaction map · what was NOT checked.
