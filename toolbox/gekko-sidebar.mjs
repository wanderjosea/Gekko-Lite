#!/usr/bin/env node
// GEKKO sidebar (spec 008 T10) — capa fina de E/S del rail. Todo el dibujo y la interpretación de
// entradas son funciones puras de gekko-panel.ts; aquí solo hay archivos, stdin y stdout.
// Trata $GEKKO_PANEL_STATE como DATO HOSTIL (parsePanelState). Nunca escribe nada que el guard lea,
// salvo el heartbeat `.alive` (AC14). El click/tecla solo cambia el plegado (panel.ui.json).
import { readFileSync, writeFileSync, renameSync, unlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  parsePanelState, renderRail, resolveTheme, parseMouse, toggleAt, handleKey, parseUi, serializeUi, STALE_MS,
} from "./gekko-panel.ts";

const PATH = process.env.GEKKO_PANEL_STATE || ".gekko-state/panel.json";
const ALIVE = PATH + ".alive"; // heartbeat: el guard sabe que el rail está dibujado mientras este mtime esté fresco
const UI_PATH = join(dirname(PATH), "panel.ui.json");
const POLL_MS = Number(process.env.GEKKO_SIDEBAR_POLL_MS) || 400;
const STALE = Number(process.env.GEKKO_STALE_MS) || STALE_MS; // ventana de caducidad (pruebas); la aplica renderRail
const out = (s) => process.stdout.write(s);

const rd = (p) => { try { return readFileSync(p, "utf-8"); } catch { return null; } };
let ui = parseUi(rd(UI_PATH) ?? "");
let good = null;      // último estado válido
let bad = false;      // el último archivo leído no validó
let hits = [];
let last = "";
let lastDims = "";

function persistUi() {
  // tmp + rename: un sidebar que arranca a mitad de la escritura nunca lee un JSON a medias
  try { writeFileSync(UI_PATH + ".tmp", serializeUi(ui)); renameSync(UI_PATH + ".tmp", UI_PATH); } catch { /* best-effort */ }
}

function draw() {
  try { writeFileSync(ALIVE, ""); } catch { /* el heartbeat nunca rompe el render */ }
  const raw = rd(PATH);
  if (raw !== null) {
    const p = parsePanelState(raw);
    if (p.ok) { good = p.state; bad = false; } else bad = true;
  }
  const cols = process.stdout.columns || 36, rows = process.stdout.rows || 24;
  let lines;
  if (!good) {
    lines = [raw === null ? "esperando al guard…" : "estado inválido"];
    hits = [];
  } else {
    const r = renderRail(good, cols, bad ? rows - 1 : rows, resolveTheme(good), ui, Date.now(), STALE);
    lines = r.lines; hits = r.hits;
    if (bad) lines.push("! último estado válido (archivo ilegible)".slice(0, cols)); // sin recortar envuelve y desplaza el rail
  }
  const dims = cols + "x" + rows;
  const frame = dims + "\n" + lines.join("\n");
  if (frame === last) return;
  last = frame;
  let buf = dims !== lastDims ? "\x1b[2J" : "";
  lastDims = dims;
  lines.slice(0, rows).forEach((l, i) => { buf += `\x1b[${i + 1};1H${l}\x1b[0m\x1b[K`; });
  // con el pane lleno no hay nada debajo que borrar: pedir la fila rows+1 se recorta a la última y la borra
  out(buf + (lines.length < rows ? `\x1b[${lines.length + 1};1H\x1b[J` : ""));
}

const KEYS = { "\x1b[A": "up", "\x1b[B": "down", "\r": "enter", "\n": "enter", " ": "space" };
let rest = "";
function onData(d) {
  const s = rest + d.toString("utf-8");
  if (s.includes("\x03")) return cleanup();
  const m = parseMouse(s);
  rest = m.rest;
  const before = ui;
  for (const e of m.events) if (e.press && good) ui = toggleAt(good, ui, hits, e.y);
  // teclas: lo que queda tras quitar las secuencias de mouse
  const keys = s.slice(0, s.length - rest.length).replace(/\x1b\[<[\d;]*[Mm]/g, "");
  // una secuencia CSI entera es UNA tecla (Shift+Arriba, F6…): si no está en KEYS, handleKey la ignora
  for (const [k] of keys.matchAll(/\x1b\[[\d;]*[@-~]|[^]/g)) { if (!good) break; ui = handleKey(good, ui, KEYS[k] ?? k); }
  if (ui !== before) { persistUi(); last = ""; draw(); }
}

function cleanup() {
  try { unlinkSync(ALIVE); } catch { /* ya no está */ }
  try { if (process.stdin.isTTY) process.stdin.setRawMode(false); } catch { /* nada */ }
  out("\x1b[?1006l\x1b[?1000l\x1b[?25h\x1b[0m");
  process.exit(0);
}

out("\x1b[2J\x1b[?25l\x1b[?1000h\x1b[?1006h"); // limpiar, ocultar cursor, mouse SGR-1006
draw();
setInterval(draw, POLL_MS);
process.stdout.on("resize", () => { last = ""; draw(); });
if (process.stdin.isTTY) {
  try { process.stdin.setRawMode(true); process.stdin.resume(); process.stdin.on("data", onData); } catch { /* sin TTY utilizable */ }
}
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, cleanup);
