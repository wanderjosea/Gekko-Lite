// Estrés de la lógica pura de la spec 010 (sin red, sin tmux): objetivos, nombres, confinamiento, andamiaje y panel.
// Uso (desde la raíz del repo):  node --no-warnings --experimental-strip-types toolbox/tests/ws-stress-pure.mjs
import { mkdtempSync, rmSync, mkdirSync, symlinkSync, realpathSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const repo = process.argv[2] ?? new URL("../..", import.meta.url).pathname.replace(/\/$/, "");
const ws = await import(`${repo}/toolbox/gekko-workspace.ts`);
const guard = await import(`${repo}/toolbox/gekko-guard.ts`);
const panel = await import(`${repo}/toolbox/gekko-panel.ts`);

let bad = 0, n = 0;
const ok = (c, m) => { n++; if (!c) { bad++; if (bad <= 15) console.error("FAIL:", m); } };
let seed = 20261114;
const rnd = (k) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % k; };
const pick = (a) => a[rnd(a.length)];

// 1. Objetivos: 60 000 tokens aleatorios. Invariante: lo aceptado lo acepta el broker; nada se pierde ni se inventa.
const alpha = "0123456789./:,# -_abcXYZ[]%$\t\\'\"é∞";
const shapes = [
  () => `${rnd(300)}.${rnd(300)}.${rnd(300)}.${rnd(300)}`,
  () => `${rnd(256)}.${rnd(256)}.${rnd(256)}.${rnd(256)}/${rnd(40)}`,
  () => `0${rnd(256)}.${rnd(256)}.${rnd(256)}.${rnd(256)}`,
  () => `${rnd(256)}.${rnd(256)}.${rnd(256)}.${rnd(256)}:${rnd(70000)}`,
  () => `${rnd(256)}.${rnd(256)}.${rnd(256)}`,
  () => Array.from({ length: 1 + rnd(12) }, () => alpha[rnd(alpha.length)]).join(""),
  () => pick(["web", "db-01", "fe80::1", "::1", "a.b.c", "-x", "..", "10.0.0.1/032", "1.2.3.4/", "/24", "１.２.３.４", "1.2.3.4\u0000", "localhost"]),
];
for (let i = 0; i < 60000; i++) {
  const parts = Array.from({ length: 1 + rnd(4) }, () => pick(shapes)());
  const input = parts.join(pick([" ", ",", ", ", "  "]));
  let r;
  try { r = ws.parseTargets(input); } catch (e) { ok(false, `parseTargets lanzó con ${JSON.stringify(input)}: ${e.message}`); continue; }
  ok(r.targets.every((t) => guard.parseScopeLine(t.ip) !== null), `aceptó algo que el broker ignora: ${JSON.stringify(input)} → ${JSON.stringify(r.targets)}`);
  const text = ws.scopeFileText("x", r.targets);
  const entries = ws.scopeEntries(text);
  ok(entries.length === r.targets.length && entries.every((l) => guard.parseScopeLine(l) !== null), `scope.txt con líneas que el broker no cuenta: ${JSON.stringify(input)}`);
  ok(!text.split("\n").some((l) => /[\x00-\x08\x0b-\x1f\x7f]/.test(l)), `carácter de control escrito en scope.txt: ${JSON.stringify(input)}`);
  ok(r.targets.every((t) => !t.label || /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(t.label)), `etiqueta fuera de la lista blanca: ${JSON.stringify(input)}`);
}

// 2. Reemplazo de scope 300 veces seguidas: las entradas vigentes son siempre las últimas; nada vigente se pierde en comentarios mal cerrados.
let scope = ws.scopeFileText("x", [{ ip: "192.0.2.1" }, { ip: "192.0.2.2", label: "old" }]);
for (let i = 0; i < 300; i++) {
  const t = [{ ip: `198.51.100.${i % 250}` }, { ip: "203.0.113.0/24", label: `l${i}` }];
  scope = ws.replaceScopeText(scope, t, "2026-11-14");
  const e = ws.scopeEntries(scope);
  ok(e.length === 2 && e[0] === t[0].ip && e[1] === "203.0.113.0/24", `reemplazo ${i}: entradas vigentes incorrectas ${JSON.stringify(e)}`);
}
ok(scope.split("\n").filter((l) => l.includes("(reemplazado 2026-11-14)")).length === 2 + 299 * 2, "cada entrada anterior queda comentada una sola vez por reemplazo");

// 3. Nombres: 40 000 candidatos hostiles. Invariante: un nombre válido nunca sale de engagements/ ni contiene separadores.
const evil = ["..", "../x", "a/../b", "/etc", "a\\b", "a\u0000b", "none", "NONE", ".hidden", "-rf", "a b", "a\nb", "x".repeat(31), "x".repeat(32), "", "é", "a..b", "a.", "a-", "CON", "a/b"];
for (let i = 0; i < 40000; i++) {
  const name = rnd(3) === 0 ? pick(evil) : Array.from({ length: rnd(36) }, () => alpha[rnd(alpha.length)]).join("");
  if (!ws.validWorkspaceName(name)) continue;
  const dir = ws.workspaceDir("/r", name);
  ok(dir === `/r/engagements/${name}` && !/[\/\\\s\x00-\x1f]/.test(name) && !name.includes("..") && name.length <= 31 && name !== "none", `nombre válido peligroso: ${JSON.stringify(name)}`);
  ok(panel.redactSummary(name) === name, `el panel redactaría un nombre válido: ${JSON.stringify(name)}`);
}

// 4. Confinamiento con enlaces simbólicos reales.
const tmp = mkdtempSync(join(tmpdir(), "gkstress-"));
try {
  mkdirSync(join(tmp, "engagements", "real"), { recursive: true });
  mkdirSync(join(tmp, "fuera"));
  mkdirSync(join(tmp, "engagements-otro"));
  symlinkSync(join(tmp, "fuera"), join(tmp, "engagements", "escape"));
  symlinkSync(join(tmp, "engagements-otro"), join(tmp, "engagements", "hermano"));
  symlinkSync(join(tmp, "engagements", "real"), join(tmp, "engagements", "alias"));
  ok(ws.confined(tmp, "real", realpathSync) === true, "directorio real confinado");
  ok(ws.confined(tmp, "alias", realpathSync) === true, "enlace que queda dentro: confinado");
  ok(ws.confined(tmp, "escape", realpathSync) === false, "enlace que sale: no confinado");
  ok(ws.confined(tmp, "hermano", realpathSync) === false, "enlace a un hermano con el mismo prefijo: no confinado");
  ok(ws.confined(tmp, "no-existe", realpathSync) === false, "inexistente: no confinado");
  // 5. Andamiaje repetido 200 veces sobre archivos editados: nunca cambia un byte.
  const dir = join(tmp, "engagements", "real");
  ws.applyScaffold(dir, ws.scaffoldPlan("real", [{ ip: "192.0.2.9" }]));
  const before = ["scope.txt", "notes.md", "AUTHORIZATION.md", "loot/creds.md"].map((f) => readFileSync(join(dir, f), "utf-8"));
  for (let i = 0; i < 200; i++) ok(ws.applyScaffold(dir, ws.scaffoldPlan("real", [{ ip: `198.51.100.${i}` }])).length === 0, "una pasada repetida creó algo");
  const after = ["scope.txt", "notes.md", "AUTHORIZATION.md", "loot/creds.md"].map((f) => readFileSync(join(dir, f), "utf-8"));
  ok(JSON.stringify(before) === JSON.stringify(after) && existsSync(join(dir, "scripts")), "200 pasadas dejaron los archivos byte a byte iguales");
} finally { rmSync(tmp, { recursive: true, force: true }); }

// 6. Panel: nombres hostiles en GEKKO_WORKSPACE × anchos y altos. Invariantes: no lanza, ninguna línea pasa del ancho,
//    el indicador de workspace nunca queda vacío, un nombre válido nunca sale redactado.
const hostile = ["", "none", "x".repeat(31), "x".repeat(500), "a\x1b[31mrojo\x1b[0m", "tab\there", "nl\nx", "ws‮gnp.exe", "guard  ON", "é".repeat(40), "a".repeat(31) + "/../..", "\u0000", "   ", "acme-2026"];
const rt = panel.newRuntime(Date.now());
for (const name of hostile) for (const w of [1, 2, 4, 8, 20, 36, 48, 80, 120, 200, 300]) for (const h of [1, 3, 10, 40, 80]) {
  try {
    const st = panel.buildPanelState(rt, { workspace: name, branch: "spec/010-workspace", model: "m-test", ctxPct: 64, ctxWindow: 128000 }, Date.now());
    const round = panel.parsePanelState(JSON.stringify(st));
    ok(round.ok === true, `panel.json no vuelve a parsear con workspace=${JSON.stringify(name)}`);
    for (const open of [true, false]) {
      const { lines } = panel.renderRail(st, w, h, {}, { open: { sesion: open } }, Date.now());
      ok(lines.every((l) => panel.vlen(l) <= w), `rail: línea más ancha que ${w} con ${JSON.stringify(name)}`);
      ok(lines.length <= h, `rail: más de ${h} filas`);
      ok(!lines.some((l) => /[\x00-\x08\x0a-\x1a\x1c-\x1f\x7f‮]/.test(l.replace(/\x1b\[[0-9;]*m/g, ""))), `rail: carácter de control dibujado con ${JSON.stringify(name)}`);
    }
    for (const rail of [true, false]) {
      const bar = panel.renderBar(st, w, rail, []);
      ok(panel.vlen(bar) <= w, `barra: más ancha que ${w} con ${JSON.stringify(name)}`);
      if (!rail && w >= 80) ok(/ws \S|sin workspace/.test(bar), `barra de ${w} sin indicador de workspace con ${JSON.stringify(name)}: ${bar}`);
    }
    const ses = st.cards.find((c) => c.id === "sesion");
    ok(ses.summary.length > 0 && ses.rows.length >= 1 && (st.bar.workspace === null || st.bar.workspace.length <= 31), "SESIÓN sin fila/resumen de workspace o nombre > 31");
  } catch (e) { ok(false, `panel lanzó con workspace=${JSON.stringify(name)} w=${w} h=${h}: ${e.message}`); }
}

console.log(`${n} comprobaciones, ${bad} fallos`);
process.exitCode = bad ? 1 : 0;
