// RUN (igual que handler-harness.ts: shell-session.ts importa typebox al cargar):
//   cd toolbox && ln -sfn <instalación de pi>/node_modules node_modules \
//     && node --experimental-strip-types tests/mirror-stress.ts ; rm -f node_modules
// Estrés y bordes de la spec 011 (espejo de shells) contra los handlers REALES de shell-session.ts y tmux real.
// Todo corre en sockets propios bajo un directorio temporal: no toca el servidor tmux por defecto, ni Pi, ni la red.
// Sale 0 sólo si todas las comprobaciones pasan. No es parte del gate (como handler-harness.ts, GAP-27).
//   E1 20 shells a la vez · E2 cambio de sesión con 20 espejos · E3 30 ciclos crear/matar · E4 nombres hostiles
//   E5 envíos con el pane entrando a copy-mode · E6 cambio de sesión con una shell creándose · E7 costo · E8 tmux caído
import { execFileSync } from "node:child_process";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const DIR = mkdtempSync(join(tmpdir(), "gk011-"));
process.env.GEKKO_TMUX_DIR = join(DIR, "socks");
delete process.env.GEKKO_WORKSPACE_DIR;
const sh = (await import("../shell-session.ts")).default;
const { runtime } = await import("../gekko-panel.ts");
const tools: Record<string, any> = {}, handlers: Record<string, any[]> = {};
sh({ on(n: string, h: any) { (handlers[n] ??= []).push(h); }, registerTool(d: any) { tools[d.name] = d; } } as any);

const OP = join(DIR, "op"); // el tmux "del operador": donde vive Pi y donde nacen las ventanas espejo
const t = (sock: string, args: string[]): string => {
  try { return execFileSync("tmux", ["-f", "/dev/null", "-S", sock, ...args], { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"], timeout: 10000 }).trim(); }
  catch (e: any) { return "ERR:" + String(e.stderr || e.message).trim(); }
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const ctx = { mode: "tui", hasUI: true };
const txt = (r: any): string => r.content[0].text;
const NEW = (name: string, extra: any = {}) => tools.session_new.execute("i", { name, ...extra }, undefined, undefined, ctx).then(txt);
const SEND = (name: string, input: string) => tools.session_send.execute("i", { name, input }).then(txt);
const KILL = (name: string) => tools.session_kill.execute("i", { name }).then(txt);
const LIST = () => tools.session_list.execute("i", {}).then(txt);
const fire = (ev: string) => { for (const h of handlers[ev] ?? []) h({}, ctx); };
const wins = () => t(OP, ["list-windows", "-a", "-F", "#{window_id}\t#{window_name}\t#{@gekko_mirror}"]).split("\n").filter(Boolean).map((l) => l.split("\t"));
const mine = () => wins().filter((w) => w[2] === String(process.pid));
const say = (s: string) => console.log(s);
let bad = 0;
const check = (c: boolean, m: string) => { say(`${c ? "  ok   " : "  FALLA"} ${m}`); if (!c) bad++; };

function opUp() {
  t(OP, ["new-session", "-d", "-s", "op", "-x", "200", "-y", "50"]);
  process.env.TMUX = `${OP},${t(OP, ["display-message", "-p", "#{pid}"])},0`;
  process.env.TMUX_PANE = t(OP, ["display-message", "-p", "-t", "op:", "#{pane_id}"]);
}
try {
  opUp();
  runtime.mirror = true;
  const active0 = t(OP, ["display-message", "-p", "-t", "op:", "#{window_id}"]);

  say("E1 · 20 shells creadas a la vez");
  let t0 = Date.now();
  const rs = await Promise.all(Array.from({ length: 20 }, (_, i) => NEW(`c${i}`)));
  const ms1 = Date.now() - t0;
  check(rs.every((r) => r.startsWith("OK:")), `las 20 devuelven OK (${rs.filter((r) => !r.startsWith("OK:")).length} no) · ${ms1} ms en total`);
  await sleep(1500);
  const m1 = mine();
  check(m1.length === 20, `20 ventanas espejo propias (hay ${m1.length})`);
  check(new Set(m1.map((w) => w[1])).size === 20 && m1.every((w) => /^sh-c\d+$/.test(w[1])), "cada ventana tiene su nombre sh-cN, sin repetidos");
  const clients = t(OP, ["list-clients", "-F", "#{client_session}"]).split("\n").filter(Boolean).sort();
  check(clients.length === 20 && new Set(clients).size === 20 && clients.every((c) => /^c\d+$/.test(c)), `20 clientes, uno por shell, sin cruces (${clients.length} clientes, ${new Set(clients).size} sesiones distintas)`);
  let crossed = 0;
  for (const [wid, wname] of m1) {
    const cmd = t(OP, ["display-message", "-p", "-t", wid, "#{pane_start_command}"]);
    const sid = t(OP, ["display-message", "-p", "-t", `=${wname.slice(3)}:`, "#{session_id}"]);
    if (!cmd.includes(sid)) crossed++;
  }
  check(crossed === 0, `el comando de cada ventana apunta al id de su propia sesión (${crossed} cruzadas)`);
  check(t(OP, ["display-message", "-p", "-t", "op:", "#{window_id}"]) === active0, "la ventana activa del operador no cambió");

  say("E2 · cambio de sesión de Pi con 20 espejos abiertos");
  t0 = Date.now(); fire("session_start"); const ms2 = Date.now() - t0;
  await sleep(500);
  check(mine().length === 0, `no queda ninguna ventana propia (quedan ${mine().length}) · cierre en ${ms2} ms`);
  check(Array.from({ length: 20 }, (_, i) => t(OP, ["has-session", "-t", `=c${i}`])).every((r) => !r.startsWith("ERR:")), "las 20 shells siguen vivas");
  for (let i = 0; i < 20; i++) t(OP, ["kill-session", "-t", `=c${i}`]);

  say("E3 · 30 ciclos de crear y matar la misma shell");
  let cyc = 0;
  for (let i = 0; i < 30; i++) { const a = await NEW("churn"); const b = await KILL("churn"); if (a.startsWith("OK:") && b.startsWith("OK:")) cyc++; }
  await sleep(1000);
  check(cyc === 30, `30 ciclos OK (${cyc})`);
  check(mine().length === 0, `al morir la shell su ventana se cierra sola: 0 ventanas colgadas (hay ${mine().length})`);
  check(wins().length === 1, `el servidor del operador queda con 1 ventana (hay ${wins().length})`);

  say("E4 · nombres hostiles");
  const pwn = join(DIR, "pwned");
  const hostile = ["#[bg=red]rojo", `#(touch ${pwn})`, `$(touch ${pwn})`, "`touch " + pwn + "`", `a; touch ${pwn}`, "con espacios y\ttab", "x".repeat(300), "ñandú-日本-🚀", "-t", "--", "a\nb", "#{pane_id}", "'\"\\"];
  let created = 0, badNames = 0;
  for (const n of hostile) if ((await NEW(n)).startsWith("OK:")) created++;
  await sleep(1000);
  for (const w of mine()) if (!/^sh-[A-Za-z0-9_-]{0,29}$/.test(w[1])) badNames++;
  check(!existsSync(pwn), "ningún nombre ejecutó nada (no existe el archivo testigo)");
  check(badNames === 0, `todas las ventanas espejo tienen nombre de lista blanca (${mine().length} ventanas, ${badNames} fuera de regla)`);
  say(`         ${created}/${hostile.length} nombres hostiles llegaron a crear shell (al resto lo rechaza session_new o tmux)`);
  fire("session_start"); await sleep(300);
  t(OP, ["kill-server"]); rmSync(OP, { force: true }); opUp();

  say("E5 · 25 envíos del modelo con el pane entrando a copy-mode cada 50 ms");
  await NEW("race");
  const pane = t(OP, ["display-message", "-p", "-t", "=race:", "#{pane_id}"]);
  let stop = false;
  const toggler = (async () => { while (!stop) { t(OP, ["copy-mode", "-t", pane]); await sleep(50); } })();
  const res: string[] = [];
  for (let i = 0; i < 25; i++) res.push(await SEND("race", `echo M_${i}_$((40+2))`));
  stop = true; await toggler;
  t(OP, ["send-keys", "-t", pane, "-X", "cancel"]); await sleep(500);
  const hist = t(OP, ["capture-pane", "-p", "-J", "-S", "-", "-t", pane]);
  let ran = 0, twice = 0, silent = 0, failed = 0;
  for (let i = 0; i < 25; i++) {
    const n = (hist.match(new RegExp(`^M_${i}_42$`, "gm")) ?? []).length;
    const reportedFail = res[i].startsWith("FAIL");
    if (n >= 1) ran++;
    if (n > 1) twice++;
    if (reportedFail) failed++;
    if (n === 0 && !reportedFail) silent++; // el error caro: decir que se envió y no haberlo enviado
  }
  say(`         ejecutados ${ran}/25 · informados como FAIL ${failed} · ejecutados dos veces ${twice} · perdidos en silencio ${silent}`);
  check(twice === 0, "ningún comando se ejecutó dos veces");
  check(silent === 0, "ningún envío se perdió en silencio (lo que no se ejecutó, se informó como FAIL)");
  fire("session_start"); await sleep(300); t(OP, ["kill-session", "-t", "=race"]);

  // Se mide de a UNA shell: con varias seguidas, el cambio de sesión siguiente cierra lo que dejó el anterior y tapa el defecto.
  say("E6 · cambio de sesión de Pi mientras una shell se está creando");
  let left = 0, adopted = 0, runs = 0;
  for (const delay of [0, 5, 10, 20, 30, 60, 120]) {
    for (let i = 0; i < 3; i++) {
      const name = `f${delay}x${i}`;
      const p = NEW(name);
      await sleep(delay);
      fire("session_start");                       // el operador hace /new con la shell todavía en vuelo
      await p; await sleep(400);
      runs++;
      left += mine().length;                       // ventana espejo que sobrevivió al cambio de sesión
      // sólo la línea "propias (verificadas): …": la de no atribuidas también contiene la palabra "propias"
      if (new RegExp(`^propias \\(verificadas\\):[^\\n]*\\b${name}\\b`, "m").test(await LIST())) adopted++; // shell que la sesión nueva heredó como propia
      for (const [wid] of mine()) t(OP, ["kill-window", "-t", wid]);
      fire("session_start");
      t(OP, ["kill-session", "-t", `=${name}`]);
    }
  }
  say(`         ${runs} corridas (retardos 0–120 ms): ${left} ventanas sobrevivieron al cambio · ${adopted} shells quedaron como propias de la sesión nueva`);
  check(left === 0, "ninguna ventana espejo sobrevive al cambio de sesión");
  check(adopted === 0, "ninguna shell creada a caballo del cambio queda como propia de la sesión nueva");

  say("E7 · costo en tiempo");
  const timeIt = async (on: boolean, tag: string) => { runtime.mirror = on; const a = Date.now(); for (let i = 0; i < 10; i++) await NEW(`${tag}${i}`); return (Date.now() - a) / 10; };
  const off = await timeIt(false, "off"), on = await timeIt(true, "on");
  runtime.mirror = true;
  say(`         session_new: ${off.toFixed(0)} ms sin espejo · ${on.toFixed(0)} ms con espejo (+${(on - off).toFixed(0)} ms)`);
  const a = Date.now(); await SEND("on0", "true");
  say(`         session_send: ${Date.now() - a} ms (incluye los 800 ms de espera que ya tenía)`);

  say("E8 · el tmux del operador se cae con espejos abiertos");
  t(OP, ["kill-server"]);
  t0 = Date.now(); fire("session_start"); const ms8 = Date.now() - t0;
  check(ms8 < 5000, `el cierre no se cuelga: ${ms8} ms`);
  delete process.env.TMUX; delete process.env.TMUX_PANE;
  const r8 = await NEW("after", { socket: "lbl" });
  check(r8.startsWith("OK:"), `fuera de tmux se sigue pudiendo crear una shell: ${r8.split("\n")[0]}`);
} finally {
  for (const s of [OP, join(DIR, "socks", "lbl")]) t(s, ["kill-server"]);
  rmSync(DIR, { recursive: true, force: true });
}
say(bad === 0 ? "RESULTADO: todo bien" : `RESULTADO: ${bad} comprobación(es) fallida(s)`);
process.exitCode = bad === 0 ? 0 : 1;
