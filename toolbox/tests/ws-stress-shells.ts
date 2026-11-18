// Estrés de las shells del agente con workspace (spec 010). Handlers REALES de shell-session.ts + tmux real en un
// socket privado; `pi` falso; sin red. Necesita @sinclair/typebox, igual que handler-harness.ts (ver su cabecera):
//   cd toolbox && ln -sfn <instalación-de-pi>/node_modules node_modules \
//     && node --experimental-strip-types tests/ws-stress-shells.ts ; rm -f node_modules
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const DIR = mkdtempSync(join(tmpdir(), "gkss-"));
process.env.GEKKO_TMUX_DIR = join(DIR, "socks");
const wsA = join(DIR, "engagements", "alfa"), wsB = join(DIR, "engagements", "beta");
mkdirSync(wsA, { recursive: true }); mkdirSync(wsB, { recursive: true });
const sh = (await import("../shell-session.ts")).default;
const tools: Record<string, any> = {};
sh({ on() {}, registerTool(d: any) { tools[d.name] = d; } } as any);

const SOCK = "st", sockPath = join(process.env.GEKKO_TMUX_DIR, SOCK);
const txt = (r: any): string => r.content[0].text;
const tm = (args: string[]): string => { try { return execFileSync("tmux", ["-S", sockPath, ...args], { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }); } catch { return ""; } };
const sessions = (): Record<string, string> => Object.fromEntries(tm(["list-sessions", "-F", "#{session_name}\t#{pane_current_path}"]).split("\n").filter(Boolean).map((l) => l.split("\t") as [string, string]));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
let fail = 0;
const ok = (c: boolean, m: string) => { console.log(`${c ? "[ok]  " : "[FAIL]"} ${m}`); if (!c) fail++; };
const newS = (name: string) => tools.session_new.execute("x", { name, socket: SOCK });

// 1. 40 creaciones CONCURRENTES en el workspace A
process.env.GEKKO_WORKSPACE_DIR = wsA;
const t0 = Date.now();
const r1 = await Promise.all(Array.from({ length: 40 }, (_, i) => newS(`a${i}`)));
const s1 = sessions();
ok(r1.every((r) => txt(r).startsWith("OK")), `40 session_new concurrentes: todas OK (${Date.now() - t0} ms)`);
ok(Object.keys(s1).length === 40 && Object.values(s1).every((p) => p === realpathSync(wsA)), "las 40 nacieron en el workspace A (directorio real reportado por tmux)");

// 2. Cambio de workspace entre llamadas (el entorno se lee en cada una): 20 más en B, intercaladas con 20 en A
const mixed = await Promise.all(Array.from({ length: 40 }, (_, i) => { process.env.GEKKO_WORKSPACE_DIR = i % 2 ? wsB : wsA; return newS(`m${i}`); }));
const s2 = sessions();
ok(mixed.every((r) => txt(r).startsWith("OK")), "40 creaciones alternando workspace entre llamadas: todas OK (ninguna se mata por veredicto cruzado)");
ok(Array.from({ length: 40 }, (_, i) => s2[`m${i}`] === realpathSync(i % 2 ? wsB : wsA)).every(Boolean), "cada una nació en el workspace vigente EN SU llamada");

// 3. Mismo nombre 12 veces a la vez: gana una sola, y las perdedoras no matan a la ganadora
process.env.GEKKO_WORKSPACE_DIR = wsA;
const dup = await Promise.all(Array.from({ length: 12 }, () => newS("dup")));
const wins = dup.filter((r) => txt(r).startsWith("OK")).length;
await sleep(300);
ok(wins === 1, `colisión de nombre concurrente: exactamente una OK (fueron ${wins})`);
ok(sessions()["dup"] === realpathSync(wsA), "la sesión ganadora sigue viva tras las 11 perdedoras");

// 4. El trabajo de las shells cae en el workspace: 30 shells escriben un archivo cada una
for (let i = 0; i < 30; i++) await tools.session_send.execute("x", { name: `a${i}`, socket: SOCK, input: `echo ${i} > out-${i}.txt`, enter: true }).catch(() => {});
await sleep(800);
ok(readdirSync(wsA).filter((f) => /^out-\d+\.txt$/.test(f)).length === 30, "30 archivos escritos por 30 shells quedaron en el workspace A");

// 5. El workspace desaparece a mitad de camino: 15 intentos, ninguno deja sesión
const before = Object.keys(sessions()).length;
const gone = join(DIR, "engagements", "gone"); mkdirSync(gone); process.env.GEKKO_WORKSPACE_DIR = gone; rmSync(gone, { recursive: true });
const r5 = await Promise.all(Array.from({ length: 15 }, (_, i) => newS(`g${i}`)));
ok(r5.every((r) => txt(r).startsWith("FAIL")), "15 session_new con el workspace borrado: todas FAIL");
ok(Object.keys(sessions()).length === before, `ninguna sesión nueva quedó viva (siguen ${before})`);
ok(!Object.values(sessions()).some((p) => p === process.env.HOME), "ninguna shell cayó a $HOME");

// 6. Sin workspace: sigue funcionando como antes
delete process.env.GEKKO_WORKSPACE_DIR;
ok(txt(await newS("plain")).startsWith("OK") && sessions()["plain"] === process.cwd(), "sin workspace: la shell nace en el directorio del proceso, como hoy");

// 7. Cierre: se matan las 82 y no queda nada
const names = Object.keys(sessions());
const kills = await Promise.all(names.map((n) => tools.session_kill.execute("x", { name: n, socket: SOCK })));
await sleep(300);
ok(kills.every((r) => txt(r).startsWith("OK")), `session_kill de ${names.length} sesiones: todas OK`);
ok(Object.keys(sessions()).length === 0, "no queda ninguna sesión viva");
tm(["kill-server"]); rmSync(DIR, { recursive: true, force: true });
console.log(fail === 0 ? "ESTRÉS DE SHELLS: TODO OK" : `ESTRÉS DE SHELLS: ${fail} FALLO(S)`);
process.exit(fail ? 1 : 0);
