// RUN (needs @sinclair/typebox, which shell-session.ts imports at load):
//   cd toolbox && ln -sfn <your-pi-install>/node_modules node_modules \
//     && node --experimental-strip-types tests/<this-file> ; rm -f node_modules
// e.g. <your-pi-install> = ~/.pi/agent/install/releases/1.5.0 . Real tmux required; no model, no network.
// MODEL-INDEPENDENT tests closing the two gaps the Stop-hook flagged:
//  (A) F24 — session_read re-verifies ours() on EVERY poll iteration: a server restart MID-POLL that
//      recycles our pane id must fail CLOSED (staleSession) and NEVER leak the stranger's pane output.
//  (B) refresh real-tmux — the shipped refreshShells (where the `probe` ReferenceError lived) runs
//      against a REAL tmux server: a live session → state "open" AND s.process populated via
//      currentProcess(s.sessionId,…) (the line that crashed); killed → "closed". End-to-end, no model.
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { newRegistry, registerShell, refreshShells, type TmuxDriver } from "../gekko-panel.ts";

const DIR = mkdtempSync(join(tmpdir(), "gkf24-"));
process.env.GEKKO_TMUX_DIR = DIR;
const sh = (await import("../shell-session.ts")).default;
const tools: Record<string, any> = {};
sh({ on() {}, registerTool(d: any) { tools[d.name] = d; } } as any);

const txt = (r: any): string => r.content[0].text;
const raw = (sockPath: string, args: string[]): string => { try { return execFileSync("tmux", ["-S", sockPath, ...args], { encoding: "utf-8" }); } catch (e: any) { return `ERR:${e.status ?? e.code}`; } };
const tmuxS = (sock: string, args: string[]): string => raw(join(DIR, sock), args);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
let fail = 0;
const ok = (c: boolean, m: string) => { console.log(`${c ? "[ok]" : "[FAIL]"} ${m}`); if (!c) fail++; };

// ── (A) F24: session_read mid-poll re-verify ───────────────────────────────────────────────────
await tools.session_new.execute("i", { name: "rdr", socket: "rs" });        // ours: server P1, session $0, pane %0
const pid1 = tmuxS("rs", ["display-message", "-p", "-t", "rdr", "#{pid}"]).trim();
// Fire the restart DURING the first inter-poll sleep (iter 1 at t~0 → sleep 3000ms → iter 2 at t~3000):
const restart = sleep(1200).then(() => {
  tmuxS("rs", ["kill-server"]);                                              // whole server dies → our $0/%0 gone
  tmuxS("rs", ["new-session", "-d", "-s", "rdr"]);                           // FRESH server: P2, recycles $0/%0
  tmuxS("rs", ["send-keys", "-t", "rdr", "echo STRANGER_SECRET_F24", "Enter"]); // stranger writes into recycled %0
});
// until never matches → it polls; iter 2 (t~3s) runs AFTER the restart:
const rr = txt(await tools.session_read.execute("i", { name: "rdr", socket: "rs", until: "MATCH_NEVER_XYZ", timeout_s: 8 }));
await restart;
const pid2 = tmuxS("rs", ["display-message", "-p", "-t", "rdr", "#{pid}"]).trim();
ok(!!pid1 && !!pid2 && pid1 !== pid2, `F24: el server reinició mid-poll (pid ${pid1}→${pid2}, $0/%0 reciclados idénticos)`);
ok(/ya no es la sesión/.test(rr), `F24: session_read falló CERRADO a mitad de poll (staleSession) → "${rr.split("\n")[0]}"`);
ok(!/STRANGER_SECRET_F24/.test(rr), "F24: NO filtró el pane del EXTRAÑO (sin STRANGER_SECRET en el output) — el re-check por iteración lo atrapó antes del capture");

// ── (B) refreshShells against REAL tmux: the probe-fix line, end to end ──────────────────────────
const SP = join(DIR, "refresh");
const realDriver: TmuxDriver = {
  serverId: () => "ok",                                                      // non-null → tmux available
  alive: (target, serverId, serverPid) => {
    const r = raw(serverId, ["display-message", "-p", "-t", target, "#{pid}"]);
    if (r.startsWith("ERR")) return false;
    return !serverPid || r.trim() === serverPid;
  },
  currentProcess: (target, serverId) => {
    const r = raw(serverId, ["display-message", "-p", "-t", target, "#{pane_current_command}"]);
    return r.startsWith("ERR") ? null : (r.trim() || null);
  },
  capture: () => "",
};
tmuxS("refresh", ["new-session", "-d", "-s", "live", "sleep", "300"]);        // real pane runs `sleep`
const sid = raw(SP, ["display-message", "-p", "-t", "live", "#{session_id}"]).trim();
const pane = raw(SP, ["display-message", "-p", "-t", "live", "#{pane_id}"]).trim();
const spid = raw(SP, ["display-message", "-p", "-t", "live", "#{pid}"]).trim();
const reg = newRegistry();
const t0 = 1_000_000;
registerShell(reg, { name: "live", serverId: SP, sessionId: sid, paneId: pane, piSessionId: "local", serverPid: spid, owner: "gekko-session", createdAt: t0, lastInteraction: t0 });
let threw = false;
try { refreshShells(reg, realDriver, t0 + 1000); } catch (e: any) { threw = true; console.log("  threw:", e.message); }
ok(!threw, "refresh: refreshShells(real tmux) NO lanza (la regresión currentProcess(probe,…) está cerrada)");
ok(reg.shells[0].state === "open", `refresh: sesión viva → state "open" (fue "${reg.shells[0].state}")`);
ok(!!reg.shells[0].process && reg.shells[0].process.length > 0, `refresh: s.process poblado vía currentProcess(s.sessionId,…) = ${JSON.stringify(reg.shells[0].process)} (la línea exacta que crasheaba)`);
tmuxS("refresh", ["kill-session", "-t", "live"]);
refreshShells(reg, realDriver, t0 + 2000);
ok(reg.shells[0].state === "closed", `refresh: tras kill → state "closed" (fue "${reg.shells[0].state}")`);

// cleanup
tmuxS("rs", ["kill-server"]); tmuxS("refresh", ["kill-server"]);
console.log(fail === 0 ? "\n[PASS] F24 mid-poll re-verify + refresh real-tmux (determinista, sin modelo)" : `\n[FAIL] ${fail} aserción(es)`);
process.exit(fail === 0 ? 0 : 1);
