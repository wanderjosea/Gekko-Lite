/**
 * shell-session — persistent interactive terminal sessions for pi, backed by tmux.
 *
 * Fixes the one-shot-bash limitation: reverse-shell listeners, interactive
 * evil-winrm / ssh / msfconsole, and async callbacks. Sessions persist across
 * tool calls (tmux server is a daemon). Non-blocking by design.
 *
 *   pi -e /opt/pi-ext/shell-session.ts ...
 *
 * Optional convenience for Pi's native toolset. It is not a security boundary;
 * containment belongs to the host/container and its network policy.
 *
 * Spec 001 (plan §5): tmux calls are ASYNC with a timeout (the operator can toggle mode
 * during long waits — the event loop is never blocked), results are STRUCTURED (success,
 * stdout, stderr, timeout — not errors-as-text), a name collision NEVER kills the existing
 * session, and creation/close are announced as successful only when VERIFIED. Ownership
 * identity (server socket, session id, pane id, pi session) is recorded only after a verified
 * creation — a name is not identity. Collision/verify decisions are the gate-tested pure
 * functions from gekko-panel.ts, so this wiring stays thin.
 */
import { type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { execFile, execFileSync } from "node:child_process";
import { accessSync, constants, lstatSync, mkdirSync, readdirSync, realpathSync, statSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  creationResult, createdResult, killResult, sendKeysText, mirrorDecision, mirrorWindowArgs, mirrorDetachArgs, sendArgs, switchVerdict,
  registerShell, touchShell, runtime, validSocketLabel, socketsToProbe, execSessionDecision, execStateAtLoad, containerIdentityVerdict,
  samePlace, placesToProbe, otherPlaceShells, CONTAINER_ID_RE,
  type AliveResult, type OpResult, type ShellPlace,
} from "./gekko-panel.ts";
import { newSessionArgs, cwdVerdict, tmuxCommand, parseExecMode, socketDir, toolboxName, SHELL_NAME_RE } from "./gekko-workspace.ts";

type Tmux = { ok: boolean; stdout: string; stderr: string; timedOut: boolean; code: number | null; noExec: boolean };
// Multi-socket (AC09): a session is identified by (socket, name). `socket` is an optional LABEL — a
// bare name, NOT a path — selecting a dedicated tmux server so agent shells stay isolated from the
// operator's own tmux; omitted = the default/inherited server. The same name on a DIFFERENT socket is
// a DIFFERENT session and must never be confused for it. The label is confined to SOCK_DIR (0700) and
// validated to [A-Za-z0-9_@-] (no '/', no '.', no leading '-'): `tmux -S <path>` REPLACES any regular
// file at that path with a socket, so letting the agent pick an arbitrary path is a silent
// data-destruction / option-injection primitive. A label can neither escape SOCK_DIR nor ever spell
// the default server's socket_path, so (label,name) maps 1:1 to (server,name) and never aliases it.
const badSocket = (s?: string): boolean => !validSocketLabel(s); // gate-tested label rule (gekko-panel.ts)
// Cada shell vive en un LUGAR (host o contenedor) y su directorio de sockets sale de ese lugar, en cada llamada: el modo
// puede cambiar con Pi abierto. `socketDir` lanza si en `os` no hay sitio fuera del workspace.
const sockDirFor = (place: ShellPlace): string => socketDir(process.env, tmpdir(), place.mode);
// En modo toolbox el directorio de sockets vive dentro del mount escribible: un proceso del contenedor puede
// reemplazarlo por un enlace simbólico. Se rehúsa antes de listarlo o usarlo (límite: no cubre la carrera entre
// esta comprobación y el uso por tmux).
function assertSockDirNotLink(dir: string): void {
  try {
    if (lstatSync(dir).isSymbolicLink()) throw new Error(`el directorio de sockets ${dir} es un enlace simbólico: no se usa`);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
}
// Resuelve la etiqueta a su ruta sin crear nada; `ensureSockDir` lo crea sólo cuando ya se validó el workspace.
const sockPath = (label: string | undefined, place: ShellPlace): string | undefined => {
  if (!label) return undefined; // default/inherited server
  const dir = sockDirFor(place);
  assertSockDirNotLink(dir);
  return join(dir, label);
};
const ensureSockDir = (place: ShellPlace): void => {
  try { mkdirSync(sockDirFor(place), { recursive: true, mode: 0o700 }); } catch { /* best-effort; tmux surfaces a real failure */ }
};
const ownKey = (socket: string | undefined, name: string): string => `${socket ?? ""}\u0000${name}`;
const HOST: ShellPlace = { mode: "os" };
// El lugar vigente según el entorno, leído al llamar (el guard lo reescribe al cambiar de modo).
function placeInForce(): ShellPlace {
  const mode = parseExecMode(process.env.GEKKO_EXEC ?? null);
  if (!mode) throw new Error("GEKKO_EXEC inválido");
  return mode === "toolbox" ? { mode, container: process.env.GEKKO_TOOLBOX } : { mode };
}
function run(file: string, args: string[], timeoutMs: number): Promise<Tmux> {
  return new Promise((resolve) => {
    execFile(file, args, { encoding: "utf-8", timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 }, (err: any, stdout, stderr) => {
      if (!err) return resolve({ ok: true, stdout, stderr, timedOut: false, code: 0, noExec: false });
      // only a timeout-kill counts as timedOut — a maxBuffer overflow also kills but is NOT a timeout.
      const maxbuf = err.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER";
      resolve({
        ok: false, stdout: stdout ?? "", stderr: stderr ?? "",
        timedOut: err.killed === true && !maxbuf,
        code: typeof err.code === "number" ? err.code : null,
        noExec: err.code === "ENOENT",
      });
    });
  });
}
// `place` = dónde nació la shell sobre la que se opera; sin él, el lugar vigente. Nunca se maneja una shell por el otro lugar.
function tmux(args: string[], timeoutMs = 15000, socket?: string, place?: ShellPlace): Promise<Tmux> {
  // `socket` here is the resolved SOCKET PATH (from sockPath), already confined — never a raw label.
  const full = socket ? ["-S", socket, ...args] : args;
  let command;
  try {
    const where = place ?? placeInForce();
    command = tmuxCommand(where.mode, where.container, full);
  } catch (e) { return Promise.resolve({ ok: false, stdout: "", stderr: String(e), timedOut: false, code: null, noExec: false }); }
  return run(command.file, command.args, timeoutMs);
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const text = (t: string) => ({ content: [{ type: "text" as const, text: t }] });
const result = (r: OpResult, extra = "") => text(`${r.ok ? "OK" : "FAIL"}: ${r.note}${extra ? `\n${extra}` : ""}`);
// Ownership gate (AC12): send/read/kill act ONLY on sessions THIS run verified-created. An
// unattributed session (pre-existing, from Bash/subagents, or after a reload) is never driven,
// read or killed by name — matches isOwn()/captureOwn() in gekko-panel.ts.
const notOwned = (name: string) =>
  text(`FAIL: '${name}' no es una sesión creada y verificada por esta corrida — no se maneja (las sesiones no atribuidas sólo se listan, no se tocan). Creála con session_new.`);
// Identity went stale: we have an owned entry but the live server/session no longer matches it (the
// session was closed, or the tmux server restarted and recycled its ids). FAIL CLOSED — never drive,
// read or kill whatever re-took the name; that would be acting on a stranger (see ours()).
const staleSession = (name: string) =>
  text(`FAIL: '${name}' ya no es la sesión que esta corrida creó (fue cerrada, o el servidor tmux se reinició y recicló los ids). No se maneja una sesión que re-tomó el nombre. Volvé a crearla con session_new.`);

// Read-only liveness check → AliveResult the pure decisions understand.
async function alive(name: string, socket: string | undefined, place: ShellPlace): Promise<AliveResult> {
  const r = await tmux(["has-session", "-t", name], 5000, socket, place);
  if (r.ok) return true;
  if (r.noExec) return { error: "no-exec" };
  if (r.timedOut) return { error: "timeout" };
  if (/denied|permission/i.test(r.stderr)) return { error: "denied" };
  return false; // "can't find session" / "no server running" → not alive
}

// Ownership registry: a shell is ours only after a VERIFIED creation (plan §5, AC09).
type Owned = { name: string; socket?: string; place: ShellPlace; serverId: string; serverPid: string; serverStart: string; sessionId: string; paneId: string; createdAt: number; lastInteraction: number };
const owned = new Map<string, Owned>(); // keyed by ownKey(socket, name) — a name alone is NOT identity (AC09)

// Confirm OUR recorded session instance still exists before we drive/kill/claim it. tmux resets its
// $N session-id and %N pane-id counters to 0 whenever a NEW server starts on a socket path, so a
// stale `owned` entry (a session that died on its own, never cleared by our verified session_kill)
// could otherwise alias a stranger's brand-new session after a restart — killing or driving it, or
// listing it as ours. The server PID (#{pid}) is the per-instance discriminator that id-reuse can't
// forge (a new server is a new process). Returns false — callers FAIL CLOSED — when identity was
// never captured ("?"), the session id is gone, or the live server pid differs from the recorded one.
// One extra read-only tmux call; the costlier error here is a false "safe to act", so we verify hard.
async function ours(sp: string | undefined, own: Owned): Promise<boolean> {
  if (own.sessionId === "?" || own.serverPid === "?") return false; // never captured → cannot prove ours
  const r = await tmux(["display-message", "-p", "-t", own.sessionId, "#{pid}\t#{session_id}\t#{start_time}"], 5000, sp, own.place);
  if (!r.ok) return false; // our session id no longer resolves (gone, or server down) → not ours
  const [pid = "", sid = "", start = ""] = r.stdout.trim().split("\t");
  // start_time: after a container restart the new tmux server can get the same pid as the old one (pids restart in the netns).
  return pid === own.serverPid && sid === own.sessionId && start === own.serverStart; // same server INSTANCE and same session → ours
}

// Cuenta los session_start: un session_new que la capturó al empezar y la ve cambiada ya no pertenece a la sesión viva.
let sessionEpoch = 0;

// Mirror windows (spec 011) THIS process opened on the operator's tmux server. Only these are ever closed: a window
// marked by another Pi run is never enumerated or touched from here. Spec 014: each remembers where its shell lives.
type MirrorWindow = { windowId: string; place: ShellPlace; socketPath: string; sessionId: string };
const mirrorWindows: MirrorWindow[] = [];
// La ventana y su marca son SIEMPRE del tmux del host: con el lugar vigente en toolbox correrían dentro del contenedor.
const hostTmux = (args: string[], timeoutMs = 15000) => tmux(args, timeoutMs, undefined, HOST);
// Cerrar la ventana de una shell de la toolbox: `kill-window` solo deja al cliente adjunto DENTRO del contenedor (probado);
// desadjuntarlo antes hace que la ventana se cierre sola. `kill-window` queda de respaldo. Ya cerrada o con el servidor
// del operador caído no queda nada que cerrar: el fallo del respaldo se ignora a propósito.
const detachCommand = (w: MirrorWindow): string[] | null => (w.place.mode === "toolbox" && w.place.container ? mirrorDetachArgs(w.socketPath, w.sessionId, w.place.container) : null);
// Al salir: síncrono, con un tope TOTAL para todos los desadjuntados; lo que no entra se cierra sólo con `kill-window`.
const SHUTDOWN_DETACH_BUDGET_MS = 2000;
function closeMirrorWindows(): void {
  const deadline = Date.now() + SHUTDOWN_DETACH_BUDGET_MS;
  for (const w of mirrorWindows.splice(0)) {
    const detach = detachCommand(w), left = deadline - Date.now();
    if (detach && left > 0) { try { execFileSync("docker", detach, { timeout: left, stdio: "ignore" }); } catch { /* el respaldo de abajo cierra la ventana */ } }
    try { execFileSync("tmux", ["kill-window", "-t", w.windowId], { timeout: 2000, stdio: "ignore" }); } catch { /* already gone, or the operator's server is down: nothing left to close */ }
  }
}
async function closeMirrorWindow(w: MirrorWindow): Promise<void> {
  const detach = detachCommand(w);
  if (detach) await run("docker", detach, 3000);
  await hostTmux(["kill-window", "-t", w.windowId], 2000);
}
// En session_start: asíncrono, el proceso sigue vivo y la espera no bloquea el bucle de eventos.
async function closeMirrorWindowsAsync(): Promise<void> {
  for (const w of mirrorWindows.splice(0)) await closeMirrorWindow(w);
}

// The window goes to the OPERATOR's server: tmux without -S/-t inherits $TMUX/$TMUX_PANE from Pi, so it lands in Pi's
// own session without taking the focus. Read at call time, never at load. Only the argv from the pure function is used.
async function openMirrorWindow(name: string, socketPath: string, sessionId: string, tui: boolean, epochAtCall: number, place: ShellPlace): Promise<void> {
  const inTmux = !!process.env.TMUX && !!process.env.TMUX_PANE;
  if (!mirrorDecision({ created: true, inTmux, tui, enabled: runtime.mirror, socketPath, sessionId }).open) return;
  const win = await hostTmux(mirrorWindowArgs(name, socketPath, sessionId, place.mode === "toolbox" ? place.container : undefined));
  const windowId = win.stdout.trim();
  if (!win.ok || !/^@\d+$/.test(windowId)) return;
  // Pi cambió de sesión mientras se abría: el barrido de session_start ya pasó y no la conoce, así que se cierra aquí.
  if (!switchVerdict(epochAtCall, sessionEpoch).ok) { await closeMirrorWindow({ windowId, place, socketPath, sessionId }); return; }
  mirrorWindows.push({ windowId, place, socketPath, sessionId });
  await hostTmux(["set-option", "-w", "-t", windowId, "@gekko_mirror", String(process.pid)]);
}

export default function (pi: ExtensionAPI) {
  // One client per session: never carry owned shells across a session switch. Clear ownership so a
  // later engagement cannot session_send/read/kill into a prior engagement's live shell. The tmux
  // sessions themselves persist (daemons) but become UNATTRIBUTED — session_list shows them, never
  // drives them. Also clears the shared registry the guard renders (idempotent with the guard's own
  // session_start reset; done here too so it holds even if the guard is not loaded).
  pi.on("session_start", () => { sessionEpoch++; owned.clear(); runtime.shells.shells = []; return closeMirrorWindowsAsync(); });
  pi.on("session_shutdown", () => closeMirrorWindows());
  // Spec 014 (D3): el estado de la toolbox al cargar; el guard hace lo mismo con la misma función (idempotente).
  try { runtime.exec = execStateAtLoad(runtime.exec, placeInForce().mode, process.env.GEKKO_TOOLBOX); } catch { /* GEKKO_EXEC inválido: session_new y tmux() lo rehúsan con su propio mensaje */ }

  pi.registerTool({
    name: "session_new",
    description:
      "Create a persistent named terminal session (tmux). NON-BLOCKING. Use for reverse-shell listeners (nc -lnvp), interactive shells (evil-winrm, ssh, msfconsole). Optionally run an initial command. A name collision does NOT touch the existing session. Then use session_read/session_send.",
    parameters: Type.Object({
      name: Type.String({ description: "session name, e.g. 'listener'" }),
      command: Type.Optional(Type.String({ description: "initial command, e.g. 'nc -lnvp 1337'" })),
      socket: Type.Optional(Type.String({ description: "optional tmux server label (NOT a path), e.g. 'gekko-ops', to isolate agent shells from the operator's own tmux. [A-Za-z0-9_@-], max 64. The same name on a different socket is a DIFFERENT session." })),
    }),
    async execute(_id, p: any, _signal?: unknown, _onUpdate?: unknown, ctx?: { mode?: string }) {
      const epochAtCall = sessionEpoch; // antes del primer await (ver switchVerdict)
      if (badSocket(p.socket)) return text("FAIL: socket inválido (usá una etiqueta [A-Za-z0-9_@-], máx 64, sin '/' ni '.' ni empezar con '-')");
      // Lugar (spec 014, D2): leído AQUÍ, antes del primer await, como el workspace: la shell nace entera en un lugar aunque
      // el operador cambie el modo mientras la llamada espera. Todo lo que se haga sobre ella pasa este lugar.
      let place: ShellPlace;
      try { place = placeInForce(); } catch (e: any) { return text(`FAIL: ${e.message}. No se creó ninguna sesión.`); }
      const stateDecision = execSessionDecision(place.mode, runtime.exec);
      if (!stateDecision.ok) return text(stateDecision.note);
      // In toolbox mode the name is echoed into a copy-pasteable attach command: only the label charset goes through.
      if (place.mode === "toolbox" && !SHELL_NAME_RE.test(p.name)) return text("FAIL: nombre de sesión inválido en modo toolbox (usá [A-Za-z0-9_@-], máx 64, sin empezar con '-'). No se creó ninguna sesión.");
      // Workspace (spec 010): read on EVERY call — subagent sessions run in-process and tests change it —
      // and read it HERE, before the first await: the call's workspace is the one in force when it was
      // made, not whatever the environment holds after a concurrent call yielded (found under stress).
      // tmux -c silently falls back to $HOME on a bad dir, so check it BEFORE creating anything.
      const wsDirEnv = process.env.GEKKO_WORKSPACE_DIR || undefined;
      let wsDir: string | undefined;
      if (wsDirEnv) {
        try {
          if (!statSync(wsDirEnv).isDirectory()) throw new Error("no es un directorio");
          accessSync(wsDirEnv, constants.X_OK);
          wsDir = realpathSync(wsDirEnv);
        } catch (e: any) {
          return text(`FAIL: el directorio del workspace no existe o no se puede entrar (${wsDirEnv}: ${e.message}). No se creó ninguna sesión. Detenete y avisá al operador; no reintentes.`);
        }
      }
      // El directorio de sockets sale del lugar; se resuelve (y puede lanzar) antes de crear nada, y se crea sólo con el workspace ya validado.
      if (p.socket) { try { sockDirFor(place); } catch (e: any) { return text(`FAIL: ${e.message}. No se creó ninguna sesión.`); } }
      const sp = sockPath(p.socket, place); // resolved, confined socket PATH (undefined = default server)
      if (place.mode === "toolbox") {
        if (!place.container || !CONTAINER_ID_RE.test(place.container)) return text("FAIL: GEKKO_TOOLBOX no es un ID de contenedor de 64 caracteres hexadecimales. No se creó ninguna sesión.");
        const probe = await run("docker", ["inspect", "--type", "container", "--format", "{{.Id}} {{.State.Running}}", place.container], 5000);
        const identity = probe.ok ? containerIdentityVerdict(probe.stdout, place.container) : { ok: false as const, note: `docker inspect falló (${probe.timedOut ? "timeout" : probe.stderr.trim() || probe.code})` };
        if (!identity.ok) return text(`FAIL: ${identity.note}. No se creó ninguna sesión, ni en el contenedor ni en el host. Detente y avisa al operador.`);
      }
      // El nombre es el asa del modelo: no se crean dos con el mismo nombre en lugares distintos mientras la otra siga viva.
      for (const other of otherPlaceShells(Array.from(owned.values()), p.name, place)) {
        if (await ours(sockPath(other.socket, other.place), other)) return text(`FAIL: '${p.name}' ya es una shell viva en ${other.place.mode} (lugar=${other.place.mode}); no se crea otra con el mismo nombre en ${place.mode}. Usá otro nombre o cerrá la otra con session_kill. No se creó ninguna sesión.`);
      }
      if (sp) ensureSockDir(place); // recién ahora: ni el estado, ni la identidad, ni el nombre rehusaron
      // collision check, ON THE TARGET SOCKET — never kill the existing session (AC10). Same name
      // on a different socket is NOT a collision (AC09): the check is scoped to (socket, name).
      const pre = creationResult(await alive(p.name, sp, place));
      if (!pre.proceed) return result(pre.result!);
      const mk = await tmux(newSessionArgs(p.name, wsDir), 15000, sp, place);
      if (!mk.ok) return result({ ok: false, stdout: mk.stdout, stderr: mk.stderr, timedOut: mk.timedOut, note: `tmux new-session falló: ${mk.stderr || mk.code}` });
      const created = createdResult(await alive(p.name, sp, place)); // announce success only when verified
      if (!created.ok) return result(created);
      // record identity ONLY now (a name is not identity): server socket_path, session id, pane id, pid.
      // Retry briefly: a transient display-message failure right after a verified create would otherwise
      // leave an UNIDENTIFIABLE session, and a "?"-identity shell defeats ours()/the refresher (the
      // name-is-identity hole creeps back in). If we still cannot identify it, KILL it and fail — never
      // register an unmanageable session. Invariant: an owned shell ALWAYS has a real (serverPid,
      // sessionId, paneId); "?" is impossible, so no drive/kill/list/refresh path can fall back to name.
      const metaFmt = "#{socket_path}\t#{session_id}\t#{pane_id}\t#{pid}\t#{start_time}\t#{pane_current_path}";
      let meta = await tmux(["display-message", "-p", "-t", p.name, metaFmt], 15000, sp, place);
      for (let i = 0; i < 2 && (!meta.ok || meta.stdout.trim().split("\t").length < 5); i++) {
        await sleep(150);
        meta = await tmux(["display-message", "-p", "-t", p.name, metaFmt], 15000, sp, place);
      }
      const parts = meta.ok ? meta.stdout.trim().split("\t") : [];
      if (parts.length < 5 || !parts[1] || !parts[2] || !parts[3] || !parts[4]) {
        const k = await tmux(["kill-session", "-t", p.name], 15000, sp, place); // our own just-created session; no collision existed (checked above)
        // Report the close FAITHFULLY: only claim "se cerró" if kill-session actually succeeded. If the
        // same transient that blocked identity capture also blocked the kill, a live unmanaged session may
        // remain — say so and point at session_list rather than assert a close we did not confirm.
        const note = k.ok
          ? "sesión creada pero no se pudo capturar su identidad (socket/session/pane/pid); se cerró para no dejar una sesión no gestionable. Reintentá session_new."
          : "sesión creada pero no se pudo capturar su identidad NI confirmar su cierre; puede haber quedado viva y no gestionada — revisá con session_list antes de reintentar.";
        // Faithful machine fields too: when the KILL itself failed (!k.ok) the acute failure is the
        // kill, so surface its stderr/timedOut; when the kill succeeded the trigger was the meta read.
        return result({ ok: false, stdout: "", stderr: k.ok ? meta.stderr : (k.stderr || meta.stderr), timedOut: k.ok ? meta.timedOut : (k.timedOut || meta.timedOut), note });
      }
      const [serverIdRaw, sessionId, paneId, serverPid, serverStart, startPath = ""] = parts;
      const verdict = cwdVerdict(wsDir, startPath);
      if (!verdict.ok) {
        const k = await tmux(["kill-session", "-t", sessionId], 15000, sp, place); // target the captured session id
        const note = k.ok ? `${verdict.note} La sesión se cerró.` : `${verdict.note} No se pudo confirmar el cierre de la sesión; revisá con session_list.`;
        return result({ ok: false, stdout: "", stderr: k.stderr, timedOut: k.timedOut, note });
      }
      const switched = switchVerdict(epochAtCall, sessionEpoch);
      if (!switched.ok) {
        const k = await tmux(["kill-session", "-t", sessionId], 15000, sp, place);
        const note = k.ok ? `${switched.note} La sesión se cerró.` : `${switched.note} No se pudo confirmar el cierre de la sesión; revisá con session_list.`;
        return result({ ok: false, stdout: "", stderr: k.stderr, timedOut: k.timedOut, note });
      }
      // serverId = the server's canonical socket_path; if tmux omitted it, fall back to the known -S path
      // (sp) so the refresher probes the right server; "?" only for the default/inherited server.
      // serverPid pins the server INSTANCE (see ours()): the identity that survives id-counter resets.
      const serverId = serverIdRaw || sp || "?";
      const now = Date.now();
      owned.set(ownKey(p.socket, p.name), { name: p.name, socket: p.socket, place, serverId, serverPid, serverStart, sessionId, paneId, createdAt: now, lastInteraction: now });
      // Publish into the shared panel registry (the guard's widget/detail read it) — only now, after
      // a VERIFIED creation. Drop any stale same-server+name entry first so a re-created name does
      // not leave a duplicate [closed] ghost behind it (AC09 identity is server+name).
      runtime.shells.shells = runtime.shells.shells.filter((x) => !(x.serverId === serverId && x.name === p.name));
      registerShell(runtime.shells, { name: p.name, serverId, serverPid, sessionId, paneId, piSessionId: "local", owner: "gekko-session", createdAt: now, lastInteraction: now, place });
      // Spec 011, best-effort: nothing below may change what session_new returns (AC4, AC8).
      await tmux(["set-option", "-t", sessionId, "mouse", "on"], 5000, sp, place); // so the operator can scroll the shell
      await openMirrorWindow(p.name, serverId, sessionId, ctx?.mode === "tui", epochAtCall, place);
      let runNote = "";
      if (p.command) { const ic = await tmux(["send-keys", "-t", paneId, "--", ...sendKeysText(p.command), "Enter"], 15000, sp, place); runNote = ic.ok ? ` · running: ${p.command}` : ` · (comando inicial no se pudo enviar: ${ic.stderr || ic.code})`; }
      const where = (p.socket ? ` socket=${p.socket}` : "") + (wsDir ? ` cwd=${wsDir}` : "") + ` lugar=${place.mode}`;
      const attach = place.mode === "toolbox" ? ` Para mirar la shell a mano: docker exec -it ${process.env.GEKKO_WORKSPACE ? toolboxName(process.env.GEKKO_WORKSPACE) : place.container} tmux${sp ? ` -S ${sp}` : ""} attach -t ${p.name}` : "";
      return result(created, `id=${sessionId} pane=${paneId}${where}${runNote}. Use session_read (with 'until' to await a callback) and session_send (pasá el mismo 'socket').${attach}`);
    },
  });

  pi.registerTool({
    name: "session_send",
    description: "Send a command/keystrokes to a session, then Enter. Drives an interactive shell or listener. Returns the last lines after a short settle.",
    parameters: Type.Object({
      name: Type.String(),
      input: Type.String({ description: "command or keys to send" }),
      enter: Type.Optional(Type.Boolean({ description: "append Enter (default true)" })),
      socket: Type.Optional(Type.String({ description: "the socket the session was created on (omit for the default server)" })),
    }),
    async execute(_id, p: any) {
      if (badSocket(p.socket)) return text("FAIL: socket inválido");
      const s = owned.get(ownKey(p.socket, p.name));
      if (!s) return notOwned(p.name);
      const sp = sockPath(p.socket, s.place);
      // A name is not identity (AC09/AC12): prove OUR exact session instance is still live (same server
      // pid + same session id) before driving it. If it died and a stranger re-took the name/ids, fail
      // closed — never send to %N blindly. After ours()===true, paneId is a real captured id.
      if (!(await ours(sp, s))) return staleSession(p.name);
      // `--` stops tmux option parsing: an input beginning with '-' (e.g. "-tVICTIM") would otherwise be
      // read as a send-keys flag — a 2nd -t RETARGETS the keystroke to a NON-owned session, bypassing the
      // ownership gate. After `--` the input is positional keys (key names like Enter/C-c still resolve).
      // sendKeysText: a trailing ';' in the text is NOT a tmux command separator (it used to fail the call or
      // drop the backslash of `\;`); the shell receives the model's text byte for byte (REQ-TMUX-010).
      // One tmux invocation: a pane in copy-mode drops send-keys, and re-entering it between two calls would lose the
      // text with exit 0 (spec 011 AC7, REQ-TMUX-013). The pane id was captured by tmux, but a bad one must fail closed.
      let sendCommand: string[];
      try { sendCommand = sendArgs(s.paneId, p.input, p.enter !== false); }
      catch (e: any) { return text(`FAIL: ${e.message}; no se envió nada.`); }
      const snd = await tmux(sendCommand, 15000, sp, s.place);
      if (!snd.ok) return result({ ok: false, stdout: snd.stdout, stderr: snd.stderr, timedOut: snd.timedOut, note: `send-keys falló: ${snd.stderr || snd.code}` });
      s.lastInteraction = Date.now();
      touchShell(runtime.shells, s.serverId, p.name, s.lastInteraction); // reflect activity in the panel
      await sleep(800);
      const cap = await tmux(["capture-pane", "-t", s.paneId, "-p", "-S", "-50"], 15000, sp, s.place);
      return text(cap.ok ? cap.stdout : `FAIL: capture-pane falló: ${cap.stderr || cap.code}`);
    },
  });

  pi.registerTool({
    name: "session_read",
    description:
      "Read recent output from a session. With 'until' (substring/regex), polls until it appears or timeout — use to catch an async reverse-shell callback (e.g. until='PS ' or until='\\$').",
    parameters: Type.Object({
      name: Type.String(),
      until: Type.Optional(Type.String({ description: "pattern to wait for" })),
      timeout_s: Type.Optional(Type.Number({ description: "max wait when 'until' set (default 120)" })),
      lines: Type.Optional(Type.Number({ description: "trailing lines to return (default 60)" })),
      socket: Type.Optional(Type.String({ description: "the socket the session was created on (omit for the default server)" })),
    }),
    async execute(_id, p: any) {
      if (badSocket(p.socket)) return text("FAIL: socket inválido");
      const s = owned.get(ownKey(p.socket, p.name));
      if (!s) return notOwned(p.name);
      const sp = sockPath(p.socket, s.place);
      const lines = p.lines ?? 60;
      const deadline = Date.now() + (p.timeout_s ?? 120) * 1000;
      let out = "";
      do {
        // Re-verify identity on EVERY poll, not just at entry: the until-loop can run for timeout_s
        // (default 120s) — long enough for the server to restart and a stranger to recycle our pane id,
        // after which capture-pane -t %N would read the STRANGER's pane and return it as our output
        // (AC12). ours() pins the server instance by pid, so a restart/replacement is caught before we
        // trust any capture. If our session is gone/replaced, fail closed rather than leak a stranger.
        if (!(await ours(sp, s))) return staleSession(p.name);
        const cap = await tmux(["capture-pane", "-t", s.paneId, "-p", "-S", `-${lines}`], 15000, sp, s.place);
        if (cap.ok) {
          out = cap.stdout;
          if (!p.until) return text(out);
          try { if (new RegExp(p.until).test(out)) return text(`[matched '${p.until}']\n${out}`); }
          catch { if (out.includes(p.until)) return text(`[matched '${p.until}']\n${out}`); }
        } else if (!p.until) {
          return text(`FAIL: capture-pane falló: ${cap.stderr || cap.code}`);
        } // with 'until' set, a transient capture failure keeps polling (don't miss a late callback)
        await sleep(3000);
      } while (Date.now() < deadline);
      return text(`[timeout waiting for '${p.until}']\n${out}`);
    },
  });

  pi.registerTool({
    name: "session_list",
    description: "List active persistent sessions. Sessions created by THIS run are shown as owned; any others the server reports are shown separately as unattributed (never claimed as ours).",
    parameters: Type.Object({}),
    async execute() {
      // Query EVERY place and socket that may hold a session: the place in force plus each distinct place of an owned
      // shell (a shell born in the container is still listed after the mode went back to os), and in each the default,
      // the ones we own, AND every labeled socket present in that place's socket dir — after a pi restart `owned` is
      // empty, so a default-only list would leave surviving sessions on a labeled socket INVISIBLE instead of "no
      // atribuidas" (they are still never claimed as ours). Each name is labeled with its socket and place so the same
      // name on two servers is never conflated (AC09), and ownership is checked per (socket, name) AND place.
      let places: ShellPlace[];
      try { places = placesToProbe(placeInForce(), Array.from(owned.values()).map((o) => o.place)); } catch (e) { return text(`FAIL: ${(e as Error).message}`); }
      const mine: string[] = [];
      const other: string[] = [];
      let anyServer = false;
      const failures: string[] = []; // hard failures (timeout/denied/unknown) — surfaced, never masked as empty
      for (const place of places) {
        let dirLabels: string[] = [];
        try {
          const dir = sockDirFor(place);
          assertSockDirNotLink(dir);
          dirLabels = readdirSync(dir);
        } catch (e) {
          if ((e as NodeJS.ErrnoException).code !== "ENOENT") {
            if (/enlace simbólico/.test((e as Error).message)) return text(`FAIL: ${(e as Error).message}`);
            failures.push(`(${place.mode}) directorio de sockets: ${(e as Error).message}`); // sin sitio seguro: sólo el servidor por defecto
          } // ENOENT = no labeled socket was ever created there
        }
        const sockets = socketsToProbe(Array.from(owned.values()).filter((o) => samePlace(o.place, place)).map((o) => o.socket), dirLabels);
        for (const sock of sockets) {
          const spL = sockPath(sock, place);
          const ls = await tmux(["list-sessions", "-F", "#{session_name}"], 5000, spL, place);
          if (!ls.ok) {
            if (ls.noExec) return text("FAIL: tmux no está instalado");
            // "no server running" / "no such file" / "error connecting" = this socket simply has no
            // server up → benign, skip it. Anything else (timeout, permission, unknown) is a REAL failure:
            // record it so we never report "(sin sesiones)" when the truth is "couldn't tell".
            if (ls.timedOut || !/no server running|no such file|error connecting/i.test(ls.stderr)) {
              failures.push(`${sock ? `@${sock}` : "(default)"} [${place.mode}]: ${ls.timedOut ? "timeout" : (ls.stderr.trim() || ls.code)}`);
            }
            continue;
          }
          anyServer = true;
          const label = `${sock ? `@${sock}` : ""} [${place.mode}]`;
          for (const n of ls.stdout.split("\n").map((s) => s.trim()).filter(Boolean)) {
            const own = owned.get(ownKey(sock, n));
            // "propia" only if we still own this EXACT live instance. A stale entry whose session died
            // and whose (socket,name) a stranger re-took is NOT ours — list it as unattributed, never
            // claim it (a name is not identity, AC09/AC12).
            (own && samePlace(own.place, place) && (await ours(spL, own)) ? mine : other).push(`${n}${label}`);
          }
        }
      }
      // Never claim empty on unconfirmed state: if nothing was readable AND a socket hard-failed, say so.
      if (!anyServer && failures.length) return text(`FAIL: list-sessions no se pudo consultar: ${failures.join("; ")}`);
      if (!anyServer) return text("(sin sesiones — no hay servidor tmux)");
      const lines = [
        mine.length ? `propias (verificadas): ${mine.join(", ")}` : "propias: ninguna",
        other.length ? `no atribuidas (NO son propias, no se inspeccionan): ${other.join(", ")}` : "",
        failures.length ? `(advertencia: no se pudo consultar: ${failures.join("; ")})` : "",
      ].filter(Boolean);
      return text(lines.join("\n"));
    },
  });

  pi.registerTool({
    name: "session_kill",
    description: "Kill a persistent session. Reports success only when the close is verified.",
    parameters: Type.Object({
      name: Type.String(),
      socket: Type.Optional(Type.String({ description: "the socket the session was created on (omit for the default server)" })),
    }),
    async execute(_id, p: any) {
      if (badSocket(p.socket)) return text("FAIL: socket inválido");
      const own = owned.get(ownKey(p.socket, p.name));
      if (!own) return notOwned(p.name); // never kill a session this run didn't create (on THIS socket)
      const sp = sockPath(p.socket, own.place);
      const cleanup = () => {
        owned.delete(ownKey(p.socket, p.name));
        // mark closed in the shared registry (verified close only) so the panel stops counting it open.
        const sh = runtime.shells.shells.find((x) => x.serverId === own.serverId && x.name === p.name);
        if (sh) { sh.state = "closed"; sh.lastCheck = Date.now(); sh.lastValidCheck = Date.now(); }
      };
      // Prove OUR exact session instance is still live BEFORE killing. If it is already gone — or a
      // stranger re-took the name/ids after a server restart — do NOT issue kill-session (that would
      // kill the stranger). Drop the stale entry and report it closed: our session is gone, which is
      // the goal of kill. A name is not identity (AC09/AC12).
      if (!(await ours(sp, own))) { cleanup(); return text(`OK: '${p.name}' ya no estaba viva (no se mató nada ajeno); registro limpiado.`); }
      await tmux(["kill-session", "-t", own.sessionId], 15000, sp, own.place); // target our verified session id
      const killed = killResult(await alive(own.sessionId, sp, own.place));    // verify the SAME id is gone
      if (killed.ok) cleanup();
      return result(killed);
    },
  });
}
