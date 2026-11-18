// RUN (needs @sinclair/typebox, which shell-session.ts imports at load):
//   cd toolbox && ln -sfn <your-pi-install>/node_modules node_modules \
//     && node --experimental-strip-types tests/<this-file> ; rm -f node_modules
// e.g. <your-pi-install> = ~/.pi/agent/install/releases/1.5.0 . Real tmux required; no model, no network.
// Deterministic, MODEL-INDEPENDENT test of the real session_* handlers (mock pi + real tmux).
// Proves at RUNTIME (not just the pure gate):
//   #9  — session_new rejects a path-shaped socket and destroys nothing
//   #1  — session_send/kill on a killed-then-recreated (socket,name) fail closed, never drive a stranger
//   #1b — ...INCLUDING across a full tmux SERVER RESTART that recycles $N/%N ids (serverPid discriminator)
//   #3  — session_list never labels a stranger (reused name/ids) as 'propia'
//   AC09 — same name on two labels = two sessions; killing one leaves the other
//   AC16/AC17 (spec 010) — a shell is born in GEKKO_WORKSPACE_DIR (re-read per call) or not at all,
//     in OS mode AND in toolbox mode (GEKKO_TEST_TOOLBOX=1, real Docker)
//   REQ-TBX-008 — hostile session name refused in toolbox mode; a symlinked socket dir is refused;
//     a tmux server that restarted with the same pid (different #{start_time}) is not "ours"
//   AC1/AC3/AC4/AC6/AC7/AC8 (spec 011) — mirror window, copy-mode send, mouse + IGNOREEOF, window cleanup (OS mode)
//   spec 014 (REQ-TBX-009/011, REQ-TMUX-017) — each shell remembers where it was born (os or container) and is only ever driven
//     there; `session_new` in toolbox needs the state `lista` and the container's identity (docker shim, OS mode); with
//     GEKKO_TEST_TOOLBOX=1 and real Docker: the mode changes under a live shell, the mirror window attaches INSIDE the container
//     and closing it detaches the client, and `docker stop` closes the window by itself
import { execFile, execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, statSync, mkdtempSync, mkdirSync, symlinkSync, renameSync, rmSync, chmodSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runtime, registerShell } from "../gekko-panel.ts";
import { toolboxName } from "../gekko-workspace.ts";

const DIR = mkdtempSync(join(tmpdir(), "gkharness-"));
process.env.GEKKO_TMUX_DIR = DIR;
const sh = (await import("../shell-session.ts")).default;

const tools: Record<string, any> = {};
const handlers: Record<string, Function[]> = {};
const mockPi: any = { on(event: string, fn: Function) { (handlers[event] ??= []).push(fn); }, registerTool(def: any) { tools[def.name] = def; } };
sh(mockPi);

const txt = (r: any): string => r.content[0].text;
const tmuxS = (sock: string, args: string[]): string => { try { return execFileSync("tmux", ["-S", sock, ...args], { encoding: "utf-8" }); } catch (e: any) { return `ERR:${e.status}`; } };
const dead = (s: string) => s.startsWith("ERR:");
let fail = 0;
const ok = (c: boolean, m: string) => { console.log(`${c ? "[ok]" : "[FAIL]"} ${m}`); if (!c) fail++; };

// Opt-in Docker check: own disposable container, only the temporary workspace mounted. Same container,
// GEKKO_TOOLBOX = its validated ID (as the launcher exports it), GEKKO_WORKSPACE names it for the attach hint.
if (process.env.GEKKO_TEST_TOOLBOX === "1") {
  const wsName = `handler-test-${process.pid}`;
  const container = `gekko-tb-${wsName}`;
  const wsReal = realpathSync(mkdtempSync(join(tmpdir(), "gkdock-")));
  const goneDir = join(wsReal, "gone"), fileNotDir = join(wsReal, "file.txt"), shimDir = join(wsReal, "shim");
  try {
    const containerId = execFileSync("docker", ["run", "-d", "--init", "--name", container, "-v", `${DIR}:${DIR}`, "-w", "/", "gekko-toolbox:latest", "sleep", "infinity"], { encoding: "utf-8" }).trim();
    process.env.GEKKO_EXEC = "toolbox";
    process.env.GEKKO_TOOLBOX = containerId;
    process.env.GEKKO_WORKSPACE = wsName;
    process.env.GEKKO_WORKSPACE_DIR = DIR;
    runtime.exec = { state: "lista", reason: "" };
    const TSOCK = join(DIR, ".gekko-sockets"); // toolbox place: <ws>/.gekko-sockets, whatever GEKKO_TMUX_DIR inherited
    const inBox = (sock: string, ...args: string[]) => spawnSync("docker", ["exec", containerId, "tmux", "-S", join(TSOCK, sock), ...args], { encoding: "utf-8" });
    const created = txt(await tools.session_new.execute("i", { name: "inside", socket: "docker" }));
    ok(created.startsWith("OK") && created.includes(`docker exec -it ${container} `) && !created.includes(containerId) && /lugar=toolbox/.test(created) && !/Espejo no disponible/.test(created), "toolbox: handler crea y anuncia attach con el nombre del contenedor, no el ID; lugar=toolbox");
    await tools.session_send.execute("i", { name: "inside", socket: "docker", input: "pwd > actual-cwd; hostname > actual-host" });
    const hostname = execFileSync("docker", ["exec", containerId, "hostname"], { encoding: "utf-8" }).trim();
    ok(readFileSync(join(DIR, "actual-cwd"), "utf-8").trim() === DIR && readFileSync(join(DIR, "actual-host"), "utf-8").trim() === hostname, "toolbox: shell nace dentro y en workspace; artefactos compartidos");
    ok(statSync(join(TSOCK, "docker")).isSocket(), "toolbox REQ-TBX-011: el socket queda en <ws>/.gekko-sockets aunque GEKKO_TMUX_DIR apunte a otro lado");
    ok(txt(await tools.session_kill.execute("i", { name: "inside", socket: "docker" })).startsWith("OK"), "toolbox: handler cierra shell");
    const processes = execFileSync("docker", ["exec", containerId, "ps", "-eo", "comm="], { encoding: "utf-8" });
    ok(!/^bash$/m.test(processes), "toolbox: cierre no deja bash vivo");

    // REQ-TBX-011 / AC12: el operador cambia el modo con Pi abierto (como lo hará el guard: entorno + runtime.exec). Cada shell
    // sigue donde nació; una nueva nace en el lugar vigente; el mismo nombre en el otro lugar se rehúsa.
    {
      const realTmux = execFileSync("sh", ["-c", "command -v tmux"], { encoding: "utf-8" }).trim();
      const osTmp = join(wsReal, "os-tmp"); mkdirSync(osTmp);
      const savedTmp = process.env.TMPDIR;
      process.env.TMPDIR = osTmp; // el socket de una shell os va fuera del workspace (que aquí es DIR): <osTmp>/gekko-sockets
      const OSOCK = join(osTmp, "gekko-sockets");
      const hostHas = (sock: string, name: string) => spawnSync(realTmux, ["-S", join(OSOCK, sock), "has-session", "-t", name]).status === 0;
      const toOs = () => { process.env.GEKKO_EXEC = "os"; delete process.env.GEKKO_TOOLBOX; runtime.exec = { state: null, reason: "" }; };
      const toToolbox = () => { process.env.GEKKO_EXEC = "toolbox"; process.env.GEKKO_TOOLBOX = containerId; runtime.exec = { state: "lista", reason: "" }; };
      const listed = async () => txt(await tools.session_list.execute("i", {}));
      try {
        const t1 = txt(await tools.session_new.execute("i", { name: "tb1", socket: "swa" }));
        toOs();
        ok(/lugar=toolbox/.test(t1) && /^SW1_2$/m.test(txt(await tools.session_send.execute("i", { name: "tb1", socket: "swa", input: "echo SW1_$((1+1))" }))), "AC12: tras pasar a os, la shell de la toolbox sigue respondiendo a session_send EN el contenedor");
        ok(/^SW1_2$/m.test(txt(await tools.session_read.execute("i", { name: "tb1", socket: "swa" }))), "AC12: ...y a session_read");
        ok(/tb1@swa \[toolbox\]/.test((await listed()).split("\n").find((l) => l.startsWith("propias")) ?? ""), "AC12: ...y session_list la da por propia con su lugar");
        const h1 = txt(await tools.session_new.execute("i", { name: "hs1", socket: "swb" }));
        ok(/^OK/.test(h1) && /lugar=os/.test(h1) && hostHas("swb", "hs1") && !existsSync(join(TSOCK, "swb")), "AC12: la shell nueva nace en el host (lugar=os), con su socket fuera del workspace");
        const dup = txt(await tools.session_new.execute("i", { name: "tb1", socket: "swc" }));
        ok(dup.startsWith("FAIL") && /lugar=toolbox/.test(dup) && !hostHas("swc", "tb1"), `AC12: el mismo nombre en el otro lugar se rehúsa sin crear nada: ${dup.slice(0, 80)}`);
        const both = (await listed()).split("\n").find((l) => l.startsWith("propias")) ?? "";
        ok(/tb1@swa \[toolbox\]/.test(both) && /hs1@swb \[os\]/.test(both), `AC12: session_list muestra las dos, cada una con su lugar: ${both}`);
        ok(txt(await tools.session_kill.execute("i", { name: "tb1", socket: "swa" })).startsWith("OK") && inBox("swa", "has-session", "-t", "tb1").status !== 0, "AC12: session_kill de la shell de la toolbox la cierra en el contenedor desde modo os");
        toToolbox();
        ok(/^SW2_4$/m.test(txt(await tools.session_send.execute("i", { name: "hs1", socket: "swb", input: "echo SW2_$((2+2))" }))) && hostHas("swb", "hs1"), "AC12: de vuelta en toolbox, la shell del host sigue respondiendo en el host");
        const tb2 = txt(await tools.session_new.execute("i", { name: "tb2", socket: "swa" }));
        const dup2 = txt(await tools.session_new.execute("i", { name: "hs1", socket: "swd" }));
        ok(/lugar=toolbox/.test(tb2) && dup2.startsWith("FAIL") && /lugar=os/.test(dup2) && inBox("swd", "has-session", "-t", "hs1").status !== 0, "AC12: a la inversa: la nueva nace en el contenedor y el nombre de la shell del host se rehúsa");
        ok(txt(await tools.session_kill.execute("i", { name: "hs1", socket: "swb" })).startsWith("OK") && !hostHas("swb", "hs1"), "AC12: session_kill de la shell del host desde modo toolbox la cierra en el host");
        await tools.session_kill.execute("i", { name: "tb2", socket: "swa" });
        // Identidad (AC3): un ID de 64 hex que no es el del contenedor → FAIL y nada creado en ningún lado.
        process.env.GEKKO_TOOLBOX = "ab".repeat(32);
        const wrong = txt(await tools.session_new.execute("i", { name: "wrong", socket: "swe" }));
        ok(wrong.startsWith("FAIL") && inBox("swe", "has-session", "-t", "wrong").status !== 0 && !hostHas("swe", "wrong") && !existsSync(join(OSOCK, "swe")), `AC3: GEKKO_TOOLBOX de otro contenedor → FAIL, nada creado: ${wrong.slice(0, 80)}`);
        toToolbox();
      } finally {
        if (savedTmp === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = savedTmp;
        for (const sock of ["swb", "swd", "swe"]) spawnSync(realTmux, ["-S", join(OSOCK, sock), "kill-server"], { stdio: "ignore" });
        toToolbox();
      }
    }

    // AC18 / REQ-TMUX-017: espejo de una shell de la toolbox, en un servidor tmux PRIVADO del host (el «operador» del arnés).
    {
      const realTmux = execFileSync("sh", ["-c", "command -v tmux"], { encoding: "utf-8" }).trim();
      const hostSock = join(wsReal, "host-op");
      const hostTmux = (...a: string[]) => execFileSync(realTmux, ["-S", hostSock, ...a], { encoding: "utf-8" }).trim();
      const windowNames = () => hostTmux("list-windows", "-a", "-F", "#{window_id} #{window_name}").split("\n").map((l) => l.split(" "));
      const saved = { TMUX: process.env.TMUX, TMUX_PANE: process.env.TMUX_PANE, mirror: runtime.mirror };
      const waitUntil = async (cond: () => boolean, ms = 8000) => { const end = Date.now() + ms; while (!cond()) { if (Date.now() > end) return false; await new Promise((r) => setTimeout(r, 100)); } return true; };
      const tui = { mode: "tui", hasUI: true };
      const clients = (sock: string, sid: string) => inBox(sock, "list-clients", "-t", sid, "-F", "#{client_name}").stdout.trim().split("\n").filter(Boolean);
      try {
        hostTmux("new-session", "-d", "-s", "hostop", "-x", "200", "-y", "50");
        process.env.TMUX = `${hostSock},${hostTmux("display-message", "-p", "#{pid}")},0`;
        process.env.TMUX_PANE = hostTmux("display-message", "-p", "-t", "hostop", "#{pane_id}");
        runtime.mirror = true;
        const before = windowNames().length;
        const mirrored = txt(await tools.session_new.execute("i", { name: "mirrored", socket: "dockm" }, undefined, undefined, tui));
        const sid = /id=(\$\d+)/.exec(mirrored)?.[1] ?? "?";
        const win = windowNames().find((w) => w[1] === "sh-mirrored");
        ok(mirrored.startsWith("OK") && /lugar=toolbox/.test(mirrored) && !/Espejo no disponible/.test(mirrored) && !!win && windowNames().length === before + 1, `AC18: la ventana espejo abre en el tmux del host para una shell de la toolbox: ${mirrored.split("\n")[0]}`);
        ok(await waitUntil(() => clients("dockm", sid).length > 0), "AC18: hay un cliente adjunto a la shell DENTRO del contenedor");
        ok(spawnSync(realTmux, ["-S", hostSock, "show-options", "-w", "-t", win?.[0] ?? "@0", "-v", "@gekko_mirror"], { encoding: "utf-8" }).stdout.trim() === String(process.pid), "AC18: la ventana lleva la marca de este Pi (puesta en el tmux del host)");
        const pane = hostTmux("list-panes", "-t", win?.[0] ?? "@0", "-F", "#{pane_id}");
        hostTmux("send-keys", "-t", pane, `hostname > ${join(DIR, "mirror-host")}`, "Enter");
        ok(await waitUntil(() => existsSync(join(DIR, "mirror-host")) && readFileSync(join(DIR, "mirror-host"), "utf-8").trim() === hostname), "AC18: lo que se teclea en la ventana corre DENTRO del contenedor (hostname del contenedor)");
        for (const fn of handlers.session_start ?? []) await fn({}, {});
        ok(await waitUntil(() => !windowNames().some((w) => w[1] === "sh-mirrored")), "AC18: tras el cierre desde Pi la ventana ya no existe");
        ok(clients("dockm", sid).length === 0 && inBox("dockm", "has-session", "-t", "mirrored").status === 0, "AC18: el contenedor queda con 0 clientes adjuntos a esa sesión y la shell sigue viva");
        inBox("dockm", "kill-session", "-t", "mirrored");

        // `docker stop`: el cliente de la ventana muere con el contenedor y la ventana se cierra sola.
        const stopped = txt(await tools.session_new.execute("i", { name: "stopme", socket: "dockm" }, undefined, undefined, tui));
        ok(stopped.startsWith("OK") && windowNames().some((w) => w[1] === "sh-stopme"), "AC18: segunda ventana espejo abierta");
        execFileSync("docker", ["stop", "-t", "2", containerId], { stdio: "ignore" });
        const closedByItself = await waitUntil(() => !windowNames().some((w) => w[1] === "sh-stopme"), 20000);
        ok(closedByItself, `AC18: \`docker stop\` del contenedor cierra la ventana espejo por sí solo${closedByItself ? "" : ` (ventanas: ${windowNames().map((w) => w.join(" ")).join(", ")}; panes: ${hostTmux("list-panes", "-a", "-F", "#{pane_id} dead=#{pane_dead} #{pane_current_command}")})`}`);
        execFileSync("docker", ["start", containerId], { stdio: "ignore" });
        for (const fn of handlers.session_start ?? []) await fn({}, {}); // vacía la lista mientras $TMUX aún apunta a este servidor: un id de ventana es de UN servidor
      } finally {
        if (saved.TMUX === undefined) delete process.env.TMUX; else process.env.TMUX = saved.TMUX;
        if (saved.TMUX_PANE === undefined) delete process.env.TMUX_PANE; else process.env.TMUX_PANE = saved.TMUX_PANE;
        runtime.mirror = saved.mirror;
        spawnSync(realTmux, ["-S", hostSock, "kill-server"], { stdio: "ignore" });
      }
    }

    // REQ-TBX-008: the name is echoed into a copy-pasteable attach command, so only the label charset is accepted.
    for (const hostile of ["a b", "x;id", "$(id)", "a`id`", "-x", "a\nb", "a.b", "x".repeat(65)]) {
      const r = txt(await tools.session_new.execute("i", { name: hostile, socket: "docker" }));
      ok(r.startsWith("FAIL") && /nombre de sesión inválido/.test(r), `toolbox: nombre hostil ${JSON.stringify(hostile.slice(0, 10))} rechazado`);
    }
    const listed = spawnSync("docker", ["exec", containerId, "tmux", "-S", join(DIR, ".gekko-sockets", "docker"), "list-sessions"], { encoding: "utf-8" });
    ok(!/x;id|a b|\$\(id\)/.test(listed.stdout + listed.stderr), "toolbox: el nombre hostil no creó ninguna sesión en el contenedor");

    // AC16/AC17 in toolbox mode: the shell is born in the workspace or not at all.
    mkdirSync(goneDir); rmSync(goneDir, { recursive: true }); writeFileSync(fileNotDir, "x");
    const hasInside = (sock: string, name: string) => spawnSync("docker", ["exec", containerId, "tmux", "-S", join(DIR, ".gekko-sockets", sock), "has-session", "-t", name]).status === 0;
    const newInBox = async (name: string, sock: string, dirEnv: string) => { process.env.GEKKO_WORKSPACE_DIR = dirEnv; return txt(await tools.session_new.execute("i", { name, socket: sock })); };
    const rGoneBox = await newInBox("g1", "dockb", goneDir);
    ok(rGoneBox.startsWith("FAIL") && /No se creó ninguna sesión/.test(rGoneBox) && !hasInside("dockb", "g1"), `toolbox AC17a: directorio borrado → FAIL, sin sesión: ${rGoneBox.split("\n")[0].slice(0, 70)}`);
    const rFileBox = await newInBox("g2", "dockb", fileNotDir);
    ok(rFileBox.startsWith("FAIL") && !hasInside("dockb", "g2"), "toolbox AC17c: archivo regular → FAIL, sin sesión");
    // The shell is born OUTSIDE the workspace: a `docker` shim, first in PATH, strips `-c <dir>` from `new-session`.
    mkdirSync(shimDir);
    const realDocker = execFileSync("sh", ["-c", "command -v docker"], { encoding: "utf-8" }).trim();
    writeFileSync(join(shimDir, "docker"), `#!/usr/bin/env bash
a=(); skip=0; isnew=0
for x in "$@"; do [ "$x" = new-session ] && isnew=1; done
for x in "$@"; do
  if [ "$skip" = 1 ]; then skip=0; continue; fi
  if [ "$isnew" = 1 ] && [ "$x" = "-c" ]; then skip=1; continue; fi
  a+=("$x")
done
exec ${JSON.stringify(realDocker)} "\${a[@]}"
`, { mode: 0o755 });
    const pathBefore = process.env.PATH;
    process.env.PATH = `${shimDir}:${pathBefore}`;
    const rBadBox = await newInBox("g3", "dockb", DIR);
    process.env.PATH = pathBefore;
    ok(rBadBox.startsWith("FAIL") && /arranc/.test(rBadBox) && /se cerró/.test(rBadBox) && !hasInside("dockb", "g3"), `toolbox mismatch: la shell nació fuera del workspace → FAIL, cierre declarado y sin sesión viva: ${rBadBox.split("\n")[0].slice(0, 90)}`);
    ok(txt(await tools.session_send.execute("i", { name: "g3", socket: "dockb", input: "id" })).startsWith("FAIL"), "toolbox mismatch: esa sesión nunca quedó registrada como propia");
    const rGoodBox = await newInBox("g4", "dockb", DIR);
    ok(rGoodBox.startsWith("OK") && hasInside("dockb", "g4"), "toolbox mismatch (control): sin el intermediario la misma llamada da OK");
    await tools.session_kill.execute("i", { name: "g4", socket: "dockb" });

    // A container replaced under a running Pi: the old ID fails closed instead of driving the new one.
    const replaced = txt(await tools.session_new.execute("i", { name: "r1", socket: "dockc" }));
    execFileSync("docker", ["rm", "-f", containerId], { stdio: "ignore" });
    execFileSync("docker", ["run", "-d", "--init", "--name", container, "-v", `${DIR}:${DIR}`, "-w", "/", "gekko-toolbox:latest", "sleep", "infinity"], { stdio: "ignore" });
    const afterSwap = txt(await tools.session_send.execute("i", { name: "r1", socket: "dockc", input: "echo PWNED_NEW_CONTAINER" }));
    ok(replaced.startsWith("OK") && afterSwap.startsWith("FAIL") && !/PWNED_NEW_CONTAINER/.test(afterSwap), `toolbox: contenedor reemplazado bajo Pi → el ID viejo falla cerrado: ${afterSwap.split("\n")[0].slice(0, 80)}`);
  } finally {
    spawnSync("docker", ["rm", "-f", container], { stdio: "ignore" });
    chmodSync(wsReal, 0o700); rmSync(wsReal, { recursive: true, force: true });
    delete process.env.GEKKO_EXEC; delete process.env.GEKKO_TOOLBOX; delete process.env.GEKKO_WORKSPACE_DIR; delete process.env.GEKKO_WORKSPACE;
    runtime.exec = { state: null, reason: "" };
  }
}

// ── spec 014 T4 (REQ-TBX-010, REQ-TBX-012, docker real): el cambio de modo en vivo con las funciones REALES del guard y el ejecutor real,
// en una raíz temporal con un workspace de nombre único (el contenedor es gekko-tb-<ese nombre>). Se borra cada contenedor creado, por ID.
if (process.env.GEKKO_TEST_TOOLBOX === "1") {
  const guard = await import("../gekko-guard.ts");
  const wsName = `gk014-${process.pid}`, name = toolboxName(wsName);
  const root = realpathSync(mkdtempSync(join(tmpdir(), "gk014-root-")));
  const wsDir = join(root, "engagements", wsName), modeFile = join(wsDir, "exec");
  const cli = fileURLToPath(new URL("../gekko-workspace.ts", import.meta.url));
  const keys = ["GEKKO_WS_ROOT", "GEKKO_OVPN", "GEKKO_TOOLBOX_IMAGE", "GEKKO_EXEC", "GEKKO_TOOLBOX", "GEKKO_WORKSPACE", "GEKKO_WORKSPACE_DIR"];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  const savedDeps = { ...guard.execDeps }, savedShells = runtime.shells.shells, savedExec = runtime.exec;
  const created: string[] = [];
  const fileMode = () => readFileSync(modeFile, "utf-8");
  const running = (id: string) => spawnSync("docker", ["inspect", "--format", "{{.State.Running}}", id], { encoding: "utf-8" }).stdout.trim() === "true";
  const inspectId = (ref: string) => spawnSync("docker", ["inspect", "--type", "container", "--format", "{{.Id}}", ref], { encoding: "utf-8" }).stdout.trim();
  try {
    mkdirSync(join(root, ".claude", "tools"), { recursive: true });
    process.env.GEKKO_WS_ROOT = root; delete process.env.GEKKO_OVPN; delete process.env.GEKKO_TOOLBOX_IMAGE;
    const made = spawnSync("node", ["--no-warnings", "--experimental-strip-types", cli, "new", wsName, "--exec", "os", "192.0.2.10"], { env: process.env, encoding: "utf-8" });
    mkdirSync(join(wsDir, ".pi-sessions"), { mode: 0o700 });
    guard.execDeps.cli = cli;
    process.env.GEKKO_WORKSPACE = wsName; process.env.GEKKO_WORKSPACE_DIR = wsDir; process.env.GEKKO_EXEC = "os"; delete process.env.GEKKO_TOOLBOX;
    runtime.exec = { state: null, reason: "" };
    ok(made.status === 0 && fileMode() === "os\n", "014 R: workspace temporal creado en os");

    // (a) del paso desde os hasta lista: el CLI del lanzador con docker real, y sólo entonces el archivo dice toolbox
    const pending = guard.changeToToolbox();
    const during = { state: runtime.exec.state, file: fileMode(), exec: process.env.GEKKO_EXEC, id: process.env.GEKKO_TOOLBOX };
    const up = await pending;
    const id = process.env.GEKKO_TOOLBOX ?? "";
    if (/^[0-9a-f]{64}$/.test(id)) created.push(id);
    ok(during.state === "levantando" && during.file === "os\n" && during.exec === "toolbox" && during.id === undefined, "014 R(a): mientras levanta, estado levantando, archivo todavía os y sin ID");
    ok(up.ok && runtime.exec.state === "lista" && id === inspectId(name) && running(id) && fileMode() === "toolbox\n", `014 R(a): llega a lista con el ID validado del contenedor ${name} y sólo entonces el archivo dice toolbox: ${up.note}`);

    // (b) docker kill del contenedor → la comprobación periódica pasa a caída
    ok(spawnSync("docker", ["kill", id], { stdio: "ignore" }).status === 0 && !running(id), "014 R(b): docker kill detuvo el contenedor");
    const changed = await guard.checkToolbox();
    ok(changed && runtime.exec.state === "caída" && /en marcha/.test(runtime.exec.reason) && !(await guard.checkToolbox()), `014 R(b): la comprobación periódica pasa a caída (${runtime.exec.reason}) y no vuelve sola a lista`);

    // (c) reintento: mismo camino, arranca el contenedor detenido
    const retry = await guard.changeToToolbox();
    ok(retry.ok && runtime.exec.state === "lista" && process.env.GEKKO_TOOLBOX === id && running(id), `014 R(c): el reintento vuelve a lista con el mismo contenedor: ${retry.note}`);

    // (d) un arranque fallido (imagen inexistente) termina en caída y deja el archivo como estaba
    guard.changeToOs();
    ok(fileMode() === "os\n" && process.env.GEKKO_EXEC === "os" && running(id), "014 R(d): volver a os guarda os y deja el contenedor arriba");
    process.env.GEKKO_TOOLBOX_IMAGE = "gekko-toolbox-no-existe:014";
    const bad = await guard.changeToToolbox();
    delete process.env.GEKKO_TOOLBOX_IMAGE;
    ok(!bad.ok && runtime.exec.state === "caída" && /imagen/.test(runtime.exec.reason) && process.env.GEKKO_EXEC === "toolbox" && process.env.GEKKO_TOOLBOX === undefined && fileMode() === "os\n",
      `014 R(d): imagen inexistente → caída (${runtime.exec.reason}), sigue en toolbox sin ID y el archivo conserva os`);

    // (e) off: detiene este contenedor y sólo él; un segundo off no llama a docker stop
    const again = await guard.changeToToolbox();
    ok(again.ok && runtime.exec.state === "lista" && process.env.GEKKO_TOOLBOX === id, "014 R(e): de caída se reintenta a lista (adopta el contenedor que corre)");
    const extraName = `gk014-extra-${process.pid}`;
    const extraId = execFileSync("docker", ["run", "-d", "--init", "--name", extraName, "gekko-toolbox:latest", "sleep", "infinity"], { encoding: "utf-8" }).trim();
    created.push(extraId);
    runtime.shells.shells = [];
    registerShell(runtime.shells, { name: "k0", serverId: join(wsDir, ".gekko-sockets", "k"), sessionId: "$0", paneId: "%0", piSessionId: "p", serverPid: "1", owner: "gekko-session", createdAt: Date.now(), lastInteraction: Date.now(), place: { mode: "toolbox", container: id } });
    const asked: string[] = [];
    const offNote = await guard.toolboxOff(async (text) => { asked.push(text); return true; });
    ok(asked.length === 1 && asked[0].includes(name) && asked[0].includes(id.slice(0, 12)) && /conoce 1/.test(asked[0]), "014 R(e): la confirmación nombra el contenedor, el ID corto y la cuenta de shells");
    ok(!running(id) && running(extraId), "014 R(e): off detuvo el contenedor del workspace y SÓLO ése (el desechable sigue en marcha)");
    ok(process.env.GEKKO_EXEC === "os" && process.env.GEKKO_TOOLBOX === undefined && runtime.exec.state === null && fileMode() === "os\n" && runtime.shells.shells.every((sh) => sh.state === "closed"), `014 R(e): modo os en memoria y archivo y la shell figura cerrada: ${offNote}`);
    const seen: string[][] = [], realRun = guard.execDeps.run;
    guard.execDeps.run = (file, args, timeoutMs) => { seen.push([file, ...args]); return realRun(file, args, timeoutMs); };
    const second = await guard.toolboxOff(async () => { throw new Error("no debe pedir confirmación"); });
    guard.execDeps.run = realRun;
    ok(/ya está detenido/.test(second) && seen.length === 1 && seen[0][1] === "inspect" && !seen.some((c) => c.includes("stop")), `014 R(e): un segundo off no llama a docker stop (${seen.map((c) => c[1]).join(",")}): ${second}`);
  } finally {
    for (const id of created) spawnSync("docker", ["rm", "-f", id], { stdio: "ignore" });
    Object.assign(guard.execDeps, savedDeps); runtime.shells.shells = savedShells; runtime.exec = savedExec;
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    rmSync(root, { recursive: true, force: true });
  }
}

// ── #9: a path-shaped socket is rejected and destroys nothing ──────────────────────────────────
const victim = join(DIR, "victim.txt");
writeFileSync(victim, "IMPORTANT DATA");
for (const bad of [victim, "../../etc/passwd", "a/b", "a.b", "-rf", ""]) {
  const r = txt(await tools.session_new.execute("i", { name: "evil", socket: bad }));
  ok(/socket inválido/.test(r), `#9: socket ${JSON.stringify(bad)} rechazado`);
}
ok(existsSync(victim) && readFileSync(victim, "utf-8") === "IMPORTANT DATA" && statSync(victim).isFile(),
  "#9: el archivo víctima sigue INTACTO (archivo regular, contenido intacto)");

// ── valid label: creates a real socket; ours() lets us drive it ────────────────────────────────
const rc = txt(await tools.session_new.execute("i", { name: "foo", socket: "lbl1" }));
ok(/OK:/.test(rc) && /socket=lbl1/.test(rc), `label válida crea sesión: ${rc.split("\n")[0]}`);
ok(existsSync(join(DIR, "lbl1")) && statSync(join(DIR, "lbl1")).isSocket(), "label resuelta a un SOCKET bajo GEKKO_TMUX_DIR");
const rsend = txt(await tools.session_send.execute("i", { name: "foo", socket: "lbl1", input: "echo HELLO_OWN" }));
ok(!/FAIL/.test(rsend), "ours()===true para una sesión viva: session_send funciona");

// ── #1 (same server): killed-then-recreated name fails closed, stranger not driven ─────────────
tmuxS(join(DIR, "lbl2"), ["new-session", "-d", "-s", "keepalive"]);          // hold the server
await tools.session_new.execute("i", { name: "bar", socket: "lbl2" });        // ours (session $?, pid P)
tmuxS(join(DIR, "lbl2"), ["kill-session", "-t", "bar"]);                      // ours dies (server stays up)
tmuxS(join(DIR, "lbl2"), ["new-session", "-d", "-s", "bar"]);                 // stranger re-takes the name (new $)
const rs = txt(await tools.session_send.execute("i", { name: "bar", socket: "lbl2", input: "echo PWNED_HARNESS" }));
ok(/FAIL/.test(rs) && /ya no es la sesión/.test(rs), `#1: session_send FALLÓ cerrado (stale): ${rs.split("\n")[0]}`);
ok(!/PWNED_HARNESS/.test(tmuxS(join(DIR, "lbl2"), ["capture-pane", "-t", "bar", "-p"])), "#1: el pane del extraño NO recibió el comando");

// A stranger re-creates `name` right after a kill-server on the same socket. That new-session races the dying
// server and fails ~4 % of the time (13/300 measured, tmux 3.6b): without the retry the cases below went red at
// random with nothing wrong in the handlers. Retry until the stranger really exists.
function strangerTakes(sock: string, name: string): void {
  for (let i = 0; i < 40; i++) {
    tmuxS(join(DIR, sock), ["new-session", "-d", "-s", name]);
    if (!dead(tmuxS(join(DIR, sock), ["has-session", "-t", name]))) return;
    execFileSync("sleep", ["0.05"]);
  }
}

// ── #1b (SERVER RESTART, id recycle): the serverPid discriminator still refuses ────────────────
await tools.session_new.execute("i", { name: "listener", socket: "ops" });    // ours: server pid P1, session $0
const pid1 = tmuxS(join(DIR, "ops"), ["display-message", "-p", "#{pid}"]).trim();
tmuxS(join(DIR, "ops"), ["kill-server"]);                                     // WHOLE server dies → socket gone
strangerTakes("ops", "listener");                                             // FRESH server: pid P2, session $0 again
const pid2 = tmuxS(join(DIR, "ops"), ["display-message", "-p", "#{pid}"]).trim();
ok(pid1 !== pid2 && !!pid2, `#1b: el server reinició (pid ${pid1} → ${pid2}); el id $0 se recicló`);
// session_kill must NOT kill the stranger (same recorded $0, different server pid)
const rk = txt(await tools.session_kill.execute("i", { name: "listener", socket: "ops" }));
ok(/OK:/.test(rk) && /no se mató nada ajeno/.test(rk), `#1b: session_kill no mató al extraño: ${rk.split("\n")[0]}`);
ok(!dead(tmuxS(join(DIR, "ops"), ["has-session", "-t", "listener"])), "#1b: la sesión del EXTRAÑO sigue viva (no la matamos)");

// ── #3: session_list never labels the stranger as 'propia' ─────────────────────────────────────
// re-register a fresh ours@ops, then simulate a restart+stranger, then list
await tools.session_new.execute("i", { name: "l2", socket: "ops" });
tmuxS(join(DIR, "ops"), ["kill-server"]);
strangerTakes("ops", "l2");                                                   // stranger re-takes 'l2'
const rl2 = txt(await tools.session_list.execute("i", {}));
const propLine = (rl2.split("\n").find(l => l.startsWith("propias")) || "");
ok(!/l2@ops/.test(propLine), `#3: 'l2@ops' (extraño tras restart) NO aparece como propia: ${propLine}`);
ok(/l2@ops/.test(rl2), "#3: 'l2@ops' sí aparece, pero como no-atribuida");

// ── AC09 multi-server: same name on two labels = two sessions; kill one leaves the other ───────
await tools.session_new.execute("i", { name: "m", socket: "sa" });
await tools.session_new.execute("i", { name: "m", socket: "sb" });
const rl = txt(await tools.session_list.execute("i", {}));
ok(/m@sa/.test(rl) && /m@sb/.test(rl), `AC09: session_list distingue m@sa y m@sb`);
const rka = txt(await tools.session_kill.execute("i", { name: "m", socket: "sa" }));
ok(/OK/.test(rka), `AC09: session_kill m@sa OK: ${rka.split("\n")[0]}`);
ok(dead(tmuxS(join(DIR, "sa"), ["has-session", "-t", "m"])), "AC09: m@sa cerrada");
ok(!dead(tmuxS(join(DIR, "sb"), ["has-session", "-t", "m"])), "AC09: m@sb SIGUE VIVA");

// ── REQ-TBX-008 / L7: a socket dir replaced by a symlink is refused before it is listed or used ──
{
  const real = `${DIR}.real`;
  renameSync(DIR, real); symlinkSync(real, DIR);
  let threw = "";
  try { await tools.session_new.execute("i", { name: "viaLink", socket: "lnk" }); } catch (e: any) { threw = e.message; }
  const listed = txt(await tools.session_list.execute("i", {}));
  rmSync(DIR); renameSync(real, DIR);
  ok(/enlace simbólico/.test(threw) && !existsSync(join(DIR, "lnk")), `L7: session_new con el directorio de sockets reemplazado por un symlink falla sin crear nada: ${threw.slice(0, 60)}`);
  ok(/^FAIL/.test(listed) && /enlace simbólico/.test(listed), "L7: session_list lo rehúsa antes de listarlo");
}

// ── REQ-TBX-008 / L8: same pid, different tmux server start_time → not ours ──
{
  const shim = join(DIR, "shim-st"); mkdirSync(shim);
  const flag = join(shim, "flag");
  const realTmux = execFileSync("sh", ["-c", "command -v tmux"], { encoding: "utf-8" }).trim();
  // Once the flag exists, the identity probe of ours() ("#{pid}\t#{session_id}\t#{start_time}") reports a different start_time.
  writeFileSync(join(shim, "tmux"), `#!/usr/bin/env bash
out="$(${JSON.stringify(realTmux)} "$@")"; rc=$?
if [ -e ${JSON.stringify(flag)} ] && [ "\${@: -1}" = $'#{pid}\t#{session_id}\t#{start_time}' ]; then out="$out-restarted"; fi
printf '%s\n' "$out"; exit $rc
`, { mode: 0o755 });
  const pathBefore = process.env.PATH;
  process.env.PATH = `${shim}:${pathBefore}`;
  const made = txt(await tools.session_new.execute("i", { name: "st", socket: "stt" }));
  const before = txt(await tools.session_send.execute("i", { name: "st", socket: "stt", input: "echo ST_BEFORE" }));
  writeFileSync(flag, "");
  const after = txt(await tools.session_send.execute("i", { name: "st", socket: "stt", input: "echo ST_AFTER" }));
  const listing = txt(await tools.session_list.execute("i", {}));
  process.env.PATH = pathBefore;
  ok(made.startsWith("OK") && !/FAIL/.test(before), "L8: control, con el mismo start_time la shell propia se maneja");
  ok(/FAIL/.test(after) && /ya no es la sesión/.test(after) && !/ST_AFTER/.test(tmuxS(join(DIR, "stt"), ["capture-pane", "-t", "st", "-p"])), "L8: mismo pid y distinto start_time → falla cerrado y no se envía nada");
  ok(!/propias \(verificadas\): .*st@stt/.test(listing), "L8: session_list no la da por propia");
  tmuxS(join(DIR, "stt"), ["kill-server"]);
}

// ── spec 010: AC16 / AC17 — la shell nace en el workspace o no nace ─────────────────────────────
const WS = realpathSync(mkdtempSync(join(tmpdir(), "gkws-")));
const wsDir = join(WS, "ws"); mkdirSync(wsDir);
const wsLink = join(WS, "ws-link"); symlinkSync(wsDir, wsLink);
const panePath = (sock: string, name: string) => tmuxS(join(DIR, sock), ["display-message", "-p", "-t", name, "#{pane_current_path}"]).trim();
const hasSession = (sock: string, name: string) => !dead(tmuxS(join(DIR, sock), ["has-session", "-t", name]));
const wsSocks: string[] = [];
const newWs = async (name: string, sock: string, dirEnv: string | undefined) => {
  if (dirEnv === undefined) delete process.env.GEKKO_WORKSPACE_DIR; else process.env.GEKKO_WORKSPACE_DIR = dirEnv;
  wsSocks.push(sock);
  return txt(await tools.session_new.execute("i", { name, socket: sock }));
};

const rNone = await newWs("w0", "wsa", undefined);
ok(/lugar=os$|lugar=os[ .]/.test(rNone.split("\n")[1] ?? ""), `spec 014: session_new dice dónde nació la shell (lugar=os): ${(rNone.split("\n")[1] ?? "").slice(0, 80)}`);
ok(/^OK/.test(rNone) && !/cwd=/.test(rNone) && hasSession("wsa", "w0") && panePath("wsa", "w0") === realpathSync(process.cwd()),
  `sin workspace: sesión OK en el cwd del proceso: ${rNone.split("\n")[0]}`);
const rWs = await newWs("w1", "wsa", wsDir);   // variable puesta DESPUÉS de cargar la extensión y de la primera sesión
ok(/^OK/.test(rWs) && rWs.includes(`cwd=${wsDir}`) && panePath("wsa", "w1") === wsDir, `AC16: workspace re-leído por llamada; pane en ${panePath("wsa", "w1")}`);
const rLink = await newWs("w2", "wsa", wsLink);
ok(/^OK/.test(rLink) && panePath("wsa", "w2") === wsDir, `AC16: workspace vía symlink → ruta real ${panePath("wsa", "w2")}`);
const rAgain = await newWs("w3", "wsa", undefined);
ok(/^OK/.test(rAgain) && panePath("wsa", "w3") === realpathSync(process.cwd()), "sin workspace otra vez: la siguiente sesión ya no nace en él");

const gone = join(WS, "gone"); mkdirSync(gone); rmSync(gone, { recursive: true });
const rGone = await newWs("w4", "wsb", gone);
ok(!existsSync(gone), "spec 014: un directorio de workspace borrado no se vuelve a crear (el directorio de sockets no se crea antes de validarlo)");
ok(rGone.startsWith("FAIL") && /No se creó ninguna sesión/.test(rGone) && !hasSession("wsb", "w4"), `AC17a: directorio borrado → FAIL, sin sesión: ${rGone.split("\n")[0].slice(0, 80)}`);
if (process.getuid?.() === 0) {
  console.log("[skip] AC17b: corre como root, modo 000 no impide entrar");
} else {
  const locked = join(WS, "locked"); mkdirSync(locked); chmodSync(locked, 0o000);
  const rLocked = await newWs("w5", "wsb", locked);
  chmodSync(locked, 0o700);
  ok(rLocked.startsWith("FAIL") && !hasSession("wsb", "w5"), `AC17b: directorio modo 000 → FAIL, sin sesión: ${rLocked.split("\n")[0].slice(0, 80)}`);
}
const aFile = join(WS, "file.txt"); writeFileSync(aFile, "x");
const rFile = await newWs("w6", "wsb", aFile);
ok(rFile.startsWith("FAIL") && !hasSession("wsb", "w6"), `AC17c: archivo regular → FAIL, sin sesión: ${rFile.split("\n")[0].slice(0, 80)}`);

// Rama "nació fuera del workspace → se mata y FAIL" (AC16/AC17), con inyección de fallo DETERMINISTA: un `tmux`
// intermediario, primero en el PATH, le quita el `-c <dir>` a `new-session`. La sesión nace entonces en el cwd del
// proceso y no en el workspace, que es justo lo que haría un tmux que cae en silencio a otro directorio.
// (Un default-command que hace `cd` compite con la lectura de #{pane_current_path}: ~13 % de corridas salía OK.)
{
  const shimDir = join(WS, "shim"); mkdirSync(shimDir);
  const realTmux = execFileSync("sh", ["-c", "command -v tmux"], { encoding: "utf-8" }).trim();
  writeFileSync(join(shimDir, "tmux"), `#!/usr/bin/env bash
a=(); skip=0; isnew=0
for x in "$@"; do [ "$x" = new-session ] && isnew=1; done
for x in "$@"; do
  if [ "$skip" = 1 ]; then skip=0; continue; fi
  if [ "$isnew" = 1 ] && [ "$x" = "-c" ]; then skip=1; continue; fi
  a+=("$x")
done
exec ${JSON.stringify(realTmux)} "\${a[@]}"
`, { mode: 0o755 });
  const pathBefore = process.env.PATH;
  process.env.PATH = `${shimDir}:${pathBefore}`;
  const rBad = await newWs("w7", "wsb", wsDir);
  process.env.PATH = pathBefore;
  ok(rBad.startsWith("FAIL") && /arranc/.test(rBad) && /se cerró/.test(rBad), `mismatch: la shell nació fuera del workspace → FAIL y cierre declarado: ${rBad.split("\n")[0].slice(0, 110)}`);
  ok(!hasSession("wsb", "w7"), "mismatch: la sesión que nació fuera del workspace fue MATADA (no queda viva)");
  const sendBad = txt(await tools.session_send.execute("i", { name: "w7", socket: "wsb", input: "id" }));
  ok(sendBad.startsWith("FAIL") && /no es una sesión creada/.test(sendBad), "mismatch: esa sesión nunca quedó registrada como propia (session_send la rechaza)");
  const rGood = await newWs("w8", "wsb", wsDir);   // control: sin el intermediario, el mismo camino da OK
  ok(/^OK/.test(rGood) && panePath("wsb", "w8") === wsDir, "mismatch (control): sin el intermediario la misma llamada da OK en el workspace");
}
// Dos llamadas simultáneas con el workspace cambiado entre una y otra: cada shell nace en el que regía AL HACER su
// llamada. (Hallado con estrés el 2026-11-14: se leía la variable después de un await y ganaba el último valor.)
{
  const wsDir2 = join(WS, "ws2"); mkdirSync(wsDir2);
  wsSocks.push("wsc");
  process.env.GEKKO_WORKSPACE_DIR = wsDir;
  const pA = tools.session_new.execute("i", { name: "c1", socket: "wsc" });
  process.env.GEKKO_WORKSPACE_DIR = wsDir2;
  const pB = tools.session_new.execute("i", { name: "c2", socket: "wsc" });
  const [rA, rB] = (await Promise.all([pA, pB])).map(txt);
  ok(/^OK/.test(rA) && /^OK/.test(rB) && panePath("wsc", "c1") === wsDir && panePath("wsc", "c2") === wsDir2,
    `concurrencia: cada llamada usa el workspace vigente al hacerla (c1 en ${panePath("wsc", "c1")}, c2 en ${panePath("wsc", "c2")})`);
}

// ── spec 014: `session_new` en toolbox necesita el estado `lista` y la identidad del contenedor; en os la shell nace fuera del
// workspace. Sin docker real: un `docker` intermediario registra cada llamada y devuelve lo que se le pida.
{
  const FAKE_ID = "ab".repeat(32), OTHER_ID = "cd".repeat(32);
  const dockerLog = join(WS, "docker.log"), shimBin = join(WS, "dockershim"), tmpRoot = join(WS, "tmp014");
  mkdirSync(shimBin); mkdirSync(tmpRoot);
  writeFileSync(join(shimBin, "docker"), `#!/bin/sh\necho "$@" >> ${JSON.stringify(dockerLog)}\ncase "$1" in inspect) printf '%s\\n' "$SHIM_INSPECT"; exit "\${SHIM_RC:-0}" ;; *) exit 1 ;; esac\n`, { mode: 0o755 });
  const saved = { EXEC: process.env.GEKKO_EXEC, TOOLBOX: process.env.GEKKO_TOOLBOX, WSDIR: process.env.GEKKO_WORKSPACE_DIR, TMUXDIR: process.env.GEKKO_TMUX_DIR, TMPDIR: process.env.TMPDIR, PATH: process.env.PATH };
  const restore = (k: string, v: string | undefined) => { if (v === undefined) delete process.env[k]; else process.env[k] = v; };
  const logged = () => (existsSync(dockerLog) ? readFileSync(dockerLog, "utf-8").trim().split("\n") : []);
  const noSockDir = () => !existsSync(join(wsDir, ".gekko-sockets"));
  try {
    process.env.GEKKO_EXEC = "toolbox"; process.env.GEKKO_TOOLBOX = FAKE_ID; process.env.GEKKO_WORKSPACE_DIR = wsDir;
    process.env.PATH = `${shimBin}:${saved.PATH}`;
    for (const state of ["levantando", "caída", null] as const) {
      runtime.exec = { state, reason: "prueba" };
      const r = txt(await tools.session_new.execute("i", { name: "st1", socket: "stx" }));
      ok(r.startsWith("FAIL") && r.includes(state ?? "sin estado") && /no se creó la shell en ningún lado/i.test(r) && !existsSync(dockerLog) && noSockDir(),
        `014 AC4: toolbox ${state}: FAIL nombrando el estado, sin invocar docker ni crear nada: ${r.slice(0, 70)}`);
    }
    runtime.exec = { state: "lista", reason: "" };
    const inspectArgv = ["inspect", "--type", "container", "--format", "{{.Id}} {{.State.Running}}", FAKE_ID].join(" ");
    for (const [out, rc, why] of [[`${OTHER_ID} true`, "0", "otro ID"], [`${FAKE_ID} false`, "0", "detenido"], ["", "1", "docker falla"], [`${FAKE_ID} true extra`, "0", "salida inesperada"]]) {
      process.env.SHIM_INSPECT = out; process.env.SHIM_RC = rc;
      const r = txt(await tools.session_new.execute("i", { name: "id1", socket: "stx" }));
      ok(r.startsWith("FAIL") && /ni en el contenedor ni en el host/.test(r) && logged().length === 1 && logged()[0] === inspectArgv && noSockDir(),
        `014 AC3: identidad (${why}): FAIL, una sola llamada \`docker inspect --type container --format …\`, nada creado: ${r.slice(0, 80)}`);
      rmSync(dockerLog);
    }
    process.env.GEKKO_TOOLBOX = "gekko-tb-no-es-un-id";
    const rBadId = txt(await tools.session_new.execute("i", { name: "id2", socket: "stx" }));
    ok(rBadId.startsWith("FAIL") && !existsSync(dockerLog) && noSockDir(), "014 AC3: GEKKO_TOOLBOX que no es un ID de 64 hex: FAIL sin invocar docker");
    process.env.GEKKO_TOOLBOX = FAKE_ID;
    const goneWs = join(WS, "gone014");
    process.env.GEKKO_WORKSPACE_DIR = goneWs;
    const rGoneBox = txt(await tools.session_new.execute("i", { name: "gw1", socket: "stx" }));
    ok(rGoneBox.startsWith("FAIL") && /workspace/.test(rGoneBox) && !existsSync(goneWs) && !existsSync(dockerLog), "014 AC9: toolbox con el workspace borrado: FAIL, el directorio no se recrea (ni el de sockets) y docker no se invoca");

    // os: la etiqueta cae FUERA del workspace aunque Pi se lanzara en toolbox y heredara GEKKO_TMUX_DIR=<ws>/.gekko-sockets.
    process.env.GEKKO_EXEC = "os"; delete process.env.GEKKO_TOOLBOX; process.env.GEKKO_WORKSPACE_DIR = wsDir;
    process.env.GEKKO_TMUX_DIR = join(wsDir, ".gekko-sockets"); process.env.TMPDIR = tmpRoot;
    runtime.exec = { state: null, reason: "" };
    const rOs = txt(await tools.session_new.execute("i", { name: "os1", socket: "osx" }));
    const osSock = join(tmpRoot, "gekko-sockets", "osx");
    ok(/^OK/.test(rOs) && /lugar=os/.test(rOs) && existsSync(osSock) && statSync(osSock).isSocket() && noSockDir(), `014 AC9: shell os con etiqueta: el socket queda en ${osSock}, fuera del workspace, y lugar=os`);
    tmuxS(osSock, ["kill-server"]);
    process.env.TMPDIR = join(wsDir, "tmpx");
    const rNoSafe = txt(await tools.session_new.execute("i", { name: "os2", socket: "osy" }));
    ok(rNoSafe.startsWith("FAIL") && /fuera del workspace/.test(rNoSafe) && noSockDir() && !existsSync(join(wsDir, "tmpx")), `014 AC9: sin directorio de sockets fuera del workspace: FAIL en español y nada creado: ${rNoSafe.slice(0, 80)}`);
  } finally {
    for (const [k, v] of Object.entries({ GEKKO_EXEC: saved.EXEC, GEKKO_TOOLBOX: saved.TOOLBOX, GEKKO_WORKSPACE_DIR: saved.WSDIR, GEKKO_TMUX_DIR: saved.TMUXDIR, TMPDIR: saved.TMPDIR, PATH: saved.PATH })) restore(k, v);
    delete process.env.SHIM_INSPECT; delete process.env.SHIM_RC;
    runtime.exec = { state: null, reason: "" };
  }
}

// REQ-TMUX-010 en tiempo real: un texto que termina en `;` llega a la shell tal cual. Antes `pwd ;` fallaba con
// "unknown command: Enter" y `find … -exec … \;` llegaba sin la barra (hallado en la validación en vivo, 2026-11-14).
{
  const BS = String.fromCharCode(92);
  const sleepMs = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const send = async (input: string) => txt(await tools.session_send.execute("i", { name: "c1", socket: "wsc", input }));
  const rSemi = await send("echo SEMI_FIN ;");
  ok(!rSemi.startsWith("FAIL") && /^SEMI_FIN$/m.test(rSemi), `';' final: session_send no falla y el comando se ejecuta: ${rSemi.startsWith("FAIL") ? rSemi.split("\n")[0] : "ok"}`);
  const rFind = await send(`find . -maxdepth 0 -exec echo HALLADO {} ${BS};`);
  ok(!rFind.startsWith("FAIL") && /^HALLADO \.$/m.test(rFind), `'-exec … \\;': la barra llega a la shell y find corre: ${(rFind.match(/^(HALLADO .*|find: .*)$/m) || ["(sin salida)"])[0]}`);
  const rInit = txt(await tools.session_new.execute("i", { name: "c3", socket: "wsc", command: "echo INICIAL_OK ;" }));
  await sleepMs(600);
  const rRead = txt(await tools.session_read.execute("i", { name: "c3", socket: "wsc" }));
  ok(/^OK/.test(rInit) && /running: echo INICIAL_OK ;/.test(rInit) && /^INICIAL_OK$/m.test(rRead), "';' final en el comando inicial de session_new: se envía y se ejecuta");
}
delete process.env.GEKKO_WORKSPACE_DIR;

// ── spec 011: espejo de shells. El "operador" es un servidor tmux propio en un socket propio: el código bajo prueba
// sólo lo alcanza por el $TMUX que se fija aquí; ninguna llamada de esta sección toca el servidor por defecto.
{
  const OP = join(DIR, "operator");
  const mirrorSocks = ["mir1", "mir3", "mir4", "mir6", "mir7", "mir8", "mir9", "mir10"];
  const killMirrorServers = () => { for (const l of ["operator", ...mirrorSocks]) tmuxS(join(DIR, l), ["kill-server"]); };
  process.on("exit", killMirrorServers); // también si una aserción lanza
  const sleepMs = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const waitFor = async (cond: () => boolean, ms = 5000) => { const end = Date.now() + ms; while (!cond()) { if (Date.now() > end) return false; await sleepMs(50); } return true; };
  const op = (...a: string[]) => tmuxS(OP, a);
  const tuiCtx = { mode: "tui", hasUI: true };
  const saved = { TMUX: process.env.TMUX, TMUX_PANE: process.env.TMUX_PANE, mirror: runtime.mirror };

  op("new-session", "-d", "-s", "opsess", "-x", "200", "-y", "50");
  const opPane = op("display-message", "-p", "-t", "opsess", "#{pane_id}").trim();
  const opPid = op("display-message", "-p", "#{pid}").trim();
  const operatorEnv = () => { process.env.TMUX = `${OP},${opPid},0`; process.env.TMUX_PANE = opPane; };
  const windows = () => op("list-windows", "-t", "opsess", "-F", "#{window_id}\t#{window_name}\t#{window_active}").trim().split("\n").filter(Boolean).map((l) => l.split("\t"));
  const mirrors = () => windows().filter((w) => w[1].startsWith("sh-"));
  const activeWindow = () => windows().find((w) => w[2] === "1")?.[0];
  const mark = (id: string) => op("show-options", "-w", "-t", id, "-v", "@gekko_mirror").trim();
  const created = async (name: string, socket: string | undefined, ctx: any = tuiCtx) => txt(await tools.session_new.execute("i", { name, socket }, undefined, undefined, ctx));
  const ids = (r: string) => ({ session: /id=(\$\d+)/.exec(r)?.[1] ?? "?", pane: /pane=(%\d+)/.exec(r)?.[1] ?? "?" });
  const clientModes = (sock: string, session: string) => tmuxS(sock, ["list-clients", "-t", session, "-F", "#{client_readonly}"]).trim().split("\n").filter(Boolean);
  const hasOn = (sock: string, name: string) => !dead(tmuxS(sock, ["has-session", "-t", name]));
  try {
    // AC1: con TMUX, TUI y check tildado, la ventana espejo nace sin cambiar la activa y el cliente es escribible.
    operatorEnv(); runtime.mirror = true;
    const before = activeWindow();
    const r1 = await created("m1", "mir1");
    const w1 = mirrors().find((w) => w[1] === "sh-m1");
    ok(/^OK/.test(r1) && !!w1, `AC1: shell con etiqueta 'socket' → ventana sh-m1 en la sesión del operador: ${r1.split("\n")[0]}`);
    ok(!!w1 && mark(w1[0]) === String(process.pid), `AC1: la ventana lleva @gekko_mirror=${process.pid} (${w1 ? mark(w1[0]) : "sin ventana"})`);
    ok(activeWindow() === before, "AC1: la ventana activa del operador no cambió");
    const sid1 = ids(r1).session;
    ok(await waitFor(() => clientModes(join(DIR, "mir1"), sid1).length > 0), "AC1: hay un cliente adjunto a la shell etiquetada");
    ok(clientModes(join(DIR, "mir1"), sid1).every((m) => m === "0"), "AC1: ese cliente es escribible (client_readonly=0)");

    const r2 = await created("m2", undefined);   // sin etiqueta: la shell vive en el servidor heredado de $TMUX
    const w2 = mirrors().find((w) => w[1] === "sh-m2");
    ok(/^OK/.test(r2) && !!w2 && hasOn(OP, "m2"), `AC1: shell del servidor del operador → ventana sh-m2: ${r2.split("\n")[0]}`);
    ok(activeWindow() === before, "AC1: la ventana activa sigue igual tras la segunda");
    const sid2 = ids(r2).session;
    ok(await waitFor(() => clientModes(OP, sid2).length > 0) && clientModes(OP, sid2).every((m) => m === "0"), "AC1: cliente escribible adjunto a la shell del servidor del operador");

    // AC3: sin espejo → mismo texto de OK y ninguna ventana nueva.
    const shape = (r: string) => r.split("\n")[0].replace(/\d+/g, "N");
    const winsBefore = windows().length;
    runtime.mirror = false;
    const r3a = await created("m3a", "mir3");
    runtime.mirror = true;
    const r3b = await created("m3b", "mir3", null);
    delete process.env.TMUX; delete process.env.TMUX_PANE;
    const r3c = await created("m3c", "mir3");
    operatorEnv();
    ok(windows().length === winsBefore, "AC3: check destildado, sin ctx y sin TMUX → ninguna ventana nueva");
    ok([r3a, r3b, r3c].every((r) => /^OK/.test(r) && shape(r) === shape(r1.replace("socket=mir1", "socket=mir3"))) && hasOn(join(DIR, "mir3"), "m3a") && hasOn(join(DIR, "mir3"), "m3b") && hasOn(join(DIR, "mir3"), "m3c"),
      `AC3: las tres shells se crean con el mismo formato de OK: ${shape(r3a)}`);

    // AC4: abrir la ventana falla (socket de $TMUX inexistente) → OK igual y la shell es manejable.
    process.env.TMUX = join(DIR, "no-such-socket") + ",1,0"; process.env.TMUX_PANE = "%0";
    const r4 = await created("m4", "mir4");
    const s4 = txt(await tools.session_send.execute("i", { name: "m4", socket: "mir4", input: "echo AC4_$((1+1))" }));
    operatorEnv();
    ok(/^OK/.test(r4) && !s4.startsWith("FAIL") && /^AC4_2$/m.test(s4), `AC4: TMUX inválido → session_new OK y session_send funciona: ${r4.split("\n")[0]}`);

    // AC7: pane en copy-mode → session_send sale del modo y el comando se ejecuta.
    delete process.env.TMUX; delete process.env.TMUX_PANE;
    const r7 = await created("m7", "mir7", null);
    const p7 = ids(r7).pane, s7 = join(DIR, "mir7");
    tmuxS(s7, ["copy-mode", "-t", p7]);
    const inMode = () => tmuxS(s7, ["display-message", "-p", "-t", p7, "#{pane_in_mode}"]).trim();
    const modeBefore = inMode();
    const o7 = txt(await tools.session_send.execute("i", { name: "m7", socket: "mir7", input: "echo AC7_$((20+22))" }));
    ok(modeBefore === "1" && !o7.startsWith("FAIL") && /^AC7_42$/m.test(o7) && inMode() === "0", `AC7: en copy-mode (${modeBefore}) → send OK, comando ejecutado, pane_in_mode=${inMode()}`);

    // AC8: mouse on y Ctrl+D en el prompt no mata la shell.
    const r8 = await created("m8", "mir8", null);
    const i8 = ids(r8), s8 = join(DIR, "mir8");
    ok(tmuxS(s8, ["show-options", "-t", i8.session, "-v", "mouse"]).trim() === "on", "AC8: la sesión nace con mouse on");
    if (/bash$/.test(process.env.SHELL ?? "")) {
      tmuxS(s8, ["send-keys", "-t", i8.pane, "C-d"]);
      await sleepMs(800);
      ok(hasOn(s8, i8.session), "AC8: tras Ctrl+D en el prompt la sesión sigue viva (IGNOREEOF)");
    } else console.log(`[skip] AC8: $SHELL=${process.env.SHELL} no es bash, IGNOREEOF no aplica`);

    // T11 (REQ-TMUX-013): con el pane volviendo a copy-mode cada ~40 ms, todo send que no dé FAIL se ejecutó, una sola vez.
    {
      const r10 = await created("m10", "mir10", null);
      const p10 = ids(r10).pane, s10 = join(DIR, "mir10");
      const toggler = setInterval(() => { execFile("tmux", ["-S", s10, "copy-mode", "-t", p10], () => {}); }, 40);
      const sent: { marker: string; failed: boolean }[] = [];
      for (let n = 0; n < 15; n++) {
        const out = txt(await tools.session_send.execute("i", { name: "m10", socket: "mir10", input: `echo GKSEND_$((${n}+1000))_X` }));
        if (out.startsWith("FAIL")) console.log(`  (T11 FAIL: ${out.split("\n")[0].slice(0, 160)})`);
        sent.push({ marker: `GKSEND_${n + 1000}_X`, failed: out.startsWith("FAIL") });
      }
      clearInterval(toggler);
      await sleepMs(300);
      tmuxS(s10, ["send-keys", "-t", p10, "-X", "cancel"]);
      const history = tmuxS(s10, ["capture-pane", "-p", "-t", p10, "-S", "-"]);
      const count = (m: string) => history.split("\n").filter((l) => l === m).length;
      const lost = sent.filter((x) => !x.failed && count(x.marker) === 0).length;
      const twice = sent.filter((x) => count(x.marker) > 1).length;
      ok(lost === 0 && twice === 0, `T11: ${sent.length} envíos con el pane volviendo a copy-mode: ${lost} perdidos en silencio, ${twice} duplicados, ${sent.filter((x) => x.failed).length} con FAIL`);
    }

    // AC6: session_start y session_shutdown cierran sólo las ventanas propias; las shells y la ajena sobreviven.
    operatorEnv();
    const foreign = op("new-window", "-d", "-P", "-F", "#{window_id}", "-t", "opsess", "-n", "otro-pi").trim();
    op("set-option", "-w", "-t", foreign, "@gekko_mirror", "999999999");
    const fireAll = async (event: string) => { for (const fn of handlers[event] ?? []) await fn({}, {}); };
    for (const event of ["session_start", "session_shutdown"]) {
      if (event === "session_shutdown") { await created("m6", "mir6"); }
      ok(mirrors().length > 0, `AC6 (${event}): antes de disparar hay ventanas espejo propias (${mirrors().length})`);
      await fireAll(event);
      ok(mirrors().length === 0, `AC6 (${event}): las ventanas espejo propias ya no existen`);
      ok(windows().some((w) => w[0] === foreign) && mark(foreign) === "999999999", `AC6 (${event}): la ventana marcada por otra corrida sigue`);
      const shellsAlive = hasOn(join(DIR, "mir1"), "m1") && hasOn(OP, "m2") && (event === "session_start" || hasOn(join(DIR, "mir6"), "m6"));
      ok(shellsAlive, `AC6 (${event}): las shells del agente siguen vivas`);
    }
    ok((handlers.session_shutdown ?? []).length > 0, "AC6: shell-session registra un handler de session_shutdown");
    // T9 (REQ-TMUX-016): session_start que cae con un session_new en vuelo. Se mide tras CADA cambio: uno posterior
    // cerraría lo que uno anterior dejó filtrado y ocultaría el defecto.
    {
      operatorEnv(); runtime.mirror = true;
      const leaked = { windows: 0, owned: 0, ghost: 0 };
      for (const [i, delay] of [0, 5, 10, 20, 30].entries()) {
        const name = `sw${i}`;
        const call = created(name, "mir9");
        await sleepMs(delay);
        for (const fn of handlers.session_start ?? []) await fn({}, {});
        const r = await call;
        await sleepMs(300);
        leaked.windows += mirrors().filter((w) => mark(w[0]) === String(process.pid)).length;
        const listing = txt(await tools.session_list.execute("i", {}));
        if ((listing.split("\n").find((l) => l.startsWith("propias")) ?? "").includes(`${name}@mir9`)) leaked.owned++;
        if (r.startsWith("FAIL") && hasOn(join(DIR, "mir9"), name)) leaked.ghost++;
        for (const fn of handlers.session_start ?? []) await fn({}, {});
      }
      ok(leaked.windows === 0 && leaked.owned === 0 && leaked.ghost === 0, `T9: 5 cambios de sesión con session_new en vuelo: ${leaked.windows} ventanas filtradas, ${leaked.owned} shells adoptadas, ${leaked.ghost} FAIL con la shell viva`);
    }
  } finally {
    if (saved.TMUX === undefined) delete process.env.TMUX; else process.env.TMUX = saved.TMUX;
    if (saved.TMUX_PANE === undefined) delete process.env.TMUX_PANE; else process.env.TMUX_PANE = saved.TMUX_PANE;
    runtime.mirror = saved.mirror;
    killMirrorServers();
  }
}
for (const l of wsSocks) tmuxS(join(DIR, l), ["kill-server"]);
chmodSync(WS, 0o700); rmSync(WS, { recursive: true, force: true });

for (const l of ["lbl1", "lbl2", "ops", "sa", "sb"]) tmuxS(join(DIR, l), ["kill-server"]);
console.log(fail === 0 ? "\n[PASS] handlers reales: #9 + #1 + #1b(restart) + #3 + AC09 + AC16/AC17 (determinista, sin modelo)" : `\n[FAIL] ${fail} aserción(es)`);
process.exit(fail === 0 ? 0 : 1);
