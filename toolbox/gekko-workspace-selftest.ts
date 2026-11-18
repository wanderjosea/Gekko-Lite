// Spec 010 — casos del workspace. Lo corre el gate (`GEKKO_GUARD_SELFTEST=1 node --experimental-strip-types
// toolbox/gekko-guard.ts`) con el mismo mapa `counts` de la traza REQ. `deps.scopeAccepts` es la regla REAL
// de scope del broker (`parseScopeLine` de gekko-guard.ts), inyectada para no importar el guard desde aquí.
// Sin red, sin tmux, sin procesos hijos: el menú se maneja con un `PickIo` doble y el andamiaje con directorios temporales.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, statSync, lstatSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  validWorkspaceName, confined, parseTargets, scopeLine, scopeFileText, scopeEntries, replaceScopeText,
  scaffoldPlan, applyScaffold, newSessionArgs, cwdVerdict, workspacePromptBlock, pickFlow, dockerContainerExists, type PickIo, type Target,
  parseExecMode, tmuxCommand, ledgerCliOnly, toolboxName, toolboxRunArgs, toolboxPlan, toolboxMountsOk, ensureToolbox, readRegularFile, readPanelLedger, socketDir, writeExecMode, SHELL_NAME_RE,
  type ExecMode, type Run, type RunResult, type ToolboxFs,
} from "./gekko-workspace.ts";

export type WorkspaceSelftestDeps = { scopeAccepts(line: string): boolean };

const FALLBACK_SCOPE_RULE = (line: string) => /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(line);

type FakeOpts = {
  names?: string[]; last?: string | null; answers: (string | null)[]; live?: number | null;
  resolves?: Record<string, string | null>; scope?: string; containers?: string[] | null;
};

function fakeIo(o: FakeOpts) {
  const answers = [...o.answers];
  const rec = {
    prompts: [] as string[], written: "", creates: [] as { name: string; targets: Target[]; mode: ExecMode }[],
    replaces: [] as { name: string; targets: Target[] }[], resolved: [] as string[], liveAsked: [] as string[],
  };
  const io: PickIo = {
    readLine: async (prompt) => { rec.prompts.push(prompt); return answers.length > 0 ? answers.shift()! : null; },
    write: (s) => { rec.written += s; },
    list: () => o.names ?? ["a", "b"],
    lastUsed: () => o.last ?? null,
    liveShells: (name) => { rec.liveAsked.push(name); return o.live === undefined ? null : o.live; },
    readScope: () => o.scope ?? "# c\n10.0.0.1\n",
    create: (name, targets, mode) => { rec.creates.push({ name, targets, mode }); },
    replaceScope: (name, targets) => { rec.replaces.push({ name, targets }); },
    resolve: async (host) => { rec.resolved.push(host); return o.resolves?.[host] ?? null; },
    containerExists: (name) => (o.containers === null ? null : (o.containers ?? []).includes(name)),
  };
  return { io, rec };
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

// REQ-WS-007: cláusulas del contrato del lanzador que NO cumple el texto dado (vacío = lo cumple). Sólo regex sobre
// el código sin líneas de comentario; el comportamiento real lo prueba tools/ws-test.sh con un `pi` falso.
function launcherViolations(src: string): string[] {
  const code = src.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
  const v: string[] = [];
  const wsAt = code.indexOf("gekko-workspace.ts"), piAt = code.indexOf('"${pi_cmd[@]}"');
  if (wsAt < 0 || piAt < 0 || wsAt > piAt) v.push("workspace-antes-de-pi");
  if (!/falta GEKKO_WORKSPACE[\s\S]{0,400}?exit 1/.test(code)) v.push("error-sin-terminal");
  if (!/ws_cli check "\$ws"\)" \|\| \{[^\n]*exit 1/.test(code)) v.push("check-corta-el-arranque");
  if (!/export GEKKO_WORKSPACE="\$ws"/.test(code)) v.push("export-GEKKO_WORKSPACE");
  if (!/export GEKKO_WORKSPACE_DIR="\$ws_dir"/.test(code)) v.push("export-GEKKO_WORKSPACE_DIR");
  if (!/export GEKKO_SCOPE="\$ws_dir\/scope\.txt"/.test(code)) v.push("export-GEKKO_SCOPE");
  if (!/export GEKKO_FINDINGS="\$ws_dir\/findings\.jsonl"/.test(code)) v.push("export-GEKKO_FINDINGS");
  if (!/session_dir="\$ws_dir\/\.pi-sessions"/.test(code) || !/export PI_CODING_AGENT_SESSION_DIR="\$session_dir"/.test(code)) v.push("export-PI_CODING_AGENT_SESSION_DIR");
  if (!/exec env -u GEKKO_WORKSPACE -u GEKKO_WORKSPACE_DIR tmux new-session env [^\n]*GEKKO_WORKSPACE="\$ws"/.test(code)) v.push("relanzamiento-limpio");
  if (!/ws_cli prompt "\$ws"/.test(code) || !/--append-system-prompt "\$generated_prompt"/.test(code)) v.push("prompt-generado");
  return v;
}

// REQ-RPT-013: cláusulas del lanzador sobre GEKKO_REPORT_URL que NO cumple el texto (vacío = lo cumple). Sólo regex.
function reportUrlViolations(src: string): string[] {
  const code = src.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
  const v: string[] = [];
  const unsetAt = code.indexOf("unset GEKKO_REPORT_URL"), ensureAt = code.search(/findings_web\.py"? ensure/);
  if (unsetAt < 0 || ensureAt < 0 || unsetAt > ensureAt) v.push("unset-antes-de-ensure");
  const guard = code.match(/if \[ "\$ws" != "none" \] && \[ "\$\{GEKKO_REPORT:-1\}" != "0" \]; then([\s\S]*?)\nfi\n/);
  if (!guard || !/findings_web\.py"? ensure/.test(guard[1])) v.push("ensure-con-guarda");
  const exports = code.match(/export GEKKO_REPORT_URL/g) ?? [];
  const okBranch = guard?.[1].match(/if \[ "\$report_ok" = 1 \][^\n]*; then\n\s*export GEKKO_REPORT_URL=[^\n]*\n\s*else/);
  if (exports.length !== 1 || !okBranch) v.push("export-sólo-si-ensure-salió-0");
  return v;
}

// ── spec 013: modo de ejecución y toolbox ──
const CLI = fileURLToPath(new URL("./gekko-workspace.ts", import.meta.url));
const cli = (root: string, args: string[]) => {
  const r = spawnSync(process.execPath, ["--no-warnings", "--experimental-strip-types", CLI, ...args], { env: { ...process.env, GEKKO_WS_ROOT: root }, encoding: "utf-8", timeout: 20000 });
  return { code: r.status, out: r.stdout.trim(), err: r.stderr };
};

const GOOD: RunResult = { code: 0, out: "", err: "" };
const fail = (code: number, err: string): RunResult => ({ code, out: "", err });
const CONTAINER_ID = "c0ffee".repeat(10) + "abcd";
const inspectOf = (running: boolean, mounts: { Type?: string; Source: string; Destination: string; RW: boolean; Propagation?: string }[]) =>
  JSON.stringify([{
    Id: CONTAINER_ID, Image: "sha256:test", NetworkSettings: { Networks: { bridge: {} } },
    Config: { Cmd: ["sleep", "infinity"], Entrypoint: null, User: "" },
    HostConfig: {
      NetworkMode: "default", Privileged: false, Init: true, CapAdd: ["NET_ADMIN"], CapDrop: ["MKNOD"], Devices: [{ PathOnHost: "/dev/net/tun", PathInContainer: "/dev/net/tun", CgroupPermissions: "rwm" }],
      PidMode: "", IpcMode: "private", UsernsMode: "", SecurityOpt: null, PortBindings: {}, PublishAllPorts: false, ExtraHosts: null, Dns: null, DeviceRequests: null, RestartPolicy: { Name: "no" },
    },
    State: { Running: running }, Mounts: mounts.map((m) => ({ Type: "bind", Propagation: "rprivate", ...m })),
  }]);

function fakeRun(answers: { version?: RunResult; image?: RunResult; inspect?: RunResult; acl?: RunResult; start?: RunResult }) {
  const calls: string[][] = [];
  const run: Run = (file, args) => {
    calls.push([file, ...args]);
    if (file === "setfacl") return answers.acl ?? GOOD;
    if (args[0] === "version") return answers.version ?? GOOD;
    if (args[0] === "image") return answers.image ?? { ...GOOD, out: "sha256:test" };
    if (args[0] === "inspect") return answers.inspect ?? fail(1, "Error: No such object: x");
    return answers.start ?? { ...GOOD, out: CONTAINER_ID + "\n" };
  };
  return { run, calls, started: () => calls.filter((c) => c[0] === "docker" && (c[1] === "run" || c[1] === "start")) };
}

async function toolboxCases(req: (id: string) => void, check: (c: boolean, m: string) => void): Promise<void> {
  const R = "/r", WS = "/r/engagements/acme", TOOLS = "/r/.claude/tools";
  const rwWs = { Source: WS, Destination: WS, RW: true }, roTools = { Source: TOOLS, Destination: TOOLS, RW: false };
  const roFile = (file: string) => ({ Source: `${WS}/${file}`, Destination: `${WS}/${file}`, RW: false });
  const sessionsMask = { Type: "tmpfs", Source: "", Destination: `${WS}/.pi-sessions`, RW: true, Propagation: "" };
  const guarded = [roFile("exec"), roFile("scope.txt"), sessionsMask]; // sin AUTHORIZATION.md
  const fullMounts = [rwWs, roTools, ...guarded];
  const fakeFs = (kinds: Record<string, "file" | "dir" | "other" | "missing"> = {}, subdirs: string[] = []): ToolboxFs => ({
    kind: (path) => { const leaf = path.split("/").pop()!; return kinds[leaf] ?? (leaf === ".pi-sessions" ? "dir" : leaf === "AUTHORIZATION.md" ? "missing" : "file"); },
    ownedSubdirs: () => subdirs,
  });

  // ── REQ-TBX-001 ──
  req("REQ-TBX-001");
  check(parseExecMode(null) === "os", "TBX-001: sin archivo → os");
  for (const [text, want] of [["os", "os"], ["toolbox", "toolbox"], [" os \n", "os"], ["\ntoolbox\n", "toolbox"], ["toolbox\r\n", "toolbox"]] as const)
    check(parseExecMode(text) === want, `TBX-001: '${JSON.stringify(text)}' → ${want}`);
  for (const text of ["OS", "docker", "", "  \n", "os toolbox", "os\ntoolbox", "toolbox2", "tool box"]) check(parseExecMode(text) === null, `TBX-001: ${JSON.stringify(text)} → null`);
  const tmp = mkdtempSync(join(tmpdir(), "gkws-tbx-"));
  try {
    const dir = (name: string) => join(tmp, "engagements", name);
    const none = cli(tmp, ["new", "w-none", "192.0.2.1"]);
    check(none.code === 0 && !existsSync(join(dir("w-none"), "exec")), "TBX-001: new sin --exec no escribe el archivo");
    check(cli(tmp, ["mode", "w-none"]).out === "os" && cli(tmp, ["mode", "w-none"]).code === 0, "TBX-001: mode sin archivo imprime os y sale 0");
    check(cli(tmp, ["mode", "none"]).out === "os", "TBX-001: mode none imprime os");
    const tb = cli(tmp, ["new", "w-tb", "--exec", "toolbox", "192.0.2.2", "web"]);
    check(tb.code === 0 && readFileSync(join(dir("w-tb"), "exec"), "utf-8").trim() === "toolbox", "TBX-001: new --exec toolbox escribe toolbox");
    check(readFileSync(join(dir("w-tb"), "scope.txt"), "utf-8").includes("192.0.2.2  # web"), "TBX-001: --exec no se mezcla con los objetivos");
    check(cli(tmp, ["mode", "w-tb"]).out === "toolbox", "TBX-001: mode devuelve toolbox");
    check(cli(tmp, ["new", "w-os", "--exec", "os"]).code === 0 && cli(tmp, ["mode", "w-os"]).out === "os", "TBX-001: new --exec os escribe os");
    const again = cli(tmp, ["new", "w-tb", "--exec", "os"]);
    check(again.code === 0 && readFileSync(join(dir("w-tb"), "exec"), "utf-8").trim() === "toolbox", "TBX-001: new no sobrescribe un exec existente");
    for (const badValue of ["docker", "OS", ""]) {
      const r = cli(tmp, ["new", "w-bad", "--exec", badValue]);
      check(r.code === 1 && r.err.includes("--exec") && !existsSync(dir("w-bad")), `TBX-001: --exec '${badValue}' se rechaza sin crear`);
    }
    check(cli(tmp, ["new", "w-bad2", "--exec"]).code === 1, "TBX-001: --exec sin valor se rechaza");
    writeFileSync(join(dir("w-none"), "exec"), "docker\n");
    const invalid = cli(tmp, ["mode", "w-none"]);
    check(invalid.code === 1 && invalid.err.includes("no se entiende") && invalid.out === "", "TBX-001: contenido inválido → salida 1 con mensaje");
    check(cli(tmp, ["prompt", "w-none"]).code === 1, "TBX-001: prompt sin el modo ya resuelto falla");
    // M3: un archivo de modo o de scope que no es regular (enlace simbólico, FIFO) no se lee.
    const execFile = join(dir("w-tb"), "exec"), scopeFile = join(dir("w-tb"), "scope.txt");
    const target = join(tmp, "elsewhere");
    writeFileSync(target, "os\n");
    rmSync(execFile); symlinkSync(target, execFile);
    const linkedMode = cli(tmp, ["mode", "w-tb"]);
    check(linkedMode.code === 1 && linkedMode.out === "" && /enlace simbólico/.test(linkedMode.err), "TBX-001: exec enlace simbólico → mode falla sin leerlo");
    rmSync(execFile);
    check(spawnSync("mkfifo", [execFile]).status === 0, "TBX-001: precondición, FIFO creada");
    const fifoMode = cli(tmp, ["mode", "w-tb"]);
    check(fifoMode.code === 1 && /no es un archivo regular/.test(fifoMode.err), "TBX-001: exec FIFO → mode falla sin quedarse leyendo");
    rmSync(execFile); writeFileSync(execFile, "toolbox\n");
    rmSync(scopeFile); symlinkSync(target, scopeFile);
    const linkedScope = cli(tmp, ["check", "w-tb"]);
    check(linkedScope.code === 1 && /enlace simbólico/.test(linkedScope.err) && cli(tmp, ["scope", "w-tb"]).code === 1, "TBX-001: scope.txt enlace simbólico → check y scope fallan");
    rmSync(scopeFile); spawnSync("mkfifo", [scopeFile]);
    check(cli(tmp, ["check", "w-tb"]).code === 1, "TBX-001: scope.txt FIFO → check falla");
    // D6: writeExecMode crea, reescribe EN EL LUGAR (mismo inodo: el contenedor monta el archivo por inodo) y no sigue enlaces.
    const wdir = join(tmp, "wem");
    mkdirSync(wdir);
    const wexec = join(wdir, "exec");
    const throws = (fn: () => void) => { try { fn(); return false; } catch { return true; } };
    writeExecMode(wdir, "os");
    check(readFileSync(wexec, "utf-8") === "os\n", "TBX-001: writeExecMode crea el archivo");
    const inoBefore = statSync(wexec).ino;
    writeExecMode(wdir, "toolbox");
    check(readFileSync(wexec, "utf-8") === "toolbox\n" && statSync(wexec).ino === inoBefore, "TBX-001: writeExecMode reescribe conservando el inodo");
    writeExecMode(wdir, "os");
    check(readFileSync(wexec, "utf-8") === "os\n" && statSync(wexec).ino === inoBefore, "TBX-001: writeExecMode a un valor más corto no deja restos");
    check(throws(() => writeExecMode(wdir, "docker" as ExecMode)) && throws(() => writeExecMode(wdir, "OS" as ExecMode)) && readFileSync(wexec, "utf-8") === "os\n", "TBX-001: writeExecMode rehúsa un modo inválido sin tocar el archivo");
    const wvictim = join(tmp, "victim");
    writeFileSync(wvictim, "intacto\n");
    rmSync(wexec); symlinkSync(wvictim, wexec);
    check(throws(() => writeExecMode(wdir, "toolbox")) && readFileSync(wvictim, "utf-8") === "intacto\n", "TBX-001: writeExecMode rehúsa un enlace simbólico y no escribe en su destino");
    rmSync(wexec); symlinkSync(join(tmp, "no-existe-aun"), wexec);
    check(throws(() => writeExecMode(wdir, "toolbox")) && !existsSync(join(tmp, "no-existe-aun")), "TBX-001: writeExecMode rehúsa un enlace colgante sin crear su destino");
    rmSync(wexec);
    check(spawnSync("mkfifo", [wexec]).status === 0 && throws(() => writeExecMode(wdir, "toolbox")), "TBX-001: writeExecMode rehúsa una FIFO sin bloquear");
    rmSync(wexec);
    check(readRegularFile(join(tmp, "no-existe")) === null && readRegularFile(target) === "os\n", "TBX-001: readRegularFile lee uno regular y da null si no existe");
    // El ledger del panel (GEKKO_FINDINGS): en toolbox el root del contenedor puede poner ahí un enlace, una FIFO o un archivo enorme.
    const pled = join(tmp, "panel-findings.jsonl"), psecret = join(tmp, "otro-engagement.jsonl");
    writeFileSync(psecret, '{"status":"confirmed","title":"SECRETO-AJENO"}\n');
    writeFileSync(pled, '{"status":"hypothesis"}\n');
    const regular = readPanelLedger(pled);
    rmSync(pled); symlinkSync(psecret, pled);
    const linked = readPanelLedger(pled);
    rmSync(pled); spawnSync("mkfifo", [pled]);
    const began = Date.now(), fifo = readPanelLedger(pled), fifoMs = Date.now() - began;
    rmSync(pled); writeFileSync(pled, "x".repeat(65));
    const big = readPanelLedger(pled, 64);
    check(regular === '{"status":"hypothesis"}\n' && linked === null && fifo === null && fifoMs < 1000 && big === null
      && readPanelLedger(join(tmp, "no-existe")) === null,
      "TUI-018: readPanelLedger lee el ledger regular y da null, sin seguir, bloquear ni lanzar, ante un enlace, una FIFO, uno sobre el tope o ninguno");
    const guardText = readFileSync(new URL("./gekko-guard.ts", import.meta.url), "utf-8");
    check(/ledger: \(\) => \(ledgerPath \? readPanelLedger\(ledgerPath\) : null\)/.test(guardText) && !/ledger: \(\) => \(ledgerPath \? readText/.test(guardText),
      "TUI-018: el lector real del panel (io.ledger del guard) pasa por readPanelLedger");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }

  // ── REQ-TBX-002 ──
  req("REQ-TBX-002");
  for (const [answer, want] of [["", "os"], ["o", "os"], ["OS", "os"], ["t", "toolbox"], [" toolbox ", "toolbox"]] as const) {
    const t = fakeIo({ answers: ["n", "h1", "10.0.0.5", answer] });
    check(await pickFlow(t.io) === "h1" && t.rec.creates.length === 1 && t.rec.creates[0].mode === want, `TBX-002: '${answer}' → ${want}`);
    check(t.rec.prompts.at(-1)!.includes("shells") && same(t.rec.creates[0].targets, [{ ip: "10.0.0.5" }]), `TBX-002: tras los objetivos se pregunta el modo ('${answer}')`);
  }
  const again = fakeIo({ answers: ["n", "h1", "", "docker", "toolbox"] });
  check(await pickFlow(again.io) === "h1" && again.rec.creates[0].mode === "toolbox" && again.rec.written.includes("responde Enter"), "TBX-002: respuesta inválida → explica y repite la pregunta");
  check(again.rec.prompts.filter((p) => p.includes("nacen las shells")).length === 2, "TBX-002: la pregunta se hizo dos veces");
  const eof = fakeIo({ answers: ["n", "h1", ""] });
  check(await pickFlow(eof.io) === null && eof.rec.creates.length === 0, "TBX-002: fin de entrada al preguntar el modo → null sin crear");
  // ── REQ-TBX-013 ──
  req("REQ-TBX-013");
  const clash = fakeIo({ answers: ["n", "h1", "h2", "10.0.0.5", "t"], containers: ["h1"] });
  check(await pickFlow(clash.io) === "h2" && same(clash.rec.creates.map((c) => c.name), ["h2"]) && clash.rec.written.includes("docker rm -f gekko-tb-h1"),
    "TBX-013: un nombre cuyo contenedor gekko-tb-<nombre> ya existe no crea nada, explica cómo borrarlo y vuelve a pedir el nombre");
  const clashEof = fakeIo({ answers: ["n", "h1"], containers: ["h1"] });
  check(await pickFlow(clashEof.io) === null && clashEof.rec.creates.length === 0, "TBX-013: fin de entrada tras el aviso del contenedor → null sin crear");
  const inspectRun = (code: number, err: string) => () => ({ code, out: "", err });
  check(dockerContainerExists("h1", inspectRun(0, "")) === true && dockerContainerExists("h1", inspectRun(1, "Error: No such object: gekko-tb-h1")) === false
    && dockerContainerExists("h1", inspectRun(127, "ENOENT")) === null && dockerContainerExists("h1", inspectRun(1, "permission denied")) === null,
    "TBX-013: dockerContainerExists da true, false o null (sin dato) según docker inspect");
  const noDockerPick = fakeIo({ answers: ["n", "h1", "10.0.0.5", ""], containers: null });
  check(await pickFlow(noDockerPick.io) === "h1" && noDockerPick.rec.creates.length === 1, "TBX-013: sin dato de docker (no instalado o sin respuesta) se crea igual");
  const existing = fakeIo({ answers: ["a", ""] });
  check(await pickFlow(existing.io) === "a" && !existing.rec.prompts.some((p) => p.includes("nacen las shells")) && existing.rec.creates.length === 0, "TBX-002: entrar a un workspace existente no pregunta el modo");

  // ── REQ-TBX-003 ──
  req("REQ-TBX-003");
  check(toolboxName("acme") === "gekko-tb-acme", "TBX-003: nombre del contenedor");
  const base = { name: "gekko-tb-acme", image: "gekko-toolbox:latest", root: R, wsDir: WS };
  const mask = ["--mount", `type=tmpfs,destination=${WS}/.pi-sessions,tmpfs-size=1048576,tmpfs-mode=0700`];
  const expected = ["run", "-d", "--init", "--name", "gekko-tb-acme", "--cap-add=NET_ADMIN", "--cap-drop=MKNOD", "--device=/dev/net/tun", "-v", `${WS}:${WS}`,
    "-v", `${WS}/exec:${WS}/exec:ro`, "-v", `${WS}/scope.txt:${WS}/scope.txt:ro`, ...mask, "-v", `${TOOLS}:${TOOLS}:ro`, "-w", WS, "gekko-toolbox:latest", "sleep", "infinity"];
  const beforeWorkdir = expected.indexOf("-w");
  check(same(toolboxRunArgs(base), expected), "TBX-003: argumentos exactos sin .ovpn ni AUTHORIZATION.md");
  check(same(toolboxRunArgs({ ...base, ovpn: "/h/t.ovpn" }), [...expected.slice(0, beforeWorkdir), "-v", "/h/t.ovpn:/vpn/target.ovpn:ro", ...expected.slice(beforeWorkdir)]), "TBX-003: argumentos exactos con .ovpn");
  check(same(toolboxRunArgs({ ...base, authorization: true }), [...expected.slice(0, 14), "-v", `${WS}/AUTHORIZATION.md:${WS}/AUTHORIZATION.md:ro`, ...expected.slice(14)]), "TBX-003: con AUTHORIZATION.md regular se monta de sólo lectura sobre sí mismo");
  const runText = toolboxRunArgs(base).join(" ");
  check(!runText.includes(".gekko-state") && !runText.includes("-v /r:") && !/ \/r\/engagements( |:)/.test(runText), "TBX-003: no monta la raíz ni .gekko-state ni engagements entero");
  for (const o of [{ ...base, wsDir: "/r/engagements/a:b" }, { ...base, root: "/r:x" }, { ...base, ovpn: "/h/t:1.ovpn" }, { ...base, wsDir: "/r/engagements/a,b" }])
    check((() => { try { toolboxRunArgs(o); return false; } catch { return true; } })(), "TBX-003: una ruta con ':' se rechaza");
  const plans: [Parameters<typeof toolboxPlan>, string][] = [[["absent", false], "run"], [["absent", true], "run"], [["stopped", true], "start"], [["running", true], "reuse"], [["stopped", false], "refuse"], [["running", false], "refuse"]];
  for (const [args, want] of plans) check(toolboxPlan(...args) === want, `TBX-003: plan ${args.join("/")} → ${want}`);
  const mountsOk = (mounts: Parameters<typeof inspectOf>[1], ovpn?: string) => toolboxMountsOk(inspectOf(true, [...mounts, ...guarded]), R, WS, ovpn);
  check(mountsOk([rwWs, roTools]), "TBX-003: montajes exactos");
  check(mountsOk([roTools, rwWs]), "TBX-003: el orden no importa");
  check(mountsOk([rwWs, roTools, { Source: "/h/t.ovpn", Destination: "/vpn/target.ovpn", RW: false }], "/h/t.ovpn"), "TBX-003: con el .ovpn esperado de sólo lectura");
  check(!mountsOk([rwWs, roTools, { Source: "/etc/passwd", Destination: "/vpn/target.ovpn", RW: false }], "/h/t.ovpn"), "TBX-003: origen .ovpn distinto se rechaza");
  check(!mountsOk([rwWs, roTools, { Source: "/h/t.ovpn", Destination: "/vpn/target.ovpn", RW: false }]), "TBX-003: .ovpn no solicitado se rechaza");
  check(!mountsOk([rwWs, roTools], "/h/t.ovpn"), "TBX-003: falta el .ovpn esperado se rechaza");
  check(!mountsOk([rwWs, roTools, { Source: "/h/t.ovpn", Destination: "/vpn/target.ovpn", RW: true }]), "TBX-003: .ovpn escribible se rechaza");
  check(!mountsOk([rwWs, roTools, { Source: "/etc", Destination: "/etc", RW: false }]), "TBX-003: un montaje de más se rechaza");
  check(!mountsOk([rwWs, roTools, { Type: "volume", Source: "v", Destination: "/data", RW: true }]), "TBX-003: un volumen de más se rechaza");
  check(!mountsOk([{ Source: R, Destination: R, RW: true }]), "TBX-003: el repo entero se rechaza");
  check(!mountsOk([{ Source: R, Destination: R, RW: true }, rwWs, roTools]), "TBX-003: repo entero además de los esperados se rechaza");
  check(!mountsOk([{ ...rwWs, RW: false }, roTools]), "TBX-003: workspace en sólo lectura se rechaza");
  check(!mountsOk([rwWs, { ...roTools, RW: true }]), "TBX-003: .claude/tools escribible se rechaza");
  check(!mountsOk([{ Source: "/otra", Destination: WS, RW: true }, roTools]), "TBX-003: otro origen para el workspace se rechaza");
  check(!mountsOk([{ Source: "/otra", Destination: "/otra", RW: true }, roTools]), "TBX-003: otra ruta se rechaza");
  check(!mountsOk([rwWs]), "TBX-003: faltar .claude/tools se rechaza");
  check(!mountsOk([]) && !toolboxMountsOk("no es json", R, WS) && !toolboxMountsOk("[]", R, WS) && !toolboxMountsOk("[{}]", R, WS), "TBX-003: salida de inspect irreconocible → no ok");

  const ensure = (answers: Parameters<typeof fakeRun>[0], extra: { ovpn?: string; ws?: string; root?: string; fs?: ToolboxFs } = {}) => {
    const f = fakeRun(answers);
    let name: string | null = null, error = "";
    try { name = ensureToolbox({ root: extra.root ?? R, ws: extra.ws ?? "acme", image: "gekko-toolbox:latest", ovpn: extra.ovpn, uid: 1234, run: f.run, fs: extra.fs ?? fakeFs() }); } catch (e) { error = (e as Error).message; }
    return { name, error, calls: f.calls, started: f.started };
  };
  const good = { out: inspectOf(true, fullMounts) };
  for (const changes of [
    { Image: "sha256:other" },
    { HostConfig: { NetworkMode: "host" } },
    { HostConfig: { Privileged: true } },
    { HostConfig: { CapAdd: ["NET_ADMIN", "SYS_ADMIN"] } },
    { HostConfig: { Devices: [] } },
    { HostConfig: { CapDrop: [] } },
    { HostConfig: { CapDrop: null } },
    { HostConfig: { PidMode: "host" } },
    { HostConfig: { IpcMode: "host" } },
    { HostConfig: { UsernsMode: "host" } },
    { HostConfig: { SecurityOpt: ["seccomp=unconfined"] } },
    { HostConfig: { Init: false } },
    { HostConfig: { CapAdd: ["CAP_NET_ADMIN", "CAP_SYS_ADMIN"] } },
    { HostConfig: { DeviceCgroupRules: ["b 8:* rwm"] } },
    { NetworkSettings: { Networks: { bridge: {}, extra: {} } } },
    { HostConfig: { PortBindings: { "80/tcp": [{ HostIp: "0.0.0.0", HostPort: "8080" }] } } },
    { HostConfig: { PublishAllPorts: true } },
    { HostConfig: { ExtraHosts: ["evil:10.0.0.1"] } },
    { HostConfig: { Dns: ["10.0.0.53"] } },
    { HostConfig: { DeviceRequests: [{ Driver: "nvidia" }] } },
    { HostConfig: { RestartPolicy: { Name: "always" } } },
    { Config: { Cmd: ["sleep", "1"], Entrypoint: null, User: "" } },
    { Config: { Cmd: ["sleep", "infinity", "--x"], Entrypoint: null, User: "" } },
    { Config: { Cmd: ["sleep", "infinity"], Entrypoint: ["/bin/evil"], User: "" } },
    { Config: { Cmd: ["sleep", "infinity"], Entrypoint: null, User: "1000" } },
    { Mounts: JSON.parse(good.out)[0].Mounts.map((m: object) => ({ ...m, Propagation: "rshared" })) },
  ]) {
    const entry = JSON.parse(good.out)[0];
    const hostile = JSON.stringify([{ ...entry, ...changes, HostConfig: { ...entry.HostConfig, ...("HostConfig" in changes ? changes.HostConfig : {}) } }]);
    const r = ensure({ inspect: { code: 0, out: hostile, err: "" } });
    check(r.name === null && r.started().length === 0 && !r.calls.some((c) => c[0] === "setfacl"), "TBX-003: imagen o aislamiento distinto se rehúsa antes de ACL/start");
  }
  const bridgeEntry = JSON.parse(good.out)[0];
  bridgeEntry.HostConfig.NetworkMode = "bridge";
  bridgeEntry.HostConfig.CapAdd = ["CAP_NET_ADMIN"];
  bridgeEntry.HostConfig.CapDrop = ["CAP_MKNOD"];
  check(ensure({ inspect: { code: 0, out: JSON.stringify([bridgeEntry]), err: "" } }).name === CONTAINER_ID, "TBX-003: Docker 29 (NetworkMode bridge, CapAdd CAP_NET_ADMIN, CapDrop CAP_MKNOD) se reutiliza");
  const noDocker = ensure({ version: fail(127, "ENOENT") });
  check(noDocker.name === null && /docker no está instalado/.test(noDocker.error) && noDocker.started().length === 0, "TBX-003: sin docker → error sin docker run");
  const noPerm = ensure({ version: fail(1, "permission denied while trying to connect to the Docker daemon socket") });
  check(noPerm.name === null && /sin permiso/.test(noPerm.error) && noPerm.started().length === 0, "TBX-003: sin permiso → error sin docker run");
  const down = ensure({ version: fail(1, "Cannot connect to the Docker daemon") });
  check(down.name === null && /no responde/.test(down.error), "TBX-003: daemon caído → error");
  const noImage = ensure({ image: fail(1, "No such image") });
  check(noImage.name === null && noImage.error.includes("make -C toolbox build") && noImage.started().length === 0 && !noImage.calls.some((c) => c[0] === "setfacl"), "TBX-003: sin imagen → nombra 'make -C toolbox build', sin docker run ni ACL");
  const absent = ensure({});
  check(absent.name === CONTAINER_ID && same(absent.started(), [["docker", ...expected]]), "TBX-003: ausente → un docker run con los argumentos esperados; devuelve el ID que docker imprimió");
  const aclAt = absent.calls.findIndex((c) => c[0] === "setfacl"), runAt = absent.calls.findIndex((c) => c[1] === "run");
  check(aclAt >= 0 && aclAt < runAt && same(absent.calls[aclAt], ["setfacl", "-m", "d:u:1234:rwx,u:1234:rwx", WS]), "TBX-003: la ACL del usuario se aplica al workspace antes de crear el contenedor");
  const stopped = ensure({ inspect: { code: 0, out: inspectOf(false, fullMounts), err: "" } });
  check(stopped.name === CONTAINER_ID && same(stopped.started(), [["docker", "start", CONTAINER_ID]]), "TBX-003: detenido → docker start por ID, devuelve el ID validado");
  const running = ensure({ inspect: { code: 0, ...good, err: "" } });
  check(running.name === CONTAINER_ID && running.started().length === 0 && running.calls.some((c) => c[0] === "setfacl"), "TBX-003: corriendo → se reutiliza sin run ni start (la ACL se asegura)");
  for (const running_ of [true, false]) {
    const other = ensure({ inspect: { code: 0, out: inspectOf(running_, [{ Source: R, Destination: R, RW: true }]), err: "" } });
    check(other.name === null && /otros montajes/.test(other.error) && other.started().length === 0 && !other.calls.some((c) => c[0] === "setfacl"), `TBX-003: existente (${running_ ? "corriendo" : "detenido"}) con otros montajes → rehúsa sin tocar nada`);
  }
  const inspectFails = ensure({ inspect: fail(1, "permission denied") });
  check(inspectFails.name === null && inspectFails.started().length === 0, "TBX-003: un inspect que falla por otro motivo no se toma por ausente");
  const aclFails = ensure({ acl: fail(1, "Operation not supported") });
  check(aclFails.name === null && /ACL/.test(aclFails.error) && aclFails.started().length === 0, "TBX-003: setfacl que falla → error sin docker run");
  const noSetfacl = ensure({ acl: fail(127, "ENOENT") });
  check(noSetfacl.name === null && /setfacl/.test(noSetfacl.error) && noSetfacl.started().length === 0, "TBX-003: sin setfacl → error sin docker run");
  const runFails = ensure({ start: fail(125, "conflict") });
  check(runFails.name === null && /docker run falló/.test(runFails.error), "TBX-003: docker run que falla → error");
  const badOvpn = ensure({}, { ovpn: "/no/existe.ovpn" });
  check(badOvpn.name === null && /GEKKO_OVPN/.test(badOvpn.error) && badOvpn.started().length === 0, "TBX-003: GEKKO_OVPN inexistente → error sin docker run");
  const colon = ensure({}, { root: "/r:x" });
  check(colon.name === null && /':'/.test(colon.error) && colon.calls.length === 0, "TBX-003: ruta con ':' → error antes de llamar a docker");
  const tmpOvpn = mkdtempSync(join(tmpdir(), "gkws-ovpn-"));
  try {
    mkdirSync(join(tmpOvpn, "dir"));
    writeFileSync(join(tmpOvpn, "t.ovpn"), "client\n");
    const withOvpn = ensure({}, { ovpn: join(tmpOvpn, "t.ovpn") });
    check(withOvpn.name !== null && withOvpn.started()[0].includes(`${join(tmpOvpn, "t.ovpn")}:/vpn/target.ovpn:ro`), "TBX-003: con GEKKO_OVPN válido se monta al crear");
    const dirOvpn = ensure({}, { ovpn: join(tmpOvpn, "dir") });
    check(dirOvpn.name === null && dirOvpn.started().length === 0, "TBX-003: GEKKO_OVPN que es un directorio → error");
    const reuse = ensure({ inspect: { code: 0, ...good, err: "" } }, { ovpn: "/no/existe.ovpn" });
    check(reuse.name === null && /GEKKO_OVPN/.test(reuse.error) && reuse.started().length === 0, "TBX-003: GEKKO_OVPN inválido se rechaza antes de reutilizar");
  } finally {
    rmSync(tmpOvpn, { recursive: true, force: true });
  }

  // L6: la adopción valida con `inspect --type container`, y todo lo posterior usa el ID validado, no el nombre.
  const adopted = ensure({ inspect: { code: 0, ...good, err: "" } });
  check(adopted.calls.some((c) => same(c, ["docker", "inspect", "--type", "container", "gekko-tb-acme"])), "TBX-003: la adopción inspecciona con --type container");
  check(adopted.name === CONTAINER_ID && !adopted.calls.some((c) => c[0] === "docker" && c.includes("gekko-tb-acme") && c[1] !== "inspect"), "TBX-003: tras validar no se vuelve a direccionar el contenedor por nombre");
  const imageDefaults = ensure({ image: { code: 0, out: 'sha256:test\t{"Entrypoint":["/entry.sh"],"User":"kali"}', err: "" }, inspect: { code: 0, ...good, err: "" } });
  check(imageDefaults.name === null && /otros montajes|aislamiento/.test(imageDefaults.error), "TBX-003: el entrypoint y el usuario deben ser los de la imagen (distintos → se rehúsa)");
  const sameDefaults = JSON.parse(good.out)[0];
  sameDefaults.Config = { Cmd: ["sleep", "infinity"], Entrypoint: ["/entry.sh"], User: "kali" };
  check(ensure({ image: { code: 0, out: 'sha256:test\t{"Entrypoint":["/entry.sh"],"User":"kali"}', err: "" }, inspect: { code: 0, out: JSON.stringify([sameDefaults]), err: "" } }).name === CONTAINER_ID, "TBX-003: entrypoint y usuario iguales a los de la imagen se adoptan");
  const noId = JSON.parse(good.out)[0]; delete noId.Id;
  check(ensure({ inspect: { code: 0, out: JSON.stringify([noId]), err: "" } }).name === null, "TBX-003: un inspect sin ID de contenedor no se adopta");
  check(ensure({ start: { code: 0, out: "no-es-un-id\n", err: "" } }).name === null, "TBX-003: docker run que no imprime un ID → error");
  // L5: la ACL cubre el workspace y los directorios de primer nivel del operador que ya existen.
  const withSubdirs = ensure({}, { fs: fakeFs({}, [`${WS}/loot`, `${WS}/scripts`, `${WS}/canaries`, `${WS}/extra`]) });
  const aclCalls = withSubdirs.calls.filter((c) => c[0] === "setfacl").map((c) => c[c.length - 1]);
  check(same(aclCalls, [WS, `${WS}/loot`, `${WS}/scripts`, `${WS}/canaries`, `${WS}/extra`]) && withSubdirs.calls.findIndex((c) => c[1] === "run") > withSubdirs.calls.map((c) => c[0]).lastIndexOf("setfacl"), "TBX-003: ACL en el workspace y en cada directorio de primer nivel existente, antes de crear");
  const subdirFails = fakeRun({}); const failingRun: Run = (file, args) => (file === "setfacl" && args[args.length - 1].endsWith("/loot") ? fail(1, "Operation not supported") : subdirFails.run(file, args));
  let subdirError = "";
  try { ensureToolbox({ root: R, ws: "acme", image: "gekko-toolbox:latest", uid: 1234, run: failingRun, fs: fakeFs({}, [`${WS}/loot`]) }); } catch (e) { subdirError = (e as Error).message; }
  check(/ACL/.test(subdirError) && subdirFails.started().length === 0, "TBX-003: una ACL que falla en un subdirectorio → error sin docker run");
  const relativeOvpn = ensure({}, { ovpn: "t.ovpn" });
  check(relativeOvpn.name === null && /absoluta/.test(relativeOvpn.error) && relativeOvpn.calls.length === 0, "TBX-003: GEKKO_OVPN relativo → error antes de llamar a docker");

  // ── REQ-TBX-007 ──
  req("REQ-TBX-007");
  for (const [mounts, why] of [
    [[rwWs, roTools, roFile("exec"), roFile("scope.txt")], "sin el tmpfs de .pi-sessions"],
    [[rwWs, roTools, roFile("scope.txt"), sessionsMask], "sin exec de sólo lectura"],
    [[rwWs, roTools, roFile("exec"), sessionsMask], "sin scope.txt de sólo lectura"],
    [[rwWs, roTools, { ...roFile("exec"), RW: true }, roFile("scope.txt"), sessionsMask], "exec escribible"],
    [[rwWs, roTools, roFile("exec"), { ...roFile("scope.txt"), RW: true }, sessionsMask], "scope.txt escribible"],
    [[rwWs, roTools, roFile("exec"), roFile("scope.txt"), { ...sessionsMask, RW: false }], "tmpfs de sólo lectura"],
    [[rwWs, roTools, roFile("exec"), roFile("scope.txt"), { ...sessionsMask, Destination: `${WS}/otro` }], "tmpfs en otra ruta"],
    [[rwWs, roTools, roFile("exec"), roFile("scope.txt"), { ...sessionsMask, Type: "bind", Source: "/tmp/x", Propagation: "rprivate" }], ".pi-sessions con un bind en lugar del tmpfs"],
    [[rwWs, roTools, roFile("exec"), roFile("scope.txt"), sessionsMask, roFile("AUTHORIZATION.md")], "AUTHORIZATION.md montado cuando no es un archivo regular"],
    [[rwWs, roTools, roFile("exec"), roFile("scope.txt"), sessionsMask, { ...roFile("notes.md") }], "otro archivo del workspace montado"],
  ] as const) check(!toolboxMountsOk(inspectOf(true, [...mounts]), R, WS), `TBX-007: se rehúsa ${why}`);
  check(toolboxMountsOk(inspectOf(true, fullMounts), R, WS), "TBX-007: el conjunto exacto se acepta");
  check(toolboxMountsOk(inspectOf(true, [...fullMounts, roFile("AUTHORIZATION.md")]), R, WS, undefined, true), "TBX-007: con AUTHORIZATION.md regular el conjunto exacto lo incluye");
  check(!toolboxMountsOk(inspectOf(true, fullMounts), R, WS, undefined, true), "TBX-007: AUTHORIZATION.md regular y sin montar → no se adopta");
  const unmasked = ensure({ inspect: { code: 0, out: inspectOf(true, [rwWs, roTools, roFile("exec"), roFile("scope.txt")]), err: "" } });
  check(unmasked.name === null && /otros montajes/.test(unmasked.error) && unmasked.started().length === 0 && !unmasked.calls.some((c) => c[0] === "setfacl"), "TBX-007: un contenedor sin el tmpfs de .pi-sessions se rehúsa antes de ACL y start");
  const authorized = ensure({ inspect: { code: 0, out: inspectOf(true, [...fullMounts, roFile("AUTHORIZATION.md")]), err: "" } }, { fs: fakeFs({ "AUTHORIZATION.md": "file" }) });
  check(authorized.name === CONTAINER_ID, "TBX-007: con AUTHORIZATION.md regular se adopta el contenedor que lo monta");
  check(ensure({ inspect: { code: 0, ...good, err: "" } }, { fs: fakeFs({ "AUTHORIZATION.md": "file" }) }).name === null, "TBX-007: con AUTHORIZATION.md regular se rehúsa el contenedor que no lo monta");
  const created = ensure({}, { fs: fakeFs({ "AUTHORIZATION.md": "file" }) });
  check(created.started()[0].includes(`${WS}/AUTHORIZATION.md:${WS}/AUTHORIZATION.md:ro`), "TBX-007: se crea con AUTHORIZATION.md de sólo lectura cuando es un archivo regular");
  for (const [kinds, why] of [
    [{ exec: "missing" }, "exec ausente"], [{ exec: "other" }, "exec enlace simbólico o FIFO"], [{ exec: "dir" }, "exec directorio"],
    [{ "scope.txt": "missing" }, "scope.txt ausente"], [{ "scope.txt": "other" }, "scope.txt no regular"],
    [{ ".pi-sessions": "missing" }, ".pi-sessions ausente"], [{ ".pi-sessions": "other" }, ".pi-sessions no es un directorio"], [{ ".pi-sessions": "file" }, ".pi-sessions es un archivo"],
  ] as const) {
    const refused = ensure({}, { fs: fakeFs({ ...kinds }) });
    check(refused.name === null && refused.error !== "" && refused.calls.length === 0, `TBX-007: ${why} → error antes de llamar a docker (nunca deja que docker cree el directorio)`);
  }
  check(ensure({}, { fs: fakeFs({ "AUTHORIZATION.md": "other" }) }).started()[0].every((arg) => !arg.includes("AUTHORIZATION.md")), "TBX-007: un AUTHORIZATION.md que no es regular no se monta");

  // ── REQ-TBX-008 ──
  req("REQ-TBX-008");
  const tmpDir = "/tmp";
  const ident = (p: string) => p;
  check(socketDir({ GEKKO_EXEC: "toolbox", GEKKO_WORKSPACE_DIR: WS }, tmpDir, undefined, ident) === `${WS}/.gekko-sockets`, "TBX-008: toolbox sin GEKKO_TMUX_DIR usa .gekko-sockets del workspace");
  check(socketDir({ GEKKO_EXEC: "toolbox", GEKKO_TMUX_DIR: "/run/user/1000/s", GEKKO_WORKSPACE_DIR: WS }, tmpDir, undefined, ident) === `${WS}/.gekko-sockets`, "TBX-008: en toolbox un GEKKO_TMUX_DIR heredado se ignora (el contenedor no lo monta)");
  check(socketDir({ GEKKO_EXEC: "os", GEKKO_TMUX_DIR: "/run/user/1000/s", GEKKO_WORKSPACE_DIR: WS }, tmpDir, "toolbox", ident) === `${WS}/.gekko-sockets`, "TBX-008: el lugar que elige quien llama manda sobre GEKKO_EXEC");
  check(socketDir({ GEKKO_EXEC: "toolbox", GEKKO_TMUX_DIR: `${WS}/.gekko-sockets`, GEKKO_WORKSPACE_DIR: WS }, tmpDir, "os", ident) === "/tmp/gekko-sockets", "TBX-008: lugar os con Pi lanzado en toolbox: el directorio del workspace se descarta y sale el de tmp");
  check(socketDir({ GEKKO_EXEC: "os", GEKKO_TMUX_DIR: "/run/user/1000/s", GEKKO_WORKSPACE_DIR: WS }, tmpDir, undefined, ident) === "/run/user/1000/s" && socketDir({ GEKKO_EXEC: "os", GEKKO_TMUX_DIR: "/x/engagements-old/s", GEKKO_WORKSPACE_DIR: WS }, tmpDir, undefined, ident) === "/x/engagements-old/s", "TBX-008: en os un GEKKO_TMUX_DIR fuera del workspace se respeta");
  check(socketDir({ GEKKO_EXEC: "os", GEKKO_TMUX_DIR: `${WS}/s` , GEKKO_WORKSPACE_DIR: WS }, tmpDir, undefined, ident) === "/tmp/gekko-sockets" && socketDir({ GEKKO_EXEC: "os", GEKKO_TMUX_DIR: WS, GEKKO_WORKSPACE_DIR: WS }, tmpDir, undefined, ident) === "/tmp/gekko-sockets", "TBX-008: en os un GEKKO_TMUX_DIR dentro del workspace (o él mismo) se ignora");
  check(socketDir({ GEKKO_EXEC: "os", GEKKO_TMUX_DIR: `${WS}-otro/s`, GEKKO_WORKSPACE_DIR: WS }, tmpDir, undefined, ident) === `${WS}-otro/s`, "TBX-008: un hermano con el mismo prefijo no es 'dentro'");
  check(socketDir({ GEKKO_TMUX_DIR: "/home/op/Gekko/engagements/x/s" }, tmpDir, undefined, ident) === "/home/op/Gekko/engagements/x/s", "TBX-008: sin workspace no hay 'dentro': ya no se decide por la palabra engagements");
  const insideTmp = (() => { try { socketDir({ GEKKO_EXEC: "os", GEKKO_TMUX_DIR: `${WS}/s`, GEKKO_WORKSPACE_DIR: WS }, `${WS}/t`, undefined, ident); return false; } catch { return true; } })();
  check(insideTmp, "TBX-008: en os, si el heredado y el de tmp caen dentro del workspace, lanza (la shell con socket propio se rehúsa)");
  const sdTmp = mkdtempSync(join(tmpdir(), "gkws-sd-"));
  try {
    const realWs = join(sdTmp, "ws"), outsideDir = join(sdTmp, "fuera");
    mkdirSync(realWs); mkdirSync(outsideDir);
    symlinkSync(realWs, join(sdTmp, "enlace-al-ws"));
    symlinkSync(outsideDir, join(realWs, "salida"));
    const viaLink = socketDir({ GEKKO_EXEC: "os", GEKKO_TMUX_DIR: join(sdTmp, "enlace-al-ws", "no-existe-aun"), GEKKO_WORKSPACE_DIR: realWs }, join(sdTmp, "tmp"));
    check(viaLink === join(sdTmp, "tmp", "gekko-sockets"), "TBX-008: un enlace que apunta al workspace cuenta como dentro, aunque el directorio aún no exista (rutas reales)");
    const wsViaLink = socketDir({ GEKKO_EXEC: "os", GEKKO_TMUX_DIR: join(realWs, "s"), GEKKO_WORKSPACE_DIR: join(sdTmp, "enlace-al-ws") }, join(sdTmp, "tmp"));
    check(wsViaLink === join(sdTmp, "tmp", "gekko-sockets"), "TBX-008: el workspace dado por un enlace se compara por su ruta real");
    const escapes = socketDir({ GEKKO_EXEC: "os", GEKKO_TMUX_DIR: join(realWs, "salida", "s"), GEKKO_WORKSPACE_DIR: realWs }, join(sdTmp, "tmp"));
    check(escapes === join(realWs, "salida", "s"), "TBX-008: un directorio bajo el workspace cuyo enlace sale de él queda fuera (ruta real)");
  } finally {
    rmSync(sdTmp, { recursive: true, force: true });
  }
  for (const good_ of ["listener", "a", "_x", "@y", "a-b_c@d", "x".repeat(64)]) check(SHELL_NAME_RE.test(good_), `TBX-008: nombre de sesión '${good_.slice(0, 12)}' admitido`);
  for (const bad_ of ["", "-x", "a b", "a;id", "a$(id)", "a`id`", "a\nb", "a.b", "a/b", "x".repeat(65), "'q'", "á"]) check(!SHELL_NAME_RE.test(bad_), `TBX-008: nombre de sesión ${JSON.stringify(bad_.slice(0, 12))} rechazado`);

  // ── REQ-TBX-004 ──
  req("REQ-TBX-004");
  const awkward = ["new-session", "-d", "-s", "a b", "-c", "/w s", "echo 'x'; ls", "\"q\""];
  check(same(tmuxCommand("os", undefined, awkward), { file: "tmux", args: awkward }), "TBX-004: os → tmux con los mismos argumentos");
  check(same(tmuxCommand("os", "gekko-tb-x", ["ls"]), { file: "tmux", args: ["ls"] }), "TBX-004: en os el contenedor se ignora");
  check(same(tmuxCommand("toolbox", "gekko-tb-x", awkward), { file: "docker", args: ["exec", "gekko-tb-x", "tmux", ...awkward] }), "TBX-004: toolbox → docker exec <contenedor> tmux <args>, uno por elemento y sin tocar");
  for (const container of [undefined, ""]) check((() => { try { tmuxCommand("toolbox", container, ["ls"]); return false; } catch { return true; } })(), `TBX-004: toolbox con contenedor ${JSON.stringify(container)} lanza`);

  // ── REQ-TBX-005 ──
  req("REQ-TBX-005");
  const F = ".claude/tools/findings.py";
  const accepted = [`${F} add --target 10.0.0.1`, `./${F} list`, `${R}/${F} render`, `python3 ${F} set 3 confirmed`, `python3 ${R}/${F} add --title "a, b: it's (ok)" --target 10.0.0.5`,
    `python3 ./${F} list --status confirmed`, `${F} add --note 'x y'`, `${F} list `];
  for (const c of accepted) check(ledgerCliOnly(c, R), `TBX-005: se acepta '${c}'`);
  const refused = [`${F} add x; id`, `${F} add x && id`, `${F} add x || id`, `${F} add x | tee f`, `${F} add x & id`, `${F} add $(id)`, `${F} add \`id\``, `${F} add "$HOME"`,
    `${F} list > /tmp/x`, `${F} list < /etc/passwd`, `${F} add x\nid`, `${F} add x\rid`, `${F} add x\tid`, `${F} add x\\`, `${F} add x\u0000`,
    `${F}c add`, `x${F} add`, `${F}.sh add`, `.claude/tools/findings.pyc add`, `.claude/tools/xfindings.py add`, `.claude/tools/findings.py`, `${F} `,
    `.claude/tools/other.py add`, `tools/findings.py add`, `/other/${F} add`, `${R}x/${F} add`, `../${F} add`, `/r/../${F} add`, `${R}/.claude/tools/../tools/findings.py add`,
    `${F} frobnicate`, `${F} selftest`, `${F} adds`, `${F} addx`, `${F}  add`, ` ${F} add`, `env X=1 ${F} add`, `sudo ${F} add`, `bash -c '${F} add'`, `python3 -c 'x'`, `python ${F} add`,
    `python3  ${F} add`, `python3 python3 ${F} add`, `${F} add x ; id`, `nmap 10.0.0.1`, ``, `${F} add 'x'\nnmap 10.0.0.1`];
  for (const c of refused) check(!ledgerCliOnly(c, R), `TBX-005: se rechaza ${JSON.stringify(c)}`);
  check(ledgerCliOnly("/a.b/" + F + " list", "/a.b") && !ledgerCliOnly("/aXb/" + F + " list", "/a.b"), "TBX-005: la raíz se compara literal, no como patrón");

  // ── REQ-TBX-006 ──
  req("REQ-TBX-006");
  const osBlock = workspacePromptBlock("acme", WS, "os");
  const tbBlock = workspacePromptBlock("acme", WS, "toolbox", "gekko-tb-acme");
  check(osBlock === workspacePromptBlock("acme", WS), "TBX-006: el modo por omisión es os");
  for (const [label, block] of [["os", osBlock], ["toolbox", tbBlock]] as const) {
    check(/mode `os`: `session_\*` shells are born on this host/.test(block) && /mode `toolbox`: `session_\*` shells are born INSIDE the container `gekko-tb-acme`/.test(block), `TBX-006: ${label} → describe los dos modos y nombra el contenedor`);
    check(/Kali, root, its own network/.test(block) && /`bash` tool and the read tools still run on the HOST/.test(block) && /read the repo and the KB/.test(block), `TBX-006: ${label} → en toolbox bash y las herramientas de lectura siguen en el host`);
    check(/against the target goes through a shell/.test(block) && /guard blocks a `bash` command that names an in-scope host/.test(block) && block.includes("findings.py"), `TBX-006: ${label} → lo que va contra el objetivo va por una shell; el guard bloquea salvo findings.py`);
    check(/sees only the workspace/.test(block) && /read-only there/.test(block) && /`\.pi-sessions` is empty/.test(block), `TBX-006: ${label} → el contenedor sólo ve el workspace`);
    check(block.includes("docker exec -it gekko-tb-acme tmux attach -t"), `TBX-006: ${label} → cómo adjuntarse a una shell`);
    check(/container's own address/.test(block) && /operator adds that address to `scope.txt`/.test(block), `TBX-006: ${label} → una dirección propia del contenedor es fuera de scope hasta que el operador la agregue`);
    check(/can change it while Pi is open/.test(block) && /`lugar=os` or `lugar=toolbox`/.test(block), `TBX-006: ${label} → el operador puede cambiar el modo y session_new dice dónde nació la shell`);
    check(/`levantando`, `caída`/.test(block) && /stop and tell the operator/.test(block) && /not retry elsewhere/i.test(block), `TBX-006: ${label} → ante levantando/caída se detiene y avisa, sin reintentar en otro lado`);
    check(block.includes(WS) && /already scaffolded/.test(block), `TBX-006: ${label} → conserva lo común`);
  }
  check(/in force at launch: `os`/.test(osBlock) && !/in force at launch: `toolbox`/.test(osBlock), "TBX-006: el bloque de os dice que rige os al lanzar");
  check(/in force at launch: `toolbox`/.test(tbBlock) && !/in force at launch: `os`/.test(tbBlock), "TBX-006: el bloque de toolbox dice que rige toolbox al lanzar");
  check(workspacePromptBlock("acme", WS, "os").includes("gekko-tb-acme"), "TBX-006: sin contenedor dado, el nombre sale de toolboxName");
  const noneBlock = workspacePromptBlock(null, null, "os");
  check(!/container/i.test(noneBlock) && !noneBlock.includes("gekko-tb-"), "TBX-006: none no nombra ningún contenedor");
  const root = mkdtempSync(join(tmpdir(), "gkws-tbx-prompt-"));
  try {
    cli(root, ["new", "p-tb", "--exec", "toolbox", "192.0.2.3"]);
    cli(root, ["new", "p-os", "192.0.2.4"]);
    check(cli(root, ["prompt", "p-tb", "toolbox"]).out.includes("docker exec -it gekko-tb-p-tb tmux attach") && /in force at launch: `toolbox`/.test(cli(root, ["prompt", "p-tb", "toolbox"]).out), "TBX-006: el CLI prompt con modo toolbox nombra el contenedor y el modo");
    check(/in force at launch: `os`/.test(cli(root, ["prompt", "p-os", "os"]).out) && cli(root, ["prompt", "p-os", "os"]).out.includes("gekko-tb-p-os"), "TBX-006: el CLI prompt con modo os describe también la toolbox");
    check(/in force at launch: `toolbox`/.test(cli(root, ["prompt", "p-os", "toolbox"]).out) && /in force at launch: `os`/.test(cli(root, ["prompt", "p-tb", "os"]).out), "TBX-006: el prompt sale del modo ya resuelto que se le pasa, no de una segunda lectura del archivo");
    for (const badMode of [[], ["Toolbox"], ["docker"], [""]]) check(cli(root, ["prompt", "p-tb", ...badMode]).code === 1, `TBX-006: prompt sin modo válido (${JSON.stringify(badMode)}) falla`);
    check(!cli(root, ["prompt", "none"]).out.includes("gekko-tb-"), "TBX-006: el CLI prompt none no nombra contenedor");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// REQ-WS-012: el aviso de salida del contenedor. Cláusulas que NO cumple el texto del lanzador (vacío = lo cumple).
function exitNoticeViolations(src: string): string[] {
  const code = src.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
  const notify = code.match(/notify_running_toolbox\(\) \{([\s\S]*?)\n\}/)?.[1] ?? "";
  const cleanup = code.match(/cleanup_after_pi\(\) \{([\s\S]*?)\n  \}/)?.[1] ?? "";
  const violations: string[] = [];
  if (!/timeout \d+ docker inspect --type container --format '\{\{\.State\.Running\}\}' "\$toolbox_name"/.test(notify)) violations.push("decide-por-docker-inspect-con-plazo");
  if (!/command -v docker/.test(notify) || !/"\$ws" != "none"/.test(notify)) violations.push("sin-docker-ni-workspace-no-imprime");
  if (!/contenedor activo: \$toolbox_name; apagar: docker rm -f \$toolbox_name/.test(notify)) violations.push("dice-cómo-apagarlo");
  const noticeAt = cleanup.indexOf("notify_running_toolbox"), silenceAt = cleanup.indexOf("exec >/dev/null 2>&1");
  if (noticeAt < 0 || silenceAt < 0 || noticeAt > silenceAt) violations.push("avisa-antes-de-silenciar");
  if (!/^trap notify_running_toolbox EXIT$/m.test(code)) violations.push("avisa-también-fuera-de-tmux");
  if (/^\s*trap '.*' EXIT$/m.test(code) || (code.match(/^\s*trap \S+ EXIT$/gm) ?? []).length !== 2) violations.push("una-sola-salida-por-camino");
  if (/^exec "\$\{pi_cmd\[@\]\}"/m.test(code)) violations.push("pi-sin-exec");
  if (!/set \+e; "\$\{pi_cmd\[@\]\}"; rc=\$\?; set -e\nexit "\$rc"\s*$/.test(code)) violations.push("conserva-el-código-de-pi");
  if (!/"shells    \$\{GEKKO_EXEC\} \(al lanzar\)/.test(code)) violations.push("banner-al-lanzar");
  return violations;
}

// REQ-WS-009: el estado del panel es de UN lanzamiento. Dos Pi vivos sobre el mismo workspace publicaban
// cada 2 s en el mismo archivo y el rail de uno mostraba el modo y las shells del otro (visto el 2026-11-15).
function panelStateViolations(hitl: string, sidebar: string): string[] {
  const code = (s: string) => s.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
  const h = code(hitl), sb = code(sidebar), v: string[] = [];
  if (!/panel_default="\$state_dir\/panel\.\$\$\.json"/.test(h) || !/panel_default="\$state_dir\/panel\.\$ws\.\$\$\.json"/.test(h)) v.push("archivo-por-lanzamiento");
  if (!/kill -0 "\$pid"[^\n]*\|\| rm -f/.test(h)) v.push("limpia-lanzamientos-muertos");
  // el hook corre desde el servidor tmux, que no hereda el entorno de Pi: la ruta viaja en el comando
  if (!/set-hook[^\n]*window-resized[^\n]*GEKKO_PANEL_STATE='\$GEKKO_PANEL_STATE'/.test(sb)) v.push("hook-con-el-archivo");
  return v;
}

const codeOf = (src: string) => src.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");

// REQ-TUI-026: el hook window-resized corre sin cliente: `--fit` saca la sesión del id de la ventana (un `display-message`
// sin contexto devuelve la de más actividad y el rail existente no se ve: un rail más por redimensionado) y serializa
// buscar-y-abrir por ventana. Sólo regex sobre el código sin comentarios; el efecto real lo prueba tools/tui-test.sh.
function fitViolations(sidebar: string): string[] {
  const sb = codeOf(sidebar), v: string[] = [];
  if (!/sess="\$\(tmux display-message -p -t "\$win" '#\{session_name\}'\)"/.test(sb)) v.push("sesion-de-la-ventana");
  if (!/tmux wait-for -L "gekko-fit-\$win"/.test(sb) || !/trap 'tmux wait-for -U "gekko-fit-\$win"' EXIT/.test(sb)) v.push("bloqueo-por-ventana");
  return v;
}

// REQ-TUI-025: el lanzador marca su sesión, instala los atajos antes de Pi y, después de Pi, barre, desmarca y devuelve
// los atajos desde una trampa de salida (también ante HUP/TERM/INT) y sale con el código de Pi; el script del rail saca el argv de `navBindings`. Sólo regex sobre el
// código sin comentarios; el efecto real lo prueba tools/ws-test.sh.
function keysViolations(hitl: string, sidebar: string): string[] {
  const h = codeOf(hitl), sb = codeOf(sidebar), v: string[] = [];
  const piAt = h.indexOf('"${pi_cmd[@]}"; rc=$?'), keysAt = h.indexOf("--keys ||"), restoreAt = h.indexOf("--keys-restore");
  if (!/tmux set-option -t "\$sess" @gekko_pi "\$\$"/.test(h)) v.push("marca-la-sesion");
  if (keysAt < 0 || piAt < 0 || keysAt > piAt) v.push("instala-atajos-antes-de-pi");
  const unsetAt = h.search(/tmux set-option -u -t "\$sess" @gekko_pi/);
  if (unsetAt < 0 || restoreAt < unsetAt || !/exit "\$rc"/.test(h.slice(piAt))) v.push("desmarca-y-devuelve-tras-pi");
  const trapAt = h.search(/trap cleanup_after_pi EXIT/), fnAt = h.search(/cleanup_after_pi\(\) \{/);
  const signalTraps = /trap 'exit 129' HUP/.test(h) && /trap 'exit 143' TERM/.test(h) && /trap 'exit 130' INT/.test(h);
  if (fnAt < 0 || trapAt < fnAt || trapAt > keysAt || !(unsetAt > fnAt && restoreAt > fnAt) || !signalTraps) v.push("limpia-en-trampa-de-salida");
  if (!/install_bindings navBindings "\$\{NAV_KEYS\[@\]\}"/.test(sb) || !/\[process\.env\.GEKKO_BINDINGS_FN\]\(prev\)/.test(sb)) v.push("argv-de-navBindings");
  const clearAt = (at: number) => sb.lastIndexOf("clear_dead_pi_marks ||", at) > sb.indexOf('"$mode" = "--restore"');
  if (!/staleMirrors\(sessions, alive\)/.test(sb) || !clearAt(sb.indexOf("grep -q .")) || !clearAt(sb.indexOf("install_bindings navBindings"))) v.push("limpia-marcas-muertas");
  return v;
}

// REQ-TMUX-014: tras Pi el lanzador barre las ventanas espejo de su sesión; el rail decide con `staleMirrors`.
function sweepViolations(hitl: string, sidebar: string): string[] {
  const h = codeOf(hitl), sb = codeOf(sidebar), v: string[] = [];
  const piAt = h.indexOf('"${pi_cmd[@]}"; rc=$?'), sweepAt = h.indexOf('--sweep-mirrors "$sess"'), unsetAt = h.search(/set-option -u -t "\$sess" @gekko_pi/);
  const trapAt = h.search(/trap cleanup_after_pi EXIT/);
  if (sweepAt < 0 || piAt < 0 || trapAt < 0 || trapAt > piAt || sweepAt > trapAt || (unsetAt >= 0 && sweepAt > unsetAt)) v.push("barre-tras-pi");
  if (!/const \{ staleMirrors \} = await import/.test(sb) || !/staleMirrors\(windows, alive\)/.test(sb)) v.push("decide-staleMirrors");
  if (!/process\.kill\(pid, 0\)[^\n]*EPERM/.test(sb)) v.push("vivo-por-kill-0");
  return v;
}

// REQ-TMUX-015: el prompt del modelo avisa que lo que aparece en una shell puede haberlo tecleado el operador.
function promptNoticeViolations(source: string): string[] {
  const prompt = source.replace(/\s+/g, " "), v: string[] = [];
  if (!/operator can watch and type into/i.test(prompt)) v.push("operador-mira-y-teclea");
  if (!/may have been typed by the operator/i.test(prompt)) v.push("puede-ser-del-operador");
  if (!/not target output/i.test(prompt) || !/not a target instruction/i.test(prompt)) v.push("no-es-del-objetivo");
  if (!/attached or scrolling[^.\n]*normal/i.test(prompt)) v.push("operador-adjunto-es-normal");
  return v;
}

export async function runWorkspaceSelftest(counts: Map<string, number> = new Map(), deps?: WorkspaceSelftestDeps): Promise<number> {
  let bad = 0;
  let cur = "";
  const req = (id: string) => { cur = id; counts.set(id, counts.get(id) ?? 0); };
  const ok = (c: boolean, m: string) => {
    counts.set(cur, (counts.get(cur) ?? 0) + 1);
    if (!c) { console.error("FAIL [workspace]:", m); bad++; }
  };
  const scopeAccepts = deps?.scopeAccepts ?? FALLBACK_SCOPE_RULE;

  // ── REQ-WS-001: nombre válido y confinado ──
  req("REQ-WS-001");
  for (const name of ["a", "A1", "x".repeat(31), "acme-2.test_1"]) ok(validWorkspaceName(name), `WS-001: '${name}' debe ser válido`);
  const invalid: [string, string][] = [["a/b", "barra"], ["a..b", "dos puntos"], ["..", "solo dos puntos"], ["a b", "espacio"],
    [".a", "punto inicial"], ["-a", "guion inicial"], ["x".repeat(32), "32 caracteres"], ["", "vacío"], ["none", "none"]];
  for (const [name, why] of invalid) ok(!validWorkspaceName(name), `WS-001: ${why} debe rechazarse`);
  const doubleRealpath = (p: string) => p === "/r/engagements" ? "/r/engagements" : p.endsWith("/inside") ? "/r/engagements/inside" : "/etc/outside";
  ok(confined("/r", "inside", doubleRealpath), "WS-001: ruta real dentro de engagements/ → confinada");
  ok(!confined("/r", "escape", doubleRealpath), "WS-001: enlace simbólico que sale → no confinada");
  ok(!confined("/r", "sib", (p) => p === "/r/engagements" ? "/r/engagements" : "/r/engagements-evil/sib"), "WS-001: directorio hermano con el mismo prefijo → no confinada");
  ok(!confined("/r", "gone", () => { throw new Error("ENOENT"); }), "WS-001: ruta irresoluble → no confinada");

  // ── REQ-WS-002: objetivos que el broker cuenta ──
  req("REQ-WS-002");
  const spaced = parseTargets("10.0.0.1 10.0.0.0/24");
  ok(same(spaced.targets, [{ ip: "10.0.0.1" }, { ip: "10.0.0.0/24" }]) && spaced.rejected.length === 0, "WS-002: IP y CIDR separados por espacio");
  ok(same(parseTargets("10.0.0.1,10.0.0.2, 10.0.0.3").targets.map((t) => t.ip), ["10.0.0.1", "10.0.0.2", "10.0.0.3"]), "WS-002: separados por coma");
  ok(same(parseTargets("10.0.0.1 web").targets, [{ ip: "10.0.0.1", label: "web" }]), "WS-002: 'IP etiqueta' conserva la etiqueta");
  const lone = parseTargets("db.example");
  ok(same(lone.names, ["db.example"]) && lone.targets.length === 0, "WS-002: nombre suelto → names");
  const afterComma = parseTargets("10.0.0.1, web");
  ok(same(afterComma.targets, [{ ip: "10.0.0.1" }]) && same(afterComma.names, ["web"]), "WS-002: no-IP tras coma es nombre, no etiqueta");
  const afterLabel = parseTargets("10.0.0.1 web other");
  ok(same(afterLabel.names, ["other"]) && afterLabel.targets[0].label === "web", "WS-002: segundo no-IP tras la etiqueta es nombre");
  for (const bad_ of ["10.0.0.1:80", "fe80::1", "300.1.1.1", "010.0.0.1", "10.0.0.0/33", "bad!token"]) {
    const r = parseTargets(bad_);
    ok(r.targets.length === 0 && r.rejected.length > 0 && r.names.length === 0, `WS-002: '${bad_}' debe rechazarse`);
  }
  ok(parseTargets("0.0.0.0 255.255.255.255/32").rejected.length === 0, "WS-002: octetos 0 y 255 válidos");
  // Entradas raras: lo que el lanzador acepte tiene que aceptarlo el broker, y lo numérico mal escrito nunca es etiqueta ni nombre.
  for (const odd of ["10.0.0.0/032", "10.0.0.0/8", "10.0.0.0/0", "1.2.3", "1.2.3.4.5", "10.0.0.1/", "0010.0.0.1", "1.2.3.4/24/1", "999.999.999.999"]) {
    const r = parseTargets(odd);
    ok(r.targets.every((t) => scopeAccepts(t.ip)) && r.names.length === 0 && (r.targets.length === 1) !== (r.rejected.length === 1), `WS-002: '${odd}' o lo acepta también el broker o se rechaza`);
  }
  const typo = parseTargets("10.0.0.1 10.0.5");
  ok(typo.targets.length === 1 && typo.targets[0].label === undefined && typo.rejected.length === 1, "WS-002: una IP mal escrita tras otra no se convierte en su etiqueta");
  const all: Target[] = [{ ip: "10.0.0.1", label: "web" }, { ip: "10.0.0.0/24" }];
  const written = [...scopeEntries(scopeFileText("acme", all)), ...scopeEntries(replaceScopeText("# c\n10.1.1.1\n", all, "2026-11-14"))];
  ok(written.length === 4 && written.every((l) => scopeAccepts(l)), "WS-002: toda entrada escrita la acepta el broker");
  ok(!scopeAccepts("web"), "WS-002: la regla del broker rechaza un nombre (el caso puede fallar)");
  ok(scopeLine({ ip: "10.0.0.1", label: "web" }) === "10.0.0.1  # web" && scopeLine({ ip: "10.0.0.1" }) === "10.0.0.1", "WS-002: formato de scopeLine");
  ok(scopeEntries(scopeFileText("acme", [])).length === 0, "WS-002: sin objetivos sólo hay encabezado");

  // ── REQ-WS-003: el andamiaje nunca sobrescribe ──
  req("REQ-WS-003");
  const plan = scaffoldPlan("acme", all);
  const planPaths = plan.map((p) => p.path).sort();
  ok(same(planPaths, ["AUTHORIZATION.md", "canaries", "loot/creds.md", "notes.md", "scope.txt", "scripts"]), "WS-003: el plan lista las seis rutas");
  ok(scopeEntries(plan.find((p) => p.path === "scope.txt")!.content!).length === 2, "WS-003: scope.txt del plan lleva los dos objetivos");
  const tmp = mkdtempSync(join(tmpdir(), "gkws-"));
  try {
    const dir = join(tmp, "ws");
    applyScaffold(dir, [{ path: "notes.md", content: "mío\n" }, { path: "scope.txt", content: "1.1.1.1\n" }]);
    const created = applyScaffold(dir, plan);
    ok(readFileSync(join(dir, "notes.md"), "utf-8") === "mío\n", "WS-003: notes.md previo intacto byte a byte");
    ok(readFileSync(join(dir, "scope.txt"), "utf-8") === "1.1.1.1\n", "WS-003: scope.txt previo intacto byte a byte");
    ok(!created.includes("notes.md") && !created.includes("scope.txt"), "WS-003: lo existente no figura como creado");
    ok(existsSync(join(dir, "AUTHORIZATION.md")) && existsSync(join(dir, "loot", "creds.md")), "WS-003: faltantes creados");
    ok(statSync(join(dir, "scripts")).isDirectory() && statSync(join(dir, "canaries")).isDirectory(), "WS-003: scripts/ y canaries/ creados");
    const again = applyScaffold(dir, plan);
    ok(again.length === 0, "WS-003: una segunda pasada no crea ni cambia nada");
    writeFileSync(join(dir, "AUTHORIZATION.md"), "editado\n");
    applyScaffold(dir, plan);
    ok(readFileSync(join(dir, "AUTHORIZATION.md"), "utf-8") === "editado\n", "WS-003: AUTHORIZATION.md editado sobrevive");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }

  // ── REQ-WS-004: reemplazar el scope conserva lo anterior como comentario fechado ──
  req("REQ-WS-004");
  const replaced = replaceScopeText("# keep\n10.0.0.1\n10.0.0.2  # b\n", [{ ip: "10.0.0.9" }], "2026-11-14");
  ok(same(scopeEntries(replaced), ["10.0.0.9"]), "WS-004: sólo queda la entrada nueva");
  ok(replaced.includes("# keep\n"), "WS-004: el comentario original se conserva");
  ok(replaced.includes("# (reemplazado 2026-11-14) 10.0.0.1\n"), "WS-004: primera entrada vieja comentada con fecha");
  ok(replaced.includes("# (reemplazado 2026-11-14) 10.0.0.2  # b\n"), "WS-004: segunda entrada vieja comentada con su texto original");

  // ── REQ-WS-005: menú ──
  req("REQ-WS-005");
  {
    const t = fakeIo({ last: "b", answers: ["", ""] });
    ok(await pickFlow(t.io) === "b", "WS-005(a): línea vacía elige el último usado");
    ok(t.rec.prompts[0] === "Elige [b]: " && t.rec.written.includes("(último usado)"), "WS-005(a): el menú marca y ofrece el último usado");
  }
  {
    const t = fakeIo({ last: "gone", answers: ["", "1", ""] });
    const picked = await pickFlow(t.io);
    ok(picked === "a" && t.rec.prompts.filter((p) => p.startsWith("Elige")).length === 2, "WS-005(b): último ausente → no se elige por defecto y se vuelve a preguntar");
    ok(!t.rec.written.includes("último usado") && !t.rec.prompts[0].includes("gone"), "WS-005(b): no se ofrece el último ausente");
  }
  {
    const t = fakeIo({ answers: ["n", "bad name", "a", "ok1", "10.0.0.5:80", "10.0.0.5 web", "", ""] });
    const picked = await pickFlow(t.io);
    ok(picked === "ok1" && t.rec.creates.length === 1, "WS-005(c): un solo create con el nombre válido");
    ok(same(t.rec.creates[0].targets, [{ ip: "10.0.0.5", label: "web" }]), "WS-005(c): create recibe los objetivos válidos");
    ok(t.rec.written.includes("nombre inválido") && t.rec.written.includes("ya existe") && t.rec.written.includes("rechazado '10.0.0.5:80'"), "WS-005(c): explica nombre inválido, repetido y objetivo rechazado");
    ok(t.rec.replaces.length === 0, "WS-005(c): crear no reemplaza scope");
  }
  {
    const t = fakeIo({ answers: ["n", "h1", "evil.example", "n", ""], resolves: { "evil.example": "203.0.113.7" } });
    await pickFlow(t.io);
    ok(same(t.rec.creates[0].targets, []) && t.rec.prompts.some((p) => p === "evil.example → 203.0.113.7 ¿añadir? [s/N]: "), "WS-005(d): sin confirmar, create no recibe la IP resuelta");
    const enter = fakeIo({ answers: ["n", "h1", "evil.example", "", ""], resolves: { "evil.example": "203.0.113.7" } });
    await pickFlow(enter.io);
    ok(same(enter.rec.creates[0].targets, []), "WS-005(d): Enter equivale a no");
    const yes = fakeIo({ answers: ["n", "h1", "evil.example", "s", ""], resolves: { "evil.example": "203.0.113.7" } });
    await pickFlow(yes.io);
    ok(same(yes.rec.creates[0].targets, [{ ip: "203.0.113.7", label: "evil.example" }]), "WS-005(d): con 's' create recibe la IP con su nombre");
    const unresolved = fakeIo({ answers: ["n", "h1", "nada.example", "", ""] });
    await pickFlow(unresolved.io);
    ok(same(unresolved.rec.creates[0].targets, []) && unresolved.rec.written.includes("no resolvió"), "WS-005(d): nombre que no resuelve → avisa y vuelve a pedir objetivos");
  }
  {
    const empty = fakeIo({ answers: [] });
    ok(await pickFlow(empty.io) === null && empty.rec.creates.length === 0 && empty.rec.replaces.length === 0, "WS-005(e): fin de entrada en el menú → null sin crear");
    const atName = fakeIo({ answers: ["n"] });
    ok(await pickFlow(atName.io) === null && atName.rec.creates.length === 0, "WS-005(e): fin de entrada al pedir el nombre → null sin crear");
    const atTargets = fakeIo({ answers: ["n", "h1"] });
    ok(await pickFlow(atTargets.io) === null && atTargets.rec.creates.length === 0, "WS-005(e): fin de entrada al pedir objetivos → null sin crear");
    const atConfirm = fakeIo({ answers: ["n", "h1", "evil.example"], resolves: { "evil.example": "203.0.113.7" } });
    ok(await pickFlow(atConfirm.io) === null && atConfirm.rec.creates.length === 0, "WS-005(e): fin de entrada en la confirmación → null sin crear");
    const atKeep = fakeIo({ answers: ["a"] });
    ok(await pickFlow(atKeep.io) === null && atKeep.rec.replaces.length === 0, "WS-005(e): fin de entrada ante mantener/reemplazar → null");
  }
  {
    const t = fakeIo({ answers: ["1", "r", "10.9.9.9"] });
    ok(await pickFlow(t.io) === "a" && t.rec.replaces.length === 1 && t.rec.creates.length === 0, "WS-005(f): reemplazar llama a replaceScope una vez");
    ok(t.rec.replaces[0].name === "a" && same(t.rec.replaces[0].targets, [{ ip: "10.9.9.9" }]), "WS-005(f): replaceScope recibe el workspace y los objetivos");
    ok(t.rec.written.includes("10.0.0.1"), "WS-005(f): se muestran las entradas actuales");
    const keep = fakeIo({ answers: ["b", ""], scope: "# solo comentario\n" });
    ok(await pickFlow(keep.io) === "b" && keep.rec.replaces.length === 0 && keep.rec.written.includes("(vacío)"), "WS-005(f): mantener no reemplaza; scope sin entradas dice (vacío)");
  }
  {
    const t = fakeIo({ answers: [""], last: "a", live: null });
    await pickFlow(t.io);
    ok(!t.rec.written.includes("shells vivas") && t.rec.written.includes("1) a"), "WS-005(g): liveShells null → menú sin conteo");
    ok(same(t.rec.liveAsked, ["a", "b"]), "WS-005(g): el conteo se pide por NOMBRE de workspace, uno por fila");
    const live = fakeIo({ answers: [""], last: "a", live: 2 });
    await pickFlow(live.io);
    ok(live.rec.written.includes("2 shells vivas"), "WS-005(g): con conteo, el menú lo muestra");
    const zero = fakeIo({ answers: [""], last: "a", live: 0 });
    await pickFlow(zero.io);
    ok(!zero.rec.written.includes("shells vivas"), "WS-005(g): conteo 0 no se muestra");
  }

  // ── REQ-WS-006: la shell nace en el workspace o no nace ──
  req("REQ-WS-006");
  ok(same(newSessionArgs("x", undefined), ["new-session", "-d", "-s", "x", "-x", "220", "-y", "50", "-e", "IGNOREEOF=10"]), "WS-006: sin workspace, la base (con IGNOREEOF=10, REQ-WS-010) y sin -c");
  ok(same(newSessionArgs("x", "/ws"), ["new-session", "-d", "-s", "x", "-x", "220", "-y", "50", "-e", "IGNOREEOF=10", "-c", "/ws"]), "WS-006: con workspace añade -c <dir> al final");
  ok(cwdVerdict("/ws", "/ws").ok, "WS-006: ruta igual → ok");
  const wrong = cwdVerdict("/ws", "/home/op");
  ok(!wrong.ok && wrong.note.includes("/home/op") && wrong.note.includes("/ws"), "WS-006: ruta distinta ($HOME) → no ok y la nota dice dónde arrancó");
  ok(cwdVerdict(undefined, "/home/op").ok, "WS-006: sin workspace → ok");

  // ── REQ-WS-010: la shell nace con IGNOREEOF=10 ──
  req("REQ-WS-010");
  for (const wsDir of [undefined, "/ws"]) {
    const args = newSessionArgs("x", wsDir), at = args.indexOf("-e");
    ok(at > 0 && args[at + 1] === "IGNOREEOF=10" && args.indexOf("-e", at + 1) === -1, `WS-010: ${wsDir === undefined ? "sin" : "con"} workspace lleva un único -e IGNOREEOF=10`);
    ok(args[args.indexOf("-s") + 1] === "x" && args.includes("-d"), `WS-010: ${wsDir === undefined ? "sin" : "con"} workspace conserva -d y -s <nombre>`);
  }

  // ── REQ-WS-011: un workspace cuyo directorio es un enlace simbólico se rehúsa ──
  req("REQ-WS-011");
  const linkRoot = mkdtempSync(join(tmpdir(), "gkws-link-"));
  try {
    const engagements = join(linkRoot, "engagements");
    cli(linkRoot, ["new", "beta", "192.0.2.50"]);
    symlinkSync(join(engagements, "beta"), join(engagements, "alfa"));
    ok(cli(linkRoot, ["check", "beta"]).code === 0, "WS-011: precondición, el workspace real pasa");
    const betaScope = readFileSync(join(engagements, "beta", "scope.txt"), "utf-8");
    for (const args of [["check", "alfa"], ["mode", "alfa"], ["scope", "alfa"], ["prompt", "alfa", "os"], ["toolbox", "alfa"], ["touch", "alfa"], ["new", "alfa"], ["new", "alfa", "--exec", "toolbox", "192.0.2.51"]]) {
      const r = cli(linkRoot, args);
      ok(r.code === 1 && r.out === "" && /enlace simbólico/.test(r.err) && /directorio real/.test(r.err), `WS-011: '${args.join(" ")}' rehúsa un workspace que es enlace, con el motivo`);
    }
    ok(readFileSync(join(engagements, "beta", "scope.txt"), "utf-8") === betaScope && !existsSync(join(engagements, "beta", "exec")), "WS-011: rehusar `new` sobre el enlace no toca el workspace al que apunta");
    symlinkSync(join(linkRoot, "no-existe"), join(engagements, "colgante"));
    const dangling = cli(linkRoot, ["new", "colgante", "192.0.2.52"]);
    ok(dangling.code === 1 && /enlace simbólico/.test(dangling.err) && !existsSync(join(linkRoot, "no-existe")), "WS-011: `new` sobre un enlace colgante se rehúsa sin crear su destino");
    const lstatLinks = lstatSync(join(engagements, "alfa")).isSymbolicLink() && lstatSync(join(engagements, "colgante")).isSymbolicLink();
    ok(lstatLinks, "WS-011: los enlaces rehusados siguen como estaban (no se reemplazan ni se borran)");
    const realRoot = mkdtempSync(join(tmpdir(), "gkws-linkparent-"));
    try {
      cli(realRoot, ["new", "gamma", "192.0.2.53"]);
      const viaParent = mkdtempSync(join(tmpdir(), "gkws-linkroot-"));
      symlinkSync(join(realRoot, "engagements"), join(viaParent, "engagements"));
      ok(cli(viaParent, ["check", "gamma"]).code === 0 && cli(viaParent, ["mode", "gamma"]).out === "os", "WS-011: un enlace en engagements/ (no en el workspace) sigue aceptado");
      rmSync(viaParent, { recursive: true, force: true });
    } finally {
      rmSync(realRoot, { recursive: true, force: true });
    }
  } finally {
    rmSync(linkRoot, { recursive: true, force: true });
  }

  // ── REQ-WS-008: bloque del prompt ──
  req("REQ-WS-008");
  const block = workspacePromptBlock("acme", "/r/engagements/acme");
  ok(block.includes("/r/engagements/acme"), "WS-008: contiene la ruta absoluta");
  ok(block.includes("GEKKO_WORKSPACE_DIR"), "WS-008: nombra la variable GEKKO_WORKSPACE_DIR");
  ok(block.includes("session_") && block.includes("bash") && /repository root/i.test(block), "WS-008: shells session_* y bash en la raíz del repo");
  ok(/subagent/i.test(block) && /task prompt/i.test(block), "WS-008: ordena pasar la ruta al delegar en un subagente");
  ok(/already scaffolded/i.test(block) && /Do NOT create another/i.test(block), "WS-008: ya está montado y no hay que crear otro árbol");
  const none = workspacePromptBlock(null, null);
  ok(!none.includes("engagements/"), "WS-008: sin workspace no nombra ninguna ruta");
  ok(/no workspace/i.test(none) && /ask the operator/i.test(none), "WS-008: sin workspace dice que no hay y pide al operador");

  // ── REQ-WS-007: contrato del lanzador ──
  req("REQ-WS-007");
  let hitl = "";
  try { hitl = readFileSync(new URL("../tools/pi-hitl.sh", import.meta.url), "utf-8"); } catch { /* ausente: los casos de abajo fallan */ }
  ok(hitl !== "", "WS-007: tools/pi-hitl.sh presente");
  ok(launcherViolations(hitl).length === 0, `WS-007: el lanzador cumple el contrato (incumple: ${launcherViolations(hitl).join(", ") || "nada"})`);
  // Cada cláusula puede fallar: se muta el texto y la violación tiene que aparecer.
  const mutated = (from: string | RegExp, to: string) => launcherViolations(hitl.replace(from, () => to));
  ok(mutated(/gekko-workspace\.ts/g, "otra-cosa.ts").includes("workspace-antes-de-pi"), "WS-007: sin la invocación del CLI de workspace el contrato falla");
  ok(mutated("falta GEKKO_WORKSPACE", "falta algo").includes("error-sin-terminal"), "WS-007: sin el error que nombra GEKKO_WORKSPACE el contrato falla");
  ok(mutated('ws_cli check "$ws")" || {', 'ws_cli check "$ws")" || true; {').includes("check-corta-el-arranque"), "WS-007: un `check` que no corta el arranque hace fallar el contrato");
  ok(mutated('export GEKKO_SCOPE="$ws_dir/scope.txt"', ":").includes("export-GEKKO_SCOPE"), "WS-007: sin derivar GEKKO_SCOPE del workspace el contrato falla");
  ok(mutated('export GEKKO_FINDINGS="$ws_dir/findings.jsonl"', ":").includes("export-GEKKO_FINDINGS"), "WS-007: sin derivar GEKKO_FINDINGS el contrato falla");
  ok(mutated('export GEKKO_WORKSPACE_DIR="$ws_dir"', ":").includes("export-GEKKO_WORKSPACE_DIR"), "WS-007: sin exportar GEKKO_WORKSPACE_DIR el contrato falla");
  ok(mutated('session_dir="$ws_dir/.pi-sessions"', ":").includes("export-PI_CODING_AGENT_SESSION_DIR"), "WS-007: sin llevar las sesiones de Pi al workspace el contrato falla");
  ok(mutated("exec env -u GEKKO_WORKSPACE -u GEKKO_WORKSPACE_DIR tmux", "exec tmux").includes("relanzamiento-limpio"), "WS-007: un relanzamiento que deja el workspace en el entorno del servidor tmux hace fallar el contrato");
  ok(mutated('--append-system-prompt "$generated_prompt"', '--append-system-prompt "$prompt_file"').includes("prompt-generado"), "WS-007: pasarle a Pi el prompt base sin el bloque de workspace hace fallar el contrato");

  // ── REQ-WS-012: aviso de salida del contenedor ──
  req("REQ-WS-012");
  ok(exitNoticeViolations(hitl).length === 0, `WS-012: el lanzador cumple el contrato del aviso (incumple: ${exitNoticeViolations(hitl).join(", ") || "nada"})`);
  const noticeMutated = (from: string | RegExp, to: string) => exitNoticeViolations(hitl.replace(from, () => to));
  ok(noticeMutated("timeout 5 docker inspect", "docker inspect").includes("decide-por-docker-inspect-con-plazo"), "WS-012: sin plazo en docker inspect el contrato falla");
  ok(noticeMutated("command -v docker", "true").includes("sin-docker-ni-workspace-no-imprime"), "WS-012: sin la guarda de docker el contrato falla");
  ok(noticeMutated("    notify_running_toolbox\n    exec >/dev/null 2>&1", "    exec >/dev/null 2>&1").includes("avisa-antes-de-silenciar"), "WS-012: un aviso que no corre antes de silenciar la salida hace fallar el contrato");
  ok(noticeMutated("trap notify_running_toolbox EXIT", "true").includes("avisa-también-fuera-de-tmux"), "WS-012: sin el aviso fuera de tmux el contrato falla");
  ok(noticeMutated("trap notify_running_toolbox EXIT", "trap 'echo x' EXIT\ntrap notify_running_toolbox EXIT").includes("una-sola-salida-por-camino"), "WS-012: una segunda trampa de salida que pisa a la primera hace fallar el contrato");
  ok(noticeMutated('set +e; "${pi_cmd[@]}"; rc=$?; set -e\nexit "$rc"\n', 'exec "${pi_cmd[@]}"\n').includes("pi-sin-exec"), "WS-012: volver a `exec` de Pi hace fallar el contrato");
  ok(noticeMutated("(al lanzar) ", "").includes("banner-al-lanzar"), "WS-012: un banner que no dice 'al lanzar' hace fallar el contrato");

  // ── REQ-WS-009: archivo de estado del panel por lanzamiento ──
  req("REQ-WS-009");
  let sidebarSh = "";
  try { sidebarSh = readFileSync(new URL("../tools/gekko-sidebar.sh", import.meta.url), "utf-8"); } catch { /* ausente: los casos de abajo fallan */ }
  ok(panelStateViolations(hitl, sidebarSh).length === 0, `WS-009: lanzador y rail usan un archivo de panel por lanzamiento (incumple: ${panelStateViolations(hitl, sidebarSh).join(", ") || "nada"})`);
  ok(panelStateViolations(hitl.replaceAll(".$$.json", ".json"), sidebarSh).includes("archivo-por-lanzamiento"), "WS-009: un archivo de panel compartido por workspace hace fallar el contrato");
  ok(panelStateViolations(hitl.replace('kill -0 "$pid"', "true"), sidebarSh).includes("limpia-lanzamientos-muertos"), "WS-009: sin la limpieza de lanzamientos muertos el contrato falla");
  // sólo la del hook: el rail abierto a mano también lleva la variable, en otra línea
  ok(panelStateViolations(hitl, sidebarSh.replace(/(window-resized[^\n]*?)GEKKO_PANEL_STATE='\$GEKKO_PANEL_STATE' /, (_m, pre: string) => pre)).includes("hook-con-el-archivo"), "WS-009: un hook de redimensionado que no lleva la ruta del archivo hace fallar el contrato");

  // ── REQ-TUI-025: atajos de ventana, contrato del lanzador y del rail ──
  req("REQ-TUI-025");
  ok(keysViolations(hitl, sidebarSh).length === 0, `TUI-025: lanzador y rail cumplen el contrato de atajos (incumple: ${keysViolations(hitl, sidebarSh).join(", ") || "nada"})`);
  ok(keysViolations(hitl.replace('tmux set-option -t "$sess" @gekko_pi "$$"', "true"), sidebarSh).includes("marca-la-sesion"), "TUI-025: sin marcar la sesión con @gekko_pi el contrato falla");
  ok(keysViolations(hitl, sidebarSh.replace("staleMirrors(sessions, alive)", "[]")).includes("limpia-marcas-muertas"), "TUI-025: sin decidir con staleMirrors el contrato falla");
  ok(keysViolations(hitl, sidebarSh.replace("clear_dead_pi_marks ||", "true ||")).includes("limpia-marcas-muertas"), "TUI-025: sin limpiar marcas muertas antes de decidir el contrato falla");
  ok(keysViolations(hitl.replace('--keys ||', "--nada ||"), sidebarSh).includes("instala-atajos-antes-de-pi"), "TUI-025: sin llamar a --keys antes de Pi el contrato falla");
  ok(keysViolations(hitl.replace("--keys-restore", "--nada"), sidebarSh).includes("desmarca-y-devuelve-tras-pi"), "TUI-025: sin --keys-restore tras Pi el contrato falla");
  ok(keysViolations(hitl.replace('tmux set-option -u -t "$sess" @gekko_pi', "true"), sidebarSh).includes("desmarca-y-devuelve-tras-pi"), "TUI-025: sin quitar la marca tras Pi el contrato falla");
  ok(keysViolations(hitl.replace("trap cleanup_after_pi EXIT", "true"), sidebarSh).includes("limpia-en-trampa-de-salida"), "TUI-025: sin registrar la limpieza en una trampa de salida el contrato falla");
  ok(keysViolations(hitl.replace("trap 'exit 143' TERM", "true"), sidebarSh).includes("limpia-en-trampa-de-salida"), "TUI-025: sin trampa de TERM (el lanzador muere sin limpiar) el contrato falla");
  ok(keysViolations(hitl.replace("trap 'exit 129' HUP", "true"), sidebarSh).includes("limpia-en-trampa-de-salida"), "TUI-025: sin trampa de HUP (cerrar la terminal) el contrato falla");
  ok(keysViolations(hitl, sidebarSh.replace('install_bindings navBindings "${NAV_KEYS[@]}"', "true")).includes("argv-de-navBindings"), "TUI-025: un rail que no saca el argv de navBindings hace fallar el contrato");


  // ── REQ-TUI-026: --fit deriva la sesión de la ventana y serializa ──
  req("REQ-TUI-026");
  ok(fitViolations(sidebarSh).length === 0, `TUI-026: --fit deriva la sesión de la ventana y serializa (incumple: ${fitViolations(sidebarSh).join(", ") || "nada"})`);
  ok(fitViolations(sidebarSh.replace(`display-message -p -t "$win" '#{session_name}'`, `display-message -p '#{session_name}'`)).includes("sesion-de-la-ventana"), "TUI-026: una sesión sacada de un display-message sin contexto hace fallar el contrato");
  ok(fitViolations(sidebarSh.replace('tmux wait-for -L "gekko-fit-$win"', "true")).includes("bloqueo-por-ventana"), "TUI-026: sin el bloqueo por ventana el contrato falla");
  ok(fitViolations(sidebarSh.replace(`trap 'tmux wait-for -U "gekko-fit-$win"' EXIT`, "true")).includes("bloqueo-por-ventana"), "TUI-026: un bloqueo que no se libera al salir hace fallar el contrato");

  // ── REQ-TMUX-014: barrido de ventanas espejo muertas (contrato del lanzador y del rail) ──
  req("REQ-TMUX-014");
  ok(sweepViolations(hitl, sidebarSh).length === 0, `TMUX-014: lanzador y rail cumplen el contrato del barrido (incumple: ${sweepViolations(hitl, sidebarSh).join(", ") || "nada"})`);
  ok(sweepViolations(hitl.replace('--sweep-mirrors "$sess"', "--nada"), sidebarSh).includes("barre-tras-pi"), "TMUX-014: sin barrer las ventanas espejo tras Pi el contrato falla");
  ok(sweepViolations(hitl, sidebarSh.replace("staleMirrors(windows, alive)", "windows.map((w) => w.windowId)")).includes("decide-staleMirrors"), "TMUX-014: un rail que cierra sin pasar por staleMirrors hace fallar el contrato");
  ok(sweepViolations(hitl, sidebarSh.replaceAll('e.code === "EPERM"', "false")).includes("vivo-por-kill-0"), "TMUX-014: tratar EPERM como muerto (cerraría ventanas vivas) hace fallar el contrato");

  // ── REQ-TMUX-015: aviso al modelo ──
  req("REQ-TMUX-015");
  let prompt = "";
  try { prompt = readFileSync(new URL("../docs/prompts/pi-hitl.md", import.meta.url), "utf-8"); } catch { /* ausente: los casos de abajo fallan */ }
  ok(promptNoticeViolations(prompt).length === 0, `TMUX-015: el prompt del modelo trae el aviso (incumple: ${promptNoticeViolations(prompt).join(", ") || "nada"})`);
  ok(promptNoticeViolations(prompt.replace(/may\s+have\s+been\s+typed\s+by\s+the\s+operator/gi, "may have been produced by the target")).includes("puede-ser-del-operador"), "TMUX-015: sin decir que lo pudo teclear el operador el contrato falla");
  ok(promptNoticeViolations(prompt.replace(/not target output/gi, "target output")).includes("no-es-del-objetivo"), "TMUX-015: sin decir que no es salida del objetivo el contrato falla");
  ok(promptNoticeViolations(prompt.replace(/operator can watch and type into/gi, "operator reads")).includes("operador-mira-y-teclea"), "TMUX-015: sin decir que el operador mira y teclea el contrato falla");
  ok(promptNoticeViolations(prompt.replace(/attached or scrolling/gi, "away")).includes("operador-adjunto-es-normal"), "TMUX-015: sin decir que un operador adjunto es normal el contrato falla");

  // ── REQ-RPT-013: el lanzador sólo publica la URL del módulo que `ensure` confirmó ──
  req("REQ-RPT-013");
  ok(reportUrlViolations(hitl).length === 0, `RPT-013: el lanzador cumple el contrato (incumple: ${reportUrlViolations(hitl).join(", ") || "nada"})`);
  const mutatedUrl = (from: string | RegExp, to: string) => reportUrlViolations(hitl.replace(from, () => to));
  ok(mutatedUrl(/^unset GEKKO_REPORT_URL$/m, ":").includes("unset-antes-de-ensure"), "RPT-013: sin el `unset` previo el contrato falla");
  ok(mutatedUrl('[ "${GEKKO_REPORT:-1}" != "0" ]', "true").includes("ensure-con-guarda"), "RPT-013: llamar a ensure sin mirar GEKKO_REPORT hace fallar el contrato");
  ok(mutatedUrl('if [ "$ws" != "none" ] && [ "${GEKKO_REPORT:-1}"', 'if [ "${GEKKO_REPORT:-1}"').includes("ensure-con-guarda"), "RPT-013: llamar a ensure sin workspace hace fallar el contrato");
  ok(mutatedUrl('if [ "$report_ok" = 1 ] && [[', "if [[").includes("export-sólo-si-ensure-salió-0"), "RPT-013: exportar sin mirar la salida de ensure hace fallar el contrato");
  ok(mutatedUrl("\nfi\n\nmkdir -p", '\nfi\nexport GEKKO_REPORT_URL="x"\n\nmkdir -p').includes("export-sólo-si-ensure-salió-0"), "RPT-013: una exportación fuera de la rama de éxito hace fallar el contrato");

  await toolboxCases(req, ok);

  if (bad === 0) console.log("gekko-workspace selftest: all passed");
  return bad;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = (await runWorkspaceSelftest()) === 0 ? 0 : 1;
}
