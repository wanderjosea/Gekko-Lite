// Spec 010 — workspace obligatorio al lanzar. Toda la lógica (nombres, objetivos, andamiaje, menú, argumentos de
// sesión tmux) vive aquí como funciones puras con E/S inyectada; abajo, un CLI mínimo que usa tools/pi-hitl.sh.
// Sin imports de Pi ni de typebox: lo importan shell-session.ts y el selftest.
import { execFileSync } from "node:child_process";
import { closeSync, constants, existsSync, fstatSync, ftruncateSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, realpathSync, statSync, writeFileSync, writeSync } from "node:fs";
import { lookup } from "node:dns/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";

export const WS_NONE = "none";

// ───────── nombre y confinamiento ─────────
export function validWorkspaceName(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,30}$/.test(name) && !name.includes("..") && name !== WS_NONE;
}

export function workspaceDir(root: string, name: string): string {
  return join(root, "engagements", name);
}

// Falla cerrado: si la ruta no se puede resolver (no existe, sin permiso) no está confinada.
export function confined(root: string, name: string, realpath: (p: string) => string): boolean {
  try {
    const base = realpath(join(root, "engagements"));
    return realpath(workspaceDir(root, name)).startsWith(base + sep);
  } catch {
    return false;
  }
}

// ───────── objetivos ─────────
export type Target = { ip: string; label?: string };
type Rejected = { token: string; reason: string };

const NAME_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const IPV4_SHAPE = /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/; // misma forma que acepta parseScopeLine del broker
const NUMERIC_ONLY = /^[\d.\/]+$/; // sólo dígitos, puntos y barra: una IP mal escrita, nunca una etiqueta ni un nombre

// null = es IPv4/CIDR válido; si no, el motivo. Octetos 0–255 sin cero inicial, bits 0–32.
function ipv4Problem(token: string): string | null {
  const [addr, bits] = token.split("/");
  const octets = addr.split(".");
  if (octets.some((o) => o.length > 1 && o.startsWith("0"))) return "octeto con cero inicial";
  if (octets.some((o) => Number(o) > 255)) return "octeto mayor que 255";
  if (bits !== undefined && Number(bits) > 32) return "máscara CIDR mayor que 32";
  return null;
}

export function parseTargets(input: string): { targets: Target[]; names: string[]; rejected: Rejected[] } {
  const targets: Target[] = [];
  const names: string[] = [];
  const rejected: Rejected[] = [];
  let labelable = false; // el token anterior fue una IP/CIDR todavía sin etiqueta
  for (const part of input.split(/([\s,]+)/)) {
    if (part === "") continue;
    if (/^[\s,]+$/.test(part)) {
      if (part.includes(",")) labelable = false;
      continue;
    }
    if (IPV4_SHAPE.test(part)) {
      const problem = ipv4Problem(part);
      if (problem) { rejected.push({ token: part, reason: problem }); labelable = false; }
      else { targets.push({ ip: part }); labelable = true; }
    } else if (NUMERIC_ONLY.test(part)) {
      rejected.push({ token: part, reason: "parece una IP o un CIDR mal escrito" });
      labelable = false;
    } else if (part.includes(":")) {
      rejected.push({ token: part, reason: "puerto o IPv6 no soportado (sólo IPv4 o CIDR)" });
      labelable = false;
    } else if (!NAME_TOKEN.test(part)) {
      rejected.push({ token: part, reason: "no es IPv4, CIDR ni un nombre válido" });
      labelable = false;
    } else if (labelable) {
      targets[targets.length - 1] = { ip: targets[targets.length - 1].ip, label: part };
      labelable = false;
    } else {
      names.push(part);
    }
  }
  return { targets, names, rejected };
}

export function scopeLine(t: Target): string {
  return t.label ? `${t.ip}  # ${t.label}` : t.ip;
}

export function scopeFileText(name: string, targets: Target[]): string {
  const header = `# ${name} — scope (allowlist). host | CIDR | host:port, uno por línea. '#' comenta.`;
  return [header, ...targets.map(scopeLine)].join("\n") + "\n";
}

function stripComment(line: string): string {
  return line.replace(/#.*/, "").trim();
}

export function scopeEntries(text: string): string[] {
  return text.split("\n").map(stripComment).filter((line) => line !== "");
}

export function replaceScopeText(oldText: string, targets: Target[], isoDate: string): string {
  const kept = oldText.replace(/\n+$/, "").split("\n").map((line) =>
    stripComment(line) === "" ? line : `# (reemplazado ${isoDate}) ${line}`);
  return [...kept, ...targets.map(scopeLine)].join("\n") + "\n";
}

// ───────── andamiaje (única fuente; el skill engagement-init llama al CLI `new`) ─────────
function notesText(name: string, ips: string): string {
  return `# ${name} — ${ips} — Notas de engagement

Modo VPN: <Full | Restricted>  (ver CLAUDE.md / toolbox/vpn-modes.md).
Workdir: \`engagements/${name}/\`.

## 0. Autorización (scope) — llenar ANTES de tocar el target
Regla efectiva = la más restrictiva (ver \`scope.md\`). Fuera de esto → parar y pedir.
- Activo(s):            <nombre/rol del sistema>
- IP / hostname:        <${ips} / fqdn>  (allowlist exacta, no "y relacionados")
- Puertos / protocolos: <p.ej. 80,443 tcp>
- Rutas / API en scope: <paths, endpoints; N/A si no aplica>
- Ventana temporal:     <YYYY-MM-DD HH:MM–HH:MM TZ>
- Origen permitido:     <IP/VPN desde la que se autoriza atacar>
- Cuentas autorizadas:  <usuarios/credenciales provistas; N/A>
- Técnicas EXCLUIDAS:   <brute-force salvo aprobación; DoS SIEMPRE prohibido; …>
- Límites de tasa:      <req/s, threads, lockout a respetar>

## 1. Recon
## 2. Vectores descartados (auditoría de negativos)
## 3. Foothold
## 4. Privesc
## 5. Lateral / AD
## 6. Loot / objetivo
## 7. Cleanup (revertir + documentar cada cambio en el target)
`;
}

function authorizationText(name: string): string {
  return `# ${name} — Autorización (llenar y confirmar ANTES de tocar el target)

Regla dura (\`rules/engagement-authorization.md\`): sin este archivo lleno + ventana
vigente, NO hay testing activo. Verbal/chat NO alcanza para un cliente real.

- Cliente (codename):     ${name}   (nombre real/PII fuera de todo path commiteado)
- Orden firmada (ref):    <doc/ID/fecha de la autorización escrita + firmante>
- Alcance (allowlist):    <IPs/hosts/URLs/puertos/cuentas exactos>
- Fuera de alcance:       <lo explícitamente vedado>
- Ventana de testing:     <YYYY-MM-DD HH:MM–HH:MM TZ>   (actuar solo dentro)
- Técnicas permitidas:    <…>   |  Vedadas: <brute-force salvo OK; DoS SIEMPRE no>
- Límites de tasa/lockout: <req/s, threads, umbral de lockout>
- Prod / notificación:    <acciones que requieren aviso previo al cliente>
- Contacto emergencia:    <nombre + canal para parar / incidentes>
- Retención/destrucción:  <qué se guarda, cuánto, y borrado seguro al cierre>
`;
}

function credsText(name: string): string {
  return `# ${name} — creds vault (procedencia obligatoria; NO se commitea)
| usuario | secreto | tipo | procedencia (cómo/dónde) | verificado |
|---|---|---|---|---|
`;
}

export function scaffoldPlan(name: string, targets: Target[]): { path: string; content: string | null }[] {
  const ips = targets.length > 0 ? targets.map((t) => t.ip).join(", ") : "IP por definir";
  return [
    { path: "scope.txt", content: scopeFileText(name, targets) },
    { path: "notes.md", content: notesText(name, ips) },
    { path: "AUTHORIZATION.md", content: authorizationText(name) },
    { path: "loot/creds.md", content: credsText(name) },
    { path: "scripts", content: null },
    { path: "canaries", content: null },
  ];
}

// Crea lo que falta y nunca toca un archivo existente ("wx" falla con EEXIST). Devuelve las rutas creadas.
export function applyScaffold(dir: string, plan: { path: string; content: string | null }[]): string[] {
  const created: string[] = [];
  for (const entry of plan) {
    const target = join(dir, entry.path);
    if (entry.content === null) {
      mkdirSync(target, { recursive: true });
      continue;
    }
    mkdirSync(dirname(target), { recursive: true });
    try {
      writeFileSync(target, entry.content, { flag: "wx" });
      created.push(entry.path);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
  }
  return created;
}

// ───────── modo de ejecución (spec 013): dónde nacen las shells del modelo ─────────
export type ExecMode = "os" | "toolbox";
export const EXEC_FILE = "exec"; // engagements/<ws>/exec: una palabra; sin archivo = os

export function parseExecMode(text: string | null): ExecMode | null {
  if (text === null) return "os";
  const word = text.trim();
  return word === "os" || word === "toolbox" ? word : null;
}

// Guarda el modo EN EL LUGAR: el contenedor monta `exec` por inodo (REQ-TBX-007), un renombre lo dejaría viendo el viejo.
// Sin seguir enlaces: O_EXCL al crear, O_NOFOLLOW al abrir uno existente (una FIFO sin lector da ENXIO, no bloquea).
export function writeExecMode(dir: string, mode: ExecMode): void {
  if (mode !== "os" && mode !== "toolbox") throw new Error(`modo inválido '${String(mode)}': debe ser 'os' o 'toolbox'`);
  const path = join(dir, EXEC_FILE);
  const text = mode + "\n";
  let fd: number;
  try {
    fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o644);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    try {
      fd = openSync(path, constants.O_WRONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    } catch (e2) {
      const code = (e2 as NodeJS.ErrnoException).code;
      if (code === "ELOOP" || code === "ENXIO") throw new Error(`'${path}' no es un archivo regular: no se escribe el modo`);
      throw e2;
    }
  }
  try {
    if (!fstatSync(fd).isFile()) throw new Error(`'${path}' no es un archivo regular: no se escribe el modo`);
    writeSync(fd, text, 0);
    ftruncateSync(fd, text.length);
  } finally {
    closeSync(fd);
  }
}

export function tmuxCommand(mode: ExecMode, container: string | undefined, args: string[]): { file: string; args: string[] } {
  if (mode === "os") return { file: "tmux", args };
  if (!container) throw new Error("modo toolbox sin nombre de contenedor: no se invoca tmux");
  return { file: "docker", args: ["exec", container, "tmux", ...args] };
}

// Excepción dentro de una regla de seguridad (el guard deja pasar un `bash` que nombra un host del scope sólo si es
// esto): lista blanca estricta, nada de metacaracteres de shell. `.` no cruza saltos de línea; además se rechazan.
export function ledgerCliOnly(command: string, root: string): boolean {
  if (/[;&|$`<>\\\x00-\x1f\x7f]/.test(command)) return false;
  const escapedRoot = root.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^(?:python3 )?(?:\\./|${escapedRoot}/)?\\.claude/tools/findings\\.py (?:add|set|list|render)(?: .*)?$`).test(command);
}

// ───────── contenedor del workspace ─────────
const OVPN_DEST = "/vpn/target.ovpn";

export function toolboxName(ws: string): string {
  return "gekko-tb-" + ws;
}

// Dentro del workspace (escritura) el contenedor ve tres archivos que deciden modo, scope y autorización en SOLO LECTURA,
// sobre sí mismos, y el almacén de sesiones de Pi enmascarado por un tmpfs vacío.
export const SESSIONS_DIR = ".pi-sessions";
export const GUARDED_FILES = ["exec", "scope.txt", "AUTHORIZATION.md"] as const;
const SESSIONS_TMPFS_OPTIONS = "tmpfs-size=1048576,tmpfs-mode=0700"; // --mount (no --tmpfs): sólo así docker inspect lo lista en Mounts

function guardedFiles(authorization: boolean): string[] {
  return GUARDED_FILES.filter((file) => authorization || file !== "AUTHORIZATION.md");
}

export function toolboxRunArgs(o: { name: string; image: string; root: string; wsDir: string; ovpn?: string; authorization?: boolean }): string[] {
  const tools = `${o.root}/.claude/tools`;
  for (const path of [o.wsDir, tools, ...(o.ovpn ? [o.ovpn] : [])]) {
    if (path.includes(":")) throw new Error(`la ruta '${path}' contiene ':' y no se puede montar`);
  }
  if (o.wsDir.includes(",")) throw new Error(`la ruta '${o.wsDir}' contiene ',' y no se puede montar (--mount)`);
  return ["run", "-d", "--init", "--name", o.name, "--cap-add=NET_ADMIN", "--cap-drop=MKNOD", "--device=/dev/net/tun",
    "-v", `${o.wsDir}:${o.wsDir}`,
    ...guardedFiles(o.authorization === true).flatMap((file) => ["-v", `${o.wsDir}/${file}:${o.wsDir}/${file}:ro`]),
    "--mount", `type=tmpfs,destination=${o.wsDir}/${SESSIONS_DIR},${SESSIONS_TMPFS_OPTIONS}`,
    "-v", `${tools}:${tools}:ro`,
    ...(o.ovpn ? ["-v", `${o.ovpn}:${OVPN_DEST}:ro`] : []),
    "-w", o.wsDir, o.image, "sleep", "infinity"];
}

export function toolboxPlan(state: "absent" | "stopped" | "running", mountsOk: boolean): "run" | "start" | "reuse" | "refuse" {
  if (state === "absent") return "run";
  if (!mountsOk) return "refuse";
  return state === "stopped" ? "start" : "reuse";
}

type InspectEntry = {
  Id?: string; Image?: string; NetworkSettings?: { Networks?: Record<string, unknown> };
  Config?: { Cmd?: string[] | null; Entrypoint?: string[] | null; User?: string };
  HostConfig?: {
    NetworkMode?: string; Privileged?: boolean; Init?: boolean; CapAdd?: string[]; CapDrop?: string[] | null; PidMode?: string; IpcMode?: string; UsernsMode?: string;
    Devices?: { PathOnHost: string; PathInContainer: string; CgroupPermissions: string }[]; SecurityOpt?: string[] | null; DeviceCgroupRules?: string[] | null;
    PortBindings?: Record<string, unknown> | null; PublishAllPorts?: boolean; ExtraHosts?: string[] | null; Dns?: string[] | null;
    DeviceRequests?: unknown[] | null; RestartPolicy?: { Name?: string };
  };
  State?: { Running?: boolean };
  Mounts?: { Type?: string; Source?: string; Destination?: string; RW?: boolean; Propagation?: string }[];
};
type ImageDefaults = { id: string; entrypoint: string[] | null; user: string };

function parseInspect(json: string): InspectEntry | null {
  try {
    const parsed = JSON.parse(json);
    return Array.isArray(parsed) && parsed.length === 1 && typeof parsed[0] === "object" && parsed[0] !== null ? parsed[0] : null;
  } catch {
    return null;
  }
}

// Montajes exactos: workspace (rw); exec, scope.txt y —si existe— AUTHORIZATION.md (ro) sobre sí mismos; el tmpfs que
// enmascara .pi-sessions; .claude/tools (ro) en sus mismas rutas, más el .ovpn (ro) si lo hay; nada más.
export function toolboxMountsOk(inspectJson: string, root: string, wsDir: string, ovpnPath?: string, authorization = false): boolean {
  const mounts = parseInspect(inspectJson)?.Mounts;
  if (!Array.isArray(mounts)) return false;
  const tools = `${root}/.claude/tools`;
  const ovpn = mounts.filter((m) => m.Destination === OVPN_DEST);
  if (ovpnPath === undefined ? ovpn.length !== 0 : ovpn.length !== 1 || ovpn[0].Type !== "bind" || ovpn[0].Source !== ovpnPath || ovpn[0].RW !== false) return false;
  const rest = mounts.filter((m) => m.Destination !== OVPN_DEST).map((m) => `${m.Type}|${m.Source}|${m.Destination}|${m.RW}`).sort();
  const expected = [`bind|${wsDir}|${wsDir}|true`, `bind|${tools}|${tools}|false`, `tmpfs||${wsDir}/${SESSIONS_DIR}|true`,
    ...guardedFiles(authorization).map((file) => `bind|${wsDir}/${file}|${wsDir}/${file}|false`)].sort();
  return same(rest, expected);
}

const sameJson = (a: unknown, b: unknown) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

function toolboxIsolationOk(entry: InspectEntry, image: ImageDefaults): boolean {
  const h = entry.HostConfig;
  return entry.Image === image.id && image.id.startsWith("sha256:") && !!h
    && same(Object.keys(entry.NetworkSettings?.Networks ?? {}), ["bridge"]) && !(h.DeviceCgroupRules?.length)
    && (h.NetworkMode === "default" || h.NetworkMode === "bridge") && h.Privileged === false && h.Init === true
    && same((h.CapAdd ?? []).map((cap) => cap.replace(/^CAP_/, "")), ["NET_ADMIN"]) // docker 29 informa CAP_NET_ADMIN
    && same((h.CapDrop ?? []).map((cap) => cap.replace(/^CAP_/, "")), ["MKNOD"]) // sin MKNOD el root del contenedor no planta un dispositivo que el host abra
    && h.Devices?.length === 1 && h.Devices[0].PathOnHost === "/dev/net/tun" && h.Devices[0].PathInContainer === "/dev/net/tun" && h.Devices[0].CgroupPermissions === "rwm"
    && h.PidMode === "" && h.IpcMode === "private" && h.UsernsMode === "" && !(h.SecurityOpt?.length)
    && Object.keys(h.PortBindings ?? {}).length === 0 && h.PublishAllPorts === false
    && !(h.ExtraHosts?.length) && !(h.Dns?.length) && !(h.DeviceRequests?.length) && ["", "no"].includes(h.RestartPolicy?.Name ?? "")
    && sameJson(entry.Config?.Cmd, ["sleep", "infinity"]) && sameJson(entry.Config?.Entrypoint, image.entrypoint) && (entry.Config?.User ?? "") === image.user
    && Array.isArray(entry.Mounts) && entry.Mounts.every((m) => m.Type !== "bind" || m.Propagation === "rprivate");
}

function same(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// ───────── shells ─────────
// Nombre de sesión que se imprime en un comando de attach copiable: sólo la etiqueta de socket, sin espacios ni metacaracteres.
export const SHELL_NAME_RE = /^[A-Za-z0-9_@][A-Za-z0-9_@-]{0,63}$/;

// Ruta real aunque el último tramo aún no exista: se resuelve por el padre existente más cercano.
function realPathOrParent(path: string, realpath: (p: string) => string): string {
  try {
    return realpath(path);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT" || dirname(path) === path) throw e;
    return join(realPathOrParent(dirname(path), realpath), basename(path));
  }
}

// Directorio de sockets tmux, según DÓNDE nace la shell. Toolbox: siempre <ws>/.gekko-sockets (un GEKKO_TMUX_DIR heredado
// es del host y el contenedor no lo monta). OS: el heredado o <tmp>/gekko-sockets, pero NUNCA dentro del workspace
// (por ruta real): ese directorio se monta escribible en el contenedor, y con el servidor tmux del host ahí el contenedor
// ejecutaría en el host (`tmux -S <sock> run-shell`). Sin sitio seguro lanza: quien llama rehúsa el socket con etiqueta.
export function socketDir(
  env: { GEKKO_TMUX_DIR?: string; GEKKO_EXEC?: string; GEKKO_WORKSPACE_DIR?: string },
  tmp: string,
  place: ExecMode = env.GEKKO_EXEC === "toolbox" ? "toolbox" : "os",
  realpath: (p: string) => string = realpathSync,
): string {
  const wsDir = env.GEKKO_WORKSPACE_DIR;
  if (place === "toolbox") return wsDir ? join(wsDir, ".gekko-sockets") : join(tmp, "gekko-sockets");
  const wsReal = wsDir ? realPathOrParent(wsDir, realpath) : undefined;
  const outside = (dir: string) => wsReal === undefined || !(realPathOrParent(dir, realpath) + sep).startsWith(wsReal + sep);
  const candidates = [env.GEKKO_TMUX_DIR, join(tmp, "gekko-sockets")].filter((dir): dir is string => !!dir);
  const safe = candidates.find(outside);
  if (safe === undefined) throw new Error("ningún directorio de sockets queda fuera del workspace: no se crea una shell con socket propio");
  return safe;
}

export function newSessionArgs(name: string, wsDir: string | undefined): string[] {
  // IGNOREEOF=10: un Ctrl+D por reflejo en el prompt no cierra la shell (sólo bash lo lee)
  const base = ["new-session", "-d", "-s", name, "-x", "220", "-y", "50", "-e", "IGNOREEOF=10"];
  return wsDir === undefined ? base : [...base, "-c", wsDir];
}

export function cwdVerdict(wsDirReal: string | undefined, paneCurrentPath: string): { ok: boolean; note: string } {
  if (wsDirReal === undefined || paneCurrentPath === wsDirReal) return { ok: true, note: "" };
  return { ok: false, note: `la shell arrancó en ${paneCurrentPath} y no en el workspace ${wsDirReal}` };
}

// ───────── prompt del modelo (en inglés: el prompt base también) ─────────
export function workspacePromptBlock(name: string | null, dir: string | null, mode: ExecMode = "os", container?: string): string {
  if (name === null || dir === null) {
    return `## Workspace

No workspace is set for this session. Do not create engagement directories. If the task needs one, ask the operator.
`;
  }
  const box = container ?? toolboxName(name);
  const shells = `- Where things run depends on the execution mode, and the operator can change it while Pi is open:
  - mode \`os\`: \`session_*\` shells are born on this host and start in the workspace directory. The \`bash\` tool runs at the repository root on the host, so use the absolute path or \`cd\` first.
  - mode \`toolbox\`: \`session_*\` shells are born INSIDE the container \`${box}\` (Kali, root, its own network), in the workspace directory. The \`bash\` tool and the read tools still run on the HOST at the repository root: use \`bash\` to read the repo and the KB. Anything that goes against the target goes through a shell (\`session_new\`, then the session tools), never through \`bash\`: the guard blocks a \`bash\` command that names an in-scope host, except registering findings with \`.claude/tools/findings.py\`.
- Mode in force at launch: \`${mode}\`. The result of \`session_new\` ends with \`lugar=os\` or \`lugar=toolbox\`: where that shell was born, and where its commands run.
- If \`session_new\` fails naming a toolbox state (\`levantando\`, \`caída\`), stop and tell the operator. Do not retry elsewhere and do not move the commands to \`bash\`.
- In toolbox mode the container sees only the workspace (read-write; \`exec\`, \`scope.txt\` and \`AUTHORIZATION.md\` are read-only there, and \`.pi-sessions\` is empty) and \`.claude/tools\` (read-only): write artifacts, scripts and loot inside the workspace directory.
- The guard counts this HOST's own addresses as always in scope, not the container's: a payload or listener that names the container's own address (its tun0 or eth0) is blocked as out of scope until the operator adds that address to \`scope.txt\`. Ask the operator.
- The operator attaches to a toolbox shell with \`docker exec -it ${box} tmux attach -t <session-name>\`.`;
  return `## Workspace

The operator selected the engagement workspace \`${name}\` for this session: \`${dir}\`
- It is already scaffolded. Do NOT create another engagement tree; work inside this directory.
- Layout: \`scope.txt\` (allowlist the broker loads), \`AUTHORIZATION.md\`, \`notes.md\`, \`scripts/\`, \`canaries/\`, \`loot/\`.
${shells}
- The environment variable \`GEKKO_WORKSPACE_DIR\` holds the workspace path and is available to every command, including those run by subagents.
- When you delegate to a subagent, put the workspace path in the task prompt.
`;
}

// ───────── menú ─────────
export type PickIo = {
  readLine(prompt: string): Promise<string | null>;
  write(s: string): void;
  list(): string[];
  lastUsed(): string | null;
  liveShells(name: string): number | null; // shells tmux vivas nacidas en ese workspace; null = sin dato
  readScope(name: string): string;
  create(name: string, targets: Target[], mode: ExecMode): void;
  replaceScope(name: string, targets: Target[]): void;
  resolve(host: string): Promise<string | null>;
  containerExists(name: string): boolean | null; // ¿existe ya gekko-tb-<nombre>? null = docker ausente o sin respuesta
};

const YES = /^(s|si|sí)$/i;

// null = fin de entrada.
async function askTargets(io: PickIo): Promise<Target[] | null> {
  for (;;) {
    const line = await io.readLine("Objetivos (IPv4 o CIDR, 'IP etiqueta'; Enter = ninguno): ");
    if (line === null) return null;
    const parsed = parseTargets(line);
    if (parsed.rejected.length > 0) {
      for (const r of parsed.rejected) io.write(`  rechazado '${r.token}': ${r.reason}\n`);
      continue;
    }
    const targets = [...parsed.targets];
    let unresolved = false;
    for (const host of parsed.names) {
      const ip = await io.resolve(host);
      if (ip === null) {
        io.write(`  '${host}' no resolvió; vuelve a dar los objetivos.\n`);
        unresolved = true;
        break;
      }
      const answer = await io.readLine(`${host} → ${ip} ¿añadir? [s/N]: `);
      if (answer === null) return null;
      if (YES.test(answer.trim())) targets.push({ ip, label: host });
    }
    if (!unresolved) return targets;
  }
}

// null = fin de entrada.
async function askExecMode(io: PickIo): Promise<ExecMode | null> {
  for (;;) {
    const line = await io.readLine("¿Dónde nacen las shells del modelo? [Enter/o = OS (este equipo), t = toolbox (contenedor)]: ");
    if (line === null) return null;
    const choice = line.trim().toLowerCase();
    if (choice === "" || choice === "o" || choice === "os") return "os";
    if (choice === "t" || choice === "toolbox") return "toolbox";
    io.write("  responde Enter, o (os) o t (toolbox).\n");
  }
}

async function createFlow(io: PickIo): Promise<string | null> {
  for (;;) {
    const answer = await io.readLine("Nombre: ");
    if (answer === null) return null;
    const name = answer.trim();
    if (!validWorkspaceName(name)) {
      io.write("  nombre inválido: usa letras, dígitos, '.', '_' o '-' (máx. 31, empieza con letra o dígito, sin '..' ni 'none').\n");
    } else if (io.list().includes(name)) {
      io.write(`  '${name}' ya existe.\n`);
    } else if (io.containerExists(name) === true) {
      // Antes de crear: si no, el lanzador rechaza el contenedor después y el workspace queda a medias (REQ-TBX-013).
      io.write(`  ${containerClashText(name)}.\n`);
    } else {
      const targets = await askTargets(io);
      if (targets === null) return null;
      const mode = await askExecMode(io);
      if (mode === null) return null;
      io.create(name, targets, mode);
      return name;
    }
  }
}

async function enterExisting(io: PickIo, name: string): Promise<string | null> {
  const entries = scopeEntries(io.readScope(name));
  io.write(`Scope de ${name}:\n${entries.length > 0 ? entries.map((e) => `  ${e}\n`).join("") : "  (vacío)\n"}`);
  for (;;) {
    const answer = await io.readLine("¿Mantener este scope? [Enter = sí, r = reemplazar]: ");
    if (answer === null) return null;
    const choice = answer.trim().toLowerCase();
    if (choice === "") return name;
    if (choice === "r") {
      const targets = await askTargets(io);
      if (targets === null) return null;
      io.replaceScope(name, targets);
      return name;
    }
    io.write("  responde Enter o r.\n");
  }
}

export async function pickFlow(io: PickIo): Promise<string | null> {
  const names = io.list();
  const last = io.lastUsed();
  const lastListed = last !== null && names.includes(last) ? last : null;
  const rows = names.map((n, i) => {
    const live = io.liveShells(n);
    return `  ${i + 1}) ${n}${n === lastListed ? "  (último usado)" : ""}${live !== null && live > 0 ? ` · ${live} shells vivas` : ""}\n`;
  });
  io.write(`Workspaces:\n${rows.join("")}  n) nuevo\n`);
  const prompt = lastListed !== null ? `Elige [${lastListed}]: ` : "Elige: ";
  for (;;) {
    const answer = await io.readLine(prompt);
    if (answer === null) return null;
    const choice = answer.trim();
    if (choice === "" && lastListed !== null) return enterExisting(io, lastListed);
    if (names.includes(choice)) return enterExisting(io, choice);
    if (/^\d+$/.test(choice) && Number(choice) >= 1 && Number(choice) <= names.length) return enterExisting(io, names[Number(choice) - 1]);
    if (choice.toLowerCase() === "n") return createFlow(io);
    io.write("  opción no válida.\n");
  }
}

// ───────── CLI ─────────
class CliError extends Error {}

function rootDir(): string {
  return process.env.GEKKO_WS_ROOT || resolve(dirname(fileURLToPath(import.meta.url)), "..");
}

function lastPointer(): string {
  return join(rootDir(), ".gekko-state", "last-workspace");
}

function recordLastUsed(name: string): void {
  mkdirSync(dirname(lastPointer()), { recursive: true });
  writeFileSync(lastPointer(), name + "\n");
}

function readLastUsed(): string | null {
  try {
    return readFileSync(lastPointer(), "utf-8").trim() || null;
  } catch {
    return null;
  }
}

function listWorkspaces(): string[] {
  const root = rootDir();
  try {
    return readdirSync(join(root, "engagements"), { withFileTypes: true })
      .filter((e) => e.isDirectory() && validWorkspaceName(e.name) && existsSync(join(workspaceDir(root, e.name), "scope.txt")))
      .map((e) => e.name)
      .sort();
  } catch {
    return [];
  }
}

// Mejor esfuerzo: null si tmux no está; los sockets que fallan se saltan.
function countLiveShells(dir: string): number | null {
  let real: string;
  try { real = realpathSync(dir); } catch { return 0; }
  const sockDir = socketDir(process.env, tmpdir());
  let sockets: string[] = [];
  try { sockets = readdirSync(sockDir).map((f) => join(sockDir, f)); } catch { /* sin directorio de sockets: sólo el servidor por defecto */ }
  let count = 0;
  for (const prefix of [[], ...sockets.map((s) => ["-S", s])]) {
    try {
      const out = execFileSync("tmux", [...prefix, "list-sessions", "-F", "#{session_path}"], { timeout: 2000, encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] });
      count += out.split("\n").filter((p) => p === real).length;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    }
  }
  return count;
}

async function resolveHost(host: string): Promise<string | null> {
  try {
    return (await lookup(host, { family: 4 })).address;
  } catch {
    return null;
  }
}

// Lee stdin línea a línea (TTY o pipe); el prompt va a stderr; EOF → null.
function stdinLines(): { readLine(prompt: string): Promise<string | null>; close(): void } {
  const rl = createInterface({ input: process.stdin, terminal: false });
  const queue: string[] = [];
  const waiters: ((line: string | null) => void)[] = [];
  let closed = false;
  rl.on("line", (line) => { const waiter = waiters.shift(); if (waiter) waiter(line); else queue.push(line); });
  rl.on("close", () => { closed = true; for (const waiter of waiters.splice(0)) waiter(null); });
  return {
    readLine(prompt) {
      process.stderr.write(prompt);
      if (queue.length > 0) return Promise.resolve(queue.shift()!);
      if (closed) return Promise.resolve(null);
      return new Promise((done) => waiters.push(done));
    },
    close() { rl.close(); },
  };
}

function realPickIo(lines: ReturnType<typeof stdinLines>): PickIo {
  const root = rootDir();
  return {
    readLine: lines.readLine,
    write: (s) => process.stderr.write(s),
    list: listWorkspaces,
    lastUsed: readLastUsed,
    liveShells: (name) => countLiveShells(workspaceDir(root, name)),
    readScope: (name) => readRegularFile(join(workspaceDir(root, name), "scope.txt")) ?? "",
    create: (name, targets, mode) => { scaffoldInto(root, name, targets, mode); },
    replaceScope: (name, targets) => {
      const file = join(workspaceDir(root, name), "scope.txt");
      writeFileSync(file, replaceScopeText(readFileSync(file, "utf-8"), targets, new Date().toISOString().slice(0, 10)));
    },
    resolve: resolveHost,
    containerExists: (name) => dockerContainerExists(name),
  };
}

function requireName(name: string | undefined): string {
  if (name === undefined || !validWorkspaceName(name)) throw new CliError(`nombre de workspace inválido: '${name ?? ""}'`);
  return name;
}

// Un workspace es su directorio real: `engagements/alfa -> beta` haría pasar el scope, el modo y el contenedor de beta
// por los de alfa. Sólo el último componente; un enlace en `engagements/` (o más arriba) sigue valiendo.
function refuseLinkedWorkspace(name: string, dir: string): void {
  let isLink: boolean;
  try {
    isLink = lstatSync(dir).isSymbolicLink();
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return;
    throw e;
  }
  if (isLink) throw new CliError(`el workspace '${name}' es un enlace simbólico (${dir}): reemplazalo por el directorio real`);
}

function checkWorkspace(name: string | undefined): string {
  const valid = requireName(name);
  const root = rootDir();
  const dir = workspaceDir(root, valid);
  refuseLinkedWorkspace(valid, dir);
  if (readRegularFile(join(dir, "scope.txt")) === null) throw new CliError(`el workspace '${valid}' no existe o no tiene scope.txt (${dir})`);
  if (!confined(root, valid, realpathSync)) throw new CliError(`el workspace '${valid}' sale de engagements/ (enlace simbólico)`);
  return dir;
}

// Único punto que escribe un andamiaje: nunca dentro de un directorio que (por enlace simbólico) salga de engagements/.
function scaffoldInto(root: string, name: string, targets: Target[], mode?: ExecMode): { dir: string; created: string[] } {
  const dir = workspaceDir(root, name);
  refuseLinkedWorkspace(name, dir);
  if (existsSync(dir) && !confined(root, name, realpathSync)) throw new CliError(`'${name}' sale de engagements/ (enlace simbólico)`);
  const created = applyScaffold(dir, scaffoldPlan(name, targets));
  if (mode !== undefined) created.push(...applyScaffold(dir, [{ path: EXEC_FILE, content: mode + "\n" }]));
  return { dir, created };
}

// Lee un archivo que decide modo o scope sólo si es regular: un enlace simbólico o una FIFO no se leen (null = no existe).
// O_NOFOLLOW + O_NONBLOCK + fstat sobre el descriptor abierto: sin carrera entre comprobar y leer.
export function readRegularFile(path: string): string | null {
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    if (code === "ELOOP") throw new CliError(`'${path}' es un enlace simbólico: debe ser un archivo regular`);
    throw e;
  }
  try {
    if (!fstatSync(fd).isFile()) throw new CliError(`'${path}' no es un archivo regular`);
    return readFileSync(fd, "utf-8");
  } finally {
    closeSync(fd);
  }
}

// El ledger que el panel cuenta (GEKKO_FINDINGS), en el hilo de Pi: null en vez de seguir un enlace, bloquear
// ante una FIFO o leer más que el tope de findings.py; en toolbox el root del contenedor escribe ese directorio.
export const PANEL_LEDGER_MAX_BYTES = 64 * 2 ** 20;
export function readPanelLedger(path: string, maxBytes = PANEL_LEDGER_MAX_BYTES): string | null {
  let fd: number;
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK | constants.O_NOCTTY); } catch { return null; }
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > maxBytes) return null;
    const buf = Buffer.alloc(info.size + 1);  // un byte de más detecta un archivo que creció tras el fstat: null, el próximo tick lo lee
    let got = 0, n: number;
    while (got < buf.length && (n = readSync(fd, buf, got, buf.length - got, null)) > 0) got += n;
    return got > info.size ? null : buf.toString("utf-8", 0, got);
  } catch { return null; } finally { closeSync(fd); }
}

// Falla si el archivo `exec` existe y no se entiende; sin archivo = os.
function readExecMode(dir: string): ExecMode {
  const mode = parseExecMode(readRegularFile(join(dir, EXEC_FILE)));
  if (mode === null) throw new CliError(`el archivo '${join(dir, EXEC_FILE)}' no se entiende: debe contener 'os' o 'toolbox'`);
  return mode;
}

// Separa `--exec <os|toolbox>` de los objetivos.
function splitExecOption(args: string[]): { mode: ExecMode | undefined; targetArgs: string[] } {
  const at = args.indexOf("--exec");
  if (at < 0) return { mode: undefined, targetArgs: args };
  const value = args[at + 1];
  if (value !== "os" && value !== "toolbox") throw new CliError(`--exec admite 'os' o 'toolbox', no '${value ?? ""}'`);
  return { mode: value, targetArgs: [...args.slice(0, at), ...args.slice(at + 2)] };
}

function createWorkspace(name: string | undefined, args: string[]): string {
  const valid = requireName(name);
  const { mode, targetArgs } = splitExecOption(args);
  const parsed = parseTargets(targetArgs.join(" "));
  if (parsed.rejected.length > 0) throw new CliError(`objetivo rechazado '${parsed.rejected[0].token}': ${parsed.rejected[0].reason}`);
  if (parsed.names.length > 0) throw new CliError(`'new' no resuelve nombres de host (${parsed.names.join(", ")}): da IPv4 o CIDR`);
  if (!existsSync(workspaceDir(rootDir(), valid)) && dockerContainerExists(valid) === true) throw new CliError(containerClashText(valid));
  const { dir, created } = scaffoldInto(rootDir(), valid, parsed.targets, mode);
  process.stderr.write(created.length > 0 ? `creado: ${created.join(", ")}\n` : "nada que crear: el andamiaje ya estaba completo\n");
  return dir;
}

// ───────── contenedor: docker y setfacl inyectables ─────────
export type RunResult = { code: number; out: string; err: string }; // code 127 + err "ENOENT" = el programa no existe
export type Run = (file: string, args: string[]) => RunResult;

export const realRun: Run = (file, args) => {
  try {
    return { code: 0, out: execFileSync(file, args, { timeout: 120_000, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }), err: "" };
  } catch (e) {
    const failure = e as NodeJS.ErrnoException & { status?: number | null; stdout?: string; stderr?: string };
    if (failure.code === "ENOENT") return { code: 127, out: "", err: "ENOENT" };
    return { code: failure.status ?? 1, out: failure.stdout ?? "", err: (failure.stderr || failure.message || "").trim() };
  }
};

// Lo que ensureToolbox necesita saber del disco del workspace; inyectable para probar sin crear archivos.
export type ToolboxFs = {
  kind(path: string): "file" | "dir" | "other" | "missing"; // sin seguir enlaces simbólicos
  ownedSubdirs(wsDir: string, uid: number): string[];       // directorios de primer nivel del workspace que son del operador
};

export const realToolboxFs: ToolboxFs = {
  kind(path) {
    try {
      const stat = lstatSync(path);
      return stat.isFile() ? "file" : stat.isDirectory() ? "dir" : "other";
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return "missing";
      throw e;
    }
  },
  ownedSubdirs(wsDir, uid) {
    return readdirSync(wsDir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && lstatSync(join(wsDir, entry.name)).uid === uid)
      .map((entry) => join(wsDir, entry.name));
  },
};

// ¿Existe ya gekko-tb-<nombre>? null = docker ausente, sin permiso o sin respuesta (REQ-TBX-013).
export function dockerContainerExists(name: string, run: Run = realRun): boolean | null {
  const r = run("docker", ["inspect", "--type", "container", toolboxName(name)]);
  return r.code === 0 ? true : /no such (object|container)/i.test(r.err) ? false : null;
}

export const containerClashText = (name: string) =>
  `ya existe el contenedor '${toolboxName(name)}' (de un workspace anterior): bórralo con 'docker rm -f ${toolboxName(name)}' o elige otro nombre`;

type EnsureOpts = { root: string; ws: string; image: string; ovpn?: string; uid: number; run: Run; fs?: ToolboxFs };

const firstLine = (text: string) => text.trim().split("\n")[0];
const CONTAINER_ID = /^[0-9a-f]{64}$/;

function requireContainerId(id: string, source: string): string {
  if (!CONTAINER_ID.test(id)) throw new CliError(`${source} no devolvió un ID de contenedor`);
  return id;
}

// `docker image inspect --format '{{.Id}}\t{{json .Config}}'`; Entrypoint y User no existen en la salida cuando la imagen no los define.
function parseImageDefaults(out: string): ImageDefaults {
  const [id = "", config = "{}"] = out.trim().split("\t");
  try {
    const parsed = JSON.parse(config) as { Entrypoint?: string[] | null; User?: string };
    return { id, entrypoint: parsed.Entrypoint ?? null, user: parsed.User ?? "" };
  } catch {
    return { id: "", entrypoint: null, user: "" };
  }
}

// Archivos que deciden modo/scope y el almacén de sesiones: docker crearía un directorio (de root) donde falte un
// archivo o el directorio, así que se exige que existan antes de crear el contenedor.
function requireGuardedPaths(wsDir: string, fs: ToolboxFs): { authorization: boolean } {
  for (const file of ["exec", "scope.txt"]) {
    if (fs.kind(join(wsDir, file)) !== "file") throw new CliError(`'${join(wsDir, file)}' debe ser un archivo regular (se monta de sólo lectura en el contenedor)`);
  }
  if (fs.kind(join(wsDir, SESSIONS_DIR)) !== "dir") throw new CliError(`falta el directorio '${join(wsDir, SESSIONS_DIR)}' (lo crea el lanzador; el contenedor lo enmascara con un tmpfs)`);
  return { authorization: fs.kind(join(wsDir, "AUTHORIZATION.md")) === "file" };
}

// Deja arriba el contenedor del workspace y devuelve su ID, ya validado (todo `docker exec` posterior usa el ID: un
// contenedor reemplazado bajo Pi falla cerrado). Todo fallo es CliError y ocurre antes de crear nada: docker run /
// start son lo último que se ejecuta.
export function ensureToolbox(o: EnsureOpts): string {
  const name = toolboxName(o.ws);
  const wsDir = workspaceDir(o.root, o.ws);
  const fs = o.fs ?? realToolboxFs;
  if (o.ovpn !== undefined && !isAbsolute(o.ovpn)) throw new CliError(`GEKKO_OVPN='${o.ovpn}' debe ser una ruta absoluta`);
  const { authorization } = requireGuardedPaths(wsDir, fs);
  let runArgs: string[];
  try { runArgs = toolboxRunArgs({ name, image: o.image, root: o.root, wsDir, ovpn: o.ovpn, authorization }); } catch (e) { throw new CliError((e as Error).message); }
  if (o.ovpn !== undefined && !isRegularFile(o.ovpn)) throw new CliError(`GEKKO_OVPN='${o.ovpn}' no es un archivo existente`);
  const docker = o.run("docker", ["version", "--format", "{{.Server.Version}}"]);
  if (docker.code === 127) throw new CliError("docker no está instalado o no está en el PATH");
  if (docker.code !== 0) {
    throw new CliError(/permission denied/i.test(docker.err) ? "sin permiso para usar docker (¿tu usuario está en el grupo docker?)" : `docker no responde: ${firstLine(docker.err)}`);
  }
  const imageInspect = o.run("docker", ["image", "inspect", "--format", "{{.Id}}\t{{json .Config}}", o.image]);
  if (imageInspect.code !== 0) throw new CliError(`falta la imagen ${o.image}: constrúyela con 'make -C toolbox build'`);
  const image = parseImageDefaults(imageInspect.out);
  const inspected = o.run("docker", ["inspect", "--type", "container", name]);
  let plan: ReturnType<typeof toolboxPlan>;
  let existingId = "";
  if (inspected.code === 0) {
    const entry = parseInspect(inspected.out);
    if (entry === null) throw new CliError(`no se entiende la salida de 'docker inspect ${name}'`);
    plan = toolboxPlan(entry.State?.Running === true ? "running" : "stopped", toolboxMountsOk(inspected.out, o.root, wsDir, o.ovpn, authorization) && toolboxIsolationOk(entry, image));
    existingId = entry.Id ?? "";
  } else if (/no such (object|container)/i.test(inspected.err)) {
    plan = toolboxPlan("absent", false);
  } else {
    throw new CliError(`docker inspect ${name} falló: ${firstLine(inspected.err)}`);
  }
  if (plan === "refuse") throw new CliError(`ya existe un contenedor '${name}' con otros montajes o aislamiento/imagen distintos: no se adopta (bórralo con 'docker rm -f ${name}')`);
  if (plan !== "run") requireContainerId(existingId, `docker inspect ${name}`);
  for (const dir of [wsDir, ...fs.ownedSubdirs(wsDir, o.uid)]) {
    const acl = o.run("setfacl", ["-m", `d:u:${o.uid}:rwx,u:${o.uid}:rwx`, dir]);
    if (acl.code !== 0) throw new CliError(`no se pudo aplicar la ACL a '${dir}' (${acl.code === 127 ? "falta setfacl" : firstLine(acl.err)})`);
  }
  if (plan === "reuse") return existingId;
  const started = plan === "run" ? o.run("docker", runArgs) : o.run("docker", ["start", existingId]);
  if (started.code !== 0) throw new CliError(`docker ${plan} falló: ${firstLine(started.err)}`);
  return plan === "run" ? requireContainerId(started.out.trim(), "docker run") : existingId;
}

function isRegularFile(path: string): boolean {
  try { return statSync(path).isFile(); } catch { return false; }
}

function toolboxCommand(ws: string | undefined): string {
  const valid = requireName(ws);
  checkWorkspace(valid);
  return ensureToolbox({
    root: rootDir(), ws: valid, image: process.env.GEKKO_TOOLBOX_IMAGE || "gekko-toolbox:latest",
    ovpn: process.env.GEKKO_OVPN || undefined, uid: process.getuid!(), run: realRun,
  });
}

async function runCli(argv: string[]): Promise<number> {
  const [command, name, ...rest] = argv;
  try {
    switch (command) {
      case "pick": {
        const lines = stdinLines();
        const picked = await pickFlow(realPickIo(lines));
        lines.close();
        if (picked === null) throw new CliError("selección abortada (fin de entrada)");
        recordLastUsed(picked);
        console.log(picked);
        return 0;
      }
      case "check": console.log(checkWorkspace(name)); return 0;
      case "new": console.log(createWorkspace(name, rest)); return 0;
      case "scope": {
        checkWorkspace(name);
        const entries = scopeEntries(readRegularFile(join(workspaceDir(rootDir(), name!), "scope.txt")) ?? "");
        if (entries.length > 0) console.log(entries.join("\n"));
        return 0;
      }
      case "prompt": {
        if (name === WS_NONE) { console.log(workspacePromptBlock(null, null)); return 0; }
        const dir = checkWorkspace(name);
        const mode = rest[0];
        if (mode !== "os" && mode !== "toolbox") throw new CliError(`prompt necesita el modo ya resuelto ('os' o 'toolbox'), no '${mode ?? ""}'`);
        console.log(workspacePromptBlock(requireName(name), dir, mode));
        return 0;
      }
      case "mode": console.log(name === WS_NONE ? "os" : readExecMode(checkWorkspace(name))); return 0;
      case "toolbox": console.log(toolboxCommand(name)); return 0;
      case "touch": checkWorkspace(name); recordLastUsed(name!); return 0;
      default:
        throw new CliError("uso: gekko-workspace.ts <pick | check <nombre> | new <nombre> [--exec os|toolbox] [objetivo…] | mode <nombre|none> | toolbox <nombre> | scope <nombre> | prompt <nombre> <os|toolbox> | prompt none | touch <nombre>>");
    }
  } catch (e) {
    if (!(e instanceof CliError)) throw e;
    process.stderr.write(`gekko-workspace: ${e.message}\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCli(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
