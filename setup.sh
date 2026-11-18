#!/usr/bin/env bash
# Bootstrap Pi 1.5.0 y el perfil Gekko HITL para esta cuenta de operador.
# Re-ejecutable. Gekko posee el provider `provider`, el alias sub-128k y subagents.json;
# respalda (.bak) cualquier archivo que cambie y deja otros providers intactos.
# Perfil de pi-hitl.sh: provider `provider` + el modelo GEKKO_MODEL (obligatorio), contexto 256k
# (262144) y maxTokens 32k (32768); subagentes siempre en foreground.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
pi_version_required="1.5.0"
cfg_dir="${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"
env_file="$repo_root/.gekko-state/env"
model="${GEKKO_MODEL:-}"

say() { printf '[gekko-setup] %s\n' "$*"; }
err() { printf '[gekko-setup] error: %s\n' "$*" >&2; }
pi_ver() { pi --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1; }
# Lee un valor `export KEY="..."` ya guardado, sin sourcear el archivo.
saved() { [ -f "$env_file" ] || return 0; sed -n "s/^export $1=\"\(.*\)\"\$/\1/p" "$env_file" | head -1; }

for cmd in node npm tmux git python3; do
  command -v "$cmd" >/dev/null 2>&1 || { err "falta $cmd (instalá: sudo apt install -y nodejs npm tmux git python3)"; exit 1; }
done

# Docker y ACL sólo se necesitan si el workspace usa shells dentro de toolbox.
toolbox_missing=()
command -v docker >/dev/null 2>&1 || toolbox_missing+=(docker)
command -v setfacl >/dev/null 2>&1 || toolbox_missing+=(setfacl)
if [ "${#toolbox_missing[@]}" -gt 0 ]; then
  say "modo OS disponible; modo toolbox requiere: ${toolbox_missing[*]} (no son necesarios para modo OS)"
fi

# Versiones mínimas (spec 008 AC16): el rail necesita tmux >= 3.2 y node >= 22.19.
# Solo bash (regex), sin utilidades externas; "next-3.5" cuenta como 3.5.
ver_ge() { [[ "$1" =~ ([0-9]+)\.([0-9]+) ]] || return 1; (( BASH_REMATCH[1] > $2 || (BASH_REMATCH[1] == $2 && BASH_REMATCH[2] >= $3) )); }
ver_ge "$(tmux -V 2>/dev/null)" 3 2 || { err "tmux >= 3.2 requerido; detectado '$(tmux -V 2>/dev/null)' (instalá/actualizá: sudo apt install -y tmux)"; exit 1; }
ver_ge "$(node --version 2>/dev/null)" 22 19 || { err "node >= 22.19 requerido; detectado '$(node --version 2>/dev/null)' (instalá: https://nodejs.org o nvm install 22)"; exit 1; }
# El node de Debian/Kali se compila sin soporte TypeScript: la versión alcanza pero el rail no arranca.
if [ "$(node -p 'process.features.typescript' 2>/dev/null)" = false ]; then
  no_ts_msg="este node ($(node --version)) no ejecuta TypeScript (típico del paquete de Debian/Kali); instalá el oficial: nvm install 22 (o https://nodejs.org). DESPUÉS reiniciá la shell (terminal nueva) para que el node nuevo quede primero en el PATH, cerrá tmux (tmux kill-server) y volvé a correr setup.sh"
  # Sin terminal, en check-only o sin curl no se instala nada: se informa y se corta.
  if [ "${GEKKO_SETUP_CHECK_ONLY:-}" = 1 ] || [ ! -t 0 ] || ! command -v curl >/dev/null 2>&1; then err "$no_ts_msg"; exit 1; fi
  read -rp "Este node ($(node --version)) no ejecuta TypeScript. ¿Instalar el oficial con nvm (node 22) en tu usuario? [Y/n] " node_ans
  case "${node_ans:-y}" in [nN]*) err "$no_ts_msg"; exit 1 ;; esac
  export NVM_DIR="$HOME/.nvm"   # explícito: un NVM_DIR heredado de otro usuario (p. ej. /root/.nvm) rompe el instalador
  say "instalando nvm + node 22 en $NVM_DIR…"
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
  set +eu; . "$NVM_DIR/nvm.sh" && nvm install 22; nvm_rc=$?; set -eu   # nvm no tolera set -eu
  [ "$nvm_rc" -eq 0 ] && [ "$(node -p 'process.features.typescript' 2>/dev/null)" = strip ] || { err "la instalación de node con nvm falló; $no_ts_msg"; exit 1; }
  node_installed=1
  say "node $(node --version) instalado; sigo el setup con él"
fi
[ "${GEKKO_SETUP_CHECK_ONLY:-}" = 1 ] && { say "prerequisitos OK (check-only)"; exit 0; }

# Pi fijado en 1.5.0 (versión fijada).
if ! command -v pi >/dev/null 2>&1 || [ "$(pi_ver)" != "$pi_version_required" ]; then
  say "instalando @earendil-works/pi-coding-agent@$pi_version_required"
  npm install -g --ignore-scripts "@earendil-works/pi-coding-agent@$pi_version_required"
fi
[ "$(pi_ver)" = "$pi_version_required" ] || { err "se requiere Pi $pi_version_required; detectado '$(pi_ver)'"; exit 1; }

# Credenciales/modelo: shell actual → env guardado → prompt.
[ -n "${GEKKO_LLM_URL:-}" ] || GEKKO_LLM_URL="$(saved GEKKO_LLM_URL)"
[ -n "${GEKKO_LLM_URL:-}" ] || read -rp 'Provider endpoint (GEKKO_LLM_URL, http(s)://host:puerto/v1): ' GEKKO_LLM_URL
[ -n "${GEKKO_LLM_KEY:-}" ] || GEKKO_LLM_KEY="$(saved GEKKO_LLM_KEY)"
[ -n "${GEKKO_LLM_KEY:-}" ] || { read -rsp 'Provider API key (GEKKO_LLM_KEY): ' GEKKO_LLM_KEY; echo; }
# Modelo: GEKKO_MODEL en la shell, o el guardado, o prompt.
[ -n "$model" ] || model="$(saved GEKKO_MODEL)"
[ -n "$model" ] || read -rp 'Model id served by the Provider (GEKKO_MODEL): ' model
[ -n "$model" ] || { err "GEKKO_MODEL es obligatorio (id del modelo que sirve el Provider)"; exit 1; }
case "$GEKKO_LLM_URL" in http://*/v1|https://*/v1) ;; *) err 'GEKKO_LLM_URL debe ser http(s)://host:puerto/v1'; exit 1 ;; esac

# Key que verá el provider de Pi y el chat del módulo de reportes (GEKKO_LLM_KEY nunca llega al módulo).
# Por defecto es la misma que GEKKO_LLM_KEY; si el Provider usa otra para ese fin, exportala.
[ -n "${GEKKO_PROVIDER_KEY:-}" ] || GEKKO_PROVIDER_KEY="$(saved GEKKO_PROVIDER_KEY)"
[ -n "${GEKKO_PROVIDER_KEY:-}" ] || GEKKO_PROVIDER_KEY="$GEKKO_LLM_KEY"

# Probá el Provider con estas credenciales AHORA — atrapa el fallo #1 (URL/key equivocada
# da un error opaco recién en request-time). La key sólo viaja en el header de este curl
# local; nunca se loguea ni se escribe fuera del env 0600 de más abajo.
if command -v curl >/dev/null 2>&1; then
  hc() { curl -sS -o /dev/null -w '%{http_code}' -m 10 -H "Authorization: Bearer $1" "$GEKKO_LLM_URL/models" 2>/dev/null || echo 000; }
  say "probando Provider: GET $GEKKO_LLM_URL/models ..."
  codes="$(hc "$GEKKO_LLM_KEY")"
  [ "$GEKKO_PROVIDER_KEY" != "$GEKKO_LLM_KEY" ] && codes="$codes $(hc "$GEKKO_PROVIDER_KEY")"
  case " $codes " in
    *" 200 "*) say "Provider OK (200) con al menos una key (códigos:$codes)" ;;
    *" 000 "*) err "no se pudo conectar a $GEKKO_LLM_URL (timeout/DNS/VPN). ¿Host y tunnel correctos?"
               read -rp '¿Guardar config igual y continuar? [y/N] ' a; [ "$a" = y ] || exit 1 ;;
    *" 401 "*|*" 403 "*) err "el Provider rechazó la(s) key(s) (códigos:$codes) — verificá endpoint y keys"; exit 1 ;;
    *) err "el Provider respondió (códigos:$codes, esperaba 200); continúo pero verificá el endpoint" ;;
  esac
else
  say "curl ausente: salteo el health-check del Provider (se validará al lanzar pi)"
fi

mkdir -p -- "$cfg_dir" "$repo_root/.gekko-state"
say "Pi $(pi_ver); config dir: $cfg_dir"

# models.json / modealias.json / subagents.json. La key NO se serializa (pi interpola
# ${GEKKO_PROVIDER_KEY} en runtime). Respalda y reescribe sólo si el contenido cambió.
# GEKKO_PROVIDER_KEY va explícita: guardada o tecleada es variable de shell y python3 no la hereda.
GEKKO_LLM_URL="$GEKKO_LLM_URL" GEKKO_MODEL="$model" GEKKO_PROVIDER_KEY="$GEKKO_PROVIDER_KEY" python3 - \
  "$cfg_dir/models.json" "$cfg_dir/modealias.json" "$repo_root/toolbox/models.json" "$cfg_dir/subagents.json" <<'PY'
import json, os, shutil, sys, time
models_path, aliases_path, catalog_path, subagents_path = sys.argv[1:]
url, model = os.environ["GEKKO_LLM_URL"], os.environ["GEKKO_MODEL"]

def load(path, default):
    try:
        with open(path, encoding="utf-8") as f: return json.load(f)
    except FileNotFoundError:
        return default

def write(path, data):
    payload = json.dumps(data, indent=2) + "\n"
    try:
        old = open(path, encoding="utf-8").read()
    except FileNotFoundError:
        old = None
    if old == payload: return
    if old is not None:
        shutil.copy2(path, path + ".bak." + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    with open(path, "w", encoding="utf-8") as f: f.write(payload)
    os.chmod(path, 0o600)

# El catálogo sale de toolbox/models.json (fuente única). Un provider por motor:
# un único provider `provider` (${GEKKO_PROVIDER_KEY}).
CTX_DEFAULT, MAX_DEFAULT = 131072, 24576
CTX_MODEL, MAX_MODEL = 262144, 32768   # modelo por defecto: 256k de contexto, 32k de salida (máximo razonamiento)
def limits(mid): return (CTX_MODEL, MAX_MODEL) if mid == model else (CTX_DEFAULT, MAX_DEFAULT)
toolbox = load(catalog_path, {}).get("providers", {})
# Gekko posee `provider`; cualquier OTRO provider del usuario queda intacto.
models = load(models_path, {"providers": {}})
models.setdefault("providers", {})
for pname, pdef in toolbox.items():
    catalog = []
    for m in pdef.get("models", []):
        if isinstance(m, dict) and m.get("id"):
            e = dict(m); e["contextWindow"], e["maxTokens"] = limits(e["id"]); e.setdefault("input", ["text"])  # pi 1.5.0 requiere input en cada modelo
            catalog.append(e)
    if not any(m["id"] == model for m in catalog):   # el modelo elegido existe en cada provider
        cw, mt = limits(model)
        catalog.append({"id": model, "contextWindow": cw, "maxTokens": mt, "reasoning": True, "input": ["text", "image"]})
    models["providers"][pname] = {
        "baseUrl": url,                 # literal: pi NO interpola baseUrl
        "apiKey": pdef.get("apiKey", "${GEKKO_PROVIDER_KEY}"),  # placeholder, pi lo interpola
        "api": pdef.get("api", "openai-completions"),
        "compat": pdef.get("compat", {"supportsDeveloperRole": False, "supportsReasoningEffort": False}),
        "models": catalog,
    }
write(models_path, models)

# Aliases estables. Los subagentes (modealias/sub-128k) le pegan al mismo provider que la sesión principal.
# El id `sub-128k` se conserva (lo referencian los agentes) aunque ahora la ventana sea 256k.
sub_target = f"provider/{model}"
aliases = [{"id": "sub-128k", "target": sub_target, "contextWindow": CTX_MODEL, "maxTokens": MAX_MODEL, "reasoning": True, "input": ["text", "image"]}]
write(aliases_path, {"aliases": aliases})

# Un subagente a la vez junto al operador, sin anidar, SIEMPRE en foreground (backgroundByDefault=false).
# Merge para no pisar otros toggles.
subagents = load(subagents_path, {})
subagents.update({"maxConcurrent": 1, "maxConcurrentForeground": 1, "maxSubagentDepth": 0, "backgroundByDefault": False})
write(subagents_path, subagents)
PY

# Credenciales en reposo (0600, gitignored). La key es un token del Provider: sin " $ \ ` embebidos.
umask 077
cat > "$env_file" <<ENV
# Gekko Pi profile — gitignored, chmod 600. tools/pi-hitl.sh lo carga solo.
export GEKKO_LLM_URL="$GEKKO_LLM_URL"
export GEKKO_LLM_KEY="$GEKKO_LLM_KEY"
export GEKKO_MODEL="$model"
export GEKKO_PROVIDER="provider"
export GEKKO_PROVIDER_KEY="$GEKKO_PROVIDER_KEY"
ENV
chmod 600 "$env_file"

PI_TELEMETRY=0 pi install npm:@tintinweb/pi-subagents
PI_TELEMETRY=0 pi install git:github.com/GoodDingo/pi-modealias@v0.1.0

python3 -m json.tool "$cfg_dir/models.json" >/dev/null
python3 -m json.tool "$cfg_dir/modealias.json" >/dev/null
say "provider (default provider/$model, ctx 262144, maxTokens 32768), alias sub-128k y subagents.json (1/1/0, foreground) listos"

# scope.txt: allowlist del engagement (gitignored). Lo creamos SIN targets reales (la IP
# de ejemplo queda comentada) para que el archivo exista pero gekko-guard siga fail-closed
# hasta que agregues un host autorizado — no asumimos ningún target por vos.
if [ ! -e "$repo_root/scope.txt" ]; then
  sed 's/^192\.0\.2\.10$/# 192.0.2.10   <- reemplazá por tu target real y descomentá/' \
    "$repo_root/toolbox/scope.txt.example" > "$repo_root/scope.txt"
  say "creado scope.txt (0 targets → fail-closed; editá antes de atacar)"
fi

# ── Herdr integration ──────────────────────────────────────────────────────────
herdr_cfg="$HOME/.config/herdr/config.toml"

# Herdr ausente: ofrecé instalarlo (recomendado). El instalador oficial del TUI
# baja el binario del canal stable (última versión) y crea el comando `herdr` en
# ~/.local/bin — el mismo que usa la integración de abajo.
if ! command -v herdr >/dev/null 2>&1; then
  read -rp '¿Instalar Herdr (multiplexor de sesiones para corridas largas del agente)? [RECOMENDADO] [Y/n] ' herdr_ans
  case "${herdr_ans:-y}" in
    [nN]*) say "Herdr: salteado por el operador" ;;
    *) if command -v curl >/dev/null 2>&1; then
         say "instalando Herdr (latest) con el instalador oficial…"
         curl -fsSL https://herdr.dev/install.sh | sh \
           && say "Herdr instalado" \
           || err "el instalador de Herdr falló; continúo sin integración"
         case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) PATH="$HOME/.local/bin:$PATH" ;; esac
       else
         err "curl ausente: no puedo correr el instalador de Herdr; instalalo a mano (https://herdr.dev)"
       fi ;;
  esac
fi

if command -v herdr >/dev/null 2>&1; then
  say "Herdr $(herdr --version 2>/dev/null | head -1) detectado"

  # Install Pi integration (agent state reporting to Herdr).
  herdr integration install pi 2>/dev/null && say "herdr integration pi instalada" \
    || say "herdr integration pi: ya instalada o no disponible"

  # Config: session picker (prefix+shift+s) and agent-friendly defaults.
  if ! grep -q 'Gekko additions' "$herdr_cfg" 2>/dev/null; then
    mkdir -p "$(dirname "$herdr_cfg")"
    # Append — no sobreescribimos config existente del usuario.
    cat >> "$herdr_cfg" <<'HERDR'

# ── Gekko additions ──
# Picker de sesiones tmux del agente (shell-session.ts). bash -c explicito:
# /bin/sh es dash en Debian/Ubuntu y no soporta `read -p`, lo que cerraba el popup al instante.
[[keys.command]]
key = "prefix+shift+s"
type = "popup"
command = "bash -c 's=$(tmux ls -F \"#{session_name}\" 2>/dev/null | fzf --height=100% --prompt=\"attach (read-only)> \") && exec tmux attach -r -t \"$s\"'"
width = "60%"
height = "50%"
HERDR
    command -v fzf >/dev/null 2>&1 || say "ojo: fzf no instalado — el picker lo necesita (dnf/apt install fzf)"
    say "herdr config: agregado session picker (prefix+shift+s)"
    herdr server reload-config 2>/dev/null && say "herdr config recargada" || true
  else
    say "herdr config: session picker ya presente, skip"
  fi
else
  say "herdr no instalado — salteo integración"
fi

cat <<DONE

Setup listo — plug & play. Para lanzar:
${node_installed:+  IMPORTANTE: se instaló un node nuevo. Reiniciá la shell (terminal nueva) y corré: tmux kill-server
}  ./tools/pi-hitl.sh       # menú de workspace: elegí o creá uno (engagements/<nombre>/, con su scope.txt)
                           # sin terminal: GEKKO_WORKSPACE=<nombre> (o =none para trabajo genérico)

gekko-guard (broker scope/DoS + firewall) se carga solo en pi-hitl.sh y lee scope.txt
(fail-closed: sin un host real en scope.txt, bloquea todo comando con IP).
Logo de marca en el arranque: isotipo pre-renderizado a ANSI (toolbox/gekko-logo.ans,
regenerable con make-logo-ans.py). Se ve en terminal truecolor; si no es TTY, sólo texto.
Dentro de Pi el banner + atajos quedan como header vía toolbox/gekko-banner.ts (pi-hitl.sh
lo carga con -e; sin instalación).
Pi arranca desde la raíz del repo: el roster .pi/agents/ se descubre solo y sus
adaptadores leen los prompts canónicos en .claude/agents/. Dentro de Pi: /agents.
Herdr: prefix+shift+s abre un picker de sesiones tmux del agente.
DONE
