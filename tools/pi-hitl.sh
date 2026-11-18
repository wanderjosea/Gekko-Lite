#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
state_dir="${GEKKO_WS_ROOT:-$repo_root}/.gekko-state"

# Config de arranque LOCAL y gitignoreada (knobs NO-secretos: URL, provider, model). Se sourcea si
# existe, para que `tools/pi-hitl.sh` corra sin exports manuales. El secreto (GEKKO_LLM_KEY) vive en
# tu shell/~/.bashrc o se deriva del archivo local de clave; NUNCA se commitea. Plantilla:
# tools/pi-hitl.env.example -> copiala a .gekko-state/pi-hitl.env.
env_file="${GEKKO_HITL_ENV:-$state_dir/pi-hitl.env}"
[ -f "$env_file" ] && { set -a; . "$env_file"; set +a; }
# Credenciales guardadas por setup.sh (.gekko-state/env, 0600, gitignored): se cargan solas, sin
# `source` manual, también dentro de la sesión tmux nueva. Solo COMPLETAN lo que falte: lo que ya
# esté exportado (tu shell o pi-hitl.env) gana, así `GEKKO_MODEL=x tools/pi-hitl.sh` sigue andando.
cred_file="${GEKKO_CRED_ENV:-$state_dir/env}"
if [ -f "$cred_file" ]; then _pre="$(export -p)"; set -a; . "$cred_file"; set +a; eval "$_pre"; unset _pre; fi

prompt_file="$repo_root/docs/prompts/pi-hitl.md"
model="${GEKKO_MODEL:?falta GEKKO_MODEL (id del modelo que sirve el Provider) — corré ./setup.sh o exportalo}"
# Provider id registrado en models.json (setup.sh crea `provider`). Override con GEKKO_PROVIDER.
provider="${GEKKO_PROVIDER:-provider}"
# La key del provider de Pi; por defecto la misma GEKKO_LLM_KEY.
export GEKKO_PROVIDER_KEY="${GEKKO_PROVIDER_KEY:-${GEKKO_LLM_KEY:-}}"

# Pi config (providers, models, modealias, extensions) comes from the OPERATOR's own
# Pi config dir — PI_CODING_AGENT_DIR, default ~/.pi/agent — so `pi install` extensions
# and the hand-maintained models.json / modealias.json are actually loaded. The launcher
# does NOT override that dir and does NOT generate or overwrite models.json. Only local
# SESSION state is redirected into the gitignored repo state dir.
session_dir="${GEKKO_PI_SESSION_DIR:-$state_dir/pi-sessions}"

if ! command -v pi >/dev/null 2>&1; then
  echo "error: pi is not installed (see docs/pi-hitl.md)" >&2
  exit 1
fi

if ! command -v tmux >/dev/null 2>&1; then
  echo "error: tmux is required by the shell-session extension (apt install tmux)" >&2
  exit 1
fi

# GEKKO_PROVIDER_KEY stays in the environment: your ~/.pi/agent/models.json uses
# apiKey "$GEKKO_PROVIDER_KEY" and pi interpolates it at request time (never written).
# NOTE: pi does NOT interpolate baseUrl — it must be a LITERAL URL in models.json.
: "${GEKKO_LLM_URL:?falta GEKKO_LLM_URL — corré ./setup.sh una vez (lo guarda en .gekko-state/env) o exportalo}"
: "${GEKKO_LLM_KEY:?falta GEKKO_LLM_KEY — corré ./setup.sh una vez (lo guarda en .gekko-state/env) o exportalo}"

# Catch the common mistake early — otherwise pi fails at request time with an opaque
# "url invalid": pi does not interpolate ${...} in baseUrl, only in apiKey/headers.
cfg_dir="${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"
if [ -f "$cfg_dir/models.json" ] && grep -qE '"baseUrl":[[:space:]]*"\$' "$cfg_dir/models.json"; then
  echo "error: $cfg_dir/models.json has a non-literal baseUrl (pi does not interpolate \$... there)." >&2
  echo "       Set baseUrl to the literal URL (the value of \$GEKKO_LLM_URL);" >&2
  echo "       apiKey CAN stay \"\$GEKKO_PROVIDER_KEY\". See docs/pi-hitl.md." >&2
  exit 1
fi

# Validate the launch model dynamically against what is registered in models.json —
# no hardcoded allowlist, so a newly added model works once it is in models.json.
# (Change the parent model inside pi with /model; subagents follow the sub-128k alias.)
if [ -f "$cfg_dir/models.json" ] && command -v python3 >/dev/null 2>&1; then
  if ! python3 -c "import json,sys;d=json.load(open('$cfg_dir/models.json'));ids=[m['id'] for p in d['providers'].values() for m in p['models']];sys.exit(0 if '$model' in ids else 1)" 2>/dev/null; then
    echo "error: model '$model' no está registrado en $cfg_dir/models.json." >&2
    echo "       Agregalo a models.json o elegí uno existente (GEKKO_MODEL)." >&2
    exit 1
  fi
fi

# Workspace (spec 010): sin workspace no arranca Pi. Se resuelve ANTES del relanzamiento en tmux para que el
# menú salga en la terminal del operador. Sin terminal interactiva hay que dar GEKKO_WORKSPACE=<nombre>|none.
# El CLI corre TypeScript: se mide la capacidad del node (el de Debian/Kali suele venir sin ella).
case "$(node -p 'process.features.typescript' 2>/dev/null)" in strip|transform) ;; *)
  echo "error: pi-hitl necesita un node que ejecute TypeScript (el actual: $(node --version 2>/dev/null || echo 'ausente'))." >&2
  echo "       Instalá el oficial: nvm install 22  (o nodejs.org). Después REINICIÁ LA SHELL (terminal nueva)" >&2
  echo "       y cerrá tmux (tmux kill-server): si no, sigue viendo el node viejo." >&2
  exit 1 ;;
esac
ws_cli() { node --no-warnings --experimental-strip-types "$repo_root/toolbox/gekko-workspace.ts" "$@"; }

ws="${GEKKO_WORKSPACE:-}"
if [ -z "$ws" ]; then
  if [ -t 0 ] && [ -t 2 ]; then
    ws="$(ws_cli pick)" || { echo "error: no se eligió workspace; Pi no arranca." >&2; exit 1; }
  else
    echo "error: falta GEKKO_WORKSPACE y no hay terminal interactiva para el menú." >&2
    echo "       Exportá GEKKO_WORKSPACE=<nombre> (un workspace de engagements/) o GEKKO_WORKSPACE=none" >&2
    echo "       (escape explícito: trabajo genérico, sin scope ni hallazgos de un engagement)." >&2
    exit 1
  fi
fi
ws_dir=""
if [ "$ws" != "none" ]; then
  ws_dir="$(ws_cli check "$ws")" || { echo "error: workspace '$ws' inválido (GEKKO_WORKSPACE); no se crea en silencio. Pi no arranca." >&2; exit 1; }
fi

# Fuera de tmux el panel lateral no puede existir: nos relanzamos dentro de una sesión nueva (lo que
# prepara la sesión del operador). Solo con terminal interactiva; GEKKO_SIDEBAR=0 lo evita.
# shortcut: si ya hay un server tmux, la sesión nueva hereda SU entorno, no el de este shell — un
# export hecho después de arrancarlo no llega. Lo guardado por setup.sh sí (se relee adentro).
if [ -z "${TMUX:-}" ] && [ "${GEKKO_SIDEBAR:-1}" != "0" ] && [ -t 0 ] && [ -t 1 ]; then
  # si el launcher falla adentro, tmux cerraría la sesión al instante y el error no se vería: se espera un Enter
  # `env -u`: el servidor tmux no debe capturar el workspace en su entorno (lo heredaría otra ventana);
  # el nombre viaja explícito al launcher interno.
  exec env -u GEKKO_WORKSPACE -u GEKKO_WORKSPACE_DIR tmux new-session env GEKKO_HITL_ENV="$env_file" GEKKO_WORKSPACE="$ws" sh -c \
    '"$@" && exit 0; rc=$?; printf "\n[pi-hitl] el launcher terminó con error %s dentro de tmux (motivo arriba). Enter para cerrar. " "$rc"; read -r _; exit "$rc"' \
    sh "$repo_root/tools/pi-hitl.sh" "$@"
fi

GEKKO_EXEC="$(ws_cli mode "$ws")" || exit 1
export GEKKO_EXEC
unset GEKKO_TOOLBOX
toolbox_name="gekko-tb-$ws"
if [ "$GEKKO_EXEC" = "toolbox" ]; then
  # El contenedor enmascara .pi-sessions con un tmpfs: el directorio tiene que existir ANTES, o dockerd lo crea de root.
  mkdir -p -- "$ws_dir/.pi-sessions"
  chmod 700 -- "$ws_dir/.pi-sessions"
  # GEKKO_TOOLBOX es el ID del contenedor ya validado: un contenedor reemplazado bajo Pi hace fallar cada `docker exec`.
  GEKKO_TOOLBOX="$(ws_cli toolbox "$ws")" || exit 1
  export GEKKO_TOOLBOX
  export GEKKO_TMUX_DIR="$ws_dir/.gekko-sockets"
fi

# Aviso de salida (REQ-WS-012): lo decide `docker inspect` al salir, no el modo del lanzamiento (con Pi abierto se
# puede levantar el contenedor). Sin docker, sin workspace o con docker colgado no imprime nada y no se queda esperando.
notify_running_toolbox() {
  [ "$ws" != "none" ] && command -v docker >/dev/null 2>&1 || return 0
  [ "$(timeout 5 docker inspect --type container --format '{{.State.Running}}' "$toolbox_name" 2>/dev/null)" = true ] || return 0
  echo "[pi-hitl] contenedor activo: $toolbox_name; apagar: docker rm -f $toolbox_name" >&2
}

# Derivación desde el workspace: lo que traiga el entorno para scope/hallazgos se pisa (y se avisa en el banner).
env_warnings=()
if [ "$ws" != "none" ]; then
  [ -z "${GEKKO_SCOPE:-}" ] || [ "$GEKKO_SCOPE" = "$ws_dir/scope.txt" ] || env_warnings+=("GEKKO_SCOPE del entorno ($GEKKO_SCOPE) pisado por el workspace")
  [ -z "${GEKKO_FINDINGS:-}" ] || [ "$GEKKO_FINDINGS" = "$ws_dir/findings.jsonl" ] || env_warnings+=("GEKKO_FINDINGS del entorno ($GEKKO_FINDINGS) pisado por el workspace")
  export GEKKO_WORKSPACE="$ws"
  export GEKKO_WORKSPACE_DIR="$ws_dir"
  export GEKKO_SCOPE="$ws_dir/scope.txt"
  export GEKKO_FINDINGS="$ws_dir/findings.jsonl"
  session_dir="$ws_dir/.pi-sessions"
  ws_cli touch "$ws"
else
  export GEKKO_WORKSPACE="none"
  unset GEKKO_WORKSPACE_DIR
fi

# Módulo de reportes: un ensure fallido sólo avisa. La URL heredada se descarta siempre: sólo vale la que confirma ensure.
unset GEKKO_REPORT_URL
if [ "$ws" != "none" ] && [ "${GEKKO_REPORT:-1}" != "0" ]; then
  report_out="$(python3 "$repo_root/.claude/tools/findings_web.py" ensure 2>&1)" && report_ok=1 || report_ok=0
  if [ "$report_ok" = 1 ] && [[ "$report_out" =~ ^http://127\.0\.0\.1:[0-9]+/$ ]]; then
    export GEKKO_REPORT_URL="$report_out"
  else
    env_warnings+=("módulo de reportes no disponible: ${report_out:-ensure no devolvió una URL}")
  fi
fi

mkdir -p -- "$session_dir"
chmod 700 -- "$session_dir"

# Do NOT set PI_CODING_AGENT_DIR: let pi use its default (~/.pi/agent of the launching
# user), which is where the operator installed extensions and wrote models.json/modealias.
export PI_CODING_AGENT_SESSION_DIR="$session_dir"
export PI_TELEMETRY=0
export PI_SKIP_VERSION_CHECK=1

# gekko-guard: broker (scope/DoS) + firewall en cada tool-call, in-process e
# independiente del modelo. scope.txt = allowlist de targets del engagement (fail-closed).
export GEKKO_SCOPE="${GEKKO_SCOPE:-$repo_root/scope.txt}"
if [ "$ws" != "none" ]; then mapfile -t scope_entries < <(ws_cli scope "$ws")
else mapfile -t scope_entries < <(grep -vE '^[[:space:]]*(#|$)' "$GEKKO_SCOPE" 2>/dev/null | sed -E 's/[[:space:]]*#.*$//' || true); fi
scope_n="${#scope_entries[@]}"

# Prompt del modelo = base + bloque de workspace (ruta real, o "sin workspace"). Un archivo POR workspace:
# dos lanzamientos simultáneos de engagements distintos no se pisan el prompt (ni el banner ni el panel, abajo).
generated_prompt="$state_dir/pi-hitl.prompt.$ws.md"
mkdir -p -- "${generated_prompt%/*}"
{ cat -- "$prompt_file"; echo; ws_cli prompt "$ws" "$GEKKO_EXEC"; } > "$generated_prompt" \
  || { echo "error: no pude generar $generated_prompt (prompt base + bloque de workspace)." >&2; exit 1; }

# Banner estilo neofetch: logo Gekko (izq) + estado de la sesión (der). A stderr, para no
# ensuciar stdout si pi corre no-interactivo con `-- <cmd>`. Color sólo si stderr es TTY.
banner() {
  local r='' bold='' line
  if [ -t 2 ]; then r=$'\033[0m'; bold=$'\033[1m'; fi
  local pv br sess scope_desc ws_desc warning
  pv="$(pi --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  br="$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '-')"
  sess="${session_dir/#$HOME/\~}"
  if [ "$scope_n" -gt 0 ]; then
    scope_desc="$(IFS=,; echo "${scope_entries[*]:0:6}" | sed 's/,/, /g')"
    [ "$scope_n" -le 6 ] || scope_desc+=" +$((scope_n - 6)) más"
  else scope_desc="0 host → FAIL-CLOSED (editá scope.txt)"; fi
  if [ "$ws" = "none" ]; then ws_desc="ninguno (GEKKO_WORKSPACE=none)"; else ws_desc="$ws"; fi
  local I=(
    "${bold}GEKKO${r}  ·  AI Red-Team  ·  modo HITL (humano en el loop)"
    "model     ${model}"
    "provider  ${provider} · ${GEKKO_LLM_URL}"
    "workspace ${ws_desc}"
    "shells    ${GEKKO_EXEC} (al lanzar) ${GEKKO_TOOLBOX:+$toolbox_name}"
    "scope     ${scope_desc}"
    "guard     ON · broker (scope/DoS) + firewall (output cercado)"
    "session   ${sess}"
    "runtime   pi ${pv:-?} · ${br}"
  )
  [ -z "${GEKKO_REPORT_URL:-}" ] || I+=("reportes  ${GEKKO_REPORT_URL}w/${ws}/")
  for warning in "${env_warnings[@]}"; do I+=("aviso     ${warning}"); done
  # Isotipo de marca pre-renderizado a ANSI half-block (toolbox/gekko-logo.ans, generado
  # por make-logo-ans.py). Truecolor + alpha → se funde con el fondo. Sin deps externas.
  printf '\n'
  local logo_ans="$repo_root/toolbox/gekko-logo.ans"
  if [ -t 2 ] && [ -f "$logo_ans" ]; then
    while IFS= read -r line; do printf '  %s\n' "$line"; done < "$logo_ans"
    printf '\n'
  fi
  for line in "${I[@]}"; do printf '  %s\n' "$line"; done
  printf '\n'
}
# pi abre el alternate screen y tapa lo impreso antes → el banner también va a un archivo
# que toolbox/gekko-banner.ts pinta como header dentro de la TUI.
export GEKKO_BANNER_FILE="$state_dir/banner.$ws.ans"
mkdir -p -- "${GEKKO_BANNER_FILE%/*}"
{
  banner
  [ "$scope_n" -gt 0 ] 2>/dev/null || \
    echo "[pi-hitl] WARN sin targets en $GEKKO_SCOPE → gekko-guard bloquea todo comando con IP."
} > "$GEKKO_BANNER_FILE"
cat -- "$GEKKO_BANNER_FILE" >&2

cd -- "$repo_root"

pi_cmd=(pi
  --provider "$provider"
  --model "$model"
  -e "$repo_root/toolbox/shell-session.ts"
  -e "$repo_root/toolbox/gekko-guard.ts"
  -e "$repo_root/toolbox/gekko-banner.ts"
  --append-system-prompt "$generated_prompt"
  -- "$@")

# Panel GEKKO fijo a la derecha (split tmux angosto, SOLO-LECTURA). Activo dentro de tmux salvo
# GEKKO_SIDEBAR=0. El guard escribe su estado en GEKKO_PANEL_STATE y el renderer lo pinta en vivo;
# lo interactivo (tildar/cambiar modo) sigue en el overlay dentro de pi (/gekko-policy · Alt+P).
sidebar="${GEKKO_SIDEBAR:-1}"
# El estado del panel es de ESTE lanzamiento (REQ-WS-009): dos Pi vivos sobre el mismo workspace publicaban en
# el mismo archivo y el rail de uno mostraba el modo y las shells del otro. `$$` vive lo que dura Pi en las dos
# rutas de abajo: con `exec` Pi hereda el pid, y dentro de tmux el lanzador espera a su hijo. Lo que dejó un lanzamiento muerto se borra acá (el pid va al final del nombre).
for stale in "$state_dir"/panel.*.json; do
  pid="${stale%.json}"; pid="${pid##*.}"
  case "$pid" in ''|*[!0-9]*) continue ;; esac
  kill -0 "$pid" 2>/dev/null || rm -f -- "$stale" "$stale.alive" "$stale.tmp"
done
if [ "$ws" = "none" ]; then panel_default="$state_dir/panel.$$.json"; else panel_default="$state_dir/panel.$ws.$$.json"; fi
export GEKKO_PANEL_STATE="${GEKKO_PANEL_STATE:-$panel_default}"
# ancho del sidebar: lo calcula gekko-sidebar.sh (25 %, 36-48 cols); GEKKO_SIDEBAR_WIDTH solo si el operador lo pisa
# pi usa teclas con modificador (Shift/Alt+Enter); sin extended-keys tmux no las pasa y pi avisa.
# Lo prendemos para el server de esta sesión (lo que recomienda la advertencia de pi), sin tocar tu
# ~/.tmux.conf. Independiente del sidebar. Opt-out: GEKKO_TMUX_KEYS=0.
if [ -n "${TMUX:-}" ] && [ "${GEKKO_TMUX_KEYS:-1}" != "0" ] && command -v tmux >/dev/null 2>&1; then
  tmux set -g extended-keys on 2>/dev/null || true
fi
tmux_ok=0
[ -n "${TMUX:-}" ] && command -v tmux >/dev/null 2>&1 && tmux_ok=1
sidebar_on=0
[ "$sidebar" != "0" ] && [ "$tmux_ok" = 1 ] && command -v node >/dev/null 2>&1 && sidebar_on=1
if [ "$tmux_ok" = 1 ]; then
  # Limpieza posterior a Pi, idempotente y desde una trampa: corre en la salida normal y también si cierran la sesión
  # tmux o el lanzador recibe HUP/TERM/INT (T13). Sin terminal escribir falla, así que se silencia todo y no corta con -e.
  # bash difiere la señal hasta que vuelve Pi: mientras Pi vive, la marca y los atajos siguen puestos.
  cleaned_up=0
  cleanup_after_pi() {
    [ "$cleaned_up" = 1 ] && return
    cleaned_up=1
    set +e
    notify_running_toolbox
    exec >/dev/null 2>&1
    if [ "$sidebar_on" = 1 ] && [ -n "${sess:-}" ]; then
      tmux set-hook -u -t "$sess" window-resized
      [ -n "${mouse_prev:-}" ] && tmux set -t "$sess" mouse "$mouse_prev"
      # restaurar el tema previo (si estaba heredado del global, -u lo desata)
      if [ "${GEKKO_TMUX_THEME:-1}" != "0" ]; then
        { [ -n "${style_prev:-}" ] && tmux set -t "$sess" status-style "$style_prev"; } || tmux set -u -t "$sess" status-style
        { [ -n "${pab_prev:-}" ] && tmux set -t "$sess" pane-active-border-style "$pab_prev"; } || tmux set -u -t "$sess" pane-active-border-style
        { [ -n "${pbd_prev:-}" ] && tmux set -t "$sess" pane-border-style "$pbd_prev"; } || tmux set -u -t "$sess" pane-border-style
      fi
      # cerrar cualquier panel GEKKO (el inicial o uno reabierto a mano, marcado @gekko_sidebar)
      for p in $(tmux list-panes -s -t "$sess" -F '#{@gekko_sidebar} #{pane_id}' | awk '$1=="1"{print $2}'); do
        tmux kill-pane -t "$p"
      done
      # devolver los bindings de mouse previos (no hace nada si queda otro sidebar en el servidor)
      "$repo_root/tools/gekko-sidebar.sh" --restore
    fi
    if [ -n "${sess:-}" ]; then
      # ventanas espejo de un Pi muerto (REQ-TMUX-014), quitar la marca y devolver los atajos del operador (REQ-TUI-025);
      # los atajos son del servidor: se devuelven aunque la sesión ya no exista
      "$repo_root/tools/gekko-sidebar.sh" --sweep-mirrors "$sess"
      tmux set-option -u -t "$sess" @gekko_pi
      "$repo_root/tools/gekko-sidebar.sh" --keys-restore
    fi
  }
  trap cleanup_after_pi EXIT
  trap 'exit 129' HUP
  trap 'exit 143' TERM
  trap 'exit 130' INT
  sess="$(tmux display-message -p '#{session_name}' 2>/dev/null || true)"
  # Atajos Shift+→/Shift+←/F3/F2 (REQ-TUI-025): sólo actúan en la sesión marcada @gekko_pi=<pid de este lanzador>. Si marcar o instalar falla,
  # Pi arranca igual (sin atajos).
  if [ -n "${sess:-}" ] && tmux set-option -t "$sess" @gekko_pi "$$" 2>/dev/null; then
    "$repo_root/tools/gekko-sidebar.sh" --keys || true
  fi
  if [ "$sidebar_on" = 1 ]; then
    rm -f "$GEKKO_PANEL_STATE" "${GEKKO_PANEL_STATE%.json}.ui.json" 2>/dev/null || true   # D12: estado y plegado frescos
    # El script pone mouse on (arrastre del borde); guardamos el valor previo para restaurarlo al salir.
    mouse_prev=""
    [ "${GEKKO_MOUSE:-1}" != "0" ] && [ -n "${sess:-}" ] && mouse_prev="$(tmux show -t "$sess" -v mouse 2>/dev/null || echo off)"
    # Tema azul GEKKO SOLO para esta sesión de pi (barra de estado + bordes de pane). Tu ~/.tmux.conf
    # global queda intacto; se guarda el valor previo y se restaura al salir. Opt-out: GEKKO_TMUX_THEME=0.
    style_prev=""; pab_prev=""; pbd_prev=""
    if [ -n "${sess:-}" ] && [ "${GEKKO_TMUX_THEME:-1}" != "0" ]; then
      style_prev="$(tmux show -t "$sess" -v status-style 2>/dev/null || true)"
      pab_prev="$(tmux show -t "$sess" -v pane-active-border-style 2>/dev/null || true)"
      pbd_prev="$(tmux show -t "$sess" -v pane-border-style 2>/dev/null || true)"
      tmux set -t "$sess" status-style 'bg=colour24,fg=colour231' 2>/dev/null || true
      tmux set -t "$sess" pane-active-border-style 'fg=colour75' 2>/dev/null || true
      tmux set -t "$sess" pane-border-style 'fg=colour238' 2>/dev/null || true
    fi
    # Abre el panel con el MISMO script que /gekko-sidebar usa para reabrirlo si lo cerrás por error
    # (responsivo + hook de re-ajuste + mouse, todo adentro; idempotente).
    "$repo_root/tools/gekko-sidebar.sh" >/dev/null || echo "[pi-hitl] aviso: el panel lateral no abrió (motivo arriba); el estado queda en la barra." >&2
  fi
  set +e; "${pi_cmd[@]}"; rc=$?; set -e
  exit "$rc"
fi
# Sin `exec`: tras Pi tiene que poder correr el aviso de salida, y el código de Pi se conserva.
trap notify_running_toolbox EXIT
set +e; "${pi_cmd[@]}"; rc=$?; set -e
exit "$rc"
