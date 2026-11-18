#!/usr/bin/env bash
# (Re)abre el panel GEKKO como split tmux a la derecha. IDEMPOTENTE: si ya hay un panel
# abierto, no duplica (lo detecta por la opción de pane @gekko_sidebar). Imprime el pane id.
#
#   tools/gekko-sidebar.sh            abre (o reporta el existente) + instala los bindings de mouse
#   tools/gekko-sidebar.sh --fit [W]  lo que corre el hook window-resized: cierra bajo 140 columnas,
#                                     reabre al volver, re-aplica el ancho (W = id de ventana tmux)
#   tools/gekko-sidebar.sh --toggle   si está abierto lo oculta, si no lo abre (lo que hace /gekko-sidebar);
#                                     oculto a mano queda oculto aunque se redimensione la ventana
#   tools/gekko-sidebar.sh --restore  si ya no queda ningún pane @gekko_sidebar, devuelve los bindings
#                                     de mouse a lo que había antes (guardado en @gekko_prev_<tecla>)
#   tools/gekko-sidebar.sh --keys     (antes limpia la marca de las sesiones cuyo lanzador murió) instala los atajos sin prefijo Shift+→/Shift+←/F3/F2 (cambian de ventana
#                                     sólo en la sesión marcada @gekko_pi; en el resto la tecla pasa intacta)
#   tools/gekko-sidebar.sh --keys-restore  los devuelve a lo previo cuando ninguna sesión conserva @gekko_pi
#                                     (@gekko_pi=<pid del lanzador>; antes limpia las marcas de pids muertos)
#   tools/gekko-sidebar.sh --sweep-mirrors [sesión]  cierra las ventanas espejo (@gekko_mirror=<pid>) de la sesión
#                                     (por defecto la actual) cuyo pid ya no vive; nunca las de un pid vivo ni sin marca
#
# Úsalo si cerraste el panel por error:
#   · dentro de pi:  !tools/gekko-sidebar.sh   (o el comando /gekko-sidebar)
# Requiere estar dentro de tmux (tools/pi-hitl.sh crea la sesión si hace falta).
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
[ -n "${TMUX:-}" ] || { echo "gekko-sidebar: hay que estar dentro de tmux (usá tools/pi-hitl.sh)" >&2; exit 1; }

MIN_COLS=140   # único lugar con el corte: bajo esto el estado vive en la barra del guard (AC10)
KEYS=(MouseDown1Pane DoubleClick1Pane TripleClick1Pane)
NAV_KEYS=(S-Right S-Left F3 F2)
UNBOUND='__unbound__'
mode="${1:-open}"

restore_bindings() {
  local k prev
  for k in "$@"; do
    prev="$(tmux show -gqv "@gekko_prev_$k" 2>/dev/null || true)"
    [ -n "$prev" ] || continue
    if [ "$prev" = "$UNBOUND" ]; then tmux unbind-key -T root "$k" 2>/dev/null || true
    else tmux bind-key -T root "$k" "$prev"; fi
    tmux set -gu "@gekko_prev_$k"
  done
}

# install_bindings <función de gekko-panel.ts que genera el argv> <tecla>...
install_bindings() {
  local generator="$1" k line prev
  shift
  for k in "$@"; do
    # `\;` de list-keys pasa a `;` (dentro de un string de if-shell `\;` no separa comandos)
    # solo se guarda la primera vez: reinstalar nunca envuelve nuestro propio binding
    if [ -z "$(tmux show -gqv "@gekko_prev_$k" 2>/dev/null)" ]; then
      line="$(tmux list-keys -T root "$k" 2>/dev/null | head -n1 || true)"
      if [ -n "$line" ]; then prev="$(printf '%s' "$line" | sed "s/^bind-key \(-[nr] \)*-T root $k //;s/ \\\\; / ; /g")"; else prev="$UNBOUND"; fi
      tmux set -g "@gekko_prev_$k" "$prev"
    fi
  done
  # los bindings los genera el generador puro (sidebarBindings/navBindings: misma fuente que el selftest); prev viaja por env
  GEKKO_PREV_JSON="$(for k in "$@"; do printf '%s\t%s\n' "$k" "$(tmux show -gqv "@gekko_prev_$k")"; done)" \
  GEKKO_BINDINGS_FN="$generator" \
  node --no-warnings --experimental-strip-types --input-type=module -e '
    const panel = await import(process.argv[1]);
    import { execFileSync } from "node:child_process";
    const prev = {};
    for (const l of (process.env.GEKKO_PREV_JSON ?? "").split("\n")) {
      const i = l.indexOf("\t"); const v = l.slice(i + 1);
      if (i > 0 && v && v !== "__unbound__") prev[l.slice(0, i)] = v;
    }
    for (const a of panel[process.env.GEKKO_BINDINGS_FN](prev)) execFileSync("tmux", a, { stdio: "inherit" });
  ' "$repo_root/toolbox/gekko-panel.ts"
}

# quita @gekko_pi de las sesiones cuyo lanzador murió sin desmarcar (SIGKILL, terminal caída); staleMirrors decide
clear_dead_pi_marks() {
  tmux list-sessions -F "#{session_id}$(printf '\t')#{@gekko_pi}" | node --no-warnings --experimental-strip-types --input-type=module -e '
    import { execFileSync } from "node:child_process";
    import { readFileSync } from "node:fs";
    const { staleMirrors } = await import(process.argv[1]);
    const sessions = readFileSync(0, "utf8").split("\n").filter(Boolean).map((l) => {
      const [windowId, mark = ""] = l.split("\t"); return { windowId, mark };
    });
    const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === "EPERM"; } };
    for (const id of staleMirrors(sessions, alive)) execFileSync("tmux", ["set-option", "-u", "-t", id, "@gekko_pi"], { stdio: "inherit" });
  ' "$repo_root/toolbox/gekko-panel.ts"
}

if [ "$mode" = "--restore" ]; then
  # mientras quede un sidebar vivo en el servidor, los bindings siguen siendo necesarios
  if tmux list-panes -a -F '#{@gekko_sidebar}' 2>/dev/null | grep -qx 1; then exit 0; fi
  restore_bindings "${KEYS[@]}"
  exit 0
fi
if [ "$mode" = "--keys-restore" ]; then
  trap 'rc=$?; [ "$rc" -eq 0 ] || echo "gekko-sidebar: $mode falló (código $rc)" >&2' EXIT
  clear_dead_pi_marks || echo "gekko-sidebar: no se pudieron limpiar marcas @gekko_pi muertas" >&2
  # mientras quede una sesión marcada en el servidor, los atajos siguen siendo necesarios
  if tmux list-sessions -F '#{@gekko_pi}' 2>/dev/null | grep -q .; then exit 0; fi
  restore_bindings "${NAV_KEYS[@]}"
  exit 0
fi

command -v node >/dev/null 2>&1 || { echo "gekko-sidebar: falta node" >&2; exit 1; }
# el rail importa gekko-panel.ts directo. El node de Debian/Kali se compila SIN soporte TypeScript
# (ERR_NO_TYPESCRIPT aunque la versión alcance), y uno < 22.18 no lo trae activo: se mide la capacidad.
case "$(node -p 'process.features.typescript' 2>/dev/null)" in strip|transform) ;; *)
  echo "gekko-sidebar: este node ($(node --version)) no ejecuta TypeScript (típico del paquete de Debian/Kali)." >&2
  echo "               Instalá el oficial: nvm install 22  (o nodejs.org). Después REINICIÁ LA SHELL" >&2
  echo "               (terminal nueva) y cerrá tmux (tmux kill-server): si no, sigue viendo el node viejo." >&2
  exit 1 ;;
esac
if [ "$mode" = "--keys" ]; then
  trap 'rc=$?; [ "$rc" -eq 0 ] || echo "gekko-sidebar: $mode falló (código $rc)" >&2' EXIT
  clear_dead_pi_marks || echo "gekko-sidebar: no se pudieron limpiar marcas @gekko_pi muertas" >&2
  install_bindings navBindings "${NAV_KEYS[@]}"
  exit 0
fi
if [ "$mode" = "--sweep-mirrors" ]; then
  trap 'rc=$?; [ "$rc" -eq 0 ] || echo "gekko-sidebar: $mode falló (código $rc)" >&2' EXIT
  target="${2:-$(tmux display-message -p '#{session_name}')}"
  # staleMirrors decide (pid muerto = marca numérica sin proceso); EPERM = el proceso existe, es de otro usuario
  tmux list-windows -t "=$target" -F "#{window_id}$(printf '\t')#{@gekko_mirror}" | node --no-warnings --experimental-strip-types --input-type=module -e '
    import { execFileSync } from "node:child_process";
    import { readFileSync } from "node:fs";
    const { staleMirrors } = await import(process.argv[1]);
    const windows = readFileSync(0, "utf8").split("\n").filter(Boolean).map((l) => {
      const [windowId, mark = ""] = l.split("\t"); return { windowId, mark };
    });
    const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === "EPERM"; } };
    for (const id of staleMirrors(windows, alive)) execFileSync("tmux", ["kill-window", "-t", id], { stdio: "inherit" });
  ' "$repo_root/toolbox/gekko-panel.ts"
  exit 0
fi
export GEKKO_PANEL_STATE="${GEKKO_PANEL_STATE:-$repo_root/.gekko-state/panel.json}"
export GEKKO_STALE_MS="${GEKKO_STALE_MS:-}"
win=""; [ "$mode" = "--fit" ] && win="${2:-}"
if [ -n "$win" ]; then
  # desde el hook (run-shell) no hay cliente: la sesión "actual" sería la de más actividad, no la dueña de la ventana
  sess="$(tmux display-message -p -t "$win" '#{session_name}')"
  # buscar-y-abrir en serie por ventana: dos --fit solapados no pueden abrir cada uno su rail
  tmux wait-for -L "gekko-fit-$win"
  trap 'tmux wait-for -U "gekko-fit-$win"' EXIT
else
  sess="$(tmux display-message -p '#{session_name}')"
  win="$(tmux display-message -p '#{window_id}')"
fi
cols="$(tmux display-message -p -t "$win" '#{window_width}')"

# ancho: 25 % de la ventana acotado a 36–48; GEKKO_SIDEBAR_WIDTH ("N%" o columnas) lo pisa sin acotar
want() {
  local w="${GEKKO_SIDEBAR_WIDTH:-}"
  case "$w" in
    "") w=$(( cols * 25 / 100 )); [ "$w" -lt 36 ] && w=36; [ "$w" -gt 48 ] && w=48 ;;
    *%) w=$(( cols * ${w%\%} / 100 )) ;;
  esac
  echo "$w"
}
find_sb() { tmux list-panes -t "$win" -F '#{@gekko_sidebar} #{pane_id}' 2>/dev/null | awk '$1=="1"{print $2; exit}'; }

open_sb() {
  local sb
  sb="$(tmux split-window -h -d -P -F '#{pane_id}' -t "$win" -l "$(want)" \
    "exec env GEKKO_PANEL_STATE='$GEKKO_PANEL_STATE' GEKKO_STALE_MS='$GEKKO_STALE_MS' node '$repo_root/toolbox/gekko-sidebar.mjs'")"
  tmux set -p -t "$sb" '@gekko_sidebar' 1 2>/dev/null || true
  echo "$sb"
}

existing="$(find_sb)"
if [ "$mode" = "--toggle" ] && [ -n "$existing" ]; then
  tmux kill-pane -t "$existing"
  tmux set -w -t "$win" '@gekko_sidebar_hidden' 1   # el hook --fit no lo reabre hasta que el operador lo pida
  echo hidden; exit 0
fi
[ "$mode" = "--fit" ] || tmux set -wu -t "$win" '@gekko_sidebar_hidden' 2>/dev/null || true
if [ "$mode" = "--fit" ]; then
  [ "$(tmux show -wqv -t "$win" '@gekko_sidebar_hidden')" = 1 ] && exit 0
  if [ "$cols" -lt "$MIN_COLS" ]; then [ -z "$existing" ] || tmux kill-pane -t "$existing"
  elif [ -n "$existing" ]; then tmux resize-pane -t "$existing" -x "$(want)"
  else open_sb >/dev/null; fi
  exit 0
fi

# El hook va ANTES de abrir y también si la ventana hoy es angosta: un redimensionado que llegue durante
# el arranque (o agrandar la ventana después) tiene que re-ajustar/abrir el rail. Cierra bajo 140 columnas.
# El hook corre desde el servidor tmux, que NO hereda el entorno de Pi: la ruta del estado viaja en el comando;
# sin ella el rail reabierto leía .gekko-state/panel.json en vez del archivo de este lanzamiento (REQ-WS-009).
tmux set-hook -t "$sess" window-resized "run-shell -b \"GEKKO_PANEL_STATE='$GEKKO_PANEL_STATE' '$repo_root/tools/gekko-sidebar.sh' --fit '#{window_id}'\"" 2>/dev/null || true
if [ "$cols" -lt "$MIN_COLS" ]; then
  echo "gekko-sidebar: ventana de $cols columnas (< $MIN_COLS): el estado va en la barra, no abro el panel" >&2
  exit 0
fi
if [ -n "$existing" ]; then echo "$existing"; exit 0; fi
install_bindings sidebarBindings "${KEYS[@]}"
sb="$(open_sb)"
# el mouse permite arrastrar el borde
[ "${GEKKO_MOUSE:-1}" != "0" ] && tmux set -t "$sess" mouse on 2>/dev/null || true
echo "$sb"
