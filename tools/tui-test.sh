#!/usr/bin/env bash
# Pruebas de proceso (P) de la spec 008: sidebar real dentro de tmux anidado, sockets dedicados.
# Uso:  bash tools/tui-test.sh            # checks deterministas (sin modelo ni red)
#       bash tools/tui-test.sh --live     # + smoke en vivo (opt-in): GEKKO_LLM_URL, GEKKO_LLM_KEY, GEKKO_LIVE_MODEL por entorno
# Sale 0 solo si todo pasa; una línea FAIL por check fallido y "N passed, M failed" al final.
set -uo pipefail
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
command -v tmux >/dev/null && command -v node >/dev/null || { echo "tui-test: faltan tmux y/o node" >&2; exit 2; }
LIVE=0; [ "${1:-}" = "--live" ] && LIVE=1

W="$(mktemp -d)"; IN="gekko-tui-test-$$-in"; OUT="gekko-tui-test-$$-out"; NEG="gekko-tui-test-$$-neg"
TWO="gekko-tui-test-$$-two"; CLI="gekko-tui-test-$$-cli"
cleanup() {
  for s in "$IN" "$OUT" "$NEG" "$TWO" "$CLI" "gekko-tui-test-$$-live"; do tmux -L "$s" kill-server 2>/dev/null; rm -f "/tmp/tmux-$(id -u)/$s" 2>/dev/null; done
  rm -rf "$W"
}
trap cleanup EXIT
PASS=0; FAIL=0
check() { # check "nombre" "expr"  (expr evaluada con eval)
  local name="$1" expr="$2"
  if eval "$expr" >/dev/null 2>&1; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL: $name"; fi
}
poll() { local n=100; while [ $n -gt 0 ]; do eval "$1" >/dev/null 2>&1 && return 0; sleep 0.1; n=$((n-1)); done; return 1; } # hasta 10 s

pcheck() { check "$1" "poll '${2//\'/\'\\\'\'}'"; } # como check, pero sondea hasta 10 s
# --- entorno del sidebar (el servidor interno lo hereda) ---
export GEKKO_PANEL_STATE="$W/panel.json" GEKKO_SCOPE="$W/scope.txt" GEKKO_STALE_MS=600000 GEKKO_SIDEBAR_POLL_MS=100
UI="$W/panel.ui.json"
printf '192.0.2.5\n' > "$W/scope.txt"

# genera panel.json fresco; $1 = noColor(0|1), $2 = SGR para todos los roles ("" = sin roles)
gen_state() {
  NOCOLOR="$1" ROLE="${2:-}" node --experimental-strip-types --input-type=module -e '
    import { buildPanelState, newRuntime } from "'"$REPO"'/toolbox/gekko-panel.ts";
    import { writeFileSync, renameSync } from "node:fs";
    const s = buildPanelState(newRuntime(Date.now()), {}, Date.now());
    s.theme.noColor = process.env.NOCOLOR === "1";
    const r = process.env.ROLE; if (r) for (const k of ["accent","ok","warn","danger","dim","border"]) s.theme.roles[k] = r;
    const p = process.env.GEKKO_PANEL_STATE; writeFileSync(p + ".tmp", JSON.stringify(s)); renameSync(p + ".tmp", p);' 2>/dev/null
}

# --- helpers tmux ---
t() { tmux -L "$IN" "$@"; }
sb_pane() { t list-panes -s -t in -F '#{pane_id} #{?@gekko_sidebar,1,0}' 2>/dev/null | awk '$2=="1"{print $1; exit}'; }
main_pane() { t list-panes -s -t in -F '#{pane_id} #{?@gekko_sidebar,1,0}' 2>/dev/null | awk '$2!="1"{print $1; exit}'; }
cap() { t capture-pane -p -t "$(sb_pane)" 2>/dev/null; }
cap_e() { t capture-pane -p -e -t "$(sb_pane)" 2>/dev/null; }
active() { t display-message -p -t "$1" '#{pane_active}' 2>/dev/null; }
click() { # click X Y ABS 1-based del cliente
  tmux -L "$OUT" send-keys -t out -l $'\e[<0;'"$1;$2"$'M'; sleep 0.03
  tmux -L "$OUT" send-keys -t out -l $'\e[<0;'"$1;$2"$'m'; sleep "${3:-0.05}"
}
header_row() { cap | awk -v n="$1" '$0 ~ /^[▾▸]/ && index($0,n){print NR; exit}'; } # fila 1-based dentro del pane
click_header() { # click_header NOMBRE [pausa]
  local sb row left; sb="$(sb_pane)"; row="$(header_row "$1")"; [ -n "$row" ] || return 1
  left="$(t display-message -p -t "$sb" '#{pane_left}')"
  click $((left + 3)) "$row" "${2:-0.05}"   # tmux 0-based pane_left -> x abs = left+1; +2 dentro del pane
}
start_stack() { # abre inner+outer y lanza el sidebar con sidebar.sh
  tmux -L "$IN" kill-server 2>/dev/null; tmux -L "$OUT" kill-server 2>/dev/null
  tmux -L "$IN" -f /dev/null new-session -d -s in -x 180 -y 50 "bash --norc"
  tmux -L "$IN" set -g mouse on
  tmux -L "$IN" run-shell "$REPO/tools/gekko-sidebar.sh" >/dev/null
  tmux -L "$OUT" -f /dev/null new-session -d -s out -x 180 -y 51 "env -u TMUX tmux -L $IN attach -t in"
}

# ============ preparación ============
gen_state 0 ""
t_before_keys() { t list-keys -T root | grep -E ' (MouseDown1Pane|DoubleClick1Pane|TripleClick1Pane) ' | sort; }
tmux -L "$IN" -f /dev/null new-session -d -s in -x 180 -y 50 "bash --norc"; tmux -L "$IN" set -g mouse on
KEYS_BEFORE="$(t_before_keys)"
tmux -L "$IN" kill-server 2>/dev/null
start_stack

# --- AC6/AC10 base: el sidebar abre a 180 columnas ---
pcheck "AC10: sidebar abierto a 180 columnas" '[ -n "$(sb_pane)" ]'
SB="$(sb_pane)"; MAIN="$(main_pane)"
pcheck "AC1: el rail dibuja las cards desde panel.json" 'cap | grep -q "▾ GUARD"'
pcheck "AC6: el pane del rail pide mouse SGR-1006" '[ "$(t display-message -p -t "$SB" "#{mouse_sgr_flag}")" = 1 ]'

# --- AC6: click real en el encabezado colapsa y no roba el foco ---
t select-pane -t "$MAIN"
click_header SCOPE 0.2
pcheck "AC6: click en encabezado colapsa la card (▸ SCOPE)" 'cap | grep -q "^▸.*SCOPE"'
check "AC6: el foco sigue en el pane de Pi tras el click" '[ "$(active "$MAIN")" = 1 ]'
fast_ok=1
for i in 1 2 3 4 5 6 7 8 9 10; do click_header GUARD 0.02; [ "$(active "$MAIN")" = 1 ] || fast_ok=0; done
check "AC6: 10 clicks rápidos (<500 ms) sin robar foco" '[ "$fast_ok" = 1 ]'
# click en cuerpo no cambia nada
before="$(cap)"; click $(( $(t display-message -p -t "$SB" '#{pane_left}') + 3 )) 48 0.2
check "AC4: click fuera de un encabezado no cambia el rail" '[ "$(cap)" = "$before" ]'
# doble click en pane normal: sigue funcionando como antes (foco al pane clicado)
t select-pane -t "$SB"
click 10 5 0.02; click 10 5 0.02
pcheck "AC6: click/doble click en pane normal enfoca ese pane" '[ "$(active "$MAIN")" = 1 ]'

# --- AC6 control negativo: sin los bindings el click rápido SÍ roba el foco (el test mide) ---
tmux -L "$NEG" -f /dev/null new-session -d -s n -x 120 -y 30 "bash --norc"; tmux -L "$NEG" set -g mouse on
NSB="$(tmux -L "$NEG" split-window -h -d -P -F '#{pane_id}' -l 40 "exec env GEKKO_PANEL_STATE=$W/panel.json node $REPO/toolbox/gekko-sidebar.mjs")"
NMAIN="$(tmux -L "$NEG" list-panes -F '#{pane_id}' | grep -v "$NSB" | head -1)"
tmux -L "$NEG" select-pane -t "$NMAIN"
# el cliente externo mide 180 columnas: el rail queda en x>=110, el click va a x=150
tmux -L "$OUT" new-window -d -n neg "env -u TMUX tmux -L $NEG attach -t n" 2>/dev/null
poll 'tmux -L "$OUT" list-windows | grep -q neg'
sleep 0.3
tmux -L "$OUT" send-keys -t out:neg -l $'\e[<0;150;5M'; tmux -L "$OUT" send-keys -t out:neg -l $'\e[<0;150;5m'
pcheck "AC6 control negativo: sin bindings el click mueve el foco al rail" '[ "$(tmux -L "$NEG" display-message -p -t "$NMAIN" "#{pane_active}")" = 0 ]'
tmux -L "$NEG" kill-server 2>/dev/null

# --- AC7: teclas con el rail enfocado ---
# el sidebar guarda el plegado en memoria: para partir de defaults se reabre el rail sin panel.ui.json
gen_state 0 ""; t kill-pane -t "$SB"; rm -f "$UI"
t run-shell "$REPO/tools/gekko-sidebar.sh" >/dev/null
poll 'cap | grep -q "^▾.*SCOPE"'; SB="$(sb_pane)"
t select-pane -t "$SB"
t send-keys -t "$SB" 2
pcheck "AC7: tecla 2 colapsa SCOPE (id fijo)" 'cap | grep -q "^▸.*SCOPE"'
t send-keys -t "$SB" 2
pcheck "AC7: tecla 2 de nuevo lo expande" 'cap | grep -q "^▾.*SCOPE"'
t send-keys -t "$SB" z
pcheck "AC7: z colapsa todas (con guard ON también el GUARD; solo AUSENTE/FALLÓ lo fija, AC3)" '! cap | grep -q "^▾.*SCOPE" && cap | grep -q "GUARD"'
t send-keys -t "$SB" a
pcheck "AC7: a expande todas" 'cap | grep -q "^▾.*SCOPE"'
t send-keys -t "$SB" j Enter
pcheck "AC7: j+Enter alterna la card del cursor" 'cap | grep -qE "^▸.*(SCOPE|TÉCNICAS)"'

# --- AC19: plegado persiste al reabrir; ui corrupto -> defaults ---
pcheck "AC19: existe panel.ui.json con JSON válido" 'node -e "JSON.parse(require(\"fs\").readFileSync(\"$UI\",\"utf8\"))"'
t send-keys -t "$SB" z   # estado conocido: todo colapsado salvo guard
poll 'cap | grep -q "^▸.*SCOPE"'
t kill-pane -t "$SB"
t run-shell "$REPO/tools/gekko-sidebar.sh" >/dev/null
pcheck "AC19: al reabrir el rail el plegado se conserva" 'cap | grep -q "^▸.*SCOPE"'
t kill-pane -t "$(sb_pane)"; printf '{{{ not json' > "$UI"
t run-shell "$REPO/tools/gekko-sidebar.sh" >/dev/null
pcheck "AC19: panel.ui.json corrupto -> defaults, sin romperse" 'cap | grep -q "^▾.*SCOPE"'
SB="$(sb_pane)"

# --- AC14: sha256 de panel.json y scope.txt intactos tras ráfaga de clicks y teclas ---
H0="$(sha256sum "$W/panel.json" "$W/scope.txt")"
for i in 1 2 3 4 5; do click_header SCOPE 0.02; click_header KB 0.02; done
t select-pane -t "$SB"; t send-keys -t "$SB" j k Enter 1 2 3 4 5 6 7 8 a z Space
sleep 0.3
check "AC14: sha256 de panel.json y scope.txt iguales tras la ráfaga" '[ "$(sha256sum "$W/panel.json" "$W/scope.txt")" = "$H0" ]'
check "AC14: el rail sigue vivo tras la ráfaga" '[ -n "$(sb_pane)" ]'

# --- AC9: cambio de roles en caliente cambia el SGR capturado ---
gen_state 0 $'\e[38;2;1;2;3m'
pcheck "AC9: roles A -> SGR 38;2;1;2;3 en la captura" 'cap_e | grep -qP "\x1b\[[0-9;]*38;2;1;2;3"'
gen_state 0 $'\e[38;2;4;5;6m'
pcheck "AC9: roles B -> cambia a 38;2;4;5;6 sin reiniciar" 'cap_e | grep -qP "\x1b\[[0-9;]*38;2;4;5;6" && ! cap_e | grep -qP "\x1b\[[0-9;]*38;2;1;2;3"'

# --- AC8: NO_COLOR -> sin SGR de color, estados distinguibles por glifo/palabra ---
gen_state 1 ""
pcheck "AC8: sin color la captura no trae SGR de color" '! cap_e | grep -qP "\x1b\[(?:[0-9;]*;)?(3[0-8]|9[0-7]|4[0-8])(?:;|m)"'
check "AC8: sin color el guard sigue legible (palabra ON)" 'cap | grep -q "ON"'
gen_state 0 ""

# --- AC10: frontera 139/140 con resize-window ---
pcheck "AC10: rail presente a 180 columnas antes de la frontera" '[ -n "$(sb_pane)" ]'
had_rail=0; [ -n "$(sb_pane)" ] && had_rail=1
t resize-window -x 139 -y 50
pcheck "AC10: a 139 columnas el rail se cierra" '[ "$had_rail" = 1 ] && [ -z "$(sb_pane)" ]'
t resize-window -x 140 -y 50
pcheck "AC10: a 140 columnas el rail se reabre" '[ -n "$(sb_pane)" ]'
t resize-window -x 80 -y 24
pcheck "AC10: a 80x24 no hay rail" '[ -z "$(sb_pane)" ]'
t resize-window -x 180 -y 50
poll '[ -n "$(sb_pane)" ]'

# --- /gekko-sidebar: --toggle oculta, no reaparece al redimensionar, y vuelve a abrir ---
t run-shell "$REPO/tools/gekko-sidebar.sh --toggle" >/dev/null
pcheck "toggle: con el rail abierto lo oculta" '[ -z "$(sb_pane)" ]'
t resize-window -x 170 -y 50; sleep 1
check "toggle: oculto a mano no reaparece al redimensionar" '[ -z "$(sb_pane)" ]'
t resize-window -x 180 -y 50
t run-shell "$REPO/tools/gekko-sidebar.sh --toggle" >/dev/null
pcheck "toggle: con el rail oculto lo abre" '[ -n "$(sb_pane)" ]'
t resize-window -x 170 -y 50; t resize-window -x 180 -y 50
pcheck "toggle: reabierto, el redimensionado vuelve a gestionarlo" '[ -n "$(sb_pane)" ]'

# --- lanzado en ventana angosta: no abre, pero al agrandar el rail aparece solo y con el ancho correcto ---
t kill-pane -t "$(sb_pane)"; t set-hook -u -t in window-resized
t resize-window -x 100 -y 40
t run-shell "$REPO/tools/gekko-sidebar.sh" >/dev/null 2>&1
check "angosta: a 100 columnas no abre el rail" '[ -z "$(sb_pane)" ]'
t resize-window -x 184 -y 50
pcheck "angosta: al agrandar a 184 el rail aparece solo" '[ -n "$(sb_pane)" ]'
pcheck "ancho: a 184 columnas el rail mide 46 (25 %)" '[ "$(t display-message -p -t "$(sb_pane)" "#{pane_width}")" = 46 ]'
t resize-window -x 150 -y 50
pcheck "ancho: al achicar a 150 se re-ajusta a 37" '[ "$(t display-message -p -t "$(sb_pane)" "#{pane_width}")" = 37 ]'
t resize-window -x 180 -y 50

# --- AC11 (GAP-61): un ts futuro no se dibuja vigente aunque GEKKO_STALE_MS sea largo; uno fresco vuelve a ON ---
pcheck "AC11: con estado fresco el rail muestra GUARD ON" 'cap | grep -q "GUARD  ON"'
node -e 'const fs=require("fs"),p=process.env.GEKKO_PANEL_STATE,s=JSON.parse(fs.readFileSync(p,"utf8"));s.ts=Date.now()+3600e3;fs.writeFileSync(p+".tmp",JSON.stringify(s));fs.renameSync(p+".tmp",p)'
pcheck "AC11: panel.json con ts una hora adelante se dibuja guard ?" 'cap | grep -q "GUARD  guard ?" && ! cap | grep -q "guard  ON"'
gen_state 0 ""
pcheck "AC11: un estado fresco vuelve a ON" 'cap | grep -q "GUARD  ON"'

# --- AC7: una tecla con modificador o de función no pliega nada (su secuencia no se lee como dígitos sueltos) ---
SB="$(sb_pane)"; t send-keys -t "$SB" a
poll 'cap | grep -q "^▾.*CAMBIOS"'
t send-keys -t "$SB" -l $'\e[1;2A'; t send-keys -t "$SB" -l $'\e[17~'   # Shift+Arriba, F6
t send-keys -t "$SB" 8   # punto de sincronía: la tecla siguiente sí llega
poll 'cap | grep -q "^▸.*CAMBIOS"'
check "AC7: Shift+Arriba y F6 no pliegan SCOPE ni SESIÓN" 'cap | grep -q "^▾.*SCOPE" && cap | grep -q "^▾.*SESIÓN"'

# --- AC1: con el frame tan alto como el pane se dibuja la última fila, y un panel.json rechazado se avisa ---
t resize-window -x 180 -y 12
pcheck "AC1: a 12 filas la última fila del rail (CAMBIOS) se dibuja" 'cap | sed -n 12p | grep -q "CAMBIOS"'
bad_state() { node -e 'const fs=require("fs"),p=process.env.GEKKO_PANEL_STATE,s=JSON.parse(fs.readFileSync(p,"utf8"));s.bar.guard="FALLÓ";fs.writeFileSync(p+".tmp",JSON.stringify(s));fs.renameSync(p+".tmp",p)'; }
bad_state
pcheck "AC1: panel.json incoherente -> el rail conserva el último frame y lo avisa en la última fila" 'cap | sed -n 12p | grep -q "^! último estado válido" && cap | sed -n 1p | grep -q "GUARD  ON"'
gen_state 0 ""
pcheck "AC1: con un estado válido el aviso desaparece" '! cap | grep -q "último estado" && cap | sed -n 12p | grep -q "CAMBIOS"'
t resize-window -x 150 -y 12   # rail de 37 columnas: el aviso (41 caracteres) no cabe entero
poll '[ "$(t display-message -p -t "$(sb_pane)" "#{pane_width}")" = 37 ]'
bad_state
pcheck "AC1: a 37 columnas el aviso se recorta: sigue en la última fila y el encabezado GUARD en la primera" 'cap | sed -n 12p | grep -q "^! último estado" && cap | sed -n 1p | grep -q "GUARD  ON"'
gen_state 0 ""
t resize-window -x 180 -y 50
poll '[ -n "$(sb_pane)" ] && cap | grep -q "GUARD  ON"'

# --- spec 014 (AC1, AC2): la fila «ejecución» del rail y su click inerte; el rail sólo muestra ---
gen_exec() { # gen_exec MODO ESTADO MOTIVO -> panel.json fresco con `exec`
  XMODE="$1" XSTATE="$2" XREASON="${3:-}" node --experimental-strip-types --input-type=module -e '
    import { buildPanelState, newRuntime } from "'"$REPO"'/toolbox/gekko-panel.ts";
    import { writeFileSync, renameSync } from "node:fs";
    const rt = newRuntime(Date.now()); rt.exec = { state: process.env.XSTATE || null, reason: process.env.XREASON };
    const s = buildPanelState(rt, { execMode: process.env.XMODE }, Date.now());
    const p = process.env.GEKKO_PANEL_STATE; writeFileSync(p + ".tmp", JSON.stringify(s)); renameSync(p + ".tmp", p);' 2>/dev/null
}
exec_row() { cap | grep -m1 "ejecución"; }
no_clear_screen() { ! cap_e | grep -qF $'\x1b[2J'; }
gen_exec os ""
pcheck "014 AC1: modo os -> la fila «ejecución» dice os" 'exec_row | grep -qE "ejecución  os *$"'
gen_exec toolbox lista
pcheck "014 AC1: toolbox lista -> la fila dice toolbox · lista" 'exec_row | grep -q "ejecución  toolbox · lista"'
gen_exec toolbox caída $'no hay imagen\x1b[2J gekko-toolbox:latest'
pcheck "014 AC1: toolbox caída -> la fila dice caída y el motivo, sin escapes" 'exec_row | grep -q "ejecución  toolbox · caída · no hay ima" && no_clear_screen'
check "014 AC1: la fila cabe en el ancho del rail" '[ "$(exec_row | awk "{print length}")" -le "$(t display-message -p -t "$(sb_pane)" "#{pane_width}")" ]'
gen_exec toolbox lista
poll 'exec_row | grep -q "toolbox · lista"'
SB="$(sb_pane)"; EX_HASH="$(sha256sum "$W/panel.json" "$W/scope.txt" | sha256sum)"; EX_UI="$(cat "$UI" 2>/dev/null)"; EX_MODE_FILE="$W/exec"
before="$(cap)"; EX_ROW="$(cap | awk '/ejecución/{print NR; exit}')"
click $(( $(t display-message -p -t "$SB" '#{pane_left}') + 6 )) "$EX_ROW" 0.3
t select-pane -t "$SB"; t send-keys -t "$SB" Enter Space
sleep 0.3
check "014 AC2: un click en la fila no cambia el rail" '[ "$(cap)" = "$before" ]'
check "014 AC2: ni click ni teclas tocan panel.json, scope.txt ni crean un archivo de modo" '[ "$(sha256sum "$W/panel.json" "$W/scope.txt" | sha256sum)" = "$EX_HASH" ] && [ ! -e "$EX_MODE_FILE" ] && [ ! -e "$W/panel.json.exec" ]'
check "014 AC2: el rail no tiene hijos docker ni tmux de modo (sólo node y su pane)" '! ps -o args= --ppid "$(t display-message -p -t "$SB" "#{pane_pid}")" | grep -qiE "docker|gekko-workspace"'
gen_state 0 ""

# --- AC6: --restore deja list-keys idéntico al previo ---
t kill-pane -t "$(sb_pane)"
t run-shell "$REPO/tools/gekko-sidebar.sh --restore" >/dev/null
pcheck "AC6: tras --restore list-keys de las 3 teclas es idéntico al de antes" '[ "$(t_before_keys)" = "$KEYS_BEFORE" ]'
check "AC6: --restore es idempotente" 't run-shell "$REPO/tools/gekko-sidebar.sh --restore" && [ "$(t_before_keys)" = "$KEYS_BEFORE" ]'

# --- T14: dos sesiones, un cliente cada una; el hook de `a` corre con la última actividad en `b` y no debe apilar rails ---
t2() { tmux -L "$TWO" "$@"; }
rails_in_a() { t2 list-panes -s -t a -F '#{?@gekko_sidebar,1,0}' 2>/dev/null | grep -c 1; }
t2 -f /dev/null new-session -d -s a -x 180 -y 50 "bash --norc"; t2 new-session -d -s b -x 180 -y 50 "bash --norc"
tmux -L "$CLI" -f /dev/null new-session -d -s cla -x 180 -y 50 "env -u TMUX tmux -L $TWO attach -t a"
tmux -L "$CLI" new-session -d -s clb -x 180 -y 50 "env -u TMUX tmux -L $TWO attach -t b"
poll '[ "$(t2 list-clients | wc -l)" = 2 ]'
T14_STATE="$W/panel-t14.json"; cp "$W/panel.json" "$T14_STATE"
t2 send-keys -t a "GEKKO_PANEL_STATE=$T14_STATE $REPO/tools/gekko-sidebar.sh" Enter
poll '[ "$(rails_in_a)" = 1 ]'
sleep 1.1; tmux -L "$CLI" send-keys -t clb x   # la última actividad pasa a `b`
sleep 1.1
for w in 190 200 185 200; do t2 resize-window -t a: -x "$w" -y 50; sleep 0.7; done
sleep 1
check "T14: tras cuatro redimensionados con la última actividad en otra sesión, la ventana tiene un solo rail" '[ "$(rails_in_a)" = 1 ]'
check "T14: el rail que queda lleva GEKKO_PANEL_STATE de su lanzamiento" 't2 list-panes -s -t a -F "#{@gekko_sidebar} #{pane_start_command}" | grep "^1 " | grep -qF "GEKKO_PANEL_STATE='"'$T14_STATE'"'"'
# --fit simultáneos (el arranque y un redimensionado pueden solaparse) sin rail previo: debe quedar exactamente uno
t2 kill-pane -t "$(t2 list-panes -s -t a -F '#{pane_id} #{?@gekko_sidebar,1,0}' | awk '$2==1{print $1; exit}')"
T14_WIN="$(t2 display-message -p -t a: '#{window_id}')"
for _ in 1 2 3 4 5 6; do t2 run-shell -b "$REPO/tools/gekko-sidebar.sh --fit $T14_WIN"; done
sleep 3
check "T14: seis --fit simultáneos para la misma ventana dejan un solo rail" '[ "$(rails_in_a)" = 1 ]'
t2 kill-server 2>/dev/null; tmux -L "$CLI" kill-server 2>/dev/null

# --- smoke en vivo (opt-in): endpoint y key solo por entorno, nunca impresos ---
if [ "$LIVE" = 1 ]; then
  if [ -z "${GEKKO_LLM_URL:-}" ] || [ -z "${GEKKO_LLM_KEY:-}" ] || [ -z "${GEKKO_LIVE_MODEL:-}" ] || ! command -v pi >/dev/null; then
    FAIL=$((FAIL+1)); echo "FAIL: live: faltan GEKKO_LLM_URL / GEKKO_LLM_KEY / GEKKO_LIVE_MODEL o pi"
  else
    LS="gekko-tui-test-$$-live"; mkdir -p "$W/piagent" "$W/sess"; : > "$W/live-scope.txt"
    node -e 'const fs=require("fs"),e=process.env;fs.writeFileSync(process.argv[1]+"/models.json",JSON.stringify({providers:{live:{baseUrl:e.GEKKO_LLM_URL,apiKey:"$GEKKO_LLM_KEY",api:"openai-completions",models:[{id:e.GEKKO_LIVE_MODEL,reasoning:false}]}}}));fs.writeFileSync(process.argv[1]+"/settings.json",JSON.stringify({theme:"dark"}))' "$W/piagent"
    export GEKKO_PANEL_STATE="$W/live.panel.json" GEKKO_SCOPE="$W/live-scope.txt" PI_CODING_AGENT_DIR="$W/piagent" PI_CODING_AGENT_SESSION_DIR="$W/sess" PI_TELEMETRY=0 PI_SKIP_VERSION_CHECK=1
    # sin redirigir la salida: Pi 1.5.0 con stdout fuera del tty sale solo (exit 0) y no hay TUI que medir
    tmux -L "$LS" -f /dev/null new-session -d -s s -x 180 -y 50 "cd $REPO && exec pi --provider live --model $GEKKO_LIVE_MODEL -e toolbox/gekko-guard.ts --no-session"
    sleep 6; tmux -L "$LS" send-keys -t s Down Down Enter   # trust prompt de Pi en worktree nuevo
    pcheck "live: el guard publica panel.json fresco" '[ -s "$GEKKO_PANEL_STATE" ]'
    tmux -L "$LS" send-keys -t s -l 'run: echo gekko-smoke'; tmux -L "$LS" send-keys -t s Enter
    pcheck "live: tras un turno SESIÓN refleja turno >= 1" 'node -e "const s=JSON.parse(require(\"fs\").readFileSync(process.env.GEKKO_PANEL_STATE,\"utf8\"));process.exit(/turno [1-9]/.test(s.cards.find(c=>c.id===\"sesion\").right)?0:1)"'
  fi
fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
