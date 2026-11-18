#!/usr/bin/env bash
# Pruebas de proceso (P) de la spec 010: el lanzador exige y aplica un workspace. Usa un `pi` falso (vuelca
# entorno, argv, cwd y prompt) y tmux en sockets propios: nunca toca tu servidor tmux, tu config de Pi ni la red.
# Uso:  bash tools/ws-test.sh
# Sale 0 solo si todo pasa; una línea FAIL por check fallido y "N passed, M failed" al final.
set -uo pipefail
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
command -v tmux >/dev/null && command -v node >/dev/null && command -v python3 >/dev/null || { echo "ws-test: faltan tmux, node y/o python3" >&2; exit 2; }

W="$(mktemp -d)"
cleanup() {
  TMUX_TMPDIR="$W/tmux" tmux kill-server 2>/dev/null
  for sock in "$W"/sockets/* "$W"/panes/*; do [ -S "$sock" ] && tmux -S "$sock" kill-server 2>/dev/null; done
  pkill -f "findings_web[.]py serve --root $W" 2>/dev/null
  [ -z "${FOREIGN_PID:-}" ] || kill "$FOREIGN_PID" 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT
PASS=0; FAIL=0
check() { # check "nombre" "expr"  (expr evaluada con eval)
  local name="$1" expr="$2"
  if eval "$expr" >/dev/null 2>&1; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL: $name"; fi
}
poll() { local n=100; while [ $n -gt 0 ]; do eval "$1" >/dev/null 2>&1 && return 0; sleep 0.1; n=$((n-1)); done; return 1; } # hasta 10 s
pcheck() { check "$1" "poll '${2//\'/\'\\\'\'}'"; }

# --- aislamiento: raíz de workspaces, tmux, config de Pi y credenciales viven en $W ---
unset TMUX TMUX_PANE GEKKO_WORKSPACE GEKKO_WORKSPACE_DIR GEKKO_SCOPE GEKKO_FINDINGS GEKKO_PI_SESSION_DIR GEKKO_MODEL GEKKO_PROVIDER GEKKO_PROVIDER_KEY GEKKO_REPORT_URL GEKKO_REPORT GEKKO_REPORT_PORT
mkdir -p "$W/tmux" "$W/bin" "$W/pi-run" "$W/cfg" "$W/sockets" "$W/panes"
chmod 700 "$W/tmux"
: > "$W/empty.env"
export GEKKO_WS_ROOT="$W" TMUX_TMPDIR="$W/tmux" GEKKO_TMUX_DIR="$W/sockets"
export PI_CODING_AGENT_DIR="$W/cfg" GEKKO_HITL_ENV="$W/empty.env" GEKKO_CRED_ENV="$W/empty.env"
export GEKKO_LLM_URL="http://192.0.2.1:8080/v1" GEKKO_LLM_KEY="dummy" GEKKO_MODEL="m-test" GEKKO_SIDEBAR=0
export PATH="$W/bin:$PATH"
export GEKKO_REPORT=0   # los casos de spec 010 no levantan módulos; los de spec 012 lo piden por lanzamiento
RUN="$W/pi-run"

# pi falso: la ruta del volcado va incrustada (el servidor tmux no hereda variables de este shell).
cat > "$W/bin/pi" <<EOF
#!/bin/sh
[ "\$1" = "--version" ] && { echo "0.0.0"; exit 0; }
d="$RUN"
env | sort > "\$d/env.txt"
printf '%s\n' "\$@" > "\$d/argv.txt"
pwd > "\$d/cwd.txt"
prev=""
for a in "\$@"; do [ "\$prev" = "--append-system-prompt" ] && cp -- "\$a" "\$d/prompt.md"; prev="\$a"; done
touch "\$d/ran"
while [ -f "$W/hold" ] || [ -f "$W/hold.\$GEKKO_WORKSPACE" ]; do sleep 0.2; done
[ -f "$W/pi-rc" ] && exit "\$(cat "$W/pi-rc")"
exit 0
EOF
chmod +x "$W/bin/pi"

LAUNCH="$REPO/tools/pi-hitl.sh"
reset_run() { rm -rf "$RUN"; mkdir -p "$RUN"; }
ran() { [ -f "$RUN/ran" ]; }
pi_env() { sed -n "s/^$1=//p" "$RUN/env.txt"; }   # valor de una variable que vio el pi falso
pi_has() { grep -q "^$1=" "$RUN/env.txt"; }
ws_dir() { echo "$W/engagements/$1"; }
ws_new() { node --no-warnings --experimental-strip-types "$REPO/toolbox/gekko-workspace.ts" new "$@" >/dev/null 2>&1; }
# lanza sin terminal (stdin /dev/null); stdout/stderr a $W/out y $W/err; rc en $RC
launch_plain() { reset_run; env "$@" bash "$LAUNCH" </dev/null >"$W/out" 2>"$W/err"; RC=$?; }

ws_new alpha 192.0.2.10 198.51.100.0/24
ws_new beta 203.0.113.7
ws_new many 192.0.2.1 192.0.2.2 192.0.2.3 192.0.2.4 192.0.2.5 192.0.2.6 192.0.2.7 192.0.2.8

# --- AC2: sin terminal y sin GEKKO_WORKSPACE ---
launch_plain
check "AC2 sin TTY ni GEKKO_WORKSPACE: sale distinto de 0" '[ "$RC" -ne 0 ]'
check "AC2 el mensaje nombra GEKKO_WORKSPACE" 'grep -q GEKKO_WORKSPACE "$W/err"'
check "AC2 Pi no arranca" '! ran'

# --- AC3: nombre existente / inexistente / inválido ---
launch_plain GEKKO_WORKSPACE=alpha
check "AC3 workspace existente: arranca (rc 0, pi corrió)" '[ "$RC" -eq 0 ] && ran'
check "AC3 workspace existente: sin menú" '! grep -q "Workspaces:" "$W/err" "$W/out"'
launch_plain GEKKO_WORKSPACE=ghost
check "AC3 workspace inexistente: error y Pi no arranca" '[ "$RC" -ne 0 ] && ! ran'
check "AC3 workspace inexistente: no se crea en silencio" '[ ! -e "$(ws_dir ghost)" ]'
launch_plain GEKKO_WORKSPACE='../x'
check "AC3 nombre inválido: error y Pi no arranca" '[ "$RC" -ne 0 ] && ! ran'
check "AC3 nombre inválido: no crea nada fuera de engagements/" '[ ! -e "$W/x" ] && [ ! -e "$W/engagements/../x" ]'

# --- AC4: none = valores de hoy ---
launch_plain GEKKO_WORKSPACE=none
check "AC4 none: arranca" '[ "$RC" -eq 0 ] && ran'
check "AC4 none: GEKKO_WORKSPACE_DIR ausente" '! pi_has GEKKO_WORKSPACE_DIR'
check "AC4 none: GEKKO_WORKSPACE=none" '[ "$(pi_env GEKKO_WORKSPACE)" = none ]'
check "AC4 none: GEKKO_SCOPE es el de hoy (raíz del repo)" '[ "$(pi_env GEKKO_SCOPE)" = "$REPO/scope.txt" ]'
check "AC4 none: sesiones en state-dir temporal" '[ "$(pi_env PI_CODING_AGENT_SESSION_DIR)" = "$W/.gekko-state/pi-sessions" ]'
check "AC4 none: GEKKO_FINDINGS no se deriva" '! pi_has GEKKO_FINDINGS'

# --- AC12: derivación ---
launch_plain GEKKO_WORKSPACE=alpha
X="$(ws_dir alpha)"
check "AC12 scope = X/scope.txt" '[ "$(pi_env GEKKO_SCOPE)" = "$X/scope.txt" ]'
check "AC12 hallazgos = X/findings.jsonl" '[ "$(pi_env GEKKO_FINDINGS)" = "$X/findings.jsonl" ]'
check "AC12 sesiones bajo X" '[ "$(pi_env PI_CODING_AGENT_SESSION_DIR)" = "$X/.pi-sessions" ]'
check "AC12 GEKKO_WORKSPACE = nombre" '[ "$(pi_env GEKKO_WORKSPACE)" = alpha ]'
check "AC12 GEKKO_WORKSPACE_DIR = X" '[ "$(pi_env GEKKO_WORKSPACE_DIR)" = "$X" ]'
check "AC12 el directorio de sesiones existe en X" '[ -d "$X/.pi-sessions" ]'

# --- AC14: GEKKO_SCOPE/GEKKO_FINDINGS previos se pisan y el banner avisa ---
launch_plain GEKKO_WORKSPACE=alpha GEKKO_SCOPE=/elsewhere/scope.txt GEKKO_FINDINGS=/elsewhere/findings.jsonl
check "AC14 gana el workspace (scope)" '[ "$(pi_env GEKKO_SCOPE)" = "$X/scope.txt" ]'
check "AC14 gana el workspace (hallazgos)" '[ "$(pi_env GEKKO_FINDINGS)" = "$X/findings.jsonl" ]'
check "AC14 el banner avisa de GEKKO_SCOPE pisado" 'grep -q "GEKKO_SCOPE.*pisado" "$W/err"'
check "AC14 el banner avisa de GEKKO_FINDINGS pisado" 'grep -q "GEKKO_FINDINGS.*pisado" "$W/err"'
launch_plain GEKKO_WORKSPACE=alpha
check "AC14 sin variables previas: sin aviso" '! grep -q "pisado" "$W/err"'

# --- AC15: banner con workspace y scope ---
launch_plain GEKKO_WORKSPACE=many
check "AC15 el banner muestra el nombre del workspace" 'grep -Eq "^ +workspace +many" "$W/err"'
check "AC15 el banner lista las primeras 6 entradas" 'grep -q "192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4, 192.0.2.5, 192.0.2.6 +2 más" "$W/err"'
check "AC15 la 7ma entrada no aparece" '! grep -q "192.0.2.7" "$W/err"'
launch_plain GEKKO_WORKSPACE=alpha
check "AC15 con pocas entradas, sin +N más" 'grep -q "192.0.2.10, 198.51.100.0/24" "$W/err" && ! grep -q "más" "$W/err"'
launch_plain GEKKO_WORKSPACE=none
check "AC15 none: el banner lo dice" 'grep -q "ninguno (GEKKO_WORKSPACE=none)" "$W/err"'

# --- AC22: prompt generado ---
launch_plain GEKKO_WORKSPACE=alpha
check "AC22 el prompt trae la ruta absoluta del workspace" 'grep -qF "$X" "$RUN/prompt.md"'
check "AC22 el prompt base sigue ahí" 'grep -q "Gekko HITL operator" "$RUN/prompt.md"'
check "AC22 el prompt ya no manda crear engagements/<codename>/" '! grep -q "engagements/<codename>" "$RUN/prompt.md" && ! grep -q "mkdir -p engagements" "$RUN/prompt.md"'
launch_plain GEKKO_WORKSPACE=none
check "AC22 none: el prompt no nombra ningún workspace" '! grep -qF "$W/engagements" "$RUN/prompt.md" && ! grep -q "engagements/<codename>" "$RUN/prompt.md"'

# --- spec 012 (AC17-AC21): el lanzador levanta o se acopla al módulo de reportes y le dice la URL a Pi ---
free_port() { python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
http_code() { python3 -I -c 'import sys, urllib.request
try: print(urllib.request.urlopen(sys.argv[1], timeout=5).status)
except Exception as e: print(getattr(e, "code", 0))' "$1"; }
http_body() { python3 -I -c 'import sys, urllib.request; print(urllib.request.urlopen(sys.argv[1], timeout=5).read().decode())' "$1"; }
module_pids() { pgrep -f "findings_web[.]py serve --root $W --port"; }
stop_modules() { pkill -f "findings_web[.]py serve --root $W" 2>/dev/null; poll '! pgrep -f "findings_web[.]py serve --root $W" >/dev/null'; }
other_root="$W/other-root"; mkdir -p "$other_root/engagements"

# AC17 + AC18: sin módulo, el lanzador lo levanta; sobrevive al lanzador; el segundo arranque se acopla al mismo proceso
RP="$(free_port)"; RURL="http://127.0.0.1:$RP/"
launch_plain GEKKO_WORKSPACE=alpha GEKKO_REPORT=1 GEKKO_REPORT_PORT="$RP"
check "AC17 Pi ve GEKKO_REPORT_URL con el puerto pedido" '[ "$(pi_env GEKKO_REPORT_URL)" = "$RURL" ]'
check "AC17 el banner trae la URL del workspace en una línea reportes" 'grep -Eq "^ +reportes +${RURL}w/alpha/$" "$W/err"'
check "AC17 la URL del workspace responde 200" '[ "$(http_code "${RURL}w/alpha/")" = 200 ]'
MOD_PID="$(module_pids)"
check "AC17 hay exactamente un módulo" '[ -n "$MOD_PID" ] && [ "$(echo "$MOD_PID" | wc -l)" -eq 1 ]'
check "AC18 terminado el lanzador, la URL sigue respondiendo" '[ "$(http_code "${RURL}w/alpha/")" = 200 ]'
launch_plain GEKKO_WORKSPACE=beta GEKKO_REPORT=1 GEKKO_REPORT_PORT="$RP"
check "AC18 el segundo arranque deja un solo módulo, el mismo pid" '[ "$(module_pids)" = "$MOD_PID" ]'
check "AC18 Pi ve otra vez la URL" '[ "$(pi_env GEKKO_REPORT_URL)" = "$RURL" ]'
check "AC18 /w/beta/ responde 200" '[ "$(http_code "${RURL}w/beta/")" = 200 ]'

# AC19: sin workspace o con GEKKO_REPORT=0 no hay URL, ni línea reportes, ni módulo
stop_modules
RP="$(free_port)"
launch_plain GEKKO_WORKSPACE=none GEKKO_REPORT=1 GEKKO_REPORT_PORT="$RP"
check "AC19 none: Pi no ve GEKKO_REPORT_URL" 'ran && ! pi_has GEKKO_REPORT_URL'
check "AC19 none: el banner no tiene línea reportes" '! grep -Eq "^ +reportes" "$W/err"'
check "AC19 none: no se levantó ningún módulo" '! module_pids'
launch_plain GEKKO_WORKSPACE=alpha GEKKO_REPORT=0 GEKKO_REPORT_PORT="$RP"
check "AC19 GEKKO_REPORT=0: Pi no ve GEKKO_REPORT_URL" 'ran && ! pi_has GEKKO_REPORT_URL'
check "AC19 GEKKO_REPORT=0: el banner no tiene línea reportes" '! grep -Eq "^ +reportes" "$W/err"'
check "AC19 GEKKO_REPORT=0: no se levantó ningún módulo" '! module_pids'

# AC20: puerto ocupado por otro programa / por un módulo de otra raíz -> aviso, Pi arranca sin URL
stop_modules
RP="$(free_port)"
python3 -I -m http.server "$RP" --bind 127.0.0.1 --directory "$W/panes" >/dev/null 2>&1 & FOREIGN_PID=$!
poll "[ \"\$(http_code http://127.0.0.1:$RP/)\" != 0 ]"
launch_plain GEKKO_WORKSPACE=alpha GEKKO_REPORT=1 GEKKO_REPORT_PORT="$RP"
check "AC20 puerto ajeno: el lanzador sale 0 y Pi corrió" '[ "$RC" -eq 0 ] && ran'
check "AC20 puerto ajeno: el banner trae un aviso del módulo" 'grep -Eq "^ +aviso +.*(módulo|modulo)" "$W/err"'
check "AC20 puerto ajeno: Pi no ve GEKKO_REPORT_URL" '! pi_has GEKKO_REPORT_URL'
check "AC20 puerto ajeno: el banner no publica la URL" '! grep -qF "http://127.0.0.1:$RP/" "$W/err"'
kill "$FOREIGN_PID" 2>/dev/null; wait "$FOREIGN_PID" 2>/dev/null; FOREIGN_PID=""
RP="$(free_port)"
python3 "$REPO/.claude/tools/findings_web.py" serve --root "$other_root" --port "$RP" >/dev/null 2>&1 &
poll "[ \"\$(http_code http://127.0.0.1:$RP/)\" = 200 ]"
launch_plain GEKKO_WORKSPACE=alpha GEKKO_REPORT=1 GEKKO_REPORT_PORT="$RP"
check "AC20 módulo de otra raíz: el lanzador sale 0 y Pi corrió" '[ "$RC" -eq 0 ] && ran'
check "AC20 módulo de otra raíz: el banner trae un aviso del módulo" 'grep -Eq "^ +aviso +.*(módulo|modulo)" "$W/err"'
check "AC20 módulo de otra raíz: Pi no ve GEKKO_REPORT_URL" '! pi_has GEKKO_REPORT_URL'
check "AC20 módulo de otra raíz: el banner no publica la URL" '! grep -qF "http://127.0.0.1:$RP/" "$W/err"'
stop_modules

# AC21: dos arranques simultáneos con workspaces distintos sobre el mismo puerto -> un solo módulo, cada ledger aislado
RP="$(free_port)"; RURL="http://127.0.0.1:$RP/"
for name in alpha beta; do
  python3 "$REPO/.claude/tools/findings.py" add --ledger "$(ws_dir $name)/findings.jsonl" --title "CANARY-${name}-9f3a" --severity low --target 192.0.2.1 >/dev/null 2>&1
done
reset_run
env GEKKO_WORKSPACE=alpha GEKKO_REPORT=1 GEKKO_REPORT_PORT="$RP" bash "$LAUNCH" </dev/null >"$W/out.a" 2>"$W/err.a" & PA=$!
env GEKKO_WORKSPACE=beta GEKKO_REPORT=1 GEKKO_REPORT_PORT="$RP" bash "$LAUNCH" </dev/null >"$W/out.b" 2>"$W/err.b" & PB=$!
wait "$PA" "$PB"
check "AC21 un solo módulo tras dos arranques simultáneos" '[ "$(module_pids | wc -l)" -eq 1 ]'
check "AC21 los dos banners traen el mismo puerto" 'grep -qF "${RURL}w/alpha/" "$W/err.a" && grep -qF "${RURL}w/beta/" "$W/err.b"'
check "AC21 /w/alpha/ y /w/beta/ responden 200" '[ "$(http_code "${RURL}w/alpha/")" = 200 ] && [ "$(http_code "${RURL}w/beta/")" = 200 ]'
check "AC21 alpha muestra su canario y no el de beta" 'b="$(http_body "${RURL}w/alpha/")"; grep -q "CANARY-alpha-9f3a" <<<"$b" && ! grep -q "CANARY-beta-9f3a" <<<"$b"'
check "AC21 beta muestra su canario y no el de alpha" 'b="$(http_body "${RURL}w/beta/")"; grep -q "CANARY-beta-9f3a" <<<"$b" && ! grep -q "CANARY-alpha-9f3a" <<<"$b"'
stop_modules

# URL heredada: nunca llega a Pi
launch_plain GEKKO_WORKSPACE=alpha GEKKO_REPORT=0 GEKKO_REPORT_URL=http://127.0.0.1:1/
check "Heredada: con GEKKO_REPORT=0 Pi no ve la GEKKO_REPORT_URL del entorno" 'ran && ! pi_has GEKKO_REPORT_URL'

# --- interactivo: el lanzador corre en un pane de un servidor tmux dedicado y se maneja con send-keys ---
PS=0
pane_start() { # pane_start CMD...  -> servidor propio en $W/panes/pN, sesión "t"; $PSOCK = socket
  PS=$((PS+1)); PSOCK="$W/panes/p$PS"; reset_run; rm -f "$W/rc"
  tmux -S "$PSOCK" -f /dev/null new-session -d -s t -x 200 -y 50 \
    "bash '$LAUNCH' $*; echo \$? > '$W/rc'; sleep 60"
}
pane_cap() { tmux -S "$PSOCK" capture-pane -p -t t 2>/dev/null; }
pane_keys() { tmux -S "$PSOCK" send-keys -t t "$@"; }
pane_has() { pane_cap | grep -qF -- "$1"; }
pane_end() { tmux -S "$PSOCK" kill-server 2>/dev/null; }
# responde a cada pregunta del menú: espera el texto y escribe la respuesta
answer() { poll "pane_has '$1'" && pane_keys -l "$2" && pane_keys Enter && sleep 0.1; }

rm -f "$W/.gekko-state/last-workspace"   # los arranques con GEKKO_WORKSPACE de arriba también lo registran
# AC1 + AC5: menú, Pi no corre hasta elegir, Enter = último usado, el último se recuerda y se descarta si ya no existe
pane_start
pcheck "AC1 aparece el menú" "pane_has 'Workspaces:'"
check "AC1 Pi no arranca mientras no se elige" '! ran'
check "AC1 sin último usado no hay opción por defecto" '! pane_has "(último usado)"'
answer "Elige:" "beta" && answer "¿Mantener este scope?" ""
pcheck "AC1 tras elegir, Pi arranca con el workspace" '[ "$(pi_env GEKKO_WORKSPACE)" = beta ]'
pane_end
pane_start
pcheck "AC5 el último usado se recuerda entre arranques" "pane_has 'beta  (último usado)'"
answer "Elige [beta]:" "" && answer "¿Mantener este scope?" ""
pcheck "AC1 Enter sin escribir elige el último usado" '[ "$(pi_env GEKKO_WORKSPACE)" = beta ]'
pane_end
rm -rf "$(ws_dir beta)"
pane_start
pcheck "AC5 un último usado borrado no se ofrece" "pane_has 'Elige:' && ! pane_has 'beta'"
pane_end

# AC6: sólo dirs con scope.txt; conteo de shells vivas desde un servidor propio en GEKKO_TMUX_DIR
mkdir -p "$W/engagements/sinscope"
tmux -S "$W/sockets/live" -f /dev/null new-session -d -s shell1 -c "$(ws_dir alpha)" "sleep 120"
tmux -S "$W/sockets/live" new-session -d -s shell2 -c "$(ws_dir alpha)" "sleep 120"
pane_start
pcheck "AC6 el menú muestra el conteo de shells vivas" "pane_has 'alpha'"
check "AC6 alpha: 2 shells vivas" "poll \"pane_cap | grep -E 'alpha.*2 shells vivas'\""
check "AC6 un directorio sin scope.txt no se lista" '! pane_has sinscope'
check "AC6 un workspace sin shells no muestra conteo" '! pane_cap | grep -E "many.*shells vivas"'
pane_end
tmux -S "$W/sockets/live" kill-server 2>/dev/null; rm -f "$W/sockets/live"

# AC9: hostname -> IP, escrita sólo tras confirmar
pane_start
answer "Elige" "n" && answer "Nombre:" "resuelto" && answer "Objetivos" "localhost"
pcheck "AC9 muestra la IP resuelta" "pane_has 'localhost → 127.0.0.1'"
check "AC9 antes de confirmar scope.txt no tiene la IP" '! grep -q "^127.0.0.1" "$(ws_dir resuelto)/scope.txt" 2>/dev/null'
answer "¿añadir?" "s" && answer "¿Dónde nacen" ""
check "AC9 el workspace termina de crearse antes de revisar scope" 'poll "ran"'
check "AC9 confirmado con 's': se escribe 127.0.0.1" 'grep -q "^127.0.0.1" "$(ws_dir resuelto)/scope.txt"'
pane_end
pane_start
answer "Elige" "n" && answer "Nombre:" "rechazado" && answer "Objetivos" "localhost" && answer "¿añadir?" "n" && answer "¿Dónde nacen" ""
pcheck "AC9 respondiendo 'n' se crea el workspace" 'poll "[ -f \"$(ws_dir rechazado)/scope.txt\" ]"'
check "AC9 respondiendo 'n' scope.txt no recibe la IP" '! grep -q "127.0.0.1" "$(ws_dir rechazado)/scope.txt"'
pane_end

# AC10: crear sobre un directorio con notes.md no lo pisa y completa lo que falta
mkdir -p "$W/engagements/previo"; printf 'mis notas, no tocar\n' > "$W/engagements/previo/notes.md"
SHA_BEFORE="$(sha256sum "$W/engagements/previo/notes.md")"
pane_start
answer "Elige" "n" && answer "Nombre:" "previo" && answer "Objetivos" "192.0.2.50" && answer "¿Dónde nacen" ""
pcheck "AC10 el lanzador sigue hasta arrancar Pi" 'ran'
check "AC10 notes.md queda byte a byte igual" '[ "$(sha256sum "$W/engagements/previo/notes.md")" = "$SHA_BEFORE" ]'
check "AC10 se agregan los archivos que faltaban" 'P="$(ws_dir previo)"; [ -f "$P/scope.txt" ] && [ -f "$P/AUTHORIZATION.md" ] && [ -f "$P/loot/creds.md" ] && [ -d "$P/scripts" ] && [ -d "$P/canaries" ]'
pane_end

# AC11: reemplazar scope deja lo viejo como comentario fechado y no toca otros archivos
ws_new reemplazo 192.0.2.60
R="$(ws_dir reemplazo)"
others() { (cd "$R" && find . -type f ! -name scope.txt ! -path './.pi-sessions/*' -exec sha256sum {} + | sort); }
OTHERS_BEFORE="$(others)"
pane_start
answer "Elige" "reemplazo" && answer "¿Mantener este scope?" "r" && answer "Objetivos" "192.0.2.61"
pcheck "AC11 Pi arranca tras reemplazar" 'ran'
check "AC11 la entrada vieja queda como comentario fechado" 'grep -Eq "^# \(reemplazado [0-9-]+\) 192.0.2.60" "$R/scope.txt"'
check "AC11 la entrada nueva es una entrada viva" 'grep -q "^192.0.2.61" "$R/scope.txt"'
check "AC11 la entrada vieja ya no es una entrada viva" '! grep -q "^192.0.2.60" "$R/scope.txt"'
check "AC11 ningún otro archivo cambia" '[ "$(others)" = "$OTHERS_BEFORE" ]'
pane_end

# AC13: un servidor tmux cuyo entorno ya trae otro workspace/scope no contamina este arranque
PS=$((PS+1)); PSOCK="$W/panes/p$PS"; reset_run
ws_new beta2 203.0.113.99
env GEKKO_WORKSPACE=alpha GEKKO_SCOPE=/old/scope.txt tmux -S "$PSOCK" -f /dev/null new-session -d -s seed "sleep 60"
tmux -S "$PSOCK" new-window -n w -t seed "GEKKO_WORKSPACE=beta2 bash '$LAUNCH'; sleep 60"
pcheck "AC13 Pi ve el workspace elegido, no el del servidor" '[ "$(pi_env GEKKO_WORKSPACE)" = beta2 ]'
check "AC13 Pi ve el scope del workspace elegido" '[ "$(pi_env GEKKO_SCOPE)" = "$(ws_dir beta2)/scope.txt" ]'
check "AC13 el scope viejo del servidor se avisa como pisado" 'poll "tmux -S \"$PSOCK\" capture-pane -p -t seed:w | grep -q \"GEKKO_SCOPE.*pisado\""'
tmux -S "$PSOCK" kill-server 2>/dev/null

# --- REQ-WS-009: el estado del panel es de UN lanzamiento. Dos Pi vivos sobre el mismo workspace no comparten
# archivo, y lo que dejó un lanzamiento muerto se borra al lanzar (lo de uno vivo no se toca). ---
touch "$W/hold"
reset_run; env GEKKO_WORKSPACE=alpha bash "$LAUNCH" </dev/null >/dev/null 2>&1 & L1=$!
poll ran; P1="$(pi_env GEKKO_PANEL_STATE)"
DEAD="$W/.gekko-state/panel.alpha.999999999.json"; : > "$DEAD"; : > "$DEAD.alive"   # pid imposible: nunca vivo
case "$P1" in */.gekko-state/panel.alpha.*.json) : > "$P1" ;; esac                      # estado del lanzamiento vivo
reset_run; env GEKKO_WORKSPACE=alpha bash "$LAUNCH" </dev/null >/dev/null 2>&1 & L2=$!
poll ran; P2="$(pi_env GEKKO_PANEL_STATE)"
check "REQ-WS-009 el archivo de panel lleva el workspace y es propio del lanzamiento" 'case "$P1" in */.gekko-state/panel.alpha.*.json) true ;; *) false ;; esac'
check "REQ-WS-009 dos Pi vivos sobre el mismo workspace publican en archivos distintos" '[ -n "$P1" ] && [ -n "$P2" ] && [ "$P1" != "$P2" ]'
check "REQ-WS-009 lo de un lanzamiento muerto se borra al lanzar" '[ ! -e "$DEAD" ] && [ ! -e "$DEAD.alive" ]'
check "REQ-WS-009 el estado de un lanzamiento vivo no se toca" 'case "$P1" in */.gekko-state/panel.alpha.*.json) [ -e "$P1" ] ;; *) false ;; esac'
rm -f "$W/hold" "$DEAD" "$DEAD.alive"; wait "$L1" "$L2" 2>/dev/null
case "$P1" in */.gekko-state/panel.alpha.*.json) rm -f "$P1" ;; esac

# --- Espejo de shells (spec 011): el lanzador DENTRO de tmux espera a Pi, marca su sesión, instala los atajos
# sin prefijo y al salir barre ventanas espejo muertas y devuelve todo. Servidores propios en $W/panes. ---
KS="$W/panes/k1"; KN="$W/panes/kn"; KC="$W/panes/kc"
ks() { tmux -S "$KS" "$@"; }
kn() { tmux -S "$KN" "$@"; }
win_of() { ks display-message -p -t "$1" '#{window_id}'; }                      # ventana activa de una sesión
client_of() { ks list-clients -t "$1" -F '#{client_name}' | head -1; }
mark_is_launcher() { [[ "$1" =~ ^[0-9]+$ ]] && tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | grep -q 'pi-hitl\.sh'; }   # la marca es el pid de un lanzador vivo
press() { ks send-keys -K -c "$(client_of "$1")" "$2"; sleep 0.3; }            # tecla por la tabla root de un cliente real
reset_run; rm -f "$W/rc"; touch "$W/hold"
tmux -S "$KS" -f /dev/null new-session -d -s main -x 200 -y 50 "sleep 120"
ks new-session -d -s other -x 100 -y 30 "cat -v"
ks new-window -d -t other "sleep 120"
ks bind-key -n F2 display-message prev
KEYS_BEFORE="$(ks list-keys -T root)"
DEAD_WIN="$(ks new-window -d -P -F '#{window_id}' -t main "sleep 120")"; ks set-option -w -t "$DEAD_WIN" @gekko_mirror 999999999
LIVE_WIN="$(ks new-window -d -P -F '#{window_id}' -t main "sleep 120")"; ks set-option -w -t "$LIVE_WIN" @gekko_mirror "$$"
kn -f /dev/null new-session -d -s c1 -x 100 -y 30 "env TMUX= tmux -S '$KS' attach -t main"
kn new-session -d -s c2 -x 100 -y 30 "env TMUX= tmux -S '$KS' attach -t other"
ks new-window -t main -n w "GEKKO_WORKSPACE=alpha bash '$LAUNCH'; echo \$? > '$W/rc'; sleep 60"
pcheck "AC9 la sesión del lanzador queda marcada @gekko_pi mientras corre Pi" 'ran && mark_is_launcher "$(ks show-options -qv -t main @gekko_pi)" && [ -n "$(client_of main)" ] && [ -n "$(client_of other)" ]'
LAUNCH_WIN="$(win_of main)"
press main S-Right; AWAY1="$(win_of main)"
check "AC9 Shift+→ en la sesión marcada cambia de ventana" '[ "$AWAY1" != "$LAUNCH_WIN" ]'
press main S-Left
check "AC9 Shift+← en la sesión marcada vuelve a la ventana de Pi" '[ "$AWAY1" != "$LAUNCH_WIN" ] && [ "$(win_of main)" = "$LAUNCH_WIN" ]'
press main F3; AWAY2="$(win_of main)"
check "AC9 F3 en la sesión marcada cambia de ventana" '[ "$AWAY2" != "$LAUNCH_WIN" ]'
press main F2
check "AC9 F2 en la sesión marcada vuelve a la ventana de Pi (pisa el binding previo sólo ahí)" '[ "$AWAY2" != "$LAUNCH_WIN" ] && [ "$(win_of main)" = "$LAUNCH_WIN" ]'
OTHER_WIN="$(win_of other)"
press other S-Right
check "AC9 en una sesión sin marcar la tecla NO cambia de ventana" '[ "$(win_of other)" = "$OTHER_WIN" ]'
check "AC9 en una sesión sin marcar la tecla llega intacta a la aplicación" 'poll "ks capture-pane -p -t other | grep -qF \"^[[1;2C\""'
press other F2
check "AC9 el binding previo del operador sigue como rama else (F2 sin marcar no cambia de ventana)" '[ "$(win_of other)" = "$OTHER_WIN" ] && ks list-keys -T root F2 | grep -qF "display-message prev"'
rm -f "$W/hold"
pcheck "AC9 al salir Pi el lanzador termina" '[ -f "$W/rc" ]'
check "AC9 el lanzador sale con el código de Pi (0)" '[ "$(cat "$W/rc")" = 0 ]'
check "AC9 al salir, list-keys -T root queda byte a byte como antes" '[ "$(ks list-keys -T root)" = "$KEYS_BEFORE" ]'
check "AC9 al salir la sesión ya no tiene @gekko_pi" '[ -z "$(ks show-options -qv -t main @gekko_pi)" ]'
check "AC6 al salir Pi se barre la ventana espejo de un pid muerto" '! ks list-windows -t main -F "#{window_id}" | grep -qxF "$DEAD_WIN"'
check "AC6 al salir Pi la ventana espejo de un pid vivo sigue abierta" 'ks list-windows -t main -F "#{window_id}" | grep -qxF "$LIVE_WIN"'
ks kill-server 2>/dev/null; kn kill-server 2>/dev/null

# REQ-TUI-025: un lanzador muerto con SIGKILL deja su marca; el siguiente en salir debe limpiarla y devolver los atajos.
# Tres lanzadores en un servidor propio: la sesión a (SIGKILL), b (salida normal) y c (salida normal, última).
KT="$W/panes/kt"
kt() { tmux -S "$KT" "$@"; }
launcher_session() { # launcher_session <sesión> <workspace>: lanza en segundo plano y anota su pid y su fin
  kt new-session -d -s "$1" -x 100 -y 30 "GEKKO_WORKSPACE=$2 bash '$LAUNCH' </dev/null & echo \$! > '$W/pid.$1'; wait \$!; touch '$W/done.$1'; sleep 60"
}
rm -f "$W/hold" "$W"/pid.* "$W"/done.*; touch "$W/hold.alpha" "$W/hold.many"
tmux -S "$KT" -f /dev/null new-session -d -s seed -x 100 -y 30 "sleep 120"
kt bind-key -n F2 display-message prev
KEYS_T="$(kt list-keys -T root)"
launcher_session a alpha; launcher_session b many
pcheck "TUI-025 cada sesión queda marcada con el pid de su lanzador" '[ "$(kt show-options -qv -t a @gekko_pi)" = "$(cat "$W/pid.a" 2>/dev/null)" ] && [ "$(kt show-options -qv -t b @gekko_pi)" = "$(cat "$W/pid.b" 2>/dev/null)" ] && mark_is_launcher "$(cat "$W/pid.a")" && [ "$(kt list-keys -T root)" != "$KEYS_T" ]'
rm -f "$W/hold.many"
pcheck "TUI-025 b sale normalmente" '[ -f "$W/done.b" ]'
check "TUI-025 con a vivo los atajos siguen instalados y a sigue marcada" '[ "$(kt list-keys -T root)" != "$KEYS_T" ] && [ -n "$(kt show-options -qv -t a @gekko_pi)" ] && [ -z "$(kt show-options -qv -t b @gekko_pi)" ]'
PID_A="$(cat "$W/pid.a")"; kill -9 "$PID_A"; rm -f "$W/hold.alpha"
check "TUI-025 a murió por SIGKILL y su sesión conserva la marca" '! kill -0 "$PID_A" 2>/dev/null && [ "$(kt show-options -qv -t a @gekko_pi)" = "$PID_A" ]'
launcher_session c beta2
pcheck "TUI-025 c sale normalmente" '[ -f "$W/done.c" ]'
pcheck "TUI-025 tras salir c, list-keys -T root queda byte a byte como antes" '[ "$(kt list-keys -T root)" = "$KEYS_T" ]'
check "TUI-025 la marca huérfana de a se limpió" '[ -z "$(kt show-options -qv -t a @gekko_pi)" ]'
kt kill-server 2>/dev/null; rm -f "$W/hold.alpha" "$W/hold.many" "$W"/pid.* "$W"/done.*

# T13: el lanzador limpia también cuando lo cierran de golpe (sesión tmux cerrada = SIGHUP al grupo, SIGHUP o SIGTERM
# directos). Servidor propio con otra sesión para que sobreviva; el pi falso se sostiene y se suelta después.
KG="$W/panes/kg"
kg() { tmux -S "$KG" "$@"; }
signal_case() { # signal_case <nombre> <kill-session|HUP|TERM> <rc esperado o vacío>
  local n="$1" action="$2" want="$3" pid
  rm -f "$W/hold" "$W"/pid.* "$W"/rc.*; touch "$W/hold.alpha"
  tmux -S "$KG" -f /dev/null new-session -d -s seed -x 100 -y 30 "sleep 120"
  kg bind-key -n F2 display-message prev
  local keys_before; keys_before="$(kg list-keys -T root)"
  kg new-session -d -s s -x 100 -y 30 "GEKKO_WORKSPACE=alpha bash '$LAUNCH' </dev/null & echo \$! > '$W/pid.s'; wait \$!; echo \$? > '$W/rc.s'; sleep 60"
  pcheck "T13 $n: el lanzador marca su sesión e instala los atajos" '[ "$(kg show-options -qv -t s @gekko_pi)" = "$(cat "$W/pid.s" 2>/dev/null)" ] && [ "$(kg list-keys -T root)" != "$keys_before" ]'
  pid="$(cat "$W/pid.s")"
  case "$action" in
    kill-session) kg kill-session -t s ;;
    *) kill -"$action" "$pid" ;;
  esac
  rm -f "$W/hold.alpha"
  pcheck "T13 $n: el lanzador termina" '! kill -0 "$pid" 2>/dev/null'
  pcheck "T13 $n: list-keys -T root queda byte a byte como antes" '[ "$(kg list-keys -T root)" = "$keys_before" ]'
  check "T13 $n: ninguna sesión conserva @gekko_pi" '! kg list-sessions -F "#{@gekko_pi}" | grep -q .'
  [ -z "$want" ] || check "T13 $n: sale con el código convencional $want" '[ "$(cat "$W/rc.s" 2>/dev/null)" = "$want" ]'
  kg kill-server 2>/dev/null; rm -f "$W"/pid.* "$W"/rc.*
}
signal_case "cierre de la sesión tmux" kill-session ""
signal_case "SIGTERM" TERM 143
signal_case "SIGHUP" HUP 129

# el código de Pi se propaga también dentro de tmux (antes `exec`, ahora hijo + espera)
rm -f "$W/rc"; echo 7 > "$W/pi-rc"
tmux -S "$KC" -f /dev/null new-session -d -s t -x 200 -y 50 "GEKKO_WORKSPACE=alpha bash '$LAUNCH'; echo \$? > '$W/rc'; sleep 60"
pcheck "Regresión: dentro de tmux el lanzador propaga el código de salida de Pi" '[ "$(cat "$W/rc" 2>/dev/null)" = 7 ]'
tmux -S "$KC" kill-server 2>/dev/null; rm -f "$W/pi-rc"

# Relanzamiento en tmux: lanzador FUERA de tmux con TTY (pty) -> el pi falso recibe el workspace y el
# servidor tmux (nacido del relanzamiento) NO lo guarda en su entorno global.
reset_run; touch "$W/hold"
GEKKO_WORKSPACE=alpha GEKKO_SIDEBAR=1 GEKKO_MOUSE=0 GEKKO_TMUX_THEME=0 python3 -I - "$LAUNCH" <<'PY' >/dev/null 2>&1 &
import fcntl, os, pty, select, struct, sys, termios, time
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm"
    os.execvp("bash", ["bash", sys.argv[1]])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 200, 0, 0))
end = time.time() + 40
while time.time() < end:
    ready, _, _ = select.select([fd], [], [], 0.5)
    if ready:
        try:
            if not os.read(fd, 65536):
                break
        except OSError:
            break
try:
    os.kill(pid, 9)
except ProcessLookupError:
    pass
PY
PTY_PID=$!
pcheck "Relanzamiento: el pi falso corre dentro de tmux con el workspace elegido" '[ "$(pi_env GEKKO_WORKSPACE)" = alpha ]'
check "Relanzamiento: el scope es el del workspace" '[ "$(pi_env GEKKO_SCOPE)" = "$(ws_dir alpha)/scope.txt" ]'
check "Relanzamiento: ocurrió dentro de tmux (TMUX presente)" 'pi_has TMUX'
check "Relanzamiento: el entorno GLOBAL del servidor tmux no contiene GEKKO_WORKSPACE" 'tmux show-environment -g >/dev/null 2>&1 && ! tmux show-environment -g | grep -q "^GEKKO_WORKSPACE"'
# REQ-WS-009: el rail lee el archivo que publica SU Pi, también cuando lo reabre el hook de redimensionado
# (el hook corre desde el servidor tmux, que no hereda el entorno de Pi).
PSTATE="$(pi_env GEKKO_PANEL_STATE)"
rail() { tmux list-panes -a -F "#{@gekko_sidebar} #{$1}" 2>/dev/null | sed -n 's/^1 //p' | head -1; }
pcheck "REQ-WS-009 el rail lee el mismo archivo que publica su Pi" '[ -n "$PSTATE" ] && rail pane_start_command | grep -qF "$PSTATE"'
RWIN="$(rail window_id)"
tmux kill-pane -t "$(rail pane_id)" 2>/dev/null
tmux resize-window -t "$RWIN" -x 180 -y 50 2>/dev/null
pcheck "REQ-WS-009 el rail reabierto por el redimensionado sigue leyendo ese archivo" '[ -n "$PSTATE" ] && rail pane_start_command | grep -qF "$PSTATE"'
rm -f "$W/hold"
wait "$PTY_PID" 2>/dev/null

# Spec 013: launcher wiring with local Docker/ACL doubles.
cat > "$W/bin/docker" <<'DOCKER'
#!/bin/bash
printf '%s\n' "$*" >> "$GEKKO_WS_ROOT/docker-calls"
TBX_ID="${TBX_ID:-$(printf 'ab%.0s' $(seq 1 32))}"
case "$1" in
  version) [ "${TBX_DOCKER_MISSING:-0}" = 0 ] || { echo ENOENT >&2; exit 127; }; [ "${TBX_DOCKER_FAIL:-0}" = 0 ] || { echo "daemon unavailable" >&2; exit 1; }; echo 29 ;;
  image) [ "${TBX_IMAGE_MISSING:-0}" = 0 ] || exit 1; echo sha256:test ;;
  inspect)
    if [ "${4:-}" = "--format" ]; then # consulta del aviso de salida del lanzador (REQ-WS-012)
      case "${TBX_EXIT:-stopped}" in absent) exit 1 ;; hang) exec sleep 30 ;; running) echo true ;; *) echo false ;; esac
      exit 0
    fi
    case "${TBX_STATE:-absent}" in
      absent) echo 'Error: No such object' >&2; exit 1 ;;
      refuse) echo '[{"State":{"Running":true},"Mounts":[]}]' ;;
      stopped|running)
        running=false; [ "$TBX_STATE" = running ] && running=true
        ws="$GEKKO_WS_ROOT/engagements/boxed"
        ro() { printf ',{"Type":"bind","Propagation":"rprivate","Source":"%s","Destination":"%s","RW":false}' "$1" "$1"; }
        cat <<JSON
[{"Id":"$TBX_ID","Image":"sha256:test","NetworkSettings":{"Networks":{"bridge":{}}},"Config":{"Cmd":["sleep","infinity"],"Entrypoint":null,"User":""},"HostConfig":{"NetworkMode":"bridge","Privileged":false,"Init":true,"CapAdd":["CAP_NET_ADMIN"],"CapDrop":["CAP_MKNOD"],"Devices":[{"PathOnHost":"/dev/net/tun","PathInContainer":"/dev/net/tun","CgroupPermissions":"rwm"}],"PidMode":"","IpcMode":"private","UsernsMode":"","SecurityOpt":null,"PortBindings":{},"PublishAllPorts":false,"ExtraHosts":null,"Dns":null,"DeviceRequests":null,"RestartPolicy":{"Name":"no"}},"State":{"Running":$running},"Mounts":[{"Type":"bind","Propagation":"rprivate","Source":"$ws","Destination":"$ws","RW":true}$(ro "$ws/exec")$(ro "$ws/scope.txt")$(ro "$ws/AUTHORIZATION.md"),{"Type":"tmpfs","Propagation":"","Source":"","Destination":"$ws/.pi-sessions","RW":true}$(ro "$GEKKO_WS_ROOT/.claude/tools")]}]
JSON
        ;;
    esac ;;
  run) [ -d "$GEKKO_WS_ROOT/engagements/${TBX_RUN_WS:-boxed}/.pi-sessions" ] && echo yes > "$GEKKO_WS_ROOT/sessions-dir-at-run"; echo "$TBX_ID" ;;
  start) echo "$2" ;;
  *) exit 1 ;;
esac
DOCKER
printf '#!/bin/sh\n[ "${TBX_ACL_FAIL:-0}" = 0 ] || exit 1\nexit 0\n' > "$W/bin/setfacl"
chmod +x "$W/bin/docker" "$W/bin/setfacl"
TBX_FAKE_ID="$(printf 'ab%.0s' $(seq 1 32))"
ws_new boxed --exec toolbox 192.0.2.20
TBX_STATE=stopped node --no-warnings --experimental-strip-types "$REPO/toolbox/gekko-workspace.ts" new clash 192.0.2.30 >/dev/null 2>"$W/err"; RC=$?
check "TBX-013 CLI new: con gekko-tb-<nombre> existente sale ≠ 0, no crea el workspace y dice cómo borrarlo" '[ "$RC" -ne 0 ] && [ ! -e "$(ws_dir clash)" ] && grep -q "docker rm -f gekko-tb-clash" "$W/err"'
TBX_STATE=running ws_new boxed --exec toolbox 192.0.2.20
check "TBX-013 CLI new sobre un workspace existente con su contenedor sigue funcionando" '[ $? -eq 0 ] && [ -f "$(ws_dir boxed)/scope.txt" ]'
launch_plain GEKKO_WORKSPACE=boxed GEKKO_TMUX_DIR=/tmp/foreign-sockets TBX_EXIT=running
check "TBX launcher: toolbox exportado" '[ "$RC" = 0 ] && [ "$(pi_env GEKKO_EXEC)" = toolbox ] && [ "$(pi_env GEKKO_TOOLBOX)" = "$TBX_FAKE_ID" ]'
check "TBX L6: GEKKO_TOOLBOX es el ID validado, no el nombre" '[[ "$(pi_env GEKKO_TOOLBOX)" =~ ^[0-9a-f]{64}$ ]]'
check "TBX AC6: banner y prompt explican toolbox y bash host" 'grep -Eq "shells[[:space:]]+toolbox \(al lanzar\) gekko-tb-boxed" "$W/err" && grep -q "INSIDE the container" "$RUN/prompt.md" && grep -q "bash.*HOST" "$RUN/prompt.md"'
check "TBX launcher: sockets dentro del workspace" '[ "$(pi_env GEKKO_TMUX_DIR)" = "$(ws_dir boxed)/.gekko-sockets" ]'
check "TBX launcher: contenedor creado" 'grep -q "^run .*gekko-tb-boxed" "$W/docker-calls"'
check "TBX launcher: aviso al salir" 'grep -q "apagar: docker rm -f gekko-tb-boxed" "$W/err"'
check "TBX H2: .pi-sessions existía en el host cuando se creó el contenedor y Pi usa esa ruta" '[ -f "$W/sessions-dir-at-run" ] && [ "$(pi_env PI_CODING_AGENT_SESSION_DIR)" = "$(ws_dir boxed)/.pi-sessions" ]'
check "TBX H2/M3: run enmascara .pi-sessions con tmpfs y monta exec, scope.txt y AUTHORIZATION.md de sólo lectura" 'grep -q -- "--mount type=tmpfs,destination=$W/engagements/boxed/.pi-sessions" "$W/docker-calls" && for f in exec scope.txt AUTHORIZATION.md; do grep -q -- "-v $W/engagements/boxed/$f:$W/engagements/boxed/$f:ro" "$W/docker-calls" || exit 1; done'
check "TBX launcher: run monta workspace rw y tools ro" 'grep -q -- "-v $W/engagements/boxed:$W/engagements/boxed" "$W/docker-calls" && grep -q -- "-v $W/.claude/tools:$W/.claude/tools:ro" "$W/docker-calls"'
pane_start
answer "Elige" "n" && answer "Nombre:" "boxedmenu" && answer "Objetivos" "192.0.2.21" && answer "¿Dónde nacen" "toolbox"
pcheck "TBX menú: toolbox se guarda y Pi recibe el modo" '[ "$(cat "$(ws_dir boxedmenu)/exec")" = toolbox ] && [ "$(pi_env GEKKO_EXEC)" = toolbox ]'
pane_end
ws_new boxedmenu --exec toolbox 192.0.2.21
launch_plain GEKKO_WORKSPACE=boxedmenu
check "TBX modo guardado: toolbox sin preguntar" '[ "$RC" = 0 ] && [ "$(pi_env GEKKO_EXEC)" = toolbox ]'
: > "$W/docker-calls"
launch_plain GEKKO_WORKSPACE=boxed TBX_STATE=running
check "TBX contenedor running: se reutiliza sin run/start" '[ "$RC" = 0 ] && ! grep -Eq "^(run|start) " "$W/docker-calls"'
: > "$W/docker-calls"
launch_plain GEKKO_WORKSPACE=boxed TBX_STATE=stopped
check "TBX contenedor stopped: se inicia por ID" '[ "$RC" = 0 ] && grep -q "^start $TBX_FAKE_ID$" "$W/docker-calls"'
launch_plain GEKKO_WORKSPACE=boxed TBX_STATE=running GEKKO_OVPN=relativo.ovpn
check "TBX GEKKO_OVPN relativo: falla antes de Pi" '[ "$RC" != 0 ] && ! ran && grep -q "ruta absoluta" "$W/err"'
launch_plain GEKKO_WORKSPACE=boxed TBX_STATE=refuse
check "TBX montajes ajenos: rehúsa y Pi no arranca" '[ "$RC" != 0 ] && ! ran && grep -q "otros montajes" "$W/err"'
launch_plain GEKKO_WORKSPACE=boxed TBX_IMAGE_MISSING=1
check "TBX imagen ausente: falla antes de Pi y nombra build" '[ "$RC" != 0 ] && ! ran && grep -q "make -C toolbox build" "$W/err"'
launch_plain GEKKO_WORKSPACE=boxed TBX_ACL_FAIL=1
check "TBX ACL fallida: falla antes de Docker run y Pi" '[ "$RC" != 0 ] && ! ran && ! grep -q "^run " "$W/docker-calls"'
mkdir -p "$W/no-docker-bin"
for cmd in bash pi node tmux python3 grep head sed git dirname mkdir chmod; do ln -sf "$(command -v "$cmd")" "$W/no-docker-bin/$cmd"; done
reset_run; env GEKKO_WORKSPACE=boxed PATH="$W/no-docker-bin" bash "$LAUNCH" </dev/null >"$W/out" 2>"$W/err"; RC=$?
check "TBX Docker ausente real en PATH: falla antes de Pi" '[ "$RC" != 0 ] && ! ran && grep -q "docker no está instalado" "$W/err"'
: > "$W/docker-calls"
launch_plain GEKKO_WORKSPACE=alpha GEKKO_EXEC=toolbox GEKKO_TOOLBOX=foreign
check "TBX modo OS: no usa Docker y descarta entorno toolbox" '[ "$RC" = 0 ] && [ "$(pi_env GEKKO_EXEC)" = os ] && ! pi_has GEKKO_TOOLBOX && ! grep -qv -- "--format" "$W/docker-calls"'
check "TBX AC6: banner y prompt explican modo OS" 'grep -Eq "shells[[:space:]]+os" "$W/err" && grep -q "born on this host" "$RUN/prompt.md"'
launch_plain GEKKO_WORKSPACE=boxed TBX_DOCKER_FAIL=1
check "TBX launcher: Docker fallido impide Pi" '[ "$RC" != 0 ] && ! ran'
printf 'invalid\n' > "$(ws_dir boxed)/exec"
launch_plain GEKKO_WORKSPACE=boxed
check "TBX launcher: modo inválido impide Pi" '[ "$RC" != 0 ] && ! ran'
rm -f "$(ws_dir boxed)/exec"; ln -s "$(ws_dir alpha)/scope.txt" "$(ws_dir boxed)/exec"
launch_plain GEKKO_WORKSPACE=boxed
check "TBX M3: exec enlace simbólico impide Pi" '[ "$RC" != 0 ] && ! ran && grep -q "enlace simbólico" "$W/err"'
rm -f "$(ws_dir boxed)/exec"; mkfifo "$(ws_dir boxed)/exec"
launch_plain GEKKO_WORKSPACE=boxed
check "TBX M3: exec FIFO impide Pi sin quedarse leyendo" '[ "$RC" != 0 ] && ! ran'
rm -f "$(ws_dir boxed)/exec"; printf 'toolbox\n' > "$(ws_dir boxed)/exec"
launch_plain GEKKO_WORKSPACE=boxed TBX_STATE=running
check "TBX L9: el prompt sale del modo ya resuelto" '[ "$RC" = 0 ] && grep -q "INSIDE the container" "$RUN/prompt.md"'

# Spec 014 (REQ-WS-011, REQ-WS-012, AC11, AC19, AC20): enlace simbólico, aviso de salida, banner, modo guardado.
ln -s "$(ws_dir beta)" "$W/engagements/linked"
launch_plain GEKKO_WORKSPACE=linked
check "WS-011 un workspace que es enlace simbólico: el lanzador falla antes de Pi y dice reemplazarlo" '[ "$RC" != 0 ] && ! ran && grep -q "enlace simbólico" "$W/err"'
rm -f "$W/engagements/linked"

# Aviso de salida FUERA de tmux (launch_plain no tiene terminal): lo decide `docker inspect` al salir, no el modo.
NOTICE='contenedor activo: gekko-tb-boxed; apagar: docker rm -f gekko-tb-boxed'
launch_plain GEKKO_WORKSPACE=boxed TBX_STATE=running TBX_EXIT=running
check "WS-012 fuera de tmux, toolbox con el contenedor en marcha: avisa" '[ "$RC" = 0 ] && grep -qF "$NOTICE" "$W/err"'
launch_plain GEKKO_WORKSPACE=boxed TBX_STATE=running TBX_EXIT=stopped
check "WS-012 fuera de tmux, contenedor detenido al salir: no avisa" '[ "$RC" = 0 ] && ! grep -q "contenedor activo" "$W/err"'
launch_plain GEKKO_WORKSPACE=boxed TBX_STATE=running TBX_EXIT=absent
check "WS-012 fuera de tmux, contenedor inexistente al salir: no avisa" '[ "$RC" = 0 ] && ! grep -q "contenedor activo" "$W/err"'
launch_plain GEKKO_WORKSPACE=alpha TBX_EXIT=running
check "WS-012 fuera de tmux, lanzado en os pero con el contenedor levantado en vivo: avisa por el estado, no por el modo" '[ "$RC" = 0 ] && [ "$(pi_env GEKKO_EXEC)" = os ] && grep -qF "gekko-tb-alpha; apagar: docker rm -f gekko-tb-alpha" "$W/err"'
: > "$W/docker-calls"
launch_plain GEKKO_WORKSPACE=none TBX_EXIT=running
check "WS-012 sin workspace (none): no consulta docker ni avisa" '[ "$RC" = 0 ] && ! grep -q "contenedor activo" "$W/err" && ! grep -q -- "--format" "$W/docker-calls"'
reset_run; start=$SECONDS; env GEKKO_WORKSPACE=alpha TBX_EXIT=hang bash "$LAUNCH" </dev/null >"$W/out" 2>"$W/err"; RC=$?
check "WS-012 un docker colgado no cuelga la salida (plazo) ni avisa" '[ "$RC" = 0 ] && [ $((SECONDS - start)) -lt 15 ] && ! grep -q "contenedor activo" "$W/err"'
mkdir -p "$W/no-docker-bin2"
for cmd in bash pi node tmux python3 grep head sed git dirname mkdir chmod cat rm env sort tr date timeout awk uname mktemp ls id cp touch; do c="$(command -v "$cmd")" && ln -sf "$c" "$W/no-docker-bin2/$cmd"; done
reset_run; env GEKKO_WORKSPACE=alpha PATH="$W/no-docker-bin2" bash "$LAUNCH" </dev/null >"$W/out" 2>"$W/err"; RC=$?
check "WS-012 sin binario docker: lanza, sale 0 y no imprime aviso ni error" '[ "$RC" = 0 ] && ran && ! grep -q "contenedor activo" "$W/err" && ! grep -qi "docker" "$W/err"'
echo 7 > "$W/pi-rc"
launch_plain GEKKO_WORKSPACE=alpha TBX_EXIT=running
check "WS-012 fuera de tmux en os (sin exec): el código de salida de Pi se conserva y el aviso sale" '[ "$RC" = 7 ] && grep -q "contenedor activo" "$W/err"'
launch_plain GEKKO_WORKSPACE=boxed TBX_STATE=running TBX_EXIT=running
check "WS-012 fuera de tmux en toolbox: el código de salida de Pi se conserva" '[ "$RC" = 7 ]'
rm -f "$W/pi-rc"

# Aviso de salida DENTRO de tmux: antes lo tapaba `exec >/dev/null` de cleanup_after_pi.
tmux_notice_case() { # nombre workspace TBX_EXIT esperado(1 = debe avisar)
  NOTICE_WS="$2"; rm -f "$W/rc.n" "$W/err.n"
  tmux -S "$KC" -f /dev/null new-session -d -s n -x 200 -y 50 "GEKKO_WORKSPACE=$2 TBX_EXIT=$3 bash '$LAUNCH' 2>'$W/err.n'; echo \$? > '$W/rc.n'; sleep 30"
  pcheck "WS-012 dentro de tmux ($1): el lanzador termina" '[ -f "$W/rc.n" ]'
  if [ "$4" = 1 ]; then check "WS-012 dentro de tmux ($1): avisa" 'grep -qF "contenedor activo: gekko-tb-$NOTICE_WS; apagar: docker rm -f gekko-tb-$NOTICE_WS" "$W/err.n"'
  else check "WS-012 dentro de tmux ($1): no avisa" '! grep -q "contenedor activo" "$W/err.n"'; fi
  tmux -S "$KC" kill-server 2>/dev/null
}
echo 7 > "$W/pi-rc"
tmux_notice_case "toolbox en marcha" boxed running 1
check "WS-012 dentro de tmux: el código de Pi se conserva junto al aviso" '[ "$(cat "$W/rc.n")" = 7 ]'
rm -f "$W/pi-rc"
tmux_notice_case "toolbox detenido" boxed stopped 0
tmux_notice_case "os con contenedor levantado en vivo" alpha running 1

# AC11: el modo guardado en `exec` (lo que escribe writeExecMode) manda en el siguiente lanzamiento, sin preguntar.
save_mode() { WM_MODULE="$REPO/toolbox/gekko-workspace.ts" WM_DIR="$(ws_dir boxed)" WM_MODE="$1" node --no-warnings --experimental-strip-types -e 'import(process.env.WM_MODULE).then((m) => m.writeExecMode(process.env.WM_DIR, process.env.WM_MODE))'; }
save_mode os
launch_plain GEKKO_WORKSPACE=boxed
check "AC11 un modo guardado como os: el lanzamiento arranca en os sin preguntar ni tocar docker" '[ "$RC" = 0 ] && [ "$(pi_env GEKKO_EXEC)" = os ] && ! pi_has GEKKO_TOOLBOX'
check "AC20 el banner dice que el modo es el del lanzamiento" 'grep -Eq "^ +shells +os \(al lanzar\)" "$W/err"'
save_mode toolbox
launch_plain GEKKO_WORKSPACE=boxed TBX_STATE=running
check "AC11 un modo guardado como toolbox: el lanzamiento arranca en toolbox sin preguntar" '[ "$RC" = 0 ] && [ "$(pi_env GEKKO_EXEC)" = toolbox ] && [[ "$(pi_env GEKKO_TOOLBOX)" =~ ^[0-9a-f]{64}$ ]] && ! grep -q "Elige" "$W/err" "$W/out"'

# T11: setup detecta deps opcionales sin instalar ni configurar Pi (--check-only).
mkdir -p "$W/setup-bin"
for cmd in node npm tmux git python3 grep head sed dirname; do ln -sf "$(command -v "$cmd")" "$W/setup-bin/$cmd"; done
GEKKO_SETUP_CHECK_ONLY=1 PATH="$W/setup-bin" /bin/bash "$REPO/setup.sh" > "$W/setup.out" 2>&1; SETUP_RC=$?
check "T11 setup: Docker/setfacl faltantes no bloquean OS y se avisan" '[ "$SETUP_RC" = 0 ] && grep -q "modo OS disponible; modo toolbox requiere: docker setfacl" "$W/setup.out"'
ln -sf "$(command -v docker)" "$W/setup-bin/docker"
GEKKO_SETUP_CHECK_ONLY=1 PATH="$W/setup-bin" /bin/bash "$REPO/setup.sh" > "$W/setup.out" 2>&1; SETUP_RC=$?
check "T11 setup: avisa que setfacl sólo hace falta en toolbox" '[ "$SETUP_RC" = 0 ] && grep -q "modo toolbox requiere: setfacl" "$W/setup.out"'

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
