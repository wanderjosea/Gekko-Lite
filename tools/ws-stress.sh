#!/usr/bin/env bash
# Estrés del lanzador (spec 010) con un `pi` falso. Todo aislado en un directorio temporal: raíz de workspaces,
# tmux, config de Pi y credenciales. Sin red (IPs de documentación). Uso: bash tools/ws-stress.sh
set -uo pipefail
REPO="${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"; W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
PASS=0; FAIL=0
ok() { if eval "$2" >/dev/null 2>&1; then PASS=$((PASS+1)); echo "[ok]   $1"; else FAIL=$((FAIL+1)); echo "[FAIL] $1"; fi; }
unset TMUX TMUX_PANE GEKKO_WORKSPACE GEKKO_WORKSPACE_DIR GEKKO_SCOPE GEKKO_FINDINGS GEKKO_PI_SESSION_DIR GEKKO_MODEL GEKKO_PROVIDER GEKKO_PROVIDER_KEY GEKKO_PANEL_STATE
mkdir -p "$W/tmux" "$W/bin" "$W/runs" "$W/cfg"; : > "$W/empty.env"
export GEKKO_WS_ROOT="$W" TMUX_TMPDIR="$W/tmux" GEKKO_TMUX_DIR="$W/sockets" PI_CODING_AGENT_DIR="$W/cfg" GEKKO_HITL_ENV="$W/empty.env" GEKKO_CRED_ENV="$W/empty.env"
export GEKKO_LLM_URL="http://192.0.2.1:8080/v1" GEKKO_LLM_KEY="dummy" GEKKO_MODEL="m-test" GEKKO_SIDEBAR=0 PATH="$W/bin:$PATH"
# pi falso: un volcado por lanzamiento; espera 0.4 s ANTES de leer el prompt para que una carrera se note
cat > "$W/bin/pi" <<EOF
#!/bin/sh
[ "\$1" = "--version" ] && { echo "0.0.0"; exit 0; }
d="$W/runs/\${GEKKO_WORKSPACE:-unset}.\$\$"; mkdir -p "\$d"
env | sort > "\$d/env.txt"
sleep 0.4
prev=""; for a in "\$@"; do [ "\$prev" = "--append-system-prompt" ] && cp -- "\$a" "\$d/prompt.md"; prev="\$a"; done
touch "\$d/ran"
EOF
chmod +x "$W/bin/pi"
CLI=(node --no-warnings --experimental-strip-types "$REPO/toolbox/gekko-workspace.ts")
launch() { env GEKKO_WORKSPACE="$1" bash "$REPO/tools/pi-hitl.sh" </dev/null >"$W/out.$1.$RANDOM" 2>&1; }
val() { sed -n "s/^$2=//p" "$1/env.txt"; }

echo "== 1. 150 workspaces"
t0=$(date +%s.%N)
for i in $(seq 1 150); do "${CLI[@]}" new "ws-$(printf %03d "$i")" "198.51.100.$((i % 250 + 1))" >/dev/null 2>&1 || echo "new falló $i"; done
t1=$(date +%s.%N)
ok "150 workspaces creados ($(printf %.1f "$(echo "$t1 - $t0" | bc)") s)" '[ "$(ls "$W/engagements" | wc -l)" = 150 ]'
menu="$("${CLI[@]}" pick </dev/null 2>&1 || true)"
ok "el menú lista los 150 y la opción nuevo" '[ "$(printf "%s\n" "$menu" | grep -cE "^ +[0-9]+\) ws-")" = 150 ] && printf "%s\n" "$menu" | grep -q "n) nuevo"'
ok "elegir por número (150) funciona" '[ "$(printf "150\n\n" | "${CLI[@]}" pick 2>/dev/null)" = "ws-150" ]'

echo "== 2. 30 lanzamientos seguidos alternando 3 workspaces"
bad=0
for i in $(seq 1 30); do
  n="ws-00$((i % 3 + 1))"; rm -rf "$W/runs"; mkdir -p "$W/runs"; launch "$n"
  d="$(ls -d "$W/runs/$n".* 2>/dev/null | head -1)"; D="$W/engagements/$n"
  { [ -n "$d" ] && [ "$(val "$d" GEKKO_SCOPE)" = "$D/scope.txt" ] && [ "$(val "$d" GEKKO_FINDINGS)" = "$D/findings.jsonl" ] \
    && [ "$(val "$d" PI_CODING_AGENT_SESSION_DIR)" = "$D/.pi-sessions" ] && [ "$(val "$d" GEKKO_WORKSPACE_DIR)" = "$D" ] \
    && grep -qF "$D" "$d/prompt.md" && [ "$(grep -c "engagements/ws-" "$d/prompt.md")" = 1 ]; } || bad=$((bad+1))
done
ok "30/30 con scope, hallazgos, sesiones y prompt de SU workspace (fallos: $bad)" '[ "$bad" = 0 ]'

echo "== 3. 12 lanzamientos SIMULTÁNEOS de 12 workspaces distintos"
rm -rf "$W/runs"; mkdir -p "$W/runs"
for i in $(seq 10 21); do launch "ws-0$i" & done; wait
bad=0; n=0
for d in "$W"/runs/*; do
  n=$((n+1)); name="$(val "$d" GEKKO_WORKSPACE)"; D="$W/engagements/$name"
  { [ "$(val "$d" GEKKO_SCOPE)" = "$D/scope.txt" ] && [ "$(val "$d" PI_CODING_AGENT_SESSION_DIR)" = "$D/.pi-sessions" ] \
    && grep -qF "\`$D\`" "$d/prompt.md" && [ "$(grep -c "engagements/ws-" "$d/prompt.md")" = 1 ]; } || { bad=$((bad+1)); echo "   cruzado: $name → $(grep -o "engagements/ws-[0-9]*" "$d/prompt.md" | head -1)"; }
done
ok "12 corridas registradas" '[ "$n" = 12 ]'
ok "ninguna recibió el entorno o el prompt de otro workspace (cruces: $bad)" '[ "$bad" = 0 ]'
ok "el último usado es uno de los lanzados" 'grep -qE "^ws-0(1[0-9]|2[01])$" "$W/.gekko-state/last-workspace"'

echo "== 4. El mismo workspace 8 veces a la vez"
rm -rf "$W/runs"; mkdir -p "$W/runs"
for i in $(seq 1 8); do launch "ws-050" & done; wait
ok "8/8 arrancaron y vieron ws-050" '[ "$(ls -d "$W"/runs/ws-050.* | wc -l)" = 8 ] && [ "$(cat "$W"/runs/*/env.txt | grep -c "^GEKKO_WORKSPACE=ws-050$")" = 8 ]'

echo "== 5. Valores hostiles en GEKKO_WORKSPACE (sin terminal)"
rm -rf "$W/runs"; mkdir -p "$W/runs"; before="$(ls "$W/engagements" | wc -l)"; bad=0
for v in '../x' 'a/b' 'none ' ' none' 'NONE' "$(printf 'x%.0s' $(seq 1 32))" '$(touch '"$W"'/pwned)' '; touch '"$W"'/pwned' '`touch '"$W"'/pwned`' '-rf' 'a b' $'a\nb' '..' '.' '~' 'ws-001/../ws-002' 'ws-001;id' 'no-existe'; do
  env GEKKO_WORKSPACE="$v" bash "$REPO/tools/pi-hitl.sh" </dev/null >/dev/null 2>&1; rc=$?
  [ "$rc" != 0 ] || { bad=$((bad+1)); echo "   aceptó: $(printf %q "$v")"; }
done
ok "18 valores hostiles: todos rechazados con código ≠ 0 (aceptados: $bad)" '[ "$bad" = 0 ]'
ok "Pi no arrancó en ninguno" '[ -z "$(ls "$W/runs")" ]'
ok "no se creó ningún workspace ni se ejecutó nada inyectado" '[ "$(ls "$W/engagements" | wc -l)" = "$before" ] && [ ! -e "$W/pwned" ]'
env -u GEKKO_WORKSPACE bash "$REPO/tools/pi-hitl.sh" </dev/null >/dev/null 2>"$W/err"; rc=$?
ok "sin variable y sin terminal: error que nombra GEKKO_WORKSPACE" '[ "$rc" != 0 ] && grep -q GEKKO_WORKSPACE "$W/err" && [ -z "$(ls "$W/runs")" ]'

echo "== 6. scope.txt con 500 entradas"
{ echo "# grande"; for i in $(seq 0 499); do echo "198.51.$((100 + i / 250)).$((i % 250 + 1))"; done; } > "$W/engagements/ws-100/scope.txt"
rm -rf "$W/runs"; mkdir -p "$W/runs"; t0=$(date +%s.%N); env GEKKO_WORKSPACE=ws-100 bash "$REPO/tools/pi-hitl.sh" </dev/null >"$W/big.out" 2>&1; rc=$?; t1=$(date +%s.%N)
ok "arranca ($(printf %.1f "$(echo "$t1 - $t0" | bc)") s) y el banner resume: 6 entradas + '+494 más'" '[ "$rc" = 0 ] && grep -q "+494 más" "$W/big.out" && [ "$(grep "^  scope" "$W/big.out" | grep -o "198\.51\.[0-9]*\.[0-9]*" | wc -l)" = 6 ]'

echo "== 7. none: sin derivaciones"
rm -rf "$W/runs"; mkdir -p "$W/runs"; launch none; d="$(ls -d "$W"/runs/none.* | head -1)"
ok "none: sin GEKKO_WORKSPACE_DIR, scope de la raíz y sesiones en .gekko-state" '! grep -q "^GEKKO_WORKSPACE_DIR=" "$d/env.txt" && [ "$(val "$d" GEKKO_SCOPE)" = "$REPO/scope.txt" ] && [ "$(val "$d" PI_CODING_AGENT_SESSION_DIR)" = "$REPO/.gekko-state/pi-sessions" ] && ! grep -q "engagements/" "$d/prompt.md"'

echo "$PASS ok, $FAIL fallos"; [ "$FAIL" = 0 ]
