#!/usr/bin/env bash
# Spec 013 D: Docker real con workspace, tools y ledger desechables. No monta el repo ni datos del operador.
set -euo pipefail
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${GEKKO_TOOLBOX_IMAGE:-gekko-toolbox:latest}"
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: Docker no está disponible"
  exit 0
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "SKIP: falta la imagen $IMAGE (construir con make -C toolbox build)"
  exit 0
fi

TMP="$(mktemp -d)"
WSNAME="tbx-test-$$"
NAME="gekko-tb-$WSNAME"
HOSTILE="gekko-013-hostile-$$"
ROOT="$TMP/root"
WS="$ROOT/engagements/$WSNAME"
TOOLS="$ROOT/.claude/tools"
PORT="$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
SERVER=""
cleanup() {
  [ -z "$SERVER" ] || { kill "$SERVER" 2>/dev/null || true; wait "$SERVER" 2>/dev/null || true; }
  docker rm -f "$NAME" "$HOSTILE" >/dev/null 2>&1 || true
  rm -rf -- "$TMP"
}
trap cleanup EXIT
FAILS=0
check() { # check "nombre" cmd...  (el comando corre en un subshell; falla = FAIL, sin cortar la corrida)
  local name="$1"; shift
  if ( set +e; "$@" ) >/dev/null 2>&1; then :; else FAILS=$((FAILS+1)); echo "FAIL: $name"; fi
}
ws_cli() { GEKKO_WS_ROOT="$ROOT" GEKKO_TOOLBOX_IMAGE="$IMAGE" node --no-warnings --experimental-strip-types "$REPO/toolbox/gekko-workspace.ts" "$@"; }

mkdir -p "$TOOLS"
cp "$REPO/.claude/tools/findings.py" "$REPO/.claude/tools/findings_web.py" "$REPO/.claude/tools/sanitize_target_content.py" "$TOOLS/"
ws_cli new "$WSNAME" --exec toolbox 192.0.2.10 >/dev/null 2>&1
mkdir -p "$WS/.pi-sessions"; chmod 700 "$WS/.pi-sessions"   # lo crea el lanzador antes del contenedor

# Camino REAL (ensureToolbox, vía el CLI `toolbox`): crea, y la segunda vez reutiliza el MISMO contenedor.
ID="$(ws_cli toolbox "$WSNAME")" || { echo "FAIL: el comando toolbox no dejó el contenedor arriba" >&2; exit 1; }
RUN_ID="$(docker inspect --type container --format '{{.Id}}' "$NAME")"   # el contenedor que existe, aunque el CLI imprima otra cosa
check "toolbox imprime el ID de 64 hex del contenedor creado" test "$ID" = "$RUN_ID"
check "segunda corrida: reutiliza el mismo contenedor (mismo ID)" test "$(ws_cli toolbox "$WSNAME")" = "$RUN_ID"
ID="$RUN_ID"
check "un solo contenedor con ese nombre" test "$(docker ps -aq --filter "name=^$NAME$" | wc -l)" = 1

# AC7: el conjunto exacto de montajes (workspace rw; exec, scope.txt y AUTHORIZATION.md ro; tmpfs en .pi-sessions; tools ro).
mounts_exact() {
  docker inspect --type container "$ID" | python3 -c 'import json,sys
x=json.load(sys.stdin)[0]
ws,tools=sys.argv[1],sys.argv[2]
want=sorted([("bind",ws,ws,True),("bind",tools,tools,False),("tmpfs","",ws+"/.pi-sessions",True)]+[("bind",ws+"/"+f,ws+"/"+f,False) for f in ("exec","scope.txt","AUTHORIZATION.md")])
got=sorted((m["Type"],m["Source"],m["Destination"],m["RW"]) for m in x["Mounts"])
assert got == want, (got,want)
assert not x["HostConfig"]["PortBindings"] and x["HostConfig"]["PublishAllPorts"] is False' "$WS" "$TOOLS"
}
check "montajes exactos y sin puertos publicados" mounts_exact

# H2: .pi-sessions está enmascarado por un tmpfs vacío: lo del host no se ve adentro, y lo de adentro no llega al host.
echo host-secret > "$WS/.pi-sessions/host-session.jsonl"
host_file_hidden() { ! docker exec "$ID" test -e "$WS/.pi-sessions/host-session.jsonl" && [ -z "$(docker exec "$ID" ls -A "$WS/.pi-sessions")" ]; }
container_file_stays_inside() {
  docker exec "$ID" sh -c 'echo tamper > "$1/.pi-sessions/from-container"' _ "$WS" && docker exec "$ID" test -e "$WS/.pi-sessions/from-container" \
    && [ ! -e "$WS/.pi-sessions/from-container" ] && [ "$(cat "$WS/.pi-sessions/host-session.jsonl")" = host-secret ]
}
check "H2: lo escrito en el host en .pi-sessions no se ve desde el contenedor" host_file_hidden
check "H2: lo escrito desde el contenedor en .pi-sessions no aparece en el host (y lo del host sigue)" container_file_stays_inside

# M3: exec, scope.txt y AUTHORIZATION.md no se pueden borrar, sobrescribir ni reemplazar desde el contenedor.
swap_by_rename() { # el contenedor crea un archivo hermano (permitido) y trata de renombrarlo sobre el protegido
  docker exec "$ID" sh -c 'echo evil > "$1/.evil"' _ "$WS"
  local moved=0; docker exec "$ID" mv -f "$WS/.evil" "$WS/$1" 2>/dev/null && moved=1
  rm -f "$WS/.evil"; [ "$moved" = 0 ]
}
for f in exec scope.txt AUTHORIZATION.md; do
  before_sum="$(sha256sum "$WS/$f" | cut -d' ' -f1)"; before_inode="$(stat -c %i "$WS/$f")"
  check "M3: $f no se borra desde el contenedor" bash -c '! docker exec "$0" rm -f "$1"' "$ID" "$WS/$f"
  check "M3: $f no se sobrescribe" bash -c '! docker exec "$0" sh -c "echo os > \"\$1\"" _ "$1"' "$ID" "$WS/$f"
  check "M3: $f no se trunca" bash -c '! docker exec "$0" sh -c ": > \"\$1\"" _ "$1"' "$ID" "$WS/$f"
  check "M3: $f no se reemplaza por renombre" swap_by_rename "$f"
  check "M3: $f no se mueve a otro nombre" bash -c '! docker exec "$0" mv "$1" "$1.moved"' "$ID" "$WS/$f"
  check "M3: $f no se reemplaza por un enlace simbólico" bash -c '! docker exec "$0" ln -sf /etc/passwd "$1"' "$ID" "$WS/$f"
  check "M3: $f del host intacto (mismo contenido e inodo)" bash -c '[ "$(sha256sum "$0" | cut -d" " -f1)" = "$1" ] && [ "$(stat -c %i "$0")" = "$2" ]' "$WS/$f" "$before_sum" "$before_inode"
done
check "MKNOD: el root del contenedor no crea un nodo de dispositivo en el workspace" bash -c '! docker exec "$0" mknod "$1/planted-dev" c 1 3 && [ ! -e "$1/planted-dev" ]' "$ID" "$WS"
check "M3: el contenedor sigue escribiendo en el resto del workspace" docker exec "$ID" sh -c 'echo ok > "$1/notes-from-container.txt"' _ "$WS"
rm -f "$WS/notes-from-container.txt"

# L5: la ACL por defecto cubre también loot/ y scripts/: lo que el contenedor crea ahí (de root) el operador lo borra.
container_tree_removable() {
  docker exec "$ID" sh -c 'mkdir -p "$1/loot/d" "$1/scripts/d" "$1/new" && echo x > "$1/loot/d/f" && echo x > "$1/scripts/d/f" && echo x > "$1/new/f"' _ "$WS" \
    && rm -rf "$WS/loot/d" "$WS/scripts/d" && [ ! -e "$WS/loot/d" ] && [ ! -e "$WS/scripts/d" ]
}
check "L5: lo creado por el contenedor dentro de loot/ y scripts/ lo borra el usuario del host" container_tree_removable

SOCK="/tmp/gekko-013-$$.sock"
docker exec "$ID" tmux -S "$SOCK" new-session -d -s spec013 -c "$WS" \
  "pwd > '$WS/cwd.txt'; printf toolbox-artifact > '$WS/artifact.txt'; exec sleep 300"
for _ in $(seq 1 50); do [ -s "$WS/artifact.txt" ] && break; sleep .1; done
[ "$(cat "$WS/cwd.txt")" = "$WS" ]
[ "$(cat "$WS/artifact.txt")" = toolbox-artifact ]
PANE_PID="$(docker exec "$ID" tmux -S "$SOCK" display-message -p '#{pane_pid}')"
docker exec "$ID" tmux -S "$SOCK" kill-session -t spec013
for _ in $(seq 1 50); do
  docker exec "$ID" tmux -S "$SOCK" has-session 2>/dev/null || break
  sleep .1
done
if docker exec "$ID" tmux -S "$SOCK" has-session 2>/dev/null; then
  echo "FAIL: tmux/shell siguió vivo tras cerrar la sesión" >&2; exit 1
fi
if docker exec "$ID" sh -c "kill -0 $PANE_PID 2>/dev/null"; then
  echo "FAIL: el proceso de la shell siguió vivo tras cerrar la sesión" >&2; exit 1
fi
rm -f "$WS/artifact.txt" "$WS/cwd.txt"
[ ! -e "$WS/artifact.txt" ]

# AC15/16: visor sobre la raíz temporal y ledger compartido con 10 altas concurrentes por lado.
LEDGER="$WS/findings.jsonl"
add_host() {
  python3 "$REPO/.claude/tools/findings.py" add --ledger "$LEDGER" \
    --title "host-$1" --severity medium --target 192.0.2.10 \
    --summary "summary-$1" --impact "impact-$1" --remediation "fix-$1" \
    --cvss 6.5 --cwe CWE-79 --cve CVE-2024-12345 --command "cmd-$1" \
    --artifact "artifacts/$1.txt" --output "proof-$1" >/dev/null
}
add_container() {
  docker exec "$ID" python3 "$TOOLS/findings.py" add --ledger "$LEDGER" \
    --title "container-$1" --severity medium --target 192.0.2.10 \
    --summary "summary-$1" --impact "impact-$1" --remediation "fix-$1" \
    --cvss 6.5 --cwe CWE-79 --cve CVE-2024-12345 --command "cmd-$1" \
    --artifact "artifacts/$1.txt" --output "proof-$1" >/dev/null
}
for n in $(seq 1 10); do add_host "h$n" & add_container "c$n" & done
wait
python3 - "$LEDGER" <<'PY'
import json,sys
rows=[json.loads(s) for s in open(sys.argv[1])]
assert len(rows)==20, len(rows)
assert len({r['id'] for r in rows})==20
for side in ('host','container'):
 r=next(x for x in rows if x['title']==f'{side}-h1' or x['title']==f'{side}-c1')
 suffix=r['title'].split('-',1)[1]
 assert (r['summary'],r['impact'],r['remediation'],r['cvss'],r['cwe'],r['cve']) == (f"summary-{suffix}",f"impact-{suffix}",f"fix-{suffix}",6.5,'CWE-79','CVE-2024-12345')
 assert r['evidence']=={'command':f'cmd-{suffix}','artifact':f'artifacts/{suffix}.txt','output':f'proof-{suffix}'}
PY
python3 "$TOOLS/findings_web.py" serve --root "$ROOT" --port "$PORT" > "$TMP/viewer.log" 2>&1 &
SERVER=$!
for _ in $(seq 1 50); do python3 - "$PORT" "$WSNAME" <<'PY' >/dev/null 2>&1 && break || true
import sys,urllib.request
urllib.request.urlopen(f'http://127.0.0.1:{sys.argv[1]}/w/{sys.argv[2]}/',timeout=.2).read()
PY
  sleep .1
done
python3 - "$PORT" "$WSNAME" <<'PY'
import re,sys,urllib.request
base=f'http://127.0.0.1:{sys.argv[1]}'
W=sys.argv[2]
page=urllib.request.urlopen(base+f'/w/{W}/',timeout=3).read().decode()
for title in ('host-h1','container-c1','20'):
 assert title in page, title
for title in ('host-h1','container-c1'):
 line=re.search(r'href="/w/'+re.escape(W)+r'/f/(\d+)"[^>]*>'+re.escape(title)+r'</a>', page)
 assert line, title
 detail=urllib.request.urlopen(base+f'/w/{W}/f/'+line.group(1),timeout=3).read().decode()
 suffix=title.split('-',1)[1]
 for field in (f'summary-{suffix}',f'impact-{suffix}',f'fix-{suffix}',f'cmd-{suffix}',f'artifacts/{suffix}.txt',f'proof-{suffix}','CWE-79','6.5','CVE-2024-12345'):
  if field not in detail: raise AssertionError((title,field,re.sub('<[^>]+>',' ',detail)[-1800:]))
PY

# L6: un contenedor ajeno con el mismo nombre no se adopta. El anterior se borra: uno reemplazado bajo un Pi en marcha
# hace fallar cada `docker exec` por el ID viejo (cierra en falso, no ejecuta en el nuevo).
docker rm -f "$NAME" >/dev/null
check "L6: el ID viejo ya no ejecuta nada tras reemplazar el contenedor" bash -c '! docker exec "$0" true' "$ID"
hostile_run() { # hostile_run <extra docker run args...>: mismo nombre, mismos montajes (salvo lo que se quite) y comando
  docker run -d --init --name "$NAME" --cap-add=NET_ADMIN --cap-drop=MKNOD --device=/dev/net/tun "$@" \
    -v "$WS:$WS" -v "$WS/exec:$WS/exec:ro" -v "$WS/scope.txt:$WS/scope.txt:ro" -v "$WS/AUTHORIZATION.md:$WS/AUTHORIZATION.md:ro" \
    -v "$TOOLS:$TOOLS:ro" -w "$WS" "$IMAGE" sleep infinity >/dev/null
}
refused_by_cli() {
  local out; out="$(ws_cli toolbox "$WSNAME" 2>&1)" && return 1
  [[ "$out" == *"no se adopta"* ]]
}
hostile_run -p 127.0.0.1::80
check "L6: contenedor del mismo nombre con un puerto publicado → se rehúsa" refused_by_cli
docker rm -f "$NAME" >/dev/null
hostile_run   # sin el tmpfs de .pi-sessions
check "H2/L6: contenedor del mismo nombre sin el tmpfs de .pi-sessions → se rehúsa" refused_by_cli
docker rm -f "$NAME" >/dev/null
recreated_with_new_id() { local fresh; fresh="$(ws_cli toolbox "$WSNAME")" && [ -n "$fresh" ] && [ "$fresh" != "$ID" ]; }
check "tras limpiar, el comando vuelve a crear un contenedor nuevo con otro ID" recreated_with_new_id

if [ "$FAILS" -ne 0 ]; then echo "FAIL: $FAILS caso(s) de Docker real" >&2; exit 1; fi
echo "PASS: ensureToolbox real (crea, reutiliza, rehúsa ajenos); H2 .pi-sessions enmascarado; M3 exec/scope.txt/AUTHORIZATION.md de sólo lectura; L5 ACL; T12 mounts/shell/cwd/cierre/artefacto; T13 20 altas simultáneas, ids únicos, campos iguales y visor local"
