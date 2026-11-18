#!/usr/bin/env bash
# Gate de las specs 012/017: selftests, vistas y descargas sobre raíz temporal.
# Uso:  bash tools/report-test.sh   (desde cualquier directorio)
# Sale 0 solo si todo pasa; una línea FAIL por check fallido y "N passed, M failed" al final.
set -uo pipefail
REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
command -v python3 >/dev/null && command -v curl >/dev/null || { echo "report-test: faltan python3 y/o curl" >&2; exit 2; }

W="$(mktemp -d)"
SERVE_PID=""; TEMPLATE_SERVE_PID=""; PROVIDER_PID=""; SPEC24_PID=""
cleanup() { [ -n "$SERVE_PID" ] && kill -9 "$SERVE_PID" 2>/dev/null; [ -n "$TEMPLATE_SERVE_PID" ] && kill -9 "$TEMPLATE_SERVE_PID" 2>/dev/null; [ -n "$PROVIDER_PID" ] && kill -9 "$PROVIDER_PID" 2>/dev/null; [ -n "$SPEC24_PID" ] && kill -9 "$SPEC24_PID" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT
PASS=0; FAIL=0
check() { # check "nombre" "expr"  (expr evaluada con eval)
  if eval "$2" >/dev/null 2>&1; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL: $1"; fi
}
poll() { local n=50; while [ $n -gt 0 ]; do eval "$1" >/dev/null 2>&1 && return 0; sleep 0.1; n=$((n-1)); done; return 1; } # hasta 5 s

check "selftest del ledger (findings.py)" "python3 '$REPO/.claude/tools/findings.py' selftest"
check "selftest del saneador (sanitize_target_content.py)" "python3 '$REPO/.claude/tools/sanitize_target_content.py' --selftest"
check "selftest del módulo (findings_web.py)" "python3 '$REPO/.claude/tools/findings_web.py' selftest"

# comando suelto: serve sobre una raíz temporal y un puerto libre propio (nunca el 4355)
mkdir -p "$W/root/engagements/demo-ws"
echo "10.0.0.5" > "$W/root/engagements/demo-ws/scope.txt"
cat > "$W/root/engagements/demo-ws/findings.jsonl" <<'JSON'
{"id":"F-S1","title":"needle hypothesis","severity":"high","status":"hypothesis","target":"fixture-one"}
{"id":"F-S2","title":"needle blocked","severity":"high","status":"needs_validation","blocker":"fixture blocker","target":"fixture-two"}
{"id":"F-S3","title":"needle unknown","severity":"high","status":"confirmed ","target":"fixture-three"}
{"id":"F-S4","title":"confirmed report fixture","severity":"high","status":"confirmed","corroboration":"independent fixture signal","target":"fixture-four","remediation":"Remediación ñ ¿ ¡ ☃"}
JSON
PORT="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
if [ -z "$PORT" ]; then
  echo "BLOCKED: HTTP checks require a loopback port; this sandbox denied the bind" >&2
  exit 1
fi
python3 "$REPO/.claude/tools/findings_web.py" serve --root "$W/root" --port "$PORT" > "$W/serve.out" 2> "$W/serve.err" &
SERVE_PID=$!
poll "[ -s '$W/serve.out' ]"
URL="$(head -n1 "$W/serve.out")"
check "serve: la primera línea de stdout es la URL base" "[ '$URL' = 'http://127.0.0.1:$PORT/' ]"
check "serve: el índice responde 200 y trae el workspace" "[ \"\$(curl -s -o '$W/index.html' -w '%{http_code}' '$URL')\" = 200 ] && grep -q demo-ws '$W/index.html'"
check "HTTP: filtros GET intersectan búsqueda, severidad y estado exacto" "[ \"\$(curl -s -o '$W/filtered.html' -w '%{http_code}' '${URL}w/demo-ws/?q=needle&sev=high&status=needs_validation')\" = 200 ] && grep -q F-S2 '$W/filtered.html' && ! grep -q F-S1 '$W/filtered.html' && ! grep -q F-S3 '$W/filtered.html'"
check "HTTP: status inválido vuelve a Todos sin reclasificar el estado desconocido" "[ \"\$(curl -s -o '$W/all.html' -w '%{http_code}' '${URL}w/demo-ws/?status=confirmed%20')\" = 200 ] && grep -q F-S1 '$W/all.html' && grep -q F-S2 '$W/all.html' && grep -q F-S3 '$W/all.html'"
check "HTTP: detalle incluye secciones y aviso de bloqueo persistente" "[ \"\$(curl -s -o '$W/detail.html' -w '%{http_code}' '${URL}w/demo-ws/f/2')\" = 200 ] && grep -q 'href=\"#evidencia\"' '$W/detail.html' && grep -q 'Por validar · bloqueo' '$W/detail.html' && grep -q 'id=\"registro\"' '$W/detail.html'"
check "HTTP: reporte disponible y exportación sigue en 404" "[ \"\$(curl -s -o '$W/report.html' -w '%{http_code}' '${URL}w/demo-ws/reporte?idioma=es')\" = 200 ] && grep -q '1 hallazgos incluidos de 4' '$W/report.html' && [ \"\$(curl -s -o /dev/null -w '%{http_code}' '${URL}export')\" = 404 ]"
DIGEST="$(sed -n 's/.*Ledger SHA-256: <code>\([0-9a-f]*\)<\/code>.*/\1/p' "$W/report.html")"
MD_SHA="$(sed -n 's/.*Markdown SHA-256: <code>\([0-9a-f]*\)<\/code>.*/\1/p' "$W/report.html")"
HTML_SHA="$(sed -n 's/.*HTML SHA-256: <code>\([0-9a-f]*\)<\/code>.*/\1/p' "$W/report.html")"
check "HTTP: página expone hashes de ledger, Markdown y HTML" "[ \"\$DIGEST\" != '' ] && [ \"\$MD_SHA\" != '' ] && [ \"\$HTML_SHA\" != '' ]"
check "HTTP: Markdown descargado coincide con render CLI" "curl -fsS '${URL}w/demo-ws/reporte.md?idioma=es&ledger=$DIGEST' -o '$W/report.md' && python3 '$REPO/.claude/tools/findings.py' render --ledger '$W/root/engagements/demo-ws/findings.jsonl' --lang es --tipo tecnico --workspace demo-ws > '$W/cli.md' && cmp '$W/report.md' '$W/cli.md' && [ \"\$(sha256sum '$W/report.md' | cut -d' ' -f1)\" = \"\$MD_SHA\" ] && curl -fsS '${URL}w/demo-ws/reporte.md?idioma=es&ledger=$DIGEST' -o '$W/report2.md' && cmp '$W/report.md' '$W/report2.md' && ! grep -q 'KB:' '$W/report.md'"
check "HTTP: HTML descargado coincide con su hash y es repetible" "curl -fsS '${URL}w/demo-ws/reporte.html?idioma=es&ledger=$DIGEST' -o '$W/report-dl.html' && [ \"\$(sha256sum '$W/report-dl.html' | cut -d' ' -f1)\" = \"\$HTML_SHA\" ] && curl -fsS '${URL}w/demo-ws/reporte.html?idioma=es&ledger=$DIGEST' -o '$W/report-dl2.html' && cmp '$W/report-dl.html' '$W/report-dl2.html'"
check "HTTP: cabeceras de descarga y vista de impresión" "curl -fsS -D '$W/headers' '${URL}w/demo-ws/reporte.md?idioma=es&ledger=$DIGEST' -o /dev/null && grep -qi 'Content-Disposition: attachment; filename=\"demo-ws-reporte-es.md\"' '$W/headers' && [ \"\$(grep -ci '^Content-Type:' '$W/headers')\" = 1 ] && grep -qi 'X-Content-Type-Options: nosniff' '$W/headers' && grep -qi 'Cache-Control: no-store' '$W/headers' && curl -fsS -D '$W/print-headers' '${URL}w/demo-ws/reporte.imprimir?idioma=es&ledger=$DIGEST' -o '$W/report-print.html' && ! grep -qi '^Content-Disposition:' '$W/print-headers' && grep -qi '^Content-Type: text/html' '$W/print-headers' && grep -qi 'X-Content-Type-Options: nosniff' '$W/print-headers' && cmp '$W/report-print.html' '$W/report-dl.html' && [ \"\$(sha256sum '$W/report-print.html' | cut -d' ' -f1)\" = \"\$HTML_SHA\" ]"
check "HTTP: el .pdf del servidor ya no existe, la vista de impresión lleva la ayuda y el @page, y el botón la abre en otra pestaña" "[ \"\$(curl -s -o /dev/null -w '%{http_code}' '${URL}w/demo-ws/reporte.pdf?idioma=es&ledger=$DIGEST')\" = 404 ] && grep -q 'Ctrl+P' '$W/report-print.html' && grep -q '@page' '$W/report-print.html' && curl -fsS '${URL}w/demo-ws/reporte?tipo=tecnico&idioma=es' | grep -q 'reporte.imprimir?[^\"]*\" target=\"_blank\" rel=\"noopener noreferrer\"'"


LEDGER="$W/root/engagements/demo-ws/findings.jsonl"
DETAIL="${URL}w/demo-ws/f/1"
curl -fsS "$DETAIL" > "$W/state-form.html"
SEEN="$(python3 -c 'import re,sys; print(re.search(r"name=\"visto\" value=\"([a-f0-9]+)\"",open(sys.argv[1]).read().split("/estado\"")[1])[1])' "$W/state-form.html")"
TICKET="$(python3 -c 'import re,sys; print(re.search(r"name=\"ficha\" value=\"([a-f0-9]+)\"",open(sys.argv[1]).read().split("/estado\"")[1])[1])' "$W/state-form.html")"
STATE_CODE="$(curl -s -o "$W/state-post.html" -D "$W/state-headers" -w '%{http_code}' -X POST \
  -H 'Sec-Fetch-Site: same-origin' --data-urlencode 'estado=triaged' --data-urlencode 'corroboracion=' \
  --data-urlencode 'bloqueo=' --data-urlencode "visto=$SEEN" --data-urlencode "ficha=$TICKET" \
  "${URL}w/demo-ws/f/1/estado")"
check "HTTP: POST de estado guarda y responde 303" "[ '$STATE_CODE' = 303 ] && grep -q 'Location: /w/demo-ws/f/1?guardado=' '$W/state-headers' && grep -q 'triaged' '$LEDGER'"
SAVED_SHA="$(sha256sum "$LEDGER" | cut -d' ' -f1)"
SAVED_PATH="$(sed -n 's/^Location: //Ip' "$W/state-headers" | tr -d '\r')"
curl -fsS "${URL}${SAVED_PATH#/}" > "$W/saved.html"
curl -fsS "${URL}${SAVED_PATH#/}" > "$W/saved-again.html"
check "HTTP: aviso de éxito y recarga no reenvían la escritura" "grep -q 'Estado guardado: Hipótesis → Triado' '$W/saved.html' && [ \"\$(sha256sum '$LEDGER' | cut -d' ' -f1)\" = '$SAVED_SHA' ]"

curl -fsS "$DETAIL" > "$W/state-form.html"
SEEN="$(python3 -c 'import re,sys; print(re.search(r"name=\"visto\" value=\"([a-f0-9]+)\"",open(sys.argv[1]).read().split("/estado\"")[1])[1])' "$W/state-form.html")"
TICKET="$(python3 -c 'import re,sys; print(re.search(r"name=\"ficha\" value=\"([a-f0-9]+)\"",open(sys.argv[1]).read().split("/estado\"")[1])[1])' "$W/state-form.html")"
BEFORE_REJECT="$(sha256sum "$LEDGER" | cut -d' ' -f1)"
REJECT_CODE="$(curl -s -o "$W/reject.html" -w '%{http_code}' -X POST --data-urlencode 'estado=confirmed' \
  --data-urlencode 'corroboracion=' --data-urlencode 'bloqueo=' --data-urlencode "visto=$SEEN" \
  --data-urlencode "ficha=$TICKET" "${URL}w/demo-ws/f/1/estado")"
check "HTTP: rechazo conserva ledger y devuelve 422" "[ '$REJECT_CODE' = 422 ] && grep -q 'no se guardó nada' '$W/reject.html' && [ \"\$(sha256sum '$LEDGER' | cut -d' ' -f1)\" = '$BEFORE_REJECT' ]"
FAKE_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST --data 'estado=triaged&corroboracion=&bloqueo=&visto=x&ficha=x' "${URL}w/demo-ws/f/1/estado")"
GET_ACTION="$(curl -s -o /dev/null -w '%{http_code}' "${URL}w/demo-ws/f/1/estado?estado=confirmed")"
check "HTTP: ficha falsa da 403 y GET a la acción da 404" "[ '$FAKE_CODE' = 403 ] && [ '$GET_ACTION' = 404 ]"
BIG_CODE="$(head -c 65537 /dev/zero | tr '\0' x | curl -s -o "$W/large.html" -w '%{http_code}' -X POST \
  -H 'Content-Length: 65537' --data-binary @- "${URL}w/demo-ws/f/1/estado")"
check "HTTP: cuerpo mayor a MAX_BODY devuelve 413" "[ '$BIG_CODE' = 413 ] && grep -q 65536 '$W/large.html'"

# Chat del hallazgo (spec 018) contra el módulo real y un Provider falso local: preguntar, aplicar y deshacer por HTTP.
cat > "$W/provider.py" <<'PY'
import http.server, json, sys
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        open(sys.argv[2], "a").write(self.headers.get("Authorization", "") + "\n")
        self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
        text = "Propongo:\n[[PROPUESTA remediation]]\nActualizar el componente afectado\n[[/PROPUESTA]]"
        self.wfile.write(b"data: " + json.dumps({"choices": [{"delta": {"content": text}}]}).encode() + b"\n\ndata: [DONE]\n\n")
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
open(sys.argv[1], "w").write(str(server.server_address[1]))
server.serve_forever()
PY
python3 "$W/provider.py" "$W/provider.port" "$W/provider.auth" &
PROVIDER_PID=$!
poll "[ -s '$W/provider.port' ]"
CANARY="CANARY-KEY-$$-$RANDOM"
mkdir -p "$W/root/.gekko-state"
printf 'export GEKKO_LLM_URL="http://127.0.0.1:%s/v1"\nexport GEKKO_PROVIDER_KEY="%s"\n' "$(cat "$W/provider.port")" "$CANARY" > "$W/root/.gekko-state/env"
form_value() { # form_value <archivo> <marcador> <campo>: valor oculto del primer campo tras el marcador
  python3 - "$1" "$2" "$3" <<'PY'
import re, sys
page = open(sys.argv[1]).read()
page = page[page.index(sys.argv[2]):]
print(re.search(r'name="%s" value="([^"]*)"' % sys.argv[3], page)[1])
PY
}
CHAT="${URL}w/demo-ws/f/1/chat"
curl -fsS "${URL}w/demo-ws/f/1" > "$W/chat-0.html"
ASK_SEEN="$(form_value "$W/chat-0.html" 'action="/w/demo-ws/f/1/chat"' visto)"
ASK_TICKET="$(form_value "$W/chat-0.html" 'action="/w/demo-ws/f/1/chat"' ficha)"
ASK_CODE="$(curl -s -o "$W/chat-ask.out" -D "$W/chat-ask.headers" -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' \
  --data-urlencode 'pregunta=Sugerir remediación' --data-urlencode "visto=$ASK_SEEN" --data-urlencode "ficha=$ASK_TICKET" "$CHAT")"
check "chat HTTP: preguntar responde 303 al panel y el Provider recibió la clave sólo en Authorization" "[ '$ASK_CODE' = 303 ] && grep -qi 'Location: /w/demo-ws/f/1#asistente' '$W/chat-ask.headers' && [ \"\$(cat '$W/provider.auth')\" = 'Bearer $CANARY' ]"
curl -fsS "${URL}w/demo-ws/f/1" > "$W/chat-1.html"
check "chat HTTP: la propuesta aparece con su botón" "grep -q 'Propuesta para ‹Remediación›' '$W/chat-1.html' && grep -q 'action=\"/w/demo-ws/f/1/chat/aplicar\"' '$W/chat-1.html'"
BEFORE_CHAT_SHA="$(sha256sum "$LEDGER" | cut -d' ' -f1)"
BAD_APPLY="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' --data 'propuesta=x&visto=x&ficha=x' "$CHAT/aplicar")"
GET_APPLY="$(curl -s -o /dev/null -w '%{http_code}' "$CHAT/aplicar")"
check "chat HTTP: ficha falsa 403, GET a la acción 404 y el ledger no cambia" "[ '$BAD_APPLY' = 403 ] && [ '$GET_APPLY' = 404 ] && [ \"\$(sha256sum '$LEDGER' | cut -d' ' -f1)\" = '$BEFORE_CHAT_SHA' ]"
APPLY_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' \
  --data-urlencode "propuesta=$(form_value "$W/chat-1.html" 'action="/w/demo-ws/f/1/chat/aplicar"' propuesta)" \
  --data-urlencode "visto=$(form_value "$W/chat-1.html" 'action="/w/demo-ws/f/1/chat/aplicar"' visto)" \
  --data-urlencode "ficha=$(form_value "$W/chat-1.html" 'action="/w/demo-ws/f/1/chat/aplicar"' ficha)" "$CHAT/aplicar")"
check "chat HTTP: aplicar responde 303 y el ledger trae la remediación propuesta" "[ '$APPLY_CODE' = 303 ] && grep -q 'Actualizar el componente afectado' '$LEDGER'"
curl -fsS "${URL}w/demo-ws/f/1" > "$W/chat-2.html"
UNDO_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' \
  --data-urlencode "propuesta=$(form_value "$W/chat-2.html" 'action="/w/demo-ws/f/1/chat/deshacer"' propuesta)" \
  --data-urlencode "visto=$(form_value "$W/chat-2.html" 'action="/w/demo-ws/f/1/chat/deshacer"' visto)" \
  --data-urlencode "ficha=$(form_value "$W/chat-2.html" 'action="/w/demo-ws/f/1/chat/deshacer"' ficha)" "$CHAT/deshacer")"
check "chat HTTP: deshacer responde 303 y el campo vuelve a no existir" "[ '$UNDO_CODE' = 303 ] && ! grep -q 'Actualizar el componente afectado' '$LEDGER'"
check "chat HTTP: la clave no está en ninguna respuesta ni en el stderr del módulo" "! grep -rq '$CANARY' '$W/chat-0.html' '$W/chat-1.html' '$W/chat-2.html' '$W/chat-ask.out' '$W/chat-ask.headers' '$W/serve.err'"
check "chat: la historia queda bajo .gekko-web, 0600 y cubierta por .gitignore" "f=\$(ls '$W'/root/engagements/demo-ws/.gekko-web/chat/*.jsonl) && [ \"\$(stat -c %a \"\$f\")\" = 600 ] && git -C '$REPO' check-ignore -q engagements/demo-ws/.gekko-web/chat/x.jsonl"
{ kill -9 "$PROVIDER_PID"; wait "$PROVIDER_PID"; } 2>/dev/null; PROVIDER_PID=""

# Spec 019a: edición de campos, CVSS y comentarios por HTTP (T20)
FINDINGS="$REPO/.claude/tools/findings.py"
EDIT="${URL}w/demo-ws/f/2/editar"
post_edit() { # post_edit <archivo-de-formulario> <accion> [campo=valor ...]: POST firmado; imprime el código HTTP
  local page="$1" action="$2"; shift 2
  local args=()
  for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  curl -s -o "$W/edit.out" -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' --data-urlencode "accion=$action" \
    --data-urlencode "visto=$(form_value "$page" 'class="edit-form"' visto)" --data-urlencode "ficha=$(form_value "$page" 'class="edit-form"' ficha)" "${args[@]}" "$EDIT"
}
curl -fsS "${URL}w/demo-ws/f/2?editar=1" > "$W/edit-0.html"
check "edición HTTP: ?editar=1 trae el formulario con huella y ficha" "grep -q 'class=\"edit-form\"' '$W/edit-0.html' && grep -q 'name=\"cwe\"' '$W/edit-0.html'"
EDIT_SHA="$(sha256sum "$LEDGER" | cut -d' ' -f1)"
CALC_CODE="$(post_edit "$W/edit-0.html" calcular 'vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' 'vector_mostrado=')"
check "edición HTTP: Calcular responde 200 con el puntaje y no escribe" "[ '$CALC_CODE' = 200 ] && grep -q '9.8' '$W/edit.out' && [ \"\$(sha256sum '$LEDGER' | cut -d' ' -f1)\" = '$EDIT_SHA' ]"
BAD_CWE="$(post_edit "$W/edit-0.html" guardar 'cwe=CWE-x')"
check "edición HTTP: un CWE inválido es 422 y no escribe" "[ '$BAD_CWE' = 422 ] && [ \"\$(sha256sum '$LEDGER' | cut -d' ' -f1)\" = '$EDIT_SHA' ]"
SAVE_CODE="$(post_edit "$W/edit-0.html" guardar 'impacto=Impacto editado por la web' 'cwe=CWE-79')"
check "edición HTTP: guardar responde 303 y el ledger trae impacto y CWE" "[ '$SAVE_CODE' = 303 ] && grep -q 'Impacto editado por la web' '$LEDGER' && grep -q 'CWE-79' '$LEDGER'"
check "edición HTTP: el mismo formulario enviado otra vez es 409 y no escribe" "[ \"\$(post_edit '$W/edit-0.html' guardar 'impacto=otro')\" = 409 ] && ! grep -q '\"impact\": \"otro\"' '$LEDGER'"
curl -fsS "${URL}w/demo-ws/f/2?editar=1" > "$W/edit-1.html"
python3 "$FINDINGS" set --ledger "$LEDGER" --id F-S2 --artifact loot/otro.txt >/dev/null
check "edición HTTP: tras un findings.py set la huella vieja da 409 con 'Ahora en el ledger'" "[ \"\$(post_edit '$W/edit-1.html' guardar 'impacto=pisado')\" = 409 ] && grep -q 'Ahora en el ledger' '$W/edit.out' && ! grep -q 'pisado' '$LEDGER'"
check "edición HTTP: GET a la ruta de edición es 404" "[ \"\$(curl -s -o /dev/null -w '%{http_code}' '$EDIT')\" = 404 ]"
COMMENT="${URL}w/demo-ws/f/2/comentario"
post_comment() { # post_comment <accion> [campo=valor ...]
  local args=(); local action="$1"; shift
  for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  curl -s -o "$W/comment.out" -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' --data-urlencode "accion=$action" "${args[@]}" "$COMMENT"
}
curl -fsS "${URL}w/demo-ws/f/2" > "$W/comment-0.html"
ADD_CODE="$(post_comment agregar 'texto=nota del operador' "nuevo=$(form_value "$W/comment-0.html" 'action="/w/demo-ws/f/2/comentario"' nuevo)" "ficha=$(form_value "$W/comment-0.html" 'action="/w/demo-ws/f/2/comentario"' ficha)")"
check "comentario HTTP: agregar responde 303 y aparece en la página y en la CLI" "[ '$ADD_CODE' = 303 ] && curl -fsS '${URL}w/demo-ws/f/2' | grep -q 'nota del operador' && python3 '$FINDINGS' comment list --ledger '$LEDGER' | grep -q 'nota del operador'"
check "comentario HTTP: reenviar el mismo formulario escribe una sola vez" "[ \"\$(post_comment agregar 'texto=nota del operador' \"nuevo=\$(form_value '$W/comment-0.html' 'action=\"/w/demo-ws/f/2/comentario\"' nuevo)\" \"ficha=\$(form_value '$W/comment-0.html' 'action=\"/w/demo-ws/f/2/comentario\"' ficha)\")\" = 303 ] && [ \"\$(grep -c 'nota del operador' '$W/root/engagements/demo-ws/.gekko-web/comentarios.jsonl')\" = 1 ]"
check "comentario HTTP: una ficha falsa es 403 y no escribe" "[ \"\$(post_comment agregar 'texto=forjado' 'nuevo=0123456789abcdef' 'ficha=x')\" = 403 ] && ! grep -q forjado '$W/root/engagements/demo-ws/.gekko-web/comentarios.jsonl'"
check "comentario: el archivo es 0600 y está cubierto por .gitignore" "[ \"\$(stat -c %a '$W/root/engagements/demo-ws/.gekko-web/comentarios.jsonl')\" = 600 ] && git -C '$REPO' check-ignore -q engagements/demo-ws/.gekko-web/comentarios.jsonl"
check "comentario: el reporte no lleva el texto del comentario" "! curl -fsS '${URL}w/demo-ws/reporte?idioma=es' | grep -q 'nota del operador' && ! python3 '$FINDINGS' render --ledger '$LEDGER' --all | grep -q 'nota del operador'"

# Tres rondas: diez filas distintas se guardan a la vez que diez altas al mismo ledger.
BASE="$(wc -l < "$LEDGER")"  # filas del fixture, sin fijar el número aquí
round_ok() {
  python3 - "$LEDGER" "$1" "$BASE" <<'PY'
import json, sys
from pathlib import Path
rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
rounds = int(sys.argv[2]) + 1
raise SystemExit(0 if len(rows) == int(sys.argv[3]) + 20 * rounds
                 and sum(str(row.get("title", "")).startswith("concurrent-") for row in rows) == 10 * rounds
                 and sum(row.get("status") == "triaged" for row in rows) == 1 + 10 * rounds else 1)
PY
}
for round in 0 1 2; do
  first=$((BASE + 1 + round * 10))
  PIDS=()
  for i in $(seq 0 9); do
    python3 "$REPO/.claude/tools/findings.py" add --ledger "$LEDGER" --title "parallel-$round-$i" \
      --severity low --status hypothesis --target fixture --command 'fixture' --artifact '' --output 'fixture' >/dev/null
  done
  for i in $(seq 0 9); do
    line=$((first + i))
    curl -fsS "${URL}w/demo-ws/f/$line" > "$W/form-$line.html"
    seen="$(python3 -c 'import re,sys; print(re.search(r"name=\"visto\" value=\"([a-f0-9]+)\"",open(sys.argv[1]).read().split("/estado\"")[1])[1])' "$W/form-$line.html")"
    ticket="$(python3 -c 'import re,sys; print(re.search(r"name=\"ficha\" value=\"([a-f0-9]+)\"",open(sys.argv[1]).read().split("/estado\"")[1])[1])' "$W/form-$line.html")"
    if [ $((i % 2)) -eq 1 ]; then
      (curl -s -o "$W/parallel-$line.out" -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' \
        --data-urlencode 'estado=triaged' --data-urlencode 'corroboracion=' --data-urlencode 'bloqueo=' \
        --data-urlencode "visto=$seen" --data-urlencode "ficha=$ticket" "${URL}w/demo-ws/f/$line/estado" > "$W/parallel-$line.code"; \
       python3 "$REPO/.claude/tools/findings.py" add --ledger "$LEDGER" --title "concurrent-$round-$i" \
         --severity low --status hypothesis --target fixture --command fixture --artifact '' --output fixture >/dev/null) &
      PIDS+=("$!")
    else
      (curl -s -o "$W/parallel-$line.out" -w '%{http_code}' -X POST \
        --data-urlencode 'estado=triaged' --data-urlencode 'corroboracion=' --data-urlencode 'bloqueo=' \
        --data-urlencode "visto=$seen" --data-urlencode "ficha=$ticket" "${URL}w/demo-ws/f/$line/estado" > "$W/parallel-$line.code"; \
       python3 "$REPO/.claude/tools/findings.py" add --ledger "$LEDGER" --title "concurrent-$round-$i" \
         --severity low --status hypothesis --target fixture --command fixture --artifact '' --output fixture >/dev/null) &
      PIDS+=("$!")
    fi
  done
  for pid in "${PIDS[@]}"; do wait "$pid"; done
  check "concurrencia ronda $round: 10 estados y 10 altas sin pérdida" "python3 '$REPO/.claude/tools/findings.py' list --ledger '$LEDGER' >/dev/null && round_ok '$round' && [ \$(grep -l '^303$' '$W'/parallel-*.code | wc -l) -ge $(((round + 1) * 10)) ]"
done
# Spec 019a (T21): diez ediciones, diez comentarios web, diez comentarios por CLI y diez altas a la vez, tres rondas.
COMMENTS="$W/root/engagements/demo-ws/.gekko-web/comentarios.jsonl"
for round in 0 1 2; do
  first=$(($(wc -l < "$LEDGER") + 1))
  for i in $(seq 0 9); do
    python3 "$FINDINGS" add --ledger "$LEDGER" --title "edit-$round-$i" --severity low --status hypothesis --target fixture --command fixture --artifact '' --output fixture >/dev/null
  done
  PIDS=()
  for i in $(seq 0 9); do
    line=$((first + i))
    curl -fsS "${URL}w/demo-ws/f/$line?editar=1" > "$W/t21-edit-$line.html"
    curl -fsS "${URL}w/demo-ws/f/$line" > "$W/t21-page-$line.html"
    fid="$(python3 -c 'import json,sys; print(json.loads(open(sys.argv[1]).read().splitlines()[int(sys.argv[2]) - 1])["id"])' "$LEDGER" "$line")"
    (curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Sec-Fetch-Site: same-origin' --data-urlencode 'accion=guardar' --data-urlencode "impacto=impacto $round-$i" \
       --data-urlencode "visto=$(form_value "$W/t21-edit-$line.html" 'class="edit-form"' visto)" --data-urlencode "ficha=$(form_value "$W/t21-edit-$line.html" 'class="edit-form"' ficha)" \
       "${URL}w/demo-ws/f/$line/editar" > "$W/t21-$line.edit"
     curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Sec-Fetch-Site: same-origin' --data-urlencode 'accion=agregar' --data-urlencode "texto=web $round-$i" \
       --data-urlencode "nuevo=$(form_value "$W/t21-page-$line.html" 'action="/w/demo-ws/f/'$line'/comentario"' nuevo)" --data-urlencode "ficha=$(form_value "$W/t21-page-$line.html" 'action="/w/demo-ws/f/'$line'/comentario"' ficha)" \
       "${URL}w/demo-ws/f/$line/comentario" > "$W/t21-$line.comment") &
    PIDS+=("$!")
    (python3 "$FINDINGS" comment add --ledger "$LEDGER" --id "$fid" --text "cli $round-$i" > "$W/t21-$line.cli"; echo $? >> "$W/t21-$line.cli"
     python3 "$FINDINGS" add --ledger "$LEDGER" --title "t21-extra-$round-$i" --severity low --status hypothesis --target fixture --command fixture --artifact '' --output fixture >/dev/null) &
    PIDS+=("$!")
  done
  for pid in "${PIDS[@]}"; do wait "$pid"; done
  check "T21 ronda $round: 10 ediciones, 10 comentarios web y 10 por CLI sin pérdida; list y comment list salen 0" "[ \$(cat '$W'/t21-*.edit | grep -c '^303$') -ge $(((round + 1) * 10)) ] && [ \$(cat '$W'/t21-*.comment | grep -c '^303$') -ge $(((round + 1) * 10)) ] && [ \$(grep -c 'impacto $round-' '$LEDGER') = 10 ] && [ \$(grep -c '\"text\":\"web $round-' '$COMMENTS') = 10 ] && [ \$(grep -c '\"text\":\"cli $round-' '$COMMENTS') = 10 ] && python3 '$FINDINGS' list --ledger '$LEDGER' >/dev/null && python3 '$FINDINGS' comment list --ledger '$LEDGER' >/dev/null"
done
# Spec 019b (T41): borradores, reporte Ejecutivo/Técnico, seis descargas y barra plegable por HTTP.
DRAFTS="$W/root/engagements/demo-ws/.gekko-web/borradores"
post_draft() { # post_draft <tipo> <accion> [campo=valor ...]: POST firmado con la huella y la ficha de la página actual; imprime el código HTTP
  local tipo="$1" action="$2"; shift 2
  local args=()
  for kv in "$@"; do args+=(--data-urlencode "$kv"); done
  curl -fsS "${URL}w/demo-ws/reporte?tipo=$tipo&idioma=es" > "$W/draft-page.html"
  curl -s -o "$W/draft.out" -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' --data-urlencode "tipo=$tipo" --data-urlencode 'idioma=es' --data-urlencode "accion=$action" \
    --data-urlencode "visto=$(form_value "$W/draft-page.html" 'action="/w/demo-ws/reporte/borrador"' visto)" --data-urlencode "ficha=$(form_value "$W/draft-page.html" 'action="/w/demo-ws/reporte/borrador"' ficha)" "${args[@]}" "${URL}w/demo-ws/reporte/borrador"
}
LEDGER_BEFORE_DRAFT="$(sha256sum "$LEDGER" | cut -d' ' -f1)"
check "borrador HTTP: previsualizar responde 200 con lo enviado y no escribe" "[ \"\$(post_draft tecnico previsualizar 'resumen=RESUMEN-PREVIEW')\" = 200 ] && grep -q RESUMEN-PREVIEW '$W/draft.out' && [ ! -e '$DRAFTS/tecnico.json' ]"
check "borrador HTTP: guardar un Técnico y un Ejecutivo responde 303" "[ \"\$(post_draft tecnico guardar 'titulo=Informe técnico' 'cliente=cliente-demo' 'resumen=Resumen técnico' 'metodologia=Método' 'recomendaciones=Parchear')\" = 303 ] && [ \"\$(post_draft ejecutivo guardar 'titulo=Informe ejecutivo' 'resumen=Resumen ejecutivo' 'recomendaciones=Priorizar')\" = 303 ]"
check "borrador: archivos 0600 en carpeta 0700, cubiertos por .gitignore; el ledger no cambió" "[ \"\$(stat -c %a '$DRAFTS/tecnico.json')\" = 600 ] && [ \"\$(stat -c %a '$DRAFTS')\" = 700 ] && git -C '$REPO' check-ignore -q engagements/demo-ws/.gekko-web/borradores/tecnico.json && [ \"\$(sha256sum '$LEDGER' | cut -d' ' -f1)\" = '$LEDGER_BEFORE_DRAFT' ]"
for tipo in tecnico ejecutivo; do
  curl -fsS "${URL}w/demo-ws/reporte?tipo=$tipo&idioma=es" > "$W/rep-$tipo.html"
  L_SHA="$(sed -n 's/.*Ledger SHA-256: <code>\([0-9a-f]*\)<\/code>.*/\1/p' "$W/rep-$tipo.html")"
  D_SHA="$(sed -n 's/.*Borrador SHA-256: <code>\([0-9a-f]*\)<\/code>.*/\1/p' "$W/rep-$tipo.html")"
  M_SHA="$(sed -n 's/.*Markdown SHA-256: <code>\([0-9a-f]*\)<\/code>.*/\1/p' "$W/rep-$tipo.html")"
  H_SHA="$(sed -n 's/.*HTML SHA-256: <code>\([0-9a-f]*\)<\/code>.*/\1/p' "$W/rep-$tipo.html")"
  Q="tipo=$tipo&idioma=es&ledger=$L_SHA&borrador=$D_SHA"
  check "descargas $tipo: Markdown, HTML y vista de impresión existen y los hashes de la página coinciden" "curl -fsS '${URL}w/demo-ws/reporte.md?$Q' -o '$W/$tipo.md' && curl -fsS '${URL}w/demo-ws/reporte.html?$Q' -o '$W/$tipo.html' && curl -fsS '${URL}w/demo-ws/reporte.imprimir?$Q' -o '$W/$tipo.print.html' && cmp '$W/$tipo.html' '$W/$tipo.print.html' && [ \"\$(sha256sum '$W/$tipo.print.html' | cut -d' ' -f1)\" = '$H_SHA' ] && [ \"\$(sha256sum '$W/$tipo.md' | cut -d' ' -f1)\" = '$M_SHA' ] && [ \"\$(sha256sum '$W/$tipo.html' | cut -d' ' -f1)\" = '$H_SHA' ] && [ \"\$(sha256sum '$DRAFTS/$tipo.json' | cut -d' ' -f1)\" = '$D_SHA' ]"
  check "descargas $tipo: el .md es byte a byte findings.py render --tipo --borrador" "python3 '$FINDINGS' render --ledger '$LEDGER' --tipo $tipo --borrador '$DRAFTS/$tipo.json' --lang es > '$W/$tipo-cli.md' && cmp '$W/$tipo.md' '$W/$tipo-cli.md'"
done
check "descargas: el Ejecutivo no lleva evidencia, comandos ni corroboración" "! grep -qi 'independent fixture signal' '$W/ejecutivo.md' '$W/ejecutivo.html'"
check "descargas: el HTML lleva el logo como data: y la CSP img-src data:" "grep -q 'url(data:image/png;base64,' '$W/ejecutivo.html' && grep -q 'img-src data:' '$W/ejecutivo.html' && ! grep -q '<script' '$W/ejecutivo.html'"
check "borrador HTTP: guardar con la huella vieja es 409 y un enlace viejo de descarga es 409 sin archivo" "[ \"\$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' --data-urlencode 'tipo=tecnico' --data-urlencode 'accion=guardar' --data-urlencode 'visto=ninguno' --data-urlencode \"ficha=\$(form_value '$W/draft-page.html' 'action=\"/w/demo-ws/reporte/borrador\"' ficha)\" '${URL}w/demo-ws/reporte/borrador')\" != 303 ] && [ \"\$(post_draft tecnico guardar 'titulo=Cambiado' 'resumen=Otro')\" = 303 ] && [ \"\$(curl -s -o /dev/null -w '%{http_code}' '${URL}w/demo-ws/reporte.md?tipo=tecnico&idioma=es&ledger=$L_SHA&borrador=$D_SHA')\" = 409 ]"
BAR_CODE="$(curl -s -o /dev/null -D "$W/bar-headers" -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' --data 'barra=plegada&volver=/w/demo-ws/reporte' "${URL}barra")"
check "barra HTTP: POST /barra pone la cookie y las páginas traen la clase" "[ '$BAR_CODE' = 303 ] && grep -qi 'Set-Cookie: gekko_barra=plegada' '$W/bar-headers' && grep -qi 'Location: /w/demo-ws/reporte' '$W/bar-headers' && curl -fsS -H 'Cookie: gekko_barra=plegada' '$URL' -o '$W/bar-page.html' && grep -q '<html lang=\"es\" class=\"barra-plegada\"' '$W/bar-page.html' && curl -fsS '$URL' -o '$W/bar-open.html' && ! grep -q 'class=\"barra-plegada\"' '$W/bar-open.html'"

# Adjuntos (spec 023a) por HTTP real: subir, aislar, adjuntar/quitar, 413, borrar y cabeceras de la imagen
mkdir -p "$W/root/engagements/gal-a" "$W/root/engagements/gal-b"
echo "10.0.0.5" > "$W/root/engagements/gal-a/scope.txt"; cp "$W/root/engagements/gal-a/scope.txt" "$W/root/engagements/gal-b/scope.txt"
printf '%s\n' '{"id":"F-1","title":"con capturas","severity":"low","status":"triaged","target":"x"}' '{"id":"F-2","title":"otro","severity":"low","status":"triaged","target":"x"}' > "$W/root/engagements/gal-a/findings.jsonl"
printf '%s\n' '{"id":"F-1","title":"b","severity":"low","status":"triaged","target":"x"}' > "$W/root/engagements/gal-b/findings.jsonl"
python3 - "$W" "$REPO/.claude/tools" <<'PY'
import sys
sys.path.insert(0, sys.argv[2])
import findings
open(sys.argv[1] + "/a.png", "wb").write(findings.selftest_png(7, 7))
open(sys.argv[1] + "/b.png", "wb").write(findings.selftest_png(8, 8))
open(sys.argv[1] + "/c.jpg", "wb").write(findings.selftest_jpeg(9, 9))
PY
GAL="$W/root/engagements/gal-a"
SHA_A="$(sha256sum "$W/a.png" | cut -d' ' -f1)"; SHA_B="$(sha256sum "$W/b.png" | cut -d' ' -f1)"; SHA_C="$(sha256sum "$W/c.jpg" | cut -d' ' -f1)"
curl -fsS "${URL}w/gal-a/galeria" > "$W/gal-0.html"
GAL_TICKET="$(form_value "$W/gal-0.html" 'action="/w/gal-a/galeria"' ficha)"
UP_CODE="$(curl -s -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: same-origin' --form-string "ficha=$GAL_TICKET" -F "archivo=@$W/a.png;filename=../../scope.txt" -F "archivo=@$W/c.jpg" "${URL}w/gal-a/galeria")"
check "W-1 Adjuntos: subir PNG y JPEG da 303 y guarda los bytes bajo su sha256 sin usar el filename" "[ '$UP_CODE' = 303 ] && [ \"\$(sha256sum '$GAL/evidencia/$SHA_A.png' | cut -d' ' -f1)\" = '$SHA_A' ] && [ \"\$(sha256sum '$GAL/evidencia/$SHA_C.jpg' | cut -d' ' -f1)\" = '$SHA_C' ] && [ \"\$(cat '$GAL/scope.txt')\" = 10.0.0.5 ] && curl -fsS '${URL}w/gal-a/galeria' | grep -q '$SHA_A'"
check "W-2 Adjuntos: la imagen de un workspace da 404 en otro" "[ \"\$(curl -s -o /dev/null -w '%{http_code}' '${URL}w/gal-b/galeria/$SHA_A.png')\" = 404 ] && [ \"\$(curl -s -o /dev/null -w '%{http_code}' '${URL}w/gal-a/galeria/$SHA_A.png')\" = 200 ]"
curl -fsS "${URL}w/gal-a/f/1" > "$W/gal-state.html"
G_SEEN="$(form_value "$W/gal-state.html" 'action="/w/gal-a/f/1/estado"' visto)"; G_TICKET="$(form_value "$W/gal-state.html" 'action="/w/gal-a/f/1/estado"' ficha)"
ATT_CODE="$(curl -s -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: same-origin' --form-string estado=triaged --form-string corroboracion= --form-string bloqueo= --form-string "visto=$G_SEEN" --form-string "ficha=$G_TICKET" --form-string "elegir=$SHA_A" -F "archivo=@$W/b.png" "${URL}w/gal-a/f/1/estado")"
check "W-3 Adjuntos: elegir de la galería y subir a la vez adjunta las dos al hallazgo" "[ '$ATT_CODE' = 303 ] && python3 -c \"import json,sys; r=json.loads(open('$GAL/findings.jsonl').readline()); sys.exit(0 if [x['sha256'] for x in r['evidence']['screenshots']]==['$SHA_A','$SHA_B'] else 1)\" && [ -f '$GAL/evidencia/$SHA_B.png' ]"
curl -fsS "${URL}w/gal-a/f/1" > "$W/gal-state2.html"
G_SEEN="$(form_value "$W/gal-state2.html" 'action="/w/gal-a/f/1/estado"' visto)"; G_TICKET="$(form_value "$W/gal-state2.html" 'action="/w/gal-a/f/1/estado"' ficha)"
RM_CODE="$(curl -s -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: same-origin' --form-string estado=triaged --form-string corroboracion= --form-string bloqueo= --form-string "visto=$G_SEEN" --form-string "ficha=$G_TICKET" --form-string "quitar-$SHA_A=1" "${URL}w/gal-a/f/1/estado")"
check "W-3 Adjuntos: quitar saca la captura del hallazgo y deja el archivo en la galería" "[ '$RM_CODE' = 303 ] && python3 -c \"import json,sys; r=json.loads(open('$GAL/findings.jsonl').readline()); sys.exit(0 if [x['sha256'] for x in r['evidence']['screenshots']]==['$SHA_B'] else 1)\" && [ -f '$GAL/evidencia/$SHA_A.png' ]"
BEFORE_413="$(sha256sum "$GAL/findings.jsonl" | cut -d' ' -f1)"
OVER=21037057
STATE_413="$(head -c $OVER /dev/zero | curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' -H 'Content-Type: multipart/form-data; boundary=x' -H "Content-Length: $OVER" --data-binary @- "${URL}w/gal-a/f/1/estado")"
GAL_413="$(head -c $OVER /dev/zero | curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' -H 'Content-Type: multipart/form-data; boundary=x' -H "Content-Length: $OVER" --data-binary @- "${URL}w/gal-a/galeria")"
URL_413="$(head -c 70000 /dev/zero | tr '\0' x | curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @- "${URL}w/gal-a/f/1/estado")"
check "W-6 Adjuntos: Content-Length sobre el tope da 413 en estado multipart, galería multipart y estado urlencoded, sin escribir" "[ '$STATE_413' = 413 ] && [ '$GAL_413' = 413 ] && [ '$URL_413' = 413 ] && [ \"\$(sha256sum '$GAL/findings.jsonl' | cut -d' ' -f1)\" = '$BEFORE_413' ]"
curl -sS -D "$W/img-headers" -o "$W/img-body" "${URL}w/gal-a/galeria/$SHA_C.jpg"
NOT_FOUND_CODE="$(curl -s -D "$W/img404-headers" -o "$W/img404-body" -w '%{http_code}' "${URL}w/gal-a/galeria/$(printf 'f%.0s' $(seq 64)).png")"
HEAD_CODE="$(curl -s -o /dev/null -I -w '%{http_code}' "${URL}w/gal-a/galeria/$SHA_C.jpg")"
check "W-8 Adjuntos: la imagen trae sus cabeceras exactas, es la subida y HEAD da 405" "cmp '$W/img-body' '$W/c.jpg' && grep -qi '^Content-Type: image/jpeg' '$W/img-headers' && grep -qi '^X-Content-Type-Options: nosniff' '$W/img-headers' && grep -qi \"^Content-Security-Policy: default-src 'none'; sandbox\" '$W/img-headers' && grep -qi '^Cross-Origin-Resource-Policy: same-origin' '$W/img-headers' && grep -qi '^Cache-Control: no-store' '$W/img-headers' && [ '$HEAD_CODE' = 405 ]"
check "W-8 Adjuntos: un hash ausente da el 404 fijo sin imagen" "[ '$NOT_FOUND_CODE' = 404 ] && ! grep -qi '^Content-Type: image' '$W/img404-headers'"
curl -fsS "${URL}w/gal-a/galeria" > "$W/gal-1.html"
DEL_URL_PATH="$(python3 -c 'import re,sys; print(re.search(r"action=\"(/w/gal-a/galeria/%s\.png/borrar)\"" % sys.argv[2], open(sys.argv[1]).read())[1])' "$W/gal-1.html" "$SHA_A")"
DEL_TICKET="$(form_value "$W/gal-1.html" "action=\"$DEL_URL_PATH\"" ficha)"; DEL_STAMP="$(form_value "$W/gal-1.html" "action=\"$DEL_URL_PATH\"" huella)"
NO_BOX="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' --data-urlencode "ficha=$DEL_TICKET" --data-urlencode "huella=$DEL_STAMP" "${URL}${DEL_URL_PATH#/}")"
DEL_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' --data-urlencode "ficha=$DEL_TICKET" --data-urlencode "huella=$DEL_STAMP" --data-urlencode confirmar=1 "${URL}${DEL_URL_PATH#/}")"
check "W-7 Adjuntos: borrar exige la casilla; con ella da 303, quita el archivo y la ruta da 404" "[ '$NO_BOX' = 422 ] && [ '$DEL_CODE' = 303 ] && [ ! -e '$GAL/evidencia/$SHA_A.png' ] && [ \"\$(curl -s -o /dev/null -w '%{http_code}' '${URL}w/gal-a/galeria/$SHA_A.png')\" = 404 ]"

kill -INT "$SERVE_PID" 2>/dev/null
check "serve: SIGINT lo termina" "poll '! kill -0 $SERVE_PID'"
SERVE_PID=""
check "serve: el puerto queda libre" "! curl -s -o /dev/null --max-time 2 '$URL'"

# Spec 021 T11: same code in an isolated tree, an extra template, and a second server.
TEMPLATE_CODE="$W/code"
mkdir -p "$TEMPLATE_CODE"
cp "$REPO/.claude/tools/findings.py" "$REPO/.claude/tools/findings_web.py" \
  "$REPO/.claude/tools/sanitize_target_content.py" "$TEMPLATE_CODE/"
cp -R "$REPO/.claude/tools/report-templates" "$TEMPLATE_CODE/report-templates"
python3 -I -c 'import json,sys; sys.path.insert(0,sys.argv[1]); from findings import SELFTEST_TEMPLATE; open(sys.argv[2],"w",encoding="utf-8").write(json.dumps(SELFTEST_TEMPLATE,ensure_ascii=False))' \
  "$TEMPLATE_CODE" "$TEMPLATE_CODE/report-templates/prueba.json"
cp "$TEMPLATE_CODE/report-templates/prueba.json" "$W/prueba-original.json"
cp "$TEMPLATE_CODE/report-templates/prueba.json" "$TEMPLATE_CODE/report-templates/invalida.json"
python3 -I -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p,encoding="utf-8")); d["etiqueta"]="<script>x</script>&\""; open(p,"w",encoding="utf-8").write(json.dumps(d,ensure_ascii=False))' \
  "$TEMPLATE_CODE/report-templates/invalida.json"
cp "$TEMPLATE_CODE/report-templates/prueba.json" "$TEMPLATE_CODE/report-templates/a\"b.json"
cp "$TEMPLATE_CODE/report-templates/prueba.json" "$TEMPLATE_CODE/report-templates/ñ.json"
TEMPLATE_ROOT="$W/template-root"
mkdir -p "$TEMPLATE_ROOT/engagements/demo-ws"
cp "$W/root/engagements/demo-ws/scope.txt" "$W/root/engagements/demo-ws/findings.jsonl" "$TEMPLATE_ROOT/engagements/demo-ws/"
TEMPLATE_LEDGER="$TEMPLATE_ROOT/engagements/demo-ws/findings.jsonl"
TEMPLATE_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
if [ -z "$TEMPLATE_PORT" ]; then
  echo "BLOCKED: copied-template HTTP checks require a loopback port; this sandbox denied the bind" >&2
  exit 1
fi
python3 "$TEMPLATE_CODE/findings_web.py" serve --root "$TEMPLATE_ROOT" --port "$TEMPLATE_PORT" > "$W/template-serve.out" 2> "$W/template-serve.err" &
TEMPLATE_SERVE_PID=$!
poll "[ -s '$W/template-serve.out' ]"
TEMPLATE_URL="$(head -n1 "$W/template-serve.out")"
check "T11 serve: la copia responde en su puerto efímero" "[ '$TEMPLATE_URL' = 'http://127.0.0.1:$TEMPLATE_PORT/' ] && [ \"\$(curl -s -o /dev/null -w '%{http_code}' '$TEMPLATE_URL')\" = 200 ]"

template_selector() { # file → ordered names and the aria-current selection from the selector links
  python3 - "$1" <<'PY'
import re,sys
page=open(sys.argv[1],encoding="utf-8").read().split('<div class="report-opts">',1)[0]
links=re.findall(r'<a href="\?tipo=([^&"]+)[^"]*"([^>]*)>([^<]+)</a>',page)
selected=next((name for name,attrs,_label in links if 'aria-current="true"' in attrs),"")
print(",".join(name for name,_attrs,_label in links)+"|"+selected)
PY
}
template_field() { # file label → code value in the report provenance
  python3 - "$1" "$2" <<'PY'
import re,sys
page=open(sys.argv[1],encoding="utf-8").read()
match=re.search(re.escape(sys.argv[2])+r': <code>([^<]+)</code>',page)
print(match.group(1) if match else "")
PY
}
curl -fsS "${TEMPLATE_URL}w/demo-ws/reporte" > "$W/template-default.html"
curl -fsS "${TEMPLATE_URL}w/demo-ws/reporte?tipo=prueba&idioma=es" > "$W/template-prueba-page.html"
DEFAULT_SELECTOR="$(template_selector "$W/template-default.html")"
PRUEBA_SELECTOR="$(template_selector "$W/template-prueba-page.html")"
check "T11 AC3: selector ordena Técnico, Ejecutivo, Prueba y Técnico es el default" "[ '$DEFAULT_SELECTOR' = 'tecnico,ejecutivo,prueba|tecnico' ] && [ '$PRUEBA_SELECTOR' = 'tecnico,ejecutivo,prueba|prueba' ]"
check "T11 AC3: los enlaces del selector conservan aria-current" "grep -q 'href=\"?tipo=tecnico[^\"]*\" aria-current=\"true\">Técnico</a>' '$W/template-default.html' && grep -q 'href=\"?tipo=prueba[^\"]*\" aria-current=\"true\">Prueba</a>' '$W/template-prueba-page.html'"
PRUEBA_PAGE_LEDGER="$(template_field "$W/template-prueba-page.html" 'Ledger SHA-256')"
PRUEBA_PAGE_TEMPLATE="$(template_field "$W/template-prueba-page.html" 'Plantilla SHA-256')"
curl -fsS "${TEMPLATE_URL}w/demo-ws/reporte.html?tipo=prueba&idioma=es&ledger=$PRUEBA_PAGE_LEDGER&borrador=ninguno&plantilla=$PRUEBA_PAGE_TEMPLATE" > "$W/template-prueba-download.html"
check "T11 AC4: el acento de prueba llega a preview y HTML" "grep -q 'class=\"preview sheet doc acento acento-azul\"' '$W/template-prueba-page.html' && grep -q 'class=\"doc acento acento-azul\"' '$W/template-prueba-download.html'"

template_tree_sha() {
  python3 - "$1" <<'PY'
import hashlib,os,sys
root=os.path.abspath(sys.argv[1]); digest=hashlib.sha256()
for base,dirs,files in os.walk(root,followlinks=False):
    dirs.sort(); files.sort()
    for name in dirs+files:
        path=os.path.join(base,name); rel=os.path.relpath(path,root).encode()
        digest.update(rel+b"\0")
        if os.path.islink(path): digest.update(b"L"+os.readlink(path).encode())
        elif os.path.isfile(path): digest.update(b"F"+hashlib.sha256(open(path,"rb").read()).digest())
        else: digest.update(b"D")
print(digest.hexdigest())
PY
}
check "T11 AC5: la plantilla hostil se rechaza y el aviso nombra archivo y clave" "grep -q 'invalida.json' '$W/template-default.html' && grep -q 'etiqueta' '$W/template-default.html' && [ '$(template_selector "$W/template-default.html")' = 'tecnico,ejecutivo,prueba|tecnico' ]"
curl -fsS --get --data-urlencode 'tipo=desconocido' "${TEMPLATE_URL}w/demo-ws/reporte" > "$W/template-unknown-page.html"
UNKNOWN_DOWNLOAD="$(curl -s -o "$W/template-unknown.out" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte.md?tipo=desconocido")"
BAD_TREE_BEFORE="$(template_tree_sha "$TEMPLATE_ROOT/engagements/demo-ws")"
INVALID_POST="$(curl -s -o "$W/template-invalid-post.out" -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' --data-urlencode 'tipo=invalida' --data-urlencode 'accion=guardar' --data-urlencode 'visto=ninguno' "${TEMPLATE_URL}w/demo-ws/reporte/borrador")"
BAD_TREE_AFTER="$(template_tree_sha "$TEMPLATE_ROOT/engagements/demo-ws")"
check "T11 AC5: tipo inválido cae al default, descarga 404 y POST 400 sin cambiar el workspace" "[ '$(template_selector "$W/template-unknown-page.html")' = 'tecnico,ejecutivo,prueba|tecnico' ] && [ '$UNKNOWN_DOWNLOAD' = 404 ] && [ '$INVALID_POST' = 400 ] && [ '$BAD_TREE_BEFORE' = '$BAD_TREE_AFTER' ]"
curl -fsS "${TEMPLATE_URL}w/demo-ws/reporte" > "$W/template-invalid-names.html"
check "T11 AC6: nombres con comilla o Unicode se rechazan con su nombre" "grep -q 'a&quot;b.json' '$W/template-invalid-names.html' && grep -q 'ñ.json' '$W/template-invalid-names.html' && [ '$(template_selector "$W/template-invalid-names.html")' = 'tecnico,ejecutivo,prueba|tecnico' ]"
DOTDOT_PAGE="$(curl -s -o "$W/template-dotdot-page.html" -w '%{http_code}' --get --data-urlencode 'tipo=../x' "${TEMPLATE_URL}w/demo-ws/reporte")"
DOTDOT_DOWNLOAD="$(curl -s -o "$W/template-dotdot.out" -w '%{http_code}' --get --data-urlencode 'tipo=../x' "${TEMPLATE_URL}w/demo-ws/reporte.md")"
JSON_SUFFIX_DOWNLOAD="$(curl -s -o "$W/template-suffix.out" -w '%{http_code}' --get --data-urlencode 'tipo=tecnico.json' "${TEMPLATE_URL}w/demo-ws/reporte.md")"
check "T11 AC6: tipo con ruta o sufijo JSON no abre archivos" "[ '$DOTDOT_PAGE' = 200 ] && [ '$(template_selector "$W/template-dotdot-page.html")' = 'tecnico,ejecutivo,prueba|tecnico' ] && [ '$DOTDOT_DOWNLOAD' = 404 ] && [ '$JSON_SUFFIX_DOWNLOAD' = 404 ]"
cp "$TEMPLATE_CODE/report-templates/tecnico.json" "$W/tecnico-original.json"
printf '{' > "$TEMPLATE_CODE/report-templates/tecnico.json"
curl -fsS "${TEMPLATE_URL}w/demo-ws/reporte" > "$W/template-broken-builtin.html"
check "T11 AC5: Técnico roto se avisa sin vista previa" "grep -q 'tecnico.json' '$W/template-broken-builtin.html' && ! grep -q 'class=\"paper\"' '$W/template-broken-builtin.html'"
cp "$W/tecnico-original.json" "$TEMPLATE_CODE/report-templates/tecnico.json"

for tipo in tecnico ejecutivo prueba; do
  for lang in es en; do
    curl -fsS "${TEMPLATE_URL}w/demo-ws/reporte?tipo=$tipo&idioma=$lang" > "$W/template-$tipo-$lang-page.html"
    TP_SHA="$(template_field "$W/template-$tipo-$lang-page.html" 'Plantilla SHA-256')"
    TL_SHA="$(template_field "$W/template-$tipo-$lang-page.html" 'Ledger SHA-256')"
    TD_SHA="$(template_field "$W/template-$tipo-$lang-page.html" 'Borrador SHA-256')"
    TM_SHA="$(template_field "$W/template-$tipo-$lang-page.html" 'Markdown SHA-256')"
    TH_SHA="$(template_field "$W/template-$tipo-$lang-page.html" 'HTML SHA-256')"
    T_FILE_SHA="$(sha256sum "$TEMPLATE_CODE/report-templates/$tipo.json" | cut -d' ' -f1)"
    T_LEDGER_SHA="$(sha256sum "$TEMPLATE_LEDGER" | cut -d' ' -f1)"
    T_QUERY="tipo=$tipo&idioma=$lang&ledger=$TL_SHA&borrador=$TD_SHA&plantilla=$TP_SHA"
    T_MD_CODE="$(curl -s -D "$W/template-$tipo-$lang.md.headers" -o "$W/template-$tipo-$lang.md" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte.md?$T_QUERY")"
    T_HTML_CODE="$(curl -s -D "$W/template-$tipo-$lang.html.headers" -o "$W/template-$tipo-$lang.html" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte.html?$T_QUERY")"
    T_PRINT_CODE="$(curl -s -D "$W/template-$tipo-$lang.print.headers" -o "$W/template-$tipo-$lang.print.html" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte.imprimir?$T_QUERY")"
    T_MD_SHA="$(sha256sum "$W/template-$tipo-$lang.md" | cut -d' ' -f1)"
    T_HTML_SHA="$(sha256sum "$W/template-$tipo-$lang.html" | cut -d' ' -f1)"
    T_PRINT_SHA="$(sha256sum "$W/template-$tipo-$lang.print.html" | cut -d' ' -f1)"
    python3 -I "$TEMPLATE_CODE/findings.py" render --ledger "$TEMPLATE_LEDGER" --tipo "$tipo" --lang "$lang" --workspace demo-ws > "$W/template-$tipo-$lang.cli.md"
    check "T11 AC3/AC10: $tipo/$lang tres formatos, nombre y hashes de Procedencia" "[ '$TP_SHA' = '$T_FILE_SHA' ] && [ '$TL_SHA' = '$T_LEDGER_SHA' ] && [ '$TD_SHA' = ninguno ] && [ '$T_MD_CODE' = 200 ] && [ '$T_HTML_CODE' = 200 ] && [ '$T_PRINT_CODE' = 200 ] && [ '$TM_SHA' = '$T_MD_SHA' ] && [ '$TH_SHA' = '$T_HTML_SHA' ] && [ '$T_PRINT_SHA' = '$T_HTML_SHA' ] && cmp '$W/template-$tipo-$lang.md' '$W/template-$tipo-$lang.cli.md' && grep -qi 'Content-Disposition: attachment; filename=\"demo-ws-reporte-$tipo-$lang.md\"' '$W/template-$tipo-$lang.md.headers' && grep -qi 'Content-Disposition: attachment; filename=\"demo-ws-reporte-$tipo-$lang.html\"' '$W/template-$tipo-$lang.html.headers' && ! grep -qi '^Content-Disposition:' '$W/template-$tipo-$lang.print.headers' && cmp '$W/template-$tipo-$lang.html' '$W/template-$tipo-$lang.print.html'"
  done
done

curl -fsS "${TEMPLATE_URL}w/demo-ws/reporte?tipo=prueba&idioma=es" > "$W/template-stale-page.html"
STALE_LEDGER="$(template_field "$W/template-stale-page.html" 'Ledger SHA-256')"
STALE_DRAFT="$(template_field "$W/template-stale-page.html" 'Borrador SHA-256')"
STALE_TEMPLATE="$(template_field "$W/template-stale-page.html" 'Plantilla SHA-256')"
cp "$TEMPLATE_CODE/report-templates/prueba.json" "$W/prueba-before-stale.json"
python3 -I -c 'import json,sys; p=sys.argv[1]; d=json.load(open(p,encoding="utf-8")); d["textos"]["es"]["titulo"]="Texto actualizado"; open(p,"w",encoding="utf-8").write(json.dumps(d,ensure_ascii=False))' "$TEMPLATE_CODE/report-templates/prueba.json"
STALE_CODE="$(curl -s -D "$W/template-stale.headers" -o "$W/template-stale.out" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte.md?tipo=prueba&idioma=es&ledger=$STALE_LEDGER&borrador=$STALE_DRAFT&plantilla=$STALE_TEMPLATE")"
check "T11 AC10: una plantilla reescrita rechaza la huella vieja sin archivo" "[ '$STALE_CODE' = 409 ] && ! grep -qi '^Content-Disposition:' '$W/template-stale.headers' && ! grep -q '# ' '$W/template-stale.out'"
cp "$W/prueba-before-stale.json" "$TEMPLATE_CODE/report-templates/prueba.json"

curl -fsS "${TEMPLATE_URL}w/demo-ws/reporte?tipo=prueba&idioma=es" > "$W/template-prueba-form.html"
PRUEBA_SEEN="$(form_value "$W/template-prueba-form.html" 'action="/w/demo-ws/reporte/borrador"' visto)"
PRUEBA_TICKET="$(form_value "$W/template-prueba-form.html" 'action="/w/demo-ws/reporte/borrador"' ficha)"
PRUEBA_POST="$(curl -s -o "$W/template-prueba-post.out" -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' \
  --data-urlencode 'tipo=prueba' --data-urlencode 'idioma=es' --data-urlencode 'accion=guardar' \
  --data-urlencode 'resumen=T10-PRUEBA-DRAFT' --data-urlencode 'metodologia=IGNORAR-CAMPO' \
  --data-urlencode "visto=$PRUEBA_SEEN" --data-urlencode "ficha=$PRUEBA_TICKET" "${TEMPLATE_URL}w/demo-ws/reporte/borrador")"
PRUEBA_DRAFT="$TEMPLATE_ROOT/engagements/demo-ws/.gekko-web/borradores/prueba.json"
check "T11 AC11: el borrador prueba sólo guarda campos ofrecidos" "[ '$PRUEBA_POST' = 303 ] && python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); raise SystemExit(0 if d==dict(resumen=\"T10-PRUEBA-DRAFT\") else 1)' '$PRUEBA_DRAFT'"
curl -fsS "${TEMPLATE_URL}w/demo-ws/reporte?tipo=tecnico&idioma=es" > "$W/template-tech-form.html"
TECH_SEEN="$(form_value "$W/template-tech-form.html" 'action="/w/demo-ws/reporte/borrador"' visto)"
TECH_TICKET="$(form_value "$W/template-tech-form.html" 'action="/w/demo-ws/reporte/borrador"' ficha)"
PRUEBA_DRAFT_SHA="$(sha256sum "$PRUEBA_DRAFT" | cut -d' ' -f1)"
CROSS_TICKET_CODE="$(curl -s -o "$W/template-cross-ticket.out" -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' \
  --data-urlencode 'tipo=prueba' --data-urlencode 'idioma=es' --data-urlencode 'accion=guardar' \
  --data-urlencode 'resumen=NO-GUARDAR' --data-urlencode "visto=$TECH_SEEN" --data-urlencode "ficha=$TECH_TICKET" "${TEMPLATE_URL}w/demo-ws/reporte/borrador")"
mv "$TEMPLATE_CODE/report-templates/prueba.json" "$W/prueba-removed.json"
curl -fsS "${TEMPLATE_URL}w/demo-ws/reporte?tipo=prueba&idioma=es" > "$W/template-prueba-removed.html"
PRUEBA_DRAFT_SHA_AFTER_REMOVE="$(sha256sum "$PRUEBA_DRAFT" | cut -d' ' -f1)"
mv "$W/prueba-removed.json" "$TEMPLATE_CODE/report-templates/prueba.json"
curl -fsS "${TEMPLATE_URL}w/demo-ws/reporte?tipo=prueba&idioma=es" > "$W/template-prueba-returned.html"
check "T11 AC11: ficha de Técnico no vale en Prueba y su borrador persiste al quitar/reponer plantilla" "[ '$CROSS_TICKET_CODE' = 403 ] && [ '$PRUEBA_DRAFT_SHA' = '$PRUEBA_DRAFT_SHA_AFTER_REMOVE' ] && grep -q 'T10-PRUEBA-DRAFT' '$W/template-prueba-returned.html'"

# Spec 021 T12h: branded fixtures live only in the copied T11 tree.
mkdir -p "$TEMPLATE_CODE/report-templates/marcas"
python3 -I -c '
import copy,json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from findings import SELFTEST_MARCA,selftest_png,selftest_jpeg,strip_image_metadata
code,templates,marks,work=map(Path,sys.argv[1:])
png=selftest_png(1,1,chunks=((b"tEXt",b"T12H-PNG-CANARY"),))
jpeg=selftest_jpeg(1,1,segmentos=((0xe1,b"T12H-JPEG-CANARY"),))
def write(slug,label,name,logo,pie,color=None):
    data=copy.deepcopy(SELFTEST_MARCA)
    data["etiqueta"]=label
    data["marca"].update(nombre=name,logo=logo,pie={"es":pie,"en":"Fictional test use"})
    if color is None: data["marca"].pop("color",None)
    else: data["marca"]["color"]=color
    (templates/(slug+".json")).write_text(json.dumps(data,ensure_ascii=False),encoding="utf-8")
write("marca-prueba","Marca prueba","Empresa Ficticia & Asociados","marca-prueba","Pie ficticio","#2B5D8C")
write("marca-jpeg","Marca JPEG","Empresa JPEG ficticia","marca-jpeg","Pie JPEG ficticio")
broken=copy.deepcopy(SELFTEST_MARCA)
broken["etiqueta"]="Marca rota"
broken["marca"]["logo"]="../x"
(templates/"marca-rota.json").write_text(json.dumps(broken,ensure_ascii=False),encoding="utf-8")
(marks/"marca-prueba.png").write_bytes(png)
(marks/"marca-jpeg.jpg").write_bytes(jpeg)
(work/"marca-prueba-clean.png").write_bytes(strip_image_metadata(png))
(work/"marca-jpeg-clean.jpg").write_bytes(strip_image_metadata(jpeg))
' "$TEMPLATE_CODE" "$TEMPLATE_CODE/report-templates" "$TEMPLATE_CODE/report-templates/marcas" "$W"
check "T12h fixtures: PNG/JPEG ficticios sólo en la copia temporal" "test -f '$TEMPLATE_CODE/report-templates/marca-prueba.json' && test -f '$TEMPLATE_CODE/report-templates/marca-jpeg.json' && grep -aFq T12H-PNG-CANARY '$TEMPLATE_CODE/report-templates/marcas/marca-prueba.png' && grep -aFq T12H-JPEG-CANARY '$TEMPLATE_CODE/report-templates/marcas/marca-jpeg.jpg'"

BRAND_PAGE_CODE="$(curl -s -o "$W/marca-prueba-page.html" -D "$W/marca-prueba-page.headers" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte?tipo=marca-prueba&idioma=es")"
JPEG_PAGE_CODE="$(curl -s -o "$W/marca-jpeg-page.html" -D "$W/marca-jpeg-page.headers" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte?tipo=marca-jpeg&idioma=es")"
BRAND_LEDGER="$(template_field "$W/marca-prueba-page.html" 'Ledger SHA-256')"
BRAND_DRAFT="$(template_field "$W/marca-prueba-page.html" 'Borrador SHA-256')"
BRAND_TEMPLATE="$(template_field "$W/marca-prueba-page.html" 'Plantilla SHA-256')"
BRAND_LOGO="$(template_field "$W/marca-prueba-page.html" 'Logo SHA-256')"
JPEG_LEDGER="$(template_field "$W/marca-jpeg-page.html" 'Ledger SHA-256')"
JPEG_DRAFT="$(template_field "$W/marca-jpeg-page.html" 'Borrador SHA-256')"
JPEG_TEMPLATE="$(template_field "$W/marca-jpeg-page.html" 'Plantilla SHA-256')"
JPEG_LOGO="$(template_field "$W/marca-jpeg-page.html" 'Logo SHA-256')"
BRAND_QUERY="tipo=marca-prueba&idioma=es&ledger=$BRAND_LEDGER&borrador=$BRAND_DRAFT&plantilla=$BRAND_TEMPLATE&logo=$BRAND_LOGO"
JPEG_QUERY="tipo=marca-jpeg&idioma=es&ledger=$JPEG_LEDGER&borrador=$JPEG_DRAFT&plantilla=$JPEG_TEMPLATE&logo=$JPEG_LOGO"
BRAND_HTML_CODE="$(curl -s -o "$W/marca-prueba.html" -D "$W/marca-prueba.html.headers" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte.html?$BRAND_QUERY")"
BRAND_PRINT_CODE="$(curl -s -o "$W/marca-prueba.print.html" -D "$W/marca-prueba.print.headers" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte.imprimir?$BRAND_QUERY")"
JPEG_HTML_CODE="$(curl -s -o "$W/marca-jpeg.html" -D "$W/marca-jpeg.html.headers" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte.html?$JPEG_QUERY")"
JPEG_PRINT_CODE="$(curl -s -o "$W/marca-jpeg.print.html" -D "$W/marca-jpeg.print.headers" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte.imprimir?$JPEG_QUERY")"
TECH_PAGE_CODE="$(curl -s -o "$W/marca-tecnico-page.html" -D "$W/marca-tecnico-page.headers" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte?tipo=tecnico&idioma=es")"
TECH_LEDGER="$(template_field "$W/marca-tecnico-page.html" 'Ledger SHA-256')"
TECH_DRAFT="$(template_field "$W/marca-tecnico-page.html" 'Borrador SHA-256')"
TECH_TEMPLATE="$(template_field "$W/marca-tecnico-page.html" 'Plantilla SHA-256')"
TECH_QUERY="tipo=tecnico&idioma=es&ledger=$TECH_LEDGER&borrador=$TECH_DRAFT&plantilla=$TECH_TEMPLATE"
TECH_HTML_CODE="$(curl -s -o "$W/marca-tecnico.html" -D "$W/marca-tecnico.html.headers" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte.html?$TECH_QUERY")"
check "T12h HTTP: páginas y descargas PNG/JPEG y Técnico responden 200" "[ '$BRAND_PAGE_CODE' = 200 ] && [ '$JPEG_PAGE_CODE' = 200 ] && [ '$BRAND_HTML_CODE' = 200 ] && [ '$BRAND_PRINT_CODE' = 200 ] && [ '$JPEG_HTML_CODE' = 200 ] && [ '$JPEG_PRINT_CODE' = 200 ] && [ '$TECH_PAGE_CODE' = 200 ] && [ '$TECH_HTML_CODE' = 200 ]"

cat > "$W/verify-brand.py" <<'PY_VERIFY_BRAND'
import base64,hashlib,html,re,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from findings_web import BRAND_PNG
_,code,brand_page,brand_html,brand_print_headers,png_clean,jpeg_page,jpeg_html,jpeg_print_headers,jpeg_clean,brand_page_headers,tech_page_headers,tech_html=sys.argv
def need(condition,message):
    if not condition: raise SystemExit(message)
def header(path):
    return next((line.split(":",1)[1].strip() for line in Path(path).read_text().splitlines()
                 if line.lower().startswith("content-security-policy:")),"")
def style(path):
    found=re.findall(r"<style>(.*?)</style>",Path(path).read_text(encoding="utf-8"),re.S)
    need(len(found)==1,f"{path}: style count")
    return found[0]
def preview(path,mime,clean,alt,canary):
    body=Path(path).read_text(encoding="utf-8")
    tags=re.findall(r'<img class="dmarca"[^>]*>',body)
    need(len(tags)==1,f"{path}: preview image count")
    match=re.fullmatch(r'<img class="dmarca" src="data:(image/png|image/jpeg);base64,([A-Za-z0-9+/=]+)" alt="([^"<>]*)">',tags[0])
    need(match is not None,f"{path}: preview image form")
    raw=base64.b64decode(match.group(2),validate=True)
    need(match.group(1)==mime and raw==Path(clean).read_bytes(),f"{path}: cleaned image")
    need(match.group(3)==html.escape(alt,quote=True),f"{path}: escaped alt")
    need(canary not in body and canary.encode() not in raw,f"{path}: metadata leak")
def document(path,headers,clean,mime,color,name,footer):
    body=Path(path).read_text(encoding="utf-8")
    sheet=style(path)
    encoded=base64.b64encode(Path(clean).read_bytes()).decode()
    need(f"url(data:{mime};base64,{encoded})" in sheet,f"{path}: logo CSS")
    need(color in sheet if color else ".acento-marca{" not in sheet,f"{path}: accent CSS")
    foot=re.search(r'<tfoot class="print-foot"><tr><td>(.*?)</td></tr></tfoot>',body,re.S)
    need(foot is not None and html.escape(name) in foot.group(1) and html.escape(footer) in foot.group(1),f"{path}: escaped footer")
    digest=base64.b64encode(hashlib.sha256(sheet.encode()).digest()).decode()
    need(f"sha256-{digest}" in body,f"{path}: embedded CSP hash")
    need(f"style-src 'sha256-{digest}'" in header(headers),f"{headers}: response CSP hash")
preview(brand_page,"image/png",png_clean,"Empresa Ficticia & Asociados","T12H-PNG-CANARY")
preview(jpeg_page,"image/jpeg",jpeg_clean,"Empresa JPEG ficticia","T12H-JPEG-CANARY")
document(brand_html,brand_print_headers,png_clean,"image/png",".acento-marca{--al:#2b5d8c;--an:#2b5d8c}","Empresa Ficticia & Asociados","Pie ficticio")
document(jpeg_html,jpeg_print_headers,jpeg_clean,"image/jpeg","","Empresa JPEG ficticia","Pie JPEG ficticio")
need(header(brand_page_headers)==header(tech_page_headers),"page CSP changed with branded template")
tech=Path(tech_html).read_text(encoding="utf-8")
need("url(data:image/png;base64,"+BRAND_PNG["horizontal-claro"]+")" in style(tech_html),"tecnico HTML missing Gekko logo")
need(base64.b64encode(Path(png_clean).read_bytes()).decode() not in tech and base64.b64encode(Path(jpeg_clean).read_bytes()).decode() not in tech,"tecnico HTML leaked template logo")
print("PNG/JPEG preview, download CSS, footer and CSP OK")
PY_VERIFY_BRAND
python3 -I "$W/verify-brand.py" "$TEMPLATE_CODE" "$W/marca-prueba-page.html" "$W/marca-prueba.html" "$W/marca-prueba.print.headers" "$W/marca-prueba-clean.png" "$W/marca-jpeg-page.html" "$W/marca-jpeg.html" "$W/marca-jpeg.print.headers" "$W/marca-jpeg-clean.jpg" "$W/marca-prueba-page.headers" "$W/marca-tecnico-page.headers" "$W/marca-tecnico.html"
BRAND_VERIFY_CODE=$?
check "T12h AC14/AC15/AC16: preview PNG/JPEG, CSS, pies y CSP" "[ '$BRAND_VERIFY_CODE' = 0 ] && cmp '$W/marca-prueba.html' '$W/marca-prueba.print.html' && cmp '$W/marca-jpeg.html' '$W/marca-jpeg.print.html'"
BRAND_LOGO_FILE_SHA="$(sha256sum "$TEMPLATE_CODE/report-templates/marcas/marca-prueba.png" | cut -d' ' -f1)"
check "T12h AC17: Procedencia logo coincide con SHA-256 del PNG" "[ '$BRAND_LOGO' = '$BRAND_LOGO_FILE_SHA' ] && grep -q 'logo=$BRAND_LOGO' '$W/marca-prueba-page.html'"
check "T12h AC18: marca-rota se rechaza y el aviso nombra archivo y clave" "grep -q 'marca-rota.json' '$W/marca-prueba-page.html' && grep -q 'marca.logo' '$W/marca-prueba-page.html'"
cp "$TEMPLATE_CODE/report-templates/marcas/marca-prueba.png" "$W/marca-prueba-original.png"
python3 -I -c 'import sys; sys.path.insert(0,sys.argv[1]); from findings import selftest_png; open(sys.argv[2],"wb").write(selftest_png(2,1))' "$TEMPLATE_CODE" "$TEMPLATE_CODE/report-templates/marcas/marca-prueba.png"
STALE_BRAND_CODE="$(curl -s -o "$W/marca-prueba-stale.out" -D "$W/marca-prueba-stale.headers" -w '%{http_code}' "${TEMPLATE_URL}w/demo-ws/reporte.html?$BRAND_QUERY")"
check "T12h AC17: pin logo obsoleto da 409 sin archivo" "[ '$STALE_BRAND_CODE' = 409 ] && ! grep -qi '^Content-Disposition:' '$W/marca-prueba-stale.headers'"
kill -INT "$TEMPLATE_SERVE_PID" 2>/dev/null
check "T11 serve: se apaga sólo el PID numérico del servidor de plantillas" "poll '! kill -0 $TEMPLATE_SERVE_PID'"
TEMPLATE_SERVE_PID=""
check "T11 serve: el segundo puerto queda libre" "! curl -s -o /dev/null --max-time 2 '$TEMPLATE_URL'"

# prompts de los agentes que escriben en el ledger (AC25)
for prompt in .claude/agents/finding-analyzer.md .claude/agents/exploit-developer.md .pi/agents/finding-analyzer.md; do
  for word in --summary --impact --remediation --cvss --cvss-vector --cwe --cve "never guess"; do
    check "prompt $prompt nombra '$word'" "grep -q -e '$word' '$REPO/$prompt'"
  done
done
for prompt in .claude/agents/report-writer.md .pi/agents/report-writer.md .codex/agents/report-writer.toml; do
  check "prompt $prompt documents language, type and corroboration filter" "grep -q -- '--lang' '$REPO/$prompt' && grep -q -- '--tipo' '$REPO/$prompt' && grep -qi 'nonblank corroboration\|corroboration' '$REPO/$prompt' && grep -qi 'confirmed' '$REPO/$prompt'"
done

# spec 024: comentario con imagen subida con curl -F, script fijado sólo en el reporte, Remediado, report-writer y tope del CSS
python3 -I -c 'import sys; sys.path.insert(0,sys.argv[1]); from findings import selftest_png; open(sys.argv[2],"wb").write(selftest_png(7,7))' "$REPO/.claude/tools" "$W/comentario.png"
mkdir -p "$W/root24/engagements/demo-ws"
echo "10.0.0.5" > "$W/root24/engagements/demo-ws/scope.txt"
cat > "$W/root24/engagements/demo-ws/findings.jsonl" <<'JSON'
{"id":"F-S1","title":"open hypothesis","severity":"low","status":"hypothesis","target":"fixture-one"}
{"id":"F-S4","title":"confirmed to remediate","severity":"high","status":"confirmed","corroboration":"independent fixture signal","target":"fixture-four"}
JSON
LEDGER="$W/root24/engagements/demo-ws/findings.jsonl"
PORT24="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
python3 "$REPO/.claude/tools/findings_web.py" serve --root "$W/root24" --port "$PORT24" > "$W/serve24.out" 2> "$W/serve24.err" &
SPEC24_PID=$!
poll "[ -s '$W/serve24.out' ]"
URL="$(head -n1 "$W/serve24.out")"
curl -fsS "${URL}w/demo-ws/f/2" > "$W/comment-form.html"
scrape() { python3 -I -c 'import re,sys; print(re.search(r"name=\"%s\" value=\"([a-f0-9]+)\"" % sys.argv[3],open(sys.argv[1]).read().split(sys.argv[2])[1])[1])' "$@"; }
C_NUEVO="$(scrape "$W/comment-form.html" '/comentario"' nuevo)"; C_FICHA="$(scrape "$W/comment-form.html" '/comentario"' ficha)"
COMMENT_CODE="$(curl -s -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: same-origin' -F "archivo=@$W/comentario.png" \
  --form-string 'texto=captura de la nueva prueba' --form-string 'accion=agregar' --form-string "nuevo=$C_NUEVO" --form-string "ficha=$C_FICHA" "${URL}w/demo-ws/f/2/comentario")"
PNG_SHA="$(sha256sum "$W/comentario.png" | cut -d' ' -f1)"
check "spec 024 AC1: comentario con imagen subida por curl -F da 303 y guarda el mismo sha256" "[ '$COMMENT_CODE' = 303 ] && [ \"\$(sha256sum '$W/root24/engagements/demo-ws/evidencia/$PNG_SHA.png' | cut -d' ' -f1)\" = '$PNG_SHA' ] && curl -fsS '${URL}w/demo-ws/f/2' | grep -q 'alt=\"Captura 1\"'"
curl -fsS -D "$W/report-csp.headers" "${URL}w/demo-ws/reporte" -o "$W/report-csp.html"
curl -fsS -D "$W/list-csp.headers" "${URL}w/demo-ws/" -o /dev/null
check "spec 024 AC5: la CSP del reporte lleva script-src con hash y la de la lista no" "grep -qi \"^Content-Security-Policy:.*script-src 'sha256-\" '$W/report-csp.headers' && ! grep -qi 'script-src' '$W/list-csp.headers' && [ \"\$(grep -c '<script' '$W/report-csp.html')\" = 1 ]"
remediar() { # remediar <nota>: confirmed -> remediated sobre F-S4 (línea 2), imprime el código HTTP
  curl -fsS "${URL}w/demo-ws/f/2" > "$W/rem-form.html"
  local seen ficha; seen="$(scrape "$W/rem-form.html" '/estado"' visto)"; ficha="$(scrape "$W/rem-form.html" '/estado"' ficha)"
  curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: same-origin' --data-urlencode 'estado=remediated' --data-urlencode 'corroboracion=' \
    --data-urlencode 'bloqueo=' --data-urlencode "retest=$1" --data-urlencode "visto=$seen" --data-urlencode "ficha=$ficha" "${URL}w/demo-ws/f/2/estado"
}
REM_NONE="$(remediar '')"; REM_OK="$(remediar 'se repitió el payload tras el parche y devuelve 403')"
check "spec 024 AC9: confirmed -> remediated sin nota da 422 y con nota 303" "[ '$REM_NONE' = 422 ] && [ '$REM_OK' = 303 ] && grep -q '\"status\": \"remediated\"\|\"status\":\"remediated\"' '$LEDGER'"
check "spec 024 AC9: la lista filtra por remediado y muestra la insignia" "curl -fsS '${URL}w/demo-ws/?status=remediated' | grep -q 'st-remediated'"
for prompt in .claude/agents/report-writer.md .pi/agents/report-writer.md .codex/agents/report-writer.toml; do
  check "spec 024 AC12: $prompt nombra remediated" "grep -q 'remediated' '$REPO/$prompt'"
done
CSS_BYTES="$(python3 -I -c 'import sys; sys.path.insert(0,sys.argv[1]); import findings_web; print(len(findings_web.CSS.encode()))' "$REPO/.claude/tools")"
check "spec 024 AC13: el CSS de las páginas es ≤ 100000 bytes ($CSS_BYTES)" "[ '$CSS_BYTES' -le 100000 ]"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
