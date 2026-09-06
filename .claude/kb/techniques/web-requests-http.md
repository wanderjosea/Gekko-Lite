---
title: HTTP/HTTPS Web Requests (cURL + DevTools)
slug: web-requests-http
category: techniques
updated: 2026-08-20
summary: "Fundamentos HTTP para pentest web: URL/headers/métodos/códigos, cURL (-v/-i/-u/-b/-H/-d/-X), basic-auth, cookies de sesión, CRUD sobre APIs"
tags: [web, http, curl, api, recon]
sensitive: false
---

# HTTP/HTTPS Web Requests

## Protocolo de Transferencia de Hipertexto (HTTP)

La mayoría de las comunicaciones por internet se hacen con peticiones web vía HTTP, un protocolo a nivel de aplicación para acceder a recursos de la WWW. Cliente solicita → servidor procesa y devuelve el recurso. Puerto por defecto HTTP: `80` (configurable). Se introduce un FQDN como URL para llegar al sitio.

### URL — estructura

`scheme://user:password@host:port/path?query#fragment`

| Componente | Ejemplo | Descripción |
|---|---|---|
| Esquema | `http://` `https://` | Protocolo; termina en `://` |
| Info de usuario | `admin:password@` | Opcional; credenciales para autenticarse en el host |
| Host | `inlanefreight.com` | Ubicación del recurso (hostname o IP) |
| Puerto | `:80` | Por defecto 80 (http) / 443 (https) |
| Ruta | `/dashboard.php` | Recurso (archivo o carpeta); default index si se omite |
| Query string | `?login=true` | `?param=value`, múltiples con `&` |
| Fragmento | `#status` | Procesado client-side por el navegador |

Campos obligatorios mínimos: esquema y host.

### Flujo HTTP
1. Usuario introduce URL → navegador pide al DNS resolver el dominio → IP.
   - Navegador consulta primero `/etc/hosts`; si no está, contacta DNS. `/etc/hosts` permite añadir registros manuales (IP + dominio).
2. Navegador envía GET al puerto 80 pidiendo `/`.
3. Servidor devuelve `index.html` con código de estado (p. ej. `200 OK`).
4. Navegador renderiza.

### cURL
`cURL` (client URL): CLI + librería, soporta HTTP y muchos protocolos. Ideal para scripting/automatización en pentest web.

```bash
curl http://info.cern.ch/            # imprime HTML crudo (no renderiza)
curl -O http://info.cern.ch/index.html   # guarda con nombre remoto
curl -o out.html http://info.cern.ch/    # guarda con nombre propio
curl -s -O http://info.cern.ch/index.html  # modo silencioso
curl -h            # ayuda por categorías; --help all para todo; man curl
```
Flags clave: `-d` POST data, `-i` incluir headers, `-o/-O` output, `-s` silent, `-u user:pass`, `-A` user-agent, `-v` verbose.

---

## HTTPS (HTTP Seguro)

HTTP transfiere todo en texto plano → vulnerable a MiTM. HTTPS cifra toda la comunicación; estándar actual. Se identifica por `https://` y el candado en la barra.

**Nota:** aunque HTTPS cifra los datos, la URL puede filtrarse vía DNS en texto plano → usar DNS cifrado (8.8.8.8, 1.1.1.1) o VPN.

### Flujo HTTPS
- Si visitas `http://` en un sitio que fuerza HTTPS: request al puerto 80 → servidor redirige (`301 Moved Permanently`) al 443.
- Cliente envía `client hello` → servidor `server hello` → intercambio de certificados SSL → verificación → handshake cifrado → comunicación HTTP normal ya cifrada.
- **HTTP downgrade attack:** MITM degrada HTTPS→HTTP para leer texto plano. Navegadores/servidores modernos protegen contra esto (HSTS).

### cURL para HTTPS
cURL maneja el handshake automáticamente. Con certificado inválido/desactualizado se niega (protección MiTM):
```bash
curl https://inlanefreight.com          # curl: (60) SSL certificate problem
curl -k https://www.inlanefreight.com   # -k omite verificación del certificado
```

---

## Peticiones y Respuestas HTTP

Comunicación = petición (cliente) + respuesta (servidor).

### Petición HTTP
Primera línea: 3 campos separados por espacios.

| Campo | Ejemplo | Descripción |
|---|---|---|
| Method | `GET` | Verbo HTTP; tipo de acción |
| Path | `/users/login.html` | Ruta al recurso (+ query string opcional) |
| Version | `HTTP/1.1` | Versión HTTP |

Luego pares de cabeceras (`Host`, `User-Agent`, `Cookie`, …), terminadas con línea nueva. Opcionalmente cuerpo/datos.

**Nota:** HTTP/1.X = texto plano separado por newlines. HTTP/2.X = datos binarios en forma de diccionario.

### Respuesta HTTP
Primera línea: versión HTTP + código de respuesta (`HTTP/1.1 200 OK`). Luego cabeceras, y opcionalmente cuerpo (HTML, JSON, imágenes, PDF…).

### cURL verbose
```bash
curl inlanefreight.com -v     # muestra request (>) y response (<) completos
curl inlanefreight.com -vvv   # aún más detalle
```

### DevTools del navegador
`CTRL+SHIFT+I` o `F12`. Pestaña **Red/Network** = peticiones web: estado, método, recurso, ruta. `Filtrar URLs` para buscar. Click en request → pestaña Response → botón `Raw` para el cuerpo crudo.

---

## Cabeceras HTTP

Categorías: Generales, de Entidad, de Solicitud, de Respuesta, de Seguridad. Formato `Nombre: valor`.

### Generales (request y response)
| Cabecera | Ejemplo | Descripción |
|---|---|---|
| `Date` | `Date: Wed, 16 Feb 2022 10:38:44 GMT` | Fecha/hora del mensaje (preferible UTC) |
| `Connection` | `Connection: close` | `close` termina conexión / `keep-alive` la mantiene |

### De Entidad (describen el contenido)
| Cabecera | Ejemplo | Descripción |
|---|---|---|
| `Content-Type` | `text/html` | Tipo de recurso; `charset` = codificación |
| `Media-Type` | `application/pdf` | Similar a Content-Type; clave en cómo el server interpreta el input |
| `Boundary` | `boundary="b4e4fbd93540"` | Separador de partes (form-data: `--b4e4fbd93540`) |
| `Content-Length` | `385` | Tamaño de la entidad; el server la usa para leer el cuerpo |
| `Content-Encoding` | `gzip` | Codificación/compresión aplicada |

### De Solicitud
| Cabecera | Ejemplo | Descripción |
|---|---|---|
| `Host` | `www.inlanefreight.com` | Host consultado; **objetivo de enumeración** (vhosts) |
| `User-Agent` | `curl/7.77.0` | Cliente (navegador, versión, OS) |
| `Referer` | `http://.../` | De dónde viene la request; manipulable, no confiar |
| `Accept` | `*/*` | Tipos de media que entiende el cliente |
| `Cookie` | `PHPSESSID=b4e4fbd93540` | Pares `nombre=valor`, identificador de sesión |
| `Authorization` | `BASIC cGFzc3dvcmQK` | Token tras autenticación (se envía cada request) |

### De Respuesta
| Cabecera | Ejemplo | Descripción |
|---|---|---|
| `Server` | `Apache/2.2.14 (Win32)` | Info del server (versión → enumeración) |
| `Set-Cookie` | `PHPSESSID=b4e4fbd93540` | Cookies para el cliente |
| `WWW-Authenticate` | `BASIC realm="localhost"` | Tipo de auth requerida |

### De Seguridad
| Cabecera | Ejemplo | Descripción |
|---|---|---|
| `Content-Security-Policy` | `script-src 'self'` | Restringe recursos externos (mitiga XSS) |
| `Strict-Transport-Security` | `max-age=31536000` | Fuerza HTTPS (HSTS) |
| `Referrer-Policy` | `origin` | Controla el valor del header Referer |

### cURL con cabeceras
```bash
curl -I https://www.inlanefreight.com     # HEAD, solo response headers
curl -i ...                               # headers + cuerpo
curl https://... -A 'Mozilla/5.0'         # setear User-Agent
curl -H 'Header: valor' ...               # setear cabecera (repetible)
```
DevTools → Network → click request → pestaña Headers (botón Raw) y Cookies.

---

## Métodos y códigos HTTP

### Métodos de solicitud
| Método | Descripción |
|---|---|
| `GET` | Solicita recurso; datos vía query string en URL |
| `POST` | Envía datos en el cuerpo (forms, uploads) |
| `HEAD` | Solo cabeceras (sin cuerpo) |
| `PUT` | Crea recursos; sin control → subida maliciosa |
| `DELETE` | Elimina recurso; sin control → DoS por borrado |
| `OPTIONS` | Métodos que acepta el server |
| `PATCH` | Modificación parcial |

Apps modernas usan sobre todo `GET`/`POST`; REST también `PUT`/`DELETE`.

### Códigos de estado
| Clase | Descripción |
|---|---|
| `1xx` | Informativo |
| `2xx` | Éxito |
| `3xx` | Redirección |
| `4xx` | Error del cliente |
| `5xx` | Error del servidor |

Comunes: `200 OK`, `302 Found`, `400 Bad Request`, `403 Forbidden`, `404 Not Found`, `500 Internal Server Error`.

---

## GET

Navegadores hacen GET por defecto al visitar una URL. Monitorear la pestaña Red revela cómo la app interactúa con su backend (esencial en assessments / bug bounty).

### Autenticación Básica HTTP
Gestionada por el server (no la app). Credenciales de ejemplo `admin:admin`.
```bash
curl -i http://<IP>:<PORT>/                       # 401 + WWW-Authenticate: Basic realm="..."
curl -u admin:admin http://<IP>:<PORT>/           # provee credenciales
curl http://admin:admin@<IP>:<PORT>/              # credenciales en la URL
```

### Cabecera Authorization
```bash
curl -v http://admin:admin@<IP>:<PORT>/
# > Authorization: Basic YWRtaW46YWRtaW4=   (base64 de admin:admin)
curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<IP>:<PORT>/   # header manual
```
Auth moderna (JWT) usa `Authorization: Bearer <token>`.

### Parámetros GET
```bash
curl 'http://<IP>:<PORT>/search.php?search=le' -H 'Authorization: Basic YWRtaW46YWRtaW4='
```
DevTools → click derecho en request → `Copy > Copy as cURL` / `Copy as Fetch` (ejecutar en consola JS con `CTRL+SHIFT+K`).

---

## POST

POST coloca los parámetros en el cuerpo (no en la URL). Ventajas: no se registra en logs de URL, menos codificación (acepta binario), más datos (URL ~2000 chars max).

### Formularios de login
```bash
curl -X POST -d 'username=admin&password=admin' http://<IP>:<PORT>/
curl -X POST -d 'username=admin&password=admin' http://<IP>:<PORT>/ -L   # seguir redirección
```

### Cookies autenticadas
```bash
curl -X POST -d 'username=admin&password=admin' http://<IP>:<PORT>/ -i
# Set-Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1; path=/
curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<IP>:<PORT>/     # usar cookie
curl -H 'Cookie: PHPSESSID=...' http://<IP>:<PORT>/                    # o como header
```
DevTools → Storage (`SHIFT+F9`) → Cookies para ver/editar. Una cookie válida basta para autenticarse (relevante en XSS).

### Datos JSON
```bash
curl -X POST -d '{"search":"london"}' -b 'PHPSESSID=...' \
  -H 'Content-Type: application/json' http://<IP>:<PORT>/search.php
# ["London (UK)"]
```

---

## API CRUD

APIs interactúan con la BD: tabla + fila en la URL, método HTTP = operación.

| Operación | Método | Descripción |
|---|---|---|
| Crear | `POST` | Añade datos a la tabla |
| Leer | `GET` | Lee la entidad |
| Actualizar | `PUT` | Actualiza la entrada (PATCH = parcial) |
| Eliminar | `DELETE` | Borra la fila |

### Leer
```bash
curl http://<IP>:<PORT>/api.php/city/london            # [{"city_name":"London","country_name":"(UK)"}]
curl -s http://<IP>:<PORT>/api.php/city/le | jq        # formatea JSON
curl -s http://<IP>:<PORT>/api.php/city/ | jq          # string vacío → todas
```

### Crear
```bash
curl -X POST http://<IP>:<PORT>/api.php/city/ \
  -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```

### Actualizar (PUT)
```bash
curl -X PUT http://<IP>:<PORT>/api.php/city/london \
  -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
```
`OPTIONS` revela si acepta PUT o PATCH. Algunas APIs crean la entrada si no existe (upsert).

### Eliminar
```bash
curl -X DELETE http://<IP>:<PORT>/api.php/city/New_HTB_City
```
Control de acceso: cada usuario debería tener privilegios read/write acotados; si cualquiera puede modificar/borrar → vulnerabilidad. Auth vía cookie o `Authorization` (JWT).

## References
- Relacionado: [[web-proxies]], [[web-app-attacks]], [[api-attacks]], [[web-fuzzing]]
- Curso CWES Bug Bounty → 03-WEB → "WEB Requests" (HTB Academy, traducido). Notion.
