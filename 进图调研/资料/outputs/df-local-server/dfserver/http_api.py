from __future__ import annotations

import base64
import binascii
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from urllib.parse import urlsplit

from .core import DomainError
from .native_identity import CONTENT_TYPE, encode_identity
from .zone_discovery import GET_ZONE_PATH, ZoneDiscovery


MAX_BODY = 1024*1024
UI_ROOT = Path(__file__).resolve().parent / "web"
UI_ROUTES = {"/": ("index.html", "text/html; charset=utf-8"),
             "/ui/": ("index.html", "text/html; charset=utf-8"),
             "/ui/index.html": ("index.html", "text/html; charset=utf-8"),
             "/ui/app.js": ("app.js", "text/javascript; charset=utf-8"),
             "/ui/style.css": ("style.css", "text/css; charset=utf-8")}


def handler_factory(backend, codec, zone_discovery):
    class Handler(BaseHTTPRequestHandler):
        server_version = "LocalBackend/0.1"

        def _bytes(self, status, encoded, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)
            self.close_connection = True

        def _respond(self, status, value):
            self._bytes(status, json.dumps(value,ensure_ascii=False,allow_nan=False).encode("utf-8"),
                        "application/json; charset=utf-8")

        def _local_request(self):
            allowed = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
            if self.headers.get("Host", "").lower() not in allowed:
                self._error("INVALID_HOST", "Use the local service address",403)
                return False
            origin = self.headers.get("Origin")
            if origin and origin.lower() not in {"http://" + host for host in allowed}:
                self._error("INVALID_ORIGIN", "Use the local entrance for browser requests",403)
                return False
            return True

        def _error(self, code, message, status=400):
            self._respond(status,{"ok":False,"error":{"code":code,"message":message},"game_compatibility_verified":False})

        def do_GET(self):
            if not self._local_request():
                return
            path = urlsplit(self.path).path
            if path in UI_ROUTES:
                filename, content_type = UI_ROUTES[path]
                self._bytes(200,(UI_ROOT/filename).read_bytes(),content_type)
            elif path == "/healthz":
                self._respond(200,{"ok":True,"service":"persistent_local_backend","game_compatibility_verified":False,
                                   "local_frontend_version":1,"native_identity_version":1})
            elif path == "/api/local/catalog":
                self._respond(200,{"ok":True,"result":{"items":backend.definitions["items"],
                                                          "containers":backend.definitions["containers"]},
                                   "game_compatibility_verified":False})
            elif path == "/api/status":
                self._respond(200,{"ok":True,"operations":sorted(backend.READS|backend.WRITES),
                                   "protocol":codec.status(),"zone_discovery":zone_discovery.status(),
                                   "local_accounts":{"provider":"local","password_required":True,
                                                     "original_client_adapter_verified":False},
                                   "game_compatibility_verified":False})
            else:
                self._error("NOT_FOUND", "Development API route does not exist",404)

        def do_POST(self):
            if not self._local_request():
                return
            if self.headers.get("Transfer-Encoding"):
                self._error("UNSUPPORTED_TRANSFER", "Chunked bodies are not accepted")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._error("INVALID_LENGTH", "Invalid Content-Length")
                return
            if not 0 < length <= MAX_BODY:
                self._error("INVALID_LENGTH", "Body must be between 1 byte and 1 MiB",413)
                return
            try:
                self.connection.settimeout(10)
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("Truncated body")
                def no_constant(value):
                    raise ValueError("Non-finite numbers are not valid JSON")
                body = json.loads(raw,parse_constant=no_constant)
                if not isinstance(body,dict):
                    raise ValueError("Expected an object")
                path = urlsplit(self.path).path
                if path == GET_ZONE_PATH:
                    self._respond(200, zone_discovery.reply(body))
                    return
                elif path == "/api/local/register":
                    result = backend.register(body.get("username"),body.get("password"))
                elif path == "/api/local/login":
                    result = backend.login(body.get("username"),body.get("password"))
                elif path == "/api/local/native-identity":
                    authorization = self.headers.get("Authorization", "")
                    if not authorization.startswith("Bearer "):
                        raise DomainError("UNAUTHORIZED", "Local session is required")
                    encoded = encode_identity(backend.native_identity(authorization[7:]))
                    self._bytes(200,encoded,CONTENT_TYPE)
                    return
                elif path in {"/api/local/dispatch","/api/local/logout","/api/local/change-password",
                              "/api/local/game-profile","/api/local/register-game-nick"}:
                    authorization = self.headers.get("Authorization", "")
                    if not authorization.startswith("Bearer "):
                        raise DomainError("UNAUTHORIZED", "Local session is required")
                    token = authorization[7:]
                    if path == "/api/local/logout":
                        result = backend.logout(token)
                    elif path == "/api/local/change-password":
                        result = backend.change_password(token,body.get("current_password"),body.get("new_password"))
                    elif path == "/api/local/game-profile":
                        identity = backend.native_identity(token)
                        result = {"game_nick":identity["game_nick"],
                                  "game_registered":identity["game_registered"]}
                    elif path == "/api/local/register-game-nick":
                        result = backend.register_game_nick(token,body.get("game_nick"))
                    else:
                        result = backend.dispatch(token,body.get("operation"),body.get("payload"),
                                                  body.get("request_id"),body.get("expected_revision"))
                elif path == "/api/protobuf/decode":
                    name = body.get("message")
                    payload = body.get("payload_base64")
                    if not isinstance(name,str) or not isinstance(payload,str):
                        raise ValueError("message and payload_base64 must be strings")
                    result = codec.decode(name,base64.b64decode(payload,validate=True))
                elif path == "/api/protobuf/dispatch":
                    raise DomainError("GAME_GATEWAY_NOT_READY", "Business schemas, packet layout and handshake are unverified; no game success response was fabricated")
                else:
                    self._error("NOT_FOUND", "Development API route does not exist",404)
                    return
                self._respond(200,{"ok":True,"result":result,"game_compatibility_verified":False})
            except DomainError as error:
                status = 401 if error.code == "UNAUTHORIZED" else 409 if error.code in {
                    "STALE_REVISION","REQUEST_ID_CONFLICT","GAME_GATEWAY_NOT_READY","UNKNOWN_MESSAGE_SCHEMA",
                    "ACCOUNT_EXISTS","GAME_PROFILE_EXISTS","GAME_NICK_EXISTS"} else 400
                self._error(error.code,error.message,status)
            except (ValueError,TypeError,binascii.Error,UnicodeError,TimeoutError):
                self._error("INVALID_REQUEST", "Invalid JSON, request value or binary payload")
            except Exception:
                self.log_error("Local request failed; no payload or token logged")
                self._error("INTERNAL_ERROR", "Request failed; database changes were rolled back",500)

        def log_message(self, format, *args):
            # Endpoint/status only. Request bodies and local sessions are never logged.
            super().log_message(format,*args)
    return Handler


def create_server(backend, codec, host="127.0.0.1", port=8877, *, game_port=65010):
    if host != "127.0.0.1":
        raise ValueError("This build accepts loopback binding only")
    discovery = ZoneDiscovery(game_port)
    server = ThreadingHTTPServer((host,port),handler_factory(backend,codec,discovery))
    server.zone_discovery = discovery
    server.daemon_threads = True
    return server
