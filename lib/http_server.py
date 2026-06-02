"""
Known - minimal non-blocking HTTP API server

Serves JSON to the local dashboard on port 8080. Single-threaded and
non-blocking: poll() is called from the main loop, accepts at most one pending
connection per call, reads what's immediately available (up to 1 KB), answers,
and closes. No keep-alive, no threading, raw sockets only - MicroPython safe.

Routes:
    GET    /health
    GET    /audit/weekly?since=<ts>&limit=<n>
    GET    /devices
    GET    /stats
    GET    /allowlist
    PUT    /allowlist            body {"pattern": "..."}
    DELETE /allowlist/<id>
    OPTIONS *                    CORS preflight (204)
"""

import socket
import select
import time

try:
    import json
except ImportError:  # pragma: no cover
    import ujson as json

_MAX_REQUEST_BYTES = 1024
_DEFAULT_LIMIT = 50
_MAX_LIMIT = 150

_CORS_HEADERS = (
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: GET, PUT, DELETE, OPTIONS\r\n"
    "Access-Control-Allow-Headers: Content-Type\r\n"
)

_STATUS_TEXT = {
    200: "OK",
    201: "Created",
    204: "No Content",
    400: "Bad Request",
    404: "Not Found",
    405: "Method Not Allowed",
    503: "Service Unavailable",
}


class HTTPServer:
    def __init__(self, dns_monitor, device_tracker, port=8080):
        self.dns_monitor = dns_monitor
        self.device_tracker = device_tracker
        self.port = port
        self.sock = None
        self.allowlist = []  # list of {"id", "pattern", "created_at"}

    def start(self):
        if self.sock:
            self.stop()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", self.port))
            self.sock.listen(2)
            self.sock.setblocking(False)
            print("HTTP server started on port {}".format(self.port))
            return True
        except Exception as e:
            print("HTTP server failed: {}".format(e))
            self.sock = None
            return False

    def stop(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def poll(self):
        """Accept and serve at most one pending connection. Never blocks."""
        if not self.sock:
            return

        ready = select.select([self.sock], [], [], 0)
        if not ready[0]:
            return

        try:
            client, addr = self.sock.accept()
        except OSError:
            return

        try:
            client.setblocking(False)
            self._handle_client(client)
        except Exception as e:
            print("HTTP handler error: {}".format(e))
        finally:
            try:
                client.close()
            except Exception:
                pass

    # --- request handling -------------------------------------------------

    def _read_request(self, client):
        """Read what's immediately available, up to _MAX_REQUEST_BYTES."""
        # Give a slow client a brief moment, but never hang the loop.
        ready = select.select([client], [], [], 0.05)
        if not ready[0]:
            return b""
        try:
            return client.recv(_MAX_REQUEST_BYTES)
        except OSError:
            return b""

    def _handle_client(self, client):
        raw = self._read_request(client)
        if not raw:
            self._send(client, 400, {"status": "error", "reason": "empty"})
            return

        # First line: METHOD PATH HTTP/x.y
        line_end = raw.find(b"\r\n")
        if line_end == -1:
            line_end = len(raw)
        first_line = raw[:line_end].decode("utf-8", "ignore")
        parts = first_line.split(" ")
        if len(parts) < 2:
            self._send(client, 400, {"status": "error", "reason": "malformed"})
            return

        method = parts[0]
        path = parts[1]

        if method == "OPTIONS":
            self._send(client, 204, None)
            return

        body = None
        if method == "PUT":
            sep = raw.find(b"\r\n\r\n")
            if sep != -1:
                body_bytes = raw[sep + 4:]
                try:
                    body = json.loads(body_bytes.decode("utf-8", "ignore"))
                except (ValueError, OSError):
                    body = None

        self._route(client, method, path, body)

    def _route(self, client, method, path, body):
        # Strip query string for matching, keep it for parsing.
        q = path.find("?")
        if q != -1:
            base = path[:q]
            query = path[q + 1:]
        else:
            base = path
            query = ""

        if method == "GET" and base == "/health":
            self._send(client, 200, {"status": "ok"})
        elif method == "GET" and base == "/audit/weekly":
            self._audit_weekly(client, query)
        elif method == "GET" and base == "/devices":
            self._safe_send(client, 200, self.device_tracker.get_all())
        elif method == "GET" and base == "/stats":
            self._stats(client)
        elif method == "GET" and base == "/allowlist":
            self._safe_send(client, 200, self.allowlist)
        elif method == "PUT" and base == "/allowlist":
            self._allowlist_add(client, body)
        elif method == "DELETE" and base.startswith("/allowlist/"):
            self._allowlist_delete(client, base[len("/allowlist/"):])
        else:
            self._send(client, 404, {"status": "error", "reason": "not found"})

    # --- endpoint implementations ----------------------------------------

    def _audit_weekly(self, client, query):
        since = None
        limit = _DEFAULT_LIMIT
        for pair in query.split("&"):
            if not pair:
                continue
            kv = pair.split("=", 1)
            if len(kv) != 2:
                continue
            key, val = kv
            if key == "since":
                try:
                    since = float(val)
                except ValueError:
                    since = None
            elif key == "limit":
                try:
                    limit = int(val)
                except ValueError:
                    limit = _DEFAULT_LIMIT

        if limit < 1:
            limit = 1
        elif limit > _MAX_LIMIT:
            limit = _MAX_LIMIT

        requests = self.dns_monitor.get_recent_requests()
        entries = []
        for r in requests:
            if since is not None and r["timestamp"] < since:
                continue
            entries.append({
                "source": r["source"],
                "domain": r["domain"],
                "timestamp": r["timestamp"],
                "flagged": False,  # future heuristic detection
            })

        # Cap to the most recent `limit` entries.
        if len(entries) > limit:
            entries = entries[-limit:]

        self._safe_send(client, 200, entries)

    def _stats(self, client):
        stats = self.device_tracker.get_stats()
        # unique_domains is cheaper to compute here from the request log.
        domains = {}
        for r in self.dns_monitor.dns_requests:
            domains[r["domain"]] = True
        stats["unique_domains"] = len(domains)
        self._safe_send(client, 200, stats)

    def _allowlist_add(self, client, body):
        if not isinstance(body, dict) or "pattern" not in body:
            self._send(client, 400, {"status": "error", "reason": "pattern required"})
            return
        entry = {
            "id": str(time.time_ns()),
            "pattern": body["pattern"],
            "created_at": int(time.time()),
        }
        self.allowlist.append(entry)
        self._send(client, 201, {"status": "ok", "id": entry["id"]})

    def _allowlist_delete(self, client, entry_id):
        for i, entry in enumerate(self.allowlist):
            if entry["id"] == entry_id:
                del self.allowlist[i]
                self._send(client, 200, {"status": "ok"})
                return
        self._send(client, 404, {"status": "error", "reason": "not found"})

    # --- response helpers -------------------------------------------------

    def _safe_send(self, client, status, payload):
        """Serialize payload, degrading to a 503 on MemoryError."""
        try:
            self._send(client, status, payload)
        except MemoryError:
            try:
                self._send(client, 503, {"status": "error", "reason": "memory"})
            except Exception:
                pass

    def _send(self, client, status, payload):
        if payload is None:
            body = b""
        else:
            body = json.dumps(payload).encode("utf-8")

        reason = _STATUS_TEXT.get(status, "OK")
        head = "HTTP/1.0 {} {}\r\n".format(status, reason)
        head += "Content-Type: application/json\r\n"
        head += _CORS_HEADERS
        head += "Content-Length: {}\r\n".format(len(body))
        head += "Connection: close\r\n\r\n"

        self._send_all(client, head.encode("utf-8"))
        if body:
            self._send_all(client, body)

    def _send_all(self, client, data):
        view = memoryview(data)
        sent = 0
        total = len(data)
        # Non-blocking socket: retry on EAGAIN, but bound the attempts so a
        # dead client can never wedge the main loop.
        attempts = 0
        while sent < total and attempts < 200:
            try:
                n = client.send(view[sent:])
                if n:
                    sent += n
                else:
                    attempts += 1
            except OSError:
                attempts += 1
                time.sleep_ms(1)
