# minimal non-blocking http server on port 8080.
# raw sockets, no keep-alive, no threads: micropython safe.
# poll() is called from the main loop, handles one connection per tick.
#
# API fields (audit/weekly entries):
#   source: str        -- client ip
#   domain: str        -- parsed dns domain
#   timestamp: float   -- epoch seconds
#   flagged: bool      -- true if a heuristic matched
#   kind: str          -- "flagged-domain" | "new-connection" | "normal"
#   reason: str|null   -- why it was flagged (e.g. "matched: doubleclick.net")
#
# API fields (stats):
#   flagged_count: int -- sum of flagged entries across all devices
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
    def __init__(self, dns_monitor, device_tracker, port=8080, device_token=None, pico_mac=None):
        self.dns_monitor = dns_monitor
        self.device_tracker = device_tracker
        self.port = port
        self.sock = None
        self.allowlist = []
        self.device_token = device_token
        # the pico's own mac (from wlan.config('mac')), formatted as
        # "aa:bb:cc:dd:ee:ff" or None. exposed in /stats and /devices so
        # the dashboard can run lookupVendor() on the heron device.
        self.pico_mac = pico_mac

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
        # Accept and serve one pending connection. Never blocks.
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
        # read request data, retry briefly for non-blocking sockets
        data = b""
        start = time.ticks_ms()
        while time.ticks_diff(time.ticks_ms(), start) < 250:
            try:
                chunk = client.recv(_MAX_REQUEST_BYTES - len(data))
                if chunk:
                    data += chunk
                    # Complete HTTP request header section ends with \r\n\r\n
                    if b"\r\n\r\n" in data:
                        return data
                elif data:
                    # Empty chunk but we already have some data
                    return data
            except OSError:
                pass
            time.sleep_ms(5)
        return data

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
        elif method == "GET" and base == "/token":
            # Expose the device token for future auth flows. Returns a
            # truncated hint: the full token is only sent over the
            # local network, never exposed publicly.
            if self.device_token:
                self._send(client, 200, {
                    "status": "ok",
                    "token_hint": self.device_token[:8]
                })
            else:
                self._send(client, 404, {"status": "error", "reason": "no_token"})
        elif method == "GET" and base == "/audit/weekly":
            self._audit_weekly(client, query)
        elif method == "GET" and base == "/devices":
            # /devices is now a wrapper: {pico_mac, devices: [...]}.
            # pico_mac is the heron device's own mac (None if
            # wlan.config('mac') isn't available). the per-device `mac`
            # field on each entry is best-effort and stays None on
            # rp2350 stock firmware (no ARP API). dashboard adapters are
            # updated to read the wrapped shape; the old bare-array
            # shape is still parsed transparently for back-compat.
            payload = {
                "pico_mac": self.pico_mac,
                "devices": self.device_tracker.get_all(),
            }
            self._safe_send(client, 200, payload)
        elif method == "GET" and base == "/stats":
            self._stats(client)
        elif method == "GET" and base == "/debug":
            self._debug(client)
        elif method == "GET" and base == "/allowlist":
            self._safe_send(client, 200, self.allowlist)
        elif method == "PUT" and base == "/allowlist":
            self._allowlist_add(client, body)
        elif method == "DELETE" and base.startswith("/allowlist/"):
            self._allowlist_delete(client, base[len("/allowlist/"):])
        elif method == "PUT" and base.startswith("/devices/"):
            self._device_rename(client, base[len("/devices/"):], body)
        elif method == "GET" and base == "/version":
            self._version(client)
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
                "flagged": r.get("flagged", False),
                "kind": r.get("kind", "normal"),
                "reason": r.get("reason"),
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
        stats["boot_time"] = self.dns_monitor.get_boot_time()
        # pico_mac: the heron device's own mac, for oui vendor lookup on
        # the dashboard. None if wlan.config('mac') isn't available.
        stats["pico_mac"] = self.pico_mac
        self._safe_send(client, 200, stats)

    def _debug(self, client):
        # raw internal state for diagnosing empty-log problems
        reqs = self.dns_monitor.dns_requests
        devs = self.device_tracker.devices
        payload = {
            "dns_requests": {
                "count": len(reqs),
                "last_5": reqs[-5:],
            },
            "device_tracker": {
                "device_count": len(devs),
                "devices": list(devs.values()),
            },
            "dns_last_error": getattr(self.dns_monitor, "last_error", None),
            "dns_sock_bound": self.dns_monitor.sock is not None,
        }
        self._safe_send(client, 200, payload)

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

    def _device_rename(self, client, device_id, body):
        from devices import MAX_NAME_LEN
        if not isinstance(body, dict) or "name" not in body:
            self._send(client, 400, {"status": "error", "reason": "name required"})
            return
        new_name = str(body["name"]).strip()
        if not new_name:
            self._send(client, 400, {"status": "error", "reason": "name empty"})
            return
        if len(new_name) > MAX_NAME_LEN:
            self._send(client, 400, {"status": "error", "reason": "name too long"})
            return
        # Find device by id (hash) or IP
        for ip, d in self.device_tracker.devices.items():
            if d["id"] == device_id or d["ip"] == device_id:
                if self.device_tracker.rename(ip, new_name):
                    self._send(client, 200, {"status": "ok"})
                    return
                # length check already passed, so rename failed because the
                # device isn't in the tracker (race with eviction, etc).
                self._send(client, 404, {"status": "error", "reason": "device not found"})
                return
        self._send(client, 404, {"status": "error", "reason": "device not found"})

    def _version(self, client):
        # Expose the current firmware version and update-key state.
        try:
            import json
        except ImportError:
            import ujson as json
        try:
            import otp_keys
            has_update_key = otp_keys.has_update_key()
            active_slot = otp_keys.get_active_update_slot()
        except Exception:
            has_update_key = False
            active_slot = 0
        fw_version = 1
        try:
            with open("/fwver.json", "r") as f:
                ver = json.load(f)
            fw_version = int(ver.get("fw_version", 1))
        except Exception:
            pass
        self._safe_send(client, 200, {
            "fw_version": fw_version,
            "has_update_key": has_update_key,
            "active_slot": active_slot,
        })

    # --- response helpers -------------------------------------------------

    def _safe_send(self, client, status, payload):
        # serialize payload, degrade to 503 on MemoryError
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
        # retry on EAGAIN, bounded so a dead client cannot wedge the main loop
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