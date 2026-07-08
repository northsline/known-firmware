import socket
import select
import time

try:
    import json
except ImportError:
    import ujson as json

_MAX_REQUESTS = 150
_DNSLOG_PATH = '/dnslog.json'
_FLUSH_INTERVAL_S = 300  # 5 minutes
_FLUSH_THRESHOLD = 50   # entries since last flush
UPSTREAM_DNS = "1.1.1.1"
UPSTREAM_PORT = 53
FORWARD_TIMEOUT = 3
_MAX_INFLIGHT = 8
_INFLIGHT_TTL_MS = 3000

# flagged domains: known tracking/ad networks. match by suffix.
# keep this under 50 entries for ram. pure domain strings, no wildcards.
FLAGGED_DOMAINS = (
    "doubleclick.net",
    "googleadservices.com",
    "googlesyndication.com",
    "scorecardresearch.com",
    "google-analytics.com",
    "adservice.google.com",
    "adsystem.amazon.com",
    "analytics.apple.com",
    "metrics.icloud.com",
    "flurry.com",
    "crashlytics.com",
    "app-measurement.com",
    "ads.yahoo.com",
    "analytics.facebook.com",
    "graph.facebook.com",
    "connect.facebook.net",
    "sc-static.net",
    "criteo.com",
    "criteo.net",
    "advertising.com",
    "quantserve.com",
    "adsrvr.org",
    "pubmatic.com",
    "rubiconproject.com",
    "openx.net",
    "moatads.com",
    "outbrain.com",
    "taboola.com",
    "disqus.com",
    "branch.io",
    "mixpanel.com",
    "segment.io",
    "amplitude.com",
)

# (ip, domain) pairs we've seen before. capped to avoid unbounded growth.
_MAX_SEEN_PAIRS = 500


class DNSMonitor:
    def __init__(self, device_tracker=None):
        self.sock = None
        self.dns_requests = []
        self.device_tracker = device_tracker
        self.last_error = None  # surfaced via /debug
        # Upstream socket, one per instance. Non-blocking, polled in check_for_packets.
        self.upstream = None
        # In-flight: [txid, client_addr, sent_ms]. Capped at _MAX_INFLIGHT.
        self._inflight = []
        # persistence state
        self._last_flush_s = time.time()
        self._entries_since_flush = 0
        self._boot_time = time.time()
        self.load_persisted()

    def start_server(self):
        if self.sock:
            self.stop_server()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('0.0.0.0', 53))
            self.sock.setblocking(False)
            self.upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.upstream.setblocking(False)
            print("DNS monitor started on port 53")
            return True
        except Exception as e:
            self.last_error = "bind: {}".format(e)
            print("DNS server failed: {}".format(e))
            self._close_upstream()
            if self.sock:
                self.sock.close()
                self.sock = None
            return False

    def stop_server(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        self._close_upstream()
        self._inflight = []

    def _close_upstream(self):
        if self.upstream:
            try:
                self.upstream.close()
            except Exception:
                pass
            self.upstream = None

    def _drop_stale(self, now_ms):
        # Drop anything older than _INFLIGHT_TTL_MS. Swap-pop, no alloc.
        i = 0
        n = len(self._inflight)
        while i < n:
            if time.ticks_diff(now_ms, self._inflight[i][2]) > _INFLIGHT_TTL_MS:
                # swap-pop to remove without allocation
                self._inflight[i] = self._inflight[n - 1]
                self._inflight.pop()
                n -= 1
            else:
                i += 1

    def check_for_packets(self):
        if not self.sock:
            return None

        now_ms = time.ticks_ms()

        # 1. Drain upstream responses. Non-blocking.
        if self.upstream is not None and self._inflight:
            r, _, _ = select.select([self.upstream], [], [], 0)
            if r:
                try:
                    resp, _ = self.upstream.recvfrom(512)
                except Exception as e:
                    self.last_error = "upstream recv: {}".format(e)
                    print("Upstream recv error: {}".format(e))
                    resp = None
                if resp and len(resp) >= 2:
                    rxid = (resp[0] << 8) | resp[1]
                    # linear scan: _inflight is small (capped at _MAX_INFLIGHT)
                    i = 0
                    n = len(self._inflight)
                    match = -1
                    while i < n:
                        if self._inflight[i][0] == rxid:
                            match = i
                            break
                        i += 1
                    if match >= 0:
                        client_addr = self._inflight[match][1]
                        # swap-pop the matched entry
                        self._inflight[match] = self._inflight[n - 1]
                        self._inflight.pop()
                        try:
                            self.sock.sendto(resp, client_addr)
                        except Exception as e:
                            self.last_error = "sendto client: {}".format(e)
                            print("Sendto client error: {}".format(e))

        # 2. Drop stale in-flight so a dead upstream response doesn't pin a slot.
        self._drop_stale(now_ms)

        # 3. Poll listen socket. Non-blocking, same as HTTP server.
        ready = select.select([self.sock], [], [], 0)
        if not ready[0]:
            return None

        try:
            data, addr = self.sock.recvfrom(512)
        except Exception as e:
            self.last_error = "recvfrom: {}".format(e)
            print("DNS recv error: {}".format(e))
            return None

        print("[dns] check_for_packets: {} bytes from {}".format(len(data), addr))
        if len(data) < 12:
            print("[dns] dropped: packet too short ({} bytes)".format(len(data)))
            return None

        domain = self._parse_domain(data)
        if domain:
            print("[dns] _parse_domain OK: {}".format(domain))
        else:
            print("[dns] _parse_domain FAILED for {}-byte packet".format(len(data)))

        # Fire-and-forget forward. Never blocks. If upstream is busy or
        # in-flight is full, we just log and move on.
        self._forward_query(data, addr)

        if domain:
            flagged, kind, reason = self._classify(addr[0], domain)
            entry = {
                'source': addr[0],
                'domain': domain,
                'timestamp': time.time(),
                'flagged': flagged,
                'kind': kind,
                'reason': reason,
            }
            self.dns_requests.append(entry)
            print("[dns] appended entry, dns_requests len now {}".format(
                len(self.dns_requests)))
            if len(self.dns_requests) > _MAX_REQUESTS:
                self.dns_requests = self.dns_requests[-_MAX_REQUESTS:]
            if self.device_tracker:
                self.device_tracker.record(
                    entry['source'], entry['domain'], entry['timestamp'],
                    flagged=flagged
                )
            self._entries_since_flush += 1
            self._maybe_flush()
            return entry

        return None

    def _forward_query(self, data, client_addr):
        if self.upstream is None or len(data) < 2:
            return
        # Cap in-flight so a slow upstream doesn't grow the list unbounded.
        if len(self._inflight) >= _MAX_INFLIGHT:
            print("[dns] forward dropped: in-flight full ({})".format(_MAX_INFLIGHT))
            return
        txid = (data[0] << 8) | data[1]
        try:
            self.upstream.sendto(data, (UPSTREAM_DNS, UPSTREAM_PORT))
        except Exception as e:
            self.last_error = "upstream send: {}".format(e)
            print("Upstream send error: {}".format(e))
            return
        # Append a small 3-tuple; no dict, no string formatting.
        self._inflight.append([txid, client_addr, time.ticks_ms()])

    def _parse_domain(self, data):
        try:
            offset = 12
            parts = []
            while offset < len(data) and data[offset] != 0:
                length = data[offset]
                if offset + length + 1 > len(data):
                    break
                parts.append(data[offset + 1:offset + 1 + length].decode('utf-8', 'ignore'))
                offset += length + 1
            return '.'.join(parts) if parts else None
        except Exception as e:
            self.last_error = "parse: {}".format(e)
            return None

    def get_recent_requests(self):
        return self.dns_requests[-_MAX_REQUESTS:]

    def get_boot_time(self):
        return self._boot_time

    # --- persistence -------------------------------------------------------

    def load_persisted(self):
        try:
            with open(_DNSLOG_PATH, 'r') as f:
                raw = f.read()
            data = json.loads(raw)
            if isinstance(data, list):
                self.dns_requests = data[-_MAX_REQUESTS:]
                print("[dns] loaded {} persisted entries".format(len(self.dns_requests)))
        except OSError:
            # file doesn't exist — first boot or wiped flash
            pass
        except Exception as e:
            print("[dns] load_persisted error: {}".format(e))

    def _maybe_flush(self):
        now = time.time()
        if self._entries_since_flush >= _FLUSH_THRESHOLD or \
                (now - self._last_flush_s) >= _FLUSH_INTERVAL_S:
            self._flush()

    def maybe_flush(self):
        self._maybe_flush()

    def _flush(self):
        try:
            entries = self.dns_requests[-_MAX_REQUESTS:]
            with open(_DNSLOG_PATH, 'w') as f:
                json.dump(entries, f)
            self._last_flush_s = time.time()
            self._entries_since_flush = 0
            print("[dns] flushed {} entries to flash".format(len(entries)))
        except Exception as e:
            print("[dns] flush failed: {}".format(e))
            self.last_error = "flush: {}".format(e)
