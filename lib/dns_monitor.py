import socket
import select
import time

_MAX_REQUESTS = 150
UPSTREAM_DNS = "1.1.1.1"
UPSTREAM_PORT = 53
FORWARD_TIMEOUT = 3
_MAX_INFLIGHT = 8
_INFLIGHT_TTL_MS = 3000


class DNSMonitor:
    def __init__(self, device_tracker=None):
        self.sock = None
        self.dns_requests = []
        self.device_tracker = device_tracker
        self.last_error = None  # surfaced via /debug
        # Upstream socket, one per instance. Non-blocking, polled in check_for_packets. Self.upstream = None
        # In-flight: [txid, client_addr, sent_ms]. Capped at _MAX_INFLIGHT. Self._inflight = []

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
        # Drop anything older than _INFLIGHT_TTL_MS. Swap-pop, no alloc. I = 0
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

        # 1. Drain upstream responses. Non-blocking. If self.upstream is not None and self._inflight:
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

        # 2. Drop stale in-flight so a dead upstream response doesn't pin a slot. Self._drop_stale(now_ms)

        # 3. Poll listen socket. Non-blocking, same as HTTP server. Ready = select.select([self.sock], [], [], 0)
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
        # in-flight is full, we just log and move on. Self._forward_query(data, addr)

        if domain:
            entry = {
                'source': addr[0],
                'domain': domain,
                'timestamp': time.time()
            }
            self.dns_requests.append(entry)
            print("[dns] appended entry, dns_requests len now {}".format(
                len(self.dns_requests)))
            if len(self.dns_requests) > _MAX_REQUESTS:
                # Trim in place. List slice allocates a new list each call,
                # but this only fires when the buffer is full, i.e. ~once
                # per _MAX_REQUESTS packets. Self.dns_requests = self.dns_requests[-_MAX_REQUESTS:]
            if self.device_tracker:
                self.device_tracker.record(
                    entry['source'], entry['domain'], entry['timestamp']
                )
            return entry

        return None

    def _forward_query(self, data, client_addr):
        if self.upstream is None or len(data) < 2:
            return
        # Cap in-flight so a slow upstream doesn't grow the list unbounded. If len(self._inflight) >= _MAX_INFLIGHT:
            print("[dns] forward dropped: in-flight full ({})".format(_MAX_INFLIGHT))
            return
        txid = (data[0] << 8) | data[1]
        try:
            self.upstream.sendto(data, (UPSTREAM_DNS, UPSTREAM_PORT))
        except Exception as e:
            self.last_error = "upstream send: {}".format(e)
            print("Upstream send error: {}".format(e))
            return
        # Append a small 3-tuple; no dict, no string formatting. Self._inflight.append([txid, client_addr, time.ticks_ms()])

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
