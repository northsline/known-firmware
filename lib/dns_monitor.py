import socket
import select
import time

_MAX_REQUESTS = 150
UPSTREAM_DNS = "1.1.1.1"
UPSTREAM_PORT = 53
FORWARD_TIMEOUT = 3


class DNSMonitor:
    def __init__(self, device_tracker=None):
        self.sock = None
        self.dns_requests = []
        self.device_tracker = device_tracker
        self.last_error = None  # surfaced via /debug

    def start_server(self):
        if self.sock:
            self.stop_server()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('0.0.0.0', 53))
            self.sock.setblocking(False)
            print("DNS monitor started on port 53")
            return True
        except Exception as e:
            self.last_error = "bind: {}".format(e)
            print(f"DNS server failed: {e}")
            return False

    def stop_server(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def check_for_packets(self):
        if not self.sock:
            return None

        ready = select.select([self.sock], [], [], 0)
        if not ready[0]:
            return None

        data, addr = self.sock.recvfrom(512)
        print("[dns] check_for_packets: {} bytes from {}".format(len(data), addr))
        if len(data) < 12:
            print("[dns] dropped: packet too short ({} bytes)".format(len(data)))
            return None

        domain = self._parse_domain(data)
        if domain:
            print("[dns] _parse_domain OK: {}".format(domain))
        else:
            print("[dns] _parse_domain FAILED for {}-byte packet".format(len(data)))
        self._forward_query(data, addr)

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
                self.dns_requests = self.dns_requests[-_MAX_REQUESTS:]
            if self.device_tracker:
                self.device_tracker.record(
                    entry['source'], entry['domain'], entry['timestamp']
                )
            return entry

        return None

    def _forward_query(self, data, client_addr):
        upstream = None
        try:
            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream.settimeout(FORWARD_TIMEOUT)
            upstream.sendto(data, (UPSTREAM_DNS, UPSTREAM_PORT))
            response, _ = upstream.recvfrom(512)
            self.sock.sendto(response, client_addr)
        except Exception as e:
            self.last_error = "forward: {}".format(e)
            print(f"Forward error: {e}")
        finally:
            if upstream:
                upstream.close()

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
