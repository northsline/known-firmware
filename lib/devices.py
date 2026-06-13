# device tracker — keeps a registry of LAN devices seen in dns queries.
# keyed by source IP. reverse-dns lookup for friendly names, fallback to "Device #N".
# trust_level and flagged_count are stubs for future heuristics.

import socket
import time


def _try_reverse_dns(ip):
    # best-effort reverse dns. returns hostname or None.
    # micropython might not have gethostbyaddr, so callers handle that.
    try:
        name, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        return None
    if not name or name == ip:
        return None
    return name


class DeviceTracker:
    def __init__(self):
        self.devices = {}  # key: ip string, value: dict
        self._next_id = 1  # monotonic, used for "Device #N" fallback names

    def record(self, ip, domain, timestamp):
        if ip not in self.devices:
            # Prefer a real hostname from reverse DNS if we can get one.
            # Fall back to "Device #N" with a stable insertion-order number.
            friendly = _try_reverse_dns(ip) or ("Device #" + str(self._next_id))
            self.devices[ip] = {
                "id": str(hash(ip) & 0x7FFFFFFF),  # positive hash
                "ip": ip,
                "name": friendly,
                "first_seen": timestamp,
                "trust_level": "unknown",
                "query_count": 0,
                "flagged_count": 0,
            }
            self._next_id += 1
        d = self.devices[ip]
        d["last_seen"] = timestamp
        d["query_count"] += 1
        # flagged_count stays 0 for the MVP (no heuristics yet)

    def get_all(self):
        return list(self.devices.values())

    def get_stats(self):
        return {
            "total_queries": sum(d["query_count"] for d in self.devices.values()),
            "unique_domains": 0,  # computed in http_server from dns_requests
            "flagged_count": 0,
            "device_count": len(self.devices),
            "period_start": min(
                (d["first_seen"] for d in self.devices.values()), default=0
            ),
        }
