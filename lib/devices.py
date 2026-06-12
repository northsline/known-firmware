"""
Known - device tracker

Lightweight registry of LAN devices seen issuing DNS queries through Known. The
DNS monitor calls record() for every parsed query; the HTTP API reads back the
registry for the /devices and /stats endpoints.

Keyed by source IP string. Heuristic detection (trust_level, flagged_count) is
left for a future revision - for the MVP every device is "unknown" and nothing
is flagged.

Naming: devices get a stable "Device #N" name based on insertion order. We try
a quick reverse-DNS lookup (socket.gethostbyaddr); if it returns a real name
(not the IP back), we use that. Otherwise we fall back to the friendly name.
"""

import socket
import time


def _try_reverse_dns(ip):
    """Best-effort reverse DNS. Returns a hostname string or None.

    The Pico's MicroPython socket may not support gethostbyaddr, so callers
    must handle the case where this isn't available. We do.
    """
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
