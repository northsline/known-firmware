"""
Known - device tracker

Lightweight registry of LAN devices seen issuing DNS queries through Known. The
DNS monitor calls record() for every parsed query; the HTTP API reads back the
registry for the /devices and /stats endpoints.

Keyed by source IP string. Heuristic detection (trust_level, flagged_count) is
left for a future revision - for the MVP every device is "unknown" and nothing
is flagged.
"""

import time


class DeviceTracker:
    def __init__(self):
        self.devices = {}  # key: ip string, value: dict

    def record(self, ip, domain, timestamp):
        if ip not in self.devices:
            self.devices[ip] = {
                "id": str(hash(ip) & 0x7FFFFFFF),  # positive hash
                "ip": ip,
                "name": "Device at " + ip,
                "first_seen": timestamp,
                "trust_level": "unknown",
                "query_count": 0,
                "flagged_count": 0,
            }
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
