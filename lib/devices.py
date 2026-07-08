# device tracker: keeps a registry of LAN devices seen in dns queries.
# keyed by source ip. hostname via nbns broadcast, fallback to "device #n".
# mac lookup is best effort -- rp2350 micropython has no arp api, may stay none.
import socket
import struct
import time

try:
    import ubinascii
except ImportError:  # running on cpython for tests
    ubinascii = None

try:
    import names_store
except ImportError:
    names_store = None


def _try_reverse_dns(ip):
    # best-effort reverse dns. rarely works on micropython, kept as a long shot.
    try:
        name, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        return None
    if not name or name == ip:
        return None
    return name


def _nbns_query_name(ip):
    # send a netbios name service query to the broadcast addr on udp 137.
    # windows boxes, printers, samba iot things usually answer. one shot, short timeout.
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return None
        bcast = ".".join(parts[:3]) + ".255"

        # transaction id 0x1337, flags 0x1000 (recursion desired).
        # one question: name "*" (wildcard), type NB (0x0020), class IN (0x0001).
        # netbios names are 16 chars padded with spaces, then length-prefixed.
        nb_name = b"*".ljust(16)  # pad to 16
        # encode as first-level netbios name: each char -> two nibbles + 'A' (0x41)
        encoded = b""
        for c in nb_name:
            encoded += bytes([0x41 + (c >> 4), 0x41 + (c & 0x0F)])
        question = bytes([len(encoded)]) + encoded + struct.pack(">HH", 0x0020, 0x0001)

        pkt = struct.pack(">HHHHHH", 0x1337, 0x1000, 1, 0, 0, 0) + question

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # enable broadcast
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception:
            pass
        s.settimeout(300)  # ms on micropython
        s.sendto(pkt, (bcast, 137))
        try:
            data, _ = s.recvfrom(1024)
        except Exception:
            s.close()
            return None
        s.close()

        # response: tid(2) flags(2) qd(2) an(2) ns(2) ar(2) then answers.
        if len(data) < 12:
            return None
        flags, qd, an = struct.unpack(">HHH", data[2:8])
        if an == 0:
            return None
        off = 12
        # skip questions
        for _ in range(qd):
            off = _skip_name(data, off)
            off += 4  # type + class
        # parse first answer
        off = _skip_name(data, off)
        if off + 10 > len(data):
            return None
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype != 0x0020 or rdlen < 18:
            return None
        # rdata: flags(2) + name(16) ... take the 16-byte netbios name.
        nb_name_raw = data[off + 2:off + 18]
        # strip trailing spaces and nulls
        name = nb_name_raw.rstrip(b" \x00").decode("ascii", "ignore")
        return name or None
    except Exception:
        return None


def _skip_name(data, off):
    # walk a dns/netbios name (with possible compression pointers) and return next offset.
    while True:
        if off >= len(data):
            return off
        n = data[off]
        if n == 0:
            return off + 1
        if (n & 0xC0) == 0xC0:
            return off + 2
        off += 1 + n


def _lookup_mac(ip):
    # rp2350 micropython has no arp table api and no /proc. try a couple things,
    # but expect none on stock firmware. returns "aa:bb:..." string or none.
    # try /proc/net/arp first -- works on cpython test hosts, not on the pico.
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f:
                cols = line.split()
                if len(cols) >= 6 and cols[0] == ip:
                    mac = cols[3]
                    if mac != "00:00:00:00:00:00" and mac != "FF:FF:FF:FF:FF:FF":
                        return mac
    except Exception:
        pass
    # no clean arp api on micropython. leaving none here; a future build
    # could do a raw arp exchange but the lwip stack doesn't expose it.
    return None


class DeviceTracker:
    def __init__(self):
        self.devices = {}  # key: ip string, value: dict
        self._next_id = 1  # monotonic, used for "device #n" fallback names
        self._saved_names = {}  # ip -> custom name, loaded from flash on boot

    def load_saved_names(self):
        # load names from flash and apply to devices we already know about.
        # called once on boot after wifi connects. devices that show up later
        # in record() will check self._saved_names too.
        if names_store is None:
            return
        self._saved_names = names_store.load_names()
        for ip, name in self._saved_names.items():
            if ip in self.devices:
                self.devices[ip]["custom_name"] = name
                self.devices[ip]["name"] = name

    def record(self, ip, domain, timestamp):
        if ip not in self.devices:
            # hostname: try reverse dns (usually fails), then nbns broadcast.
            # fall back to "device #n" with a stable insertion-order number.
            friendly = _try_reverse_dns(ip)
            if not friendly:
                friendly = _nbns_query_name(ip)
            if not friendly:
                friendly = "Device #" + str(self._next_id)
            # mac: best effort, likely none on rp2350. exposed for oui lookup anyway.
            mac = _lookup_mac(ip)
            # if we have a saved custom name for this ip, use it.
            custom_name = None
            if ip in self._saved_names:
                custom_name = self._saved_names[ip]
                friendly = custom_name
            self.devices[ip] = {
                "id": str(hash(ip) & 0x7FFFFFFF),  # positive hash
                "ip": ip,
                "name": friendly,
                "mac": mac,
                "first_seen": timestamp,
                "trust_level": "unknown",
                "query_count": 0,
                "flagged_count": 0,
            }
            if custom_name is not None:
                self.devices[ip]["custom_name"] = custom_name
            self._next_id += 1
        d = self.devices[ip]
        d["last_seen"] = timestamp
        d["query_count"] += 1
        # if mac was missed on first pass, try again later
        if d.get("mac") is None:
            mac = _lookup_mac(ip)
            if mac:
                d["mac"] = mac
        # if we still have a "device #n" name, retry nbns -- answers can be slow
        if d["name"].startswith("Device #"):
            nb = _nbns_query_name(ip)
            if nb:
                d["name"] = nb
        # flagged_count stays 0 for the MVP (no heuristics yet)

    def get_all(self):
        out = []
        for d in self.devices.values():
            item = {
                "id": d["id"],
                "ip": d["ip"],
                "name": d["name"],
                "mac": d.get("mac"),
                "first_seen": d["first_seen"],
                "last_seen": d.get("last_seen"),
                "trust_level": d["trust_level"],
                "query_count": d["query_count"],
                "flagged_count": d["flagged_count"],
            }
            # include custom_name if a user has set one
            if d.get("custom_name") is not None:
                item["custom_name"] = d["custom_name"]
            out.append(item)
        return out

    def rename(self, ip, new_name):
        # set both the user-facing name and the persistent custom_name override.
        # saves to flash so the name survives reboots.
        if ip in self.devices:
            self.devices[ip]["custom_name"] = new_name
            self.devices[ip]["name"] = new_name
            if names_store is not None:
                self._saved_names[ip] = new_name
                if not names_store.save_names(self._saved_names):
                    print("name save failed for", ip)
            return True
        return False

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