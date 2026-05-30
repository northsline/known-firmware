import socket
import select
import time

class DNSMonitor:
    def __init__(self):
        self.sock = None
        self.dns_requests = []
        
    def start_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind(('0.0.0.0', 53))
            self.sock.setblocking(False)
            print("DNS monitor started on port 53")
            return True
        except Exception as e:
            print(f"DNS server failed: {e}")
            return False
    
    def check_for_packets(self):
        if not self.sock:
            return None
            
        ready = select.select([self.sock], [], [], 0)
        if ready[0]:
            data, addr = self.sock.recvfrom(1024)
            if len(data) >= 12:
                domain = self._parse_domain(data)
                if domain:
                    entry = {
                        'source': addr[0],
                        'domain': domain,
                        'timestamp': time.time()
                    }
                    self.dns_requests.append(entry)
                    if len(self.dns_requests) > 10:
                        self.dns_requests = self.dns_requests[-10:]
                    return entry
        return None
    
    def _parse_domain(self, data):
        try:
            offset = 12
            domain_parts = []
            
            while offset < len(data) and data[offset] != 0:
                length = data[offset]
                if offset + length + 1 < len(data):
                    part = data[offset+1:offset+1+length].decode('utf-8', errors='ignore')
                    domain_parts.append(part)
                    offset += length + 1
                else:
                    break
            
            return '.'.join(domain_parts) if domain_parts else None
        except Exception:
            return None
    
    def get_recent_requests(self):
        return self.dns_requests[-5:]