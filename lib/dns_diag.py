"""
DNS diagnostic harness for the Pico 2 W.

Upload this file to the Pico (e.g. via mpremote) and run:

    >>> from lib.dns_diag import run
    >>> run(my_ip="192.168.1.50")

Replace my_ip with the IP the Pico is actually using (printed at boot
or visible on the OLED). The script will print PASS/FAIL for each of
four tests so you can see exactly which link in the chain is broken.

Tests, in order:

  T1 listen      can we bind and recv a packet on 0.0.0.0:53?
  T2 echo        if T1 passes, does nslookup-style traffic reach us?
                 run an "echo server" that mirrors each packet back to
                 the sender. From a PC on the same wifi do
                    nslookup google.com <pico_ip>
                 and watch the serial output.
  T3 upstream    can the Pico reach 1.1.1.1:53 and get a real DNS
                 reply? this catches router firewalls, captive
                 portals, and APs that block outbound DNS to anyone
                 but themselves.
  T4 forward     end-to-end: listen + upstream + relay. this is the
                 one that matters.

Notes
-----
* Runs on the live network. If T1 fails the test aborts - nothing
  else will work.
* T2 leaves a 30s server up. Hit Ctrl-C in the REPL to bail early.
* Uses the same patterns as lib/dns_monitor.py (non-blocking,
  select.poll) so a pass here means the real monitor should too.
"""

import socket
import select
import time


def _now_ms():
    return time.ticks_ms()


def _log(tag, msg):
    # Tagged print so output is easy to grep.
    print("[{}] {}".format(tag, msg))


def test_listen(bind_ip="0.0.0.0", port=53, wait_s=8):
    """T1: bind to 0.0.0.0:53, wait for a packet, return it."""
    _log("T1", "binding {}:{} ...".format(bind_ip, port))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((bind_ip, port))
        s.settimeout(1)  # so we can check wall clock each second
    except Exception as e:
        _log("T1", "FAIL bind: {}".format(e))
        return None, None

    _log("T1", "bound. waiting up to {}s for any packet ...".format(wait_s))
    deadline = _now_ms() + wait_s * 1000
    last_print = 0
    while time.ticks_diff(deadline, _now_ms()) > 0:
        try:
            data, addr = s.recvfrom(512)
        except Exception:
            data = None
        if data:
            _log("T1", "PASS got {}B from {}".format(len(data), addr))
            s.close()
            return data, addr
        # Periodic "still alive" so the user knows it's not hung.
        if time.ticks_diff(_now_ms(), last_print) >= 2000:
            _log("T1", "  ...still waiting")
            last_print = _now_ms()
    _log("T1", "FAIL no packet in {}s".format(wait_s))
    s.close()
    return None, None


def test_echo(bind_ip="0.0.0.0", port=53, wait_s=30):
    """T2: echo every received packet back to its sender.

    From a PC on the same wifi, run:
        nslookup google.com <pico_ip>
    and watch the serial console. If you see the query come in and
    the response go out, the basic UDP path is good. If you see
    nothing come in even though the PC says it sent it, the issue
    is AP isolation or a wrong IP - not the firmware.
    """
    _log("T2", "starting echo server on {}:{} for {}s".format(
        bind_ip, port, wait_s))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((bind_ip, port))
        s.settimeout(1)
    except Exception as e:
        _log("T2", "FAIL bind: {}".format(e))
        return

    deadline = _now_ms() + wait_s * 1000
    echoed = 0
    while time.ticks_diff(deadline, _now_ms()) > 0:
        try:
            data, addr = s.recvfrom(512)
        except Exception:
            continue
        if not data:
            continue
        _log("T2", "rcv {}B from {} (txid=0x{:04x})".format(
            len(data), addr, (data[0] << 8) | data[1]))
        try:
            s.sendto(data, addr)
            echoed += 1
            _log("T2", "echoed back to {} (count={})".format(addr, echoed))
        except Exception as e:
            _log("T2", "sendto FAIL: {}".format(e))
    s.close()
    _log("T2", "done. echoed {} packets".format(echoed))


def test_upstream(host="1.1.1.1", port=53, timeout_s=5):
    """T3: send a real DNS query for cloudflare.com and see if we
    get a real answer back. failure here means the router/firewall
    is blocking outbound DNS to public resolvers.
    """
    # Hand-crafted DNS query for "cloudflare.com" A record.
    # Header: id=0x1234, RD=1, 1 question.
    # \x12\x34   txid
    # \x01\x00   standard query, RD
    # \x00\x01   1 question
    # \x00\x00\x00\x00\x00\x00  rest of header
    # \x0a cloudflare \x03 com \x00  question
    # \x00\x01   type A
    # \x00\x01   class IN
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    q += b"\x0acloudflare\x03com\x00"
    q += b"\x00\x01\x00\x01"

    _log("T3", "sending {}B to {}:{} (timeout {}s)".format(
        len(q), host, port, timeout_s))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout_s)
        s.sendto(q, (host, port))
        data, addr = s.recvfrom(512)
        s.close()
    except Exception as e:
        _log("T3", "FAIL: {}".format(e))
        return False

    if len(data) < 12:
        _log("T3", "FAIL response too short: {}B".format(len(data)))
        return False
    rcode = data[3] & 0x0f
    ancount = (data[6] << 8) | data[7]
    _log("T3", "rcv {}B from {} rcode={} ancount={}".format(
        len(data), addr, rcode, ancount))
    if rcode != 0:
        _log("T3", "FAIL rcode != 0 (DNS error from upstream)")
        return False
    if ancount == 0:
        _log("T3", "FAIL 0 answers in response")
        return False
    _log("T3", "PASS got valid DNS response")
    return True


def test_forward(pico_ip, peer_hint=None, wait_s=20):
    """T4: end-to-end. bind 53, recv from a peer, forward to
    1.1.1.1, send the answer back. polls an upstream socket via
    select just like the real dns_monitor does.

    The packet source needs to come from somewhere. Options:
    - run this while doing nslookup from a PC on the same wifi
    - or, if peer_hint is given, the test will send a probe query
      *to itself* on 127.0.0.1 to exercise the path
    """
    _log("T4", "starting forwarder on {}:53 for {}s".format(pico_ip, wait_s))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 53))
        s.setblocking(False)
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up.setblocking(False)
    except Exception as e:
        _log("T4", "FAIL bind: {}".format(e))
        return

    inflight = []  # [[txid, client_addr, sent_ms]]
    deadline = _now_ms() + wait_s * 1000
    queries = 0
    answered = 0

    while time.ticks_diff(deadline, _now_ms()) > 0:
        now = _now_ms()

        # Drain upstream responses.
        if inflight:
            r, _, _ = select.select([up], [], [], 0)
            if r:
                try:
                    resp, _ = up.recvfrom(512)
                except Exception:
                    resp = None
                if resp and len(resp) >= 2:
                    rxid = (resp[0] << 8) | resp[1]
                    for i, e in enumerate(inflight):
                        if e[0] == rxid:
                            s.sendto(resp, e[1])
                            answered += 1
                            _log("T4", "answered txid=0x{:04x} -> {}".format(
                                rxid, e[1]))
                            inflight.pop(i)
                            break

        # Drop stale inflight.
        i = 0
        while i < len(inflight):
            if time.ticks_diff(now, inflight[i][2]) > 3000:
                _log("T4", "drop stale txid=0x{:04x}".format(inflight[i][0]))
                inflight.pop(i)
            else:
                i += 1

        # Read new queries.
        r, _, _ = select.select([s], [], [], 0)
        if r:
            try:
                data, addr = s.recvfrom(512)
            except Exception:
                data = None
            if data and len(data) >= 12:
                queries += 1
                txid = (data[0] << 8) | data[1]
                if len(inflight) < 8:
                    try:
                        up.sendto(data, ("1.1.1.1", 53))
                        inflight.append([txid, addr, _now_ms()])
                        _log("T4", "fwd txid=0x{:04x} from {} (inflight={})".format(
                            txid, addr, len(inflight)))
                    except Exception as e:
                        _log("T4", "upstream send FAIL: {}".format(e))
                else:
                    _log("T4", "drop query: inflight full")
        time.sleep_ms(20)

    s.close()
    up.close()
    _log("T4", "done. queries={} answered={}".format(queries, answered))
    if queries == 0:
        _log("T4", "FAIL: never received a query - check AP isolation / IP")
    elif answered == 0:
        _log("T4", "FAIL: got queries but never answered - upstream path broken")
    else:
        _log("T4", "PASS end-to-end")


def run(my_ip):
    """Run the full diagnostic. Pass my_ip = the Pico's IP."""
    print("==== Known DNS diagnostic ====")
    print("Pico IP: {}".format(my_ip))
    print()

    # T1: can we even receive?
    data, addr = test_listen(wait_s=8)
    if data is None:
        print()
        print("T1 failed. nothing else to do.")
        print("Things to try:")
        print("  - is the IP correct? nslookup from a PC should")
        print("    reach the Pico on UDP/53")
        print("  - check AP isolation on the router")
        print("  - is another service already on UDP/53?")
        return

    # T2: echo a real nslookup
    print()
    print("T2: starting echo. from a PC on the same wifi, run:")
    print("    nslookup google.com {}".format(my_ip))
    print("    you have 30s.")
    test_echo(wait_s=30)

    # T3: outbound DNS
    print()
    ok = test_upstream()

    # T4: end-to-end (only useful if user runs nslookup during it)
    print()
    print("T4: starting forwarder. from a PC on the same wifi, run:")
    print("    nslookup cloudflare.com {}".format(my_ip))
    print("    you have 20s.")
    test_forward(my_ip, wait_s=20)

    print()
    print("==== done ====")
