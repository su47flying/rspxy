#!/usr/bin/env python3
"""Resolve a name over UDP through a SOCKS5 proxy (UDP ASSOCIATE).

    socks5_udp_dns.py [PROXY_HOST:PORT] [NAME] [DNS_SERVER]
    defaults: 127.0.0.1:1080 www.youtube.com 8.8.8.8
"""
import random, socket, struct, sys, time

proxy = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:1080"
name = sys.argv[2] if len(sys.argv) > 2 else "www.youtube.com"
dns = sys.argv[3] if len(sys.argv) > 3 else "8.8.8.8"
phost, pport = proxy.rsplit(":", 1)

ctrl = socket.create_connection((phost, int(pport)), timeout=10)
ctrl.sendall(b"\x05\x01\x00")
assert ctrl.recv(2) == b"\x05\x00", "auth negotiation failed"
ctrl.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
rep = ctrl.recv(10)
assert rep[1] == 0, f"UDP ASSOCIATE rejected, rep={rep[1]}"
relay = (socket.inet_ntoa(rep[4:8]), struct.unpack("!H", rep[8:10])[0])

qid = random.randrange(65536)
query = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
query += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
query += struct.pack("!HH", 1, 1)  # A, IN
pkt = b"\x00\x00\x00\x01" + socket.inet_aton(dns) + struct.pack("!H", 53) + query

u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(3)
for attempt in range(3):
    t0 = time.time()
    u.sendto(pkt, relay)
    try:
        data, _ = u.recvfrom(65535)
    except socket.timeout:
        continue
    rtt = (time.time() - t0) * 1000
    resp = data[10:]  # RSV(2) FRAG(1) ATYP(1) IPv4(4) PORT(2)
    rid, flags, qd, an = struct.unpack("!HHHH", resp[:8])
    assert rid == qid, "mismatched DNS id"
    print(f"OK: {name} via {dns} through socks5 UDP relay {relay[0]}:{relay[1]}: "
          f"rcode={flags & 0xF} answers={an} rtt={rtt:.0f}ms")
    sys.exit(0)
print("FAIL: no UDP response")
sys.exit(1)
