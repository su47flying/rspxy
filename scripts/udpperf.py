#!/usr/bin/env python3
"""Minimal UDP throughput/loss tester using a single UDP port (no TCP control).

server: udpperf.py server PORT
client: udpperf.py up   HOST PORT MBPS SECS   # client -> server
        udpperf.py down HOST PORT MBPS SECS   # server -> client (NAT-friendly)
"""
import json, socket, struct, sys, time

PKT = 1200
HDR = struct.Struct("!4sIQd")  # magic, test id, seq, send time


class Sink:
    def __init__(self):
        self.n = self.bytes = self.maxseq = self.reorder = 0
        self.seen = set()
        self.dup = 0
        self.t0 = self.t1 = None
        self.last = -1

    def add(self, seq, size):
        now = time.time()
        if self.t0 is None:
            self.t0 = now
        self.t1 = now
        if seq in self.seen:
            self.dup += 1
            return
        self.seen.add(seq)
        self.n += 1
        self.bytes += size
        if seq < self.last:
            self.reorder += 1
        self.last = max(self.last, seq)
        self.maxseq = max(self.maxseq, seq)

    def report(self, sent):
        dur = (self.t1 - self.t0) if self.t0 and self.t1 > self.t0 else 0
        return {
            "sent": sent, "recv": self.n, "dup": self.dup, "reorder": self.reorder,
            "loss_pct": round(100.0 * (1 - self.n / sent), 2) if sent else None,
            "recv_mbps": round(self.bytes * 8 / dur / 1e6, 2) if dur else 0,
            "dur": round(dur, 2),
        }


def blast(sock, addr, tid, mbps, secs):
    pad = b"x" * (PKT - HDR.size)
    interval = PKT * 8 / (mbps * 1e6)
    start = time.time()
    seq = 0
    while True:
        now = time.time()
        if now - start >= secs:
            break
        target = start + seq * interval
        if now < target:
            time.sleep(min(target - now, 0.002))
            continue
        try:
            sock.sendto(HDR.pack(b"DATA", tid, seq, now) + pad, addr)
        except (BlockingIOError, OSError):
            time.sleep(0.001)
            continue
        seq += 1
    return seq


def server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    s.bind(("0.0.0.0", port))
    sinks = {}
    done = set()
    print(f"listening udp/{port}", flush=True)
    while True:
        data, addr = s.recvfrom(65535)
        if data[:4] == b"DATA":
            _, tid, seq, _ = HDR.unpack_from(data)
            sinks.setdefault(tid, Sink()).add(seq, len(data))
        elif data[:4] == b"END ":
            tid, sent = struct.unpack_from("!IQ", data, 4)
            rep = sinks.get(tid, Sink()).report(sent)
            s.sendto(b"REP " + json.dumps(rep).encode(), addr)
        elif data[:4] == b"DOWN":
            tid, mbps, secs = struct.unpack_from("!Idd", data, 4)
            if tid in done:
                continue
            done.add(tid)
            print(f"down test {tid} -> {addr} {mbps}Mbps {secs}s", flush=True)
            sent = blast(s, addr, tid, mbps, secs)
            for _ in range(10):
                s.sendto(b"END " + struct.pack("!IQ", tid, sent), addr)
                time.sleep(0.1)


def client(mode, host, port, mbps, secs):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    addr = (host, port)
    tid = int(time.time() * 1000) & 0xFFFFFFFF
    if mode == "up":
        sent = blast(s, addr, tid, mbps, secs)
        time.sleep(1.0)
        s.settimeout(1.5)
        for _ in range(8):
            s.sendto(b"END " + struct.pack("!IQ", tid, sent), addr)
            try:
                data, _ = s.recvfrom(65535)
                if data[:4] == b"REP ":
                    rep = json.loads(data[4:])
                    rep["offered_mbps"] = mbps
                    print(json.dumps(rep))
                    return
            except socket.timeout:
                pass
        print(json.dumps({"error": "no report from server", "sent": sent}))
    else:
        sink = Sink()
        s.settimeout(3)
        for _ in range(3):
            s.sendto(b"DOWN" + struct.pack("!Idd", tid, mbps, secs), addr)
        deadline = time.time() + secs + 10
        while time.time() < deadline:
            try:
                data, _ = s.recvfrom(65535)
            except socket.timeout:
                break
            if data[:4] == b"DATA":
                _, t, seq, _ = HDR.unpack_from(data)
                if t == tid:
                    sink.add(seq, len(data))
            elif data[:4] == b"END ":
                t, sent = struct.unpack_from("!IQ", data, 4)
                if t == tid:
                    rep = sink.report(sent)
                    rep["offered_mbps"] = mbps
                    print(json.dumps(rep))
                    return
        print(json.dumps({"error": "no END from server", "recv": sink.n,
                          "recv_mbps": sink.report(1)["recv_mbps"]}))


if __name__ == "__main__":
    if sys.argv[1] == "server":
        server(int(sys.argv[2]))
    else:
        client(sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5]))
