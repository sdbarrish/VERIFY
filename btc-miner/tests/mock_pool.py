#!/usr/bin/env python3
"""Mock Stratum v1 pool for end-to-end testing of zenminer.

Builds headers independently of the miner (standard Stratum conventions) and
verifies every submitted share with hashlib. Exits 0 once --shares valid shares
arrive, 1 on any invalid share or timeout."""
import argparse, hashlib, json, os, socket, struct, sys, time

def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=3334)
ap.add_argument("--shares", type=int, default=2)
ap.add_argument("--timeout", type=int, default=300)
ap.add_argument("--expect-user", help="fail unless the miner authorizes as this username")
a = ap.parse_args()

EN1 = bytes.fromhex("f00dbabe"); EN2_SIZE = 4
coinb1 = os.urandom(42).hex(); coinb2 = os.urandom(60).hex()
branches = [os.urandom(32).hex() for _ in range(5)]
prevhash = os.urandom(28).hex() + "00000000"   # stratum word-swapped form, any value works
version, nbits, ntime = "20000000", "1703a30c", "%08x" % int(time.time())
JOB = "job1"

def header(en2_hex, ntime_hex, nonce_hex):
    cb = bytes.fromhex(coinb1) + EN1 + bytes.fromhex(en2_hex) + bytes.fromhex(coinb2)
    root = dsha(cb)
    for b in branches: root = dsha(root + bytes.fromhex(b))
    ph = bytes.fromhex(prevhash)
    ph = b"".join(ph[i:i+4][::-1] for i in range(0, 32, 4))
    return (struct.pack("<I", int(version, 16)) + ph + root + struct.pack("<I", int(ntime_hex, 16))
            + struct.pack("<I", int(nbits, 16)) + struct.pack("<I", int(nonce_hex, 16)))

DIFF1 = 0xFFFF << 208
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", a.port)); srv.listen(1); srv.settimeout(a.timeout)
print(f"mock pool listening on {a.port}", flush=True)
c, _ = srv.accept(); c.settimeout(a.timeout)
f = c.makefile("rw")
def send(o): f.write(json.dumps(o) + "\n"); f.flush()
good = bad = 0; seen = set(); t_end = time.time() + a.timeout
while time.time() < t_end:
    line = f.readline()
    if not line: break
    m = json.loads(line)
    if m["method"] == "mining.subscribe":
        send({"id": m["id"], "result": [[["mining.notify", "x"]], EN1.hex(), EN2_SIZE], "error": None})
    elif m["method"] == "mining.authorize":
        print(f"authorize as {m['params'][0]}", flush=True)
        if a.expect_user and m["params"][0] != a.expect_user: print("WRONG USER"); sys.exit(1)
        send({"id": m["id"], "result": True, "error": None})
        send({"id": None, "method": "mining.set_difficulty", "params": [1]})
        send({"id": None, "method": "mining.notify",
              "params": [JOB, prevhash, coinb1, coinb2, branches, version, nbits, ntime, True]})
    elif m["method"] == "mining.submit":
        user, job, en2, nt, nonce = m["params"]
        if a.expect_user and user != a.expect_user: print("WRONG USER on submit"); sys.exit(1)
        h = dsha(header(en2, nt, nonce))
        val = int.from_bytes(h, "little")
        ok = job == JOB and val <= DIFF1 and (en2, nonce) not in seen
        seen.add((en2, nonce))
        print(f"share en2={en2} nonce={nonce} hash={h[::-1].hex()} -> {'VALID' if ok else 'INVALID'}", flush=True)
        send({"id": m["id"], "result": ok, "error": None if ok else [23, "invalid share", None]})
        good += ok; bad += not ok
        if bad: sys.exit(1)
        if good >= a.shares: print("PASS"); sys.exit(0)
print("TIMEOUT"); sys.exit(1)
