#!/usr/bin/env bash
# Static exposure check + hardening for CVE-2026-109618 / CVE-2026-109619
# (PHP session upload-progress stale-pointer RCE).  Runs INSIDE your own
# php:8.2-apache container.  Read-only: it only inspects and reports.
#
#   docker exec -it <your-container> bash /check_and_harden.sh
#
# Usage from the host against a running container:
#   docker cp check_and_harden.sh <container>:/tmp/ && \
#   docker exec <container> bash /tmp/check_and_harden.sh

set -uo pipefail

pass=0; fail=0; warn=0
ok()   { printf '  [ OK ] %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  [VULN] %s\n' "$1"; fail=$((fail+1)); }
note() { printf '  [WARN] %s\n' "$1"; warn=$((warn+1)); }

echo "== PHP version =="
ver=$(php -r 'echo PHP_VERSION;' 2>/dev/null)
echo "  detected: PHP $ver"

# Vulnerable: 8.2.0-8.2.34, 8.3.0-8.3.35, 8.4.0-8.4.26, 8.5.0-8.5.11
# Fixed:      8.2.35, 8.3.36, 8.4.27, 8.5.12
fixed_vulnerable=0
case "$ver" in
  8.2.*) [ "$(printf '%s\n' 8.2.35 "$ver" | sort -V | head -1)" = "8.2.35" ] && fixed_vulnerable=1 ;;
  8.3.*) [ "$(printf '%s\n' 8.3.36 "$ver" | sort -V | head -1)" = "8.3.36" ] && fixed_vulnerable=1 ;;
  8.4.*) [ "$(printf '%s\n' 8.4.27 "$ver" | sort -V | head -1)" = "8.4.27" ] && fixed_vulnerable=1 ;;
  8.5.*) [ "$(printf '%s\n' 8.5.12 "$ver" | sort -V | head -1)" = "8.5.12" ] && fixed_vulnerable=1 ;;
  *)     fixed_vulnerable=1 ;;  # EOL branch (<=8.1): assume vulnerable
esac
if [ "$fixed_vulnerable" -eq 1 ]; then
  bad "PHP $ver is in the vulnerable range -> patch to the fixed release above"
else
  ok "PHP $ver is patched for CVE-2026-109618/109619"
fi

echo "== session.upload_progress (the attack surface) =="
prog_enabled=$(php -r 'echo ini_get("session.upload_progress.enabled");')
prog_name=$(php -r 'echo ini_get("session.upload_progress.name");')
prog_cleanup=$(php -r 'echo ini_get("session.upload_progress.cleanup");')

if [ "$prog_enabled" = "1" ] || [ "$prog_enabled" = "On" ] || [ "$prog_enabled" = "on" ]; then
  bad "session.upload_progress.enabled=On  (primary trigger; disable to mitigate pre-patch)"
else
  ok "session.upload_progress.enabled=Off  (bug class not reachable)"
fi
echo "  progress field name: $prog_name   cleanup=$prog_cleanup"

echo "== size limits that bound the OOM trigger =="
for k in post_max_size memory_limit upload_max_filesize max_file_uploads; do
  printf '  %s=%s\n' "$k" "$(php -r "echo ini_get('$k');")"
done
mem=$(php -r 'echo ini_get("memory_limit");')
note "memory_limit=$mem -- lower memory_limit makes the OOM trigger EASIER to hit; do not rely on it as a control"

echo "== SAPI (process model) =="
sapi=$(php -r 'echo PHP_SAPI;')
echo "  $sapi"
case "$sapi" in
  *apache2handler*) note "mod_php prefork: worker-pinning chain applies; PHP-FPM+event MPM is not vulnerable to the pinning step" ;;
  *)                ok "SAPI=$sapi -- not the mod_php prefork model the chain targets" ;;
esac

echo
echo "== Result: $pass ok, $fail vulnerable, $warn warnings =="

if [ "$fail" -gt 0 ]; then
  cat <<'CFG'

== Hardening (drop into php.ini; disables the trigger outright) ==
; Neutralizes CVE-2026-109618 / CVE-2026-109619 without a code patch.
session.upload_progress.enabled = Off

; If you NEED upload progress, keep it but contain it:
; session.upload_progress.enabled = On
; session.upload_progress.cleanup = On
; session.upload_progress.prefix  = "upload_progress_"
; ...and rate-limit concurrent POSTs + cap body size at the web tier.

; Real fix: upgrade PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+
CFG
fi
exit 0
