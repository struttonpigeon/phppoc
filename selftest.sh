#!/bin/bash
# selftest.sh -- mechanical verification that this repo is in a usable state.
#
# Static checks (always run):
#   1. every Python file compiles
#   2. both entry points parse their CLI (--help)
#   3. the pure/pwn_pure.py alias resolves to an existing file
#   4. every helper phppoc2.py invokes actually exists
#   5. every file pure/run_pure.sh mounts/reference exists (+ calibration kit)
#   6. shell scripts pass bash -n
#
# Dynamic check (opt-in, needs Docker):
#   ./selftest.sh --docker    # boots the lab target via pure/run_pure.sh and
#                             # fires one exploit attempt end-to-end
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$HERE"

PASS=0
FAIL=0
ok()  { echo "  ok    $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }

echo "[1/6] python syntax"
for f in *.py pure/*.py; do
    [ -e "$f" ] || continue
    if python3 -m py_compile "$f" 2>/dev/null; then ok "$f"; else bad "$f (py_compile)"; fi
done

echo "[2/6] entry points"
if python3 phppoc2.py --help >/dev/null 2>&1; then ok "phppoc2.py --help"; else bad "phppoc2.py --help"; fi
if python3 phpexploit.py --help >/dev/null 2>&1; then ok "phpexploit.py --help"; else bad "phpexploit.py --help"; fi

echo "[3/6] pwn_pure.py alias target"
ALIAS_TARGET=$(python3 - <<'EOF'
import re
src = open("pure/pwn_pure.py").read()
m = re.search(r'os\.path\.join\(ROOT,\s*"([^"]+)"\)', src)
print(m.group(1) if m else "")
EOF
)
if [ -n "$ALIAS_TARGET" ] && [ -f "$ALIAS_TARGET" ]; then
    ok "pure/pwn_pure.py -> $ALIAS_TARGET"
else
    bad "pure/pwn_pure.py target '$ALIAS_TARGET' does not exist"
fi

echo "[4/6] helpers invoked by phppoc2.py"
for h in chunked_send.py mk_a1.py mk_leak_b.py cheap_oom_a.py mk_ht.py fake_ref_b.py; do
    if [ -f "pure/$h" ]; then ok "pure/$h"; else bad "pure/$h missing"; fi
done

echo "[5/6] lab + calibration files"
for f in pure/docker/www/index.php pure/docker/apache-single-worker.conf \
         pure/run_pure.sh pure/RESEARCH_PURE_128M.md pure/extract_offsets.sh; do
    if [ -f "$f" ]; then ok "$f"; else bad "$f missing"; fi
done

echo "[6/6] shell script syntax"
for s in pure/run_pure.sh pure/repro_pure.sh pure/watch_md.sh pure/extract_offsets.sh; do
    [ -e "$s" ] || continue
    if bash -n "$s"; then ok "$s"; else bad "$s (bash -n)"; fi
done

if [ "${1:-}" = "--docker" ]; then
    echo ""
    echo "[docker] end-to-end lab reproduction (php:8.4.26-apache, stock config)"
    if docker info >/dev/null 2>&1 || sudo -n docker info >/dev/null 2>&1; then
        if pure/run_pure.sh; then
            if python3 phppoc2.py --port 18110 --retries 2; then
                echo "  ok    end-to-end RCE (proof below)"
                cat out/p1 2>/dev/null && PASS=$((PASS + 1)) || bad "out/p1 not readable"
            else
                bad "exploit chain did not produce proof (see stage output above)"
            fi
        else
            bad "pure/run_pure.sh failed to boot the lab target"
        fi
    else
        echo "  skip  docker not available on this machine"
    fi
fi

echo ""
echo "passed=$PASS failed=$FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
    exit 0
else
    echo "FAILURES PRESENT"
    exit 1
fi
