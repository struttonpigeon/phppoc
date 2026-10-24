#!/bin/bash
# Automate multi-version offset extraction (README "Multi-version support",
# steps 2-4): pull the matching official php:<version>-apache image, read the
# zval_ptr_dtor / zif_system symbol offsets out of libphp.so with readelf,
# report the architecture, and print the ready-to-paste PROFILES values.
#
# With --patch, also rewrite the matching PROFILES block in ../phppoc2.py.
#
# usage:
#   pure/extract_offsets.sh <php-version>            # e.g. 8.4.25
#   pure/extract_offsets.sh <php-version> --patch
#
# Note: this extracts offsets from an official Docker image you pull, to
# match a lab target running that same image.  It does not probe or extract
# anything from live remote systems.
set -eu

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)

if [ $# -lt 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi

VER=$1
PATCH=0
if [ "${2:-}" = "--patch" ]; then
    PATCH=1
fi

IMAGE="php:${VER}-apache"
NAME="p2s-offsets-$$"

if [ -n "${DOCKER:-}" ]; then
    :
elif docker info >/dev/null 2>&1; then
    DOCKER=docker
else
    DOCKER="sudo docker"
fi

echo "[*] pulling $IMAGE ..."
$DOCKER pull "$IMAGE" >/dev/null

# Keep the container idle; we only need its filesystem (libphp.so).
$DOCKER run -d --name "$NAME" --entrypoint sleep "$IMAGE" 600 >/dev/null
trap '$DOCKER rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

ARCH=$($DOCKER exec "$NAME" uname -m)
if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "aarch64" ]; then
    echo "[-] unsupported architecture '$ARCH' (PROFILES has x86_64/aarch64 only)" >&2
    exit 1
fi

SYMS=$($DOCKER exec "$NAME" \
    readelf -Ws /usr/local/lib/apache2/modules/libphp.so \
    | grep -wE 'zval_ptr_dtor|zif_system')

DTOR=$(echo "$SYMS" | awk '$NF == "zval_ptr_dtor" {print $2}' | head -n 1)
ZIF=$(echo "$SYMS" | awk '$NF == "zif_system" {print $2}' | head -n 1)

if [ -z "$DTOR" ] || [ -z "$ZIF" ]; then
    echo "[-] could not find zval_ptr_dtor/zif_system in $IMAGE (stripped build?)" >&2
    echo "$SYMS" >&2
    exit 1
fi

# normalise 000000000065eb60 -> 0x65EB60
hexfmt() { echo "0x$(echo "$1" | sed 's/^0*//' | tr 'a-f' 'A-F')"; }
DTOR_HEX=$(hexfmt "$DTOR")
ZIF_HEX=$(hexfmt "$ZIF")

echo ""
echo "image          : $IMAGE"
echo "architecture   : $ARCH"
echo "zval_ptr_dtor  : $DTOR_HEX"
echo "zif_system     : $ZIF_HEX"
echo ""
echo "Paste into the \"$ARCH\" block of PROFILES in phppoc2.py:"
echo "    \"dtor_offset\": $DTOR_HEX,"
echo "    \"zif_offset\":  $ZIF_HEX,"
echo ""
echo "(leave ptr_max / delta_min / delta_max unchanged -- architecture constants)"

if [ "$PATCH" = "1" ]; then
    python3 - "$ARCH" "$DTOR_HEX" "$ZIF_HEX" "$ROOT/phppoc2.py" <<'EOF'
import re
import sys

arch, dtor, zif, path = sys.argv[1:5]
src = open(path).read()
pat = re.compile(r'("%s"\s*:\s*\{[^{}]*\})' % re.escape(arch))
m = pat.search(src)
if not m:
    sys.exit("no PROFILES block for %r found in %s" % (arch, path))
block = m.group(1)
nb = re.sub(r'"dtor_offset"\s*:\s*0x[0-9A-Fa-f]+', '"dtor_offset": %s' % dtor, block)
nb = re.sub(r'"zif_offset"\s*:\s*0x[0-9A-Fa-f]+', '"zif_offset": %s' % zif, nb)
open(path, "w").write(src[:m.start()] + nb + src[m.end():])
print("[+] patched PROFILES[%r] in %s (dtor=%s zif=%s)" % (arch, path, dtor, zif))
EOF
fi
