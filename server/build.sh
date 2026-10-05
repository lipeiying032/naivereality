#!/bin/bash
# Builds the lightweight REALITY front end and the PoCs.
#
#   BSSL_DIR=/path/to/boringssl bash server/build.sh [outdir]
#
# BSSL_DIR must point at a BoringSSL checkout with
# patches/boringssl-reality-server.patch applied and libssl/libcrypto built
# (cmake -GNinja -B build -DBUILD_TESTING=OFF . && ninja -C build ssl crypto).
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BSSL="${BSSL_DIR:-$ROOT/../boringssl}"
OUT="${1:-$ROOT/bin}"
ONLY_SERVER="${ONLY_SERVER:-0}"

if [ ! -f "$BSSL/build/libssl.a" ]; then
  echo "error: $BSSL/build/libssl.a not found; build BoringSSL first" >&2
  exit 1
fi

mkdir -p "$OUT"
CXX="${CXX:-g++}"
FLAGS="-std=c++17 -O2 -g -Wall -Wextra -I$BSSL/include -I$HERE"
LIBS="-L$BSSL/build -lssl -lcrypto -lpthread"

if [ "$ONLY_SERVER" = "1" ]; then
  # Programs that need only the server-side BoringSSL seams.
  APPS="reality_server poc_mirror_server poc_suspend"
else
  APPS="reality_server poc_mirror_server poc_client poc_suspend poc_end_to_end genkey"
fi

for app in $APPS; do
  echo "building $app"
  if [ "$app" = "genkey" ]; then
    $CXX $FLAGS -o "$OUT/$app" "$HERE/$app.cc" $LIBS
  else
    $CXX $FLAGS -o "$OUT/$app" "$HERE/$app.cc" "$HERE/reality_common.cc" $LIBS
  fi
done

echo "ok: $OUT"
