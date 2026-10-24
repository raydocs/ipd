#!/bin/sh
# Fetch a published ipd binary and check its sha256.
# Set IPD_URL and IPD_SHA256. Without them the script refuses to download.
# Release signing (cosign) is a publish step, not part of this tree.
set -eu
URL="${IPD_URL:-}"
WANT="${IPD_SHA256:-}"
DEST="${DEST:-/usr/local/bin/ipd}"
if [ -z "$URL" ] || [ -z "$WANT" ]; then
  echo "set IPD_URL and IPD_SHA256 to the artifact you built" >&2
  exit 2
fi
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL "$URL" -o "$tmp"
got=$(sha256sum "$tmp" | awk '{print $1}')
if [ "$got" != "$WANT" ]; then
  echo "sha256 mismatch: got $got want $WANT" >&2
  exit 1
fi
install -m 0755 "$tmp" "$DEST"
echo "installed $DEST"
