#!/bin/sh
# Downloads a release of the HTM UC PBX agent, verifies its SHA-256, and runs the installer.
#
#   curl -fsSLO https://raw.githubusercontent.com/raziffmohamed/htmuc-pbx-agent/main/get.sh
#   sh get.sh --version X.Y.Z --sha256 <64 hex from the release notes> [installer options...]
#
# Options before `--` are for this script; everything else is passed to install_agent.py.
set -eu
REPO="${UCAGENT_REPO:-raziffmohamed/htmuc-pbx-agent}"
VERSION="" ; SHA="" ; URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --sha256)  SHA="$2"; shift 2;;
    --url)     URL="$2"; shift 2;;
    *) break;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }
[ -n "$SHA" ] || { echo "--sha256 is required (it is listed with the release). Refusing to install unverified code." >&2; exit 1; }
case "$SHA" in *[!0-9a-f]*|"") echo "bad --sha256" >&2; exit 1;; esac
[ "${#SHA}" = 64 ] || { echo "bad --sha256 length" >&2; exit 1; }
if [ -z "$URL" ]; then
  [ -n "$VERSION" ] || { echo "--version or --url required" >&2; exit 1; }
  URL="https://raw.githubusercontent.com/$REPO/main/releases/ucagent-$VERSION.tar.gz"
fi
case "$URL" in https://*) ;; *) echo "URL must be https" >&2; exit 1;; esac
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo "Downloading $URL"
curl -fsSL --proto '=https' --tlsv1.2 -o "$TMP/agent.tar.gz" "$URL"
echo "$SHA  $TMP/agent.tar.gz" | sha256sum -c - >/dev/null || { echo "SHA-256 mismatch. Not installing." >&2; exit 1; }
mkdir "$TMP/src"; tar -xzf "$TMP/agent.tar.gz" -C "$TMP/src" --no-same-owner
DIR="$(find "$TMP/src" -maxdepth 2 -name install_agent.py -printf '%h' -quit)"
[ -n "$DIR" ] || { echo "install_agent.py not found in the archive" >&2; exit 1; }
exec python3 "$DIR/install_agent.py" "$@"
