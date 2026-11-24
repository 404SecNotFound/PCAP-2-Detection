#!/usr/bin/env bash
# Rebuild the core timeline from a capture with tshark.
# Usage: tools/extract_timeline.sh capture.pcap
set -euo pipefail
[ -f "${1:-}" ] || { echo "usage: $0 capture.pcap"; exit 2; }

echo "## HTTP requests (time, dst ip, dst port, host, uri, user-agent)"
tshark -r "$1" -Y "http.request" -T fields -e frame.time_utc -e ip.dst -e tcp.dstport -e http.host -e http.request.uri -e http.user_agent

echo
echo "## First TLS SNI per name (time, dst ip, sni)"
tshark -r "$1" -Y "tls.handshake.extensions_server_name" -T fields -e frame.time_utc -e ip.dst -e tls.handshake.extensions_server_name | awk '!s[$3]++'

echo
echo "## First and last NetSupport check-in"
tshark -r "$1" -Y 'http.user_agent contains "NetSupport"' -T fields -e frame.time_utc | sed -n '1p;$p'
