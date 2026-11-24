#!/usr/bin/env bash
# Offline detection test for case 2026-11-16-clickfix-netsupport.
# Usage: run_tests.sh --pcap PATH [--mp4 PATH]
# Runs Suricata over the capture and YARA over the MP4 carrier, then compares
# results with expected-alerts.json. Inputs are read in place and never copied
# into the repository. Output goes to a temp dir that is removed on exit.
# Optional: SURICATA_CONFIG=/path/to/suricata.yaml to override the minimal config.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CASE="$(dirname "$HERE")"
REPO="$(cd "$CASE/../.." && pwd)"
EXPECTED="$HERE/expected-alerts.json"
PCAP="" MP4="" FAILS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --pcap) PCAP="${2:-}"; shift 2 ;;
    --mp4)  MP4="${2:-}"; shift 2 ;;
    *) echo "usage: $0 --pcap PATH [--mp4 PATH]"; exit 2 ;;
  esac
done
[ -f "$PCAP" ] || { echo "usage: $0 --pcap PATH [--mp4 PATH]"; exit 2; }

inside_repo() { case "$(cd "$(dirname "$1")" && pwd)/" in "$REPO"/*) return 0 ;; esac; return 1; }
for f in "$PCAP" ${MP4:+"$MP4"}; do
  if inside_repo "$f"; then echo "refusing: $f is inside the repository, keep samples outside it"; exit 2; fi
done

check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "PASS  $1 (expected $2, got $3)"
  else echo "FAIL  $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi
}
jget() { python3 -c "import json,sys;d=json.load(open('$EXPECTED'));print(eval(sys.argv[1]))" "$1"; }
sha() { shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1 || sha256sum "$1" | cut -d' ' -f1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# Capture identity
check "pcap sha256" "$(jget "d['pcap']['sha256']")" "$(sha "$PCAP")"

# Suricata
RULES="$CASE/$(jget "d['suricata']['rules']")"
CONF="${SURICATA_CONFIG:-$HERE/suricata-minimal.yaml}"
if ! command -v suricata >/dev/null; then echo "FAIL  suricata not installed"; FAILS=$((FAILS + 1))
elif [ ! -f "$RULES" ]; then echo "FAIL  rules file missing: $RULES"; FAILS=$((FAILS + 1))
else
  suricata -c "$CONF" -r "$PCAP" -S "$RULES" -l "$TMP" -k none >"$TMP/suricata.out" 2>&1 \
    || { echo "FAIL  suricata run, see output below"; cat "$TMP/suricata.out"; FAILS=$((FAILS + 1)); }
  COUNTS="$(python3 - "$TMP/eve.json" <<'EOF'
import json, sys, collections
c = collections.Counter()
try:
    for line in open(sys.argv[1]):
        e = json.loads(line)
        if e.get("event_type") == "alert":
            c[str(e["alert"]["signature_id"])] += 1
except FileNotFoundError:
    pass
print(json.dumps(c))
EOF
)"
  for s in $(jget "' '.join(d['suricata']['alerts_by_sid'])"); do
    check "suricata sid $s" "$(jget "d['suricata']['alerts_by_sid']['$s']")" \
      "$(python3 -c "import json,sys;print(json.loads(sys.argv[1]).get('$s',0))" "$COUNTS")"
  done
fi

# YARA
if [ -n "$MP4" ]; then
  YRULES="$CASE/$(jget "d['yara']['rules']")"
  check "mp4 sha256" "$(jget "d['yara']['targets'][0]['sha256']")" "$(sha "$MP4")"
  if ! command -v yara >/dev/null; then echo "FAIL  yara not installed"; FAILS=$((FAILS + 1))
  elif [ ! -f "$YRULES" ]; then echo "FAIL  rules file missing: $YRULES"; FAILS=$((FAILS + 1))
  else
    check "yara rules matched on mp4" "$(jget "d['yara']['targets'][0]['rules_matched']")" "$(yara -c "$YRULES" "$MP4")"
  fi
else
  echo "SKIP  yara (no --mp4 given)"
fi

echo
if [ "$FAILS" -eq 0 ]; then echo "RESULT PASS"; else echo "RESULT FAIL ($FAILS failed)"; fi
exit $((FAILS > 0))
