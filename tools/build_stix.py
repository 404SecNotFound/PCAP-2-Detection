#!/usr/bin/env python3
"""Build a deterministic STIX 2.1 bundle from a case's iocs/iocs.csv.

Usage: python3 tools/build_stix.py cases/<case-dir>

Ids are UUIDv5 and timestamps are fixed per case, so reruns produce identical output.
Standard library only. The bundle holds LIVE indicator values.
"""
import csv
import json
import sys
import uuid
from pathlib import Path

NS = uuid.UUID("4f3c0b8e-9a1d-5c2e-8b7f-404404404404")  # 404SecurityNotFound namespace

# Per-case settings. Add an entry when a new case is added.
CASES = {
    "2026-11-16-clickfix-netsupport": {
        "created": "2026-11-24T00:00:00.000Z",
        "fallback_first_seen": "2026-11-16T21:59:38.329Z",  # MP4 carrier, source of decoded-only items
        "source_url": "https://www.malware-traffic-analysis.net/2026/11/16/index.html",
        "c2_values": {"dasiiiitt.com", "93.152.209.36", "http://93.152.209.36:443/fakeurl.htm",
                      "NetSupport Manager/1.3", "piuifoasf.com"},
        "payload_values": {"anycheckgocap.com", "94.26.0.162", "http://anycheckgocap.com/",
                           "http://94.26.0.162/0909.mp4"},
        "techniques": [
            ("T1189", "Drive-by Compromise"),
            ("T1204.004", "User Execution: Malicious Copy and Paste"),
            ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
            ("T1027", "Obfuscated Files or Information"),
            ("T1105", "Ingress Tool Transfer"),
            ("T1059.006", "Command and Scripting Interpreter: Python"),
            ("T1027.003", "Obfuscated Files or Information: Steganography"),
            ("T1219", "Remote Access Tools"),
            ("T1571", "Non-Standard Port"),
            ("T1036.003", "Masquerading: Rename Legitimate Utilities"),
            ("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"),
        ],
    },
}


def sid(kind, name):
    return f"{kind}--{uuid.uuid5(NS, kind + '|' + name)}"


def esc(v):
    return v.replace("\\", "\\\\").replace("'", "\\'")


def pattern(t, v):
    return {
        "domain": f"[domain-name:value = '{esc(v)}']",
        "ipv4": f"[ipv4-addr:value = '{esc(v)}']",
        "url": f"[url:value = '{esc(v)}']",
        "sha256": f"[file:hashes.'SHA-256' = '{esc(v)}']",
        "user-agent": f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{esc(v)}']",
    }.get(t)  # http-server-header has no standard STIX object path, so it is skipped


def build(case_dir):
    case_dir = Path(case_dir)
    cfg = CASES[case_dir.name]
    created = cfg["created"]
    ident = sid("identity", "404SecurityNotFound")
    common = {"spec_version": "2.1", "created": created, "modified": created, "created_by_ref": ident}
    src_ref = {"source_name": "malware-traffic-analysis.net",
               "description": "Original capture, exercise and notes by Brad Duncan",
               "url": cfg["source_url"]}

    objs = [{"type": "identity", "id": ident, "spec_version": "2.1", "created": created, "modified": created,
             "name": "404SecurityNotFound", "identity_class": "individual",
             "description": "Personal research by DJR (404SecurityNotFound). Views and rules are my own and do not represent my employer."}]
    mal = sid("malware", "NetSupport RAT")
    objs.append({"type": "malware", "id": mal, **common, "name": "NetSupport RAT", "is_family": True,
                 "malware_types": ["remote-access-trojan"],
                 "description": "Abused NetSupport Manager client delivered by ClickFix. Case " + case_dir.name,
                 "external_references": [src_ref]})
    c2 = sid("infrastructure", case_dir.name + "|c2")
    pay = sid("infrastructure", case_dir.name + "|payload")
    objs.append({"type": "infrastructure", "id": c2, **common, "name": "NetSupport gateway dasiiiitt.com / 93.152.209.36:443",
                 "infrastructure_types": ["command-and-control"]})
    objs.append({"type": "infrastructure", "id": pay, **common, "name": "Payload server anycheckgocap.com / 94.26.0.162",
                 "infrastructure_types": ["hosting-malware"]})
    rels = [("uses", mal, c2), ("uses", mal, pay)]

    for tid, name in cfg["techniques"]:
        ap = sid("attack-pattern", tid)
        objs.append({"type": "attack-pattern", "id": ap, **common, "name": name,
                     "external_references": [{"source_name": "mitre-attack", "external_id": tid,
                                              "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"}]})
        rels.append(("uses", mal, ap))

    lines = (l for l in (case_dir / "iocs" / "iocs.csv").read_text().splitlines() if not l.startswith("#"))
    for row in csv.DictReader(lines):
        p = pattern(row["type"], row["value_raw"])
        if not p:
            continue
        ind = sid("indicator", row["type"] + "|" + row["value_raw"])
        objs.append({"type": "indicator", "id": ind, **common,
                     "name": f"{row['type']} {row['value_defanged']}",
                     "description": f"{row['role']}. Evidence {row['evidence']}. LIVE value in pattern.",
                     "indicator_types": ["malicious-activity"], "pattern": p, "pattern_type": "stix",
                     "valid_from": row["first_seen_utc"] or cfg["fallback_first_seen"],
                     "confidence": {"low": 15, "medium": 50, "high": 85}[row["confidence"]],
                     "external_references": [src_ref]})
        rels.append(("indicates", ind, mal))
        if row["value_raw"] in cfg["c2_values"]:
            rels.append(("indicates", ind, c2))
        if row["value_raw"] in cfg["payload_values"]:
            rels.append(("indicates", ind, pay))

    for r, s, t in rels:
        objs.append({"type": "relationship", "id": sid("relationship", f"{r}|{s}|{t}"), **common,
                     "relationship_type": r, "source_ref": s, "target_ref": t})

    bundle = {"type": "bundle", "id": sid("bundle", case_dir.name), "objects": objs}
    out = case_dir / "iocs" / "iocs.stix.json"
    out.write_text(json.dumps(bundle, indent=2) + "\n")
    print(f"wrote {out} with {len(objs)} objects")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    build(sys.argv[1].rstrip("/"))
