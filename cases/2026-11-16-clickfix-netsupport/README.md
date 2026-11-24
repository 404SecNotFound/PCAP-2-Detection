# 2026-11-16 Unidentified ClickFix pushes NetSupport RAT

> Personal research by DJR (404SecurityNotFound). Views and rules are my own and do not represent my employer.

## Credit

The capture, scenario and exercise notes for this case are by **Brad Duncan** at malware-traffic-analysis.net. Original exercise page is [hxxps://www.malware-traffic-analysis[.]net/2026/11/16/index.html](https://www.malware-traffic-analysis.net/2026/11/16/index.html). The capture is not redistributed here. Download it from that page and handle it in an isolated VM.

## Summary

A compromised website loaded an injected script that showed a fake CAPTCHA and placed a PowerShell command on the clipboard. The victim pasted and ran it, which pulled a stage-2 script, a portable Python runtime and an MP4 file hiding a Python loader. That loader dropped a NetSupport RAT client that checked in to its gateway every minute for more than five hours.

**121 seconds from page load to the first NetSupport check-in.** The last click to the first check-in took 89 seconds.

## Compact timeline (UTC, 2026-11-16)

| Time | Event | Evidence |
|---|---|---|
| 21:57:41.465 | Victim loads compromised site crownherliving[.]com | `[PCAP]` |
| 21:57:42.715 | Injected script from wuntred[.]com | `[PCAP]` |
| 21:57:43.325 | Lure loader kyc2.js from adsmanagertgo[.]click | `[PCAP]` |
| 21:57:44.247 | Fake CAPTCHA backend adsmanagerast[.]pro | `[PCAP]` |
| 21:58:13.232 | Second click and clipboard set | `[Notes]` |
| 21:59:33.709 | PowerShell fetches stage 2 from anycheckgocap[.]com | `[PCAP]` |
| 21:59:38.329 | MP4 carrier hxxp://94.26.0[.]162/0909.mp4 | `[PCAP]` |
| 21:59:42.986 | First NetSupport POST to 93.152.209[.]36:443 | `[PCAP]` |
| 03:16:25.865 (17 Nov) | Last of 320 check-ins | `[PCAP]` |

The full table is in [analysis/timeline.md](analysis/timeline.md).

## ATT&CK techniques

T1189, T1204.004, T1059.001, T1027, T1105, T1059.006, T1027.003, T1219, T1571, T1036.003, T1547.001. Coverage scores are in [attack-layer.json](attack-layer.json).

## Contents

| Path | What it holds |
|---|---|
| [analysis/timeline.md](analysis/timeline.md) | Full timeline with evidence labels |
| [analysis/stages.md](analysis/stages.md) | Eight stages with the detection opportunity for each |
| [analysis/decoded-config.md](analysis/decoded-config.md) | Stage-2 behaviour, carrier format, agent settings, client32.ini |
| [iocs/](iocs/) | CSV, STIX 2.1 bundle and hash list |
| detections/suricata/ | Network rules, tested against the capture. TODO to follow in a later PR |
| detections/yara/ | MP4 carrier rules, tested against 0909.mp4. TODO to follow in a later PR |
| detections/sigma/ | Host rules, one per file. TODO to follow in a later PR |
| [detections/kql/](detections/kql/) | Microsoft Defender advanced hunting queries |
| [detections/siem/](detections/siem/) | SIEM detection spec UC-01 to UC-07 |
| [tests/](tests/) | Expected alert counts and the offline test runner |
| media/ | Screenshots from the analysis. TODO to follow in a later PR |

## Links

- Walkthrough with audio narration on GitHub Pages. TODO to follow in a later PR
- Medium article TODO
- Original exercise by Brad Duncan on [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2026/11/16/index.html)
