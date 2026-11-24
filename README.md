# PCAP to Detection

A public series by 404SecurityNotFound. Each case takes one packet capture and turns it into detections that have been run against that capture and checked.

> Personal research by DJR (404SecurityNotFound). Views and rules are my own and do not represent my employer.

## Credit

Every case in this series starts from the work of **Brad Duncan**, who publishes free traffic analysis exercises, packet captures and notes at [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/). The captures, the scenarios and the exercise notes are his. This repository only adds analysis and detection content on top. If you find this useful, go and read the original exercises and support his site.

Captures are never redistributed here. Each case links back to the original exercise page.

## Method

1. Start from a published capture and the exercise notes.
2. Rebuild the timeline from the capture with tshark.
3. Decode every stage statically. Nothing is executed, detonated or replayed against a live host.
4. Write detections for each stage (Suricata, YARA, Sigma, KQL and SIEM logic).
5. Run the network and file rules against the capture and the extracted carrier, then record the measured results in `tests/expected-alerts.json`.

## Evidence labels

Every factual claim in an analysis file carries one of four labels.

| Label | Meaning |
|---|---|
| `[PCAP]` | Seen directly in the packet capture |
| `[Decoded]` | Recovered by static decoding of content carried in the capture |
| `[Notes]` | Stated in the exercise author's notes on malware-traffic-analysis.net |
| `[Inference]` | My reasoning from the evidence, not directly observed |

## Cases

| Date | Title | ATT&CK techniques | Rules | Walkthrough |
|---|---|---|---|---|
| 2026-11-16 | [Unidentified ClickFix pushes NetSupport RAT](cases/2026-11-16-clickfix-netsupport/) | 11 | KQL, SIEM spec (Suricata, YARA and Sigma to follow) | Walkthrough to follow |

## Repository layout

```
cases/<date>-<slug>/     analysis, IOCs, detections, tests and media for one case
docs/                    GitHub Pages site with the walkthroughs
tools/                   tshark extraction, static decoders and the STIX builder
.github/workflows/       CI that validates every rule and data file
```

## Safe handling

- Download captures only from the original source. This repository never hosts them.
- Analyse captures and any extracted content inside an isolated virtual machine with no route to production networks.
- Decoded output from the tools in `tools/` is malicious source code. Read it, never run it.
- `.gitignore` and CI both block captures, archives, executables, libraries and video carriers from being committed.

## Licence

Detection content under `cases/*/detections/` is released under the [Detection Rule License 1.1](LICENSE-DRL). Write-ups, data files and media are released under [CC BY 4.0](LICENSE-CC-BY). See [LICENSE](LICENSE) for the details.
