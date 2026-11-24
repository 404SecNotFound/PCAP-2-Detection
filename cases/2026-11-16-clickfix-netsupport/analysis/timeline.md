# Timeline

All times are UTC. The capture starts on 2026-11-16 and ends on 2026-11-17.

## Capture

| Field | Value | Evidence |
|---|---|---|
| SHA256 | 30ab1b26b358314ad7e37f084765dd14aabcea85ef65dc716c41cb635ad90498 | `[PCAP]` |
| Size | 30,017,024 bytes, about 30,000 packets | `[PCAP]` |
| Window | 2026-11-16 21:57:41 to 2026-11-17 03:16:33 | `[PCAP]` |
| Victim | 10.11.16[.]128, MAC 00:16:ea:d7:01:68 | `[PCAP]` |
| Resolver | 10.11.16[.]2 | `[PCAP]` |
| Hostname and user | Not recoverable. The capture holds no DHCP, Kerberos or NBNS traffic. | `[PCAP]` |
| Source | [malware-traffic-analysis.net exercise by Brad Duncan](https://www.malware-traffic-analysis.net/2026/11/16/index.html) | Link only |

## Events

| Time | Event | Indicator | Evidence |
|---|---|---|---|
| 21:57:41.465 | DNS and TLS to compromised site | crownherliving[.]com 66.223.49[.]89 | `[PCAP]` |
| 21:57:42.561 | Site asset | bronkbuilder-website-assets.s3.us-east-2.amazonaws[.]com | `[PCAP]` |
| 21:57:42.715 | Injected script host | wuntred[.]com 172.67.165[.]144, 104.21.42[.]198 | `[PCAP]` |
| 21:57:43.325 | Lure loader kyc2.js | adsmanagertgo[.]click 104.21.45[.]172, 172.67.217[.]8 | `[PCAP]` |
| 21:57:43.578 | Fingerprint call change.php?fp=1 | adsmanagerast[.]pro | `[Notes]` |
| 21:57:44.247 | Fake CAPTCHA backend | adsmanagerast[.]pro 104.21.35[.]159, 172.67.177[.]159 | `[PCAP]` |
| 21:58:06.311 | First click check-in change.php?click=1 | epoch 1794866286311 | `[Notes]`, epoch `[Decoded]` |
| 21:58:13.232 | Second click, clipboard set | epoch 1794866293232 | `[Notes]`, epoch `[Decoded]` |
| 21:59:33.709 | PowerShell GET / for stage 2 | anycheckgocap[.]com 94.26.0[.]162:80 | `[PCAP]` |
| 21:59:34.837 | Python 3.12.7 embeddable zip | www.python[.]org 167.82.48[.]223 | `[PCAP]` |
| 21:59:38.329 | MP4 carrier download | hxxp://94.26.0[.]162/0909.mp4 | `[PCAP]` |
| 21:59:42.758 | Gateway DNS answer | dasiiiitt[.]com resolves to 93.152.209[.]36 | `[PCAP]` |
| 21:59:42.986 | First NetSupport POST | 93.152.209[.]36:443 /fakeurl.htm | `[PCAP]` |
| 03:16:25.865 | Last of 320 check-ins, mean interval 59.6 s | 93.152.209[.]36:443 | `[PCAP]` |

The two click epochs are millisecond Unix timestamps. Converting them gives 21:58:06.311 and 21:58:13.232 UTC on 2026-11-16, which matches the times in the exercise notes.

## Key spans

| Span | Duration | Evidence |
|---|---|---|
| Page load to first C2 check-in | 121 s | `[PCAP]` |
| Last click to first C2 check-in | 89 s | `[Notes]` for the click, `[PCAP]` for the check-in |
| Last click to PowerShell request | 80 s | `[Notes]` for the click, `[PCAP]` for the request |
| Observed dwell, first to last check-in | 5 h 17 m | `[PCAP]` |

## Reproducing the timeline

Run `tools/extract_timeline.sh <capture.pcap>` to list HTTP requests, the first TLS SNI per name and the first and last NetSupport check-in.
