# SIEM detection spec

Vendor-neutral use cases for the 2026-11-16 ClickFix to NetSupport RAT chain. Each use case names the log source, the logic and a severity. UC-07 joins them into one correlated alert.

> Personal research by DJR (404SecurityNotFound). Views and rules are my own and do not represent my employer.

TODO reconcile this spec with `siem_correlation_sketch.txt` from the original analysis notes, which was not available when this file was written.

## Use cases

### UC-01 ClickFix Run-box execution

- **Severity** High
- **Sources** Sysmon EID 1 or Windows Security 4688 with command line. Companion Sysmon EID 13.
- **Logic** Parent process is explorer.exe. Process is powershell.exe, pwsh.exe, mshta.exe or cmd.exe. The command line holds at least one fetch term (`http`, `irm`, `iwr`, `RestMethod`, `WebRequest`, `WebClient`, `Get-Command`) and at least one execute term (`iex`, `Invoke-Expression`, `|&`).
- **Companion** Sysmon EID 13 write to `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` whose value holds `powershell` or `http`.
- **Covers** Stage 3. T1204.004, T1059.001.

### UC-02 Obfuscated stage-2 PowerShell

- **Severity** Medium
- **Source** PowerShell 4104 script block logging.
- **Logic** The script text holds two or more of these.
  - `GetConsoleWindow` together with `ShowWindow`
  - `FromBase64String` together with `ProgramData`
  - `-bxor`
  - a string matching `python-*-embed-*.zip`
  - `Expand-Archive` with a destination under LocalAppData
- **Covers** Stage 4. T1059.001, T1027.

### UC-03 Portable Python staging

- **Severity** Medium
- **Sources** Web proxy, Sysmon EID 1 and EID 11.
- **Logic** Any of these.
  - A proxy request for `/ftp/python/*/python-*-embed-*.zip` from a host that is not a developer workstation
  - python.exe or pythonw.exe running from `\AppData\Local\.<hex>\py-embed\`
  - Files created under `\AppData\Local\.<hex>\py-embed\`
- **Covers** Stage 5. T1059.006, T1105.

### UC-04 MP4 carrier from a raw IP

- **Severity** Medium
- **Sources** Web proxy, NetMon or NDR.
- **Logic** Response content type is `video/mp4`, the URL host is an IP literal, and the User-Agent is exactly `Mozilla/5.0` or is not a browser. Add a network signature for the uuid box marker `FB DB 81 0D` where payload inspection is available.
- **Covers** Stage 6. T1027.003, T1105.

### UC-05 NetSupport RAT C2

- **Severity** Critical
- **Sources** Web proxy, NetMon or NDR.
- **Logic** Any of these.
  - User-Agent contains `NetSupport Manager`
  - Server header contains `NetSupport Gateway`
  - Application protocol HTTP on destination port 443 to an external IP
- **Covers** Stage 7. T1219, T1571.

### UC-06 Unauthorised NetSupport client

- **Severity** High
- **Sources** Sysmon EID 1, EID 11 and EID 13, Windows Security 4688.
- **Logic** Any of these.
  - Process with OriginalFileName `client32.exe` running outside `Program Files\NetSupport`
  - client32.ini created outside Program Files
  - A .vbs file created in a Startup folder, then run by wscript.exe with `//B`
- **Covers** Stages 7 and 8. T1036.003, T1547.001.

### UC-07 Correlation

- **Severity** High to Critical
- **Grouping** By host, after mapping source IP to hostname.
- **Logic**
  1. Block 1 is UC-01.
  2. Block 2 is any of UC-02, UC-03 or UC-04 within 5 minutes of block 1.
  3. Block 3 is any of UC-05 or UC-06 within 10 minutes of block 2.
- **Outcome**
  - Blocks 1 and 2 raise a High alarm.
  - Blocks 1, 2 and 3 raise a Critical alarm with automated host isolation, a block on the C2 address and collection of client32.ini from the host.

In this capture the full chain completed inside 121 seconds, well inside both windows `[PCAP]`.

## Data sources

| Source | Events and fields | Use cases |
|---|---|---|
| Sysmon | EID 1 process create, EID 3 network connect, EID 11 file create, EID 13 registry value set, EID 22 DNS query | UC-01, UC-03, UC-06 |
| Windows Security | 4688 with command line auditing enabled | UC-01, UC-06 |
| PowerShell | 4104 script block logging | UC-02 |
| Web proxy | URL, User-Agent, content type | UC-03, UC-04, UC-05 |
| NetMon or NDR | Application, destination port, User-Agent, server header | UC-04, UC-05 |
| DNS | Query name and answer | Enrichment, UC-05 pivot |
| DHCP or host records | IP to hostname mapping | UC-07 grouping |

LogRhythm log source type names vary by version and must be confirmed for each deployment before these use cases are built.

## Host identity warning

Network-only sources identify the victim by IP address. The capture itself holds no DHCP, Kerberos or NBNS traffic, so the hostname and user could not be recovered from it `[PCAP]`. In a real deployment UC-07 depends on reliable IP to hostname mapping from DHCP logs or an asset inventory. Without it, host-side blocks (UC-01, UC-02, UC-06) and network blocks (UC-04, UC-05) will not join, and the correlation will under-alert.

## Build order

1. UC-05. Highest confidence, network only, catches the C2 even if delivery is missed.
2. UC-01. Earliest point of user execution.
3. UC-06. Confirms the client on the host and covers persistence.
4. UC-04 and UC-03. Delivery signals that feed the correlation.
5. UC-02. Needs 4104 logging, which is often not enabled.
6. UC-07. Build last, once the blocks above are producing clean events and IP to hostname mapping is in place.
