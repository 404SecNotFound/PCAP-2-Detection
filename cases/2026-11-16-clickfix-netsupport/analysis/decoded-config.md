# Decoded configuration

Everything here was recovered by static decoding. Nothing was executed. Secrets in client32.ini are redacted.

## Stage-2 PowerShell

| Field | Value | Evidence |
|---|---|---|
| Source | hxxp://anycheckgocap[.]com/ on 94.26.0[.]162:80 | `[PCAP]` |
| Size | 16,043 bytes | `[Decoded]` |
| SHA256 | 5df712fea72f3c1ccb7847fa683eb62651d4fa78158a1059d654c9ee9b8e72d4 | `[Decoded]` |

Behaviour in order `[Decoded]`.

1. Exits if `%COMPUTERNAME%` matches CLEAN or CLEN. Both strings are stored as XOR byte arrays with keys 96 and 108.
2. Uses Add-Type to compile a C# class and calls `ShowWindow(GetConsoleWindow(), 0)` to hide the console.
3. Exits if the marker file `%ProgramData%\.ch_7c4ff2c7b8ec` exists.
4. Downloads python-3.12.7-embed-amd64.zip with four fallbacks, tried in this order.
   1. `HttpClient.GetByteArrayAsync`
   2. `WebClient.DownloadData` with User-Agent `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`
   3. `Invoke-WebRequest`, with the cmdlet name stored as base64
   4. `System32\curl.exe -fsSL`

   A download counts only if it is larger than 500 KB. If every method fails, it falls back to the full Python installer with `/quiet InstallAllUsers=0 PrependPath=0`.
5. Extracts the runtime to `%LOCALAPPDATA%\.k835d0dd0454\py-embed\312\` and starts an embedded Python loader with a hidden window.

## MP4 carrier

| Field | Value | Evidence |
|---|---|---|
| URL | hxxp://94.26.0[.]162/0909.mp4 | `[PCAP]` |
| Request User-Agent | Exactly `Mozilla/5.0` | `[Decoded]` |
| Size | 6,045,332 bytes | `[Decoded]` |
| SHA256 | b5db2a004d8d90119add09c3ab222bf14b7207cf3cafe9d0e239453cc4f953e4 | `[Decoded]` |
| Container | Valid ISO media file, `ftyp` at offset 4 | `[Decoded]` |
| Payload box | `uuid` box at offset 0x0b95, box size 0x005c32ff | `[Decoded]` |
| Output | host.py, about 15.3 MB of Python carrying 20 NetSupport files as base64 | `[Decoded]` |

The payload box ends exactly at the end of the file (0x0b95 plus 0x005c32ff equals 6,045,332) `[Decoded]`.

### Box layout

```
[4-byte size][4-byte type "uuid"]
[16-byte usertype 0c5ae5ad-666d-4dbb-9723-361869c8ee54]
[4-byte magic FB DB 81 0D]
[2-byte key length]            20 in this sample
[key]                          20 bytes in this sample
[4-byte big-endian data length]
[data]                         XOR with the repeating key, then gzip
```

`tools/decode_mp4_carrier.py` reverses this layout with the Python standard library and writes the result as a `.txt` file outside the repository. Byte order of the 2-byte key length is not stated in my notes. The decoder reads it big-endian and falls back to little-endian if the value is out of range (TODO confirm against the sample).

## Agent settings in host.py

| Setting | Value | Evidence |
|---|---|---|
| `_CH_EXE_B64` | MIseN.Exe, a renamed client32.exe | `[Decoded]` |
| `_CH_DROP_ROOT` | public | `[Decoded]` |
| `_CH_PUBLIC_STD_NAMES` | Documents, Downloads, Music, Pictures, Videos | `[Decoded]` |
| `_CH_AUTOSTART_STARTUP_VBS` | True. A random ten letter .vbs in the Startup folder, launched by `wscript.exe //B //Nologo` | `[Decoded]` |
| `_CH_RUN` | OneDriveSyncHelper, an HKCU Run value in one branch | `[Decoded]` |
| Second branch Run value | SecurityHealth | `[Decoded]` |
| `_CH_LAUNCH_CHAIN` | exec, createprocess, shellexecute, popen | `[Decoded]` |
| Data directory | .k835d0dd0454 | `[Decoded]` |
| Script name | host.py | `[Decoded]` |

Which Run value was actually written cannot be seen in the capture `[Inference]`. The exercise notes confirm two Startup .vbs files and the NetSupport package in C:\Users\Public\Documents `[Notes]`.

## client32.ini

Packed inside host.py as LHQPT.iNI `[Decoded]`.

| Key | Value | Evidence |
|---|---|---|
| GatewayAddress | dasiiiitt[.]com:443 | `[Decoded]` |
| SecondaryGateway | piuifoasf[.]com:443. Not contacted in the capture. | `[Decoded]` `[PCAP]` |
| silent | 1 | `[Decoded]` |
| SysTray | 0 | `[Decoded]` |
| DisableDisconnect | 1 | `[Decoded]` |
| DisableClientConnect | 1 | `[Decoded]` |
| Usernames | * | `[Decoded]` |
| ShowUIOnConnect | 0 | `[Decoded]` |
| Password | [redacted] | `[Decoded]` |
| RADIUSSecret | [redacted] | `[Decoded]` |
| Licence file | Licensee NSM1234, generated 2018 | `[Decoded]` |
| `_Info` Filename | `C:\Users\Administrator\Documents\node-putty-lab-test\4\1\client32.ini` | `[Decoded]` |

The `_Info` Filename is the path on the builder's machine. It is a useful pivot for finding other samples from the same builder `[Inference]`.

## C2 exchange

Seen in TCP stream 40 `[PCAP]`.

```
Client  POST hxxp://93.152.209[.]36/fakeurl.htm   (destination port 443, no TLS)
        User-Agent: NetSupport Manager/1.3
        CMD=POLL INFO=1 ACK=1

Server  Server: NetSupport Gateway/1.92 (Windows NT)
        CMD=ENCD ES=1 DATA=<encrypted>
```

## NetSupport package

The 20 files carried in host.py include the binaries listed in [../iocs/hashes.txt](../iocs/hashes.txt) `[Decoded]`. Most DLLs are genuine NetSupport components, so they are hunting context rather than block-list material `[Inference]`.
