## Overview

Date:2025-05-12

Attack:PURELOGS INFECTION 

The attacker aimed to deploy PureLogs, a .NET-based information stealer, onto victim machines using a socially engineered phishing email with a malicious attachment.

## Download associated the files

`2025-05-12-IOCs-for-unidentified-malware-infection.txt.zip`   
`2025-05-12-email-with-malware-attachment-0845-UTC.eml.zip`   
`2025-05-12-infection-traffic-from-unidentified-malware.pcap.zip`  
`2025-05-12-unidentified-malware-and-artifacts.zip`  

## Associated Malware Artifacts - May 12, 2025 PureLogs Incident

- [`2025-05-12-IOCs-for-unidentified-malware-infection.txt.zip`](#)
  -  Contains IOC text file (likely domains, hashes, file paths, IPs)
  - ZIP archive (1.3 kB)

- [`2025-05-12-email-with-malware-attachment-0845-UTC.eml.zip`](#)
  - Captured phishing email that delivered the payload
  - Includes headers, subject line, and the malicious `.xz` attachment
  - File size: 1.5 MB

- [`2025-05-12-infection-traffic-from-unidentified-malware.pcap.zip`](#)
  -  Network packet capture from the infected host
  - Shows communication to C2 (`176.65.144[.]169:7702`)
  - File size: 1.7 MB

- [`2025-05-12-unidentified-malware-and-artifacts.zip`](#)
  -  Full extracted artifacts from the attack chain:
    - `invoice_10988.xz`
    - `invoice_10988.img`
    - `KTMBE25040170.exe`
    - `Count.vbs`, config files, logs
  - File size: 4.3 MB



##  Indicators of Compromise

<img width="1095" height="569" alt="image" src="https://github.com/user-attachments/assets/2028d3ee-9874-46af-9de6-d42674978608" />

## Email & Social Engineering

| Field            | Value                                                                  |
| ---------------- | ---------------------------------------------------------------------- |
| **Sender Name**  | Sedra Al Jundi                                                         |
| **From Address** | `<unknown>` via `etsdc.com`                                            |
| **Sender IP**    | `185.222.57[.]74`                                                      |
| **Date**         | May 12, 2025 – 08:45 UTC                                               |
| **Subject**      | `RE: Urgent: Confirmation Required for Invoice & Down Payment Details` |
| **Attachment**   | `invoice_10988.xz`                                                     |
| **Message-ID**   | `<20250512014532.63FE56B89701F86C@etsdc[.]com>`                        |
| **Trick Used**   | ZIP password stored on phishing site "About" page to evade scanners    |

## Malicious attachment breakdown

**Zipfile**

| IOC Type            | Details                                                            |
| ------------------- | ------------------------------------------------------------------ |
| File Name           | `invoice_10988.xz`                                                 |
| Type                | Misleading ZIP archive                                             |
| SHA256              | `341f58943626dec0cabc58fbec4f7263125ec1ed75e0c97418cefe0ca23c6a25` |
| File Size           | 1,427,085 bytes                                                    |
| Description | Contiains the iso                            |


**ISO image**

| IOC Type     | Details                                                            |
| ------------ | ------------------------------------------------------------------ |
| File Name    | `invoice_10988.img`                                                |
| Type         | ISO 9660 CD-ROM image                                              |
| SHA256       | `f757fc452dbb8eb564081d3decfdb31ec24fc4b91e22ee8088cb5884729cc99a` |
| File Size    | 1,515,520 bytes                                                    |
| Volume Label | `KTMBE25040170`                                                    |
| Description  | Contains final EXE payload                                         |

**Executable image**

| IOC Type            | Details                                                            |
| ------------------- | ------------------------------------------------------------------ |
| File Name           | `KTMBE25040170.exe`                                                |
| Post-Infection Path | `C:\Users\[username]\AppData\Roaming\Count.exe`                    |
| SHA256              | `116c096a488f53b298d3bac99942770afd3d791ae376534f050e6e4642c2fbb4` |
| File Size           | 1,464,320 bytes                                                    |
| File Type           | .NET PE32 executable (Mono)                                        |
| Purpose             | Info-stealer (PureLogs malware)                                    |


### Persistence Mechanism

<img width="1095" height="619" alt="image" src="https://github.com/user-attachments/assets/5a0086a9-efb0-4cbf-9229-32a20c20961f" />

| File Path | C:\Users\[username]\AppData\Roaming\Windows\Start Menu\Programs\Startup\Count.vbs |
| VBS Script Content | CreateObject("WScript.Shell").Run """C:\Users\[username]\AppData\Roaming\Count.exe""" |
| Purpose | Auto-launch PureLogs on every system startup |

## Process Tree

```plaintext
explorer.exe
└── user manually opens: invoice_10988.xz  (misleading ZIP file)
        └── invoice_10988.img  (ISO disk image)
            └── double-clicked by user / autorun (KTMBE25040170.exe)
                 └── Mounted or double-clicked by user
                    └── KTMBE25040170.exe 
                        ├── Copies itself to:
                        │   └── C:\Users\[username]\AppData\Roaming\Count.exe
                        ├── Writes persistence script:
                        │   └── C:\Users\[username]\AppData\Roaming\Windows\Start Menu\Programs\Startup\Count.vbs
                        │       └── Content:
                        │           CreateObject("WScript.Shell").Run """C:\Users\[username]\AppData\Roaming\Count.exe"""
                        └── Network connection:
                            └── TCP encrypted session to:
                                ├── 176.65.144[.]169:7702
                                └── mxcnss.dns04[.]com (C2)
```

## Dynamic Anlaysis of `KTMBE25040170.exe`


<img width="1165" height="338" alt="image" src="https://github.com/user-attachments/assets/667071a9-632d-4eaa-87e4-71e1f4f7b966" />


<img width="847" height="487" alt="image" src="https://github.com/user-attachments/assets/1c3880db-5cf2-46d3-bf3a-4760e5d09ab5" />


**Initial Execution**
Executed from:

"C:\Users\user\Desktop\KTMBE25040170.exe"

**Dropper behavior**:

 - Drops files in %AppData%\Roaming\:

   Count.exe

   Count.vbs (in Startup folder)

 - Drops or spawns secondary payload(s):

   %SAMPLEPATH%\116c096a488f53b298d3bac99942770afd3d791ae376534f050e6e4642c2fbb4.exe

   _Volumes_KTMBE25040170_KTMBE25040170.exe

**Persistence Mechanism**
 - Registers VBS script as a Startup item:

  `C:\Windows\System32\wscript.exe "C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Count.vbs"`

 - That script launches:

   `"C:\Users\user\AppData\Roaming\Count.exe"`
   
   This VBS–EXE combo is classic AgentTesla/Remcos-style persistence via Startup folder.

**Abuse of Legitimate Tools**

 - Uses InstallUtil.exe:

  `C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe`

 - Likely abused for DLL sideloading or installing payloads without UAC.

  Spawns Google Chrome with sandbox escape flags:

  --no-sandbox, --disable-gpu, --user-data-dir=Temp, --mute-audio

 - Indicates headless Chrome used for stealthy data exfiltration or C2 beaconing

 - Possibly being used to evade detection by hiding in a trusted process

**Network Activity**

 - Most domains are legitimate (Google/Microsoft), but one suspicious domain stands out:


  `mxcxnss.dns04.com` — 12/94 detections
   Registrar: PDR Ltd.
   Created: 2001-03-20
   Likely C2 endpoint

 - Common pattern for malware using Dynamic DNS (DynDNS) services.C2 exfil might be happening through Chrome.exe to evade network-based detection tools.

## PCAP Analysis

<img width="1095" height="714" alt="image" src="https://github.com/user-attachments/assets/c79db85c-d988-4c75-9ffc-9d1ad97bf606" />

<img width="1095" height="673" alt="image" src="https://github.com/user-attachments/assets/d6608b01-6d70-4e1d-a38b-af8f5a504fc5" />

The PCAP captures a multi-stage attack sequence that begins with the victim connecting to a suspicious external IP address (193.29.57.167), where a JavaScript payload is delivered—likely from a compromised or spoofed legitimate site. This JavaScript facilitates the download of a ZIP archive (invoice_10988.xz), which contains a disguised executable (KTMBE25040170.exe). Upon execution, this binary establishes an encrypted connection to a known NetSupport RAT command-and-control server at 194.180.191.168:443.

Shortly after the RAT establishes persistence, it receives a second-stage payload (a VBScript file named Count.vbs, part of the StealC family) from the C2 server. The script is designed to steal browser credentials and sensitive files, and it is installed to run at startup via the Windows Registry. Finally, the PCAP shows outbound FTP traffic from the victim to ftp.ercolina-usa.com, which resolves to 192.254.225.136, indicating that stolen data is being exfiltrated over FTP.

## Splunk Detection


```bash
source="rat.json"  "176.65.144.169" OR "10.5.12.22"
| rex field=_raw "\"ip\.src\":\s*\"(?<src_ip>[^\"]+)\""
| rex field=_raw "\"ip\.dst\":\s*\"(?<dst_ip>[^\"]+)\""
| eval pair=if(src_ip < dst_ip, src_ip . " → " . dst_ip, dst_ip . " → " . src_ip)
| stats count by pair
```
<img width="1263" height="390" alt="image" src="https://github.com/user-attachments/assets/a0076c98-48bb-4947-9c52-c7dbeb5443d2" />

To analyze IP communication patterns within the captured dataset, we extracted all occurrences of interactions between the internal IP 10.5.12.22 and any associated external or internal entities. The processed output reveals two significant communication pairs:

 - 10.5.12.1 → 10.5.12.22 occurred 4 times, indicating minimal local interaction.

 - 10.5.12.22 → 176.65.144.169 occurred 1846 times, suggesting persistent communication with  this external IP.

The high volume of traffic between 10.5.12.22 and 176.65.144.169 is indicative of a potential command-and-control (C2) channel. This level of frequency, especially when contrasted with local communication, warrants further inspection of the remote endpoint and the data being transmitted.

## MITRE ATT&CK Mapping 

| Phase                  | Technique (Tactic)                                      | ID        | Description                                                                 |
|------------------------|----------------------------------------------------------|-----------|-----------------------------------------------------------------------------|
| **Initial Access**     | Phishing: Spearphishing Attachment                       | T1566.001 | User received a crafted email with a malicious attachment (`invoice_10988.xz`). |
| **Execution**          | User Execution: Malicious File                          | T1204.002 | The user opened/extracted and executed the EXE from the disk image.        |
| **Defense Evasion**    | Obfuscated Files or Information                         | T1027    | The EXE was embedded within `.xz` and `.img` formats to evade detection.   |
| **Persistence**        | Boot or Logon Autostart Execution: Startup Folder       | T1547.001 | A VBS file (`Count.vbs`) was placed in the Startup folder for persistence. |
| **Command and Control**| Application Layer Protocol: Web Protocols (HTTPS/Other) | T1071.001 | Malware communicated over TCP to `176.65.144[.]169:7702` (possibly HTTPS-like). |
| **Discovery**          | System Information Discovery                            | T1082     | Likely performed by malware post-execution (common behavior).              |
| **Collection**         | Data from Local System                                  | T1005     | Malware likely collects data from infected system (inferred).              |
| **Exfiltration**       | Exfiltration Over C2 Channel                            | T1041     | Data may be exfiltrated via encrypted C2 channel.                          |


