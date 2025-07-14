## Overview
Date - 2025-01-30

**Source:** [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net)

On January 30, 2025, a phishing email delivered a malicious RAR archive containing an EXE payload, which, upon execution, infected the host with XLoader malware,a successor to FormBook. The malware established persistence, performed data theft, and exfiltrated credentials and system data to multiple C2 domains over HTTP.

## Download the investigation files

`2025-01-30-IOCs-for-XLoader-infection.txt.zip`     
`2025-01-30-XLoader-infection-traffic.pcap.zip`     
`2025-01-30-email-and-malware-files-from-XLoader-infection.zip`     

use password `infected_20250130` 


2025-01-30-email-and-malware-files-from-XLoader-infection.zip

 - Contains the malicious email, malware sample, and supporting artifacts.

2025-01-30-IOCs-for-XLoader-infection.txt.zip

 - Text file with IOCs: domains, file hashes, persistence paths, etc.

2025-01-30-XLoader-infection-traffic.pcap.zip

 - Captured network traffic during the infection.

## Initial Infection Vector

<img width="1095" height="615" alt="image" src="https://github.com/user-attachments/assets/ae929be1-d607-40b5-8a02-b46bb583ac64" />

### Phishing Email

- **Sender**: brij@saffronshipping[.]com (Brij Mohan Vashist)
- **Subject**: RE;ADVANCE TT SLIP // December/January SOA PAYMENT
- **Attachment**: `Payment Slip.rar` (~729 KB)

### Inside the RAR

- **Extracted file**: `Payment Slip.exe`
- **Type**: Windows PE executable
- **Size**: ~850 KB
- **Original name**: bHgy.exe
- **No digital signature**

### Social Engineering

- Fake invoice/payment request
- Legit-looking sender info with phone, address, and website
- Tries to trick the victim into opening a disguised `.exe` file

###  Infection Trigger

- User manually extracts and runs the `.exe`
- No exploit — purely social engineering-based


## Dynamic Behavior Analysis – Payment Slip.exe


<img width="1250" height="644" alt="image" src="https://github.com/user-attachments/assets/36fb5e62-0e0a-46c8-be2f-5aba5d011417" />


### Contacted Domains

The executable contacted multiple suspicious and known domains:

###  Legitimate (likely used to blend traffic):
- `microsoft.com`
- `sectigo.com`
- `crt.sectigo.com`
- `res.public.onecdn.static.microsoft`

###  Suspicious / Malicious (associated with XLoader C2):
- `physicsbrain.xyz`
- `bydotoparca.net`
- `www.physicsbrain.xyz`
- `www.bydotoparca.net`

**Inference**: Attempts to contact `.xyz` domains is a hallmark of XLoader’s command-and-control (C2) behavior.

---

<img width="553" height="602" alt="image" src="https://github.com/user-attachments/assets/69f14bd6-2a4c-4e02-a3c9-05b5b37590a1" />


### Process Tree (Execution Chain)

### Primary Executable Observed:

Instruction N.7376.exe

### Behavior Summary:
- Spawned multiple processes from `%USERPROFILE%\Desktop` and `%SAMPLEPATH%`
- Interacted with system processes such as:
  - `wmiadap.exe`, `wmiprvse.exe`, `explorer.exe`
- Dropped/ran additional files in unexpected paths:
  - `C:\Program Files\Reference Assemblies\task hotel.exe`
  - `C:\Program Files\Microsoft Analysis Services\in major put.exe`
  - `C:\Windows\SysWOW64\secinit.exe`

These randomly named executables and abnormal paths strongly indicate payload deployment and persistence behavior.

---
- Multiple executions of the sample from various locations suggest **evasion and redundancy** tactics.
- Writes to `SysWOW64` and `Program Files` hint at **privilege abuse or persistence** setup.
- Uses `wmiadap.exe` and `wmiprvse.exe` to potentially gather system info or evade detection.

---
This dynamic behavior confirms that:
- The sample initiates outbound connections to known **XLoader C2 domains**
- It **injects or spawns multiple executables** with deceptive names
- It uses **legitimate Windows binaries** for evasion (living-off-the-land)
- The file exhibits classic **malware indicators** consistent with XLoader operations

 This supports the classification of `Instruction N.7376.exe` as a **malicious loader with C2 capabilities** and potential data-stealing behavior.

## Persistence Mechanism

<img width="1095" height="783" alt="image" src="https://github.com/user-attachments/assets/37f73980-d3cf-4c9b-aed8-3349a75a7420" />

XLoader ensures persistence via Windows Registry Run key:

Registry Path:
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

Executable Path:
C:\Program Files (x86)\Opera\H1zxxm.exe

This allows the malware to relaunch on each user login, making it stealthy and long-lasting unless removed manually or by antivirus tools.

## Analyzing pcap file

Opened the pcap file 

```
(http.request or tls.handshake.type eq 1) and !(ssdp
```
shows all HTTP requests and TLS Client Hello packets (the start of HTTPS sessions), while excluding noisy SSDP traffic. It helps focus on web communication, both in cleartext and encrypted form, useful for spotting malware communication or C2 activity.

<img width="1918" height="747" alt="image" src="https://github.com/user-attachments/assets/e28dfa2a-59b1-4d33-afa4-bd594b569090" />

### Malicious Indicators from PCAP
Repeated POST requests to /s3u9/ and similar paths on suspicious domains — common XLoader C2 behavior.

Domains like bydotoparca.net, car-select.online, topked.top use shady TLDs (.net, .online, .top) often linked to malware infra.

POSTs carry encoded payloads (~4.3 KB) — unusual for normal web traffic.

No typical browser headers/User-Agent — likely sent by a malware implant.

Multiple C2 fallback domains contacted, indicating redundancy and evasion.

Timing and size suggest beaconing or data exfiltration behavior.

## Detection in Splunk

```bash
source="xloader.json" sourcetype="Xloader" source="xloader.json" sourcetype="Xloader"
| rex "\"http\.host\":\s*\"(?<host>[^\"]+)\""
| stats count by host
| sort -count
```

<img width="1918" height="925" alt="image" src="https://github.com/user-attachments/assets/737a9db0-0dee-4063-8de9-13361c8c35ca" />


Multiple known XLoader domains identified, including:

 - bydotoparca.net, car-select.online, topked.top

High volume of POST traffic to these domains observed in PCAP

Suspicious TLDs like .xyz, .top, .online frequently used

Traffic pattern suggests:

 - Initial beaconing

 - Potential data exfiltration or bot instructions

---

```bash
| rex "\"ip\.src\":\s*\"(?<src_ip>[^\"]+)\""
| rex "\"ip\.dst\":\s*\"(?<dest_ip>[^\"]+)\""
| stats count by src_ip dest_ip 
| sort -count
```

<img width="1912" height="928" alt="image" src="https://github.com/user-attachments/assets/fdf7555b-36b6-4fa2-8fbf-ec8e2a239eca" />

## C2 Communication Pattern 

- **Infected Host:** `10.1.30.242`
- **Connected to Known XLoader C2s:**
  - `bydotoparca.net` → `85.159.66.93`
  - `car-select.online` → `31.31.196.17`
  - `topked.top` → `192.64.118.221`
- **Volume of Connections:**
  - Over 500 POST requests per host suggest persistent beaconing.

These IPs match the dynamic analysis and PCAP payload, confirming malware activity and C2 interaction.



## Timeline of Events

| Time (UTC)       | Event                                                                |
| ---------------- | -------------------------------------------------------------------- |
| 2025-01-29 23:52 | Phishing email sent from `saffronshipping[.]com`                     |
| 2025-01-30 00:52 | Email received by victim                                             |
| Shortly after    | User opens `Payment Slip.rar` and executes EXE                       |
| + Few seconds    | Malware installs itself to `C:\Program Files (x86)\Opera\H1zxxm.exe` |
| + Few seconds    | HTTP POST traffic initiated to multiple C2 domains                   |
| + Minutes        | System data, credentials, and possibly keystrokes exfiltrated        |


## MITRE ATT&CK Tactics & Techniques

| **Tactic**             | **Technique**                                | **ID**        |
|------------------------|----------------------------------------------|---------------|
| Initial Access         | Spearphishing Attachment                     | T1566.001     |
| Execution              | User Execution (Malicious File)              | T1204.002     |
| Persistence            | Registry Run Keys / Startup Folder           | T1547.001     |
| Command and Control    | Application Layer Protocol (HTTP)            | T1071.001     |
| Exfiltration           | Exfiltration Over C2 Channel                 | T1041         |
| Defense Evasion        | Obfuscated Files or Information              | T1027         |

