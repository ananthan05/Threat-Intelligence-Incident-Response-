## Overview
Attack : AgentTesla Variant Using FTP

Date : 2024-12-04

An **AgentTesla variant** was distributed via **malspam** on December 4, 2024. The malware was delivered as a **RAR archive inside a `.TAR` email attachment**, which contained a **.NET executable**. The payload used **FTP (port 21)** for **data exfiltration**. 

The infrastructure used for command and control is a compromised FTP server hosted at `ftp.ercolina-usa[.]com`.

## Firstly download the infected files

`2024-12-04-IOCs-for-AgentTesla-variant-using-FTP.txt.zip`
`2024-12-04-AgentTesla-variant-malspam-1251-UTC.eml.zip`  
`2024-12-04-AgentTesla-variant-using-FTP.pcap.zip`   
`2024-12-04-AgentTesla-variant-malware.zip`

use the password `infected_20241204`

## Artifact Summary

## Artifact Summary

### 🔹 `2024-12-04-IOCs-for-AgentTesla-variant-using-FTP.txt.zip` (1.4 kB)
- Contains a text file listing **Indicators of Compromise (IOCs)**.
- Includes: hashes, IPs, domains, filenames.

### 🔹 `2024-12-04-AgentTesla-variant-malspam-1251-UTC.eml.zip` (832.3 kB)
- Archive contains the **original malspam email** in `.eml` format.
- Includes full email headers, body text, and attached `.TAR` file.

### 🔹 `2024-12-04-AgentTesla-variant-using-FTP.pcap.zip` (18.5 kB)
- Contains a **network packet capture (.pcap)** file from the infection scenario.
- Shows FTP-based data exfiltration to `ftp.ercolina-usa[.]com`.
- Includes a benign HTTPS request to `api.ipify[.]org` for IP checking.

### 🔹 `2024-12-04-AgentTesla-variant-malware.zip` (1.6 MB)
- Contains the actual **malware binary**: `TECHNICAL SPECIFICATIONS.exe`.
- The file is a **.NET-based AgentTesla variant**, extracted from the `.RAR` inside the `.TAR`.

## Initial IOC Extraction

<img width="1095" height="840" alt="image" src="https://github.com/user-attachments/assets/3086db3d-5efa-488c-850a-8cecc6bb5166" />

The file `2024-12-04-AgentTesla-variant-malspam-1251-UTC.eml.zip` contains the email

---

### Email Header Details

- **Received From IP**: `94.141.120[.]32`
  - Likely the **origin IP** of the sender. Could be a compromised server or bulletproof host.
  
- **From (Base64 Decoded)**: `Sertan ÖKÜR`
  - Impersonates a Turkish business contact to increase legitimacy.

- **Subject**: `PURCHASE QUOTATION`
  - A common social engineering lure used to bait recipients into opening attachments.

- **Date**: `Wed, 04 Dec 2024 12:51:16 +0000 (UTC)`
  - Time of email transmission; useful for correlation with endpoint or mail server logs.

- **Message-ID**: `<20241204045117.4A43A7B93A5F2488@acronas[.]com[.]tr>`
  - Spoofed domain resembling **acronis.com** (a known legitimate backup service).
  - The domain `acronas[.]com[.]tr` may be typosquatted or compromised.

- **Attachment Name**: `TECHNICAL SPECIFICATIONS.TAR`
  - Unusual file format in a business context.
  - Likely contains a nested archive (RAR) with an executable payload.

---

### Initial Indicators of Compromise (IOCs)

| Type           | Value                           | Description                         |
|----------------|----------------------------------|-------------------------------------|
| IP Address     | `94.141.120.32`                 | Sender IP address                   |
| From Name      | `Sertan ÖKÜR`                   | Spoofed sender name (Base64-decoded)|
| Email Subject  | `PURCHASE QUOTATION`            | Lure to prompt download             |
| Message-ID Domain | `acronas.com.tr`             | Likely spoofed or malicious domain  |
| Attachment Name| `TECHNICAL SPECIFICATIONS.TAR`  | Contains the AgentTesla payload     |

---
##  Malware Analysis Progress – AgentTesla Variant

<img width="1258" height="859" alt="image" src="https://github.com/user-attachments/assets/eb1b022b-3b4f-42c1-a720-9c2155517d25" />


#### 1. `TECHNICAL SPECIFICATIONS.TAR` Archive
- Extracted content: `TECHNICAL SPECIFICATIONS.exe`
- File type: `.NET PE32 executable`
- Original filename: `nCItN.exe`
- File info spoofed to appear benign:
  - **Description**: Pizza_Project
  - **Product Name**: Pizza_Project
  - **Version**: 1.0.0.0
- **Size**: 1.04 MB (1,096,704 bytes)
- **Date Modified**: 2024-12-04 12:02 AM

#### Suspicious Characteristics
- Generic file name and fake project metadata.
- Misleading archive format chain (`.tar` → `.rar` → `.exe`) to evade email filters.
- Embedded executable likely an AgentTesla variant.

---

###  2. Network Indicators (From VirusTotal Sandbox)

<img width="1372" height="672" alt="image" src="https://github.com/user-attachments/assets/e64b253e-40e8-4222-8d45-7044ddc77ab1" />


####  Contacted URLs:
- `https://api.ipify.org/` – IP-check service.
- `http://crt.sectigo.com/SectigoPublicCodeSigningCAR36.crt` – Certificate fetch.
- `http://www.microsoft.com/pki/certs/...` – Likely used for misleading legitimacy.

####  Malicious or Suspicious Domains:
| Domain                 | Detection | Notes                          |
|------------------------|-----------|--------------------------------|
| `ftp.ercolina-usa.com` | 7 / 94    | FTP server used for exfiltration |
| `ercolina-usa.com`     | 4 / 94    | Associated with the FTP host   |
| `api.ipify.org`        | 1 / 94    | Common IP-check service (benign usage, but can help profile infected host) |

---

### 3. Process tree

<img width="1197" height="616" alt="image" src="https://github.com/user-attachments/assets/d0f771ff-2c3c-4878-8835-13c9d00339e5" />

## Process Flow 

```plaintext
explorer.exe
└── TECHNICAL SPECIFICATIONS.exe
    ├── powershell.exe Add-MpPreference -ExclusionPath "C:\Users\<USER>\Desktop\TECHNICAL SPECIFICATIONS.exe"
    ├── newapp.exe (repeated under AppData\Roaming)
    ├── d1b068b8...exe (Downloads, Desktop, AppData)
    ├── program.exe
    └── conhost.exe / wmiprvse.exe (possible persistence)
```

Suspicious Behaviors

### PowerShell Defender Exclusion

`powershell.exe Add-MpPreference -ExclusionPath "<malware_path>"`
`pwsh.exe Add-MpPreference -ExclusionPath "<malware_path>"`

Tactic: Defense Evasion

Files Excluded:

 - TECHNICAL SPECIFICATIONS.exe

 - newapp.exe

 - program.exe

 - d1b068b8...exe

 - executable.exe

### Executables Launched From Suspicious Paths

| Path                         | File                                             |
| ---------------------------- | ------------------------------------------------ |
| `C:\Users\<USER>\Desktop\`   | `TECHNICAL SPECIFICATIONS.exe`, `executable.exe` |
| `C:\Users\<USER>\Downloads\` | `d1b068b8...exe`                                 |
| `%APPDATA%\Roaming\newapp\`  | `newapp.exe`                                     |
| `C:\Users\<USER>\Desktop\`   | `program.exe`                                    |

Malware is renamed and reused across user-writable directories.

### Abused Windows Binaries

| Binary                        | Purpose                                                    |
| ----------------------------- | ---------------------------------------------------------- |
| `powershell.exe` / `pwsh.exe` | Bypass Windows Defender                                    |
| `conhost.exe`                 | Console host, may be hijacked or spawned in malware chains |
| `wmiprvse.exe`                | May indicate WMI-based persistence                         |
| `svchost.exe`                 | Used in legitimate services; ensure context is valid       |


Use of PowerShell for Defender exclusions

Execution from Desktop, Downloads, AppData

Same hash with different file names

Persistence via repeated startup from %APPDATA%

<img width="1095" height="464" alt="image" src="https://github.com/user-attachments/assets/b3af89cc-c95d-43cc-8887-8d073433ffb7" />

## PCAP Analysis

<img width="1917" height="707" alt="image" src="https://github.com/user-attachments/assets/e0e30c5b-d3f6-46f7-b6ef-663d19209eef" />

##  FTP Exfiltration Observed

This section captures malicious exfiltration behavior using FTP from the infected host to a remote server.

### 🧾 Summary

- **Protocol**: FTP
- **Infected Host**: `10.12.4.101`
- **Exfiltration Server**: `192.254.225.136` (`ftp.ercolina-usa.com`)
- **Username Used**: `ben@ercolina-usa.com`
- **Password Used**: `nx@e0M~WkW&nJ`
- **Data Type**: `.html` / `.txt` files representing stolen data (likely browser profiles, credentials, etc.)

---

### FTP Session Details

| Frame | Command | Details |
|-------|---------|---------|
| 24    | `USER`  | `ben@ercolina-usa.com` (login initiation) |
| 27    | `PASS`  | `nx@e0M~WkW&nJ` (cleartext FTP password) |
| 30–49 | `PWD`, `TYPE I`, `PASV`, `STOR` | File uploads initiated |
| 50+   | `STOR`  | Exfiltrated files like:  
  - `PW_gary.strickman...html`  
  - `CO_Chrome_Default.txt`  
  - `CO_Edge Chromium_Default.txt`  
  - `KL_gary.strickman...html` |

---

### Indicators of Compromise

- **FTP Server**: `ftp.ercolina-usa.com` (`192.254.225.136`)
- **Protocol**: Plaintext FTP (unsecured)
- **Username**: `ben@ercolina-usa.com`
- **Exfiltrated Files**:
  - Credential-related: `PW_`, `CO_` (cookies), `KL_` (keylogger output)
  - Common format: `[TYPE]_[username]-[hostname]-[timestamp].ext`

---

###  Observations

- Multiple files uploaded via `STOR` command in passive mode (`PASV`)
-  FTP used with no encryption; credentials visible in packet capture
- Exfiltrated data mimics browser artifacts and keylogging results
- Email-style username indicates compromise of a legitimate FTP account or abuse of exposed credentials

## Detection in Splunk

```bash
source="Tesla.json" sourcetype="AgentTesla"
| rex "\\\"(?<ftp_raw>.*USER.*|.*PASS.*|.*STOR.*)\\\""
| rex field=ftp_raw "USER\s+(?<ftp_user>\S+)"
| rex field=ftp_raw "PASS\s+(?<ftp_pass>\S+)"
| rex field=ftp_raw "STOR\s+(?<ftp_filename>\S+)"
| search ftp_user=* OR ftp_pass=* OR ftp_filename=*
| table _time host ftp_user ftp_pass ftp_filename ftp_raw
```
This SPL query detects **FTP-based data exfiltration** by the AgentTesla malware using known FTP command patterns (`USER`, `PASS`, `STOR`) extracted from JSON logs.

<img width="1912" height="656" alt="image" src="https://github.com/user-attachments/assets/1cbac295-ef50-46a2-94a3-ecaf2a67afa8" />

Splunk indexes and displays **each raw log line as a distinct event** unless explicitly grouped. FTP commands (`USER`, `PASS`, `STOR`) are logged and stored **individually** in the malware’s telemetry or exfil JSON payload.

```bash
source="Tesla.json" sourcetype="AgentTesla"
| regex _raw="(?i)(ftp\.|192\.254\.225\.136|ercolina-usa\.com)"
| table _time host _raw
```

<img width="1666" height="822" alt="image" src="https://github.com/user-attachments/assets/18010add-64ef-49f8-8dbc-f291d046888f" />

- **DNS Resolution Activity**:
  - `ercolina-usa.com → 192.254.225.136` (A record)
  - `ftp.ercolina-usa.com → ercolina-usa.com` (CNAME)
  - Indicates active domain resolution for FTP command & control.

- **FTP Protocol Indicators**:
  - Presence of:
    - `ftp.request_raw`
    - `ftp.response_raw`
    - `ftp.response.code_raw`
    - `ftp.response.arg_raw`
    - `ftp.current-working-directory_raw`
  - Indicates successful FTP session and file transactions.


- These logs confirm **AgentTesla using FTP for data exfiltration**.
- DNS resolutions and subsequent FTP commands align with expected malware behavior.
- You can correlate this data with:
  - `USER` and `PASS` commands
  - `STOR` (file uploads)
  - Extracted filenames or keylog content
 
## MITRE ATT&CK Summary 

| Tactic             | Technique                           | ID         |
|--------------------|--------------------------------------|------------|
| Initial Access      | Spearphishing Attachment             | T1566.001  |
| Execution           | User Execution                       | T1204.002  |
| Defense Evasion     | PowerShell Defender Exclusion        | T1562.001  |
| Credential Access   | Input Capture (Keylogging)           | T1056.001  |
| Command & Control   | FTP for C2 Communication             | T1071.002  |
| Exfiltration        | Exfiltration Over FTP                | T1048.003  |


