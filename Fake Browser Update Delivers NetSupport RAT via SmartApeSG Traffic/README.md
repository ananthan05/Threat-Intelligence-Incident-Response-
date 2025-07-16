## Overview

Date:2025-03-26

Attack: SMARTAPESG TRAFFIC FOR FAKE BROWSER UPDATE LEADS TO NETSUPPORT RAT AND STEALC

SmartApeSG (aka ZPHP/HANEYMANEY) was delivered via a malicious JavaScript injected into a legitimate website. Victims saw a fake browser update prompt, triggering a JS dropper that downloaded a ZIP containing the NetSupport RAT. Once executed, the RAT connected to its C2 at 194.180.191.168:443, which responded with another ZIP carrying the StealC malware. StealC was side-loaded using a legitimate mfpmp.exe to run a malicious rtworkq.dll, enabling data exfiltration via HTTP POST to 193.239.237.40.

## First Download the associated files

`2025-03-26-IOCs-for-SmartApeSG-fake-browser-update-leads-to-NetSupport-RAT-and-StealC.txt.zip`

`2025-03-26-SmartApeSG-leads-to-NetSupport-RAT-and-StealC.pcap.zip` 

`2025-03-26-malware-for-NetSupport-RAT-and-StealC.zip`   

2025-03-26-IOCs-for-SmartApeSG-fake-browser-update-leads-to-NetSupport-RAT-and-StealC.txt.zip
 - ZIP file containing a plain-text list of IOCs (hashes, domains, IPs, file names) related to the SmartApeSG → NetSupport RAT → StealC attack chain.

2025-03-26-SmartApeSG-leads-to-NetSupport-RAT-and-StealC.pcap.zip
 - Compressed PCAP capture showing the full infection traffic: from fake browser update to NetSupport RAT beaconing and StealC exfiltration.

2025-03-26-malware-for-NetSupport-RAT-and-StealC.zip
 - Password-protected archive containing actual malware samples (JS loader, NetSupport RAT, StealC DLL) used in the attack chain for static/dynamic analysis.


## Summary of the Attack Chain

1. User visits compromised site `freepetchipregistry[.]com`.
2. Malicious JS (`lib.css.js`) from `layardrama21[.]top` fakes a browser update.
3. Drops large JS file (`Edge 50728.js`) that downloads a ZIP from `sleepwellmagazine[.]com`.
4. Extracted payload installs NetSupport RAT.
5. RAT connects to C2 and pulls another ZIP (`misk.zip`) containing StealC.
6. StealC is side-loaded via legitimate `mfpmp.exe` and malicious DLL `rtworkq.dll`.
7. Credentials and sensitive data exfiltrated via HTTP POST to `193.239.237[.]40`.

### Initial Access IOCs

| Type                  | Value                                                                                   | Description                          |
|-----------------------|------------------------------------------------------------------------------------------|--------------------------------------|
| Compromised Site      | `hxxps://www.freepetchipregistry[.]com/`                                                | Legitimate but injected              |
| JS Loader URL         | `hxxp://layardrama21[.]top/upload/lib.css.js`                                           | Malicious SmartApeSG JS              |
| Additional Assets     | `layardrama21[.]top/upload/index.js`, `.png`, `.css`                                    | Fake browser update website assets   |
| Malicious JS File     | `Edge 50728.js`                                                                         | Fake update installer (JS payload)   |
| SHA256 (Edge JS)      | `68c6411cc9afa68047641932530cf7201f17029167d4811375f1458cae32c7bd`                      | Obfuscated script                    |
| Payload Download URL  | `hxxps://sleepwellmagazine[.]com/2mprext.zip?&track=608`                                | Delivers NetSupport RAT              |
| ZIP SHA256            | `4c048169e303dc3438e53e5abdec31b45b5184f05dc6d1bc39e18caa0e4a3f3e`                      | NetSupport RAT payload               |

<img width="1095" height="569" alt="image" src="https://github.com/user-attachments/assets/1326bec7-73f0-489f-8766-22d70bca2af2" />

<img width="1095" height="569" alt="image" src="https://github.com/user-attachments/assets/1b4b5c32-536e-4be0-bb1b-12e51368c603" />


---

### Processing Stage IOCs

| Type                  | Value                                                                                   | Description                          |
|-----------------------|------------------------------------------------------------------------------------------|--------------------------------------|
| NetSupport C2         | `hxxp://194.180.191[.]168/fakeurl.htm` (port 443)                                       | RAT beaconing                        |
| Second-stage ZIP      | `C:\Users\Public\mint.zip`                                                               | Contains StealC malware              |
| ZIP SHA256            | `45085f479b048dd0ef48bef5b8c78618113bc19bde6349f61d184cdf4331bff0`                      | StealC delivery ZIP                  |
| Legitimate Binary     | `mfpmp.exe`                                                                             | Used for DLL side-loading            |
| SHA256 (mfpmp.exe)    | `ff7e8ccc41bc3a506103bdd719a19318bf711351ac0e61e1f1cf00f5f02251d5`                      | Clean Media Foundation binary        |
| Malicious DLL         | `rtworkq.dll`                                                                           | Actual StealC DLL payload            |
| SHA256 (bloat DLL)    | `2bc17933b9dd18627610a509736f8cf6c149338be5f6bd3d475ea22d0d914ae3`                      | Inflated with junk                   |
| SHA256 (clean DLL)    | `1ae8f9d618d9b5c7ef474b815a857afebbb9e06b54bdf13726280942501cb48b`                      | Deflated StealC payload              |

---

###  Exfiltration & Follow-Up IOCs

| Type                  | Value                                                                                   | Description                          |
|-----------------------|------------------------------------------------------------------------------------------|--------------------------------------|
| Exfil Domain          | `hxxp://193.239.237[.]40/`                                                               | StealC C2                            |
| POST URL              | `hxxp://193.239.237[.]40/52a50518b868057e.php`                                          | Victim-specific data exfil path      |
| Supporting DLLs       | `/sqlite3.dll`, `/freebl3.dll`, `/mozglue.dll`, `/nss3.dll`, etc.                      | Downloaded at runtime by StealC      |
| Host Path             | `/ca8e51ecb2d000b2/` prefix used for dynamic DLLs                                       | Changes per infection                |


<img width="1095" height="570" alt="image" src="https://github.com/user-attachments/assets/f8924c21-f958-4ad4-9ed7-52c2163bd8f5" />

<img width="1095" height="569" alt="image" src="https://github.com/user-attachments/assets/9d851930-51bc-45e0-b95a-30b046574e7f" />


---

## Process Tree

```plaintext
explorer.exe
└── Edge 50728.js                    ← Malicious JS Loader from fake update site
    └── powershell.exe / wscript.exe
        └── [Download] 2mprext.zip  ← Contains NetSupport RAT
        └── client32.exe            ← Executes NetSupport RAT
            ├── Reads config: client32.ini
            ├── Loads DLLs: AudioCapture.dll, HTCCTL32.DLL, etc.
            └── C2: 194.180.191[.]168
                └── [Download] mint.zip  ← Contains StealC
                    └── mfpmp.exe        ← Legit signed binary (used for sideloading)
                        └── Loads: rtworkq.dll
                            └── Executes StealC malware
                                └── Exfil to: 193.239.237[.]40 (HTTP POST)
```

## Analysis of the executable files

### Client32.ini

<img width="948" height="832" alt="image" src="https://github.com/user-attachments/assets/8d5a8c6d-3a50-4e77-bd38-806ab8f8ae85" />

The malicious JavaScript file, when double-clicked by the user, automatically downloads a ZIP archive containing `client32.exe` and extracts it. Upon execution, `client32.exe` uses its configuration file (`client32.ini`) to establish a connection with the NetSupport RAT command-and-control (C2) server at `194.180.191.168`. From this C2, additional payloads are silently delivered to the infected host, enabling further stages of exploitation such as data theft and remote access.

### mfpmp.exe

<img width="395" height="225" alt="image" src="https://github.com/user-attachments/assets/dc9e5d54-2e79-4311-b94d-3e956884d4f1" />

The following DLLs were loaded during execution:

- `RTWorkQ.DLL` ← **Malicious payload (StealC)**
- Other system DLLs: `MFCORE.dll`, `MFPlat.DLL`, etc.

The presence of `RTWorkQ.DLL` among loaded modules indicates that the legitimate executable `mfpmp.exe` was abused to sideload a malicious DLL — a well-known stealthy execution method.

### rtworkq.dll

<img width="672" height="212" alt="image" src="https://github.com/user-attachments/assets/20216b8c-3cdb-4f22-93a6-ef0b7a2a6402" />


- **Loaded via DLL sideloading** by `mfpmp.exe`
- Connects to: `http://193.239.237.40/`
- Downloads supporting `.dll` files for browser data access and exfiltration
- Performs:
  - Credential theft (browser, cookies, autofill)
  - Screenshot capture
  - File theft
  - HTTP POST-based data exfiltration

This DLL is the **main malicious component** and its C2 interaction confirms active data theft.

## PCAP analysis

<img width="1095" height="524" alt="image" src="https://github.com/user-attachments/assets/a918bcc3-e3ee-4a11-88fb-0fe7ba4593e1" />


This network traffic (from PCAP) captures a full infection chain starting with a **fake browser update**, leading to **NetSupport RAT** and finally to the **StealC infostealer**.

---

### 1. SmartApeSG Traffic (Initial Access)
| Timestamp         | Destination Host              | Port | Notes                                      |
|------------------|-------------------------------|------|--------------------------------------------|
| 2025-03-26 14:45 | www.freepetchipregistry.com    | 443  | **Legitimate but compromised website**     |
| 2025-03-26 14:45 | layardrama21.top               | 443  | **Injected JS from SmartApeSG** — fake update site |
| 2025-03-26 14:45 | sleepwellmagazine.com          | 443  | **Hosts malicious ZIP (2mprext.zip)**      |

**Purpose:**  
Injected JS on a compromised pet registry site (`freepetchipregistry[.]com`) redirects the victim to `layardrama21[.]top` and then downloads a malicious JavaScript payload, which leads to `2mprext.zip` from `sleepwellmagazine[.]com`.

---

### 2. NetSupport RAT C2 Communication

| Timestamp         | Destination IP       | Port | Host              | Info                 |
|------------------|----------------------|------|-------------------|----------------------|
| 2025-03-26 14:46 | 194.180.191.168       | 443  | NetSupport C2     | POST /fakeurl.htm    |

**Purpose:**  
Once `client32.exe` is executed, it reads from `client32.ini` and connects to the C2 server at `194.180.191.168:443`. This is the **NetSupport RAT** post-infection beaconing. It uses HTTPS over port 443 but communicates via **HTTP POST requests to a fake HTML endpoint** (`fakeurl.htm`).

---

### 3. StealC Traffic (Data Exfiltration)

| Timestamp         | Destination IP       | Port | Host              | Info                                    |
|------------------|----------------------|------|-------------------|-----------------------------------------|
| 2025-03-26 14:50 | 193.239.237.40        | 80   | StealC C2         | POST /52a50518b86805... (dynamic path)  |
| 2025-03-26 14:52 | 193.239.237.40        | 80   | StealC C2         | GET various `*.dll` files               |

**Purpose:**  
StealC is loaded via `mfpmp.exe` and the malicious `rtworkq.dll`. The malware exfiltrates data using **HTTP POST requests** to `193.239.237.40`. It also **downloads additional DLL dependencies** (like `nss3.dll`, `sqlite3.dll`, etc.) to function correctly — all hosted on the same C2.

---

| Tactic                  | Technique                         | ID         | Description                                                      |
|------------------------|-----------------------------------|------------|------------------------------------------------------------------|
| Initial Access         | Drive-by Compromise               | T1189      | User visits compromised website with injected SmartApeSG script. |
| Execution              | Malicious Script                  | T1059.007  | JavaScript file auto-executes and downloads payload.             |
| Execution              | User Execution                    | T1204.002  | Victim double-clicks the JS file or extracted executable.        |
| Persistence            | DLL Side-Loading                  | T1574.002  | Legit `mfpmp.exe` used to sideload `rtworkq.dll` (StealC).       |
| Command & Control      | Application Layer Protocol: HTTPS | T1071.001  | NetSupport RAT connects to C2 at `194.180.191.168` over HTTPS.   |
| Defense Evasion        | Obfuscated Files/Information      | T1027      | Inflated StealC DLL to evade detection.                          |
| Defense Evasion        | Masquerading                      | T1036      | Uses Google-like folder names and benign EXE as a loader.        |
| Collection             | Input Capture                     | T1056.001  | StealC likely captures credentials or keystrokes.                |
| Exfiltration           | Exfiltration Over C2 Channel      | T1041      | StealC exfiltrates via repeated HTTP POSTs to attacker server.   |
