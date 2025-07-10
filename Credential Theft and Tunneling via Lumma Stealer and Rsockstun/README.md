## Overview

Attack: Lumma Stealer Infection with Rsockstun Malware

Date Observed: 2025-07-02

**Source:** [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net)

On July 2, 2025, a Windows host was observed downloading and executing malicious cracked software that led to a two-stage malware infection. The initial payload was Lumma Stealer, an info-stealer designed to exfiltrate browser credentials. Shortly after, a second malware named Rsockstun was deployed to establish a remote SOCKS5 proxy backdoor, enabling attackers to pivot or proxy through the infected system

This report provides a timeline of the attack, threat intelligence insights, indicators of compromise (IOCs), MITRE ATT&CK mapping, and defensive recommendation

## Downloading the Investigation Materials


- **[2025-07-02-IOCs-from-Lumma-Stealer-with-Rsockstun-malware.txt.zip](https://www.malware-traffic-analysis.net/2025/07/02/2025-07-02-IOCs-from-Lumma-Stealer-with-Rsockstun-malware.txt.zip)**  
  — Contains **Indicators of Compromise (IOCs)** extracted from the infection.

- **[2025-07-02-Lumma-Stealer-infection-with-Rsockstun-malware.pcap.zip](https://www.malware-traffic-analysis.net/2025/07/02/2025-07-02-Lumma-Stealer-infection-with-Rsockstun-malware.pcap.zip)**  
   — Complete **PCAP (network capture)** of the infection traffic.

- **[2025-07-02-malware-and-artifacts-from-the-infection.zip](https://www.malware-traffic-analysis.net/2025/07/02/2025-07-02-malware-and-artifacts-from-the-infection.zip)**  
  Includes **malware binaries**, execution artifacts, and logs from the infected system.

  Use the password `infected_20250702` during extraction

  ## Initial Infection Vector

The infection campaign observed on **2025-07-02** used social engineering to trick users into downloading fake cracked software packages hosted on suspicious platforms.

###  Infection Lures

Victims were enticed to download one of the following:

1. `FB Limiter Pro Cracked Full Version`
2. `4K Video Downloader v6.1.3.2079 Setup Cracks Full Version`

These were delivered as `.7z` archives, protected with the password: `8290`. The archives contained `.exe` files that acted as droppers for the **Lumma Stealer** malware.

---

###  Download Path Chains

#### FB Limiter Pro Variant
- `https://www.facebook.com/media/set/?set=a.3164653780507169`
- `https://urluss.com/2wyPix`
- `https://media.cloud839v3[.]cyou/fb+limiter+pro+cracked+full+version.zip`
- `https://arch2.kot3jsd[.]my/bridge/u/lAoEVF3Q00zZLYmbh6o9om5J/fb%20limiter%20pro%20cracked%20full%20version.zip`

####  4K Video Downloader Variant
- `https://www.facebook.com/media/set/?set=a.331497049494729`
- `https://8diaprinzpistpe.blogspot.com/?download=2wEjP9`
- `https://vittuv.com/2wEjP9`
- `https://media.cloud839v3[.]cyou/4K+Video+Downloader+v6.1.3.2079Setup+Cracks+full+version.zip`
- `https://arch2.kot3jsd[.]my/bridge/u/loD59okQBxMndtxaeGW22GoK/4K%20Video%20Downloader%20v6.1.3.2079Setup%20Cracks%20full%20version.zip`

---

### Archive and Executable Details

| File Name |  Description |
|-----------|-------------|
| `fb limiter pro cracked full version.7z` | 7-Zip archive (password: `8290`) |
| `4K Video Downloader v6.1.3.2079Setup Cracks full version.7z` |  7-Zip archive (password: `8290`) |
| `*.exe` inside both archives | Self-extracting installer for Lumma Stealer |

---

### Execution Flow

1. Victim downloads and extracts `.7z` file 
2. Runs the `.exe` file, which:
   - Drops a `.bat` file (`Johnson.pot.bat`)
   - Extracts a `.cab` archive (`Theology.pot`)
   - Drops a fake AutoIt3.exe (`Batman.com`)
   - Deobfuscates and executes Lumma `.a3x` binary

---

### Dropped Artifacts

| File | Description |
|------|--------|
| `Johnson.pot.bat` |  Obfuscated batch script |
| `Theology.pot` |  CAB archive |
| `Batman.com` |  Dropped AutoIt3 executable |
| `.a3x` payload |  Lumma Stealer AutoIt script |

---

### Lumma Stealer Command & Control (C2)

- Domain: `ponqcf.top`
- IP Address: `144.172.115.212`
- Port: `443`
- Protocol: TLSv1.3 (HTTPS)

---
# Behavioral Analysis

After uploading the `fb limiter pro cracked full version.exe-deflated` onto virustotal we can see it is flagged malicious and under the process created we can see the various files created from this executable file


![image](https://github.com/user-attachments/assets/b7498f16-d550-4094-bcd4-0f54aca52d5c)


> Based on sandbox analysis from VirusTotal  
> Hash: `8fa8b03392bcce6657b3d14b87e79252862fdb8d2799b12b98656a7f4b67a279`

##  File Creation & Execution Chain

Upon execution, the malicious EXE (`fb limiter pro cracked full version.exe`) follows a structured multi-stage dropper behavior.

### Step-by-Step Chain:

```text
[1] fb limiter pro cracked full version.exe
     |
     ├── Copies: Johnson.pot → Johnson.pot.bat
     |       ↳ CMD: copy Johnson.pot Johnson.pot.bat & Johnson.pot.bat
     |
     ├── Executes: Johnson.pot.bat
     |       ↳ BAT script includes:
     |           - Extraction: extrac32 /Y Theology.pot *.*
     |           - Execution: Batman.com p
     |
     ├── Extracts from: Theology.pot
     |       ↳ Contains additional `.pot` files and payloads
     |
     └── Executes: Batman.com
             ↳ Custom AutoIt3.exe clone
             ↳ Runs: `.a3x` payload (Lumma Stealer script logic)
```

#  Lumma Stealer Execution via `.a3x` AutoIt Script

##  What Is `.a3x`?

- `.a3x` is a **compiled AutoIt v3 script** (binary bytecode).
- Not standalone: must be run via `AutoIt3.exe` or its clone (e.g., `Batman.com`).
- Typically created via:
  ```sh
  Aut2Exe.exe /in malware.au3 /out malware.a3x

## Network Behavior:
Once .a3x is executed:

Steals browser passwords, cookies, autofill, wallets

Sends to C2: ponqcf.top:443 via HTTPS

Downloads Rsockstun (SOCKS5 proxy)

# PCAP Analysis

![image](https://github.com/user-attachments/assets/b1d6a211-59a5-4153-b9f3-2f14eb0618d2)

Initial TLS Handshakes to ponqcf.top (Lumma Stealer C2):

 - Multiple TLSv1.3 Client Hello messages are observed from the infected host (10.7.2.101) to 144.172.115.212, which resolves to ponqcf.top.

 - These occur within the first ~26 seconds of the infection.

 - This pattern of repeated TLS handshakes is typical of Lumma Stealer attempting to establish secure communication with its C2 server to exfiltrate stolen data.

 - These connections are encrypted, so no payloads are visible in plaintext HTTP.

HTTP GET Request for soks.exe from 86.54.25.50:

 - At 26.38 seconds, the host downloads soks.exe over plaintext HTTP.

 - This download indicates a second-stage payload — specifically, Rsockstun, a tunneling/backconnect malware used for post-exploitation access.

 - Since this is fetched via cleartext HTTP, it would be easily detectable by a proxy, firewall, or Suricata rule.

TLS Handshake to eset-blacklist.net:

 - Later (350s), another TLSv1.3 handshake is made to 185.117.90.230, SNI: eset-blacklist.net.

 - This is likely Rsockstun connecting to its C2 to set up a SOCKS tunnel.

 - The use of TLS here hides the nature of commands or traffic sent over the tunnel, but the SNI reveals the domain.



## Malware Functionality

### Lumma Stealer

- **Method**: AutoIt `.a3x` executed by `Batman.com`
- **C2**: `ponqcf.top` (via TLS)
- **Observed Behavior**:
  - Collects credentials, autofill, crypto wallets
  - Anti-sandbox — does not exfiltrate in VM-only runs
  - Waits for real environment triggers before beaconing
- **Files Involved**:
  - `payload.a3x`, `Batman.com`, `Johnson.pot(.bat)`

### Rsockstun (aka rockston)

- **Method**: Downloaded via HTTP GET request to `/soks.exe`
- **C2**: `eset-blacklist.net` (via TLS)
- **Function**:
  - Establishes reverse SOCKS proxy tunnel
  - Enables attacker persistence, lateral movement
  - Used as post-infection backdoor
- **Files Involved**:
  - `soks.exe`
 
# Simulated Incident Detection

##  What Was Simulated

A user executed a suspicious cracked application:  
**`fb limiter pro cracked full version.exe`**

Shortly after:
- The file dropped and executed a batch script (`Johnson.pot.bat`)
- An AutoIt interpreter (`Batman.com`) was silently launched
- A compiled AutoIt script (`payload.a3x`) began executing
- Multiple unknown `.pot` files appeared in `AppData\Temp\`

Endpoint behavior showed:
- Repeated outbound TLS connections to **ponqcf.top**
- A suspicious HTTP GET to **86.54.25.50/soks.exe**
- Later beaconing to **eset-blacklist.net** over TLS

---

## What Happened

1. **Initial Execution**
   - `fb limiter pro cracked full version.exe` executed by user
   - Dropped `Johnson.pot` → copied to `Johnson.pot.bat` and executed
   - The `.bat` file launched `Batman.com` (a renamed AutoIt3 interpreter)

2. **AutoIt Loader Activity**
   - `Batman.com` executed `payload.a3x` (compiled AutoIt script)
   - Payload initiated network connections to **ponqcf.top**

3. **Lumma Stealer Behavior**
   - TLS connections suggest active beaconing to C2
   - No credentials exfiltrated in sandbox—but Lumma is known to target:
     - Browser passwords, autofill data
     - Crypto wallets
     - Stored cookies

4. **Rsockstun Activity**
   - `payload.a3x` or another dropped component made HTTP GET request to:
     - `http://86.54.25.50/soks.exe`  
   - Downloaded and ran a second-stage proxy/tunneling malware
   - Established TLS connection to **eset-blacklist.net**
   - Behavior consistent with **Rsockstun**, which provides SOCKS tunneling for covert access


#  Incident Response: Lumma Stealer + Rsockstun (2025-07-02)

##  Readiness Measures in Place

- **EDR & SIEM** actively monitoring user endpoints and network flows.
- Analysts trained to detect:
  - Execution of AutoIt-based malware (.a3x)
  - Dropper behavior from misleading executables
  - Proxy malware like Rsockstun
- DNS filtering enabled, alerting on suspicious TLDs such as `.top` and `.xyz`.
- File hash matching and sandbox detonation workflows were in place.

---

## Detection Phase Overview

**Initial Observations:**
- Outbound TLS connections to `ponqcf[.]top` (Lumma C2).
- HTTP request to `86.54.25.50/soks.exe` → indicative of Rsockstun download.
- Analysis of dropper file: `fb limiter pro cracked full version.exe` revealed the following:

```text
 fb limiter pro cracked full version.exe (dropper)
├── Johnson.pot → Obfuscated batch script
├── Johnson.pot.bat → Renamed batch, executed by dropper
├── Theology.pot → CAB archive with embedded payloads
├── Batman.com → Renamed AutoIt3 interpreter
└── payload.a3x → Lumma Stealer compiled AutoIt script
```

**Additional Indicators:**
- PCAP logs show clear staging:
  - TLS Handshakes → `ponqcf.top`
  - Plain HTTP → GET `/soks.exe`
- VirusTotal confirmed Lumma Stealer hash.
- Suspicious activity from `AutoIt3.exe` running under renamed instance (`Batman.com`).

---

## Isolation Actions

- Disconnected infected host (`10.7.2.101`) from the internal network.
- Blocked following IOCs:
  - Domains: `*.top`, `ponqcf.top`
  - IPs: `144.172.115.212`, `86.54.25.50`
  - URIs: `/soks.exe`
- Stopped and removed:
  - Any unknown scheduled tasks
  - `Batman.com`, `payload.a3x`, and related files under `%Temp%`, `%AppData%`
  - Registry autoruns linked to dropper

---

## Clean-up Operations

- Manually deleted all dropped files:
  - `.pot`, `.bat`, `.a3x`, and interpreter binaries
- Investigated:
  - Auto-start registry keys
  - Scheduled tasks added during infection
- Exported:
  - PowerShell execution logs
  - Network connection history

---

##  Host Recovery

- Re-imaged system using secure, clean baseline.
- Restored user files from backups after multi-engine scanning.
- Performed password resets across affected user accounts.
- Confirmed:
  - No connections to blocked IOCs post-cleanup
  - AutoIt interpreters removed across environment

---

##  Takeaways and Improvements

- Restrict execution of `.a3x` and similar compiled scripting files.
- Enhance DNS-layer controls:
  - Auto-block known malicious TLDs
  - Alert on C2 connection attempts from non-browser processes
- Deploy behavioral YARA/Sigma rules:
  - AutoIt execution from temp paths
  - HTTP GETs to untrusted IPs by non-browser processes
- Educate users about:
  - Dangers of cracked software downloads
  - Recognizing fake installer and dropper lures
