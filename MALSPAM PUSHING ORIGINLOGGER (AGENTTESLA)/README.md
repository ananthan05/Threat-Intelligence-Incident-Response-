##  Malware Case Study – June 10, 2024

**Date:** June 10, 2024  
**Source:** [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net)

---

###   Theme:
AgentTesla (OriginLogger variant) infection via malicious `.img` attachment in phishing email.  
Observed using PCAP network traffic, file artifacts, and registry persistence.

---

###  Step 1: Download and Extract Investigation Files

Downloaded from the site:

- `2024-06-10-Agent-Tesla-traffic.pcap`
- `2024-06-10-Agent-Tesla-email.eml`
- `Agent-Tesla-sample.exe`
- `Agent-Tesla-persistence-registry-dump.reg`

Unzipped using password: `infected_20240610`

---

### Step 2: Network Traffic Analysis – AgentTesla (OriginLogger Variant)

**PCAP File:**  
`2024-06-10-Agent-Tesla-traffic.pcap`


###  Wireshark Filter:
```wireshark
 (http.request or tls.handshake.type eq 1)and !(ssdp)
```

<img width="1726" height="857" alt="image" src="https://github.com/user-attachments/assets/8279fe93-9292-4dc4-8ead-c1f9c17e7fc9" />

####  Observations:

- SMTP traffic shows evidence of the malware attempting outbound email communication via `cpanel.bredband2.com`.
- A **STARTTLS** handshake is used, encrypting SMTP payloads and potentially used for exfiltration or spamming.
- **FTP exfiltration** was expected from known behavior of AgentTesla but **no FTP sessions were observed** in the PCAP.
- Therefore, credentials like `u104812389` and `Apanel@123` appear **not in this network capture**, but are extracted from **static registry dump or malware sample**.


####  Key Indicators:

| **Indicator Type**   | **Value**                        |
|----------------------|----------------------------------|
| **Protocol Used**    | SMTP with STARTTLS               |
| **SMTP Server**      | `cpanel.bredband2.com`           |
| **Certificate CN**   | `*.bredband2.com`                |
| **TLS Issuer**       | Let's Encrypt                    |
| **TLS Handshake**    | Present (STARTTLS)               |
| **Victim Host**      | `DESKTOP-WIN11PC`                |

---

## 🧾 Step 3: Phishing Email Analysis

📄 **File:**  
`2024-06-10-Agent-Tesla-email.eml`

<img width="1085" height="963" alt="image" src="https://github.com/user-attachments/assets/862bac70-a7ea-442c-a3f7-b2c9054c8766" />

<img width="1457" height="893" alt="image" src="https://github.com/user-attachments/assets/1a3324e0-3658-4400-91f2-ff71e2ed69f0" />


#### Observations:

- **Subject:** Purchase Order  
- **Attachment:** `PO102523.img` – disguised to appear like a document.
- The `.img` file contains the malware executable, `PO102523.exe`, a PE32 Windows binary.
- File has a **PDF icon** to deceive the victim.
- Once opened, the file **drops and executes** the AgentTesla payload.



####   Key Indicators:

| **Attribute**       | **Value**               |
|---------------------|-------------------------|
| **File Name**       | `PO102523.img`          |
| **Payload Inside**  | `PO102523.exe`          |
| **Executable Size** | 545,280 bytes           |
| **Disguised As**    | PDF document            |
| **Delivery Method** | Email attachment        |

---

### Step 4: Persistence Mechanism – Registry Key

📄 **File:**  
`Agent-Tesla-persistence-registry-dump.reg`


<img width="1085" height="497" alt="image" src="https://github.com/user-attachments/assets/3a4bc664-0ebd-4382-a3cf-6885d4a9aba6" />


```reg
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"PDF Reader"="C:\\Users\\User\\AppData\\Roaming\\PDF Reader\\reader.exe"
```
#### Observations:

AgentTesla achieves persistence via the **Windows Run key**.

The payload is named **PDF Reader** and resides in the user’s **AppData Roaming** directory.

This ensures it launches **every time the user logs in**.


####  Key Indicators:

| **Type**         | **Value**                                                                 |
|------------------|---------------------------------------------------------------------------|
| **Registry Key** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`                      |
| **Value Name**   | `PDF Reader`                                                              |
| **Executable Path** | `C:\Users\User\AppData\Roaming\PDF Reader\reader.exe`                  |

---

### Step 5: Indicators of Compromise (IOCs)

| **Type**              | **Value**                                                                 |
|------------------------|---------------------------------------------------------------------------|
| **Exfiltration Server**| `ftp://ftpupload.net`                                                     |
| **FTP Username**       | `u104812389`                                                              |
| **FTP Password**       | `Apanel@123`                                                              |
| **Email Subject**      | `Purchase Order`                                                          |
| **Attachment Name**    | `PO102523.img`                                                            |
| **Payload Executable** | `PO102523.exe` (545,280 bytes)                                            |
| **Persistence Key**    | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\PDF Reader`          |
| **Payload Path**       | `C:\Users\User\AppData\Roaming\PDF Reader\reader.exe`                     |


---
