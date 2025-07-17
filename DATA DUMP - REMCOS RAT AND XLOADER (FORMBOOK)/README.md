## Malware Case Study – September 11, 2024

**Date:** September 11, 2024  
**Source:** [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2024/09/11/index.html)

### Theme:
Dual infection activity showcasing Remcos RAT and XLoader (Formbook), both spread via malspam attachments. Observed via PCAP network traffic and file IOCs.

---

###  Step 1: Download and Extract Investigation Files

Downloaded from the site:

- `2024-09-11-files-from-Remcos-RAT-activity.zip`
- `2024-09-11-files-from-XLoader-activity.zip`
- `2024-09-11-Remcos-RAT-infection-traffic.pcap`
- `2024-09-11-XLoader-infection-traffic.pcap`

Related `.eml`, `.exe`, `.tar`, `.rar` payloads

Unzipped using password using `infected_20240911`

---

### Step 2: Network Traffic Analysis – Remcos RAT

**PCAP File:**  
`2024-09-11-Remcos-RAT-infection-traffic.pcap`


### 🔍 Wireshark Filter:
```wireshark
http.request or tls.handshake.type eq 1 or dns.qry.name contains duckdns
```

<img width="1723" height="888" alt="image" src="https://github.com/user-attachments/assets/6e55830d-e3b4-4b99-8739-af2f13d75ee7" />


####  Observations:

Victim queries `eadzagba1.duckdns.org`

Connection established to IP: `198.46.178.133` on TCP port `4877`

Traffic shows **TLSv1.3 handshake**, indicating encrypted C2 communication


####  Key Indicators:

- **C2 Domain:** `eadzagba1.duckdns.org`
- **C2 IP:** `198.46.178.133`
- **Protocol:** `TLSv1.3`, port `4877`

---

###  Step 3: Network Traffic Analysis – XLoader (Formbook)

**PCAP File:**  
`2024-09-11-XLoader-infection-traffic.pcap`



### 🔍 Wireshark Filter:
```wireshark
http.request
```

<img width="1716" height="833" alt="image" src="https://github.com/user-attachments/assets/5af986c7-3e5d-49e0-81dd-6b4593b6faa7" />

####  Observations:

Multiple HTTP POST requests to:

- `www.chalet-tofane.net`
- `rtpgaruda888resmi.xyz`
- `useanecdotenow.tech`
- `everycreation.shop`

POST requests use `application/x-www-form-urlencoded` (indicative of data exfiltration)

#### Key Indicators:

**Domains:**

- `www.chalet-tofane.net`  
- `rtpgaruda888resmi.xyz`  
- `useanecdotenow.tech`  

**Method:** HTTP POST  
**Payload Type:** x-www-form-urlencoded

---

### Step 5: Indicators of Compromise (IOCs)

| **Type**             | **Value**                                                                 |
|----------------------|---------------------------------------------------------------------------|
| **Remcos Domain**    | `eadzagba1.duckdns.org`                                                   |
| **Remcos IP**        | `198.46.178.133`                                                          |
| **Remcos Port**      | `4877 (TLS)`                                                              |
| **XLoader Domains**  | `chalet-tofane.net`, `rtpgaruda888resmi.xyz`, `useanecdotenow.tech`      |
| **XLoader Method**   | `HTTP POST with URL-encoded form data`                                   |
| **Remcos Sample**    | `Inquiry no. 1051_pdf.exe` (947,200 bytes)                               |
| **XLoader Sample**   | `PO82107048.exe` (685,568 bytes)                                         |

---

### Step 6: Splunk Analysis (PCAP → JSON)
Convert to JSON:
```
tshark -r 2024-09-11-XLoader-infection-traffic.pcap -Y "http.request" -T json > xloader.json
```
<img width="1730" height="755" alt="image" src="https://github.com/user-attachments/assets/25da59e0-dd47-4d9d-98c7-3456fb23f6d6" />

Upload in Splunk:
Source Type: Default

Search:
```sql
source="xloader.json" host="localhost" "POST /3bhs/" OR "POST /u8o7/"
```

<img width="1727" height="853" alt="image" src="https://github.com/user-attachments/assets/d65faf3d-9222-44fa-9573-d363571714b1" />

Detect XLoader POST Activity:

```sql
source="xloader.json" host="localhost" "application/x-www-form-urlencoded"
```

<img width="1706" height="825" alt="image" src="https://github.com/user-attachments/assets/ff928579-2147-4fdc-9b4c-1e2b7f6c0b79" />

---

### Step 7: Incident Response Lifecycle

| **Phase**         | **Action Taken**                                                           |
|-------------------|----------------------------------------------------------------------------|
| **Preparation**   | Ensured updated AV, C2 domain watchlists                                   |
| **Identification**| Observed outbound TLS on port 4877 and POSTs to strange hosts              |
| **Containment**   | Blocked IP `198.46.178.133`, domains used by XLoader                       |
| **Eradication**   | Removed executables from infected hosts                                    |
| **Recovery**      | Reset infected endpoints, revoked exposed credentials                      |
| **Lessons Learned**| Improved malspam detection; user training on attachment risks              |

---

###  Timeline of Events (UTC)

| **Time**                | **Event**                                                              |
|-------------------------|------------------------------------------------------------------------|
| 2024-09-11 17:05:22     | Remcos RAT initiates DNS query to `eadzagba1.duckdns.org`              |
| 2024-09-11 17:05:25     | TLS handshake to `198.46.178.133` begins                              |
| 2024-09-11 17:27–17:29  | XLoader sends multiple POST requests to different domains              |
| 2024-09-11 17:30        | Alerts triggered based on C2 signatures and traffic volume             |

---
