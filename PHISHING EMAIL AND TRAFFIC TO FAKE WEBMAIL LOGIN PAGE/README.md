#  Phishing Case Study – August 29, 2024

##  Date: August 29, 2024  
**Source:** [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2024/08/29/index.html)

###  Theme:  
Credential theft via phishing email leading to a fake webmail login page, designed to harvest email passwords through HTTP POST requests.

---

##  Step 1: Download and Extract Investigation Files

Downloaded the following from the case study page:

- `2024-08-29-phishing-email-0415-UTC.eml.zip`  
- `2024-08-29-phishing-website-traffic.pcap.zip`

**Unzipped using password:** `infected_20240829`

---

##  Step 2: Email Analysis (Phishing Email)

**Email Subject:**  
`Account Validation!! For admin@malware-traffic-analysis.net Only!!`

**From Address:**  
`SupportDesk <khz.port@scp[.]gov[.]iq>`

**Received Headers:**
```
Received: from s940027.srvape[.]com (188.127.247[.]252)
Received: from ip172.ip-149-56-149[.]net
Message-ID: <20240828030626.DFAECAD6A3F54472@scp[.]gov[.]iq>
```

**Key Content:**

- Fake account validation request for `admin@malware-traffic-analysis.net`
- Contains a malicious “Re-authenticate Now” button
- Embedded phishing URL:
```
https://email.procedure.best/management.aspx?good=admin@malware-traffic-analysis.net
```
**Phishing Email Interface**  

<img width="1877" height="981" alt="Screenshot 2025-07-16 092903" src="https://github.com/user-attachments/assets/5a0cfdc8-195c-44c1-bf32-e2ca6d122d2a" />

---

##  Step 3: Fake Webmail Page Analysis

The victim is redirected to a **fake Webmail login page** hosted at:

**URL Visited:**
```
http://email.procedure.best/management.aspx?good=admin@malware-traffic-analysis.net
```

### Page Characteristics:

- Web page mimics a legitimate email login interface
- **Email address field** is **auto-filled** with the recipient’s address
- **Password input field** prompts for user credentials

 **Fake Webmail Login Page**  

<img width="1085" height="609" alt="image" src="https://github.com/user-attachments/assets/38d82f3d-0bcc-465c-907b-e5a7d236d4f8" />

---


## Step 4:  Network Traffic Analysis (Wireshark)

**Opened File:**  
`2024-08-29-phishing-website-traffic.pcap`

### 🔍 Wireshark Filter Used:
```wireshark
http.request or tls.handshake.type eq 1
```
This filter helps identify all HTTP and TLS-based communications, especially connections to phishing domains and encrypted handshake details.

<img width="1726" height="897" alt="image" src="https://github.com/user-attachments/assets/cdfbd4af-ab3f-46dc-acf5-4aed5f8de271" />

 Observations:
Targeted domain:
email.procedure.best

 Key Activity:

- Victim makes an HTTP GET request to fetch the phishing page.
- Follows with a POST request to `/management.aspx`.

 POST request includes:
- Victim’s email address
- Entered password

 This confirms successful credential harvesting by the fake login portal.

---

## Step 5: Credential Exfiltration – Follow HTTP Stream

**Wireshark Filter Used:**
```wireshark
tcp.stream eq 13
```

#### Locate the Packet:
- Find the **HTTP POST** packet related to your phishing domain (e.g., `email.procedure.best`).
- Look for `POST /management.aspx?...` in the **Info** column.

####  Action:
- **Right-click** the POST packet  
- Navigate to: `Follow` → `TCP Stream`

This reveals the full request and response between the victim and the phishing server, including any credentials sent over the wire.

<img width="1717" height="943" alt="image" src="https://github.com/user-attachments/assets/725eb704-2d25-4f32-9d45-e01e0f6ef618" />

#### Observed HTTP POST Request:

```http
POST /management.aspx?good=admin@malware-traffic-analysis.net HTTP/1.1
Host: email.procedure.best
Content-Type: application/x-www-form-urlencoded
...
JV-Yh-gl-admin%40malware-traffic-analysis.net&RZ-Jt-US=this_is_not_a_real_password...
```

The TCP stream confirms that user input from the fake login page is transmitted in plain HTTP via POST, making it easily interceptable and proving successful credential theft.

---

## Step 6: Indicators of Compromise (IOCs)

| **Type**         | **Value**                                                       |
|------------------|------------------------------------------------------------------|
| **Phishing Domain** | `email.procedure.best`                                        |
| **URL Path**        | `/management.aspx?good=admin@malware-traffic-analysis.net`    |
| **Origin IP**       | `172.67.202.104` (Cloudflare proxied)                         |
| **Sender Email**    | `khz.port@scp[.]gov[.]iq`                                      |
| **Subject**         | `Account Validation!! For admin@malware-traffic-analysis.net` |

---

##  Step 7: Detection Logic in Splunk

Once filtered and converted to JSON:

###  Convert PCAP to JSON:
```bash
tshark -r 2024-08-29-phishing-website-traffic.pcap -Y "http.request or tcp.stream eq 13" -T json > phishing.json
```
<img width="1486" height="606" alt="image" src="https://github.com/user-attachments/assets/49af34b2-8aab-4024-89b3-72f90a3e666b" />

Upload it in splunk and select source type as default only.

<img width="1693" height="828" alt="image" src="https://github.com/user-attachments/assets/85e828b0-df5e-4788-b8e2-c3dea2d80b9a" />

### Detect Credentials POST:

```spl
source="phishing.json" host="localhost" "/management.aspx" POST
```

<img width="1706" height="872" alt="image" src="https://github.com/user-attachments/assets/972555e2-0b7d-4aa9-80f3-11df428e75ba" />

### Detect Email Harvesting Pattern:

```sql
source="phishing.json" host="localhost" "admin@malware-traffic-analysis.net"
```

<img width="1711" height="732" alt="image" src="https://github.com/user-attachments/assets/ab48a407-4306-4302-8169-35e8702d7106" />

---

##  Step 8: Incident Response Lifecycle

| **Phase**       | **Action Taken**                                                                 |
|------------------|----------------------------------------------------------------------------------|
| **Preparation**  | Enabled email gateway phishing detection                                         |
| **Identification** | User reports suspicious email; SOC alert on HTTP POST to suspicious domain      |
| **Containment**  | Blocked `email.procedure.best`; alerted all users                               |
| **Eradication**  | Removed phishing email; cleared proxy logs and DNS cache                        |
| **Recovery**     | Reset compromised credentials; enforced 2FA                                      |
| **Lessons Learned** | Educated users on spear-phishing and domain impersonation tactics               |

---

##  Timeline of Events (UTC)

| **Time**              | **Event**                                                 |
|------------------------|-----------------------------------------------------------|
| 2024-08-29 04:15       | Phishing email received                                   |
| 2024-08-29 21:03       | Victim opens phishing site and enters credentials         |
| 2024-08-29 21:03:36    | HTTP POST sends credentials to attacker's server          |
| 2024-08-29 21:05       | Alert triggered from proxy logs                           |
| 2024-08-29 21:30       | Credentials reset and Incident Response initiated         |

---
