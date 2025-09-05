# HTB Sherlock - Reaper

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-05 | Andrew McKenzie | Very Easy  | DFIR           |

---
## Description
This challenge focuses on investigating a classic **NTLM Relay Attack**. The primary objective is to analyze a packet capture (`.pcapng`) and Windows Security Event Logs (`.evtx`) to validate a SIEM alert. The alert was triggered by a common indicator of this attack: a logon event where the source IP address and the source workstation name do not match. The analysis involves correlating network traffic with host-based logs to identify the victim, the attacker, and the timeline of the malicious logon.
## Scenario
Our SIEM alerted us to a suspicious logon event which needs to be looked at immediately . The alert details were that the IP Address and the Source Workstation name were a mismatch .You are provided a network capture and event logs from the surrounding time around the incident timeframe. Corelate the given evidence and report back to your SOC Manager.
## Artifacts Provided
- Reaper.zip
	- `ntlmrelay.pcapng`
	- `SECURITY.evtx`

| Filename           | Algorithm | Hash                                                             |
| ------------------ | --------- | ---------------------------------------------------------------- |
| `ntlmrelay.pcapng` | SHA256    | 7BF9BC187C5C6EDB2380F618FD2940D8E32329AD9EEE2AA251A37B4D5835174B |
| `ntlmrelay.pcapng` | SHA1      | 1E0D1CA577704956E932127F20D1DE6322B75914                         |
| `ntlmrelay.pcapng` | MD5       | 7B7BE1432504EBF8D7FFA5BE042D0DC7                                 |
| `SECURITY.evtx`    | SHA256    | 4DF60929424D93B2094FA6267CAB8E549ACA7CB02F024DADBCB6106FBCFF4EC6 |
| `SECURITY.evtx`    | SHA1      | A94433991186D4F59CE8C7717F008E0D592DF0DF                         |
| `SECURITY.evtx`    | MD5       | AB3A8A7A6F13C9973E6533B194E79A0B                                 |
## Skills Learned
- **Network Forensics:** Analyzing packet captures in Wireshark to identify hosts, protocols, and user activity. 
- **Protocol Analysis:** Specifically decoding and interpreting `NBNS`, `NTLMSSP`, and `SMB2` traffic to reconstruct an attack chain.
- **Host-Based Forensics:** Investigating Windows Security Event Logs, particularly Event IDs `4624` (Successful Logon) and `5140` (Network Share Access).
- **Log Correlation:** Connecting network-level evidence (e.g., captured NTLM hashes) with host-level artifacts (e.g., logon events) to build a complete picture of an incident.
- **TTP Identification:** Recognizing the indicators of an NTLM Relay attack, including the IP/hostname mismatch and access to the `IPC$` share.
## Initial Analysis
The investigation started by analyzing the provided network capture to understand the environment and identify the suspicious activity, followed by a pivot to the host logs to confirm the attack.
1. **Network Baselining:** I began by examining the `ntlmrelay.pcapng` file in Wireshark. Filtering on `nbns` traffic quickly identified the legitimate workstations on the network: `FORELA-WKSTN001` at `172.17.79.129` and `FORELA-WKSTN002` at `172.17.79.136`.
2. **Identifying the Attack:** Next, I filtered for `ntlmssp` to inspect NTLM authentication challenges and responses. This traffic revealed that the user account `arthur.kyle` from workstation `172.17.79.136` was communicating with an unknown device at `172.17.19.135`. This third party is the attacker's machine, positioned to intercept and relay the authentication. An `smb2` filter showed the initial trigger was the victim attempting to access a share named `\\DC01\Trip`.
3. **Correlating with Host Logs:** I then pivoted to the `SECURITY.evtx` log. Filtering for successful network logons (**Event ID 4624**, Logon Type 3), I found a logon event for the user `arthur.kyle`. This event was the key to the investigation, as it showed:
    - **The Mismatch:** The logon originated from the attacker's IP (`172.17.79.135`) but claimed to be from the victim's workstation (`FORELA-WKSTN002`), confirming the SIEM alert.
    - **Timestamp:** The malicious logon occurred at **`2024-07-31 04:55:16` UTC**.
    - **Session Details:** The logon used source port `40252` and was assigned the Logon ID `0x64a799`.
4. **Final Confirmation:** To find what the attacker did immediately after logon, I filtered for **Event ID 5140** (Network Share Access). This revealed that the malicious session immediately accessed the `\\*\IPC$` share, a common action for enumeration and lateral movement tools after a successful relay.
The correlated evidence confirms that an attacker successfully performed an NTLM relay attack against the user `arthur.kyle`.
## Questions:
1. **What is the IP Address for Forela-Wkstn001?**
After opening the `.pcapng` file with Wireshark, we can see there are NetBIOS Name Service requests, so we can find this and the next answer easily by filtering for just `nbns` and reviewing the entries. The first entry is regarding `FORELA-WKSTN001` and its IP address is shown as `172.17.79.129`.

![image one](./Images/Pasted%20image%2020250905154838.png)

2. **What is the IP Address for Forela-Wkstn002?**
Several records below question 1, we can see in the info column 002 is being discussed. Reviewing those details shows us the IP address is `172.17.79.136`.

![image two](./Images/Pasted%20image%2020250905154952.png)

3. **What is the username of the account whose hash was stolen by attacker?**
Taking the name of the pcapng file into play, we can assume this challenge has something to do with NTLM. Then this question asks us for a hash, so we can assume potentially an NTLM hash is being used to authenticate. We can then filter results for `ntlmssp` in Wireshark. We can see one name being thrown around: `arthur.kyle`.

![image three](./Images/Pasted%20image%2020250905160232.png)


4. **What is the IP Address of Unknown Device used by the attacker to intercept credentials?**
Staying in the same results, we notice that there are only two IP addresses here. One of which we already identified as a workstation, so the attacker must be the other IP address `172.17.19.135`.

![image four](./Images/Pasted%20image%2020250905160328.png)

5. **What was the fileshare navigated by the victim user account?**
Filtering for `smb2` shows that the results coming from the compromised workstation `136` attempted to reach out to `DC01\Trip` multiple times unsuccessfully.

![image five](./Images/Pasted%20image%2020250905160804.png)

6. **What is the source port used to logon to target workstation using the compromised account?**
For the following question, we need to utilize the `SECURITY` logs that were provided. Which we can then filter for event ID `4624`. We can look through the results looking for [logon type 3](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624). From the results, the only one that matches the user we found from question 3 utilized source port `40252`.

![image six](./Images/Pasted%20image%2020250905161850.png)

7. **What is the Logon ID for the malicious session?**
The login ID can be found in the same results from the previous question. `0x64a799`.

![image seven](./Images/Pasted%20image%2020250905162004.png)

8. **The detection was based on the mismatch of hostname and the assigned IP Address. What is the workstation name and the source IP Address from which the malicious logon occur?**
Again, this information can be found in the same results from the previous two questions. The workstation name is `FORELA-WKSTN002` and the IP address is `172.17.79.135`.

![image eight](./Images/Pasted%20image%2020250905162135.png)

9. **At what UTC time did the the malicious logon happen?**
We can view the XML of this same event to find the appropriate time the login occurred. The answer is `2024-07-31 04:55:16`.

![image nine](./Images/Pasted%20image%2020250905162244.png)

10. **What is the share Name accessed as part of the authentication process by the malicious tool used by the attacker?**
To answer this, we can change our filter to `5140`, “A network share object was accessed.” The only result shows that the share was `\\*\IPC$`.

![image ten](./Images/Pasted%20image%2020250905162437.png)