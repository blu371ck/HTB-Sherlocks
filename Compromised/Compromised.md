# HTB Sherlock - Compromised

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-13 | Andrew McKenzie | Easy       | SOC            |

---
## Description
This challenge is a network forensics investigation centered on analyzing a single packet capture (`.pcap`) file from a compromised host. The objective is to dissect the network traffic to identify the initial access vector, characterize the malware using open-source intelligence, and detail the command-and-control (C2) communication channels, including analyzing TLS certificates and detecting DNS tunneling.
## Scenario
Our SOC team detected suspicious activity in Network Traffic, the machine has been compromised and company information that should not have been there has now been stolen – it’s up to you to figure out what has happened and what data has been taken.
## Artifacts Provided
- compromised.zip
	- capture.pcap

| File Name    | Algorithm | Hash                                                             |
| ------------ | --------- | ---------------------------------------------------------------- |
| capture.pcap | SHA256    | cde5c8ab5797894820b40a7f9038766863aa48c3f8614abe7b2b2d205a72863c |
| capture.pcap | SHA1      | f147a8f1cd751b1e0e43061a283f53feb44a1ebc                         |
| capture.pcap | MD5       | 50b6fde8eb31c565abe4981b0326d146                                 |
## Skills Learned
- **Network Forensics:** Using Wireshark to analyze a `.pcap` file, filter by protocol, and trace malicious activity.
- **File Carving:** Extracting malicious executables transferred over HTTP from network traffic for further analysis.
- **Malware Triage with OSINT:** Using file hashes on platforms like VirusTotal to identify malware families (`Pikabot`) and gather threat intelligence.
- **TLS Certificate Analysis:** Inspecting details of self-signed certificates to extract unique and suspicious IOCs for C2 infrastructure.
- **C2 Traffic Identification:** Recognizing C2 communication over non-standard ports using encrypted protocols like TLS.
- **DNS Tunneling Detection:** Identifying suspicious DNS query patterns that suggest the use of DNS for C2.
## Initial Analysis
The investigation was conducted by performing a thorough analysis of the provided `capture.pcap` file.
1. **Initial Access:** The first malicious activity identified was the download of an executable file over HTTP from the IP address **`162.252.172.54`**.
2. **Malware Identification:** The executable was carved from the PCAP, and its SHA256 hash was calculated. A search on VirusTotal identified the malware as a variant of **`Pikabot`**, a known information stealer and backdoor.
3. **C2 Communication:** After execution, the malware initiated command-and-control (C2) communication. By filtering for TLS traffic, it was observed that the malware communicated over several non-standard ports: **`2078`**, **`2222`**, and **`32999`**.
4. **Certificate Analysis:** The C2 traffic was encrypted using self-signed TLS certificates. An inspection of the certificate details revealed unusual and suspicious metadata, such as a `localityName` of **`Pyopneumopericardium`** and a `notBefore` date of **`2023-05-14`**. These unique values can be used as indicators to hunt for related C2 infrastructure.
5. **DNS Tunneling:** An analysis of DNS traffic revealed numerous queries to the domain **`steasteel.net`**. The pattern of these queries suggests the malware was also using DNS tunneling as a secondary, stealthier C2 channel.
## Questions:
1. **What is the IP address used for initial access?**
Reviewing the traffic in Wireshark, we can see an item downloaded from an IP address `162.252.172.54`.

![image one](./Images/Pasted%20image%2020250913070716.png)

2. **What is the SHA256 hash of the malware?**
The item downloaded from the IP address above turns out to be an executable file. The hash of the file is `9b8ffdc8ba2b2caa485cca56a82b2dcbd251f65fb30bc88f0ac3da6704e4d3c6`.

![image two](./Images/Pasted%20image%2020250913070820.png)

3. **What is the Family label of the malware?**
Reviewing the hash on VirusTotal shows that the family label of this malware is `pikabot`.

![image three](./Images/Pasted%20image%2020250913070931.png)

4. **When was the malware first seen in the wild (UTC)?**
According to VirusTotal, the malware was first seen in the wild on `2023-05-19 14:01:21`.

![image four](./Images/Pasted%20image%2020250913071032.png)

5. **The malware used HTTPS traffic with a self-signed certificate. What are the ports, from smallest to largest?**
Reviewing TLS traffic for the victim IP address. We can see three different (non-standard TLS) ports being utilized. In order from smallest to largest, they are `2078, 2222, 32999`.

6. **What is the id-at-localityName of the self-signed certificate associated with the first malicious IP?**
Going back to the beginning of the TLS traffic and inspecting the first malicious IP address shows that the first id-at-localityName of the certificate was `Pyopneumopericardium`.

![image five](./Images/Pasted%20image%2020250913072324.png)

7. **What is the notBefore time(UTC) for this self-signed certificate?**
Inspecting the same certificate exchange from the previous question, we can see that the notBefore time is `2023-05-14 08:36:52`.

![image six](./Images/Pasted%20image%2020250913072455.png)

8. **What was the domain used for tunneling?**
Reviewing DNS traffic shows that the likely domain being used for tunneling is `steasteel.net`.

![image seven](./Images/Pasted%20image%2020250913072700.png)