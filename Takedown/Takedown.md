# HTB Sherlock - Takedown

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-13 | Andrew McKenzie | Easy       | SOC            |

---
## Description
This challenge is a network forensics investigation that requires analyzing a PCAP file to deconstruct a multi-stage malware infection chain. The objective is to trace the attack from the initial download of a VBScript dropper to the final execution of the DarkGate RAT. The process involves carving scripts, analyzing their contents, identifying the use of legitimate binaries for defense evasion, and using OSINT to characterize the final payload.
## Scenario
We've identified an unusual pattern in our network activity, indicating a possible security breach. Our team suspects an unauthorized intrusion into our systems, potentially compromising sensitive data. Your task is to investigate this incident.
## Artifacts Provided
- takedown.zip
	- Takedown.pcap

| File Name     | Algorithm | Hash                                                             |
| ------------- | --------- | ---------------------------------------------------------------- |
| Takedown.pcap | SHA256    | c6f00b34cbaa34a5e992388a6b85c8b3109b32237590043118605a5538a5c296 |
| Takedown.pcap | SHA1      | c72974adbfa759825655c4802a599a111df2042c                         |
| Takedown.pcap | MD5       | 61dde440dadbdffb745a5ab849877f08                                 |
## Skills Learned
- **Multi-Stage Malware Analysis:** Tracing a complex infection that uses multiple downloader scripts (VBS, PowerShell) to deliver a final payload.
- **Network Forensics:** Using Wireshark to export HTTP objects, analyze DNS traffic, and inspect script contents directly from network traffic.
- **Script Analysis:** Manually reviewing VBScript and PowerShell to understand their functionality and extract next-stage C2 URLs.
- **Living Off The Land (LOLBAS) Recognition:** Identifying the abuse of a legitimate, signed application (`AutoHotkey.exe`) to execute malicious code as a defense evasion tactic.
- **Malware Triage with OSINT:** Using file hashes on platforms like VirusTotal to identify malware families (`DarkGate`) and gather valuable metadata like TLSH.
- **Indicator of Compromise (IOC) Extraction:** Identifying and documenting a full range of IOCs, including domains, URLs, IPs, filenames, hashes, and user-agent strings.
## Initial Analysis
The investigation of the `Takedown.pcap` file revealed a sophisticated, multi-stage infection process consistent with the DarkGate malware.
1. **Initial Access:** The attack began with the user downloading a VBScript file named **`AZURE_DOC_OPEN.vbs`** from the domain **`escuelademarina.com`** (`165.22.16.55`).
2. **Second Stage:** Analysis of the VBScript showed that its purpose was to download and execute a PowerShell script from **`badbutperfect.com/nrwncpwo`**.
3. **Defense Evasion:** The PowerShell script then downloaded a legitimate, signed executable, **`AutoHotkey.exe`**. This is a Living Off The Land (LOLBAS) technique, used to execute subsequent malicious code under the guise of a trusted process, thereby evading detection.
4. **Final Payload:** The script then downloaded the final malicious payload from **`http://badbutperfect.com/jvtobaqj`** and saved it to disk as **`script.ahk`**. It used the previously downloaded `AutoHotkey.exe` to execute this script.
5. **Malware Identification:** The `jvtobaqj` file was carved from the PCAP and its hash was analyzed on VirusTotal, which confirmed the malware as **DarkGate** and provided its TLSH.
6. **C2 Communication:** The final step observed in the PCAP was the DarkGate RAT communicating with its C2 server at **`103.124.105.78`**, using a standard Chrome user-agent string.
## Questions:
1. **From what domain is the VBS script downloaded?**
Reviewing downloaded objects in the PCAP file, we can see the VBS script is downloaded from `escuelademarina.com`.

![image one](./Images/Pasted%20image%2020250913075350.png)

2. **What was the IP address associated with the domain in question #1 used for this attack?**
We can see from DNS records that the A record for the domain in question 1 is linked to `165.22.16.55`.

![image two](./Images/Pasted%20image%2020250913075608.png)

3. **What is the filename of the VBS script used for initial access?**
From question 1, we know the VBS script name is `AZURE_DOC_OPEN.vbs`.

4. **What was the URL used to get a PowerShell script?**
Reviewing the VBS script, we can see the URL to download the next step is `badbutperfect.com/nrwncpwo`.

![image three](./Images/Pasted%20image%2020250913075816.png)

5. **What likely legit binary was downloaded to the victim machine?**
Reviewing the PowerShell script from question 4's answer, we can see that the executable downloaded is `AutoHotkey.exe`.

![image four](./Images/Pasted%20image%2020250913075939.png)

6. **From what URL was the malware used with the binary from question #5 downloaded?**
Continuing with the same script, we can see that AutoHotkey was used only to run another script. The URL where this script was downloaded was `http://badbutperfect.com/jvtobaqj`.

![image five](./Images/Pasted%20image%2020250913080556.png)

7. **What filename was the malware from question #6 given on disk?**
The script that was mentioned as being downloaded and used by AutoHotkey in the previous question is `script.ask`.

8. **What is the TLSH of the malware?**
Taking a SHA256 hash of the file "jvtobaqj," which later turns into the script from the previous question, can be looked up on VirusTotal. Which shows the TLSH of the malware as `T15E430A36DBC5202AD8E3074270096562FE7DC0215B4B32659C9EF16835CF6FF9B6A1B8`.

![image six](./Images/Pasted%20image%2020250913080853.png)

9. **What is the name given to this malware? Use the name used by McAfee, Ikarus, and alejandro.sanchez.**
Reviewing VirusTotal's community posts for this malware, we can see the user `alejandro.sanchez` provided the name of the malware as `DarkGate`.

![image seven](./Images/Pasted%20image%2020250913081032.png)

10. **What is the user-agent string of the infected machine?**
Looking at the end HTTP traffic coming from the infected machine, we can see that the user agent is listed as `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36`.

![image eight](./Images/Pasted%20image%2020250913081242.png)

11. **To what IP does the RAT from the previous question connect?**
Reviewing the same communications from the previous question, the IP address the victim machine is connected to is `103.124.105.78`.

![image nine](./Images/Pasted%20image%2020250913081350.png)