# HTB Sherlock - Unit42

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-06 | Andrew McKenzie | Very Easy  | DFIR           |

---
## Description
This challenge serves as an introduction to analyzing **Sysmon logs** to detect and investigate malicious activity on a Windows system. The scenario is based on research by Palo Alto's Unit42 on a campaign that used a backdoored version of the UltraVNC remote access tool. The goal is to trace the initial access and execution stages of the malware by examining key Sysmon events.
## Scenario
In this Sherlock, you will familiarize yourself with Sysmon logs and various useful EventIDs for identifying and analyzing malicious activities on a Windows system. Palo Alto's Unit42 recently conducted research on an UltraVNC campaign, wherein attackers utilized a backdoored version of UltraVNC to maintain access to systems. This lab is inspired by that campaign and guides participants through the initial access stage of the campaign.
## Artifacts Provided
- unit42.zip
	- `Microsoft-Windows-Sysmon-Operational.evtx`

| Filename                                    | Algorithm | Hash                                                             |
| ------------------------------------------- | --------- | ---------------------------------------------------------------- |
| `Microsoft-Windows-Sysmon-Operational.evtx` | SHA256    | 447C1D3084B919244696ADEC7C541873778B60B35DAAF35C539582FE8E66287B |
| `Microsoft-Windows-Sysmon-Operational.evtx` | SHA1      | C3B2F06AC6FF87B9C7F293FF1A624AA5839FAA7D                         |
| `Microsoft-Windows-Sysmon-Operational.evtx` | MD5       | 697B7939D59F117E5CA4C90AB730658F                                 |
## Skills Learned
- **Sysmon Log Analysis:** Gaining experience in navigating and filtering Sysmon operational logs (`Microsoft-Windows-Sysmon-Operational.evtx`) for threat hunting.
- **Event Correlation:** Understanding and utilizing key Sysmon Event IDs to build a narrative of an attack:
    - **Event ID 1 (Process Creation):** Identifying the execution of malicious processes.
    - **Event ID 2 (File Creation Time Changed):** Detecting defense evasion techniques like "Timestomping".
    - **Event ID 5 (Process Terminated):** Confirming the end of a process's lifecycle.
    - **Event ID 11 (File Create):** Tracking malware-dropped files.
    - **Event ID 22 (DNS Query):** Uncovering network indicators like distribution sites or C2 domains.
- **Malware TTPs:** Recognizing common attacker tactics, such as using cloud services for distribution and performing internet connectivity checks.
## Initial Analysis
The investigation started by examining the provided Sysmon logs to trace the malware's lifecycle. The first step was to identify the initial point of execution. By filtering for **Event ID 1 (Process Creation)**, a suspicious executable named `Preventivo24.02.14.exe.exe` was quickly identified as the source of the infection.

Next, the malware's network activity was analyzed using **Event ID 22 (DNS Query)**. These logs revealed that the malware was likely distributed via `dropbox.com` and that it performed a connectivity check by attempting to resolve `www.example.com`.

The on-host actions of the malware were then investigated. **Event ID 11 (File Create)** logs showed that the process dropped multiple files, including a command script named `once.cmd` in the user's `AppData\Roaming` directory. A notable defense evasion technique was uncovered by looking at **Event ID 2 (File Creation Time Changed)**, which showed the malware "timestomping" a created PDF file to alter its creation date and blend in with legitimate files.

Finally, the full execution timeline was bookended by identifying the process termination event, which marks the completion of the initial payload's execution.
## Questions:
1. **How many Event logs are there with Event ID 11?**
Using Event Log Explorer and applying the filter for Event ID 11, we can see there are `56` results.

![image one](./Images/Pasted%20image%2020250906215546.png)

2. **Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim's system?**
Filtering the logs for Event ID 1, we can see that one of the entries has a very suspicious name, `C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe`.

![image two](./Images/Pasted%20image%2020250906215719.png)

3. **Which Cloud drive was used to distribute the malware?**
Filtering for Event ID 22, we can see mentions of `dropbox`.

![image three](./Images/Pasted%20image%2020250906220027.png)

5. **For many of the files it wrote to disk, the initial malicious file used a defense evasion technique called Time Stomping, where the file creation date is changed to make it appear older and blend in with other files. What was the timestamp changed to for the PDF file?**
Utilizing Event ID 2, we can review events until we find one regarding a PDF file. We eventually find one, and its timestamp was changed to `2024-01-14 08:10:06`.

![image four](./Images/Pasted%20image%2020250906220250.png)

6. **The malicious file dropped a few files on disk. Where was "once.cmd" created on disk? Please answer with the full path along with the filename.**
To find this, we need to filter for Event ID 11, then look for the first occurrence of the mentioned `once.exe`. Starting from the bottom, we find the very long path where this file was created on this system, `C:\Users\CyberJunkie\AppData\Roaming\Photo and Fax Vn\Photo and vn 1.1.2\install\F97891C\WindowsVolume\Games\once.cmd`.

![image five](./Images/Pasted%20image%2020250906220513.png)

7. **The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?**
Filtering for Event ID 22, we can see of the three results, one stands out as odd, `www.example.com`.

![image six](./Images/Pasted%20image%2020250906220617.png)

8. **Which IP address did the malicious process try to reach out to?**
This information can be found in the same event from the previous question. The IP address is `93.184.216.34`.

![image seven](./Images/Pasted%20image%2020250906220704.png)

9. **The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?**
To answer this, we need to filter for Event ID 11. Then we need to review from the top down any mentions of `viewer.exe`. We find the item in question with the timestamp `2024-02-14 03:41:58`.

![image eight](./Images/Pasted%20image%2020250906220931.png)