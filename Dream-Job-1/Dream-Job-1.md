# HTB Sherlock: Dream Job-1
![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type      |
| ---------- | --------------- | ---------- | ------------------- |
| 2025-08-31 | Andrew McKenzie | Very Easy  | Threat Intelligence |

---
## Description
This threat intelligence challenge focuses on the investigation of “Operation Dream Job,” a cyber espionage campaign. The objective is to utilize open-source intelligence tools like the MITRE ATT&CK® framework and VirusTotal to gather crucial information about the threat actor, their tactics, techniques, and procedures (TTPs), and to analyze the provided Indicators of Compromise (IOCs).
## Scenario
You are a junior threat intelligence analyst at a cybersecurity firm. You have been tasked with investigating a cyber espionage campaign known as Operation Dream Job. The goal is to gather crucial information about this operation.
## Artifacts Provided
- DreamJob1.zip
	- ICOs.txt

| Filename | Algorithm | Hash                                                             |
| -------- | --------- | ---------------------------------------------------------------- |
| IOCs.txt | SHA256    | 9edda982fc5933181da898305230b5a71b41c7314430c0ea2f15ebed10a6793c |
| IOCs.txt | SHA1      | c23a9733638c7d81e4e37644d59a3e394b94ca66                         |
| IOCs.txt | MD5       | 24bd3c9680d4d6dbd0dd2042d2580e67                                 |
## Skills Learned
- **Threat Actor Profiling:** Researching and identifying the adversary behind a known campaign.
- **Campaign Analysis:** Using the MITRE ATT&CK framework to understand the scope, timeline, and associated operations of a cyber campaign.
- **TTP Identification:** Identifying specific tactics, techniques, and procedures used by an adversary, such as `Internal Spearphishing` (T1534) and the use of `Native API`.
- **IOC Analysis:** Utilizing VirusTotal to analyze file hashes and extract key details like file names, creation timestamps, and relationships with other entities.
- **Open-Source Intelligence (OSINT):** Correlating artifacts with publicly available threat reports and intelligence to build a comprehensive picture of an attack.
## Initial Analysis
The investigation commenced with a query on the MITRE ATT&CK website for the campaign name “Operation Dream Job.” This search immediately identified the `Lazarus Group` as the responsible threat actor and provided extensive details on their operational methods. Key findings from this initial step included the campaign's first observation date, associated campaigns (`Operation North Star`, `Operation Interception`), and specific techniques used for execution and lateral movement. 

Following the intelligence gathering from MITRE, the analysis pivoted to the supplied `IOCs.txt` file. Each hash was systematically analyzed using VirusTotal to uncover specific information about the malicious files used in the campaign. This process linked the abstract TTPs to concrete artifacts, revealing file names, parent processes, and network communications associated with the operation.
## Questions:
1. **Who conducted Operation Dream Job?**
According to [MITRE,](https://attack.mitre.org/campaigns/C0022/) the group that conducted `Operation Dream Job` is the `Lazarus Group`. 

![image one](./Images/Pasted%20image%2020250831171430.png)

2. **When was this operation first observed?**
According to the same reference, the operation was first observed in `September 2019`.

![image two](./Images/Pasted%20image%2020250831171452.png)

3. **There are 2 campaigns associated with Operation Dream Job. One is `Operation North Star`, what is the other?**
According to the same reference, the other associated campaign is `Operation Interception`.

![image three](./Images/Pasted%20image%2020250831171512.png)

4. **During Operation Dream Job, there were the two system binaries used for proxy execution. One was `Regsvr32`, what was the other?**
According to the same reference, the other binary used is `Rundll32`.

![image four](./Images/Pasted%20image%2020250831171620.png)

5. **What lateral movement technique did the adversary use?**
According to the same reference, the lateral movement technique is `Internal Spearphishing`.

![image five](./Images/Pasted%20image%2020250831171704.png)

6. **What is the technique ID for the previous answer?**
According to the same reference, the technique ID is `T1534`.

![image six](./Images/Pasted%20image%2020250831171735.png)

7. **What Remote Access Trojan did the Lazarus Group use in Operation Dream Job?**
According to the same reference, the Lazarus Group used a remote access trojan named `DRATzarus`.

![image seven](./Images/Pasted%20image%2020250831171818.png)

8. **What technique did the malware use for execution?**
Navigating to the MITRE [link](https://attack.mitre.org/software/S0694/) associated with DRATzarus, we can see that the malware utilized `Native API`.

![image eight](./Images/Pasted%20image%2020250831171926.png)

9. **What technique did the malware use to avoid detection in a sandbox?**
According to the DRATzarus resource, the technique used to avoid detection was `Time Based Evasion`.

![image nine](./Images/Pasted%20image%2020250831172009.png)

10. **To answer the remaining questions, utilize VirusTotal and refer to the IOCs.txt file. What is the name associated with the first hash provided in the IOC file?**
Putting the hash into VirusTotal, it appears to be named `IEXPLORE.EXE`.

![image ten](./Images/Pasted%20image%2020250831174251.png)

11. **When was the file associated with the second hash in the IOC first created?**
According to VirusTotal's Details tab for this hash, its creation timestamp is `2020-05-12 19:26:17 UTC`.

![image eleven](./Images/Pasted%20image%2020250831174407.png)

12. **What is the name of the parent execution file associated with the second hash in the IOC?**
According to VirusTotal's Relations tab, the parent execution file associated with this file is `BAE_HPC_SE.iso`.

![image twelve](./Images/Pasted%20image%2020250831174901.png)

13. **Examine the third hash provided. What is the file name likely used in the campaign that aligns with the adversary's known tactics?**
According to the Community tab on VirusTotal, this hash belongs to a file used by the Lazarus Group.

![image thirteen](./Images/Pasted%20image%2020250831175129.png)

Viewing the [link](https://www.threatdown.com/blog/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/) provided, we can see two possible file names, the correct answer being `Salary_Lockheed_Martin_job_opportunities_confidential.doc`.

![image fourteen](./Images/Pasted%20image%2020250831175205.png)

14. **Which URL was contacted on 2022-08-03 by the file associated with the third hash in the IOC file?**
Viewing the Relations tab in VirusTotal for this third, we can see the URL associated with this timestamp is `https://markettrendingcenter.com/1k_job_oppor.docx`.

![image fifteen](./Images/Pasted%20image%2020250831175421.png)