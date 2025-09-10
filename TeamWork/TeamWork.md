# HTB Sherlock - TeamWork

![htb logo](./Images/htb_logo.png)

| Date          | Author          | Difficulty | Challenge Type      |
| ------------- | --------------- | ---------- | ------------------- |
| 2025-09-10 | Andrew McKenzie | Easy       | Threat Intelligence |

---
## Description
This challenge is a Cyber Threat Intelligence (CTI) investigation that begins with a single suspicious email. The objective is to use Open-Source Intelligence (OSINT) techniques to analyze the email, its sender, and associated infrastructure. The investigation expands to profile the threat actor, map their actions to the MITRE ATT&CK framework, and uncover Indicators of Compromise (IOCs) from their broader campaigns.
## Scenario
It is Friday afternoon and the SOC at Edny Consulting Ltd has received alerts from the workstation of Jason Longfield, a software engineer on the development team, regarding the execution of some discovery commands. Jason has just gone on holiday and is not available by phone. The workstation appears to have been switched off, so the only evidence we have at the moment is an export of his mailbox containing today's messages. As the company was recently the victim of a supply chain attack, this case is being taken seriously and the Cyber Threat Intelligence team is being called in to determine the severity of the threat.
## Artifacts Provided
- TeamWork.zip

| File Name    | Algorithm | Hash                                                             |
| ------------ | --------- | ---------------------------------------------------------------- |
| TeamWork.zip | SHA256    | d48793ce17f4ffe349d66b3941c995d82a03dfddb4cd5bd4764898aa9704941d |
| TeamWork.zip | SHA1      | 6e00213e9620d4e4dd9dd66b1bc4c17506ad4b5c                         |
| TeamWork.zip | MD5       | fda83bc46c02e8e4489dd5b4ce8c8930                                 |
## Skills Learned
- **Open-Source Intelligence (OSINT):** Using public tools like Whois databases, the Internet Archive, and search engines to investigate domains, social media profiles, and historical website content.
- **Threat Actor Profiling:** Attributing a campaign to a specific threat actor (**Moonstone Sleet**) by pivoting from technical indicators (file hashes) to security vendor reports.
- **MITRE ATT&CK Mapping:** Identifying and mapping adversary tactics, techniques, and procedures (TTPs) to the ATT&CK framework, from initial resource development to execution.
- **Indicator of Compromise (IOC) Analysis:** Extracting and documenting IOCs—such as domains, file hashes, IP addresses, and malicious package names—from technical write-ups.
- **Alias Correlation:** Linking different names for the same threat actor (`Moonstone Sleet`, `Stressed Pungsan`) used by various security researchers.
## Initial Analysis
The investigation began with the analysis of a suspicious email received by the employee. The email, from **`theodore.todtenhaupt@developingdreams.site`**, presented a collaboration offer for a game project.
1. **Infrastructure Analysis:** An OSINT investigation into the sender's domain revealed it was recently created (**January 31st, 2025**), a common tactic for phishing campaigns (**T1583.001**). The threat actor also established a corresponding social media presence on X (formerly Twitter) to build a seemingly legitimate front (**T1585.001**).
2. **Payload Staging:** The email contained a link to a file. Using the Internet Archive to safely access the historical version of the linked website, the project was identified as a game called **`DeTankWar`**. The malicious executable was downloaded from this archived page, and its **SHA-256 hash** was calculated. The act of hosting this malware on their own infrastructure corresponds to **T1608.001**.
3. **Threat Actor Attribution:** A search for the executable's hash on VirusTotal led to a Microsoft security article. This article attributed the activity to **Moonstone Sleet**, a threat actor associated with **North Korea**. The report also noted the group's use of trojanized software like **PuTTY** (**T1195.002**).
4. **Campaign Correlation:** Further research on Moonstone Sleet uncovered a DataDog article detailing a supply chain attack targeting **npm** packages. This campaign, attributed to an alias "Stressed Pungsan," shared TTPs with Moonstone Sleet.
5. **IOC Extraction:** From the DataDog article, additional IOCs were gathered, including the last malicious package published (**`harthat-hash v1.3.3`**) and a C2 server IP address (**`142.111.77.196`**). The article also described the final payload execution method, which maps to **T1218.011** (System Binary Proxy Execution: Rundll32).
## Questions:
1. **Identify the sender of the suspicious email.**
Reviewing the content of the different email messages, the attacker was likely the fictitious game development company. Specifically because the link provided in the email is a direct link to a ZIP file. The email address is `theodore.todtenhaupt@developingdreams.site`.

![image one](./Images/Pasted%20image%2020250910174153.png)


2. **The suspicious email came from a custom domain, identify its creation date.**
Utilizing [whoxy](https://www.whoxy.com/developingdreams.site) we can see that this domain was set up on `January 31st of 2025`.

![image two](./Images/Pasted%20image%2020250910174420.png)

3. **The domain was registered shortly before the suspicious email was received, which likely corresponds to the time when the threat actor was planning this campaign. Which MITRE ATT&CK sub-technique of the Resource Development tactic corresponds to this activity?**
The technique from MITRE regarding acquiring infrastructure to lead a phishing campaign is `T1583.001`. [Source](https://attack.mitre.org/techniques/T1583/001/)

4. **The previously identified domain appears to belong to a company, what is the full URL of the company's page on X (formerly Twitter)?**
The answer to this question is `https://x.com/Develop_Dreams`

5. **Reading the suspicious email carefully, it appears that the threat actor first contacted the victim using the previously identified social media profile. Which MITRE ATT&CK sub-technique of the Resource Development tactic corresponds to this activity?**
The MITRE ATT&CK tactic for this is `T1585.001`. [Source](https://attack.mitre.org/techniques/T1585/001/)

6. **What is the name of the game the threat actor would like us to collaborate on?**
You have to utilize the Internet Archive to access the site from back in February. The name of the game is `DeTankWar`.

![image three](./Images/Pasted%20image%2020250910175608.png)

7. **What is the SHA-256 hash of the executable shared by the threat actor?**
You have to utilize the Internet Archive to access the link that is embedded in the email. Once there, you get the ZIP file. The SHA256 hash of the executable is `56554117d96d12bd3504ebef2a8f28e790dd1fe583c33ad58ccbf614313ead8c`.

![image four](./Images/Pasted%20image%2020250910175903.png)

8. **As part of the preparation of the tools for the attack, the threat actor hosted this file, presumably malware, on its infrastructure. Which MITRE ATT&CK sub-technique of the Resource Development tactic corresponds to this activity?**
The MITRE ATT&CK technique for staging malware on your infrastructure is `T1608.001`. [Source](https://attack.mitre.org/techniques/T1608/001/)

9. **Based on the information you have gathered so far, do some research to identify the name of the threat actor who may have carried out this attack.**
Reviewing VirusTotal community posts, an article provided by Microsoft points at `Moonstone Sleet`.

![image five](./Images/Pasted%20image%2020250910180509.png)

10. **What nation is the threat actor believed to be associated with?**
According to the Microsoft article form the previous question, the nation state is `North korea`.

![image six](./Images/Pasted%20image%2020250910180644.png)

11. **Another campaign from this threat actor used a trojanized version of a well-known software to infect victims. What is the name of this tool?**
The article states that one such item is `PuTTY`.

![image seven](./Images/Pasted%20image%2020250910180748.png)

12. **Which MITRE ATT&CK technique corresponds to the activity of deploying trojanized/manipulated software?**
The MITRE ATT&CK technique for manipulating normal software to hide malicious code is `T1195.002`. [Source](https://attack.mitre.org/techniques/T1195/002/)

13. **Our company wants to protect itself from other supply chain attacks, so in documenting more about this threat actor, the CTI team found that other security researchers were also tracking a group whose techniques closely match Moonstone Sleet, and discovered a new supply chain campaign around the end of July 2024. What technology is this campaign targeting?**
This was an interesting find. I had to Google a couple of different ways to find the correct answer. But if you search “moonstone sleet supply chain attack,” a couple of articles down is a DataDog article. This article states a group named “Stressed Pungsan.” The article states, “…sets align closely with what Microsoft calls MOONSTONE SLEET…” [source](https://securitylabs.datadoghq.com/articles/stressed-pungsan-dprk-aligned-threat-actor-leverages-npm-for-initial-access/). This article states the technology used was `npm`.

![image eight](./Images/Pasted%20image%2020250910181937.png)


14. **We now need some indicators to be able to rule out that other systems have been compromised. What is the name and version of the lastest malicious package published? (Format: package-name vX.X.X)**
The article provided in the last question provides the latest version (as of July 7th) as `harthat-hash v1.3.3`.

![image nine](./Images/Pasted%20image%2020250910182031.png)

15. **The malicious packages downloaded an additional payload from a C2 server, what is its IP address?**
The C2 server IP address is listed in the same article. It is `142.111.77.196`

![image ten](./Images/Pasted%20image%2020250910182109.png)

16. **The payload, after being renamed, is finally executed by a legitimate Windows binary to evade defenses. Which MITRE ATT&CK technique corresponds to this activity?**
The same article provides a link to MITRE ATT&CK technique `T1218.011`. [Source](https://attack.mitre.org/techniques/T1218/011/)

![image eleven](./Images/Pasted%20image%2020250910182401.png)