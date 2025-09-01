# HTB Sherlock: UFO-1
![htb logo](./Images/htb_logo.png)

| Date          | Author          | Difficulty | Challenge Type      |
| ------------- | --------------- | ---------- | ------------------- |
| 2025-09-01 | Andrew McKenzie | Very Easy  | Threat Intelligence |

---
## Description
This challenge serves as a practical assessment of threat intelligence skills, specifically focusing on the research and analysis of an Advanced Persistent Threat (APT) group. The objective is to use the MITRE ATT&CK framework to gather detailed information about the Sandworm Team (also known as the BlackEnergy Group and APT44), including their history, techniques, tools, and notable campaigns.
## Scenario
Being in the ICS industry, your security team always needs to be up to date and should be aware of the threats targeting organizations in your industry. You just started as a threat intelligence intern, with a bit of SOC experience. Your manager has given you a task to test your skills in research and how well you can utilize MITRE ATT&CK to your advantage. Do your research on the Sandworm Team, also known as the BlackEnergy Group and APT44. Utilize MITRE ATT&CK to understand how to map adversary behavior and tactics in actionable form. Smash the assessment and impress your manager, as threat intelligence is your passion.
## Artifacts Provided
N/A
## Skills Learned
* Researching threat actor groups and their Tactics, Techniques, and Procedures (TTPs). 
* Navigating and utilizing the MITRE ATT&CK framework for threat intelligence gathering. 
* Mapping adversary behaviors and tools to specific MITRE ATT&CK IDs. 
* Analyzing the details of historical cyber campaigns against critical infrastructure. 
* Identifying specific malware, tools, and vulnerabilities associated with an APT group.
## Initial Analysis
The investigation begins by navigating to the MITRE ATT&CK website and locating the page for the threat group **Sandworm Team (G0034)**. The information required to answer the questions is found by carefully reviewing the group's description, associated techniques, software, and the references detailing their historical campaigns, particularly the 2016 and 2022 attacks against Ukrainian infrastructure. Each question requires searching for specific keywords like malware names, dates, or techniques within the provided MITRE ATT&CK resources.
## Questions:
1. **According to the sources cited by Mitre, in what year did the Sandworm Team begin operations?**
Looking at the MITRE [website](https://attack.mitre.org/groups/G0034/) for the Sandworm Team, they state that they have been active since at least `2009`.

![image one](./Images/Pasted%20image%2020250901170230.png)

2. **Mitre notes two credential access techniques used by the BlackEnergy group to access several hosts in the compromised network during a 2016 campaign against the Ukrainian electric power grid. One is LSASS Memory access (T1003.001). What is the Attack ID for the other?**
According to the layers view, the other credential access attack that was performed was `T1110`, brute-force.

![image two](./Images/Pasted%20image%2020250901170836.png)

3. **During the 2016 campaign, the adversary was observed using a VBS script during their operations. What is the name of the VBS file?**
Reviewing the 2016 campaign information page, we can see that the VBS script in question is `ufn.vbs`.

![image three](./Images/Pasted%20image%2020250901171023.png)

4. **The APT conducted a major campaign in 2022. The server application was abused to maintain persistence. What is the Mitre Att&ck ID for the persistence technique was used by the group to allow them remote access?**
Reviewing the 2022 campaigns layer view, the persistence techniques all point to a web shell being their persistence technique `T1505.003`.

![image four](./Images/Pasted%20image%2020250901171237.png)

5. **What is the name of the malware / tool used in question 4?**
Reviewing the 2022 campaign information page, we can see that the reference to webshell mentions the tool deployed was `Neo-REGEORG`.

![image five](./Images/Pasted%20image%2020250901171339.png)

6. **Which SCADA application binary was abused by the group to achieve code execution on SCADA Systems in the same campaign in 2022?**
Sticking with the 2022 campaign's information page, we can see that the only executable mentioned with SCADA, in multiple locations, is `scilc.exe`.

![image six](./Images/Pasted%20image%2020250901171506.png)

7. **Identify the full command line associated with the execution of the tool from question 6 to perform actions against substations in the SCADA environment.**
Sticking with the same 2022 information page, we can see that the command that was issued against substations was `C:\sc\prog\exec\scilc.exe -do pack\scil\s1.txt`.

![image seven](./Images/Pasted%20image%2020250901171602.png)

8. **What malware/tool was used to carry out data destruction in a compromised environment during the same campaign?**
Searching for destruction-level items, we can see that the program in question was `CaddyWiper`.

![image eight](./Images/Pasted%20image%2020250901171650.png)

9. **The malware/tool identified in question 8 also had additional capabilities. What is the Mitre Att&ck ID of the specific technique it could perform in Execution tactic?**
While there are many capabilities listed for this application, the one this particular question is looking for is `T1106`, which is CaddyWiper's ability to utilize native APIs like `SeTakeOwnershipPrivilege`.

![image nine](./Images/Pasted%20image%2020250901172000.png)

10. **The Sandworm Team is known to use different tools in their campaigns. They are associated with an auto-spreading malware that acted as a ransomware while having worm-like features .What is the name of this malware?**
If you search specifically for ransomware, you will find a reference to `notpetya` in the references section.

![image ten](./Images/Pasted%20image%2020250901172205.png)

11. **What was the Microsoft security bulletin ID for the vulnerability that the malware from question 10 used to spread around the world?**
The security bulletin ID can be found by reading the reference from the last question. The ID is `MS17-010`.

![image eleven](./Images/Pasted%20image%2020250901172353.png)

12. **What is the name of the malware/tool used by the group to target modems?**
Returning to the Sandworm group's information page and searching for “modem,” we can find a reference to `AcidRain` in the references section.

![image twelve](./Images/Pasted%20image%2020250901172456.png)

13. **Threat Actors also use non-standard ports across their infrastructure for Operational-Security purposes. On which port did the Sandworm team reportedly establish their SSH server for listening?**
Reviewing the same information page and searching for SSH, we will eventually see the tactic of using non-standard ports. In this case they utilized `6789`.

![image thirteen](./Images/Pasted%20image%2020250901172601.png)

14. **The Sandworm Team has been assisted by another APT group on various operations. Which specific group is known to have collaborated with them?**
This information can be found in the introductory paragraph of the group's information page. It is `APT28` or GRU Unit 26165.

![image fourteen](./Images/Pasted%20image%2020250901172800.png)