# HTB Sherlock - Psittaciformes

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-12 | Andrew McKenzie | Easy       | DFIR           |

---
## Description
This challenge involves investigating a supply chain compromise on a penetration tester's Linux host. The primary objective is to analyze forensic artifacts from the compromised system to understand how a trojanized version of a legitimate open-source tool was used to gain a foothold. The investigation requires tracing the attacker's steps from the initial script execution to the deployment of the final payload and the establishment of persistence.
## Scenario
Forela carry out penetration testing of their internal networks utilising an internal team within their security department. The security team have notes from tests in addition to company critical credentials. It seems their host may have been compromised. Please verify how this occurred using the retrospective collection provided.
## Artifacts Provided
- Psittaciformes.zip
## Skills Learned
- **Linux Forensics:** Analyzing `.bash_history` to reconstruct user activity.
- **Supply Chain Attack Analysis:** Investigating a compromise originating from a malicious, backdoored tool on GitHub.
- **Code Review & Deobfuscation:** Manually inspecting shell scripts to identify malicious functions and decoding Base64-encoded payloads.
- **Git Forensics:** Using `git log` to examine a repository's commit history to track malicious modifications over time.
- **MITRE ATT&CK Mapping:** Associating attacker TTPs, such as persistence via Cron jobs and impact via cryptomining, with their corresponding technique IDs.
- **OSINT for Threat Intelligence:** Using platforms like VirusTotal to identify malware based on file hashes found in logs.
## Initial Analysis
The investigation into the compromised penetration tester's host revealed a sophisticated supply chain attack originating from a trojanized GitHub repository.
1. **Initial Vector:** Analysis of the user's `.bash_history` showed that the compromise began when the pentester cloned and executed a script from a public GitHub repository for a tool named **`autoenum`**.
2. **Malicious Code:** A review of the tool's source code identified a malicious function named **`do_wget_and_run`**. This function was designed to download a password-protected `.zip` file from a Dropbox URL, unzip it, and execute the contents. The password for the archive, **`superhacker`**, was discovered in two separate Base64-encoded strings within the script.
3. **Repository Analysis:** To understand the history of the malicious code, the repository's Git commit history was analyzed using `git log`. This revealed that on **December 23, 2023**, the attacker removed comments from the malicious function to make it appear less suspicious. The logs also showed that the Dropbox URL had been updated, exposing a previously used C2 link.
4. **Persistence:** The malicious script established persistence by creating a Cron job, a technique that maps to MITRE ATT&CK ID **T1053.003 (Scheduled Task/Job: Cron)**.
5. **Final Payload:** Logs on the system contained the hash of the final payload (`/tmp/blob`). A search on VirusTotal confirmed this file is a cryptominer. This activity aligns with MITRE ATT&CK ID **T1496 (Resource Hijacking)**, where an attacker uses compromised system resources for unauthorized purposes like cryptocurrency mining.
## Questions:
1. **What is the name of the repository utilized by the Pen Tester within Forela that resulted in the compromise of his host?**
We can go to the directory of the only non-root user, and checking their bash history gives multiple possible answers. Going from earliest, the answer is `autoenum`.

![image one](./Images/Pasted%20image%2020250912151746.png)

2. **What is the name of the malicious function within the script ran by the Pen Tester?**
Based on the answers, formatting, and reviewing the GitHub of this application, the item that matches up is `do_wget_and_run`.

![image two](./Images/Pasted%20image%2020250912151936.png)

3. **What is the password of the zip file downloaded within the malicious function?**
In the function's code, we can see the password is split into two parts, both base64 encoded.

![image three](./Images/Pasted%20image%2020250912152034.png)

Putting it back together and decoding it gives us `superhacker`.

![image four](./Images/Pasted%20image%2020250912152126.png)

4. **What is the full URL of the file downloaded by the attacker?**
The full URL can be found by putting the two pieces back together. The answer is `https://www.dropbox.com/scl/fi/uw8oxug0jydibnorjvyl2/blob.zip?rlkey=zmbys0idnbab9qnl45xhqn257&st=v22geon6&dl=1`.

![image five](./Images/Pasted%20image%2020250912152246.png)

5. **When did the attacker finally take out the real comments for the malicious function?**
After cloning the repository, we can utilize `git` command line to find the exact timestamp. Running `git log -p` we can see more details for each commit, and the commit at `2023-12-23 22:27:58` shows comments within the `do_wget_and_run` function.

![image six](./Images/Pasted%20image%2020250912153950.png)

6. **The attacker changed the URL to download the file, what was it before the change?**
Reviewing more commits, we can see the URL used to be `https://www.dropbox.com/scl/fi/wu0lhwixtk2ap4nnbvv4a/blob.zip?rlkey=gmt8m9e7bd02obueh9q3voi5q&st=em7ud3pb&dl=1`.

![image seven](./Images/Pasted%20image%2020250912154203.png)

7. **What is the MITRE technique ID utilized by the attacker to persist?**
The MITRE ATT&CK technique ID for the persistence used in the code (which is a Cron job) is `T1053.003`. [Source](https://attack.mitre.org/techniques/T1053/003/).

![image eight](./Images/Pasted%20image%2020250912154327.png)

8. **What is the Mitre Att&ck ID for the technique relevant to the binary the attacker runs?**
Reviewing the Cron schedules of the users on the system shows the file should be located in `/tmp//blob`, unfortunately that was not provided. We can check to see if it was ever executed and get a hash. Doing a recursive grep for `/tmp/blob` returns results and a potential hash `ea7c97294f415dc8713ac8c280b3123da62f6e56`.

VirusTotal lists this as a miner, which gives us a lead to look at for MITRE.

![image nine](./Images/Pasted%20image%2020250912155410.png)

Doing a quick Google search for “crypto miner MITRE ATT&CK” returns the correct answer, resource hijacking `T1496`. [Source](https://attack.mitre.org/techniques/T1496/).
