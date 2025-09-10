# HTB Sherlock - LogJammer

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-10 | Andrew McKenzie | Easy       | DFIR           |

---
## Description
This challenge is a Digital Forensics and Incident Response (DFIR) exercise focused on **Windows Event Log Analysis**. The objective is to investigate the provided event logs to trace the activities of a user named "Cyberjunkie" who is suspected of performing malicious actions after logging into a Windows system. The analysis involves examining security, firewall, antivirus, and PowerShell logs to answer specific questions about the user's behavior.
## Scenario
You have been presented with the opportunity to work as a junior DFIR consultant for a big consultancy. However, they have provided a technical assessment for you to complete. The consultancy Forela-Security would like to gauge your Windows Event Log Analysis knowledge. We believe the Cyberjunkie user logged in to his computer and may have taken malicious actions. Please analyze the given event logs and report back.
## Artifacts Provided
- logjammer.zip
	- Event-Logs
		- Powershell-Operational.evtx
		- Security.evtx
		- System.evtx
		- Windows-Defender-Operational.evtx
		- Windows-Firewall-Firewall.evtx

| Filename                          | Algorithm | Hash                                                             |
| --------------------------------- | --------- | ---------------------------------------------------------------- |
| Powershell-Operational.evtx       | SHA256    | AA6A620BB16E34433395D0F3BB6A99F29FEC22414D9796E02090C1106412CA35 |
| Powershell-Operational.evtx       | SHA1      | CD557CF1CD95DFA6AD47E3DE81B60A73213C9D36                         |
| Powershell-Operational.evtx       | MD5       | 6739802C74ADC7BF6432DFCEC853397C                                 |
| Security.evtx                     | SHA256    | 83979AD971FA5D3646BF30655E81F3E4F6D0E31C0BEC694B33C22E5E593162AA |
| Security.evtx                     | SHA1      | B974B9532CD736013226AFEA09440E25C1C5789D                         |
| Security.evtx                     | MD5       | 5B75F867D2107D04721CCAEEA7914CFD                                 |
| System.evtx                       | SHA256    | 0CFF977D864705027774815E0255C99C4E21E9919F663B5F5D4BC52FC651E7F3 |
| System.evtx                       | SHA1      | A45987211C71C375958F0509316A2332829BDA94                         |
| System.evtx                       | MD5       | 34B0D7A505C880A8AE78405D581B2B1A                                 |
| Windows-Defender-Operational.evtx | SHA256    | 9DDEB039F6A730DFEA5463D5EFD5DDF38A6234E3FBA16CD96EE397C5A247971C |
| Windows-Defender-Operational.evtx | SHA1      | DFF99ACCCDC7B664C033C3D655D1E5C686E34CD8                         |
| Windows-Defender-Operational.evtx | MD5       | A2F06FAAD866AC054705643B0E2C2364                                 |
| Windows-Firewall-Firewall.evtx    | SHA256    | 898085C98B75E12FE3483EF11E4BCB6E6F9BD999E357493C43D804B297D53F67 |
| Windows-Firewall-Firewall.evtx    | SHA1      | 9D78E0FFC3BCB0D4AC7020A66744C4D35FBBEB41                         |
| Windows-Firewall-Firewall.evtx    | MD5       | 7FF34616822BAA259A8179ED3677173A                                 |
## Skills Learned
This investigation demonstrates proficiency in several key areas of Windows forensics:
- **User Logon Analysis**: Identifying successful logon events (Event ID 4624) to establish a timeline of user activity.
- **Firewall Configuration Auditing**: Analyzing firewall logs to detect the creation of suspicious outbound rules.
- **Audit Policy Monitoring**: Tracking changes to system audit policies (Event ID 4719) that could indicate an attempt to evade detection.
- **Scheduled Task Forensics**: Examining security logs for the creation of scheduled tasks (Event ID 4698) to uncover persistence mechanisms.
- **Antivirus Log Review**: Parsing Windows Defender logs to identify detected threats, their locations, and the actions taken by the AV software.
- **PowerShell Command Line Auditing**: Reviewing PowerShell operational logs to reconstruct commands executed by a user.
- **Log Tampering Detection**: Identifying events that indicate logs have been cleared (System Event ID 104) to hide malicious activity.
## Initial Analysis
The investigation began by establishing the user's initial point of access. By filtering the **Security.evtx** log for **Event ID 4624** (An account was successfully logged on), we determined the first time the `CyberJunkie` user logged into the machine.

Following this, an analysis of the user's actions revealed several signs of malicious intent. A review of the **Windows-Firewall-Firewall.evtx** logs uncovered a new outbound rule named `Metasploit C2 Bypass`, suggesting an attempt to establish a command-and-control channel. The user also tampered with the system's audit policy, specifically the `Other Object Access Events` subcategory, as evidenced by **Event ID 4719** in the security logs.

Further investigation of the security logs for **Event ID 4698** (A scheduled task was created) revealed a task named `HTB-AUTOMATION` designed to run a PowerShell script, `Automation-HTB.ps1`. The **Powershell-Operational.evtx** log confirmed that the user executed a `Get-FileHash` command on this same script.

The **Windows-Defender-Operational.evtx** log showed that the antivirus software detected and quarantined a threat, `SharpHound`, from the user's downloads folder. Finally, evidence of covering tracks was found in the **System.evtx** log, where **Event ID 104** indicated that the `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` log file had been cleared.
## Questions:
1. **When did the cyberjunkie user first successfully log into his computer? (UTC)**
We can utilize the name provided in the question as well as the security logs event ID 4624 to find this answer. The answer is `2023-03-27 14:37:09`.

![image one](./Images/Pasted%20image%2020250910130145.png)

2. **The user tampered with firewall settings on the system. Analyze the firewall event logs to find out the Name of the firewall rule added?**
Reviewing the Windows Firewall logs, we can see one of the most recent entries is named `Metasploit C2 Bypass`.

![image two](./Images/Pasted%20image%2020250910130750.png)

3. **Whats the direction of the firewall rule?**
The direction of this rule is listed as 2. Which is `outbound`.

![image three](./Images/Pasted%20image%2020250910130956.png)

4. **The user changed audit policy of the computer. Whats the Subcategory of this changed policy?**
Filtering security events for event ID 4719, we see only one result. The subcategory is listed as `Other Object Access Events`.

![image four](./Images/Pasted%20image%2020250910131148.png)

5. **The user "cyberjunkie" created a scheduled task. Whats the name of this task?**
We can filter the security event logs for ID 4698. Confirming the account name, we see only one entry. The name of the task is `HTB-AUTOMATION`.

![image five](./Images/Pasted%20image%2020250910131308.png)

6. **Whats the full path of the file which was scheduled for the task?**
Scrolling down on the same event, we can see the full file path is `C:\Users\CyberJunkie\Desktop\Automation-HTB.ps1`.

![image six](./Images/Pasted%20image%2020250910131348.png)

7. **What are the arguments of the command?**
Directly below the previous question's answer, we see this question's answer: `-A cyberjunkie@hackthebox.eu`.

![image seven](./Images/Pasted%20image%2020250910131433.png)

8. **The antivirus running on the system identified a threat and performed actions on it. Which tool was identified as malware by antivirus?**
This is a weird question because there were two actual items found and actioned by Defender. One is Meterpreter, and one is SharpHound. The question expects the answer as `SharpHound`.

![image eight](./Images/Pasted%20image%2020250910131643.png)

9. **Whats the full path of the malware which raised the alert?**
Reviewing the same item from the previous question, the file path for this is `C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip`.

![image nine](./Images/Pasted%20image%2020250910131735.png)

10. **What action was taken by the antivirus?**
The action taken by the antivirus was `Quarantine`.

![image ten](./Images/Pasted%20image%2020250910131823.png)

11. **The user used Powershell to execute commands. What command was executed by the user?**
The command run by the user was `Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1`.

![image eleven](./Images/Pasted%20image%2020250910132210.png)

12. **We suspect the user deleted some event logs. Which Event log file was cleared?**
There were two logs cleared, but the answer that is expected is `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`.

![image twelve](./Images/Pasted%20image%2020250910132415.png)