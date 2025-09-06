# HTB Sherlock - Campfire-1

![htb logo](./Images/htb_logo.png)

| Date | Author          | Difficulty | Challenge Type |
| ---- | --------------- | ---------- | -------------- |
| 2025-09-06 | Andrew McKenzie | Very Easy  | DFIR           |

---
## Description
This challenge involves analyzing artifacts from a suspected Kerberoasting attack. The primary goal is to use Domain Controller security logs, workstation PowerShell logs, and Prefetch files to confirm the attack, identify the tools used, and establish a timeline of events.
## Scenario
Alonzo Spotted Weird files on his computer and informed the newly assembled SOC Team. Assessing the situation it is believed a Kerberoasting attack may have occurred in the network. It is your job to confirm the findings by analyzing the provided evidence. You are provided with: 1- Security Logs from the Domain Controller 2- PowerShell-Operational Logs from the affected workstation 3- Prefetch Files from the affected workstation
## Artifacts Provided
- campfire-1.zip
- Domain Controller
	- `SECURITY-DC.evtx`
- Workstation
	- `Powershell-Operational.evtx`
	- 2024-05-21T033012_triage_asset/

| Filename/Path                   | Algorithm | Hash                                                             |
| ------------------------------- | --------- | ---------------------------------------------------------------- |
| `SECURITY-DC.evtx`              | SHA256    | 5242D1CB346BE62E2DF1FDF8528A9F47C29D144C10B109FB459C916AF60A3B45 |
| `SECURITY-DC.evtx`              | SHA1      | B8E4C846879162DAEB0853ED06964EB108893175                         |
| `SECUIRTY-DC.evtx`              | MD5       | 93D1A6B2B1E94E3CFB06E3C94FDE9A5A                                 |
| `Powershell-Operational.evtx`   | SHA256    | EC9E735BB383FC2443A114F94AE5C40A39C8A285BCA67E7A8218F1EB0A6DA0E4 |
| `Powershell-Operational.evtx`   | SHA1      | AB6553B4AEF5D321076BA49BC73A072965FD880A                         |
| `Powershell-Operational.evtx`   | MD5       | A6FA6D20B9887AF4389CA80C2648DDAE                                 |
| 2024-05-21T033012_triage_asset/ | SHA256    | [Data](./Data/hashes.csv)                                 |

## Skills Learned
- **Windows Event Log Analysis:** Analyzing Security (`SECURITY.evtx`) and PowerShell Operational (`Powershell-Operational.evtx`) logs to trace attacker activity.
- **Kerberoasting Detection:** Identifying a Kerberoasting attack by filtering for Event ID `4769` and looking for specific indicators, such as a weak encryption type like `0x17` (RC4-HMAC).
- **PowerShell Script Analysis:** Reconstructing and identifying malicious PowerShell scripts (`PowerView.ps1`) used for Active Directory reconnaissance.
- **Prefetch File Analysis:** Examining Prefetch files to identify the execution of attacker tools (`RUBEUS.EXE`) and determine their last run times.
- **Timeline Correlation:** Correlating timestamps across different artifacts (event logs, prefetch files) to build a comprehensive timeline of an attack.
## Initial Analysis
The investigation began with the Domain Controller's security logs (`SECURITY-DC.evtx`). By filtering for Event ID `4769` (A Kerberos service ticket was requested), a specific event stood out. This event showed a ticket request for the `MSSQLService` with an encryption type of `0x17`, which is indicative of a Kerberoasting attack. This log entry confirmed the time of the attack and identified the source IP address of the compromised workstation.

Next, the focus shifted to the provided workstation artifacts. Analysis of the PowerShell operational logs (`Powershell-Operational.evtx`) revealed the execution of `PowerView.ps1`, a well-known Active Directory enumeration script. The logs showed the script being loaded and executed just moments before the Kerberoasting event on the Domain Controller, indicating it was used for reconnaissance.

Finally, an examination of the Prefetch files from the workstation triage data confirmed the use of the tool `RUBEUS.EXE`. The last execution time of `RUBEUS.EXE` corresponded almost exactly with the Event ID `4769` on the Domain Controller, confirming it was the tool used to perform the Kerberoasting attack and request the service ticket.
## Questions:
1. **Analyzing Domain Controller Security Logs, can you confirm the date & time when the kerberoasting activity occurred?**
We need to look for several things. We need to look at the `SECURITY.evtx` logs from the DC, filtering for event code `4769` as well as review the results to find: 
- A non-standard service name `krbtgt` or `DCXX$`. 
- An encryption type [0×17](https://redcanary.com/blog/threat-detection/marshmallows-and-kerberoasting/) 
With those in mind, we find the most likely candidate with a time of `2024-05-21 03:18:09`.

![image one](./Images/Pasted%20image%2020250906153127.png)

2. **What is the Service Name that was targeted?**
Reviewing the same finding, we can answer this by providing the Service Name value of `MSSQLService`.

![image two](./Images/Pasted%20image%2020250906153252.png)

3. **It is really important to identify the Workstation from which this activity occurred. What is the IP Address of the workstation?**
This information is also included in the same finding. The IP address is `172.17.79.129`.

![image three](./Images/Pasted%20image%2020250906153349.png)

4. **Now that we have identified the workstation, a triage including PowerShell logs and Prefetch files are provided to you for some deeper insights so we can understand how this activity occurred on the endpoint. What is the name of the file used to Enumerate Active directory objects and possibly find Kerberoastable accounts in the network?**
Moving to the `Powershell-Operational.evtx` logs, we can see the first warning (chronologically) includes the script being used as `PowerView.ps1`.

![image four](./Images/Pasted%20image%2020250906153620.png)

5. **When was this script executed?**
We want to look where "Category" is "Execute a Remote Command". Fortunately, shortly after the event we found from the question above, we see many "Execute a Remote Command" category events, all pertaining to the same execution. The script block takes 20 events to fully capture. This is definitely `PowerView.ps1` being loaded and utilized. The time it starts is at `2024-05-21T03:16:32`.

![image five](./Images/Pasted%20image%2020250906153957.png)

6. **What is the full path of the tool used to perform the actual kerberoasting attack?**
After creating a CSV file for Timeline explorer we see there is only 200 results (roughly). So, we can just visually inspect the "Executable Name" column for common tooling used for this purpose. We find `RUBEUS.EXE`.

![image six](./Images/Pasted%20image%2020250906154639.png)

7. **When was the tool executed to dump credentials?**
Reviewing to the right of the "Executable Name" column we find the "Last Run" column. It shows the last runtime was `2024-05-21 03:18:08`.