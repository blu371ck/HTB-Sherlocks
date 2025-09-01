# HTB SHerlock: Operation Blackout 2025: Phantom Check
![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-08-31 | Andrew McKenzie | Very Easy  | DFIR           |

---
## Description
This challenge focuses on analyzing PowerShell event logs to uncover anti-virtualization techniques used by an attacker. The analyst must trace the attacker's steps, from initial WMI queries to the execution of a full detection script, identifying specific WMI classes, registry keys, and processes the attacker checked to determine if the host was a virtual machine.
## Scenario
Talion suspects that the threat actor carried out anti-virtualization checks to avoid detection in sandboxed environments. Your task is to analyze the event logs and identify the specific techniques used for virtualization detection. Byte Doctor requires evidence of the registry checks or processes the attacker executed to perform these checks.
## Artifacts Provided
- PhantomCheck.zip
	- Microsoft-Windows-Powershell.evtx
	- Windows-Powershell-Operational.evtx

| Filename                            | Algorithm | Hash                                                             |
| ----------------------------------- | --------- | ---------------------------------------------------------------- |
| Microsoft-Windows-Powershell.evtx   | SHA256    | b5f8c3534ae60b3b0534cbc149babdfcec851bd0aa40634cc585ab4b365f903a |
| Microsoft-Windows-Powershell.evtx   | SHA1      | 16127dae4a9ebb7ccda32088e85d2024e84fc6df                         |
| Microsoft-Windows-Powershell.evtx   | MD5       | a39bd903cecb7fe720768a66a9766eac                                 |
| Windows-Powershell-Operational.evtx | SHA256    | a5de8a943cd6ca1a640cfea5d6f748d5e60ab3fd9bcc18ae2636c07be8b80d5e |
| Windows-Powershell-Operational.evtx | SHA1      | faf2e62d274e6373a86a99c8b57a38cb9446d2fa                         |
| Windows-Powershell-Operational.evtx | MD5       | 18a59c5a8d1f489944e0e80b975d0f98                                 |
## Skills Learned
- Analyzing PowerShell operational logs (**Event ID 4104** - Script Block Logging).
- Identifying attacker reconnaissance through WMI queries.
- Deconstructing PowerShell scripts from log data to understand their functionality.
- Recognizing common anti-virtualization and sandbox evasion techniques.
- Pinpointing specific artifacts checked by malware, such as registry keys, running processes, and hardware information.
- Correlating script execution logs with their output logs.
- Using log analysis tools and effective filtering techniques.
## Initial Analysis
The investigation begins with two PowerShell event logs. The primary source of information will be **`Windows-Powershell-Operational.evtx`**, as it contains detailed script block logs (Event ID 4104) that record the actual content of executed commands and scripts. The **`Microsoft-Windows-Powershell.evtx`** log will be useful for viewing the final output of scripts. Our strategy is to first filter the operational log for Event ID 4104 to reconstruct the attacker's actions and then pivot to the other log to see the results of those actions.
## Questions:
1. **Which WMI class did the attacker use to retrieve model and manufacturer information for virtualization detection?**
Utilizing [Event Log Explorer](https://eventlogxp.com/) and opening the two event logs. We can filter down the `Windows-Powershell-Operational.evtx` logs for event code `4104` and for text in the description being `Get-WmiObject`. Viewing the three results, the second item contains `Win32_ComputerSystem`, which is a WMI object that can reveal information about the host, including virtualization.

![image one](./Images/Pasted%20image%2020250831151429.png)

2. **Which WMI query did the attacker execute to retrieve the current temperature value of the machine?**
Keeping on the same filtered results, we can look at the three results, and the first one provides us with our answer. The query was `SELECT * FROM MSAcpi_ThermalZoneTemperature`.

![image two](./Images/Pasted%20image%2020250831151608.png)

3. **The attacker loaded a PowerShell script to detect virtualization. What is the function name of the script?**
Sticking with the same logs in Event Log Explorer, let's remove the filter for `Get-WmiObject`. Now, using find, search for `function` in the text description. Reviewing the results, we can see the function name `Get-VM` mentioned in the logs.

![image three](./Images/Pasted%20image%2020250831152214.png)

4. **Which registry key did the above script query to retrieve service details for virtualization detection?**
Reviewing the same found log entry from question 4. We can scroll through the function and observe its interacting with many registry keys. The question states specifically “service” details, and we eventually find `HKLM:\SYSTEM\ControlSet001\Services` registry key.

![image four](./Images/Pasted%20image%2020250831152509.png)

5. **The VM detection script can also identify VirtualBox. Which processes is it comparing to determine if the system is running VirtualBox?**
Continue to review the function from earlier questions. We can see towards the bottom of the script a section dedicated to fingerprinting VirtualBox. From there we can see that two processes are being investigated for matches: `vboxservice.exe` and `vboxtray.exe`.

![image five](./Images/Pasted%20image%2020250831152903.png)

6. **The VM detection script prints any detection with the prefix 'This is a'. Which two virtualization platforms did the script detect?**
Switching to the Microsoft-Windows-PowerShell logs, we can filter them down using the string provided in the question `This is a`. This should return only one result. Reviewing the result, at the end of the description we see that `Hyper-V` and `VMWare` are tagged.

![image six](./Images/Pasted%20image%2020250831153308.png)