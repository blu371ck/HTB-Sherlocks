# HTB Sherlock: Operation Blackout 2025: Smoke & Mirrors
![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-08-31 | Andrew McKenzie | Very Easy  | DFIR           |

---
## Description
This challenge focuses on identifying defense evasion techniques within a compromised system. The analyst must examine a combination of PowerShell and Sysmon logs to uncover how an attacker disabled or manipulated critical security controls like LSA Protection, Windows Defender, AMSI, and PowerShell command history logging to operate without being detected.
## Scenario
Byte Doctor Reyes is investigating a stealthy post-breach attack where several expected security logs and Windows Defender alerts appear to be missing. He suspects the attacker employed defense evasion techniques to disable or manipulate security controls, significantly complicating detection efforts. Using the exported event logs, your objective is to uncover how the attacker compromised the system's defenses to remain undetected.
## Artifacts Provided
- Smoke-and-Mirrors.zip
	- Microsoft-Windows-Powershell-Operational.evtx
	- Microsoft-Windows-Powershell.evtx
	- Microsoft-Windows-Sysmon-Operational.evtx

| Filename                                      | Algorithm | Hash                                                             |
| --------------------------------------------- | --------- | ---------------------------------------------------------------- |
| Microsoft-Windows-Powershell-Operational.evtx | SHA256    | AFF7286F5ADD8D63F306F927D32F857A3CA8DD5AD4147C3BE4273E7A7017A348 |
| Microsoft-Windows-Powershell-Operational.evtx | SHA1      | 76A5D5E6F9BF777D58848BE83DEC4A575CDEDC03                         |
| Microsoft-Windows-Powershell-Operational.evtx | MD5       | F0998FB2B11B8084B6491FB5EC89E20E                                 |
| Microsoft-Windows-Powershell                  | SHA256    | FD0391939810806A2518008B77EDF719B17F55D9AF826329FA1A6310AB00FF41 |
| Microsoft-Windows-Powershell                  | SHA1      | 8E16679E4F173B9FE6E3ACCC41AAC291DECF90F8                         |
| Microsoft-Windows-Powershell                  | MD5       | 256D0BBF9C216189D91D90B43612FF90                                 |
| Microsoft-Windows-Sysmon-Operational          | SHA256    | C1BD14FDF13FB4D64A85FEAD50FB200CCC6F369389DB08DB51477185DEEDBECF |
| Microsoft-Windows-Sysmon-Operational          | SHA1      | 268B47F7D2EB0501378AD55684D6E1ED5FED44E4                         |
| Microsoft-Windows-Sysmon-Operational          | MD5       | 39F547FCCA7910F04AD83FEAC975E173                                 |
## Skills Learned
- Analyzing PowerShell classic, operational, and Sysmon logs.
- Correlating attacker activity across multiple log sources.
- Identifying common defense evasion techniques.
- Recognizing commands used to disable Windows Defender (`Set-MpPreference`).
- Deconstructing AMSI bypass scripts from script block logs (**Event ID 4104**).
- Identifying system utility abuse (`bcdedit.exe`) for evasion.
- Detecting anti-forensics, such as disabling command history (`Set-PSReadlineOption`).
## Initial Analysis
The investigation begins with three distinct event logs. A successful analysis will require pivoting between them to build a complete picture of the attacker's actions. 
- **`Microsoft-Windows-Powershell.evtx`**: The classic log, useful for finding high-level command executions. 
- **`Microsoft-Windows-Powershell-Operational.evtx`**: The modern log containing detailed script block logs (**Event ID 4104**), which is critical for viewing the full content of executed scripts. 
- **`Microsoft-Windows-Sysmon-Operational.evtx`**: Provides deep system visibility, including process creation (**Event ID 1**), registry modifications (**Event ID 13**), and more. Our strategy is to use keyword searches for terms like “disable”, “defender”, “amsi”, and “history” across all three logs to find evidence of defense evasion.
## Questions:
1. **The attacker disabled LSA protection on the compromised host by modifying a registry key. What is the full path of that registry key?**
The registry key that is used to disable/enable LSA is located at `HKLM\System\CurrentControlSet\Control\Ls`.

2. **Which PowerShell command did the attacker first execute to disable Windows Defender?**
We can review the `Microsoft-Windows-Powershell.evtx` event logs and filter by `DisableRealtimeMonitoring`. This returns three results, and as the question asks for the first item, we can review the earliest log and see the command `Set-MpPreference -DisableIOAVProtection $true -DisableEmailScanning $true -DisableBlockAtFirstSeen $true`.

![image one](./Images/Pasted%20image%2020250831161605.png)

3. **The attacker loaded an AMSI patch written in PowerShell. Which function in the DLL is being patched by the script to effectively disable AMSI?**
Switching to `Microsoft-Windows-Powershell-Operational` logs, we can first filter by event code 4104. We can then utilize the search functionality for `GetProcAddress`, `VirtualProtect`, `Marshal.Copy` or anything with `amsi` in the description. Searching with `GetProceAddress` returns a useful result. Reviewing the contents, we can see the function attempting to be patched by the script is `AmsiScanBuffer`.

![image two](./Images/Pasted%20image%2020250831162652.png)

4. **Which command did the attacker use to restart the machine in Safe Mode?**
We can review `Microsoft-Windows-Sysmon-Operational` logs and filter by the keyword `safe`. Scrolling through the details of the first result, we can see the command issued was `bcdedit.exe /set safeboot network`.

![image three](./Images/Pasted%20image%2020250831162922.png)

5. **Which PowerShell command did the attacker use to disable PowerShell command history logging?**
We can move back to `Microsoft-Windows-Powershell-Operational` logs and filter for the keyword `HistorySaveStyle`. The second result contains the command `Set-PSReadlineOption -HistorySaveStyle SaveNothing`.

![image four](./Images/Pasted%20image%2020250831163109.png)