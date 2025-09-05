# HTB Sherlock - CrownJewel-1

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-05 | Andrew McKenzie | Very Easy  | DFIR           |

---
## Description
This challenge focuses on a common attack vector against Windows Domain Controllers: credential dumping. The objective is to analyze a set of artifacts from a compromised DC to trace the attacker's use of the **Volume Shadow Copy service** (`vssadmin`) to create a snapshot and exfiltrate the `NTDS.dit` database. By correlating Windows Event Logs (`.evtx`) and Master File Table (`$MFT`) data, we can build a clear timeline of the incident.
## Scenario
Forela's domain controller is under attack. The Domain Administrator account is believed to be compromised, and it is suspected that the threat actor dumped the NTDS.dit database on the DC. We just received an alert of vssadmin being used on the DC. Since this is not part of the routine schedule, we have good reason to believe that the attacker abused this LOLBIN utility to get the domain environment's crown jewel. Perform some analysis on provided artifacts for a quick triage, and if possible, kick the attacker out as early as possible.
## Artifacts Provided
- CrownJewel.zip
	- `Artifacts\C\$MFT`
	- `Microsoft-Windows-NFTS.evtx`
	- `SECURITY.evtx`
	- `SYSTEM.evtx`

| Filename                      | Algorithm | Hash                                                             |
| ----------------------------- | --------- | ---------------------------------------------------------------- |
| `Artifacts\C\$MFT`            | SHA256    | E22CB3664D76D009F44F1A11A2DF1CAFDEC33F6CE3C8F20EAD0D185FC9AB3D7F |
| `Artifacts\C\$MFT`            | SHA1      | D22EEA88EB8694AC3E7005655E47A3AAD1071941                         |
| `Artifacts\C\$MFT`            | MD5       | 5D85B9D3A41FBF8BC32339BB1D81345E                                 |
| `Microsoft-Windows-NTFS.evtx` | SHA256    | 12C7127971C8D330B656A4D2FBDDE2676BA5783EA316CD838DA8FCA6E69F1639 |
| `Microsoft-Windows-NTFS.evtx` | SHA1      | 3353A8E3BA82C1E0B67664FBE23DE172AEBE7387                         |
| `Microsoft-Windows-NTFS.evtx` | MD5       | 781092ACE092791F4853482CFE29AF2C                                 |
| `SECURITY.evtx`               | SHA256    | C71BED617D69EBE1CA16780B7991EFDD33CAFC48286BC0227F6CE1981E572467 |
| `SECURITY.evtx`               | SHA1      | 3708A82BF1992C6D8C329BBCADFD4B6CE90C0D7D                         |
| `SECURITY.evtx`               | MD5       | 608C12608DB00AC8D2B8F8C0CE270638                                 |
| `SYSTEM.evtx`                 | SHA256    | 02166593936355611B00C653957E019E296CE88A91C17E551C5F74277B893874 |
| `SYSTEM.evtx`                 | SHA1      | 457509CA9A70495997E8C33C8A7A4FA55947F646                         |
| `SYSTEM.evtx`                 | MD5       | 782A3C73BC49BF397FCB0B3D4341395B                                 |
## Skills Learned
- **Windows Event Log Analysis:** Analyzing `SYSTEM`, `SECURITY`, and application-specific logs to trace system and user activity.
- **Filesystem Forensics:** Parsing the `$MFT` to recover file metadata, including timestamps, paths, and size, to identify attacker-created files.
- **Incident Triage:** Using key artifacts to quickly understand the scope of a compromise and identify attacker techniques.
- **TTP Identification:** Recognizing the common attacker technique of using `vssadmin` to bypass file locks and access sensitive system files like `NTDS.dit`.
- **Tool Proficiency:** Using forensic tools such as Event Log Explorer, MFTECmd, and Timeline Explorer for efficient artifact analysis.
## Initial Analysis
The investigation began with the hypothesis that the attacker used the `vssadmin` utility. To confirm this, the analysis focused on correlating events across the provided logs and file system artifacts to build a timeline.
1. **Service Start-up:** I first examined the `SYSTEM.evtx` log, filtering for **Event ID 7036**, which indicates service state changes. This search confirmed that the Volume Shadow Copy service (`vssvc`) entered a running state on **`2024-05-14` at `03:42:16`**, establishing the start of the attack.
2. **Privilege Enumeration:** Next, I pivoted to the `SECURITY.evtx` log and filtered for **Event ID 4799** ("A security-enabled local group membership was enumerated") related to the `vssvc.exe` process. This revealed that the machine account **`DC01$`** enumerated the **`Administrators`** and **`Backup Operators`** groups, likely to validate its permissions before creating the snapshot. The Process ID for this operation was **`4496`**.
3. **Snapshot Mounting:** The `Microsoft-Windows-NTFS.evtx` log provided evidence of the snapshot being mounted. It recorded a successful mount event with the Volume ID **`{06c4a997-cca8-11ed-a90f-000c295644f9}`**.
4. **File System Evidence:** Finally, I analyzed the `$MFT` artifact using `MFTECmd` and Timeline Explorer. By filtering for the filename `NTDS.dit`, I discovered a copy was created at **`2024-05-14 03:44:22`** in a suspicious path: **`\Users\Administrator\Documents\backup_sync_dc`**. Further analysis of this directory showed that the **`SYSTEM`** registry hive, with a size of **`17,563,648` bytes**, was also dumped to the same location. The attacker copied both files because the `SYSTEM` hive is required to decrypt the password hashes contained within `NTDS.dit`.
This analysis confirms the initial alert: the attacker successfully used the Volume Shadow Copy utility to create a snapshot, from which they extracted both the `NTDS.dit` database and the `SYSTEM` registry hive for offline credential cracking.
## Questions:
1. **Attackers can abuse the vssadmin utility to create volume shadow snapshots and then extract sensitive files like NTDS.dit to bypass security mechanisms. Identify the time when the Volume Shadow Copy service entered a running state.**
To find this, we first want to ingest the `.evtx` log files using Event Log Explorer. Once ingested, we can look for event ID `7036` in the SYSTEM logs. We can further reduce the logs down by adding “shadow” to the description. This returns one result, with the answer `2024-05-14T03:42:16`.

![image one](./Images/Pasted%20image%2020250905141532.png)

2. **When a volume shadow snapshot is created, the Volume shadow copy service validates the privileges using the Machine account and enumerates User groups. Find the two user groups the volume shadow copy process queries and the machine account that did it.**
To find this information, we can move over to the SECURITY logs and filter for the event ID `4799`, “A security-enabled local group membership was enumerated.” From there we can further filter down by adding “vssvc.exe” into the description filter. From the results, we can see that the only computer that made requests was `DC01$`, and the only two groups that were enumerated were `Administrators` and `Backup Operators`.

![image two](./Images/Pasted%20image%2020250905142015.png)

![image three](./Images/Pasted%20image%2020250905142027.png)

3. **Identify the Process ID (in Decimal) of the volume shadow copy service process.**
This answer is in the results from the previous question. We can see a process ID field in hexadecimal in the results. Converting this hexadecimal value to decimal equates to `4496`.

![image four](./Images/Pasted%20image%2020250905142238.png)

4. **Find the assigned Volume ID/GUID value to the Shadow copy snapshot when it was mounted.**
To find this information, you need to utilize the NTFS event logs. You can filter for “shadow” in the description to return all results for this. If you look at the first result (chronologically), you will see that it's a successful mount event and the volume correlation ID is `{06c4a997-cca8-11ed-a90f-000c295644f9}`.

![image five](./Images/Pasted%20image%2020250905142534.png)

5. **Identify the full path of the dumped NTDS database on disk.**
To find this, we need to parse the `$MFT` file using `MFTECmd`, this produces a CSV file, which we can then load into Timeline Explorer. Once loaded, we can filter 'File Names' for `NTDS.dit`. Based on the results, we can see an odd path `\Users\Administrator\Documents\backup_sync_dc`.

![image six](./Images/Pasted%20image%2020250905143610.png)

6. **When was newly dumped ntds.dit created on disk?**
To answer this question, view the `Created0x10` column for the entry above. You'll find that it's `2024-05-14 03:44:22`.

![image seven](./Images/Pasted%20image%2020250905143723.png)

7. **A registry hive was also dumped alongside the NTDS database. Which registry hive was dumped and what is its file size in bytes?**
It's a good guess to assume that the attacker would download the registry hive to the same file location. We can filter results based on the day in question (from the previous question) and the file path we found two questions ago. The answer appears to be `SYSTEM, 17563648`.

![image eight](./Images/Pasted%20image%2020250905143955.png)