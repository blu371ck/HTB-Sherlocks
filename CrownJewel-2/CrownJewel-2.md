# HTB Sherlock - CrownJewel-2

![htb logo](./Images/htb_logo.png)

| Date          | Author          | Difficulty | Challenge Type |
| ------------- | --------------- | ---------- | -------------- |
| 2025-09-05 | Andrew McKenzie | Very Easy  | DFIR           |

---
## Description
This challenge simulates a follow-up incident response scenario on a Domain Controller. After mitigating an initial attack where credentials were dumped using `vssadmin`, the attacker, leveraging persistent access, strikes again. This time, they use `ntdsutil.exe`, a different built-in utility, to achieve the same goal. The investigation requires a deep dive into Windows Event Logs (`SYSTEM`, `SECURITY`, and `APPLICATION`) to trace the attacker's new TTPs (Tactics, Techniques, and Procedures) and establish a timeline from initial logon to the completion of the database dump.
## Scenario
Forela's Domain environment is pure chaos. Just got another alert from the Domain controller of NTDS.dit database being exfiltrated. Just one day prior you responded to an alert on the same domain controller where an attacker dumped NTDS.dit via vssadmin utility. However, you managed to delete the dumped files kick the attacker out of the DC, and restore a clean snapshot. Now they again managed to access DC with a domain admin account with their persistent access in the environment. This time they are abusing ntdsutil to dump the database. Help Forela in these chaotic times!!
## Artifacts Provided
- CrownJewel2.zip
	- `APPLICATION.evtx`
	- `SECURITY.evtx`
	- `SYSTEM.evtx`

| Filename           | Algorithm | Hash                                                             |
| ------------------ | --------- | ---------------------------------------------------------------- |
| `APPLICATION.evtx` | SHA256    | DB32B80CB263C31789C511B6CFFEA31ED9FDA503931324533504F277B2D3BCFC |
| `APPLICATION.evtx` | SHA1      | 324E4B57EE81C93583AFF24B53A1ED9E1757EC03                         |
| `APPLICATION.evtx` | MD5       | C6FCE39B8AA24471BBC90B4FB98472BE                                 |
| `SECURITY.evtx`    | SHA256    | AD171FD07E9D1C6F2322EDA8A2E9B817C702F8DFD02248B45ED612668E586F15 |
| `SECURITY.evtx`    | SHA1      | 759F5B5FA073FD53144CBA43F879A219FA0B4547                         |
| `SECURITY.evtx`    | MD5       | 3F0DA185E0AC869B78B0AC4D354263FE                                 |
| `SYSTEM.evtx`      | SHA256    | 678BD96EBD0A4DF7E4D136CCF19DB007F9792210D699F3DEBBA0A63A5F22D2E7 |
| `SYSTEM.evtx`      | SHA1      | EF91EBA1D9069281108DF0BD9671672C5E13FCFC                         |
| `SYSTEM.evtx`      | MD5       | 1AB701B20D744051CFD2A9680DB3D9FD                                 |
## Skills Learned
- **Advanced Event Log Correlation:** Correlating events across `SYSTEM`, `SECURITY`, and `APPLICATION` logs to build a comprehensive timeline of an attack.
- **TTP Identification:** Differentiating between credential dumping techniques (`vssadmin` vs. `ntdsutil`) and understanding their forensic footprints.
- **Application Log Analysis:** Analyzing logs from specific sources like `ESENT` (Extensible Storage Engine) to trace database operations related to the `NTDS.dit` dump.
- **User Session Tracking:** Using Logon IDs from security events (like `4799`) to pivot and identify the initial logon time by tracing back through Kerberos and Credential Manager events (`4769`, `5379`).
## Initial Analysis
The investigation followed the attacker's trail through the event logs, starting from the moment they initiated the credential dump and working backward to their initial logon.
1. **Confirming the Technique:** The scenario indicated the use of `ntdsutil`. Like `vssadmin`, this utility leverages the Volume Shadow Copy service. I confirmed this by checking the `SYSTEM.evtx` log for **Event ID 7036**, which showed the service entering a running state at **`2024-05-15 05:39:55`**.
2. **Locating the Dumped File:** I then pivoted to the `APPLICATION.evtx` log. By searching for "ntds", I found several events logged by the **`ESENT`** source. These logs detailed the creation of a shadow copy of the database, revealing the full path of the dumped file: **`C:\Windows\Temp\dump_tmp\Active Directory\ntds.dit`**. The logs showed the creation process started at **`05:39:56`** and the database was successfully detached (completed) at **`05:39:58`**.
3. **Identifying the User Session:** To identify the user and session responsible, I moved to the `SECURITY.evtx` log. Filtering for **Event ID 4799** (Group Membership Enumeration), I found that the `ntdsutil.exe` process enumerated the **`Administrators`** and **`Backup Operators`** groups. This event contained the **Logon ID `0x8de3d`**.
4. **Tracing Back to Logon:** Using this Logon ID, I traced the session backward through the security logs. By correlating this ID with **Event ID 5379** (Credential Manager) and the preceding **Event ID 4769** (Kerberos Ticket Request), I pinpointed the exact start of the malicious session to **`2024-05-15 05:36:31`**.
This end-to-end analysis confirms that a domain admin account logged on, and three minutes later, used `ntdsutil.exe` to successfully dump the `NTDS.dit` database.
## Questions:
1. **When utilizing ntdsutil.exe to dump NTDS on disk, it simultaneously employs the Microsoft Shadow Copy Service. What is the most recent timestamp at which this service entered the running state, signifying the possible initiation of the NTDS dumping process?**
We can utilize the `SYSTEM` logs for this with event code `7036` and a description filter of `shadow`. Looking at the most recent running state event, we can see the timestamp is `2024-05-15 05:39:55`.

![image one](./Images/Pasted%20image%2020250905150705.png)

2. **Identify the full path of the dumped NTDS file.**
We can utilize the `APPLICATION` logs for this with a description filter of `ntds`. Reviewing the entries, we can see in the third entry a path is presented that is suspicious: `C:\Windows\Temp\dump_tmp\Active Directory\ntds.dit`.

![image two](./Images/Pasted%20image%2020250905150947.png)

3. **When was the database dump created on the disk?**
We can keep the same logs and filter from the previous question. Then we can navigate through the results in chronological order, looking for the first reference of the file path from the previous question. We can see the earliest timestamp is on `2024-05-15 05:39:56`.

![image three](./Images/Pasted%20image%2020250905151215.png)

4. **When was the newly dumped database considered complete and ready for use?**
This will be the specific timestamp for the event we used in question 2. The event timestamp when the database engine successfully detached from the newly created database file. `2024-05-15 05:39:58`.

![image four](./Images/Pasted%20image%2020250905151410.png)

5. **Event logs use event sources to track events coming from different sources. Which event source provides database status data like creation and detachment?**
This answer can be found on the 'Standard' event information from the event we utilized in the previous question. The “Source” is `ESENT`.

![image five](./Images/Pasted%20image%2020250905151517.png)

6. **When ntdsutil.exe is used to dump the database, it enumerates certain user groups to validate the privileges of the account being used. Which two groups are enumerated by the ntdsutil.exe process? Give the groups in alphabetical order joined by comma space.**
Reviewing the `SECURITY` logs for event ID `4799`, we can see that there are only two groups that were enumerated. `Administrators, Backup Operators`.

![image six](./Images/Pasted%20image%2020250905151654.png)
![image seven](./Images/Pasted%20image%2020250905151704.png)

7. **Now you are tasked to find the Login Time for the malicious Session. Using the Logon ID, find the Time when the user logon session started.**
This requires piecing together two different events from the `SECURITY` logs. We can filter for `4769`, “Kerberos service ticket was requested,” and `5379`, “Credential Manager credentials were used.” We first need to locate the logon ID from the previous question, which is `0x8de3d` and look for this to show up in event `5379`. Once found, we need to find the Kerberos ticket request `4769` that happens immediately before it. The answer to the question is `2024-05-15 05:36:31`.

![image eight](./Images/Pasted%20image%2020250905152748.png)
![image nine](./Images/Pasted%20image%2020250905152854.png)