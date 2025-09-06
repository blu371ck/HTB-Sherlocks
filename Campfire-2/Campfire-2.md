# HTB Sherlock - Campfire-2

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-06 | Andrew McKenzie | Very Easy  | DFIR           |

---
## Description
This challenge focuses on detecting and analyzing an **AS-REP Roasting attack** using only the security event logs from a Domain Controller. The objective is to identify the specific indicators of the attack within the logs, determine the targeted user, pinpoint the attack time, and trace the activity back to the source account and IP address.
## Scenario
Forela's Network is constantly under attack. The security system raised an alert about an old admin account requesting a ticket from KDC on a domain controller. Inventory shows that this user account is not used as of now so you are tasked to take a look at this. This may be an AsREP roasting attack as anyone can request any user's ticket which has preauthentication disabled.
## Artifacts Provided
- campfire-2.zip
	- `Security.evtx`

| Filename        | Algorithm | Hash                                                             |
| --------------- | --------- | ---------------------------------------------------------------- |
| `Security.evtx` | SHA256    | 5AFD64BCE6C9F69A57A00701B6CF600E0C93B1E47D89F6146B05966AD90CBF05 |
| `Security.evtx` | SHA1      | 6CBD4040DCFB5F6D34FBB8DA126C47D5DC12FEEF                         |
| `Security.evtx` | MD5       | 58EA357BF39AF9E4831BF65D361DE537                                 |
## Skills Learned
- **Windows Event Log Analysis:** Analyzing Domain Controller security logs (`Security.evtx`) to investigate threats.
- **AS-REP Roasting Detection:** Identifying the attack by filtering for Event ID `4768` (A Kerberos authentication ticket (TGT) was requested) and looking for specific indicators, such as a ticket encryption type of `0x17` (RC4), which is common when Kerberos pre-authentication is disabled.
- **Incident Timeline Reconstruction:** Using event timestamps to establish a precise timeline of malicious activity.
- **Attacker Attribution:** Correlating subsequent log events to identify the user account (`happy.grunwald`) that likely performed the attack.
## Initial Analysis
The investigation began by analyzing the provided `Security.evtx` log file from the Domain Controller. Based on the scenario describing a potential AS-REP Roasting attack, the logs were filtered for **Event ID `4768`**, which corresponds to a Kerberos TGT request.

A specific event quickly stood out, showing a successful TGT request for the user `arthur.kyle` using the weak **RC4 encryption algorithm (`0x17`)**. This is a classic indicator of an AS-REP Roasting attack, as it targets accounts with Kerberos pre-authentication disabled. This single log entry contained most of the critical information: the exact timestamp of the attack, the targeted user account and its SID, and the source IP address of the attack (`172.17.79.129`).

To identify the account used by the attacker, the event log filter was removed. By examining events immediately following the attack that originated from the same source IP, it was observed that the user `happy.grunwald` was actively requesting service tickets. This strongly suggests that the `happy.grunwald` account was compromised and used to launch the attack against the `arthur.kyle` account.
## Questions:
1. **When did the ASREP Roasting attack occur, and when did the attacker request the Kerberos ticket for the vulnerable user?**
To find ASREP roasting attacks, we need to filter the `SECURITY.evtx` logs by event ID `4768`. From there, we need to look for the ticket encryption type to be 0×17 (RC4) encryption. We find a viable item, and its timestamp is `2024-05-29 06:36:40`.

![image one](./Images/Pasted%20image%2020250906161603.png)

2. **Please confirm the User Account that was targeted by the attacker.**
We can find this information in the same event. The target was `arthur.kyle`.

![image two](./Images/Pasted%20image%2020250906161723.png)

3. **What was the SID of the account?**
We can find this information in the same event as well. The SID is `S-1-5-21-3239415629-1862073780-2394361899-1601`.

![image three](./Images/Pasted%20image%2020250906161817.png)

4. **It is crucial to identify the compromised user account and the workstation responsible for this attack. Please list the internal IP address of the compromised asset to assist our threat-hunting team.**
Another answer that can be found on the same event is the compromised asset is `172.17.79.129`.

![image four](./Images/Pasted%20image%2020250906161908.png)

5. **We do not have any artifacts from the source machine yet. Using the same DC Security logs, can you confirm the user account used to perform the ASREP Roasting attack so we can contain the compromised account's?**
We need to remove our event ID filter and find the event we have been reviewing thus far using its timestamp. Once found, we can see that the event directly after this event has a user `happy.grunwald` requesting Kerberos service tickets.

![image five](./Images/Pasted%20image%2020250906162319.png)