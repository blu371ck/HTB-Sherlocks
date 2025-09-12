# HTB Sherlock - OpTinselTrace24-4: Neural Noel

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-12 | Andrew McKenzie | Easy       | DFIR           |

---
## Description
This challenge involves a multi-stage investigation into the compromise of an AI chatbot system. By correlating network traffic, authentication logs, and user command history, the goal is to trace the attacker's path. The analysis covers initial information gathering through chatbot manipulation, credential theft, lateral movement via SSH, and finally, privilege escalation by exploiting a vulnerability in a Python AI library.
## Scenario
Santa's North Pole Operations is developing an AI chatbot to handle the overwhelming volume of messages, gift requests, and communications from children worldwide during the holiday season. The AI system is designed to process these requests efficiently and provide support in case of any issues. As Christmas approaches, Santa's IT team observes unusual activity in the AI system. Suspicious files are being accessed, and the system is making unusual HTTP traffic. Additionally, the customer service department has reported strange and unexpected requests coming through the automated AI chatbot, raising the need for further investigation.
## Artifacts Provided
- NeuralNoel.zip
	- auth.log
	- history
	- Neural-Noel.pcap

| Filename         | Algorithm | Hash                                                             |
| ---------------- | --------- | ---------------------------------------------------------------- |
| auth.log         | SHA256    | 6aa9db2819ed81afc710807f5e24574e3172251d1d9266ff1af5e928eb4af801 |
| auth.log         | SHA1      | 1636ce7da8db6d9ca51819dbac1c72e5b34314cb                         |
| auth.log         | MD5       | 1e2cdecbea59ba02b5fad9900489fbcc                                 |
| history          | SHA256    | f5af2c8e9e4a5edb34a258f3cc0c139dfed3a8d43fcd3050c47c68a3e68bc541 |
| history          | SHA1      | 14fc3ea1cc4bc65a92ea80ed898d7c9d81420e9f                         |
| history          | MD5       | b3eb357a36337e0fb433245e41087507                                 |
| Neural-Noel.pcap | SHA256    | 3f2520db5f1934118234ab292ffc35168c42e59950e272bb03903c021156f6e3 |
| Neural-Noel.pcap | SHA1      | e8a0aba245c2661a9aaa6b5546d9c97293cafb89                         |
| Neural-Noel.pcap | MD5       | f36a5c7398a7c5736d56079372a540f6                                 |
## Skills Learned
- **Network Traffic Analysis:** Using Wireshark to analyze HTTP conversations and understand attacker interactions with a web application.
- **Log Correlation:** Connecting events across network traffic (`.pcap`), system authentication logs (`auth.log`), and user command logs (`.bash_history`).
- **AI Chatbot Security:** Identifying prompt injection techniques used to manipulate AI chatbots into disclosing sensitive information.
- **Vulnerability Research:** Using version information found in logs (Langchain 0.0.14) to perform OSINT and identify a relevant CVE.
- **Privilege Escalation Analysis:** Tracing an attacker's steps from initial user-level access to successful root privilege escalation.
## Initial Analysis
The investigation pieced together the attack by correlating evidence from the network traffic and host-based logs.
1. **Information Gathering via Chatbot:** The `Neural-Noel.pcap` file showed the attacker first interacting with the AI system. They queried multiple chatbots, eventually manipulating the **`Web & Files Chatbot`** into disclosing the contents of a local file named **`creds.txt`**. This file contained credentials for a user named `noel`.
2. **Initial Access:** The investigation then pivoted to the `auth.log`. At **06:49:44**, an SSH login event confirmed that the attacker used the credentials stolen from the chatbot to successfully authenticate as the `noel` user.
3. **Privilege Escalation Discovery:** The `history` file revealed the attacker's post-exploitation commands. The attacker inspected a local application and discovered it was using **Langchain version 0.0.14**.
4. **Exploitation:** A quick OSINT search on this version of Langchain revealed a critical remote code execution vulnerability, **`CVE-2023-44467`**, caused by the unsafe use of the `__import__` function in Python.
5. **Root Compromise:** The attacker exploited this vulnerability to escalate their privileges. The `auth.log` shows a successful `sudo` command execution at **06:56:41**, confirming the attacker had gained root access to the system.
The attack followed a clear path: information disclosure through a vulnerable AI chatbot, initial access using the stolen credentials, and privilege escalation via an N-day vulnerability in a third-party library.
## Questions:
1. **What username did the attacker query the AI chatbot to check for its existence?**
The attacker first queries for information about the user `Juliet`.

![image one](./Images/Pasted%20image%2020250912181006.png)

2. **What is the name of the AI chatbot that the attacker unsuccessfully attempted to manipulate into revealing data stored on its server?**
The second chatbot failed to provide the attacker with the information they were requesting about data. From the HTTP stream we can see the name is `GDPR Chatbot`.

![image two](./Images/Pasted%20image%2020250912181404.png)

3. **On which server technology is the AI chatbot running?**
From the same HTTP stream, we can see the server leaks its information. The server technology is `Werkzeug/3.1.3 Python/3.12.7`.

![image three](./Images/Pasted%20image%2020250912181515.png)

4. **Which AI chatbot disclosed to the attacker that it could assist in viewing webpage content and files stored on the server?**
The chatbot that disclosed information is named `Web & Files Chatbot`.

![image four](./Images/Pasted%20image%2020250912181636.png)

5. **Which file exposed user credentials to the attacker?**
From the same conversation that we found the user `Juliet`, the attacker also requested information about a file `creds.txt`.

![image five](./Images/Pasted%20image%2020250912181751.png)

6. **What time did the attacker use the exposed credentials to log in?**
Reviewing the auth logs provided, we can see a couple of different usernames logging in. The one of interest has a failed attempt right before a successful attempt and occurred after the timestamp from the last question. The user who logged in was Noel, and the time was `06:49:44`.

![image six](./Images/Pasted%20image%2020250912182207.png)

7. **Which CVE was exploited by the attacker to escalate privileges?**
Reviewing the history file provided, we get some hints as to what application and version we need to look into. In particular, it's Langchain 0.0.14. Looking on Google, I can see that a CVE was released specifically for this version, `CVE-2023-44467`. [Source](https://www.tenable.com/plugins/nessus/206977)

8. **Which function in the Python library led to the exploitation of the above vulnerability?**
If you review the article linked in the previous question, you see that the function that led to the vulnerability is the use of `__import__`.

![image seven](./Images/Pasted%20image%2020250912182640.png)

9. **What time did the attacker successfully execute commands with root privileges?**
Reviewing auth logs again, we can see that the timestamp of the successful use of root occurred at `06:56:41`.

![image eight](./Images/Pasted%20image%2020250912182847.png)