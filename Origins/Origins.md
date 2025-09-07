# HTB Sherlock - Origins

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-07 | Andrew McKenzie | Very Easy  | DFIR           |

---
## Description
This challenge focuses on network forensics by analyzing a packet capture (`.pcap`) file from a compromised FTP server. The objective is to trace the attacker's steps, from identifying the initial brute-force attack and compromised credentials to discovering evidence of data exfiltration. The analysis of the exfiltrated data reveals further indicators of compromise related to a much larger incident.
## Scenario
A major incident has recently occurred at Forela. Approximately 20 GB of data were stolen from internal s3 buckets and the attackers are now extorting Forela. During the root cause analysis, an FTP server was suspected to be the source of the attack. It was found that this server was also compromised and some data was stolen, leading to further compromises throughout the environment. You are provided with a minimal PCAP file. Your goal is to find evidence of brute force and data exfiltration.
## Artifacts Provided
- Origins.zip
	- ftp.pcap

| Filename | Algorithm | Hash                                                             |
| -------- | --------- | ---------------------------------------------------------------- |
| ftp.pcap | SHA256    | b770184fbc4a68e64d8e28ed9d9cf3e778ca441869736b8b33d13ab69e317c8b |
| ftp.pcap | SHA1      | 318eb8b880ccdea14c06adcb4c2f446fcf18ac5d                         |
| ftp.pcap | MD5       | 08fb0c29a5431606615ff09269428132                                 |
## Skills Learned
- **PCAP Analysis:** Utilizing Wireshark to inspect and filter network traffic captures.
- **Network Forensics:** Analyzing FTP protocol traffic to identify attacker IPs, server banners (software versions), and commands.
- **Brute-Force Attack Identification:** Recognizing the pattern of multiple failed login attempts from a single source IP.
- **Credential Recovery:** Following TCP streams to reconstruct application-layer conversations and extract compromised credentials.
- **File Extraction from PCAP:** Carving and exporting files transferred over the network for offline analysis.
- **Indicator of Compromise (IOC) Discovery:** Analyzing exfiltrated data to find additional IOCs like passwords, URLs, and email addresses.
## Initial Analysis
The investigation began by loading the `ftp.pcap` file into Wireshark to analyze the captured network traffic. By filtering for the FTP protocol, it was immediately apparent that a single external IP address, **`15.206.185.207`**, was responsible for a large volume of login attempts, identifying it as the attacker. An OSINT lookup traced this IP to Mumbai.

The traffic revealed a classic brute-force attack, starting on **`2024-05-03 at 04:12:54`**. By meticulously following the FTP command and response sequence, a "Login successful" message was located. Following the corresponding TCP stream confirmed the compromised credentials were **`forela-ftp:ftprocks69$`**.

Once authenticated, the attacker was observed using the **`RETR`** command to download two files: `Maintenance-Notice.pdf` and `s3_buckets.txt`. These files were exported directly from the PCAP for inspection. Analysis of these exfiltrated files yielded critical intelligence for the larger incident: the PDF contained a temporary SSH password (`**B@ckup2024!**`), and the text file contained an S3 bucket URL and an internal email address, linking this FTP compromise to the broader data breach.
## Questions:
1. **What is the attacker's IP address?**
Reviewing the PCAP in Wireshark and reviewing FTP traffic, we see the IP address `15.206.185.207` making multiple requests to the FTP server `172.31.45.144` with different usernames, indicating that it is the attacker.

![image one](./Images/Pasted%20image%2020250907074156.png)

2. **It's critical to get more knowledge about the attackers, even if it's low fidelity. Using the geolocation data of the IP address used by the attackers, what city do they belong to?**
Using online resources, looking up the IP address shows they belong to `Mumbai`.

![image two](./Images/Pasted%20image%2020250907074310.png)

3. **Which FTP application was used by the backup server? Enter the full name and version. (Format: Name Version)**
Reviewing FTP traffic will show the version in the info column throughout the FTP communication. The application and version are `vsFTPd 3.0.5`.

![image three](./Images/Pasted%20image%2020250907074553.png)

4. **The attacker has started a brute force attack on the server. When did this attack start?**
We can utilize the same resource from question 1. The first occurrence of our attacker IP address submitting passwords to the FTP server. The timestamp is `2024-05-03 04:12:54`.

![image four](./Images/Pasted%20image%2020250907074721.png)

5. **What are the correct credentials that gave the attacker access? (Format username:password)**
Reviewing the brute force attack, we eventually see a successful login message. Following the TCP stream, we can see the username and password are `forela-ftp:ftprocks69$`.

![image five](./Images/Pasted%20image%2020250907074926.png)

6. **The attacker has exfiltrated files from the server. What is the FTP command used to download the remote files?**
Continuing to review FTP traffic, we see the attacker utilized `RETR` commands to download files.

![image six](./Images/Pasted%20image%2020250907075124.png)

7. **Attackers were able to compromise the credentials of a backup SSH server. What is the password for this SSH server?**
Utilizing Wireshark export, we can export the two files that were retrieved from the FTP server by the attacker (Maintenance-Notice.pdf and s3_buckets.txt). Within the PDF file, we can see that there is some planned maintenance occurring and that a temporary password has been issued: `**B@ckup2024!**`.

![image seven](./Images/Pasted%20image%2020250907075526.png)

8. **What is the s3 bucket URL for the data archive from 2023?**
From the s3_buckets.txt file, we can see the S3 bucket URL from 2023 is `https://2023-coldstorage.s3.amazonaws.com`.

![image eight](./Images/Pasted%20image%2020250907075612.png)

9. **The scope of the incident is huge as Forela's s3 buckets were also compromised and several GB of data were stolen and leaked. It was also discovered that the attackers used social engineering to gain access to sensitive data and extort it. What is the internal email address used by the attacker in the phishing email to gain access to sensitive data stored on s3 buckets?**
The email address can also be found in the s3_buckets.txt file. The email address was `archivebackups@forela.co.uk`.

![image nine](./Images/Pasted%20image%2020250907080009.png)