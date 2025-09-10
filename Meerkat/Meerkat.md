# HTB Sherlock - Meerkat

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-09 | Andrew McKenzie | Easy       | SOC            |

---
## Description
This challenge simulates a Security Operations Center (SOC) investigation into a suspected compromise of a business management platform. By analyzing provided network traffic (`.pcap`) and IDS alerts (`.json`), the objective is to confirm the compromise, identify the specific attack vectors used, trace the attacker's post-exploitation activities, and determine how they established persistence on the server.
## Scenario
As a fast-growing startup, Forela has been utilising a business management platform. Unfortunately, our documentation is scarce, and our administrators aren't the most security aware. As our new security provider we'd like you to have a look at some PCAP and log data we have exported to confirm if we have (or have not) been compromised.
## Artifacts Provided
- meerkat.zip
	- meerkat-alerts.json
	- meerkat.pcap

| Filename            | Algorithm | Hash                                                             |
| ------------------- | --------- | ---------------------------------------------------------------- |
| meerkat-alerts.json | SHA256    | 012aa4e8aae5d500c001510d6e65567eb0cdbfffe2dab9a119b66f7770c222be |
| meerkat-alerts.json | SHA1      | ed4ef9766212cac76b5e99dd4b45d0c32e3429ab                         |
| meerkat-alerts.json | MD5       | f9642326d526c4f5159470b1c5d89b4a                                 |
| meerkat.pcap        | SHA256    | aa3838dbd634f9798d1e9505d243a4fee1d340d6e25e2f0c9648dd64e2178dbf |
| meerkat.pcap        | SHA1      | a39dbb956fde83942b32068eb2f823ec6c478dda                         |
| meerkat.pcap        | MD5       | 7ac62b1e835e0850104f1fc2ecf1f002                                 |
## Skills Learned
- **IDS Alert Analysis:** Interpreting JSON-based alert data to quickly identify key incident details like application names and associated CVEs.
- **Network Traffic Analysis:** Using Wireshark to analyze HTTP traffic, filter for malicious activity, and reconstruct attack sequences.
- **Attack Vector Identification:** Differentiating between brute-force techniques like **Credential Stuffing** and identifying the exploitation of a known vulnerability (**CVE-2022-25237**).
- **Post-Exploitation TTPs:** Tracing attacker actions after initial access, including retrieving second-stage payloads from external sites like `pastes.io`.
- **Persistence Mechanism Analysis:** Analyzing attacker scripts to identify persistence techniques, such as modifying SSH `authorized_keys`.
- **MITRE ATT&CK Framework Mapping:** Associating observed adversary behaviors with their corresponding ATT&CK technique IDs.
## Initial Analysis
The investigation began by reviewing the `meerkat-alerts.json` file, which provided immediate context. The alerts confirmed the targeted application was **BonitaSoft** and pointed to a specific vulnerability, **CVE-2022-25237**.

With this information, the `meerkat.pcap` file was analyzed in Wireshark to observe the attack in detail.
1. **Initial Access:** A **Credential Stuffing** attack was identified, involving **56** unique username and password combinations. The attacker successfully authenticated with the credentials **`seb.broom@forela.co.uk:g0vernm3nt`**, confirmed by a `204 No Content` response to a login POST request.
2. **Exploitation:** After gaining access, the attacker exploited `CVE-2022-25237`. This was achieved by appending the string **`i18ntranslation`** to an API URL, which bypassed an authorization filter and allowed for privileged actions.
3. **Persistence:** Post-exploitation traffic showed the attacker accessing a link on **`https://pastes.io`**. The content from this link was a shell script designed to establish persistence. The script downloaded a public key file named **`hffgra4unv`** and appended its contents to `/home/ubuntu/.ssh/authorized_keys`. This action allows the attacker to maintain SSH access to the server and corresponds to the MITRE ATT&CK technique **T1098.004**.
The evidence confirms a full compromise, from initial access via stolen credentials to the establishment of a persistent backdoor.
## Questions:
1. **We believe our Business Management Platform server has been compromised. Please can you confirm the name of the application running?**
Browsing through meerkat-alerts.json, we can see some mentions in JSON fields. The application running is `BonitaSoft`.

![image one](./Images/Pasted%20image%2020250909214443.png)

2. **We believe the attacker may have used a subset of the brute forcing attack category - what is the name of the attack carried out?**
We can see the login activity in Wireshark, and since some usernames/passwords are being used more than once, it appears to be `Credential stuffing` and not password spraying. Looking at question 5 also proves that.

![image two](./Images/Pasted%20image%2020250909215622.png)

3. **Does the vulnerability exploited have a CVE assigned - and if so, which one?**
We can see mentions of a CVE in the meerkat-alerts file. The CVE mentioned is `CVE-2022-25237`.

![image three](./Images/Pasted%20image%2020250909215659.png)

4. **Which string was appended to the API URL path to bypass the authorization filter by the attacker's exploit?**
From the same location in Wireshark, we eventually see 200 responses to requests with odd URL paths. The answer to the question is `i18ntranslation`.

![image four](./Images/Pasted%20image%2020250909215941.png)

5. **How many combinations of usernames and passwords were used in the credential stuffing attack?**
The answer to this is `56` there are probably fancy ways of getting this number, but I simply counted them as there weren't that many packets. Do not forget to subtract one for `install:install`.

6. **Which username and password combination was successful?**
We just need to find the POST request to `/bonita/loginservice` that did not return a 4XX response. In this case we see one returns a 204, and the credentials are `seb.broom@forela.co.uk:g0vernm3nt`.

![image five](./Images/Pasted%20image%2020250909220941.png)

7. **If any, which text sharing site did the attacker utilise?**
Reviewing HTTP traffic, we eventually see requests to `https://pastes.io`.

![image six](./Images/Pasted%20image%2020250909221036.png)

8. **Please provide the filename of the public key used by the attacker to gain persistence on our host.**
To find the answer, you actually need to follow the link from the last question. It contains a bash script that is executed a little downstream and shows the file name is `hffgra4unv`.

![image seven](./Images/Pasted%20image%2020250909222105.png)

9. **Can you confirm the file modified by the attacker to gain persistence?**
This answer is also in the bash script from the previous question. The answer is `/home/ubuntu/.ssh/authorized_keys`.

10. **Can you confirm the MITRE technique ID of this type of persistence mechanism?**
The MITRE ATT&CK technique for manipulating and using SSH authorized keys is `T1098.004`. [Resource](https://attack.mitre.org/techniques/T1098/004/)