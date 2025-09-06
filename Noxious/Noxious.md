# HTB Sherlock - Noxious

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-06 | Andrew McKenzie | Very Easy  | SOC            |

---
## Description
This challenge involves analyzing a packet capture to investigate an Intrusion Detection System (IDS) alert. The focus is on network forensics within an Active Directory environment where an LLMNR poisoning attack is suspected to have occurred, leading to credential theft.
## Scenario
The IDS device alerted us to a possible rogue device in the internal Active Directory network. The Intrusion Detection System also indicated signs of LLMNR traffic, which is unusual. It is suspected that an LLMNR poisoning attack occurred. The LLMNR traffic was directed towards Forela-WKstn002, which has the IP address 172.17.79.136. A limited packet capture from the surrounding time is provided to you, our Network Forensics expert. Since this occurred in the Active Directory VLAN, it is suggested that we perform network threat hunting with the Active Directory attack vector in mind, specifically focusing on LLMNR poisoning.
## Artifacts Provided
- noxious.zip
	- capture.pcap

| Filename     | Algorithm | Hash                                                             |
| ------------ | --------- | ---------------------------------------------------------------- |
| capture.pcap | SHA256    | ceecf4be35983111eb9a78a5311319b4939e327690b796f208e8c08335a5508b |
| capture.pcap | SHA1      | e76c6021bc6dabd0f7a51451b60df8897aae8abf                         |
| capture.pcap | MD5       | dfaa529285a59d0ccd299355f0169055                                 |
## Skills Learned
- Network traffic analysis using Wireshark and Suricata.
- Applying Wireshark display filters to isolate specific protocols like `llmnr`, `ntlmssp`, and `smb2`.
- Identifying Indicators of Compromise (IOCs) from IDS alerts and DHCP traffic.
- Understanding the methodology of an LLMNR poisoning attack.
- Extracting NTLMv2 hash components (Server Challenge, NTProofStr, etc.) from authentication traffic.
- Constructing a hashcat-compatible hash from captured network data.
- Password cracking using hashcat to validate the severity of a compromised credential.
## Initial Analysis
The first step was to get a high-level overview of the network capture and validate the initial IDS alert. The `capture.pcap` file was analyzed using Suricata to identify any obvious malicious patterns or rule matches. This process quickly returned a critical alert: `ET INFO Possible Kali Linux hostname in DHCP Request Packet`. This alert provided strong evidence of a known attack platform on the network, confirming the suspicion of a rogue device. From the alert details, the attacker's IP address was identified as `172.17.79.135` and its hostname was the default `Kali`. This provided the perfect pivot point for a more granular investigation within Wireshark.
## Questions:
1. **Its suspected by the security team that there was a rogue device in Forela's internal network running responder tool to perform an LLMNR Poisoning attack. Please find the malicious IP Address of the machine.**
We can start this by running Suricata against the PCAP to grab all the low-hanging fruit. From the output we eventually see a line, “ET INFO Possible Kali Linux hostname in DHCP Request Packet,” indicating that an attack machine was present and the IP address of that machine was `172.17.79.135`.

![image one](./Images/Pasted%20image%2020250905234436.png)

2. **What is the hostname of the rogue machine?**
From the same line as above, we know that Kali Linux uses the generic “Kali” hostname by default. The message does not indicate that this hostname was altered, so the hostname is `Kali`.

![image two](./Images/Pasted%20image%2020250905234452.png)

3. **Now we need to confirm whether the attacker captured the user's hash and it is crackable!! What is the username whose hash was captured?**
Moving to Wireshark, we can filter traffic for `ntlmssp`. Based on the number of error states found for user `john.deacon`, it's a safe bet this is the user.

![image three](./Images/Pasted%20image%2020250905235010.png)

4. **In NTLM traffic we can see that the victim credentials were relayed multiple times to the attacker's machine. When were the hashes captured the First time?**
We can continue on using the same results we used in the previous question. We are looking for the first negotiation instance, and the timestamp for that is `2024-06-24 11:18:30`.

![image four](./Images/Pasted%20image%2020250905235451.png)

5. **What was the typo made by the victim when navigating to the file share that caused his credentials to be leaked?**
Filtering for `llmnr` we can see that there is a request from `172.17.79.136` to `172.17.79.135` (the attacker) regarding an A record to `DCC01`.

![image five](./Images/Pasted%20image%2020250906000107.png)

6. **To get the actual credentials of the victim user we need to stitch together multiple values from the ntlm negotiation packets. What is the NTLM server challenge value?**
Filtering again for `ntlmssp`, we can inspect the packets and find the challenge in the “Session Setup Response” section of the packets. The challenge value is `601019d191f054f1`.

![image six](./Images/Pasted%20image%2020250906000410.png)

7. **Now doing something similar find the NTProofStr value.**
This value can be found in the packets for “Session Setup Request” within the “Security Blob” section. The answer is `c0cc803a6d9fb5a9082253a04dbd4cd4`.

![image seven](./Images/Pasted%20image%2020250906000642.png)

8. **To test the password complexity, try recovering the password from the information found from packet capture. This is a crucial step as this way we can find whether the attacker was able to crack this and how quickly.**
We can build the NTLM hash from the items we have been provided and found in previous questions. The format will be `user.name::DOMAIN:challenge:ntlmv2response`. In our case this equates to:
```
john.deacon::FORELA:601019d191f054f1:c0cc803a6d9fb5a9082253a04dbd4cd4:010100000000000080e4d59406c6da01cc3dcfc0de9b5f2600000000020008004e0042004600590001001e00570049004e002d00360036004100530035004c003100470052005700540004003400570049004e002d00360036004100530035004c00310047005200570054002e004e004200460059002e004c004f00430041004c00030014004e004200460059002e004c004f00430041004c00050014004e004200460059002e004c004f00430041004c000700080080e4d59406c6da0106000400020000000800300030000000000000000000000000200000eb2ecbc5200a40b89ad5831abf821f4f20a2c7f352283a35600377e1f294f1c90a001000000000000000000000000000000000000900140063006900660073002f00440043004300300031000000000000000000
```
We can then crack this with hashcat:
```powershell
.\hashcat.exe -m 5600 .\hashes\noxious.hash .\wordlist\rockyou.txt
```
It cracks pretty fast and the answer is `NotMyPassword0k?`

![image eight](./Images/Pasted%20image%2020250906001811.png)

9. **Just to get more context surrounding the incident, what is the actual file share that the victim was trying to navigate to?**
Going back to Wireshark and filtering for `smb2`, we can see the only share of value would be `\\DC01\DC-Confidential`.

![image nine](./Images/Pasted%20image%2020250906001938.png)