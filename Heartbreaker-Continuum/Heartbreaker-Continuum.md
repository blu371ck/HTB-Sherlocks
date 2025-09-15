# HTB Sherlock - Heartbreaker Continuum

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type   |
| ---------- | --------------- | ---------- | ---------------- |
| 2025-09-15 | Andrew McKenzie | Easy       | Malware Analysis |

---
## Description
This challenge focuses on the static analysis of a malicious executable delivered via a phishing campaign. The primary objective is to reverse engineer the binary, which acts as a wrapper for an obfuscated PowerShell script. The investigation involves using forensic tools to inspect the PE file, extract and deobfuscate the embedded script, and identify key Indicators of Compromise (IOCs) to understand the malware's full capabilities.
## Scenario
Following a recent report of a data breach at their company, the client submitted a potentially malicious executable file. The file originated from a link within a phishing email received by a victim user. Your objective is to analyze the binary to determine its functionality and possible consequences it may have on their network. By analyzing the functionality and potential consequences of this binary, you can gain valuable insights into the scope of the data breach and identify if it facilitated data exfiltration. Understanding the binary's capabilities will enable you to provide the client with a comprehensive report detailing the attack methodology, potential data at risk, and recommended mitigation steps.
## Artifacts Provided
- HeartBreakerContinuum.zip
	- Superstar_MemberCard.tiff.exe

| File Name                     | Algorithm | Hash                                                             |
| ----------------------------- | --------- | ---------------------------------------------------------------- |
| Superstar_MemberCard.tiff.exe | SHA256    | 12DAA34111BB54B3DCBAD42305663E44E7E6C3842F015CCCBBE6564D9DFD3EA3 |
| Superstar_MemberCard.tiff.exe | SHA1      | 6236F6F30E1CD180D3F9BD1D48EA4CCCDFC2A806                         |
| Superstar_MemberCard.tiff.exe | MD5       | ACE3E42D95E5B9D0744763BDE9888069                                 |
## Skills Learned
- **Static PE Analysis:** Using tools like PEStudio to inspect a binary's metadata, resources, and strings.
- **Embedded Script Extraction:** Identifying and locating obfuscated PowerShell scripts embedded within an executable's resources.
- **Deobfuscation Techniques:** Recognizing and reversing common obfuscation methods, such as reversed strings and **Base64** encoding, using tools like CyberChef.
- **PowerShell Script Analysis:** Analyzing deobfuscated PowerShell code to understand its logic, including C2 communication, data staging, and exfiltration.
- **Indicator of Compromise (IOC) Extraction:** Pulling critical IOCs, such as C2 IP addresses and hardcoded passwords, from malicious code.
- **MITRE ATT&CK Mapping:** Associating observed malware behaviors with their corresponding ATT&CK framework technique IDs.
## Initial Analysis
The investigation involved a static analysis of the `Superstar_MemberCard.tiff.exe` binary to uncover its true purpose.
1. **Initial Triage:** The executable was analyzed with **PEStudio**, which provided its **SHA256 hash**, creation timestamp (`2024-03-13 10:38:06`), and other metadata. A key finding in the file's resources was its original name: **`newILY.ps1`**, indicating it was a PowerShell script converted into an executable.
2. **Script Extraction and Deobfuscation:** An obfuscated block of code was found in the binary at offset **`2C74`**. The obfuscation technique involved reversing the character order of a string and then encoding it with **Base64**. Using CyberChef, this process was reversed to reveal a clean PowerShell script.
3. **Functionality Analysis:** The deobfuscated script revealed the malware's functionality. It used the **`Invoke-WebRequest`** cmdlet for network communications. It was designed to collect files and store them in a staging directory at **`C:\Users\Public\Public Files`** before exfiltration. This behavior corresponds to the MITRE ATT&CK technique **T1119 (Automated Collection)**.
4. **IOC Discovery:** The script contained several hardcoded Indicators of Compromise:
    - **C2 IP Addresses:** `35.169.66.138` and `44.206.187.144`.
    - **Exfiltration Password:** `M8&C!i6KkmGL1-#`.
The binary is a dropper that executes a PowerShell script to stage and exfiltrate files from a victim's machine to attacker-controlled infrastructure.
## Questions:
1. **To accurately reference and identify the suspicious binary, please provide its SHA256 hash.**
Part of the initial static analysis of the binary, we find that the SHA256 sum is `12DAA34111BB54B3DCBAD42305663E44E7E6C3842F015CCCBBE6564D9DFD3EA3`.

2. **When was the binary file originally created, according to its metadata (UTC)?**
Utilizing PEStudio, we can find that the binary was created on `2024-03-13 10:38:06`.

![image one](./Images/Pasted%20image%2020250915143643.png)

3. **Examining the code size in a binary file can give indications about its functionality. Could you specify the byte size of the code in this binary?**
According to PEStudio, we can find the size of the binary as `38400` bytes. 

![image two](./Images/Pasted%20image%2020250915143841.png)

4. **It appears that the binary may have undergone a file conversion process. Could you determine its original filename?**
Continuing to review the binary in PEStudio, we can see, under the resources tab, that the binary was originally named `newILY.ps1`.

![image three](./Images/Pasted%20image%2020250915144059.png)

5. **Specify the hexadecimal offset where the obfuscated code of the identified original file begins in the binary.**
We can find the offset of the location where the obfuscated code looks by inspecting the strings in PEStudio. The offset is `2C74`. 

![image four](./Images/Pasted%20image%2020250915144524.png)

6. **The threat actor concealed the plaintext script within the binary. Can you provide the encoding method used for this obfuscation?**
We can see from the code snippet that the encoding is `base64`.

7. **What is the specific cmdlet utilized that was used to initiate file downloads?**
Based on the code that is not obfuscated, we can see how to directly decode it. The characters are stored in reverse order and then base64 encoded. So we can use CyberChef to reverse the characters and then base64 decode them. This provides us the answer of `Invoke-WebRequest`.

![image five](./Images/Pasted%20image%2020250915145119.png)

8. **Could you identify any possible network-related Indicators of Compromise (IoCs) after examining the code? Separate IPs by comma and in ascending order.**
You can find the following two IP addresses within the obfuscated code. `35.169.66.138,44.206.187.144`.

![image six](./Images/Pasted%20image%2020250915145447.png)

![image seven](./Images/Pasted%20image%2020250915145503.png)

9. **The binary created a staging directory. Can you specify the location of this directory where the harvested files are stored?**
We can see that, at the beginning, a likely suspect directory was utilized. `C:\Users\Public\Public Files`.

![image eight](./Images/Pasted%20image%2020250915145603.png)

10. **What MITRE ID corresponds to the technique used by the malicious binary to autonomously gather data?**
Doing a Google search for the “MITRE ID corresponds to the technique used by the malicious binary to autonomously gather data,” you can find a few hits, but directly Google points to `T1119`.

![image nine](./Images/Pasted%20image%2020250915145728.png)

11. **What is the password utilized to exfiltrate the collected files through the file transfer program within the binary?**
Re-inspecting the obfuscated code, we can find the password is attached to one of the URLs from question 8. The password is `M8&C!i6KkmGL1-#`.

![image ten](./Images/Pasted%20image%2020250915145849.png)