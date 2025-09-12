# HTB Sherlock - Loggy

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type   |
| ---------- | --------------- | ---------- | ---------------- |
| 2025-09-12 | Andrew McKenzie | Easy       | Malware Analysis |

---
## Description
This challenge involves performing basic static and dynamic malware analysis on a keylogger executable. By using reverse engineering tools like Cutter and string analysis tools like FLOSS, the objective is to determine the malware's capabilities, identify its dependencies, and extract critical indicators of compromise (IOCs) such as command-and-control (C2) server details and hardcoded credentials.
## Scenario
Janice from accounting is beside herself! She was contacted by the SOC to tell her that her work credentials were found on the dark web by the threat intel team. We managed to recover some files from her machine and sent them to the our REM analyst.
## Artifacts Provided
- Loggy.zip
	- loggy.exe

| Filename  | Algorithm | Hash                                                             |
| --------- | --------- | ---------------------------------------------------------------- |
| loggy.exe | SHA256    | 6ACD8A362DEF62034CBD011E6632BA5120196E2011C83DC6045FCB28B590457C |
| loggy.exe | SHA1      | 5A1B751B2B4929FAEC702DF0719D498659E0887B                         |
| loggy.exe | MD5       | 215E79EAA7B9AC16A7D2BCE15C94B8DE                                 |
## Skills Learned
- **Static Malware Analysis:** Using a reverse engineering tool like Cutter to inspect an executable's properties, functions, and disassembled code.
- **String Extraction and Analysis:** Utilizing FLOSS to extract strings from a binary and filtering them to identify libraries and potential capabilities.
- **Identifying Malware Capabilities:** Deducing malware functions such as keylogging, screen capture, and FTP data exfiltration by analyzing imported libraries and function names.
- **Reverse Engineering Go Binaries:** Analyzing the structure and characteristics of malware compiled with the Go programming language.
- **Dynamic Malware Analysis:** Running malware in a controlled environment to observe its runtime behavior, such as file creation.
- **Indicator of Compromise (IOC) Extraction:** Finding hardcoded IOCs like C2 domains and credentials within the malware's code.
## Initial Analysis
The investigation involved a combination of static and dynamic analysis to understand the functionality of `loggy.exe`.
1. **Initial Triage:** The executable was first opened in **Cutter**, which identified it as a **golang v1.22.3** binary and provided its **SHA-256 hash**.
2. **Capability Assessment:** Strings were extracted using **FLOSS**, which revealed several imported GitHub repositories. The presence of `github.com/kbinani/screenshot` and `github.com/jlaffaye/ftp` immediately suggested the malware's ability to take screenshots and exfiltrate data via FTP.
3. **Code Analysis:** Deeper static analysis in **Cutter** confirmed these capabilities. A function named `sendFilesViaFTP` was discovered, which contained hardcoded strings for the C2 server. The exfiltration domain was **`gotthem.htb`**, and the FTP credentials were **`NottaHacker:Cle@rtextP@ssword`**. The `syscall.WriteFile` function was also present, indicating that the malware writes data to disk.
4. **Behavioral Analysis:** Dynamic analysis (running the executable) confirmed that it creates a file named **`keylog.txt`** to log keystrokes. Analysis of the provided `keylog.txt` file revealed the compromised credentials of the user: **`Janice:Password123`**.
5. **Data Exfiltration:** Examination of the captured screenshots confirmed the malware was working as intended, with the last captured image showing the game **`Solitaire`** open on the user's desktop.
The analysis confirms that `loggy.exe` is a keylogger and screen-capture tool that exfiltrates stolen data to a hardcoded FTP server.
## Questions:
1. **What is the SHA-256 hash of this malware binary?**
Once we open the malicious executable in Cutter to learn more about it, we can find the SHA256 hash. The hash is `6acd8a362def62034cbd011e6632ba5120196e2011c83dc6045fcb28b590457c`.

![image one](./Images/Pasted%20image%2020250912083112.png)

2. **What programming language (and version) is this malware written in?**
Cutter also shows that the language is Go version 1.22.3. So, the answer is `golang 1.22.3`.

![image two](./Images/Pasted%20image%2020250912083202.png)

3. **There are multiple GitHub repos referenced in the static strings. Which GitHub repo would be most likely suggest the ability of this malware to exfiltrate data?**
Running FLOSS against the binary produces many strings. We can filter out using PowerShell `type C:\Users\andrew\Desktop\floss_results.txt | Select-String -Pattern "github.com"`. From the results, we can see a package with FTP, showing that this is probably the data exfiltration asset. The answer is `github.com/jlaffaye/ftp`.

![image three](./Images/Pasted%20image%2020250912083433.png)

4. **What dependency, expressed as a GitHub repo, supports Janice’s assertion that she thought she downloaded something that can just take screenshots?**
From the FLOSS results, we can see one repository contains the word screenshot in its title. The answer is `github.com/kbinani/screenshot`.

![image four](./Images/Pasted%20image%2020250912083555.png)

5. **Which function call suggests that the malware produces a file after execution?**
Filtering the functions pane in Cutter, we can see many items that return for “write.” But of interest is the syscall to `WriteFile`.

![image five](./Images/Pasted%20image%2020250912083916.png)

6. **You observe that the malware is exfiltrating data over FTP. What is the domain it is exfiltrating data to?**
Within Cutter, you can see a function `sendFilesViaFTP`, this is likely going to contain the domain that we are looking for. While reviewing the disassembled code, we can find a string for the domain, and it is `gotthem.htb`.

![image six](./Images/Pasted%20image%2020250912142707.png)

7. **What are the threat actor’s credentials?**
We can continue inspecting the function to find the string locations for both the username and password. The pair is `NottaHacker:Cle@rtextP@ssword`.

![image seven](./Images/Pasted%20image%2020250912144822.png)

8. **What file keeps getting written to disk?**
When running the application, you can see a file (outside of screenshot pictures) getting written to disk. The filename is `keylog.txt`.

![image eight](./Images/Pasted%20image%2020250912144937.png)

9. **When Janice changed her password, this was captured in a file. What is Janice's username and password?**
If you inspect the keylog file that was provided with the zip, we can piece together Janice's username and password; it is `Janice:Password123`.

![image nine](./Images/Pasted%20image%2020250912145130.png)
![image ten](./Images/Pasted%20image%2020250912145150.png)

10. **What app did Janice have open the last time she ran the "screenshot app"?**
Looking at the provided screenshots, it appears she was playing `Solitaire`.

![image eleven](./Images/Pasted%20image%2020250912145342.png)