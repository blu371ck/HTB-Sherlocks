# HTB Sherlock - Operation Blackout 2025 - Ghost Thread

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-08 | Andrew McKenzie | Easy       | DFIR           |

---
## Description
This challenge focuses on analyzing a **process injection** attack by examining a malicious executable and a capture of its API calls. Using tools like IDA for static analysis and API Monitor for dynamic analysis, the goal is to reverse-engineer the attack by identifying the specific injection technique, the targeted process, and the sequence of Win32 API functions used to carry out the injection.
## Scenario
Byte Doctor suspects the attacker used a process injection technique to run malicious code within a legitimate process, leaving minimal traces on the file system. The logs reveal Win32 API calls that hint at a specific injection method used in the attack. Your task is to analyze these logs using a tool called API Monitor to uncover the injection technique and identify which legitimate process was targeted.
## Artifacts Provided
- GhostThread.zip
	- Ghost-Thread.apmx64
	- inject.exe.i64

| Filename            | Algorithm | Hash                                                             |
| ------------------- | --------- | ---------------------------------------------------------------- |
| Ghost-Thread.apmx64 | SHA256    | 1ADEE8789B3AF0ABAD4E31510B5080975441A43DCDEFF3D60C51F2AC5F325151 |
| Ghost-Thread.apmx64 | SHA1      | 26A974E31ABC364EC17B1AC17BBEAF10CBF57BCE                         |
| Ghost-Thread.apmx64 | MD5       | DB83F26E5E5F3BAAC0D29A6CB316EAAC                                 |
| inject.exe.i64      | SHA256    | 651B0F57835EA1F11EB2078D8375EA9BA6A760835FD660FA5F67593487697F37 |
| inject.exe.i64      | SHA1      | 75C734DADF152B30ABF9AB45636EE7450F31404C                         |
| inject.exe.i64      | MD5       | FA85994F8B272637E92169A528568C36                                 |
## Skills Learned
- **Static Analysis with IDA:** Using a disassembler to inspect an executable's imports and code structure to identify its core functionality and potential malicious techniques.
- **Dynamic Analysis with API Monitor:** Analyzing a capture of Win32 API calls to trace a program's execution flow and understand its runtime behavior.
- **Process Injection Identification:** Recognizing the indicators of a **Thread Local Storage (TLS) Callback Injection** from static and dynamic analysis.
- **Win32 API Analysis:** Identifying the purpose of key APIs used for process enumeration (`CreateToolhelp32Snapshot`) and injection (`CreateRemoteThread`).
- **MITRE ATT&CK Mapping:** Associating an observed technique with its corresponding MITRE ATT&CK ID (**T1055.005**).
## Initial Analysis
The investigation was conducted in two parts: static analysis of the injector executable and dynamic analysis of its captured API calls.

First, the `inject.exe.i64` file was loaded into **IDA** for static analysis. The presence of **Thread Local Storage (TLS) callback functions** that contained process injection logic was a key finding. This immediately pointed to a **TLS Callback Injection** technique, a stealthy method where malicious code is executed before the program's main entry point. Inspection of the executable's imports also confirmed the use of `CreateToolhelp32Snapshot`, an API used to enumerate running processes.

Next, the `Ghost-Thread.apmx64` capture was opened in **API Monitor** to view the program's runtime behavior. The logs showed the injector using `CreateToolhelp32Snapshot` to list system processes and then iterating through them, comparing each process name to find its target. The target was identified as **`Notepad.exe`** with a Process ID of **`16224`**.

Once the target process was found, the attacker allocated **511 bytes** of memory within `Notepad.exe`, wrote the shellcode to this new memory region, and then used **`CreateRemoteThread`** to execute it. The final action recorded was a call to **`ExitProcess`**, which terminated the injector, completing the attack before its `main()` function was ever reached.
## Questions:
1. **What process injection technique did the attacker use?**
Start with opening the executable using IDA. From there we can see some comments in the code referencing injection; double-clicking on “OpenProcess” reveals: `extrn OpenProcess:qword ; CODE XREF: TlsCallback_0+54↑p`. Taking a look online, we can see that TLS stands for `thread local storage` and that these can be part of callback injection, which involves manipulating pointers inside a PE to redirect processes to malicious code before getting to any entry points. This technique is part of MITRE ATT&CK ID [T1055.005](https://attack.mitre.org/techniques/T1055/005/)

![image 1.1](./Images/Pasted%20image%2020250908215750.png)
![image 1.2](./Images/Pasted%20image%2020250908220034.png)

2. **Which Win32 API was used to take snapshots of all processes and threads on the system?**
For this question, I started first by googling “Win32 API used to take snapshots of all processes and threads on the system.” Gemini provided a lead to investigate in IDA.

![image 2.1](./Images/Pasted%20image%2020250908220226.png)
Reviewing IDA imports, we can see that this Win32 API is present and is the answer, `CreateToolhelp32SNapshot`.

![image 2.2](./Images/Pasted%20image%2020250908220300.png)

3. **Which process is the attacker's binary attempting to locate for payload injection?**
Moving to the API monitor inspecting Ghost-Thread.apmx64, we view `inject.exe`. From there we can see that there is a lot of comparing of “`Notepad.exe`” to other processes.

![image 5](./Images/Pasted%20image%2020250908221307.png)

4. **What is the process ID of the identified process?**
Scrolling through the results until the match for Notepad.exe was found. We can see the process ID is listed as `16224`.

![image 6](./Images/Pasted%20image%2020250908221615.png)

5. **What is the size of the shellcode?**
Shortly after the process handle was created, we can see that virtual memory is allocated. The size is then listed on that step as `511`.

![image seven](./Images/Pasted%20image%2020250908221736.png)

6. **Which Win32 API was used to execute the injected payload in the identified process?**
A couple of items down from the previous question, we can see that `CreateRemoteThread` was called, and after searching online, this is one Win32 API listed for executing injected payloads.

![image 8.1](./Images/Pasted%20image%2020250908222155.png)
![image 8.2](./Images/Pasted%20image%2020250908222207.png)

7. **The injection method used by the attacker executes before the main() function is called. Which Win32 API is responsible for terminating the program before main() runs?**
The final item in this list is simply `ExitProcess`, which is the answer to this question.

![image nine](./Images/Pasted%20image%2020250908222304.png)