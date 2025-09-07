# HTB Sherlock - BFT

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-06 | Andrew McKenzie | Very Easy | DFIR |

---
## Description
This challenge provides a hands-on introduction to **Master File Table (MFT) forensics**. Participants learn to use standard DFIR tools (`MFTECmd`, `Timeline Explorer`, and a hex editor) to parse and analyze an MFT file from an NTFS file system. The objective is to trace malicious activity from the initial download of a file to the recovery of critical indicators of compromise (IOCs) hidden within the MFT itself.
## Scenario
In this Sherlock, you will become acquainted with MFT (Master File Table) forensics. You will be introduced to well-known tools and methodologies for analyzing MFT artifacts to identify malicious activity. During our analysis, you will utilize the MFTECmd tool to parse the provided MFT file, TimeLine Explorer to open and analyze the results from the parsed MFT, and a Hex editor to recover file contents from the MFT.
## Artifacts Provided
- BFT.zip
	- `BFT\C\$MFT`

| Filename | Algorithm | Hash                                                             |
| -------- | --------- | ---------------------------------------------------------------- |
| `$MFT`   | SHA256    | 9CAB6341521A15D8356221AC1A0D0BCB5823C044CAA98C5599EA60C176546DEE |
| `$MFT`   | SHA1      | 4DB07E9E52E3147E804F6318457A27E79A7C8B69                         |
| `$MFT`   | MD5       | 83A65487821A804375B5CD17FDFABF5E                                 |
## Skills Learned
- **MFT Parsing and Analysis:** Using `MFTECmd` to parse the `$MFT` file and `Timeline Explorer` to analyze the filesystem timeline.
- **Filesystem Timelining:** Filtering filesystem metadata based on timestamps and attributes to reconstruct a sequence of events.
- **Zone Identifier Analysis:** Extracting the `HostUrl` from the `$Zone.Identifier` alternate data stream to determine a file's download origin.
- **MFT Resident File Recovery:** Understanding the concept of MFT resident files and using a hex editor to carve file content directly from its MFT record.
- **Offset Calculation:** Calculating the physical byte offset of an MFT record using its entry number.
## Initial Analysis
The investigation began by parsing the `$MFT` artifact using `MFTECmd` to generate a CSV file. This file was then loaded into `Timeline Explorer` for detailed analysis.

The first objective was to find the initial infection vector. By filtering the timeline for file creation events on the specified date (`2024-02-13`) and for files with a `.zip` extension, the initial downloaded archive, `Stage-20240213T093324Z-001.zip`, was quickly identified. A crucial IOC was recovered by examining the `Zone ID Contents` for this file, which revealed the full Google Storage URL from which it was downloaded.

Next, the contents of the unzipped archive were examined by filtering the `Parent Path` to the extracted folder. This led to the discovery of a malicious batch script, `invoice.bat`. With the stager file identified, the next step was to recover its contents.

Because the `invoice.bat` script was very small, it was a prime candidate for being an **MFT resident file**, meaning its contents would be stored directly within its MFT record instead of elsewhere on the disk. To find it, the script's MFT entry number was used to calculate its exact byte offset within the `$MFT` file. A hex editor (`HxD`) was then used to jump to this offset. As suspected, the full contents of the batch script were present in the MFT record, revealing a PowerShell command that contained the C2 server IP and port.
## Questions:
1. **Simon Stark was targeted by attackers on February 13. He downloaded a ZIP file from a link received in an email. What was the name of the ZIP file he downloaded from the link?**
To analyze the `$MFT` file, we first need to utilize `MFTEcmd` to extract the data into CSV format. We can then analyze the results in Timeline Explorer. When in Timeline Explorer, we can start by filtering the `Created` column for the day provided, 02/13/2024, and then we can also filter further by adding contains `.zip` to the File Name column. We can see a result for `Stage-20240213T093324Z-001.zip`.

![image one](./Images/Pasted%20image%2020250906223152.png)

2. **Examine the Zone Identifier contents for the initially downloaded ZIP file. This field reveals the HostUrl from where the file was downloaded, serving as a valuable Indicator of Compromise (IOC) in our investigation/analysis. What is the full Host URL from where this ZIP file was downloaded?**
We can keep the results as we had from the previous question. Scrolling to the right we are provided a column 'Zone ID Contents'. For the second item in the list we are provided with the full URL: `https://storage.googleapis.com/drive-bulk-export-anonymous/20240213T093324.039Z/4133399871716478688/a40aecd0-1cf3-4f88-b55a-e188d5c1c04f/1/c277a8b4-afa9-4d34-b8ca-e1eb5e5f983c?authuser`.

![image two](./Images/Pasted%20image%2020250906223350.png)

3. **What is the full path and name of the malicious file that executed malicious code and connected to a C2 server?**
Modifying the filters by removing the “File Name” filter we previously used and adding `.\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\Stage\invoice\invoices` to “Parent Path,” we can see some new results, one ending with a `.bat` file extension, `invoice.bat`. Making the full path `C:\Users\simon.stark\Downloads\Stage-20240213T093324Z-001\Stage\invoice\invoices\invoice.bat`.

![image three](./Images/Pasted%20image%2020250906223939.png)

4. **Analyze the $Created0x30 timestamp for the previously identified file. When was this file created on disk?**
We can keep our results; scroll to the right to find this column, and the timestamp is `2024-02-13 16:38:39`.

![image four](./Images/Pasted%20image%2020250906224023.png)

5. **Finding the hex offset of an MFT record is beneficial in many investigative scenarios. Find the hex offset of the stager file from Question 3.**
Doing some research online, it turns out that the Entry Number column in Timeline Explorer can be multiplied by 1024 to get the decimal equivalent [source](https://aaforensics.blogspot.com/2014/05/the-master-file-table-part-2.html). Then you can convert that decimal number to hexadecimal with an online converter, making the answer `16E3000`.

![image five](./Images/Pasted%20image%2020250906224349.png)
![image six](./Images/Pasted%20image%2020250906224409.png)
![image seven](./Images/Pasted%20image%2020250906224453.png)

6. **Each MFT record is 1024 bytes in size. If a file on disk has smaller size than 1024 bytes, they can be stored directly on MFT File itself. These are called MFT Resident files. During Windows File system Investigation, its crucial to look for any malicious/suspicious files that may be resident in MFT. This way we can find contents of malicious files/scripts. Find the contents of The malicious stager identified in Question3 and answer with the C2 IP and port.**
Utilizing HxD, we can open the file, then "Search" > “Go To…” and in the Offset section type the offset from the previous question `16E3000`. After clicking ok, we can scroll down and start to see PowerShell instructions, and eventually we see `43.204.110.203:6666`.

![image eight](./Images/Pasted%20image%2020250906225153.png)