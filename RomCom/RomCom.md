# HTB Sherlock - RomCom

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-11 | Andrew McKenzie | Very Easy  | DFIR           |

---
## Description
This challenge involves performing endpoint forensic analysis on a triage VHDX image to investigate a compromise stemming from a WinRAR vulnerability. By parsing the Master File Table ($MFT) and building a filesystem timeline, the goal is to reconstruct the attack, identifying the initial malicious archive, the dropped backdoor, the persistence mechanism, and the decoy document used to deceive the user.
## Scenario
Susan works at the Research Lab in Forela International Hospital. A Microsoft Defender alert was received from her computer, and she also mentioned that while extracting a document from the received file, she received tons of errors, but the document opened just fine. According to the latest threat intel feeds, WinRAR is being exploited in the wild to gain initial access into networks, and WinRAR is one of the Software programs the staff uses. You are a threat intelligence analyst with some background in DFIR. You have been provided a lightweight triage image to kick off the investigation while the SOC team sweeps the environment to find other attack indicators.
## Artifacts Provided
- RomCom.zip
	- 2025-09-02T083211_pathology_department_incidentalert.vhdx

| Filename                                                  | Algorithm | Hash |
| --------------------------------------------------------- | --------- | ---- |
| 2025-09-02T083211_pathology_department_incidentalert.vhdx | SHA256    |      |
| 2025-09-02T083211_pathology_department_incidentalert.vhdx | SHA1      |      |
| 2025-09-02T083211_pathology_department_incidentalert.vhdx | MD5       |      |
## Skills Learned
- **Disk Image Forensics:** Mounting and analyzing a VHDX disk image to investigate an endpoint.
- **MFT Analysis:** Using tools like `MFTECmd` to parse the Master File Table and `Timeline Explorer` to visualize and analyze filesystem activity.
- **Timeline Reconstruction:** Correlating file system timestamps (creation, modification, access) to build a precise timeline of an attack.
- **Exploit Chain Analysis:** Identifying the sequence of events following a vulnerability exploit, including the dropping of a decoy document, a backdoor, and a persistence artifact.
- **Persistence Mechanism Identification:** Recognizing the use of the user's Startup folder with a `.lnk` file to maintain persistence.
## Initial Analysis
The investigation began by using open-source threat intelligence to identify the specific vulnerability being exploited. Research confirmed that the RomCom threat group was leveraging **`CVE-2025-8088`**, a **path traversal** vulnerability in WinRAR.

With this context, the forensic analysis of the provided VHDX image commenced. The image was mounted, and the `$MFT` was parsed using `MFTECmd` to create a filesystem timeline in `Timeline Explorer`.
1. **Initial Vector:** The timeline was filtered to Susan's `Documents` folder, where the malicious archive, **`Pathology-Department-Research-Records.rar`**, was found. It was created at **08:13:50 UTC** and opened at **08:14:04 UTC**.
2. **Payload Delivery:** Upon opening the archive, the path traversal vulnerability was exploited. The decoy document, **`Genotyping_Results_B57_Positive.pdf`**, was extracted to the `Documents` folder as expected. However, the exploit simultaneously dropped the actual backdoor, **`ApbxHelper.exe`**, into the `C:\Users\Susan\Appdata\Local\` directory.
3. **Persistence:** To ensure the backdoor would run automatically, a shortcut file, **`Display Settings.lnk`**, was created in the user's Startup folder (`C:\Users\susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`). This technique ensures the malware executes every time the user logs in.
4. **User Deception:** The timeline's "Last Access" timestamp confirmed that Susan opened the decoy PDF at **08:15:05 UTC**, believing it was the only file extracted, while the malware was already active in the background.
## Questions:
1. **What is the CVE assigned to the WinRAR vulnerability exploited by the RomCom threat group in 2025?**
The CVE associated with RomCom and the WINRAR application is `CVE-2025-8088`. [Source](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)

2. **What is the nature of this vulnerability?**
From the above article, the nature of the vulnerability is a `path traversal` vulnerability.

![image one](./Images/Pasted%20image%2020250911160924.png)

3. **What is the name of the archive file under Susan's documents folder that exploits the vulnerability upon opening the archive file?**
First, we need to mount the image using FTK or Arsenal. Then we can use MFTECmd to target the `$MFT` file and create a CSV file. Then we can upload that CSV file to Timeline Explorer to view the results graphically.

Once there, we can filter the “Parent Path” directory for `Susan\Documents` and see the likely filename is `Pathology-Department-Research-Records.rar`.

![image two](./Images/Pasted%20image%2020250911161118.png)

4. **When was the archive file created on the disk?**
The creation date is located a few columns over from the last question's answer. We can see the creation time of `2025-09-02 08:13:50`.

![image three](./Images/Pasted%20image%2020250911161214.png)

5. **What was the archive file opened?**
For this we need to look at the “Last Record Change,” which is `2025-09-02 08:14:04`.

![image four](./Images/Pasted%20image%2020250911161501.png)

6. **What is the name of the decoy document extracted from the archive file, meant to appear legitimate and distract the user?**
The only other file listed in this same directory (where the RAR file is) is `Genotyping_Results_B57_Positive.pdf`.

![image five](./Images/Pasted%20image%2020250911161631.png)

7. **What is the name and path of the actual backdoor executable dropped by the archive file?**
We can cross-compare files created shortly after the timestamp in question 5 that still reside on the user's ultimate path. Doing this provides an event that occurred at 08:14:18, with a file named `ApbxHelper.exe`. Making the full path: `C:\Users\Susan\Appdata\Local\ApbxHelper.exe`.

![image six](./Images/Pasted%20image%2020250911164009.png)

8. **The exploit also drops a file to facilitate the persistence and execution of the backdoor. What is the path and name of this file?**
Utilizing the known file creation timestamp, we can expand our search to all directories under Susan. In general, it would be assumed the persistence is stored in “Startup,” as this is where items are stored for automatic starting when the user logs in.

Looking at the results, we can see three files that match the timestamp; the other two have already been discussed, so the likely persistence mechanism is the one placed in `Startup`. Which is `Display Settings.lnk`. For a full path of `C:\Users\susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk`

![image seven](./Images/Pasted%20image%2020250911164627.png)

9. **What is the associated MITRE Technique ID discussed in the previous question?**
The answer to this is actually wrong, I believe. The MITRE ATT&CK the question wants is `T1547.009`, but this is specific to shortcut modifications.

10. **When was the decoy document opened by the end user, thinking it to be a legitimate document?**
Utilizing the “Last Access” column from our data and knowing the filename already. We can see that the file was “last accessed” on `2025-09-02 08:15:05`.

![image eight](./Images/Pasted%20image%2020250911164807.png)