# HTB Sherlock: SmartPants
![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-08-31 | Andrew McKenzie | Very Easy  | DFIR           |

---
## Description
This challenge involves performing a triage analysis on a compromised Windows system. An attacker gained RDP access to a file server, downloaded several tools, located and exfiltrated critical documents, and then attempted to cover their tracks by destroying the original files and clearing event logs. The investigation leverages Windows Event Logs and specifically enabled SmartScreen Debug Logs to piece together the attacker's timeline and actions.
## Scenario
Forela's CTO, Dutch, stores important files on a separate Windows system because the domain environment at Forela is frequently breached due to its exposure across various industries. On 24 January 2025, our worst fears were realized when an intruder accessed the file server, installed utilities to aid their actions, stole critical files, and then deleted them, rendering them unrecoverable. The team was immediately informed of the extortion attempt by the intruders, who are now demanding money. While our legal team addresses the situation, we must quickly perform triage to assess the incident's extent. Note from the manager: We enabled SmartScreen Debug Logs across all our machines for enhanced visibility a few days ago, following a security research recommendation. These logs can provide quick insights, so ensure they are utilized.
## Artifacts Provided
- SmaryPants.zip
	- Logs

> File hashes saved in text files in `Hashes` directory.
## Skills Learned
- Parsing Windows Event Logs (`.evtx`) using tools like EvtxCmd.
- Conducting timeline analysis with Timeline Explorer.
- Filtering event logs by specific Event IDs to find key activities (e.g., RDP logon, log clearing).
- Analyzing SmartScreen logs to identify downloaded files and execution events.
- Reconstructing an attacker's steps from initial access to data exfiltration and destruction.
## Initial Analysis
The initial step of the investigation involves processing the large volume of provided logs. Eric Zimmerman's `EvtxCmd` tool is used to parse the entire directory of `.evtx` files into a more manageable CSV format. This CSV file is then loaded into Timeline Explorer, which provides a powerful interface for sorting, filtering, and reviewing events in chronological order. This setup allows for an efficient analysis of the attacker's activities on the day of the incident.
## Questions:
1. **The attacker logged in to the machine where Dutch saves critical files, via RDP on 24th January 2025. Please determine the timestamp of this login.**
As there are an enormous amount of logs, we can utilize Eric Zimmerman's [EvtxCmd](https://github.com/EricZimmerman/evtx) to parse the entire directory into CSV files that we can then utilize [Timeline Explorer](https://ericzimmerman.github.io/#!index.md) to better review.

With the results loaded in, we can now filter for event code 1149, which represents a successful RDP connection. The single result on the day in question provides the timestamp `2025-01-24 10:15:14`.
![image one](./Images/Pasted%20image%2020250831223834.png)

2. **The attacker downloaded a few utilities that aided them for their sabotage and extortion operation. What was the first tool they downloaded and installed?**
Since SmartScreen debug logs were provided, we can filter Timeline Explorer for “debug” and review the first timestamp item. This points to `Winrar` as the first downloaded tool.

![image two](./Images/Pasted%20image%2020250831224829.png)

3. **They then proceeded to download and then execute the portable version of a tool that could be used to search for files on the machine quickly and efficiently. What was the full path of the executable?**
The answer to this question is in the same location as the previous answer. Reviewing the items I don't personally know, I search `Everything.exe` on Google and find out that it is precisely what the question describes.

![image three](./Images/Pasted%20image%2020250831225049.png)

4. **What is the execution time of the tool from task 3?**
This can be found within the same line from the previous question. The time was recorded at `2025-01-24 10:17:33`.

![image four](./Images/Pasted%20image%2020250831225338.png)

5. **The utility was used to search for critical and confidential documents stored on the host, which the attacker could steal and extort the victim. What was the first document that the attacker got their hands on and breached the confidentiality of that document?**
Removing the filter for download but staying within the `SmartScreen` logs. We can sift through until we find the download/execute timestamp from the previous question. Then, shortly after, we notice a very sensitive-sounding filename in the logs, `C:\Useres\Dutch\Documents\2025- Board of directors Documents\Ministry Of Defense Audit.pdf`.

![image five](./Images/Pasted%20image%2020250831225759.png)

6. **Find the name and path of second stolen document as well.**
We can find this information directly below the previous question. The full file path is `C:\Users\Dutch\Documents\2025- Board of directors Documents\2025-BUDGET-ALLOCATION-CONFIDENTIAL.pdf`.

![image six](./Images/Pasted%20image%2020250831230038.png)

7. **The attacker installed a Cloud utility as well to steal and exfiltrate the documents. What is name of the cloud utility?**
This is the third item that was downloaded and reviewed in question 2. However, you have to format your answer specifically as `MEGAsync`.

![image seven](./Images/Pasted%20image%2020250831230316.png)

8. **When was this utility executed?**
Data is only placed into the `AppData` directory when its application puts it there during use or when the item is installed for a single user. If we review the log output, we can see a second log with the keyword “MEGAsync,” this time regarding data stored in `AppData`, indicating this is the field of interest. The time of this field is `2025-01-24 10:22:19`.

![image eight](./Images/Pasted%20image%2020250831230829.png)

9. **The Attacker also proceeded to destroy the data on the host so it is unrecoverable. What utility was used to achieve this?**
This is the fourth downloaded item from question 2, `File Shredder`.

![image nine](./Images/Pasted%20image%2020250831230958.png)

10. **The attacker cleared 2 important logs, thinking they covered all their tracks. When was the security log cleared?**
To find this information, we will need to utilize event code 1104 (ensuring we are also filtering by the day in question). This should be the last item in results with a time of `2025-01-24 10:28:41`.

![image ten](./Images/Pasted%20image%2020250831231547.png)
