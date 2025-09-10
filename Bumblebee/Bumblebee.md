# HTB Sherlock - Bumblebee

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-10 | Andrew McKenzie | Easy       | DFIR           |

---
## Description
This challenge focuses on a web application compromise investigation. By analyzing a phpBB forum's database dump and its corresponding web server access log, the goal is to trace the actions of a malicious external contractor. The investigation covers the entire attack lifecycle, from initial account creation and credential theft via a malicious post to privilege escalation and, ultimately, data exfiltration.
## Scenario
An external contractor has accessed the internal forum here at Forela via the Guest Wi-Fi, and they appear to have stolen credentials for the administrative user! We have attached some logs from the forum and a full database dump in sqlite3 format to help you in your investigation.
## Artifacts Provided
- bumblebee.zip
	- incident.tgz
		- phpbb.sqlite3
		- access.log

| Filename      | Algorithm | Hash                                                             |
| ------------- | --------- | ---------------------------------------------------------------- |
| phpbb.sqlite3 | SHA256    | ec7579dbe5435f1972a44d462a8dd0b76db994be4eb5f68b5c3622164418940f |
| phpbb.sqlite3 | SHA1      | 2e18a569b6edf997e985efe3f6d98dc2347f3aef                         |
| phpbb.sqlite3 | MD5       | c8e5e00a1c6ea2de63d664ce50981c6b                                 |
| access.log    | SHA256    | 43ca54b7fce36f772d8e0705625b2f54eaf91a3d32e71d342b1c4af7a16ce577 |
| access.log    | SHA1      | f9e1f7987744c88db49af6dadff250b2289b04f9                         |
| access.log    | MD5       | 06f9895e21643aa5bc74bfcc1a0a5f79                                 |
## Skills Learned
- **SQLite Database Forensics:** Querying a database to extract user information, post content, configuration data, and audit logs.
- **Web Server Log Analysis:** Analyzing `access.log` files to trace user sessions, identify login events, and track file downloads.
- **Data Correlation:** Linking evidence between a database (e.g., user IDs, timestamps) and log files to build a comprehensive incident timeline.
- **Time Zone Conversion:** Correctly converting timestamps with timezone offsets and epoch formats to a standardized UTC format.
- **Malicious Content Identification:** Analyzing user-generated content within a database to find injected HTML/JavaScript used for credential theft.
## Initial Analysis
The investigation involved a correlated analysis of the `phpbb.sqlite3` database and the `access.log` to reconstruct the attacker's activities.
1. **Initial Foothold:** The investigation began by identifying the external contractor in the `phpbb_users` database table. The user **`apoole1`** was confirmed as the attacker, having registered from the IP address **`10.10.0.78`**.
2. **Credential Theft:** The attacker then made a malicious post (post_id **`9`**) containing a fake login form. The form was designed to send any submitted credentials to a harvester at **`http://10.10.0.78/update.php`**. This successfully captured the administrator's credentials.
3. **Account Takeover:** The `access.log` confirmed that the attacker used the stolen credentials to log in as the `admin` user at **10:53:12 UTC**.
4. **Privilege Escalation:** Immediately after logging in as the administrator, the attacker escalated their own account's privileges. The `phpbb_log` table shows that at **10:53:51 UTC**, the `apoole1` user was added to the Administrator group.
5. **Information Gathering:** During the investigation, plaintext credentials for an LDAP connection (`Passw0rd1`) were discovered in the `phpbb_config` table, highlighting a severe security misconfiguration.
6. **Data Exfiltration:** The final act of the attacker was to download a backup of the forum's database. The `access.log` shows this download occurred at **11:01:38 UTC**, with a total file size of **34,707 bytes**.
## Questions:
1. **What was the username of the external contractor?**
Reviewing the phpbb_users table in SQLITE3, we can see a small list of possible usernames in this scenario. To deduce the username of the external contractor, we just need to look at the `user_email` section, as the contractor's email provides a strong hint. As there are two with similar usernames, we can assume the one with the latest user_lastmark is the one needed to answer this question. The answer is `apoole1`.

![image one](./Images/Pasted%20image%2020250910114109.png)

2. **What IP address did the contractor use to create their account?**
The IP address is located on the same row of data from the previous question. The IP address is `10.10.0.78`.

![image two](./Images/Pasted%20image%2020250910114147.png)

3. **What is the post_id of the malicious post that the contractor made?**
We can utilize the phpbb_posts table to find this information. From the previous question, there is a user_lastpost_time column containing an epoch timestamp. Using that timestamp, we can see that post_id `9` is the post that corresponds to the contractor's last post.

![image three](./Images/Pasted%20image%2020250910114940.png)
![image four](./Images/Pasted%20image%2020250910115006.png)

4. **What is the full URI that the credential stealer sends its data to?**
Reviewing the same line in the table from the above question, you can see the contractors post. Within the post you can eventually find a form action with the URI `http://10.10.0.78/update.php`.

![image five](./Images/Pasted%20image%2020250910115911.png)

5. **When did the contractor log into the forum as the administrator? (UTC)**
Using the access logs, we can filter for the “admin” keyword, and we see two different potential times of activity. The second one being the answer: `26/04/2023 10:53:12` (the server is +0100, so we need to subtract an hour to get UTC time).

![image six](./Images/Pasted%20image%2020250910120907.png)

6. **In the forum there are plaintext credentials for the LDAP connection, what is the password?**
Since the forum has the credentials, we can view the phpbb_config table and filter for LDAP. We can see the password is `Passw0rd1`.

![image seven](./Images/Pasted%20image%2020250910121219.png)

7. **What is the user agent of the Administrator user?**
Filtering the access logs for “ldap,” we can see multiple requests, all having the same user agent, which is the answer `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36`.

![image eight](./Images/Pasted%20image%2020250910121528.png)

8. **What time did the contractor add themselves to the Administrator group? (UTC)**
For this we can go back to the phpbb_log table and look for the “LOG_USERS_ADDED” log_operation. The timestamp is in epoch, but the answer is `26/04/2023 10:53:51`.

![image nine](./Images/Pasted%20image%2020250910121731.png)

9. **What time did the contractor download the database backup? (UTC)**
To find this question, we just need to do some filtering on the access logs. After filtering for the appropriate IP address and keywords like “back.” We need to look for a GET request to a backup file. We find one such occurrence at `26/04/2023 11:01:38` (don't forget to subtract one hour from what is actually in the logs).

![image ten](./Images/Pasted%20image%2020250910122410.png)

10. **What was the size in bytes of the database backup as stated by access.log?**
We can see the size of the download in the same line from the previous question. It was `34707`.