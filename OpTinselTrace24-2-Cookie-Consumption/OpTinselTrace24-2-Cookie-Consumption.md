# HTB Sherlock - OpTinselTrace24-2: Cookie Consumption

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-12 | Andrew McKenzie | Easy       | DFIR           |

---
## Description
This challenge focuses on a forensic investigation within a compromised Kubernetes environment. By analyzing a collection of logs—including application logs, Kubernetes object descriptions, and host process logs—the goal is to trace an attacker's steps from initial web application exploitation to establishing persistence, all within the context of a containerized infrastructure.
## Scenario
Santa’s North Pole Operations have implemented the “Cookie Consumption Scheduler” (CCS), a crucial service running on a Kubernetes cluster. This service ensures Santa’s cookie and milk intake is balanced during his worldwide deliveries, optimizing his energy levels and health.
## Artifacts Provided
- CookieConsumption.zip

| File Name             | Algorithm | Hash                                                             |
| --------------------- | --------- | ---------------------------------------------------------------- |
| CookieConsumption.zip | SHA256    | 87728bbc7ede12b5511855c96f2d37d70f18f928fe536bfca02fae5593ef362d |
| CookieConsumption.zip | SHA1      | 99659806253ba66d23e403923e7a467c51afab05                         |
| CookieConsumption.zip | MD5       | 734a32c6e2adb7fe4d0b10c60160b2bc                                 |
## Skills Learned
- **Kubernetes Log Analysis:** Correlating data across various Kubernetes artifacts, including application logs, service descriptions, pod configurations, and host process logs.
- **Web Application Fuzzing Detection:** Identifying automated scanning and fuzzing activity by spotting a high volume of `404` errors from a single IP address in web server logs.
- **Command Injection Analysis:** Analyzing executed commands through a vulnerable endpoint to understand attacker objectives.
- **Container Compromise Identification:** Tracing an attack back to a specific compromised pod by correlating attacker IP addresses with process and network logs.
- **Kubernetes Post-Exploitation:** Recognizing attacker TTPs within a Kubernetes cluster, such as deploying a custom malicious pod.
- **Persistence Detection:** Identifying persistence mechanisms by examining scheduled tasks like Cron jobs.
## Initial Analysis
The investigation involved a step-by-step analysis of the provided logs to reconstruct the attacker's kill chain within the Kubernetes cluster.
1. **Initial Reconnaissance:** The investigation started by understanding the service configuration. The `flask-app` was found to be running with **3 replicas** and exposed externally on **NodePort `30000`**.
2. **Web Application Exploitation:** The `flask-app.logs` revealed a fuzzing attack against the `/system/` endpoint, which began at **22:02:48 UTC**. The attacker eventually discovered a vulnerable command injection endpoint at **`/system/execute`**. Through this, they attempted to download additional tools using `curl`.
3. **Foothold Identification:** By analyzing the `host-process` logs, the attacker's IP was identified as **`10.129.231.112`**. Correlating this IP with other logs confirmed that the initial point of compromise was the pod named **`flask-app-77fbdcfcff-2tqgw`**.
4. **Post-Exploitation:** After gaining a foothold, the attacker deployed a malicious pod to maintain access and carry out further actions. The `pods.log` file showed a new, unauthorized pod had been created with the name **`evil`**.
5. **Persistence:** To ensure long-term access, the attacker established a persistence mechanism. An analysis of the `cron.txt` file revealed a suspicious entry that executed a script located at **`/opt/backdoor.sh`** on a recurring schedule.
## Questions:
1. **How many replicas are configured for the flask-app deployment?**
Doing a simple recursive grep on the directory of contents, we can find that there are `3` replicas for the Flask app.

![image one](./Images/Pasted%20image%2020250912220836.png)

2. **What is the NodePort through which the flask-app is exposed?**
Searching the file `default/describes/services.log` we can see the node port is listed as `30000/TCP`.

![image two](./Images/Pasted%20image%2020250912221227.png)

3. **What time (UTC) did the attacker first initiate fuzzing on the /system/ endpoint?**
Since we are looking for fuzzing, we need to look at the flask-app.logs, specifically for the first instance of a 404 coming from a repeated IP address. We can find that this started at `2024-11-08 22:02:48`.

![image three](./Images/Pasted%20image%2020250912222348.png)

4. **Which endpoint did the attacker discover through fuzzing and subsequently exploit?**
We can see at the end of that same log file that `/system/execute` returns a 200 response from the same IP address as the previous question.

![image four](./Images/Pasted%20image%2020250912222455.png)

5. **Which program did the attacker attempt to install to access their HTTP pages?**
Towards the end of the same log from the previous two questions, we can see an error trying to find a common binary. The binary was `curl`, which is later downloaded.

![image five](./Images/Pasted%20image%2020250912222843.png)

6. **What is the IP address of the attacker?**
Reviewing the host-process logs shows a running process connecting to a foreign IP address at `10.129.231.112`.

![image six](./Images/Pasted%20image%2020250912223142.png)

7. **What is the name of the pod that was compromised and used by the attacker as the initial foothold?**
We can do a recursive grep for the newly found IP address. From the results we get, the only other hit is in binary data located in the `flask-app-77fbdcfcff-2tqgw` process dump logs. 

![image seven](./Images/Pasted%20image%2020250912223554.png)

8. **What is the name of the malicious pod created by the attacker?**
Reviewing the containers detailed in the pods.log, we can see one has an interesting name. The answer is `evil`.

![image eight](./Images/Pasted%20image%2020250912223826.png)

9. **What is the absolute path of the backdoor file left behind by the attacker?**
While reviewing the items provided, you will eventually find that the cron.txt file contains an improper entry. The answer is `/opt/backdoor.sh`.

![image nine](./Images/Pasted%20image%2020250912223924.png)