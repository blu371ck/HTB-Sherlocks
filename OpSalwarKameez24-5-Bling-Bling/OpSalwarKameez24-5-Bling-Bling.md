# HTB Sherlock - OpSalwarKameez24-5: Bling Bling

![htb logo](./Images/htb_logo.png)

| Date       | Author          | Difficulty | Challenge Type |
| ---------- | --------------- | ---------- | -------------- |
| 2025-09-13 | Andrew McKenzie | Easy       | SOC            |

---
## Description
This challenge is a data-driven investigation focusing on fraud detection within a Neo4j graph database. By loading a database backup from a fictional e-commerce site, the task is to use the Cypher query language to analyze relationships between nodes (like Accounts, IPs, and Credit Cards). The goal is to uncover patterns of coordinated abuse, such as multiple accounts linked to a single IP address or credit card, to identify fraudulent activity.
## Scenario
It's the festive season of Diwali, and a newly launched website, Bling-Bling Crackers (a fictional site, inspired by platforms like Amazon and Flipkart), is offering huge discounts and free gifts for new users. To celebrate the festival of lights, Deepam Mart has launched a "Diwali Dhamaka" sale, offering ₹1 products, 50% off discounts, and free gifts like Diwali decorations and sweets for first-time users. The company Bling-Bling Crackers uses StoreD.
## Artifacts Provided
- BlingBling.zip
	- neo4j-2024-10-27T12-05-17.backup

| File Name                        | Algorithm | Hash                                                             |
| -------------------------------- | --------- | ---------------------------------------------------------------- |
| neo4j-2024-10-27T12-05-17.backup | SHA256    | e2b15fe40496be35e5536dbc9da0b7cb7ab928d5aa098598990ce1d4a49ecbf4 |
| neo4j-2024-10-27T12-05-17.backup | SHA1      | 28e3e68a0aa9b5e444e274849c952ffd53cb8baf                         |
| neo4j-2024-10-27T12-05-17.backup | MD5       | 4d9d40e257bf9daed9b5c599cbb8529b                                 |
## Skills Learned
- **Graph Database Analysis:** Using Neo4j to investigate and visualize relationships within a dataset.
- **Cypher Query Language:** Writing effective Cypher queries to count nodes, filter by properties, and identify entities with multiple relationships.
- **Fraud Detection:** Recognizing common indicators of e-commerce fraud, including multi-account creation from a single IP, and the reuse of physical addresses and credit card numbers.
- **Data Correlation:** Linking disparate data points (users, IPs, credit cards) to build a strong case for coordinated fraudulent activity.
## Initial Analysis
The investigation began by restoring the provided Neo4j database backup to analyze its contents for signs of fraud related to the "Diwali Dhamaka" sale. The Cypher query language was used to explore the relationships between different data entities.
1. **Dataset Overview:** Initial queries established the size of the database, revealing a total of **2,802 nodes**, with **1,406** of them being `Account` nodes.
2. **IP Address Correlation:** The first indicator of fraud was the reuse of IP addresses for account registration. A query found **38 users** who had created multiple accounts from shared IPs. Notably, the IP address `88.236.1.190` was used to create **22** separate accounts.
3. **Shared Personal Information:** Further queries revealed that other personal details were being reused. The physical address **`19/63, Krishnan Ganj, Danapur 441303`** and the credit card number **`371593995427734`** were both linked to multiple accounts.
4. **Connecting the Dots:** The final step was to link these indicators together. An analysis of the fraudulent credit card showed that **11** of the accounts associated with it also shared the same registration IP address.
This pattern of reusing IPs, addresses, and a single credit card across numerous accounts is a clear indicator of a coordinated fraud ring attempting to abuse the promotional offers of the new user sale.
## Questions:
1. **Total number of Nodes in the database?**
With the query: 
```sql 
MATCH (n) 
RETURN COUNT (n) as totalNodes 
``` 
We get that there are `2802` total nodes.

![image one](./Images/Pasted%20image%2020250913101754.png)

2. **How many Account nodes does the database have?**
With the query:
```sql
MATCH (n:Account)
RETURN COUNT (n)
```
We get that there are `1406` account nodes.

![image two](./Images/Pasted%20image%2020250913101901.png)

3. **How many accounts are registered from the IP address 88.236.1.190?**
With the query:
```sql
MATCH (n:Account)
WHERE n.register_ip_address = '88.236.1.190'
RETURN COUNT (n)
```
We get that there are `22` accounts.

4. **How many Users have created multiple accounts with same IP address?**
With the query:
```sql
MATCH (n:Account)
WITH n.register_ip_address AS ip_addr, COLLECT(n) AS nodes
WHERE SIZE(nodes) > 1
RETURN ip_addr, SIZE(nodes) AS duplicates
```
We get two rows of results, one containing `22` and one containing `16`. For a total of `38`.

![image three](./Images/Pasted%20image%2020250913102448.png)

5. **What physical address has been used multiple times?**
We can modify our previous query to request `n.address` and we get a result of `19/63, Krishnan Ganj, Danapur 441303`.

![image four](./Images/Pasted%20image%2020250913102643.png)

6. **Which Credit Card number is attached to multiple accounts?**
With the query:
```sql
MATCH (c:CreditCard)-[r:HAS_CREDITCARD]-()
WITH C, COUNT (r) AS count
WHERE count > 1
RETURN C, count
```
We see the card number used in multiple accounts is `371593995427734`.

![image five](./Images/Pasted%20image%2020250913103206.png)

7. **When was the account with username obhandari created?**
With the query:
```sql
MATCH (n:Account)
WHERE n.username = 'obhandari'
RETURN n.created_at
```
We find it was created on `2024-11-08 07:42:20.228775`.

![image six](./Images/Pasted%20image%2020250913103501.png)

8. **How many accounts using the credit card number from question 6 use the same registered IP address?**
We can reuse the same query from question 6; viewing the table data, we see that count is `11`.

![image seven](./Images/Pasted%20image%2020250913103925.png)