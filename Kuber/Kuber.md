# HTB Sherlock - Kuber

![htb logo](./Images/htb_logo.png)

| Date          | Author          | Difficulty | Challenge Type |
| ------------- | --------------- | ---------- | -------------- |
| 2025-09-11 | Andrew McKenzie | Easy       | DFIR           |

---
## Description
This challenge involves a forensic investigation into a potentially compromised Kubernetes cluster. By analyzing a dump of YAML manifest files from the `kube-system` namespace, the objective is to identify security misconfigurations, discover hardcoded secrets, and find evidence of a malicious pod deployed by an attacker.
## Scenario
As a digital forensics investigator, you received an urgent request from a client managing multiple proxy Kubernetes clusters. The client reports unusual behavior in one of their development environments, where they were testing a proxy via SSH. This environment was exposed to the internet, raising concerns about a potential security breach. You have been provided with a dump of the `kube-system` namespace, as most of the testing activity occurred there. Your task is to thoroughly analyze the data and determine if the system has been compromised.
## Artifacts Provided
- Kuber.zip
	- kube-system
		- 00-namespace.yaml
		- configmaps.yaml
		- daemonset.yaml
		- deployment.yaml
		- job.yaml
		- pods.yaml
		- secrets.yaml
		- serviceaccount.yaml
		- service.yaml

| Filename            | Algorithm | Hash                                                             |
| ------------------- | --------- | ---------------------------------------------------------------- |
| 00-namespace.yaml   | SHA256    | f35f62e28b21e461e34b8d2d04faad4f7d63e698a055a4e4d3ad9a1ff0aa1eff |
| 00-namespace.yaml   | SHA1      | 3d2ae46735485ef849ea59e78480454ac01f8590                         |
| 00-namespace.yaml   | MD5       | a7d6e1ef3051e8cba78fb4c587379673                                 |
| configmaps.yaml     | SHA256    | 30b1338132d4ea9d2179246893abcacd7e7afc4747d202fe0718aff0eaff29d9 |
| configmaps.yaml     | SHA1      | 284f203ed36628402bdfe6a5cd7f1ae0c88b4fe4                         |
| configmaps.yaml     | MD5       | c805a8743ef2ad7d0137d15f23191dce                                 |
| daemonset.yaml      | SHA256    | 14e97f81c844bf2feb68e4c1d5d3c4335923a2486e2da9c6eb9e9a2885b13718 |
| daemonset.yaml      | SHA1      | 2eeafe2826347ed0c79d02da00cc891cf5e7391a                         |
| daemonset.yaml      | MD5       | 1a07a9f74d324b8937c98c546fe70e36                                 |
| deployment.yaml     | SHA256    | 8c6808ddc6c249275a6a3c09aa227c66bc809272943d1843110a96a6f2951fbb |
| deployment.yaml     | SHA1      | 035e7aa0a679cba2d8ff96d6eb3c62d0cc6fe7d2                         |
| deployment.yaml     | MD5       | 77b3a3aeb996ebc93b3637bcd28e2df6                                 |
| job.yaml            | SHA256    | 4af4bdc6808d0b6df47e0d7877f78ec69590ccb13244b88801fd29d9d3a7d6cb |
| job.yaml            | SHA1      | 67360512f6fc2666591681a2ec94d05d40153b8b                         |
| job.yaml            | MD5       | 8e3b40fb2cddde2dacdcab61113343d1                                 |
| pods.yaml           | SHA256    | 40b2f192b693016a61d8669f62f577688450bc7501721baf0253ca98267fd8d2 |
| pods.yaml           | SHA1      | 8f49b9b3a12aada100448c98eb685e995d1f473c                         |
| pods.yaml           | MD5       | b2a4d9aa4df22e674cd0940b747c77dc                                 |
| secrets.yaml        | SHA256    | fc5c07446c34c12e09c39bcec442f31fbde28c3f05b70a84c9996b9e4509fad8 |
| secrets.yaml        | SHA1      | 6b92a6e5a90309d5dff86750fc998f08583cca2a                         |
| secrets.yaml        | MD5       | 10c44ccc646df9176b4694dbe5050f59                                 |
| serviceaccount.yaml | SHA256    | bd9fea0f22a0e0399a788c34ccd0d0e05f43aa47af2001e4d7d454f5e7b4587f |
| serviceaccount.yaml | SHA1      | 175ba6bee7738db6ee52538d306bb2646d6c5b94                         |
| serviceaccount.yaml | MD5       | 0b265db19aa871a288c15bf6774b4fe9                                 |
| service.yaml        | SHA256    | 833d5199f3bfe5d8362b20eafde70f9fbd869fd6894b7b7559b11f8c9bb823b1 |
| service.yaml        | SHA1      | c8cde689ed9f45c8c199ac6c88f095fa3b5d0da4                         |
| service.yaml        | MD5       | cbcb54e6782d3219805b1d913f752805                                 |

## Skills Learned
- **Kubernetes Forensics:** Analyzing Kubernetes YAML manifest files to understand cluster configuration and identify security issues.
- **Configuration Review:** Inspecting `Service`, `ConfigMap`, and `Secret` objects to find exposed ports, hardcoded data, and credentials.
- **Command-Line Analysis:** Using `grep` to efficiently search across multiple configuration files for key artifacts.
- **Base64 Decoding:** Recognizing and decoding Base64-encoded values commonly used in Kubernetes Secrets.
- **Anomaly Detection:** Identifying malicious resources, like a rogue pod, by spotting deviations from expected configurations.
## Initial Analysis
The investigation involved a systematic review of the provided Kubernetes YAML files to identify misconfigurations and signs of a compromise.
1. **External Exposure:** The `service.yaml` file was analyzed first to determine the external attack surface. The `ssh-deployment` service was found to be exposed on **NodePort `31337`**, providing a direct entry point from the internet. The service's internal **ClusterIP was `10.43.191.212`**.
2. **Information Disclosure:** The `configmaps.yaml` and `secrets.yaml` files were then inspected for sensitive data. A flag, **`HTB{1d2d2b861c5f8631f841b57f327f46f8}`**, was discovered in the `ssh-config` ConfigMap. A Base64-encoded password was also found in a Secret; after decoding, it was revealed to be **`SuperCrazyPassword123!`**.
3. **Compromise Confirmation:** The `pods.yaml` file was examined for anomalous pods. Two pods named `metrics-server` were present, which is highly suspicious. One, named **`metrics-server-557ff575fx-4q62x`**, stood out. Its configuration showed it was running a generic **`alpine`** image instead of a legitimate metrics server image.
4. **Attacker Presence:** The status of this malicious pod confirmed the attacker's presence inside the cluster, listing its internal IP address as **`10.10.14.11`**.
The evidence clearly indicates that the cluster was compromised. The attacker likely gained access via the exposed SSH service using the hardcoded password and then deployed a pod to establish a foothold.
## Questions:
1. **At which NodePort is the `ssh-deployment` Kubernetes service exposed for external access?**
We can grep over the files looking for `ssh-deployment` and we find the NodePort is `31337`.

![image one](./Images/Pasted%20image%2020250911170851.png)

2. **What is the ClusterIP of the kubernetes cluster?**
We can find this answer by targeting the file from the previous question and utilizing before/after lines in grep to reveal the ClusterIP, which is `10.43.191.212`.

![image two](./Images/Pasted%20image%2020250911171403.png)

3. **What is the flag value inside ssh-config configmap?**
We can target the configmap file directly or continue to use the same recursive grep command, but this time filtering for “ssh-config.” The answer is `HTB{1d2d2b861c5f8631f841b57f327f46f8}`.

![image three](./Images/Pasted%20image%2020250911171521.png)

4. **What is the value of password (in plaintext) which is found inside ssh-deployment via secret?**
We can find the password by doing a recursive search and expanding lines for substance. The user password is base64 encoded, but when decoded is `SuperCrazyPassword123!`.

![image four](./Images/Pasted%20image%2020250911171847.png)

5. **What is the name of the malicious pod?**
There are several pods that are deployed during a Kubernetes deployment that are normal, as well as the pods we provision, like in this case the SSH deployment. However, inspecting the metadata names shows there are two metrics servers. One ending with `4q62w` and one ending with `4q62x`.

![image five](./Images/Pasted%20image%2020250911172708.png)

You will notice that when I performed this grep, I actually got answers to coming questions, as it's easy to see the malicious pod whose name is `metrics-server-557ff575fx-4q62x`

6. **What is the image attacker is using to create malicious pod?**
As mentioned, the previous question's screenshot shows the answers to these two questions. The image being used in the malicious pod is `alpine`.

7. **Whats the attacker IP?**
As mentioned, question five's screenshot shows the answers for these questions. The IP address of the attack is shown as `10.10.14.11`.