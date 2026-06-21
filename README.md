## 📋 Executive Summary
* **Scenario:** During routine maintenance, a critical misconfiguration was discovered where internal VMs handling infrastructure services (DNS, DHCP, Domain Services) were accidentally exposed to the public internet.
* **Objective:** Actively hunt for network brute-force attempts, cross-reference telemetry to detect successful compromises, and design robust hardening remediation steps based on the threat activity.
* **Tools Used:** Microsoft Defender for Endpoint (MDE), Kusto Query Language (KQL), Azure Virtual Machines.

---

## 🗺️ Lab Architecture & Attack Lifecycle

1. **Exposure:** A virtual machine (windows-target-) is misconfigured with an active public IP address.
2. **Reconnaissance:** Automated internet bots scan the public space and locate the exposed asset.
3. **Initial Access Attempt:** High-velocity brute-force authentication streams hit the endpoint from external IP addresses.
4. **Compromise:** Brute-force tactics completely fail to secure a foothold due to robust password complexity or pre-existing credential hygiene, resulting in zero initial access.

---

## 🔍 Hunting Strategy & KQL Highlights
We utilized Advanced Hunting in Microsoft Defender for Endpoint to analyze the exposure and isolate malicious activity.

### 1. Identifying High-Volume Authentication Failures
- 1-Confirm Internet-Facing Telemetry.kql This initial step, verifies the baseline vulnerability by querying for endpoints exposing an active internet footprint:
```kql
let VMName = "windows-target-";
DeviceInfo 
| where DeviceName startswith VMName
| where IsInternetFacing == true
| project Timestamp, DeviceName, PublicIP, OSPlatform, AdditionalFields
| order by Timestamp desc
```
---

### 2. Detecting Correlated Brute-Force Successes
- **2-Isolate Top Failed Brute-Force Attempts.kql:** This query targets high-velocity authentication failures originating from external internet-facing bots:
```kql
let VMName = "windows-target-";
DeviceLogonEvents
| where DeviceName startswith VMName
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP) and RemoteIP != "127.0.0.1"
| summarize Attempts = count() by RemoteIP, DeviceName, LogonType
| order by Attempts desc
| take 20
```
---

### 3. Verification of Zero Initial Access
To fully validate whether the perimeter held, two additional analytical pivots were executed:
- **3-Cross-Reference Attacker IPs for Successful Auth.kql:** This query isolated the top threat actor IPs observed in step 2 and cross-referenced them against successful logons. Result: 0 records returned.
```kql
let ThreatActorIPs = dynamic([
    "120.49.65.104", "186.19.188.69", "148.72.152.145", "194.180.48.83", 
    "202.79.169.166", "35.199.91.184", "209.127.178.131", "211.168.177.21", 
    "182.191.113.35", "179.184.46.161", "159.195.39.90", "81.16.240.53", 
    "38.19.156.227", "185.62.57.60", "103.185.185.251", "203.163.247.74", 
    "216.250.250.204", "104.218.164.229", "38.255.37.45", "103.9.204.212"
]);
let VMName = "windows-target-";
DeviceLogonEvents
| where DeviceName startswith VMName
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(ThreatActorIPs)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol
```
---
- **4-Identify Correlation Between Failures and Successes.kql:** This query built a proactive inner join linking failed attempts and successful logons by RemoteIP and DeviceName to capture any stealthy or multi-stage brute-force successes. Result: 0 records returned.
```kql
let VMName = "windows-target-";
DeviceInfo 
| where DeviceName startswith VMName
| where IsInternetFacing == true
| project Timestamp, DeviceName, PublicIP, OSPlatform, AdditionalFields
| order by Timestamp desc
```
---

## 🛡️ MITRE ATT&CK Mapping & Findings
* **Tactics Attempted:** Initial Access (TA0001), Credential Access (TA0006).
* **Techniques Detected:** Brute Force: Password Guessing (T1110.001).
* **Key Observations:** Extensive automated scanning and thousands of authentication failures hit the exposed target. However, correlation analysis definitively confirms that no unauthorized initial access or lateral movement occurred during the exposure window.

## 🚀 Remediation & Defensive Hardening
To eliminate the attack surface and prevent future exposure risks, the following controls should be implemented:

* **Network Security:** Bind administrative endpoints tightly; eliminate direct public IP exposures for infrastructure servers, enforcing Azure Bastion or Just-In-Time (JIT) VM access instead.
* **Identity Security:** Formalize strict Account Lockout Policies to explicitly safeguard legacy or unconfigured assets from automated, sustained credential-stuffing campaigns.
* **Credential Hygiene:** Construct continuous alerting rules around the DeviceInfo table tracking IsInternetFacing == true anomalies to catch rogue public exposures before automated threat actors can scan them.
