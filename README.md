# Azure Threat Hunt — Internet-Facing Brute Force

**Suggested repo description:** `Threat hunt against a publicly exposed Azure VM using MDE and KQL — detecting brute-force campaigns and proving zero compromise through correlation analysis.`

**Suggested topics:** `threat-hunting` `kql` `microsoft-defender-for-endpoint` `azure` `blue-team` `soc` `mitre-attack` `brute-force`

---

## Summary

A routine infrastructure review found that a virtual machine running internal services (DNS, DHCP, domain services) had been misconfigured with a public IP address. This hunt answers the only question that matters in that situation: **did anyone get in?**

Automated scanners found the host within hours and generated thousands of failed authentication attempts from external addresses. Two independent correlation methods confirmed **zero successful unauthorized logons** during the exposure window. Password complexity held. The finding is a near miss, not a breach — but the exposure itself is the real vulnerability.

| | |
|---|---|
| **Platform** | Microsoft Defender for Endpoint (Advanced Hunting) |
| **Query language** | Kusto (KQL) |
| **Target** | Azure VM, `windows-target-*` |
| **Outcome** | No compromise. Exposure remediated, detection rule proposed. |

---

## Repository structure

```
queries/
  1-confirm-internet-facing-telemetry.kql
  2-isolate-top-failed-brute-force.kql
  3-cross-reference-attacker-ips.kql
  4-correlate-failures-to-successes.kql
README.md
```

---

## Hunt methodology

The hunt moves from **confirming the exposure** to **measuring the attack** to **disproving compromise** — in that order. Reversing it risks chasing successful logons before you know the host was even reachable.

### 1. Confirm the exposure is real

Before hunting an attack, verify the attack surface exists. MDE tracks internet reachability directly in `DeviceInfo`:

```kql
let VMName = "windows-target-";
DeviceInfo
| where DeviceName startswith VMName
| where IsInternetFacing == true
| project Timestamp, DeviceName, PublicIP, OSPlatform, AdditionalFields
| order by Timestamp desc
```

**Result:** exposure confirmed, with the public IP and the full window during which the host was reachable.

### 2. Measure the attack volume

Aggregate failed logons by source address to separate a genuine campaign from background noise:

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

**Result:** sustained failures from ~20 distinct external addresses across multiple ASNs and geographies — the signature of commodity botnet scanning rather than a targeted operator.

### 3. Disprove compromise — direct cross-reference

Take the attacking addresses and check them against successful logons:

```kql
// Source IPs redacted. Populate from the output of query 2 in your own tenant.
let ThreatActorIPs = dynamic([
    "203.0.113.10", "198.51.100.42", "192.0.2.77"
    // ... remaining observed sources
]);
let VMName = "windows-target-";
DeviceLogonEvents
| where DeviceName startswith VMName
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(ThreatActorIPs)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol
```

**Result: 0 records.**

> **Note on IP handling:** observed source addresses are redacted here. Brute-force traffic frequently originates from shared cloud ranges, compromised third-party hosts, and NAT gateways — publishing a raw list as "attacker infrastructure" attributes malice to owners who may be victims themselves. Reproduce the list from your own telemetry.

### 4. Disprove compromise — independent correlation

Query 3 only catches attackers whose successful logon came from the *same* address as their failures. A join across the full failure and success sets catches slower or distributed attempts that a static list would miss:

```kql
let VMName = "windows-target-";
let FailedLogons = DeviceLogonEvents
    | where DeviceName startswith VMName
    | where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
    | where ActionType == "LogonFailed"
    | where isnotempty(RemoteIP)
    | summarize FailedAttempts = count() by RemoteIP, DeviceName;
let SuccessfulLogons = DeviceLogonEvents
    | where DeviceName startswith VMName
    | where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
    | where ActionType == "LogonSuccess"
    | where isnotempty(RemoteIP)
    | summarize SuccessfulLogons = count() by RemoteIP, DeviceName, AccountName;
FailedLogons
| join kind=inner SuccessfulLogons on RemoteIP, DeviceName
| project RemoteIP, DeviceName, AccountName, FailedAttempts, SuccessfulLogons
| order by FailedAttempts desc
```

**Result: 0 records.** Two methods, same conclusion.

---

## MITRE ATT&CK mapping

| Tactic | Technique | Observed |
|---|---|---|
| Reconnaissance (TA0043) | Active Scanning: Scanning IP Blocks (T1595.001) | Yes — automated discovery of the exposed host |
| Credential Access (TA0006) | Brute Force: Password Guessing (T1110.001) | Yes — sustained, high volume |
| Initial Access (TA0001) | External Remote Services (T1133) | Attempted, unsuccessful |
| Lateral Movement (TA0008) | — | None observed |

---

## Findings and remediation

**Finding 1 — Infrastructure host directly exposed to the internet.** *(Critical)*
Domain and DNS services should never be publicly reachable. Remove the public IP and gate administrative access behind Azure Bastion or Just-In-Time VM access. Enforce this at the subscription level with an Azure Policy denying public IPs on the infrastructure subnet, so it can't recur through manual error.

**Finding 2 — No account lockout policy on the exposed host.** *(High)*
Complexity requirements alone stopped this campaign, which is luck rather than control. A weak or reused credential would have changed the outcome. Apply a lockout threshold and duration via GPO across all assets, not just internet-facing ones.

**Finding 3 — No alerting on unexpected internet exposure.** *(High)*
The misconfiguration was found manually during maintenance, after the fact. A scheduled detection on `DeviceInfo` for `IsInternetFacing == true` outside an approved allowlist would surface the next occurrence in minutes rather than days:

```kql
let ApprovedPublicHosts = dynamic(["web-frontend-01", "vpn-gw-01"]);
DeviceInfo
| where IsInternetFacing == true
| where DeviceName !in~ (ApprovedPublicHosts)
| summarize FirstSeen = min(Timestamp), PublicIP = any(PublicIP) by DeviceName
```

---

## What I took from this

The instinct on an exposed host is to hunt for the successful logon. The more useful discipline is proving a negative with more than one method — a single query returning zero results is an absence of evidence, not evidence of absence. Building the join in query 4 was what actually let me close the incident with confidence, because it doesn't depend on my having captured the right source IPs in step 2.
