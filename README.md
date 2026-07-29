# Azure Threat Hunt — Internet-Facing Brute Force

---

## Summary

A routine infrastructure review found that a virtual machine running internal services (DNS, DHCP, domain services) had been misconfigured with a public IP address. This hunt answers the only question that matters in that situation: **did anyone get in?**

Automated scanners found the host within hours and generated sustained failed authentication attempts from external addresses. Three checks — increasing in scope, each able to catch what the previous one could miss — confirmed **zero successful unauthorized logons**. The finding is a near miss, not a breach — but the exposure itself is the real vulnerability.

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
  2-measure-failed-logon-volume.kql
  3-cross-reference-attacker-ips.kql
  4-correlate-failures-to-successes.kql
  5-all-external-successful-logons.kql
LICENSE
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

**Result:** exposure confirmed, with the public IP and the first and last timestamps at which the host was reachable. That window bounds every query that follows — each one below opens by pinning `ExposureStart` and `ExposureEnd` to the values this query returns.

### 2. Measure the attack volume

Aggregate failed logons by source address to separate a genuine campaign from background noise. Note the two-part output: the totals establish the scale of the campaign, the ranked list identifies which addresses to cross-reference in step 3.

```kql
let VMName = "windows-target-";
let ExposureStart = datetime(YYYY-MM-DD HH:MM:SS);  // from query 1
let ExposureEnd   = datetime(YYYY-MM-DD HH:MM:SS);  // from query 1
let FailedExternal =
    DeviceLogonEvents
    | where Timestamp between (ExposureStart .. ExposureEnd)
    | where DeviceName startswith VMName
    | where LogonType in~ ("Network", "Interactive", "RemoteInteractive", "Unlock")
    | where ActionType == "LogonFailed"
    | where isnotempty(RemoteIP) and not(ipv4_is_private(RemoteIP));
// Scale of the campaign
FailedExternal
| summarize TotalAttempts = count(), DistinctSources = dcount(RemoteIP)
```

```kql
// Ranked sources — feeds the IP list used in step 3
FailedExternal
| summarize Attempts = count() by RemoteIP, DeviceName, LogonType
| top 20 by Attempts
```

**Result:** thousands of failed attempts spread across a large number of distinct external addresses, with a long tail of low-volume sources — consistent with commodity botnet scanning rather than a single targeted operator. The distinct count comes from `dcount` in the first query; the `top 20` in the second is a display limit for the cross-reference list and is not the number of sources observed.

### 3. Disprove compromise — direct cross-reference

Take the highest-volume attacking addresses and check them against successful logons:

```kql
// Source IPs redacted using RFC 5737 documentation ranges.
// Populate from the output of query 2 in your own tenant.
let ThreatActorIPs = dynamic([
    "203.0.113.10", "198.51.100.42", "192.0.2.77"
    // ... remaining observed sources
]);
let VMName = "windows-target-";
DeviceLogonEvents
| where DeviceName startswith VMName
| where ActionType == "LogonSuccess"
| where RemoteIP in~ (ThreatActorIPs)
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol
```

**Result: 0 records.**

> **Operator note — why `in~` and not `has_any`.** `has` and `has_any` are token operators: KQL splits the field on delimiters (including dots) and matches whole tokens only. An IPv4 address is not a single token, so `RemoteIP has_any(ThreatActorIPs)` returns nothing regardless of what is in the data — a zero result that looks identical to a clean environment. On a query whose entire purpose is to prove a negative, that failure mode is silent and total. `in~` performs case-insensitive exact matching against the list and is the correct operator here.

> **Note on IP handling:** observed source addresses are redacted here and replaced with RFC 5737 documentation-range addresses. Brute-force traffic frequently originates from shared cloud ranges, compromised third-party hosts, and NAT gateways — publishing a raw list as "attacker infrastructure" attributes malice to owners who may be victims themselves. Reproduce the list from your own telemetry.

### 4. Disprove compromise — remove the dependency on a hand-copied list

Query 3 is only as complete as the IP list transcribed out of step 2 — anything below the top 20, or mistyped, is invisible to it. Query 4 asks the same question directly against the telemetry, joining the full failure set to the full success set:

```kql
let VMName = "windows-target-";
let ExposureStart = datetime(YYYY-MM-DD HH:MM:SS);  // from query 1
let ExposureEnd   = datetime(YYYY-MM-DD HH:MM:SS);  // from query 1
let FailedLogons =
    DeviceLogonEvents
    | where Timestamp between (ExposureStart .. ExposureEnd)
    | where DeviceName startswith VMName
    | where LogonType in~ ("Network", "Interactive", "RemoteInteractive", "Unlock")
    | where ActionType == "LogonFailed"
    | where isnotempty(RemoteIP)
    | summarize FailedAttempts = count() by RemoteIP, DeviceName;
let SuccessfulLogons =
    DeviceLogonEvents
    | where Timestamp between (ExposureStart .. ExposureEnd)
    | where DeviceName startswith VMName
    | where LogonType in~ ("Network", "Interactive", "RemoteInteractive", "Unlock")
    | where ActionType == "LogonSuccess"
    | where isnotempty(RemoteIP)
    | summarize SuccessfulLogons = count() by RemoteIP, DeviceName, AccountName;
FailedLogons
| join kind=inner SuccessfulLogons on RemoteIP, DeviceName
| project RemoteIP, DeviceName, AccountName, FailedAttempts, SuccessfulLogons
| order by FailedAttempts desc
```

**Result: 0 records.**

This removes the transcription dependency, but it does not remove the *logical* one. Queries 3 and 4 both require the successful logon to originate from an address that also produced failures. An attacker who sprays from a botnet and then authenticates from a clean residential or VPN address satisfies neither. Both queries would return zero, and the host would still be compromised.

### 5. Disprove compromise — drop the correlation entirely

The only check that closes that gap makes no assumption about where the successful logon came from. Every external successful authentication during the exposure window, correlated to nothing:

```kql
let VMName = "windows-target-";
let ExposureStart = datetime(YYYY-MM-DD HH:MM:SS);  // from query 1
let ExposureEnd   = datetime(YYYY-MM-DD HH:MM:SS);  // from query 1
DeviceLogonEvents
| where Timestamp between (ExposureStart .. ExposureEnd)
| where DeviceName startswith VMName
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP) and not(ipv4_is_private(RemoteIP))
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType, Protocol
| order by Timestamp asc
```

**Result: 0 records.**

This is the query that actually closes the incident. Queries 3 and 4 narrow a haystack; query 5 checks whether the needle exists at all. It is also the noisiest of the three — on a host with legitimate external administration it would return real results requiring individual triage, which is why it comes last rather than first.

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
No attempt succeeded, but the telemetry does not establish why. `DeviceLogonEvents` records the failure, not the reason for it — attempts against non-existent accounts, wrong passwords against valid accounts, and a scanner abandoning the host all look the same here. Absent a lockout threshold, nothing limited the number of guesses, and a weak or reused credential would have changed the outcome. Apply a lockout threshold and duration via GPO across all assets, not just internet-facing ones.

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

Two things.

The instinct on an exposed host is to hunt for the successful logon. The more useful discipline is proving a negative deliberately — and being precise about what each query can and cannot see. Queries 3 and 4 look like independent confirmation, and reporting them that way would have been comfortable. They aren't: both assume the successful logon shares an address with the failures. Recognizing that they share a blind spot is what made query 5 necessary, and query 5 is what actually closed the incident.

The second thing is narrower and mechanical. A zero result is only evidence if the query was capable of returning a non-zero one. `has_any` against an IP list returns nothing whether or not the attacker got in, because KQL tokenizes on dots and an address is never a whole token. On a hunt built entirely around zero results, an operator choice that silently guarantees zero is not a syntax detail — it is the difference between a finding and a false negative.
