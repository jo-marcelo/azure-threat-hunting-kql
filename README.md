# azure-threat-hunting-kql

Threat Hunting Project: Devices Accidentally Exposed to the Internet
🎯 Project Objective
The primary objective of this project is to proactively hunt for security vulnerabilities and active exploits resulting from accidental internet exposure. Utilizing Microsoft Defender for Endpoint (MDE) and Kusto Query Language (KQL), this lab focuses on detecting misconfigured internet-facing Virtual Machines (VMs), isolating malicious external Indicators of Compromise (IoCs), investigating automated brute-force campaigns, and performing rigorous impact analysis to verify potential account takeovers.

🛠️ Technologies & Log Frameworks Used
SIEM / XDR Ecosystem: Microsoft Defender for Endpoint (MDE) Advanced Hunting Portal

Query Language: Kusto Query Language (KQL)

Log Schemas Utilized: * DeviceInfo (Asset configuration and network orientation telemetry)

DeviceLogonEvents (Authentication attempts, types, and success/failure statuses)

Target OS Environments: Hybrid Sandbox Network (Windows and Linux Target Instances)

🧪 Phase 1: Preparation & Hypothesis Generation
Standard infrastructure audits frequently flag perimeter exposure vulnerabilities before a formal incident occurs. For this hunting engagement, the infrastructure baseline was established under the following threat hypothesis:

💡 Threat Hypothesis: Persistent threat actors scanning public IP ranges will rapidly discover exposed administrative network services (such as RDP/SSH). They will subsequently launch automated, high-volume brute-force attacks attempting to compromise administrative credentials due to a lack of aggressive account lockout controls or network access control lists (ACLs).

🔍 Phase 2: Attack Surface Validation & Discovery
Step 1: Perimeter Asset Visibility Verification
This initial phase establishes baseline telemetry to confirm which endpoints are actively exposed to the public internet, verifying their public-facing IP configurations and device states.

Code snippet
// [PASTE HERE: 1-Confirm Internet-Facing Telemetry.kql]
📸 [INSERT SCREENSHOT HERE: Internet Exposure Telemetry Verification]

Step 2: Malicious Indicator Extraction (High-Volume Failures)
Once public internet exposure is verified, telemetry is parsed to isolate the external malicious network nodes actively attempting to exploit the asset via brute-force connection streams.

Code snippet
// [PASTE HERE: 2-Isolate Top Failed Brute-Force Attempts.kql]
📸 [INSERT SCREENSHOT HERE: Isolated Attacker IP Address Leaderboard]

🛡️ Phase 3: Analytical Pivot & Impact Analysis
Step 3: Targeted Authentication Cross-Referencing
To determine if the high-volume automated attacks achieved lateral or administrative access, the isolated top-offending malicious IPs are cross-referenced directly against successful authentication logs.

Code snippet
// [PASTE HERE: 3-Cross-Reference Attacker IPs for Successful Auth.kql]
📸 [INSERT SCREENSHOT HERE: Targeted Success Monitoring Output]

Step 4: Multi-Key Inner Join Correlation Engine
To detect advanced "low-and-slow" stealth attacks or precise brute-force conclusions, a correlation matrix matches failed logons followed immediately by a successful authentication on the exact same host asset within a tight temporal window.

Code snippet
// [PASTE HERE: 4-Identify Correlation Between Failures and Successes.kql]
📸 [INSERT SCREENSHOT HERE: Fail-To-Success Correlation Matrix Output]

📊 Summary of Findings & Tactical Conclusion
🛡️ Windows Target Infrastructure (True Negative)
The final host-scoped cross-correlation query returned zero records for the specific windows-target- asset. Perimeter defenses and host-level security configurations effectively deflected the brute-force streams during this observational window. Conclusion: No administrative accounts were compromised on the Windows endpoint.

⚠️ Ad-Hoc Network Telemetry Discovery (Linux Honeypot Account Takeover)
Prior to enforcing strict host-name query constraints, an un-scoped execution of the multi-key correlation query exposed critical unauthorized root administrative activity on parallel cloud components (linux-target-1).

Malicious IoCs: Multiple public malicious IPs (including 38.148.249.2 and 45.148.10.147) achieved successful root access paths immediately following their automated failure streams.

Impact: Confirmed compromise of parallel Linux assets requiring immediate containment and credential rotation.

🧠 Technical Takeaway
This lab demonstrates the high architectural value of building multi-key inner joins (on RemoteIP, DeviceName) within KQL. Correlating multi-stage telemetry allows analysts to immediately cut through massive amounts of background tenant noise and isolate true, successful endpoint compromises.
