# Brute-Force Authentication Detection and Containment on Azure Virtual Machines

## Overview
This project documents a Security Operations Center (SOC) investigation into external brute-force authentication attempts targeting Azure virtual machines. Using Microsoft Defender for Endpoint and Microsoft Sentinel, the activity was detected, analyzed, validated, and contained. No successful compromise was observed, and preventive controls were implemented to reduce future risk.

---

## Objectives
- Detect brute-force authentication attempts against Azure virtual machines
- Validate whether any attempts resulted in successful access
- Contain affected assets and reduce attack surface
- Map observed behavior to the MITRE ATT&CK framework
- Document findings in a SOC-appropriate investigation report

---

## Environment
- **Cloud Platform:** Microsoft Azure
- **Security Tooling:** Microsoft Defender for Endpoint, Microsoft Sentinel
- **Data Sources:** Authentication logs, endpoint telemetry
- **Query Language:** KQL

---

## Detection & Analysis
Multiple Azure virtual machines were identified as potential targets of external brute-force login attempts originating from public IP addresses. The primary source IP observed was **146.190.25.114**, associated with the host **linux-target-1**, with additional activity originating from **20.57.2.159**.

Authentication telemetry was analyzed to determine whether any login attempts resulted in successful authentication. Review of logon events confirmed that all observed attempts failed, with no evidence of credential compromise or unauthorized access.

### Verification Query
```kql
DeviceLogonEvents
| where ActionType != "LogonFailed"
| where RemoteIP in ("146.190.25.114", "20.57.2.159")
```
**Result:**  
No successful authentications were identified from the suspected source IPs.

---

## Containment & Mitigation

- Isolated affected virtual machines using Microsoft Defender for Endpoint  
- Executed full antimalware scans; no malicious artifacts were detected  
- Hardened Azure Network Security Groups (NSGs) to block public RDP access  
- Restricted management access to trusted IP ranges  
- Recommended Azure Bastion as the standard secure administrative access method  

---

## MITRE ATT&CK Mapping

- **T1110 – Brute Force (Credential Access):**  
  Repeated external authentication attempts against exposed VM login services  

- **T1078 – Valid Accounts (Credential Access) [Attempted]:**  
  Attempts did not result in successful authentication  

- **T1021.001 – Remote Services: RDP (Lateral Movement):**  
  Public RDP exposure represented an attack surface prior to NSG hardening  

---

## Final Status

**Incident contained.**  
No evidence of account compromise, persistence, or lateral movement was observed. Preventive controls were implemented to reduce exposure to future brute-force activity.

---

## Key Takeaways

- Publicly exposed management services significantly increase brute-force risk  
- Proactive monitoring and rapid containment prevent escalation  
- IP-restricted access and secure management services materially improve cloud security posture  

---

## Skills Demonstrated

- SOC alert triage and investigation  
- Brute-force attack detection  
- Endpoint and authentication telemetry analysis  
- KQL querying (Defender & Sentinel)  
- Incident containment and response  
- Azure network security hardening  
- MITRE ATT&CK mapping and reporting  

---

## Author

**Abdul-Mumin Abdur-Rahman**  
SOC Analyst | Threat Hunting | Incident Response
