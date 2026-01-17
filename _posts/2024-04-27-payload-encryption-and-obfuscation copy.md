---
title: Threat Hunting Basics
author: nirajkharel
date: 2026-01-17 14:10:00 +0800
categories: [Red Teaming, Threat Hunting]
tags: [Red Teaming, Threat Hunting]
render_with_liquid: false
---


# Threat Hunting Basics

**Dwell time** refers to the period an attacker remains undetected in your environment, using that window to gather credentials, exfiltrate sensitive data, or move laterally.


## The Limitations of Traditional Security Tools

AV and EDR solutions operate based on pre-defined detection rules such as signatures, file hashes, or behavioral indicators. While effective against known threats, these systems struggle with:

- Zero-day malware  
- Advanced persistent threats (APT)  
- Insider abuse or misconfigurations  

Security tools are reactive by design. If a malicious action doesn’t match existing detection rules, it often goes unnoticed. This is why **threat hunting** is essential—it fills the gaps left by automated defenses.

---

## The Value of Threat Hunting

Beyond detecting ongoing intrusions, threat hunting uncovers critical issues that may otherwise go unnoticed:

- Unpatched vulnerabilities on key endpoints or servers  
- Misconfigured devices that could be exploited  
- Unauthorized software installations  
- Privilege escalation or access issues  

The intelligence gathered from hunts strengthens your overall security program by improving detection rules, enhancing logging infrastructure, and informing proactive risk mitigation strategies.


## When to Hunt

Threat hunts can be triggered by a variety of scenarios:

- Routine, scheduled hunts in organizations with dedicated teams  
- New intelligence about emerging threats or active exploits targeting your industry  
- SOC/IR alerts indicating anomalies or ongoing incidents  
- Observations from previous hunts, such as newly discovered IOCs  
- Post-risk assessment validation to secure critical systems


## Threat Hunting Lifecycle

A typical hunt follows three main phases:

1. **Trigger**: Define the reason for hunting, usually in the form of a hypothesis.  
2. **Investigation**: Search across your telemetry to confirm or adjust the hypothesis.  
3. **Resolution**: Conclude the hunt, document findings, and communicate results. Insights often lead to new hunts or improved detection logic.

---

## Types of Threat Hunts

### Structured Hunts
Focus on specific adversary TTPs derived from frameworks like **MITRE ATT&CK**. These hunts are symptom-driven rather than indicator-driven, seeking evidence of behaviors rather than specific files or IPs.

### Unstructured Hunts
Start with known IOCs from intelligence reports, previous incidents, or security alerts. Logs and network traffic are analyzed to determine if malicious activity occurred.

### Situational Hunts
Target specific high-risk assets or systems, often based on a risk assessment. This approach leverages baselines to identify deviations that may indicate compromise.


## The Pyramid of Pain

Understanding the **Pyramid of Pain** helps prioritize what to hunt:

| Indicator Type | Hunting Impact |
|----------------|----------------|
| Hash Values     | Easy to detect, easy for attackers to change |
| IP Addresses    | Moderate difficulty; attackers can rotate quickly |
| Domain Names    | Harder to change; requires registration and hosting |
| Network/Host Artifacts | Requires attacker effort to alter; valuable detection points |
| Tools           | Disrupts adversary operations; forces creation of new tools |
| TTPs            | Highest value; detecting behaviors impacts attacker operations directly |



## Cyber Kill Chain

Detecting threats often aligns with the **Cyber Kill Chain**, which maps the stages of an attack from reconnaissance to final objectives.  

![Cyber Kill Chain Diagram](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/photo/cyber/THE-CYBER-KILL-CHAIN-body.png.pc-adaptive.1280.medium.png)

| Phase | Threat Hunting Relevance |
|-------|-------------------------|
| Reconnaissance | Passive/active information gathering; often invisible in logs |
| Weaponization | Payload creation; typically undetectable until delivery |
| Delivery | First observable point (email, drive-by, USB) |
| Exploitation | Execution of malicious payload; multi-stage escalation |
| Installation | Tools and backdoors installed; persistence established |
| Command & Control | Communication with attacker infrastructure; monitoring needed |
| Actions on Objectives | Data exfiltration, encryption, destruction; ultimate impact |

---

## MITRE ATT&CK Framework

**MITRE ATT&CK** is a structured knowledge base of adversary behaviors, enabling hunters to map techniques to tactics across enterprise environments. TTP-based hunting allows for reusable detection strategies and proactive threat identification.

<img alt="" class="bf jp jq dj" loading="lazy" role="presentation" src="https://raw.githubusercontent.com/nirajkharel/nirajkharel.github.io/master/assets/img/images/mitre.png">

---

## Threat Hunting Methodologies

### Intelligence-Driven Hunting
Use threat intelligence to formulate hypotheses:  
- Which actors are targeting your industry?  
- What TTPs are they known to use?  
- Map intel to ATT&CK techniques for structured hunts.

### Data-Driven Hunting
Leverage internal telemetry and logs to detect anomalies without initial indicators. This approach can surface hidden threats through pattern analysis.

### Knowledge-Based Hunting
Hunters apply deep understanding of systems, network architecture, and adversary behaviors. Hypotheses are crafted based on observed TTPs and potential attack surfaces.

---

## Data Collection & Log Management

Effective hunting relies on comprehensive data collection:

- **Endpoint Logs:** Sysmon, PowerShell, application events, authentication logs  
- **Network Logs:** Netflow, proxy, firewall, DNS traffic  
- **Cloud & Applications:** CloudTrail, SaaS logs, remote access portals  

Retention policies, normalization, and enrichment of logs are critical. Use tools like **Splunk**, **ELK Stack**, and **Velociraptor** to aggregate and analyze telemetry.


## IOC Correlation

**Correlating IOCs** transforms isolated signals into actionable intelligence:

- **Exact Matching:** IPs, hashes, domains  
- **Infrastructure Pivoting:** Identify shared infrastructure across multiple indicators  
- **Fuzzy Matching:** Detect typosquatting or near-identical malware variants  
- **Time-Based Correlation:** Reconstruct events to reveal attack progression  
- **TTP/Campaign Linking:** Map activity to known adversaries and MITRE techniques  


## Endpoint Threat Hunting

Hunting at the endpoint involves tracking file-based, process-based, registry, and service anomalies:

- **File IOCs:** Filenames, hashes, paths  
- **Registry & Services:** Creation/modification of system services, startup entries  
- **Processes:** Suspicious parent-child relationships, unusual execution paths  
- **Scheduled Tasks:** Malicious task creation or modification  
- **PowerShell Activity:** Module logging, scriptblock logging, encoded commands


## Network-Based Threat Hunting

Focuses on capturing anomalies in traffic patterns:

- **Protocol Misuse:** HTTP over unusual ports, DNS tunneling  
- **Volume & Frequency:** Unusual transfers, beaconing behavior  
- **Unexpected Transfers:** Lateral movement or data exfiltration  
- **Network Capture Tools:** Wireshark, tcpdump, NetWitness Investigator, NetworkMiner

## Sysmon Event IDs for Threat Hunting

Sysmon provides critical endpoint telemetry. Below are essential event IDs for hunting:

| Event ID | Description |
|----------|-------------|
| 1        | Process creation – track command-line execution and parent process |
| 2        | File creation time changed – detect timestomping attempts |
| 3        | Network connection – monitor outbound connections for C2 activity |
| 5        | Process terminated – identify suspicious process lifecycles |
| 6        | Driver loaded – detect malicious driver insertion |
| 7        | Image loaded – track DLLs and suspicious code execution |
| 8        | CreateRemoteThread – potential process injection activity |
| 10       | Process access – detect privilege escalation or tampering |
| 11       | File created – monitor unusual file creation activity |
| 12       | Registry value change – track persistence modifications |
| 13       | Registry value deleted – detect deletion of critical keys |
| 14       | Registry value renamed – identify tampering for evasion |
| 15       | File stream created – detect hidden or alternate data streams |
| 22       | DNS query – monitor for suspicious external lookups |

---

## Conclusion

Threat hunting requires a **strategic, intelligence-driven mindset**, deep technical expertise, and robust telemetry infrastructure. By combining endpoint and network hunting, leveraging MITRE ATT&CK, and correlating IOCs across multiple sources, hunters can proactively detect, disrupt, and respond to sophisticated adversaries before they achieve their objectives.  


