# Threat Intelligence Fundamentals — Enterprise Security Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Threat Intelligence — Foundations & Enterprise Application
>
> **Context:** Threat intelligence is the practice of collecting, analysing, and applying information about threats to make better security decisions. In enterprise engagements, I integrate threat intelligence into every phase — from pre-engagement OSINT that surfaces leaked credentials before testing begins, to post-engagement reporting that contextualises findings within the threat landscape relevant to the client's sector.

---

## 🧠 What Threat Intelligence Actually Is (and Is Not)

```
Threat intelligence IS:
  → Processed, analysed information about adversaries, TTPs, and indicators
  → Actionable context that improves security decision-making
  → Evidence-based understanding of who might attack you and how
  → Input to risk prioritisation, detection, and response planning

Threat intelligence is NOT:
  → Raw data (IP feeds, domain lists, hash lists without context)
  → News articles about cyber incidents
  → Vendor marketing fear-mongering
  → Certainty (it is probabilistic and time-sensitive)

The intelligence cycle:
  Planning → Collection → Processing → Analysis → Dissemination → Feedback
```

---

## 📊 The Intelligence Pyramid — Types by Utility

```
Strategic Intelligence (C-suite, Board):
  → Who is likely to target us and why?
  → What industries are being targeted by which threat groups?
  → What is our risk profile relative to peers?
  → Timeframe: weeks to months
  → Consumers: CISO, Risk Committee, Board
  → Sources: Industry reports, government advisories, sector ISACs

Operational Intelligence (Security Teams):
  → What campaigns are active right now?
  → What TTPs (Tactics, Techniques, Procedures) are being used?
  → What vulnerabilities are being actively exploited in the wild?
  → Timeframe: days to weeks
  → Consumers: SOC managers, incident responders, pentest teams
  → Sources: Threat actor tracking, CTI platforms, CERT advisories

Tactical Intelligence (Analysts, Detection):
  → What specific malware families are being deployed?
  → What are the exact command-and-control patterns?
  → What network indicators can we detect?
  → Timeframe: hours to days
  → Consumers: SOC analysts, detection engineers, SIEM teams
  → Sources: Malware analysis, threat feeds, honeypots

Technical Intelligence (Tools & Detection):
  → Indicators of Compromise (IOCs): IPs, domains, hashes, URLs
  → YARA rules, Sigma rules, Snort signatures
  → Direct input to detection tooling
  → Timeframe: minutes to hours
  → Consumers: Firewalls, SIEMs, EDR platforms
  → Sources: Threat intelligence platforms, open source feeds
```

---

## 🏢 How I Apply TI in Enterprise Penetration Testing

### Pre-Engagement Phase (Most Impactful)

```
Before touching the first endpoint:

1. Credential exposure assessment
   → HIBP domain check: are employee credentials in breach databases?
   → Paste site monitoring: are credentials being shared in the wild?
   → Dark web forum search: is the organisation mentioned as a target?
   
   Enterprise value: A finding like "247 company.com credentials are
   freely available in breach databases" changes the entire risk
   conversation before testing even starts.

2. Attack surface intelligence
   → Certificate transparency: what internet assets exist?
   → Shodan: what services are exposed and what versions?
   → GitHub: are internal tools, configs, or credentials in public repos?
   
   Enterprise value: Finds assets the client didn't know were public.
   Often the most unexpected and valuable findings.

3. Threat actor relevance
   → What threat groups target this industry/geography?
   → Has this organisation been mentioned in threat actor chatter?
   → Are there active campaigns using techniques we should test specifically?
   
   Enterprise value: Tailors the engagement to the realistic threat.
   A retail client faces different adversaries than a defence contractor.
```

### During Engagement

```
Context enrichment for findings:
  → Is this CVE being actively exploited in the wild?
    (Changes CVSS 7.5 into a higher-priority immediate fix)
  → Has this vulnerability been used by groups targeting this sector?
    (Adds urgency that plain CVSS scores lack)
  → Is this leaked credential in a currently active credential stuffing campaign?
    (Changes "credential exposure" from theoretical to active risk)
```

### Post-Engagement Reporting

```
Executive summary enrichment:
  → "The vulnerability identified in Finding #3 (Apache Struts RCE)
     was exploited by FIN7 in 17 documented incidents targeting
     financial institutions in 2024."
  → This framing connects technical findings to business risk
     in language executives and boards understand
```

---

## 📋 Intelligence Sources — Free vs Commercial

### Free / Open Source

| Source | Type | Best For |
|---|---|---|
| **MITRE ATT&CK** | TTP framework | Mapping findings to adversary behaviour |
| **CISA Advisories** | Gov advisories | Known exploited vulnerabilities (KEV catalog) |
| **AlienVault OTX** | IOC feeds | Community threat indicators |
| **Abuse.ch** | IOC feeds | Malware, C2, ransomware indicators |
| **CIRCL MISP** | Threat sharing | IOC sharing platform |
| **Shodan** | Asset intel | Internet-facing asset discovery |
| **crt.sh** | Passive DNS | Certificate transparency |
| **VirusTotal** | File/URL intel | Malware analysis and reputation |
| **MalwareBazaar** | Malware samples | Malware family intelligence |
| **RansomWatch** | Ransomware TI | Victim tracking, ransom group monitoring |
| **HIBP API** | Credential intel | Breach exposure by domain |
| **URLhaus** | URL feeds | Malicious URL indicators |

### Commercial / Enterprise

| Platform | Specialty |
|---|---|
| **Recorded Future** | Comprehensive, dark web, predictive analytics |
| **Digital Shadows (ReliaQuest)** | Brand monitoring, exposed data, attack surface |
| **Mandiant Advantage** | APT tracking, threat actor profiles |
| **CrowdStrike Falcon X** | Adversary intelligence, attribution |
| **Flashpoint** | Criminal forums, dark web chatter |
| **DarkOwl** | Dark web content indexing |
| **Secureworks CTU** | Threat intelligence unit reports |

---

## 🎯 Threat Intelligence in Pentest Reports — Practical Examples

### Example 1 — CVE With Active Exploitation Context

```
Without TI context:
  Finding: Apache Log4j CVE-2021-44228 — Remote Code Execution
  Severity: Critical (CVSS 10.0)
  Remediation: Upgrade to Log4j 2.17.1 or later

With TI context:
  Finding: Apache Log4j CVE-2021-44228 — Remote Code Execution
  Severity: Critical (CVSS 10.0)
  Active Exploitation Status: This vulnerability has been weaponised
  by 60+ documented threat actors including APT41, Lazarus Group,
  and multiple ransomware affiliates. CISA added it to the Known
  Exploited Vulnerabilities catalog on December 10, 2021.
  Exploitation has been observed in attacks against financial
  services organisations in India and Southeast Asia specifically.
  Remediation: IMMEDIATE — upgrade Log4j to 2.17.1 within 24 hours

The TI context converts "Critical finding to fix in next sprint"
into "Critical finding requiring emergency change control tonight."
```

### Example 2 — Credential Finding With Active Campaign Context

```
Without TI context:
  Finding: 247 company.com credentials found in breach databases
  Severity: High
  Recommendation: Force password reset for affected accounts

With TI context:
  Finding: 247 company.com credentials found in breach databases
  Threat Intelligence Context: The breach dataset containing these
  credentials (Collection #3, 2023) is actively being used in
  targeted credential stuffing campaigns against Indian financial
  services portals, per Recorded Future intelligence from Q1 2025.
  Two company.com accounts were validated as still active against
  the OWA portal during this engagement.
  Severity: Critical (active, confirmed exploitation path)
  Recommendation: IMMEDIATE password reset + MFA enforcement for
  all 247 accounts. Block associated IPs from known stuffing infrastructure.
```

---

## 🗂️ Building a Personal TI Workflow

```
Daily intelligence ritual (15-20 minutes):

1. CISA KEV catalog update check (rss.cisa.gov/known-exploited-vulnerabilities.xml)
   → Any new actively exploited CVEs in tech stacks I commonly test?

2. CERT-In advisories for India (cert-in.org.in)
   → Regional threat context for Indian enterprise clients

3. RansomWatch (ransomwatch.telemetry.ltd)
   → Any clients from recent or current engagements appeared?
   → Which industries are current ransomware targets?

4. Twitter/X lists: @vxunderground, @BushidoToken, @malwrhunterteam
   → Real-time threat actor activity and new malware

Pre-engagement ritual (per engagement):

1. HIBP domain query → credential exposure count
2. Shodan org search → internet-facing asset inventory
3. crt.sh → subdomain enumeration
4. GitHub search → credential/config leaks
5. RansomWatch → client name search
6. Google dorks → public data exposure
```

---

## 🧭 Key Takeaways

**1. Pre-engagement TI is the highest-ROI security activity per hour invested.**
An hour of TI before testing starts tells you which employees have compromised credentials, which systems are internet-facing, and whether the organisation is on any threat actor's radar. This context shapes the entire engagement.

**2. TI context transforms technical findings into business risk.**
A CVSS 9.8 vulnerability is a number. The same vulnerability with "actively exploited by Lazarus Group in financial sector attacks this quarter" is an immediate executive action item. Always enrich Critical and High findings with active exploitation context.

**3. MITRE ATT&CK is the common language between red teams and blue teams.**
Mapping findings to ATT&CK technique IDs (T1190, T1078, T1055) connects pentest findings to detection capability gaps in a language SOC teams and detection engineers understand. This makes pentest reports genuinely actionable for the defensive side.

---

## 🔗 References
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [FIRST CVSS 3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [SANS Threat Intelligence Curriculum](https://www.sans.org/cyber-security-courses/?focus-area=threat-intelligence)

---
<div align="center">

*Part of [Dark Web From The Trenches](../README.md) — Threat intelligence field notes from 6+ years of enterprise security.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
