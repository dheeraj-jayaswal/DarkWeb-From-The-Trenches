# MITRE ATT&CK in Enterprise Security — Field Usage Guide

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Threat Intelligence — ATT&CK Framework Application
>
> **Context:** MITRE ATT&CK is the most widely adopted framework for describing adversary behaviour. In professional penetration testing, it gives findings a standardised language that security teams, SOC analysts, and executives can all reference. When I map a finding to ATT&CK technique T1190 (Exploit Public-Facing Application), the client's detection team can immediately look up whether they have detection coverage for that technique — converting pentest findings into detection engineering tasks.

---

## 📖 Understanding the ATT&CK Structure

```
MITRE ATT&CK Hierarchy:

Tactic (the WHY — adversary goal):
  14 tactics covering the full attack lifecycle
  Examples: Initial Access, Execution, Persistence, Privilege Escalation,
            Defense Evasion, Credential Access, Discovery, Lateral Movement,
            Collection, Command and Control, Exfiltration, Impact

Technique (the HOW — general method):
  Identified as T#### (e.g., T1190)
  Describes a broad attack category
  Example: T1190 — Exploit Public-Facing Application

Sub-technique (the SPECIFIC HOW):
  Identified as T####.### (e.g., T1059.001)
  More specific implementation of the technique
  Example: T1059.001 — Command and Scripting Interpreter: PowerShell

Procedure (the CONCRETE INSTANCE):
  Specific threat actor implementation
  Example: APT28 using PowerShell Empire for initial access

ATT&CK Matrix views:
  Enterprise (most relevant for web/API testing): attack.mitre.org/matrices/enterprise/
  Mobile: attack.mitre.org/matrices/mobile/
  ICS: attack.mitre.org/matrices/ics/
```

---

## 🎯 ATT&CK Techniques Most Relevant to Web & API Penetration Testing

### Initial Access (TA0001)

| Technique | ID | Description | When I Use It |
|---|---|---|---|
| Exploit Public-Facing Application | T1190 | Exploit weakness in internet-facing app | Web app SQLi, RCE, authentication bypass |
| Valid Accounts | T1078 | Use legitimate credentials | Credential stuffing, password spray success |
| Phishing | T1566 | Social engineering for access | Phishing simulation, credential harvesting |

### Credential Access (TA0006)

| Technique | ID | Description | When I Use It |
|---|---|---|---|
| Brute Force | T1110 | Repeated login attempts | No rate limiting finding |
| Credentials from Password Stores | T1555 | Extract stored credentials | Password hash extraction via SQLi |
| Unsecured Credentials | T1552 | Find credentials in plaintext | Hardcoded credentials, .env files, git repos |
| Credentials in Files | T1552.001 | Credentials in config files | web.config, appsettings.json exposure |

### Privilege Escalation (TA0004)

| Technique | ID | Description | When I Use It |
|---|---|---|---|
| Exploitation for Privilege Escalation | T1068 | Exploit for elevated access | Mass assignment → admin role |
| Access Token Manipulation | T1134 | Manipulate tokens | JWT algorithm confusion |

### Defense Evasion (TA0005)

| Technique | ID | Description | When I Use It |
|---|---|---|---|
| Exploitation for Defense Evasion | T1211 | Exploit weaknesses in defenses | WAF bypass techniques |

### Collection (TA0009)

| Technique | ID | Description | When I Use It |
|---|---|---|---|
| Data from Information Repositories | T1213 | Access repos/databases | BOLA to access bulk data |
| Screen Capture | T1113 | Capture screenshots | During authorised exploitation PoC |

### Exfiltration (TA0010)

| Technique | ID | Description | When I Use It |
|---|---|---|---|
| Exfiltration Over Web Service | T1567 | Exfil via HTTP/API | SSRF → data exfiltration demonstration |
| Automated Exfiltration | T1020 | Automated data collection | API enumeration scripts |

---

## 📋 Mapping Pentest Findings to ATT&CK — Practical Examples

### Example 1 — SQL Injection

```
Finding: SQL injection in /api/v1/reports?ref_id= parameter
CVSS: 9.8 (Critical)

ATT&CK Mapping:
  Primary Technique:    T1190 — Exploit Public-Facing Application
  Secondary Technique:  T1213 — Data from Information Repositories
  Credential Impact:    T1552.001 — Credentials in Files (if DB creds exposed)

Detection Gap (from mapping):
  T1190: Does the SOC have detection rules for SQL error responses?
  T1213: Is database query logging enabled and monitored?
  T1552.001: Is DLP monitoring for credential pattern exfiltration?

Report addition:
  "This finding maps to MITRE ATT&CK T1190 (Exploit Public-Facing Application)
   and T1213 (Data from Information Repositories). Review detection coverage
   for these techniques in your SIEM/EDR platform."
```

### Example 2 — Credential Exposure

```
Finding: 247 employee credentials found in dark web breach databases
CVSS: High

ATT&CK Mapping:
  Primary Technique:  T1078.004 — Valid Accounts: Cloud Accounts
  Secondary:          T1110.004 — Brute Force: Credential Stuffing
  If validated:       T1078 — Valid Accounts (confirmed access)

Adversary groups using this technique against similar organisations:
  → FIN7: extensively uses credential stuffing against financial services
  → Scattered Spider: credential phishing and stuffing against tech companies
  → Multiple ransomware affiliates: initial access via stolen credentials

Report addition:
  "Credential exposure maps to T1078 (Valid Accounts) and T1110.004
   (Credential Stuffing). Threat actors including FIN7 regularly exploit
   exposed credential databases for initial access to financial sector targets."
```

### Example 3 — SSRF → AWS Metadata

```
Finding: SSRF in webhook endpoint allowing access to cloud metadata service
CVSS: 9.8 (Critical)

ATT&CK Mapping:
  Primary:    T1190  — Exploit Public-Facing Application (initial SSRF)
  Secondary:  T1552.005 — Cloud Instance Metadata API
  Impact:     T1098  — Account Manipulation (using stolen IAM credentials)

Cloud-specific ATT&CK coverage:
  The ATT&CK framework includes cloud-specific sub-techniques:
  T1552.005: Unsecured Credentials: Cloud Instance Metadata API
  → Specifically covers SSRF → IMDSv1 credential theft

Report addition:
  "This finding maps to T1552.005 (Cloud Instance Metadata API),
   a technique documented in attacks by multiple nation-state and
   financially motivated threat actors targeting cloud-hosted infrastructure."
```

---

## 🔧 Using ATT&CK Navigator for Engagement Reporting

```
ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/):

1. Open Navigator → create a new layer
2. Name the layer: "ClientName Pentest Findings — [Date]"
3. Colour-code findings by status:
   Red:    Vulnerable — finding confirmed during engagement
   Yellow: Tested — not vulnerable to this technique
   Green:  Detected — would have been detected by existing controls
   Blue:   Mitigated — control in place prevents exploitation

4. Add comment on each highlighted technique:
   "Finding #3: SQL injection in /api/v1/reports
    CVSS 9.8 — Full database access demonstrated"

5. Export as SVG or JSON for report inclusion

Value for the client:
  → Visual representation of attack surface coverage
  → Immediate identification of detection/protection gaps
  → Comparison to known threat actor TTPs targeting their sector
  → Roadmap for security improvement (fill the red areas)
```

---

## 🏢 ATT&CK in Pre-Engagement TI

```
Before testing begins, use ATT&CK to frame the engagement context:

Step 1: Identify threat actors targeting the client's sector
  → ATT&CK Groups filtered by industry: attack.mitre.org/groups/
  → Example for financial sector: FIN7, Carbanak, Lazarus Group, APT38

Step 2: Extract their TTPs
  → Click each group → view all techniques they use
  → This is your threat-informed testing priority list

Step 3: Prioritise testing by adversary relevance
  → FIN7 heavily uses T1190 (web exploitation) → prioritise web testing
  → APT38 uses T1059.003 (Windows Command Shell) → if Windows systems in scope
  → Lazarus uses T1566 (phishing) → if social engineering in scope

Report framing:
  "This engagement was conducted against the threat model of financially
   motivated threat actors known to target Indian financial services
   organisations, including FIN7 (G0046) and Lazarus Group (G0032).
   Testing prioritised techniques documented in their ATT&CK profiles."
```

---

## 🧭 Key Takeaways

**1. ATT&CK mapping transforms pentest findings into detection engineering tasks.**
When you map Finding #3 to T1190, the client's SOC team can immediately open their SIEM and search for existing detection rules for T1190. If they have none, that is a detection gap. ATT&CK converts "you have a vulnerability" into "here is the specific detection you need."

**2. Use ATT&CK to prioritise what to test based on client's actual threat actors.**
A retail company and a defence contractor face completely different adversaries. ATT&CK Groups filtered by sector gives you the TTP profile of the adversaries most likely to target your client. Test those TTPs specifically — it makes the engagement threat-realistic rather than generic.

**3. ATT&CK Navigator visuals are board-level communication tools.**
A heat map showing which ATT&CK techniques are vulnerable vs detected vs mitigated gives executives an instant visual assessment of security posture. It is the clearest possible answer to "where are we exposed?" that can fit on one slide.

---

## 🔗 References
- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK Groups](https://attack.mitre.org/groups/)
- [CISA ATT&CK Mapping Guidance](https://www.cisa.gov/resources-tools/resources/best-practices-mitre-attck-mapping)

---
<div align="center">

*Part of [Dark Web From The Trenches](../README.md) — Real notes from 6+ years of enterprise security.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
