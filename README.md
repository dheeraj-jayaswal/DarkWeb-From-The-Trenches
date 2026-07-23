# 🌐 Dark Web From The Trenches

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Role:** Technology Lead – Offensive Security | Infosys Limited, Pune
>
> **Context:** Dark web intelligence is a standard component of enterprise security assessments. Before testing an application, I check whether the organisation's credentials have already been leaked on dark web forums. After a breach, I check where the data surfaced. This repository documents the threat intelligence and OSINT methodology I apply in professional enterprise engagements — how to find leaked credentials, monitor for brand exposure, and use dark web intelligence to strengthen real-world security posture.

---

## 🧠 What Is "Dark Web" in the Enterprise Security Context?

```
The internet has three layers:

Surface Web:
  Indexed by Google, Bing, etc.
  Publicly accessible without special tools
  ~5% of all internet content

Deep Web:
  Not indexed — requires authentication to access
  Corporate intranets, email systems, databases
  Online banking portals, medical records
  ~90% of all internet content

Dark Web:
  Requires Tor browser or I2P to access
  .onion domains — not resolvable via standard DNS
  Intentionally anonymous overlay network
  ~5% of all internet content

Enterprise security relevance of the dark web:
  → Stolen credential marketplaces (breached username/password pairs)
  → Data leak forums (corporate documents, database dumps)
  → Ransomware group blogs (victim lists, stolen data proof)
  → Malware-as-a-Service and exploit kits
  → Threat actor communication channels
  → Dark web OSINT for proactive threat intelligence
```

---

## 🎯 Why Enterprise Security Professionals Monitor the Dark Web

```
Scenario 1 — Credential Stuffing Attack Prevention:
  A dark web marketplace lists 50,000 credentials from a breach
  that includes 200 email addresses from company.com.
  Attackers buy the list → credential stuff against the corporate portal.
  Proactive monitoring finds this BEFORE the attack happens.
  → Password reset campaign for affected users preempts the breach.

Scenario 2 — Post-Breach Investigation:
  A ransomware group claims to have exfiltrated 10GB from Company X.
  Their dark web blog posts sample files to prove the claim.
  Threat intelligence identifies what data was taken, scope of exposure.
  → Informs breach notification obligations, regulatory response.

Scenario 3 — Pre-Engagement Intelligence:
  Before a pentest, I check if the target organisation's credentials
  are already available on dark web forums or paste sites.
  → Immediately focuses testing on systems where leaked passwords apply.
  → "Your IT admin's password was in a breach from 2022" is a Critical finding.

Scenario 4 — Brand Protection / Executive Monitoring:
  C-suite personal email addresses, home addresses, or identity documents
  appearing on dark web forums = executive impersonation risk.
  → Informs physical security and targeted phishing awareness.
```

---

## 📚 Series Contents

| Topic | File |
|---|---|
| Credential Leak Monitoring | [Credential_Leak_Monitoring.md](Credential_Leak_Monitoring.md) |
| Dark Web OSINT Methodology | [Dark_Web_OSINT_Methodology.md](Dark_Web_OSINT_Methodology.md) |
| Ransomware Intelligence | [Ransomware_Intelligence.md](Ransomware_Intelligence.md) |
| Threat Actor Profiling | [Threat_Actor_Profiling.md](Threat_Actor_Profiling.md) |
| Brand Protection (Enterprise) | [Brand_Protection_Enterprise.md](Brand_Protection_Enterprise.md) |
| Dark Web Tools Reference | [Dark_Web_Tools_Reference.md](Dark_Web_Tools_Reference.md) |
| MITRE ATT&CK Field Usage | [MITRE_ATT_CK_Field_Usage.md](MITRE_ATT_CK_Field_Usage.md) |
| OSINT to Threat Intel Pipeline | [OSINT_To_ThreatIntel_Pipeline.md](OSINT_To_ThreatIntel_Pipeline.md) |
| Pre-Engagement TI Report (Template) | [Pre_Engagement_TI_Report.md](Pre_Engagement_TI_Report.md) |
| TI Fundamentals (Enterprise) | [TI_Fundamentals_Enterprise.md](TI_Fundamentals_Enterprise.md) |

---

## 🛠️ Tools & Platforms Used

### Open Source / Free

| Tool | Purpose | Usage |
|---|---|---|
| **Tor Browser** | Anonymous access to .onion sites | Safe browsing during research |
| **Ahmia** | Surface-web indexed dark web search | Initial keyword searches |
| **OnionSearch** | CLI dark web search aggregator | Automated search across multiple engines |
| **theHarvester** | OSINT email/domain harvesting | Pre-dark web recon |
| **SpiderFoot** | Automated OSINT including dark web | Bulk organisation intelligence |
| **Maltego** | Visual threat intelligence mapping | Connecting threat actor relationships |
| **truffleHog** | Leaked secrets in git repositories | Credential exposure detection |
| **gitleaks** | Git repository secret scanning | Source code credential audit |
| **HIBP API** | Have I Been Pwned breach data | Automated credential exposure check |
| **Shodan** | Internet device intelligence | Infrastructure exposure mapping |

### Commercial (Enterprise)

| Platform | Purpose |
|---|---|
| **Recorded Future** | Automated dark web intelligence, threat actor tracking |
| **Digital Shadows (ReliaQuest)** | Brand monitoring, leaked data detection |
| **Flashpoint** | Criminal forum intelligence, credential monitoring |
| **Mandiant Advantage** | Threat intelligence, APT tracking |
| **DarkOwl** | Dark web content indexing and search |

---

## 🔍 Methodology — Enterprise Dark Web Investigation

### Phase 1 — Surface Web Pre-Recon (Always First)

```
# Before touching Tor — exhaust surface web sources

# HIBP — have credentials been exposed?
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/target@company.com" \
  -H "hibp-api-key: YOUR_API_KEY" | jq .

# Check domain-level exposure:
curl -s "https://haveibeenpwned.com/api/v3/breaches" | \
  jq '.[] | select(.Domain == "company.com") | {Name, Title, BreachDate, PwnCount}'

# Pastebin/paste site monitoring (surface web):
# Google: site:pastebin.com "company.com" "password"
# Google: site:pastebin.com "@company.com" email
# Google: site:paste.ee OR site:ghostbin.com "@company.com"

# GitHub credential leak check:
# github.com/search → "company.com" "password" in code
# github.com/search → "company.com" filename:.env

# Google dorking for leaked documents:
# site:company.com filetype:pdf "confidential"
# "company.com" filetype:xlsx "internal"
# "@company.com" "password" site:pastebin.com
```

### Phase 2 — Safe Dark Web Access Setup

```
Legal and safety requirements BEFORE accessing dark web:
  ✓ Written client authorisation for dark web investigation
  ✓ Dedicated investigation VM (not work or personal machine)
  ✓ VPN → Tor layering for additional anonymity
  ✓ Tor Browser only — never open documents inside Tor that
    could call home (PDFs, Word docs, media files)
  ✓ No login to any personal accounts inside Tor session
  ✓ Screenshot evidence only — no downloading files
  ✓ Documented methodology for legal defensibility

VM setup for investigation:
  Dedicated Kali or Whonix VM
  Snapshot before and after each session
  No shared clipboard with host machine
  No network bridges to internal corporate network
```

### Phase 3 — Dark Web Search Techniques

```
# Ahmia.fi — surface-accessible dark web search engine
# https://ahmia.fi/search/?q=company.com+credentials

# OnionSearch — CLI tool for multiple dark web search engines
pip install onionsearch --break-system-packages

onionsearch "company.com credentials" --output company_results.txt
onionsearch "company.com database dump" --output dump_results.txt
onionsearch "@company.com email password" --output cred_results.txt

# Targeted search operators:
# "company.com" site:.onion
# "company.com" "database" "download"
# "company.com" "breach" "2024"
# "company.com" "admin" "password"

# SpiderFoot automated OSINT (includes dark web sources):
# spiderfoot -s company.com -m sfp_ahmia,sfp_tor,sfp_pastes -o spiderfoot_results.json
```

### Phase 4 — Evidence Collection Standards

```
When dark web intelligence is found — documentation requirements:

1. Screenshot the source page (with Tor circuit path hidden)
2. Note the exact search query that surfaced the result
3. Record the date and time of discovery
4. Note the .onion URL (for reference — not for the report)
5. Extract only the minimum data needed to prove the exposure:
   → Number of records
   → Data types exposed (email, password hash, PII)
   → Date of apparent breach
   → Sample (masked) to confirm data is real and current
6. Do NOT download, store, or reproduce full datasets
7. Document what was NOT found (negative findings)

Report format:
  "During pre-engagement threat intelligence, the client's domain
  (company.com) was found in [X] breach databases accessible via
  dark web sources. Approximately [N] employee credentials were
  identified in a dataset dated [approximate date], including
  email addresses matching the company.com domain paired with
  password hashes. Affected accounts should be identified and
  forced to reset passwords immediately."
```

---

## 🚨 Ransomware Group Tracking

```
Major ransomware groups operate "leak blogs" on Tor where they:
  → List victim organisations
  → Post sample stolen files to prove access
  → Publish full datasets if ransom is not paid

Monitoring these blogs is standard threat intelligence practice.
Finding a client listed there during pre-engagement research
= immediate Critical notification regardless of scope.

Key tracking resources (surface web):
  → ransomwatch.telemetry.ltd — aggregates ransomware group posts
  → id-ransomware.malwarehunterteam.com — ransomware identification
  → CISA Known Ransomware Groups advisories
  → @vxunderground on Twitter/X — threat actor tracking

Intelligence value for enterprise clients:
  "Your organisation is listed on [group]'s blog as a claimed victim.
  Sample files posted include [data type]. This was discovered during
  pre-engagement OSINT and is reported immediately outside the main
  pentest scope as it requires urgent response."
```

---

## 🔐 Using Leaked Credentials in Authorised Assessments

```
When leaked credentials are found during pre-engagement OSINT,
they become a valid test vector — with specific professional controls:

Authorisation required:
  ✓ Explicit written permission in scope document to test leaked credentials
  ✓ Client informed of specific credentials being tested
  ✓ Test conducted only against agreed scope systems

Safe testing methodology:
  1. Report the credential exposure finding immediately
  2. Obtain specific written authorisation for credential testing
  3. Test ONLY against the agreed target systems
  4. Stop immediately on first successful authentication
  5. Document: which credential, which system, what access level
  6. Do not use the access beyond confirming it works (screenshot)

Report finding:
  "Employee credentials found in dark web breach database were valid
  against the corporate email portal. The password 'Company@2022'
  was used by 3 employees whose accounts were found in the breach.
  All three accounts successfully authenticated to Outlook Web Access.
  This demonstrates that the affected users had not changed their
  passwords following the 2022 breach disclosure."
```

---

## 📋 Pre-Engagement TI Report Template

```
## Threat Intelligence Report — Pre-Engagement OSINT
**Target:** Company Name  
**Date:** [DD-MM-YYYY]  
**Investigator:** Dheeraj Kumar Jayaswal

### Credential Exposure Summary

| Source | Records Found | Data Types | Approximate Date |
|--------|--------------|------------|-----------------|
| HIBP   | 247 accounts | Email + password hash | 2022 breach |
| Paste sites | 12 entries | Email + plaintext passwords | 2023 |
| Dark web forum | ~50 accounts | Email + bcrypt hashes | Q1 2024 |

**Total exposed accounts:** ~309 unique company.com email addresses

### Sample (Redacted for Report)
Email format: [name]@company.com  
Password type: bcrypt hash / plaintext (indicates reuse from older breach)  
Source confirmation: 3 of 5 sampled email addresses verified as current
employees via LinkedIn

### Risk Assessment
**Severity: High**  
Active employee credentials are available for purchase or freely accessible.
Credential stuffing attacks against corporate email, VPN, and SSO portals
are immediately feasible without any technical exploitation.

### Recommended Actions (Before Pentest Begins)
1. Immediate: Force password reset for all 309 identified accounts
2. Immediate: Enable MFA on all corporate portals (email, VPN, SSO)
3. Short-term: Deploy credential monitoring service for ongoing alerting
4. Short-term: Dark web monitoring integration for automated breach detection
```

---

## ⚖️ Legal and Ethical Framework

```
Dark web investigation is legitimate professional activity.
These principles govern how I conduct every investigation:

ALWAYS:
  ✓ Written client authorisation before investigating their exposure
  ✓ Dedicated isolated investigation environment
  ✓ Purpose limited to intelligence gathering — no purchasing of data
  ✓ Minimum necessary data extraction for evidence purposes
  ✓ Documentation of methodology for legal defensibility
  ✓ Immediate notification if critical exposure found mid-engagement
  ✓ Compliance with local law on data handling (GDPR, IT Act)

NEVER:
  ✗ Purchase leaked data from criminal markets
  ✗ Download or store full breach databases
  ✗ Use dark web intelligence against non-agreed targets
  ✗ Interact with threat actors or provide cover for their activities
  ✗ Access dark web without explicit authorisation and documented purpose
  ✗ Share or republish leaked personal data
  ✗ Use dark web access for any purpose beyond the engagement scope

The professional standard:
  Observe and document → Report to client → Delete local copies
  The goal is to help the client understand their exposure
  and take protective action — not to possess their leaked data.
```

---

## 🧭 Key Takeaways for Enterprise Security Teams

**1. Pre-engagement dark web OSINT is the highest-ROI threat intelligence activity.** An hour checking HIBP, paste sites, and dark web forums before testing starts tells you which employees already have compromised credentials. A finding like "247 employee credentials are available for free online" changes the client's risk posture before a single vulnerability is exploited.

**2. Breach data on the dark web often predates detection by months or years.** Organisations frequently discover breaches from dark web intelligence long before their own systems generate alerts. A 2022 breach database appearing on forums in 2024 is not unusual. Continuous monitoring is essential — point-in-time checks are insufficient.

**3. The credential:access chain is the most impactful finding chain in enterprise testing.** Leaked credentials → valid authentication → confirmed access → escalate privileges → full compromise. No injection vulnerability required. The hardest part (credential theft) was done for you by a previous breach. Demonstrating this chain with evidence is the most compelling executive-level finding in any assessment.

**4. Documentation and legal compliance are non-negotiable.** Dark web investigation generates sensitive evidence. Document every step, retain only what is needed for reporting, delete the rest. Written authorisation protects both you and the client. Methodology documentation protects you legally. This is professional discipline, not optional.

---

## 🔗 References

- [Have I Been Pwned](https://haveibeenpwned.com)
- [CISA Ransomware Resources](https://www.cisa.gov/ransomware)
- [Ahmia Dark Web Search](https://ahmia.fi)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Tor Project](https://www.torproject.org)
- [OnionSearch GitHub](https://github.com/megadose/OnionSearch)
- [SpiderFoot OSINT](https://www.spiderfoot.net)
- [RansomWatch](https://ransomwatch.telemetry.ltd)

---

## 📄 License

This content is licensed under **[CC BY 4.0](LICENSE.md)**. You're welcome to
reuse or adapt any of these notes — just give clear attribution to
**Dheeraj Kumar Jayaswal** with a link back to this repository. See
[LICENSE.md](LICENSE.md) for the full terms.

---

<div align="center">

*Dark Web From The Trenches — Real threat intelligence field notes from enterprise security engagements.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)
[![AppSec Repo](https://img.shields.io/badge/Also%20See-AppSec%20From%20The%20Trenches-9B59B6?style=flat-square)](https://github.com/dheeraj-jayaswal/AppSec-From-The-Trenches)

</div>
