# Pre-Engagement Threat Intelligence Report — Template & Methodology

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Threat Intelligence — Professional Deliverable Templates

---

## 🎯 Why a Pre-Engagement TI Report Matters

```
A standard penetration test answers: "Can I exploit this vulnerability?"
A threat-informed penetration test answers: "Can real adversaries exploit
what they care about in this specific organisation?"

The pre-engagement TI report bridges these questions by establishing:
  1. What is the organisation's threat landscape?
  2. What data and systems do relevant adversaries care about?
  3. What initial access techniques do they use against similar targets?
  4. What is already exposed/compromised before testing starts?

This document:
  → Sets the risk context for all findings
  → Identifies the most business-relevant attack paths to test
  → Provides immediate value (credential exposure, brand abuse)
    before technical testing even begins
  → Differentiates professional from commodity penetration testing
```

---

## 📋 Pre-Engagement TI Report Template

```markdown
# Pre-Engagement Threat Intelligence Assessment

**Classification:** CONFIDENTIAL — [CLIENT NAME] Only
**Target Organisation:** [Company Name]
**Industry Sector:** [Financial Services / Healthcare / Retail / etc.]
**Assessment Date:** [DD-MM-YYYY]
**Assessor:** Dheeraj Kumar Jayaswal, Technology Lead – Offensive Security
**Engagement Reference:** [Engagement ID]

---

## Executive Summary

This threat intelligence assessment was conducted prior to the
penetration test engagement to establish the current threat landscape
for [Company Name] and identify existing exposures that require
immediate attention independent of the planned technical assessment.

**Critical Findings Requiring Immediate Action:**

| Priority | Finding | Recommended Action |
|---|---|---|
| CRITICAL | 247 employee credentials found in breach databases | Force password reset + MFA enforcement |
| HIGH | Potential typosquatting domain identified | Takedown request + employee alert |
| HIGH | DMARC policy missing — email spoofing possible | Implement DMARC enforcement |
| MEDIUM | 4 legacy subdomains accessible with different controls | Audit and harden |

---

## 1. Threat Landscape — Sector Overview

### 1.1 Threat Actor Relevance

Based on publicly available threat intelligence, the following adversaries
have documented history of targeting organisations in the [SECTOR] sector
in [REGION]:

**Tier 1 — Most Active and Relevant:**

[Threat Actor Name] (MITRE ATT&CK: G[XXXX])
- Motivation: [Financial / Espionage / Hacktivism]
- Known Targets: [Sector details]
- Primary Initial Access: [T1190, T1566.002, etc.]
- Recent Activity: [Summary of recent known campaigns]
- Relevance to [Client]: [Why this actor is specifically relevant]

**Tier 2 — Active in Sector:**
[Additional actors in table format]

### 1.2 Current Threat Climate

[Sector] organisations in [Region] have experienced [N] documented
significant incidents in [Year], primarily involving:
- [Attack type 1] (X% of incidents)
- [Attack type 2] (X% of incidents)

Source: [CERT-In, CISA, industry reports]

---

## 2. Credential Exposure Assessment

### 2.1 Summary

| Metric | Value |
|---|---|
| Total email addresses in breach databases | [N] |
| Accounts with exposed passwords | [N] |
| Distinct breach sources | [N] |
| Most recent breach source | [Breach name, Year] |
| Accounts requiring immediate reset | [N] |

### 2.2 Breach Sources

| Breach Name | Year | Exposed Accounts | Data Types |
|---|---|---|---|
| [Breach 1] | [Year] | [N] | Email, password hash |
| [Breach 2] | [Year] | [N] | Email, plaintext password |

### 2.3 Risk Assessment

**HIGH RISK accounts (immediate action required):**
- [N] accounts with plaintext passwords in breach data
- [N] accounts with easily crackable hashes (MD5/SHA-1)
- [N] accounts belonging to IT/admin personnel

**MEDIUM RISK accounts:**
- [N] accounts with bcrypt hashes (resistant but not immune)
- [N] accounts from breaches 3+ years old (may have changed)

### 2.4 Recommended Immediate Actions

1. Force password reset for all [N] identified accounts
2. Enable MFA on all affected accounts BEFORE password reset
3. Audit login history for all affected accounts for the past 90 days
4. Implement HIBP integration in password change flow to prevent
   reuse of known-breached passwords

---

## 3. External Attack Surface

### 3.1 Discovered Assets

| Asset | Status | Security Notes |
|---|---|---|
| app.company.com | Live — main application | In-scope for testing |
| staging.company.com | Live — staging environment | Less secure — prioritise |
| old-portal.company.com | Live — legacy application | Different security controls |
| dev.company.com | Live — dev environment | No WAF, direct access |

### 3.2 Exposed Services

From Shodan/Censys intelligence:
- [Service] on [Port]: [Notes on version, vulnerability exposure]
- [Service] on [Port]: [Notes]

---

## 4. Brand and Domain Exposure

### 4.1 Typosquatting Findings

[N] potentially malicious lookalike domains identified:

| Domain | Registered | SSL | Content | Risk |
|---|---|---|---|---|
| [domain1] | [Date] | Yes | Login page clone | CRITICAL |
| [domain2] | [Date] | No | Parked | LOW |

### 4.2 Email Authentication Status

| Control | Status | Finding |
|---|---|---|
| SPF | Present | v=spf1 ~all (weak — use -all) |
| DKIM | Present | Correctly configured |
| DMARC | Missing | Email spoofing trivially possible |
| BIMI | Not configured | Enhancement only |

---

## 5. Ransomware Intelligence

### 5.1 Ransomware Group Exposure Check

Target organisation name and domain searched across:
- RansomWatch aggregated victim database
- Publicly known ransomware group sites (via surface web aggregators)

**Result:** [Not found / Found — details]

### 5.2 Active Campaigns Targeting Sector

[Description of current ransomware campaigns targeting the sector]

---

## 6. GitHub / Source Code Exposure

| Repository | Exposure | Risk |
|---|---|---|
| [repo name] | [Finding] | [HIGH/MED/LOW] |

---

## 7. Testing Recommendations Based on TI

Based on threat actor TTP analysis, prioritise testing for:

1. **Web Application Exploitation (T1190):** Primary initial access
   vector for [Actor 1] and [Actor 2] targeting this sector
2. **Valid Accounts (T1078):** 247 exposed credentials make credential
   stuffing immediately feasible — test rate limiting and lockout
3. **Phishing Simulation (T1566):** If in scope — relevant to [Actor 1]
   TTP profile
4. **Legacy System Exploitation:** staging.company.com and old-portal.company.com
   identified as potentially lower-security targets

---

## 8. References

- MITRE ATT&CK: attack.mitre.org
- CISA Advisories: cisa.gov/resources-tools/resources/advisories
- Have I Been Pwned: haveibeenpwned.com
- RansomWatch: ransomwatch.telemetry.ltd
- Shodan: shodan.io
- Certificate Transparency: crt.sh
```

---

## 🔧 Automating the TI Collection Phase

```bash
#!/bin/bash
# Pre-engagement TI collection script
# Usage: ./pre_engagement_ti.sh company.com "Company Name"

DOMAIN="${1:-company.com}"
ORG_NAME="${2:-Company}"
REPORT_DIR="ti_report_${DOMAIN}_$(date +%Y%m%d)"
mkdir -p "$REPORT_DIR"

echo "=== Pre-Engagement TI Collection: $DOMAIN ==="
echo "Started: $(date)"

# 1. Certificate transparency - subdomain enumeration
echo "[1/6] Certificate transparency..."
curl -s "https://crt.sh/?q=%.${DOMAIN}&output=json" 2>/dev/null | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
subs = set()
for item in data:
    name = item.get('name_value', '')
    for sub in name.split('\n'):
        if '$DOMAIN' in sub and sub != '$DOMAIN':
            subs.add(sub.replace('*.', '').strip())
for s in sorted(subs): print(s)
" > "$REPORT_DIR/subdomains.txt" 2>/dev/null
echo "    Found: $(wc -l < $REPORT_DIR/subdomains.txt) subdomains"

# 2. DNS records
echo "[2/6] DNS records..."
{
  echo "A: $(dig +short A $DOMAIN)"
  echo "MX: $(dig +short MX $DOMAIN)"
  echo "TXT: $(dig +short TXT $DOMAIN)"
  echo "NS: $(dig +short NS $DOMAIN)"
  echo "SPF: $(dig +short TXT $DOMAIN | grep spf)"
  echo "DMARC: $(dig +short TXT _dmarc.$DOMAIN)"
} > "$REPORT_DIR/dns_records.txt"

# 3. Typosquatting check
echo "[3/6] Typosquatting detection..."
if command -v dnstwist &>/dev/null; then
  dnstwist "$DOMAIN" --registered --format csv \
    > "$REPORT_DIR/typosquatting.csv" 2>/dev/null
  echo "    Registered variants: $(tail -n +2 $REPORT_DIR/typosquatting.csv | wc -l)"
else
  echo "    dnstwist not installed — skipping"
fi

# 4. Ransomwatch check
echo "[4/6] Ransomware group check..."
curl -s "https://api.ransomwatch.telemetry.ltd/v2/recentcyberattacks" | \
  python3 -c "
import json, sys
org = '$ORG_NAME'.lower()
attacks = json.load(sys.stdin)
matches = [a for a in attacks
           if org in a.get('post_title','').lower() or
              org in a.get('post_description','').lower()]
if matches:
    print('CRITICAL: Organisation found in ransomware group listings!')
    for m in matches:
        print(f'  Group: {m[\"group_name\"]} | Date: {m[\"discovered\"]}')
else:
    print('Not found in recent ransomware victim listings')
" > "$REPORT_DIR/ransomwatch.txt" 2>/dev/null

# 5. Live subdomain probe
echo "[5/6] Probing live subdomains..."
if command -v httpx &>/dev/null; then
  httpx -l "$REPORT_DIR/subdomains.txt" \
    -sc -title -server -silent \
    -o "$REPORT_DIR/live_subdomains.txt" 2>/dev/null
  echo "    Live hosts: $(wc -l < $REPORT_DIR/live_subdomains.txt)"
fi

# 6. Summary
echo "[6/6] Generating summary..."
{
  echo "PRE-ENGAGEMENT TI SUMMARY"
  echo "Domain: $DOMAIN | Date: $(date)"
  echo ""
  echo "Subdomains discovered: $(wc -l < $REPORT_DIR/subdomains.txt)"
  echo "Typosquatting variants registered: $(tail -n +2 $REPORT_DIR/typosquatting.csv 2>/dev/null | wc -l)"
  echo "Ransomwatch: $(cat $REPORT_DIR/ransomwatch.txt)"
  echo ""
  echo "DMARC status:"
  DMARC=$(grep "DMARC:" $REPORT_DIR/dns_records.txt | cut -d: -f2-)
  [ -z "$DMARC" ] && echo "  MISSING" || echo "  $DMARC"
} > "$REPORT_DIR/SUMMARY.txt"

cat "$REPORT_DIR/SUMMARY.txt"
echo ""
echo "=== TI Collection complete → $REPORT_DIR/ ==="
```

---

## 🧭 Key Takeaways

**1. Deliver TI findings immediately — do not wait for the pentest report.**
If pre-engagement TI reveals an active phishing domain or the client listed on a ransomware site, that information has zero value sitting in a draft report. Call the security contact immediately. This is professional obligation, not scope.

**2. The TI report is a standalone deliverable — even if technical testing finds nothing.**
A pre-engagement report showing 247 exposed credentials, a missing DMARC policy, and a registered typosquatting domain is a high-value deliverable completely independent of the technical assessment findings. Sometimes the biggest risk is not in the application.

**3. Always include testing recommendations based on TI.**
The pre-engagement TI report should explicitly recommend which ATT&CK techniques to prioritise in the technical assessment based on adversary profiles. This demonstrates threat-informed testing and justifies testing choices to the client.

---

## 🔗 References
- [SANS CTI Summit Presentations](https://www.sans.org/cyber-security-summit/archives/)
- [TIBER-EU Framework](https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf)
- [CREST Cyber Threat Intelligence Report](https://www.crest-approved.org/membership/crest-publications/)

---
<div align="center">

*Part of [Dark Web From The Trenches](../README.md) — Real notes from 6+ years of enterprise security.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
