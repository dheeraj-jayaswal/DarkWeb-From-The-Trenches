# Credential Leak Monitoring — Enterprise Security Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Threat Intelligence — Credential Exposure & Breach Monitoring
>
> **Context:** Credential monitoring is the threat intelligence activity with the most direct, immediate security value for enterprise organisations. When employee credentials appear in a breach database, an attack becomes trivially accessible to anyone who buys or downloads the breach dataset. In enterprise assessments, I always run credential exposure checks before testing begins — it is often the most impactful finding, and it shapes the entire testing strategy.

---

## 🧠 Why Credential Leaks Are a Critical Enterprise Risk

```
The credential exposure threat chain:

1. Breach occurs (company A's database breached)
2. Data sold/released on dark web marketplaces
3. Attacker queries breach data for @targetcompany.com emails
4. Attacker finds 247 valid email addresses with passwords
5. Attacker scripts credential stuffing against target's portals
   (OWA, VPN, SSO, corporate applications)
6. Success rate 0.5-2% typical = 1-5 account compromises
7. One compromised account = initial foothold achieved
8. No technical vulnerability exploitation required

Why this matters in enterprise penetration testing:
  Credential stuffing attacks bypass ALL technical security controls:
  → WAF: doesn't help (valid credentials, valid session)
  → IDS/IPS: doesn't help (legitimate authentication traffic)
  → Firewall: doesn't help (traffic to legitimate public portal)
  → Vulnerability scanners: don't detect this at all

The only defences are:
  → Monitoring and detecting the stuffing attempt
  → MFA enforcement (makes valid password insufficient)
  → Credential monitoring (catch before attacker does)
```

---

## 🔧 Phase 1 — Free Credential Monitoring Tools

### Have I Been Pwned (HIBP)

```python
#!/usr/bin/env python3
"""
HIBP Domain Credential Exposure Check
For pre-engagement threat intelligence
Requires: HIBP API key (haveibeenpwned.com/API/Key)
"""

import requests
import json
import time
from typing import List, Dict

def check_domain_breaches(domain: str, api_key: str) -> Dict:
    """
    Check all breaches associated with a domain
    Returns summary of breach exposure
    """
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "Enterprise-TI-Assessment"
    }

    # Get all breaches for the domain
    url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
    response = requests.get(url, headers=headers, timeout=15)

    if response.status_code == 200:
        breach_data = response.json()
        
        # Analyse the breaches
        total_accounts = sum(
            len(accounts) for accounts in breach_data.values()
        )
        
        return {
            "domain": domain,
            "status": "EXPOSED",
            "total_accounts_in_breaches": total_accounts,
            "breach_count": len(breach_data),
            "breaches": breach_data
        }
    elif response.status_code == 404:
        return {
            "domain": domain,
            "status": "NOT_FOUND",
            "total_accounts_in_breaches": 0,
            "breach_count": 0
        }
    else:
        return {
            "domain": domain,
            "status": "ERROR",
            "error": f"HTTP {response.status_code}"
        }

def check_email_breaches(email: str, api_key: str) -> Dict:
    """
    Check if a specific email address appears in any breach
    """
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "Enterprise-TI-Assessment"
    }

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    params = {"truncateResponse": False}
    
    response = requests.get(url, headers=headers, params=params, timeout=15)
    time.sleep(1.5)  # HIBP rate limit: ~1 request per 1.5 seconds

    if response.status_code == 200:
        breaches = response.json()
        sensitive_breaches = [
            b for b in breaches
            if b.get("IsSensitive", False) or
               any(d in ["Passwords", "Email addresses", "Financial data"]
                   for d in b.get("DataClasses", []))
        ]
        return {
            "email": email,
            "status": "FOUND",
            "total_breaches": len(breaches),
            "sensitive_breaches": len(sensitive_breaches),
            "breach_names": [b["Name"] for b in breaches],
            "data_classes": list(set(
                dc for b in breaches
                for dc in b.get("DataClasses", [])
            ))
        }
    elif response.status_code == 404:
        return {"email": email, "status": "CLEAN"}
    else:
        return {"email": email, "status": "ERROR", "code": response.status_code}

def bulk_email_check(emails: List[str], api_key: str) -> List[Dict]:
    """
    Check multiple email addresses with rate limiting
    """
    results = []
    total = len(emails)

    for i, email in enumerate(emails, 1):
        print(f"[{i}/{total}] Checking: {email}")
        result = check_email_breaches(email, api_key)
        results.append(result)
        time.sleep(1.5)  # Respect HIBP rate limit

    return results

def generate_exposure_report(results: List[Dict]) -> str:
    """Generate a summary exposure report"""
    exposed = [r for r in results if r["status"] == "FOUND"]
    clean = [r for r in results if r["status"] == "CLEAN"]
    
    report = [
        "=" * 60,
        "CREDENTIAL EXPOSURE ASSESSMENT REPORT",
        "=" * 60,
        f"Total accounts checked: {len(results)}",
        f"Accounts found in breaches: {len(exposed)} ({len(exposed)/len(results)*100:.1f}%)",
        f"Clean accounts: {len(clean)}",
        "",
        "EXPOSED ACCOUNTS:",
    ]

    for account in exposed:
        report.append(
            f"  {account['email']}: "
            f"{account['total_breaches']} breach(es) | "
            f"Data types: {', '.join(account.get('data_classes', [])[:3])}"
        )

    return "\n".join(report)

# Usage example:
if __name__ == "__main__":
    API_KEY = "YOUR_HIBP_API_KEY"
    TARGET_EMAILS = [
        "admin@company.com",
        "ceo@company.com",
        "it.helpdesk@company.com"
    ]
    
    results = bulk_email_check(TARGET_EMAILS, API_KEY)
    print(generate_exposure_report(results))
```

### Paste Site Monitoring (Free)

```bash
#!/bin/bash
# Paste site monitoring for credential and data leaks
# Checks surface-accessible paste aggregators

DOMAIN="${1:-company.com}"
OUTPUT="paste_monitor_${DOMAIN}_$(date +%Y%m%d).txt"

echo "=== Paste Site Monitoring: $DOMAIN ===" | tee "$OUTPUT"
echo "Date: $(date)" | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Google dorking for paste sites (manual execution recommended):
echo "=== Manual Google Search Queries ===" | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

QUERIES=(
  "site:pastebin.com \"$DOMAIN\" password"
  "site:pastebin.com \"@$DOMAIN\""
  "site:paste.ee \"$DOMAIN\" credentials"
  "site:hastebin.com \"$DOMAIN\" password"
  "site:justpaste.it \"$DOMAIN\" password"
  "site:dpaste.com \"$DOMAIN\""
  "\"$DOMAIN\" \"password\" site:pastebin.com OR site:paste.ee"
)

for query in "${QUERIES[@]}"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$query'))")
  echo "Search URL: https://www.google.com/search?q=$encoded" | tee -a "$OUTPUT"
done

echo "" | tee -a "$OUTPUT"
echo "=== psbdmp.ws API (Pastebin dump monitor) ===" | tee -a "$OUTPUT"
# psbdmp.ws provides a searchable index of Pastebin content
curl -s "https://psbdmp.ws/api/search/$DOMAIN" | \
  python3 -c "import sys,json; data=json.load(sys.stdin); print(json.dumps(data[:5], indent=2))" \
  2>/dev/null | tee -a "$OUTPUT"

echo "" | tee -a "$OUTPUT"
echo "=== Results saved to: $OUTPUT ===" 
```

---

## 🔍 Phase 2 — Interpreting Credential Exposure

### Risk Stratification by Account Type

```
Credential exposure severity by account role:

CRITICAL priority (immediate action):
  → IT Administrator accounts (@company.com with admin role)
  → C-suite executive accounts (CEO, CTO, CISO)
  → Finance / treasury accounts
  → System/service accounts
  → DevOps and cloud infrastructure accounts

HIGH priority (within 24 hours):
  → All accounts with valid current passwords in breaches
  → HR and payroll access accounts
  → Customer data access accounts
  → VPN / remote access accounts

MEDIUM priority (within 7 days):
  → Accounts in older breaches (3+ years) — may have changed passwords
  → Accounts where only non-password data was exposed (email, name)
  → Contractor/vendor accounts

Evidence quality assessment:
  Highest risk: plaintext passwords in breach data
  High risk:    MD5 or SHA-1 hashes (crackable in minutes)
  Medium risk:  bcrypt or Argon2 hashes (hard to crack)
  Lower risk:   Email address only, no password
  
  Note: bcrypt hashes are STILL a finding — they confirm the 
  account was in a breach and weak passwords are still crackable.
  "Company@2022" cracks in seconds regardless of bcrypt.
```

### Enterprise Breach Assessment Template

```markdown
## Pre-Engagement Credential Exposure Summary

**Target Domain:** company.com
**Assessment Date:** [DD-MM-YYYY]
**Assessor:** Dheeraj Kumar Jayaswal

### Executive Summary

| Metric | Value |
|---|---|
| Total email addresses found in breaches | 247 |
| Accounts with plaintext passwords | 18 |
| Accounts with crackable hashes (MD5/SHA1) | 89 |
| Accounts with strong hashes (bcrypt) | 140 |
| Number of distinct breach sources | 7 |
| Oldest breach source | LinkedIn (2021) |
| Most recent breach source | [Dataset name] (2024) |

### Breach Sources

| Breach | Year | Accounts | Data Types Exposed |
|---|---|---|---|
| LinkedIn | 2021 | 156 | Email, password hash, name |
| Canva | 2019 | 34 | Email, name, geolocation |
| [Breach 3] | 2023 | 57 | Email, plaintext password |

### Risk Assessment

**Severity: HIGH**

247 company.com email addresses are accessible in publicly available
breach databases. 18 accounts have exposed plaintext passwords.
Active credential stuffing campaigns routinely target Indian financial
services organisations using exactly these breach datasets.

### Recommended Actions

1. **Immediate (24 hours):** Force password reset for all 247 affected accounts
2. **Immediate (24 hours):** Enforce MFA on all affected accounts before password reset
3. **Short-term (7 days):** Audit login history for all 247 accounts for anomalous access
4. **Short-term (7 days):** Deploy credential monitoring service for ongoing alerting
5. **Long-term:** Implement HIBP integration in password reset to prevent reuse of known-breached passwords
```

---

## 🛡️ Phase 3 — Defensive Recommendations for Clients

### Technical Controls

```python
# Integration of HIBP into password change workflow
# Prevents users from setting passwords known to be in breach databases
# (Microsoft and Google both do this natively)

import requests
import hashlib

def is_password_pwned(password: str) -> dict:
    """
    Check if a password appears in HIBP's pwned passwords database
    Uses k-anonymity — only the first 5 chars of SHA1 hash are sent
    No privacy risk — full password never leaves local system
    """
    # Hash the password
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    # Query HIBP with only the hash prefix
    response = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"Add-Padding": "true"},
        timeout=10
    )

    if response.status_code != 200:
        return {"status": "ERROR", "count": 0}

    # Check if our suffix appears in the response
    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return {
                "status": "PWNED",
                "count": int(count),
                "message": f"This password appears in {count} known data breaches"
            }

    return {"status": "CLEAN", "count": 0}

# Enterprise integration example (password change endpoint):
def validate_new_password(new_password: str) -> dict:
    """Validate new password against breach database"""
    result = is_password_pwned(new_password)

    if result["status"] == "PWNED":
        return {
            "valid": False,
            "reason": f"This password has appeared in {result['count']:,} "
                      f"data breaches and cannot be used. "
                      f"Please choose a different password."
        }

    return {"valid": True}
```

---

## 🧭 Key Takeaways

**1. Credential monitoring is the highest-ROI security activity per hour.**
Running HIBP against a domain takes five minutes and frequently reveals more immediate risk than a full-day technical assessment. "247 employees have passwords available in breach databases" is a C-level finding that triggers immediate action.

**2. Integrate HIBP into password change workflows.**
Microsoft, Google, and many enterprise identity providers natively check passwords against breach databases during password change. For organisations without this, a simple HIBP API integration prevents users from reusing known-compromised passwords. This is a cheap, high-value control.

**3. Always check account roles when prioritising exposed credentials.**
An IT admin's password in a breach database is Critical. A junior analyst's password is High. The account's level of privilege determines the blast radius of a successful credential stuffing attack.

---

## 🔗 References
- [Have I Been Pwned API Documentation](https://haveibeenpwned.com/API/v3)
- [HIBP Pwned Passwords (k-anonymity)](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [CISA Protecting Against Credential Stuffing](https://www.cisa.gov/sites/default/files/publications/CISA_MS-ISAC_Ransomware%20Guide_S508C.pdf)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---
<div align="center">

*Part of [Dark Web From The Trenches](../README.md) — Real notes from 5+ years of enterprise security.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
