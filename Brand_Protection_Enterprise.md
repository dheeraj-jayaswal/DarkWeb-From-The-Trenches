# Brand Protection & Domain Monitoring — Enterprise Security Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Threat Intelligence — Brand Protection & Digital Risk
>
> **Context:** Brand protection and domain monitoring are critical components of enterprise digital risk management. Attackers register lookalike domains to conduct phishing campaigns, clone company websites to harvest credentials, and impersonate brands in social media to redirect customers. In enterprise engagements, I include brand exposure assessment as part of pre-engagement OSINT. Finding an active typosquatting domain collecting client credentials before the pentest begins is a Critical finding that requires immediate action.

---

## 🎯 Brand Abuse Attack Vectors

```
Primary brand abuse methods targeting enterprises:

1. TYPOSQUATTING DOMAINS:
   company.com → cornpany.com, company-in.com, cormpany.com
   Used for: Phishing employees and customers
   Attack chain: Register domain → clone website → harvest credentials

2. LOOKALIKE/HOMOGRAPH DOMAINS:
   company.com → cοmpany.com (Cyrillic 'ο' instead of Latin 'o')
   These look IDENTICAL to the legitimate domain in most fonts
   Extremely effective in phishing emails

3. SUBDOMAIN TAKEOVER:
   staging.company.com → CNAME points to deprovisioned cloud service
   Attacker registers the old cloud resource → controls the subdomain
   Used for: XSS, phishing, cookie theft via same-origin

4. SOCIAL MEDIA IMPERSONATION:
   Fake LinkedIn company pages, Twitter/X accounts, YouTube channels
   Used for: Credential phishing, investment fraud, executive impersonation

5. APP STORE CLONES:
   Fake mobile apps claiming to be official company apps
   Used for: Credential harvesting, malware distribution

6. EMAIL SPOOFING:
   Exploiting missing/misconfigured SPF, DKIM, DMARC records
   Used for: Business Email Compromise (BEC), spearphishing employees
```

---

## 🔧 Domain Monitoring Tools and Techniques

### DNSTwist — Typosquatting Detection

```bash
# Install: pip3 install dnstwist

# Generate all possible typosquatting variants:
dnstwist company.com --registered --format csv > typosquatting_results.csv

# Check which variants are actually registered:
dnstwist company.com --registered --mxcheck --format json | \
  python3 -c "
import json,sys
data = json.load(sys.stdin)
malicious = [d for d in data if d.get('dns-a') and d['domain'] != 'company.com']
for d in malicious[:20]:
    print(f\"REGISTERED: {d['domain']} → {d.get('dns-a',['?'])[0]}\")
"

# Phishing-specific variants (most dangerous):
dnstwist --phishing company.com --registered --format json
```

### Python Brand Monitoring Script

```python
#!/usr/bin/env python3
"""
Brand protection monitoring — domain and certificate transparency
"""

import requests
import socket
import json
from datetime import datetime

def check_certificate_transparency(domain: str) -> list:
    """Find lookalike domains registered with SSL certificates"""
    response = requests.get(
        f"https://crt.sh/?q=%25{domain}&output=json",
        timeout=15
    )
    certs = response.json()

    # Find certificates for domains similar to ours
    our_domain = domain.lower()
    suspicious = []

    for cert in certs:
        cert_domain = cert.get("name_value", "").lower()
        # If it's not exactly our domain but contains our name
        if our_domain in cert_domain and cert_domain != our_domain:
            if not cert_domain.startswith("*."):
                suspicious.append({
                    "domain": cert_domain,
                    "issued": cert.get("not_before"),
                    "issuer": cert.get("issuer_ca_id")
                })

    return list({d["domain"]: d for d in suspicious}.values())

def check_spf_dmarc(domain: str) -> dict:
    """Check email authentication records"""
    import subprocess

    results = {}

    # SPF record
    try:
        spf_output = subprocess.run(
            f"dig +short TXT {domain} | grep spf",
            shell=True, capture_output=True, text=True
        ).stdout.strip()
        results["spf"] = {
            "record": spf_output if spf_output else "MISSING",
            "status": "OK" if "v=spf1" in spf_output else "MISSING"
        }
    except Exception:
        results["spf"] = {"status": "ERROR"}

    # DMARC record
    try:
        dmarc_output = subprocess.run(
            f"dig +short TXT _dmarc.{domain}",
            shell=True, capture_output=True, text=True
        ).stdout.strip()
        if dmarc_output and "v=DMARC1" in dmarc_output:
            # Check if policy is reject (most strict)
            policy = "none"
            if "p=reject" in dmarc_output:
                policy = "reject"
            elif "p=quarantine" in dmarc_output:
                policy = "quarantine"
            results["dmarc"] = {"record": dmarc_output, "policy": policy, "status": "OK"}
        else:
            results["dmarc"] = {"status": "MISSING"}
    except Exception:
        results["dmarc"] = {"status": "ERROR"}

    return results

def generate_brand_report(domain: str) -> dict:
    """Generate a brand protection assessment report"""

    print(f"[*] Brand protection assessment for: {domain}")

    # Certificate transparency lookalikes
    print("[*] Checking certificate transparency...")
    ct_lookalikes = check_certificate_transparency(domain)

    # Email authentication
    print("[*] Checking email authentication...")
    email_auth = check_spf_dmarc(domain)

    report = {
        "domain": domain,
        "assessment_date": datetime.now().isoformat(),
        "lookalike_domains": ct_lookalikes,
        "lookalike_count": len(ct_lookalikes),
        "email_authentication": email_auth,
        "risk_indicators": []
    }

    # Risk assessment
    if len(ct_lookalikes) > 0:
        report["risk_indicators"].append(
            f"{len(ct_lookalikes)} lookalike domains with SSL certificates found"
        )

    if email_auth.get("spf", {}).get("status") == "MISSING":
        report["risk_indicators"].append("SPF record missing — email spoofing possible")

    if email_auth.get("dmarc", {}).get("status") == "MISSING":
        report["risk_indicators"].append("DMARC record missing — phishing emails appear legitimate")
    elif email_auth.get("dmarc", {}).get("policy") == "none":
        report["risk_indicators"].append("DMARC policy=none — spoofed emails delivered without action")

    return report

if __name__ == "__main__":
    import sys
    domain = sys.argv[1] if len(sys.argv) > 1 else "company.com"
    report = generate_brand_report(domain)
    print(json.dumps(report, indent=2))
```

---

## 📧 Email Authentication Assessment

```bash
# Check SPF, DKIM, DMARC for a domain:
TARGET="company.com"

echo "=== Email Authentication Assessment: $TARGET ==="

echo ""
echo "1. SPF Record:"
dig +short TXT "$TARGET" | grep "v=spf1"
# If empty: SPF missing = email spoofing possible

echo ""
echo "2. DMARC Record:"
dig +short TXT "_dmarc.$TARGET"
# If empty: DMARC missing = spoofed emails delivered to recipients
# If p=none: monitoring only, not enforcing
# If p=quarantine: suspicious to spam
# If p=reject: BEST — rejects spoofed emails

echo ""
echo "3. DKIM (need selector — check email headers from legitimate mail):"
dig +short TXT "selector1._domainkey.$TARGET"
dig +short TXT "google._domainkey.$TARGET"

# DMARC policy assessment:
DMARC=$(dig +short TXT "_dmarc.$TARGET")
if [ -z "$DMARC" ]; then
  echo ""
  echo "⚠️  FINDING: DMARC record missing"
  echo "   An attacker can send emails appearing to be from @$TARGET"
  echo "   with no technical indication of spoofing to most recipients"
  echo "   Severity: HIGH for enterprise organisations"
elif echo "$DMARC" | grep -q "p=none"; then
  echo ""
  echo "⚠️  FINDING: DMARC present but policy=none (monitoring only)"
  echo "   Spoofed emails are still delivered — DMARC not enforcing"
  echo "   Severity: MEDIUM — monitoring exists but no enforcement"
elif echo "$DMARC" | grep -q "p=reject"; then
  echo ""
  echo "✓  DMARC policy=reject — strong email authentication"
fi
```

---

## 📋 Brand Assessment Report Template

```
Finding Title: Active Typosquatting Domain Collecting Credentials

Severity: Critical | Immediate client notification required

Finding:
  Domain: cornpany-login.com (typosquatting company.com)
  Registered: 15 days ago
  SSL certificate: Valid (Let's Encrypt)
  Content: Exact clone of company.com login page

Evidence:
  → dnstwist identified cornpany-login.com as a registered variant
  → crt.sh confirms SSL certificate issued within the past 30 days
  → Website content: cloned login page requesting company credentials
  → MX records: configured (capable of receiving credentials via form)

Technical Indicators:
  Registrar: [Registrar name]
  Registrant: Private (WHOIS privacy)
  IP: [IP address]
  Hosting: [Hosting provider]

Recommended Actions:
  Immediate: Register an abuse report with the hosting provider
  Immediate: Submit takedown request to the registrar
  Immediate: Alert employees about the phishing domain via internal communication
  Immediate: Monitor for any employees who may have entered credentials
  Short-term: Implement DMARC reject policy to prevent related email spoofing
  Long-term: Register common typosquatting variants defensively
  Long-term: Implement brand monitoring service for ongoing detection

Finding: Missing DMARC Policy
Severity: High

dig +short TXT "_dmarc.company.com"
→ No output returned (DMARC record not present)

Impact:
  Any attacker can send emails appearing to come from @company.com
  with no technical authentication failure. Business Email Compromise
  (BEC) attacks typically use exactly this technique.

Remediation:
  Step 1: Publish DMARC record at monitoring level:
  _dmarc.company.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@company.com"

  Step 2: After 4 weeks of monitoring, move to quarantine:
  "v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@company.com"

  Step 3: After validation, enforce rejection:
  "v=DMARC1; p=reject; rua=mailto:dmarc@company.com; ruf=mailto:dmarc-forensics@company.com"
```

---

## 🧭 Key Takeaways

**1. Missing DMARC policy is a High severity finding in every enterprise engagement.**
An organisation without DMARC enforcement is one that any attacker can impersonate via email with no technical barrier. Business Email Compromise costs enterprises billions annually. DMARC reject policy is a 30-minute implementation that eliminates the simplest form of email spoofing.

**2. Typosquatting domain detection should be part of every pre-engagement TI check.**
Run dnstwist against the client domain before engagement starts. Finding an active phishing domain collecting employee credentials is a Critical out-of-band finding that the client needs to know about immediately — completely independent of the technical testing scope.

**3. Register your own typosquatting variants defensively.**
After identifying lookalike domains through dnstwist, recommend that the client proactively register the highest-risk variants (Keyboard adjacency errors, common misspellings). Domain registration is inexpensive. Credential harvest cleanup is not.

---

## 🔗 References
- [DNSTwist GitHub](https://github.com/elceef/dnstwist)
- [DMARC.org Implementation Guide](https://dmarc.org/overview/)
- [Google Postmaster Tools](https://postmaster.google.com)
- [CERT-In Advisory on Phishing](https://www.cert-in.org.in)

---
<div align="center">

*Part of [Dark Web From The Trenches](../README.md) — Real notes from 6+ years of enterprise security.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
