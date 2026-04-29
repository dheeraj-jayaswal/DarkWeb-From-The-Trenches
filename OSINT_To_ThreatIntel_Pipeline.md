# OSINT to Threat Intelligence Pipeline — Enterprise Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Threat Intelligence — OSINT Pipeline & Automation
>
> **Context:** Raw OSINT (Open Source Intelligence) is data. Threat intelligence is processed, contextualised, actionable data. The pipeline between them — collection, processing, enrichment, and analysis — is what converts "I found these 47 IP addresses" into "these 47 addresses are associated with an active Cobalt Strike campaign targeting Indian financial services organisations." This document covers the OSINT-to-TI pipeline I apply in enterprise assessments.

---

## 🔄 The OSINT → TI Conversion Process

```
OSINT Collection → Processing → Enrichment → Analysis → Actionable TI

Example pipeline for a credential finding:

OSINT Collection:
  Raw: "dheeraj@company.com:Password123 found in paste site"

Processing:
  → Validate email format ✓
  → Confirm domain matches target ✓
  → Hash the password for breach database lookup ✓
  → Record source, date found, confidence level

Enrichment:
  → HIBP API: email in 3 additional breaches (LinkedIn 2021, Canva 2019)
  → Credential validation (with authorisation): password still active on OWA
  → LinkedIn: employee is IT Administrator (high-value target)
  → Account age: joined 2018 (long tenure = institutional access)

Analysis:
  → This is a currently valid credential for a high-privilege account
  → Available in 4 breach datasets = widely accessible to attackers
  → Active credential stuffing campaigns use exactly this dataset type
  → Risk: immediate account takeover possible without any technical attack

Actionable TI:
  → Priority 1: Force password reset within 24 hours
  → Priority 2: Audit this account's recent login history for anomalies
  → Priority 3: Enforce MFA on all admin accounts immediately
  → Finding severity: Critical (not just High)
```

---

## 🔧 Phase 1 — Automated OSINT Collection

### Domain Intelligence Pipeline

```python
#!/usr/bin/env python3
"""
Enterprise OSINT collection pipeline
For pre-engagement threat intelligence
Usage: python3 osint_pipeline.py company.com
"""

import subprocess
import requests
import json
import sys
from datetime import datetime

TARGET_DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "company.com"
OUTPUT_FILE = f"ti_report_{TARGET_DOMAIN}_{datetime.now().strftime('%Y%m%d')}.json"

results = {
    "domain": TARGET_DOMAIN,
    "collection_date": datetime.now().isoformat(),
    "findings": {}
}

def run_cmd(cmd):
    """Run a shell command and return stdout"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "TIMEOUT"

# 1. Certificate transparency — subdomain enumeration
print(f"[*] Querying certificate transparency for {TARGET_DOMAIN}...")
ct_response = requests.get(
    f"https://crt.sh/?q=%.{TARGET_DOMAIN}&output=json",
    timeout=30
).json()
subdomains = list(set([
    entry['name_value'].replace('*.', '')
    for entry in ct_response
    if TARGET_DOMAIN in entry['name_value']
]))
results["findings"]["subdomains"] = {
    "count": len(subdomains),
    "list": sorted(subdomains)[:50]  # top 50
}
print(f"    Found {len(subdomains)} subdomains")

# 2. HIBP breach check
print(f"[*] Checking HIBP for {TARGET_DOMAIN} domain breaches...")
# Note: Domain search requires HIBP API key (have-i-been-pwned.com/API)
# Substitute your API key
try:
    hibp_response = requests.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{TARGET_DOMAIN}",
        headers={"hibp-api-key": "YOUR_HIBP_API_KEY"},
        timeout=10
    )
    if hibp_response.status_code == 200:
        results["findings"]["hibp_breaches"] = hibp_response.json()
        print(f"    Domain appears in {len(hibp_response.json())} breaches")
    elif hibp_response.status_code == 404:
        results["findings"]["hibp_breaches"] = []
        print("    No breaches found for this domain")
except Exception as e:
    print(f"    HIBP check failed: {e}")

# 3. DNS records
print(f"[*] Collecting DNS records...")
results["findings"]["dns"] = {
    "a_records": run_cmd(f"dig +short A {TARGET_DOMAIN}"),
    "mx_records": run_cmd(f"dig +short MX {TARGET_DOMAIN}"),
    "txt_spf":    run_cmd(f"dig +short TXT {TARGET_DOMAIN} | grep spf"),
    "ns_records": run_cmd(f"dig +short NS {TARGET_DOMAIN}")
}

# 4. Live subdomain probing
print("[*] Probing live subdomains with httpx...")
subdomains_file = f"/tmp/{TARGET_DOMAIN}_subs.txt"
with open(subdomains_file, 'w') as f:
    f.write('\n'.join(subdomains))
live_output = run_cmd(f"httpx -l {subdomains_file} -sc -title -silent 2>/dev/null")
results["findings"]["live_subdomains"] = live_output.split('\n') if live_output else []

# Save results
with open(OUTPUT_FILE, 'w') as f:
    json.dump(results, f, indent=2)

print(f"\n[+] OSINT collection complete → {OUTPUT_FILE}")
print(f"    Subdomains found: {results['findings']['subdomains']['count']}")
```

### GitHub Secret Scanning

```bash
#!/bin/bash
# GitHub credential leak scan for an organisation
# Usage: ./github_scan.sh CompanyOrgName

ORG=${1:-"CompanyName"}
OUTPUT="github_leaks_${ORG}.txt"

echo "=== GitHub Secret Scan: $ORG ===" | tee "$OUTPUT"
echo "Date: $(date)" | tee -a "$OUTPUT"
echo "" | tee -a "$OUTPUT"

# Search terms for enterprise credential leaks:
SEARCHES=(
  '"${ORG}" password'
  '"${ORG}" api_key'
  '"${ORG}" secret_key'
  '"${ORG}" DB_PASSWORD'
  '"${ORG}" connectionString'
  '"${ORG}" aws_access_key'
  'filename:.env "${ORG}"'
  'filename:web.config "${ORG}"'
  'filename:appsettings.json "${ORG}"'
)

# Note: Use GitHub's web search interface at github.com/search
# or the GitHub API with authentication for programmatic search
# The gh CLI tool:
for term in "${SEARCHES[@]}"; do
  expanded="${term/\$\{ORG\}/$ORG}"
  echo "Searching: $expanded" | tee -a "$OUTPUT"
  # gh search code "$expanded" --limit 10 2>/dev/null | tee -a "$OUTPUT"
  echo "  → Manual check: https://github.com/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$expanded'))")&type=code"
  echo "" | tee -a "$OUTPUT"
done

echo "[+] GitHub scan URLs generated in $OUTPUT"
echo "    Review each URL manually at github.com/search"
```

---

## 🔍 Phase 2 — IOC Enrichment

### Enriching IP Addresses

```python
#!/usr/bin/env python3
"""
IP address enrichment for threat intelligence
Checks multiple reputation sources
"""

import requests
import json

def enrich_ip(ip_address):
    """Enrich an IP address with threat intelligence context"""
    intelligence = {"ip": ip_address, "sources": {}}

    # VirusTotal (requires API key — free tier available)
    try:
        vt_response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
            headers={"x-apikey": "YOUR_VT_API_KEY"},
            timeout=10
        )
        if vt_response.status_code == 200:
            vt_data = vt_response.json()
            stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            intelligence["sources"]["virustotal"] = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "country": vt_data.get("data", {}).get("attributes", {}).get("country", "Unknown"),
                "as_owner": vt_data.get("data", {}).get("attributes", {}).get("as_owner", "Unknown")
            }
    except Exception:
        pass

    # AbuseIPDB (free API — excellent for C2 detection)
    try:
        abuse_response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip_address, "maxAgeInDays": 90},
            headers={
                "Key": "YOUR_ABUSEIPDB_API_KEY",
                "Accept": "application/json"
            },
            timeout=10
        )
        if abuse_response.status_code == 200:
            abuse_data = abuse_response.json().get("data", {})
            intelligence["sources"]["abuseipdb"] = {
                "abuse_confidence": abuse_data.get("abuseConfidenceScore", 0),
                "total_reports": abuse_data.get("totalReports", 0),
                "country": abuse_data.get("countryCode", "Unknown"),
                "isp": abuse_data.get("isp", "Unknown"),
                "usage_type": abuse_data.get("usageType", "Unknown")
            }
    except Exception:
        pass

    # ThreatFox (free — malware C2 tracking)
    try:
        tf_response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ip_address},
            timeout=10
        )
        if tf_response.status_code == 200:
            tf_data = tf_response.json()
            if tf_data.get("query_status") == "ok":
                intelligence["sources"]["threatfox"] = {
                    "found": True,
                    "data": tf_data.get("data", [{}])[0] if tf_data.get("data") else {}
                }
            else:
                intelligence["sources"]["threatfox"] = {"found": False}
    except Exception:
        pass

    return intelligence

def assess_threat_level(enriched_ip):
    """Determine overall threat level from enrichment data"""
    score = 0
    indicators = []

    vt = enriched_ip["sources"].get("virustotal", {})
    if vt.get("malicious", 0) > 5:
        score += 3
        indicators.append(f"VirusTotal: {vt['malicious']} malicious detections")

    abuse = enriched_ip["sources"].get("abuseipdb", {})
    if abuse.get("abuse_confidence", 0) > 75:
        score += 3
        indicators.append(f"AbuseIPDB: {abuse['abuse_confidence']}% confidence malicious")
    elif abuse.get("abuse_confidence", 0) > 25:
        score += 1
        indicators.append(f"AbuseIPDB: moderate confidence ({abuse['abuse_confidence']}%)")

    tf = enriched_ip["sources"].get("threatfox", {})
    if tf.get("found"):
        score += 4
        malware = tf.get("data", {}).get("malware", "Unknown")
        indicators.append(f"ThreatFox: associated with {malware}")

    levels = {0: "CLEAN", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 5: "CRITICAL"}
    level = "CLEAN"
    for threshold, label in sorted(levels.items()):
        if score >= threshold:
            level = label

    return {"threat_level": level, "score": score, "indicators": indicators}

# Example usage:
if __name__ == "__main__":
    import sys
    ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    enriched = enrich_ip(ip)
    assessment = assess_threat_level(enriched)
    print(json.dumps({"ip": ip, "assessment": assessment, "raw": enriched}, indent=2))
```

---

## 📊 Phase 3 — Intelligence Analysis Framework

### TIBER-EU / Structured Analysis Approach

```
When analysing collected intelligence for an enterprise client:

1. RELEVANCE FILTER
   Question: Is this intelligence relevant to THIS client?
   - Is the threat actor known to target this industry?
   - Is this vulnerability in technology the client uses?
   - Is the leaked credential associated with this domain?
   
   Filter ruthlessly — irrelevant TI wastes analyst time.

2. TIMELINESS ASSESSMENT
   Question: Is this intelligence still current?
   - Credentials: valid until changed (test to confirm with authorisation)
   - IOCs: IPs rotate frequently (>30 days old = low confidence)
   - TTPs: persist for years (MITRE ATT&CK techniques are stable)
   - Vulnerabilities: permanent until patched
   
   Always note the collection date and assess decay.

3. SOURCE RELIABILITY MATRIX
   
   Source Type          | Reliability | Speed | Depth
   ─────────────────────────────────────────────────────
   Government advisories | High        | Slow  | Medium
   Vendor TI platforms   | High        | Fast  | High
   Community feeds (OTX) | Medium      | Fast  | Low
   Paste sites           | Low-Medium  | Fast  | Low
   Social media          | Low         | Fast  | Low
   Honey pots (own)      | High        | Vary  | High
   Dark web forums       | Low-Medium  | Vary  | Medium

4. CONFIDENCE LEVELS
   Rate every piece of intelligence:
   High (confirmed):   Validated against multiple independent sources
   Medium (probable):  One reliable source with corroborating indicators
   Low (possible):     Single source, unverified, treat as hypothesis
   
   Always include confidence level in reports.
   "The organisation's CEO email was found in a dark web forum
   (Low confidence — single source, unverified)"

5. ACTION MAPPING
   Every intelligence finding should map to at least one action:
   
   Credential exposure → Force password reset
   Exposed asset → Add to hardening schedule
   Active threat actor targeting sector → Test for their known TTPs
   Zero-day in client stack → Emergency patch evaluation
   
   If you cannot map intelligence to an action, question its value.
```

---

## 🔗 References
- [SANS FOR578 — Cyber Threat Intelligence](https://www.sans.org/cyber-security-courses/cyber-threat-intelligence/)
- [MITRE ATT&CK](https://attack.mitre.org)
- [CISA Threat Intelligence Resources](https://www.cisa.gov/resources-tools/resources/cyber-threat-intelligence)
- [AbuseIPDB API](https://docs.abuseipdb.com)
- [ThreatFox API](https://threatfox.abuse.ch/api)

---
<div align="center">

*Part of [Dark Web From The Trenches](../README.md) — Real notes from 6+ years of enterprise security.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
