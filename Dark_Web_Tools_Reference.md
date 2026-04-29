# Dark Web & Threat Intelligence Tools Reference

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Tools Reference — TI Platform & OSINT Tooling

---

## 🌐 Surface Web TI Tools (No Special Setup Required)

| Tool | Purpose | Free? | URL |
|---|---|---|---|
| **Shodan** | Internet device intelligence, exposed services | Free tier | shodan.io |
| **Censys** | Internet-wide scan data, certificate intel | Free tier | censys.io |
| **crt.sh** | Certificate transparency, subdomain discovery | Free | crt.sh |
| **HIBP** | Credential breach database lookup | Free + paid API | haveibeenpwned.com |
| **URLhaus** | Malicious URL intelligence | Free | urlhaus.abuse.ch |
| **MalwareBazaar** | Malware sample intelligence | Free | bazaar.abuse.ch |
| **ThreatFox** | IOC sharing and lookup | Free | threatfox.abuse.ch |
| **VirusTotal** | File/URL/domain/IP reputation | Free + paid | virustotal.com |
| **Ahmia** | Dark web search (surface accessible) | Free | ahmia.fi |
| **RansomWatch** | Ransomware victim tracking | Free | ransomwatch.telemetry.ltd |
| **OTX AlienVault** | Community threat intelligence | Free | otx.alienvault.com |
| **DNSTwist** | Typosquatting domain detection | Free/Open source | github.com/elceef/dnstwist |

---

## 🔍 OSINT Automation Frameworks

### SpiderFoot

```bash
# Install: pip3 install spiderfoot --break-system-packages
# Or Docker: docker pull smicallef/spiderfoot

# Web interface:
python3 sf.py -l 127.0.0.1:5001

# CLI scan for organisation OSINT:
python3 sfcli.py -t company.com \
  -m sfp_shodan,sfp_censys,sfp_dnstwist,sfp_ahmia,sfp_haveibeenpwned \
  -o csv -f spiderfoot_results.csv

# Key modules for TI work:
# sfp_shodan      → Shodan IP and host intelligence
# sfp_censys      → Censys internet scan data
# sfp_dnstwist    → Typosquatting detection
# sfp_ahmia       → Dark web content indexing
# sfp_haveibeenpwned → Credential exposure
# sfp_github      → GitHub secret scanning
# sfp_hunter      → Email address discovery
# sfp_dnsdumpster → DNS enumeration
```

### theHarvester

```bash
# Email, domain, and host intelligence gathering
theHarvester -d company.com \
  -b google,bing,linkedin,shodan,censys \
  -l 500 \
  -f harvester_output.html

# Sources: google, bing, linkedin, shodan, censys,
#          hunter, securitytrails, duckduckgo, yahoo
```

### Maltego (Visual Intelligence)

```
Maltego provides visual relationship mapping for threat intelligence.
Community edition: free, limited transforms
Professional: paid, full transform set

Key transforms for enterprise TI:
  → Domain → Certificate → Subdomains
  → Email → Breach → Credentials
  → IP → Shodan → Services
  → Organisation → Threat Actors → TTPs
  → HIBP Transform: check breach exposure visually

Best for: connecting dots between multiple OSINT sources,
          visualising threat actor relationships,
          presenting intelligence to non-technical stakeholders
```

---

## 🔐 Credential Intelligence Tools

### truffleHog — Git Repository Secret Scanning

```bash
# Install: pip3 install trufflehog --break-system-packages

# Scan a public GitHub repository for secrets:
trufflehog github \
  --repo https://github.com/company/public-repo \
  --only-verified \
  --json | python3 -c "
import sys, json
for line in sys.stdin:
    finding = json.loads(line)
    if finding.get('VerificationFromCredential'):
        print(f\"VERIFIED SECRET: {finding.get('DetectorName')}\")
        print(f\"  File: {finding.get('SourceMetadata', {}).get('Data', {})}\")
        print()
"

# Scan an organisation's GitHub:
trufflehog github \
  --org company-github-org \
  --only-verified

# Scan local directory:
trufflehog filesystem /path/to/local/repo --only-verified

# What truffleHog finds:
# AWS Access Keys + Secret Keys (and VERIFIES them against AWS API)
# Stripe API keys (verified against Stripe API)
# GitHub tokens
# Generic high-entropy strings that match credential patterns
```

### gitleaks

```bash
# Install: apt install gitleaks OR download from GitHub releases

# Scan current git repository:
gitleaks detect --source . --report-format json --report-path leaks.json

# Scan a remote GitHub repository:
gitleaks detect \
  --source https://github.com/company/repo \
  --report-format json \
  --report-path leaks.json

# Scan git history (finds deleted secrets too):
gitleaks detect --log-opts="--all" --report-format json

# Parse results:
cat leaks.json | python3 -c "
import json, sys
findings = json.load(sys.stdin)
for f in findings[:10]:
    print(f\"Rule: {f.get('RuleID')}\")
    print(f\"File: {f.get('File')}\")
    print(f\"Secret: {f.get('Secret', '')[:20]}...\")
    print()
"
```

---

## 📊 Threat Intelligence Platforms

### MISP (Malware Information Sharing Platform)

```
Open source threat intelligence sharing platform
Install: https://www.misp-project.org/download/

Key capabilities:
  → Store and share IOCs (indicators of compromise)
  → Correlate events across multiple sources
  → Export to STIX/TAXII format for SIEM integration
  → Connect to other MISP instances for community sharing

Enterprise use:
  → Internal IOC repository for pentest findings
  → Subscribe to community threat feeds
  → Export indicators to firewall/IDS for detection
  → Share indicators with sector peers (ISACs)
```

### OpenCTI

```
Open source threat intelligence platform
More modern interface than MISP
GitHub: https://github.com/OpenCTI-Platform/opencti

Key capabilities:
  → Structured threat intelligence using STIX 2.1
  → ATT&CK integration for technique mapping
  → Threat actor relationship mapping
  → Connector ecosystem for auto-ingestion from feeds
  → Dashboard and reporting

Connectors available for:
  MITRE ATT&CK, CISA advisories, AlienVault OTX,
  Shodan, VirusTotal, AbuseCH, URLhaus, and 100+ others
```

---

## 🛡️ Email Authentication Tools

```bash
# Check all email authentication in one command:
check_email_auth() {
  local domain=$1
  echo "=== Email Auth Assessment: $domain ==="

  echo "SPF:"
  result=$(dig +short TXT "$domain" 2>/dev/null | grep "v=spf1")
  [ -z "$result" ] && echo "  MISSING" || echo "  $result"

  echo "DMARC:"
  result=$(dig +short TXT "_dmarc.$domain" 2>/dev/null)
  if [ -z "$result" ]; then
    echo "  MISSING - email spoofing trivially possible"
  elif echo "$result" | grep -q "p=reject"; then
    echo "  ENFORCED (p=reject) ✓"
  elif echo "$result" | grep -q "p=quarantine"; then
    echo "  PARTIAL (p=quarantine)"
  else
    echo "  MONITORING ONLY (p=none) - not enforcing"
  fi

  echo "BIMI (Brand Indicators):"
  result=$(dig +short TXT "default._bimi.$domain" 2>/dev/null)
  [ -z "$result" ] && echo "  Not configured" || echo "  $result"
}

check_email_auth company.com
```

---

## 🧭 Tool Selection Guide

```
For different professional contexts:

Solo analyst / small team:
  → theHarvester + SpiderFoot (free, CLI)
  → HIBP API (simple Python script)
  → VirusTotal for IOC enrichment
  → crt.sh for certificate transparency
  → RansomWatch for ransomware monitoring

Enterprise security team:
  → Commercial platform (Recorded Future / Digital Shadows)
  → MISP or OpenCTI for internal intelligence management
  → Shodan team membership for asset monitoring
  → SpiderFoot HX for automation
  → HIBP team/enterprise plan for domain monitoring

Incident response:
  → VirusTotal (immediate file/URL/IP analysis)
  → ThreatFox (C2 infrastructure identification)
  → MISP (IOC correlation)
  → Shodan (attacker infrastructure analysis)
  → RansomWatch (ransomware group identification)

Pre-engagement TI (pentest):
  → crt.sh (subdomain enumeration)
  → HIBP (credential exposure)
  → Shodan (asset discovery)
  → GitHub + truffleHog (secret scanning)
  → dnstwist (typosquatting detection)
  → RansomWatch (client name check)
```

---

## 🔗 References
- [SpiderFoot Documentation](https://www.spiderfoot.net/documentation/)
- [truffleHog GitHub](https://github.com/trufflesecurity/trufflehog)
- [gitleaks GitHub](https://github.com/gitleaks/gitleaks)
- [MISP Project](https://www.misp-project.org)
- [OpenCTI Platform](https://github.com/OpenCTI-Platform/opencti)

---
<div align="center">

*Part of [Dark Web From The Trenches](../README.md) — Real notes from 6+ years of enterprise security.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
