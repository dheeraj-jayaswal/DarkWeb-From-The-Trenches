# Dark Web OSINT Methodology — Enterprise Security Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 5+ Years Enterprise AppSec
>
> **Category:** Dark Web Intelligence — Safe Reconnaissance Methodology
>
> **Context:** Dark web reconnaissance is a legitimate, essential component of enterprise threat intelligence. Security professionals, incident responders, law enforcement, and researchers regularly use dark web sources to understand the threat landscape, find exposed organisational data, and monitor for emerging threats. This document covers the professional methodology I apply — safely, legally, and within ethical boundaries.

---

## ⚖️ Legal and Ethical Framework First

```
Dark web research is LEGAL when:
  ✓ Conducted for threat intelligence and defensive security
  ✓ Limited to observation and documentation — not participation
  ✓ You have written client authorisation for the investigation scope
  ✓ You do not purchase, possess, or distribute illegal content
  ✓ You do not interact with criminal services or actors
  ✓ You maintain an isolated investigation environment
  ✓ Evidence is documented for legitimate professional purposes

Dark web research is ILLEGAL when:
  ✗ Purchasing stolen data, credentials, or illegal goods
  ✗ Participating in criminal forums or transactions
  ✗ Accessing content that is illegal to view (CSAM, etc.)
  ✗ Facilitating or enabling criminal activity
  ✗ Conducting research without proper authorisation on others' behalf

Professional standard I follow:
  OBSERVE → DOCUMENT → REPORT → DELETE
  The goal is defensive intelligence, not data possession.
```

---

## 🛡️ Safe Investigation Environment Setup

### VM Configuration

```
Dedicated investigation VM — never your work or personal machine:

OS: Tails OS (most privacy-preserving) or Whonix (VM-based)
    Kali Linux with dedicated investigation profile (acceptable)

Network configuration:
  VPN → Tor (defence in depth for anonymity)
  Never: bare Tor without VPN on corporate network
  Never: bridge corporate network to investigation VM

Browser: Tor Browser ONLY (never standard browser on .onion)
  → Security Level: Safest (disables JavaScript on .onion sites)
  → This prevents most fingerprinting and tracking

Session hygiene:
  → Take snapshot BEFORE each investigation session
  → Revert to snapshot AFTER each session
  → No clipboard sharing between investigation VM and host
  → No file transfers from investigation VM to host
  → No logins to personal accounts inside investigation session

Tor Browser security settings for professional use:
  Security Level: Safest
  → JavaScript disabled on all non-HTTPS sites
  → JavaScript disabled on .onion sites
  → This is non-negotiable for professional investigations
  → Any .onion document (PDF, Word, etc.) can "phone home"
  → Never open downloaded documents inside Tor Browser
```

---

## 🔍 Phase 1 — Surface Web Dark Web Search (No Tor Required)

### Ahmia.fi — Indexed Dark Web Search

```bash
# Ahmia indexes dark web content and makes it searchable
# from the regular web — no Tor required for basic searches
# URL: https://ahmia.fi/search/?q=QUERY

TARGET="company.com"

# Search queries for organisational exposure:
QUERIES=(
  "$TARGET credentials"
  "$TARGET database"
  "$TARGET breach"
  "@$TARGET email"
  "\"$TARGET\" leak"
)

for query in "${QUERIES[@]}"; do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$query'))")
  echo "Ahmia: https://ahmia.fi/search/?q=$encoded"
done

# Important: Ahmia results show snippets only
# Do NOT click through to .onion links without Tor Browser + safe environment
```

### OnionSearch — Multi-Engine CLI Search

```bash
# OnionSearch queries multiple dark web search engines simultaneously
# Install: pip3 install onionsearch

# Basic search for organisation exposure:
onionsearch "company.com credentials" \
  --output company_darkweb_results.txt \
  --engines ahmia darksearchio \
  2>/dev/null

# Parse results:
cat company_darkweb_results.txt | grep -v "^#" | head -20

# Safe practice: review titles and snippets ONLY
# Do not visit .onion URLs without proper setup
```

---

## 🔍 Phase 2 — Structured Investigation Protocol

### What to Search For (Priority Order)

```
Tier 1 — Immediate business risk (search first):
  "[organisation name] credentials"
  "[organisation name] database dump"
  "[domain.com] passwords"
  "[domain.com] breach 2024"
  "admin@[domain.com]"    ← admin/privileged accounts specifically

Tier 2 — Infrastructure exposure:
  "[organisation name] source code"
  "[organisation name] config files"
  "[organisation name] VPN credentials"
  "[organisation name] AWS keys"

Tier 3 — Reputation and threat actor interest:
  "[organisation name] target"
  "[organisation name] hack"
  "[organisation name] ransomware"
  "[executive names]"     ← executive targeting

Tier 4 — Third-party and supply chain:
  "[key technology vendor]"
  "[major software used by org]"
```

### Evidence Collection Standards

```
When potentially relevant content is found:

1. Screenshot the search results page (not the content)
2. Record:
   → Exact search query used
   → Search engine/platform
   → Date and time of discovery
   → URL or .onion address (for reference, not distribution)
   → Brief description of what was found (type of data, apparent age)
   → Apparent data freshness (recent vs old breach)

3. Assess:
   → Is this actually relevant to the target organisation?
   → Is this new information or a known historical breach?
   → What is the apparent threat level?
   → What immediate action should be recommended?

4. Document for client report:
   → "During pre-engagement threat intelligence, evidence of [DATA TYPE]
      associated with [TARGET DOMAIN] was found on [PLATFORM TYPE].
      The data appears to be from approximately [DATE PERIOD].
      This represents [RISK LEVEL] to the organisation."

5. Do NOT:
   → Download or store breach data
   → Reproduce PII or credentials in the report (summarise only)
   → Share .onion URLs in client reports
   → Screenshot content containing others' personal data
```

---

## 📊 Dark Web Monitoring Platforms for Enterprises

### Commercial Platforms (What I Recommend to Enterprise Clients)

```
For organisations that need continuous monitoring (not point-in-time):

Digital Shadows (ReliaQuest):
  → Monitors dark web forums, paste sites, criminal markets
  → Brand protection: typosquatting, lookalike domains
  → Exposed data: credentials, source code, financial data
  → Automated alerting when new exposure detected
  → Best for: mid-large enterprise with dedicated security team

Recorded Future:
  → Comprehensive threat intelligence + dark web monitoring
  → Threat actor tracking and attribution
  → API integration with SIEMs and security tools
  → Best for: organisations with sophisticated security operations

DarkOwl:
  → Largest dark web content index
  → API access to dark web data without direct browsing
  → Good for researchers and incident responders
  → Best for: security researchers and IR teams

Flare.io (mid-market):
  → Credential monitoring + dark web exposure
  → More accessible price point for SME
  → Good initial visibility without enterprise budget
```

### Free Monitoring Options

```
For organisations without commercial TI budget:

HIBP (credentials):
  → Free for personal use, enterprise plans available
  → Domain monitoring via API
  → notification service for new breach inclusion

SpiderFoot HX:
  → OSINT automation including dark web sources
  → Free community version available
  → Limited but useful for initial assessment

Google Alerts (surface web adjacent):
  → Alert: "[company name] breach"
  → Alert: "[company name] leaked"
  → Alert: "[company name] hack"
  → Catches news coverage of incidents

Shodan Alerts:
  → Monitors for new internet-exposed assets
  → Alerts when new ports/services appear on known IPs
  → Free tier includes basic monitoring
```

---

## 🧭 Key Takeaways

**1. Surface web dark web search tools provide most of the value without requiring Tor.**
Ahmia, OnionSearch, and paste site monitoring via Google dorking surface the vast majority of organisational exposure findings. Full Tor browser investigation is reserved for specific leads that require deeper verification — it is not the starting point.

**2. Screenshot search results, not content.**
Professional investigation evidence captures what was found and where — not the actual leaked data. A screenshot of "search for company.com returned 15 results on [platform]" with a brief description of each result is professional, legally defensible evidence. Downloading and storing actual breach data is not.

**3. Observe, document, report, delete — always in that order.**
The professional standard for dark web investigation is a one-way information flow. Intelligence flows from dark web to analyst to client report. Data never flows from dark web to analyst's storage. Completion of each engagement should include deletion of investigation VM snapshots.

---

## 🔗 References
- [Tor Project](https://www.torproject.org)
- [Tails OS](https://tails.boum.org)
- [Ahmia Dark Web Search](https://ahmia.fi)
- [OnionSearch GitHub](https://github.com/megadose/OnionSearch)
- [SANS Dark Web Investigations](https://www.sans.org/blog/dark-web-osint-tools/)

---
<div align="center">

*Part of [Dark Web From The Trenches](../README.md) — Real notes from 6+ years of enterprise security.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
