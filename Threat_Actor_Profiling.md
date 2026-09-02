# Threat Actor Profiling — Enterprise Security Field Notes

> **Author:** Dheeraj Kumar Jayaswal — Senior Penetration Tester | 6+ Years Enterprise AppSec
>
> **Category:** Threat Intelligence — Adversary Profiling & Tracking
>
> **Context:** Threat actor profiling is the practice of building structured knowledge about adversaries — who they are, who they target, what techniques they use, and what their objectives are. In professional penetration testing, threat actor profiles inform what I should test. If a financial services client in India faces targeted attacks from APT groups that specifically exploit web application vulnerabilities, then web application testing is not just a compliance exercise — it directly tests the access path their real-world adversaries use.

---

## 📖 The Diamond Model of Intrusion Analysis

```
The Diamond Model provides a structured framework for understanding
and relating threat intelligence:

         Adversary
             │
    ─────────┼─────────
    │                  │
Capability          Infrastructure
    │                  │
    ─────────┼─────────
             │
           Victim

Four core features:
  Adversary:      Who is conducting the attack?
                  (Nation-state APT, financially motivated, hacktivist)
  
  Capability:     What tools and techniques are they using?
                  (Malware families, exploitation frameworks, TTPs)
  
  Infrastructure: What resources do they use?
                  (C2 servers, domains, email infrastructure, VPNs)
  
  Victim:         Who are they targeting?
                  (Industry vertical, geography, organisation size, technology)

Enterprise application:
  Understanding the diamond for threats relevant to your client
  allows you to test the specific capability-victim relationship
  that applies to them — not a generic vulnerability list.
```

---

## 🎯 Threat Actor Categories Relevant to Enterprise Clients

### Nation-State Advanced Persistent Threats (APTs)

```
APTs targeting sectors commonly tested in Indian enterprise engagements:

Financial Sector:
  APT38 (Lazarus Group financial unit, attributed to DPRK):
    Primary Motivation: Financial theft
    Known Targets: Banks, cryptocurrency exchanges, payment systems
    Initial Access: T1190 (web exploits), T1566 (spearphishing)
    Common Techniques: SWIFT system compromise, ATM malware
    Known Tools: BLINDINGCAN, COPPERHEDGE, TAINTEDSCRIBE
    ATT&CK Group ID: G0082

  APT41 (Winnti, attributed to China):
    Primary Motivation: Espionage + financial crime (dual mandate)
    Known Targets: Healthcare, financial, technology, gaming
    Initial Access: T1190 (supply chain, VPN exploits), T1078
    Common Techniques: Supply chain compromise, living-off-the-land
    ATT&CK Group ID: G0096

Technology/IT Sector:
  Lazarus Group (G0032):
    Motivation: Financial + espionage
    Known for: WannaCry attribution, financial heists, IT sector targeting
    Initial Access: T1566 (spearphishing), T1195 (supply chain)

Healthcare:
  Documented campaigns by Cl0p, LockBit affiliates
  ALPHV/BlackCat active in healthcare sector
```

### Financially Motivated Groups

```
FIN7 (Carbanak):
  ATT&CK Group ID: G0046
  Motivation: Financial — estimated $1+ billion stolen
  Primary targets: Restaurant, retail, hospitality + financial services
  Initial Access: T1566 (highly sophisticated spearphishing)
  Known Tools: CARBANAK malware, Cobalt Strike
  Relevant to: Retail, hospitality, financial sector clients

Cl0p (TA505):
  ATT&CK Group ID: G0092
  Motivation: Financial — ransomware + data extortion
  Primary targets: Healthcare, financial, legal, manufacturing
  Known for: MOVEit, GoAnywhere zero-day exploitation
  Initial Access: T1190 (zero-day web application exploitation)
  Relevant to: Any organisation using enterprise file transfer software
```

---

## 🔧 Building a Threat Actor Profile for a Client Engagement

```python
#!/usr/bin/env python3
"""
Build a structured threat actor profile relevant to a specific client
Uses MITRE ATT&CK and public threat intelligence sources
"""

# ATT&CK groups data (subset — full data at attack.mitre.org/groups/)
THREAT_ACTORS = {
    "APT38": {
        "att_ck_id": "G0082",
        "also_known_as": ["Lazarus Group Financial", "BeagleBoyz"],
        "attributed_to": "DPRK (North Korea)",
        "motivation": "Financial theft",
        "primary_sectors": ["financial", "cryptocurrency", "banking"],
        "primary_regions": ["worldwide", "asia_pacific"],
        "initial_access_ttps": ["T1190", "T1566.002", "T1195.002"],
        "key_techniques": ["T1204", "T1059", "T1105", "T1005"],
        "references": [
            "https://attack.mitre.org/groups/G0082/",
            "https://www.cisa.gov/uscert/ncas/alerts/AA20-239A"
        ]
    },
    "FIN7": {
        "att_ck_id": "G0046",
        "also_known_as": ["Carbanak", "GOLD NIAGARA"],
        "attributed_to": "Russia-nexus, financially motivated",
        "motivation": "Financial theft",
        "primary_sectors": ["retail", "restaurant", "hospitality", "financial"],
        "primary_regions": ["north_america", "europe", "asia_pacific"],
        "initial_access_ttps": ["T1566.001", "T1566.002", "T1190"],
        "key_techniques": ["T1055", "T1059.001", "T1078", "T1071"],
        "references": [
            "https://attack.mitre.org/groups/G0046/"
        ]
    },
    "CL0P": {
        "att_ck_id": "G0092",
        "also_known_as": ["TA505", "Cl0p", "GOLD TAHOE"],
        "attributed_to": "Russia-nexus, financially motivated",
        "motivation": "Ransomware + data extortion",
        "primary_sectors": ["healthcare", "financial", "legal", "manufacturing"],
        "primary_regions": ["worldwide"],
        "initial_access_ttps": ["T1190", "T1195.002"],
        "key_techniques": ["T1486", "T1537", "T1567"],
        "references": [
            "https://attack.mitre.org/groups/G0092/",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"
        ]
    }
}

def get_relevant_actors(sector: str, region: str = "asia_pacific") -> list:
    """Get threat actors relevant to a specific sector and region"""
    relevant = []
    for name, profile in THREAT_ACTORS.items():
        sector_match = sector.lower() in profile.get("primary_sectors", [])
        region_match = (
            region.lower() in profile.get("primary_regions", []) or
            "worldwide" in profile.get("primary_regions", [])
        )
        if sector_match or region_match:
            relevant.append({"name": name, **profile})
    return relevant

def generate_threat_context(sector: str) -> str:
    """Generate threat intelligence context for a client engagement"""
    actors = get_relevant_actors(sector)

    lines = [
        f"Threat Actor Context — {sector.title()} Sector",
        "=" * 50,
        f"Based on documented threat intelligence, the following adversaries",
        f"have been observed targeting organisations in the {sector} sector:",
        ""
    ]

    for actor in actors:
        lines.extend([
            f"Threat Actor: {actor['name']} ({actor['att_ck_id']})",
            f"  Motivation: {actor['motivation']}",
            f"  Initial Access: {', '.join(actor['initial_access_ttps'])}",
            f"  Recommendation: Test for {', '.join(actor['initial_access_ttps'][:2])}",
            f"  Reference: {actor['references'][0]}",
            ""
        ])

    return "\n".join(lines)

if __name__ == "__main__":
    import sys
    sector = sys.argv[1] if len(sys.argv) > 1 else "financial"
    print(generate_threat_context(sector))
```

---

## 📋 Incorporating Threat Actor Profiles in Pentest Reports

### Executive Summary Framing

```
Instead of:
  "We conducted a web application penetration test and found
   5 Critical, 8 High, and 12 Medium severity vulnerabilities."

With threat actor context:
  "This engagement was conducted against the threat model of
   adversaries documented to target Indian financial services
   organisations. The two most active threat actors in this
   sector are APT38 (G0082) and FIN7 (G0046), both of which
   primarily use web application exploitation (T1190) and
   credential-based attacks (T1078) for initial access.

   5 Critical vulnerabilities were identified, including 3 that
   directly correspond to techniques used by APT38 in documented
   attacks against financial institutions.

   Key finding: The SQL injection vulnerability (Finding #1)
   and the missing authentication on the admin API (Finding #3)
   represent exactly the initial access path documented in APT38
   operations targeting SWIFT-connected financial systems."

This framing:
  → Connects findings to the organisation's ACTUAL threat landscape
  → Creates urgency appropriate to the real-world risk
  → Gives the board context for why security investment is justified
  → Demonstrates the tester's understanding beyond just "finding bugs"
```

---

## 🧭 Key Takeaways

**1. Know which adversaries are relevant before you start testing.**
Five minutes on MITRE ATT&CK filtering groups by sector and geography tells you who is most likely to attack your client. Testing their documented initial access techniques specifically makes the engagement threat-realistic.

**2. Threat actor context escalates finding urgency appropriately.**
"SQL injection" without context is a Critical finding. "SQL injection matching T1190 — the primary initial access technique of APT38 targeting financial institutions in this region" is an emergency action item. The context is not exaggeration — it is accurate risk communication.

**3. The Diamond Model connects intelligence to defence gaps.**
By understanding the Adversary-Capability-Infrastructure-Victim relationship, you can identify which capabilities an adversary would use against this specific victim, test for those capabilities specifically, and recommend defences targeted at disrupting that specific relationship.

---

## 🔗 References
- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [Diamond Model of Intrusion Analysis](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf)
- [CISA Threat Advisories](https://www.cisa.gov/resources-tools/resources/advisories)
- [MANDIANT APT Groups](https://www.mandiant.com/resources/insights/apt-groups)

---
<div align="center">

*Part of [Dark Web From The Trenches](../README.md) — Real notes from 6+ years of enterprise security.*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dheeraj%20Kumar%20Jayaswal-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/dheerajkumarjayaswal)

</div>
