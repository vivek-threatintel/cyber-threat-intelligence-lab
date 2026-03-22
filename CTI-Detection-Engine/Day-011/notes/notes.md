# Day 11 — Threat Feed Correlation, Confidence Scoring, IOC Enrichment, and SOC Response Thinking

## Objective

The objective of Day 11 was to simulate a real SOC threat intelligence workflow using Python and analyst thinking. The focus was on:

* Combining multiple threat feeds
* Counting IOC occurrences across sources
* Assigning confidence scores based on source frequency
* Enriching IOC data with intelligence
* Understanding SOC response when internal system communicates with malicious IOC
* Developing CTI confidence evaluation mindset

This day closely simulated how real SIEM and Threat Intelligence Platforms correlate and evaluate threats.

---

# Python Task 1 — Combining Threat Feeds and Counting IOC Occurrences

## Goal

Combine multiple threat intelligence feeds and count how many times each IOC appears.

Threat feeds used:

```
feed1:
evil.com → ThreatFox
45.33.32.156 → AlienVault
8.8.8.8 → OSINT

feed2:
evil.com → VirusTotal
23.21.11.90 → ThreatFox
8.8.8.8 → Internal
```

These feeds simulate multiple independent threat intelligence sources.

---

## Logical Process

Step 1: Combine both feeds into a single dataset.

Purpose:
SOC systems aggregate feeds from multiple sources into one intelligence database.

Step 2: Extract IOC values from each feed entry.

Example:

```
item = {"ioc": "evil.com", "source": "ThreatFox"}
ioc = evil.com
```

Step 3: Count how many times each IOC appears.

Resulting internal structure:

```
evil.com → 2 sources
8.8.8.8 → 2 sources
45.33.32.156 → 1 source
23.21.11.90 → 1 source
```

This simulates IOC correlation logic used in SIEM and Threat Intelligence Platforms.

---

## Actual Output

```
IOC COUNT:

evil.com → 2 sources
45.33.32.156 → 1 sources
8.8.8.8 → 2 sources
23.21.11.90 → 1 sources
```

---

## What this simulates in real SOC

This simulates threat intelligence correlation.

If multiple feeds report the same IOC, confidence increases that it is malicious infrastructure.

---

# Python Task 2 — Confidence Score Assignment Based on Source Count

## Goal

Assign confidence level based on number of threat intelligence sources.

Confidence logic implemented:

```
1 source → LOW confidence
2 sources → MEDIUM confidence
3+ sources → HIGH confidence
```

---

## Logical Thinking Process

IOC count dictionary used:

```
IOC → number of sources reporting it
```

Example:

```
evil.com → 2 → MEDIUM confidence
45.33.32.156 → 1 → LOW confidence
```

---

## Actual Output

```
RISK OUTPUT:

evil.com -->> Score: 2 -->> Level: MEDIUM
45.33.32.156 -->> Score: 1 -->> Level: LOW
8.8.8.8 -->> Score: 2 -->> Level: MEDIUM
23.21.11.90 -->> Score: 1 -->> Level: LOW
```

---

## Real SOC significance

Confidence score helps SOC analyst decide response priority.

Example:

LOW confidence → Monitor
MEDIUM confidence → Investigate
HIGH confidence → Alert and block

This prevents false positives and ensures proper threat handling.

---

# Python Task 3 — IOC Enrichment with Threat Intelligence Data

## Goal

Enrich IOC data with additional intelligence such as:

* country
* reputation

Enrichment database used:

```
evil.com → Unknown → malicious
45.33.32.156 → RU → malicious
8.8.8.8 → US → benign
```

---

## Logical Process

Step 1: Extract IOC from threat feed.

Step 2: Search enrichment database.

Step 3: Merge enrichment intelligence.

Step 4: Print enriched threat intelligence.

---

## Actual Output

```
IOC: evil.com
Country: Unknown
Reputation: malicious

IOC: 45.33.32.156
Country: RU
Reputation: malicious

IOC: 8.8.8.8
Country: US
Reputation: benign
```

---

## Real SOC significance

This simulates threat intelligence enrichment performed by:

* SIEM
* EDR
* Threat Intelligence Platforms

Enrichment converts raw IOC into actionable intelligence.

Without enrichment, SOC analyst cannot determine threat severity.

---

# CTI Task — Analyst Logic: Why Multiple Source IOC is More Trustworthy

## Understanding Confidence in Threat Intelligence

IOC reported by multiple independent sources is more reliable because it confirms malicious activity across multiple intelligence providers.

Example:

```
evil.com reported by:
ThreatFox
VirusTotal
```

This increases confidence that it is malicious infrastructure.

---

## Single Source IOC May Be Unreliable

IOC reported by only one source may be unreliable due to:

* false positive detection
* research or testing infrastructure
* outdated intelligence

Example:

```
45.33.32.156 reported by only one source
```

SOC analyst should monitor instead of blocking immediately.

---

## False Positive vs Confirmed Threat

False Positive:

IOC reported by only one source
Confidence LOW

Confirmed Threat:

IOC reported by multiple sources
Confidence MEDIUM or HIGH

SOC analyst uses confidence score to differentiate between them.

---

# Networking Task — SOC Response When Internal System Connects to Malicious IOC

## Scenario

Internal system communicates with HIGH confidence malicious IOC.

This indicates possible system compromise.

---

## SOC Analyst Response Steps

Step 1 — Verify alert

SOC analyst confirms IOC reputation and system identity.

Step 2 — Isolate affected system

Isolation prevents attacker from:

* spreading malware
* stealing data
* accessing internal systems

Step 3 — Block malicious IOC

IOC blocked in firewall, DNS filtering, and EDR systems.

Step 4 — Investigate logs

SOC analyst checks:

* firewall logs
* DNS logs
* authentication logs
* EDR logs

Step 5 — Remediation

If compromise confirmed, malware removed and system secured.

---

# Key Concepts Learned Today

Threat Feed Aggregation
IOC Correlation
Dictionary-based IOC counting
Threat Intelligence Enrichment
Confidence Score Assignment
False Positive vs Confirmed Threat Analysis
SOC Incident Response Thinking

---

# Real-World Tools That Use Same Logic

SIEM platforms
Splunk
Microsoft Sentinel
QRadar
VirusTotal
AlienVault OTX
ThreatFox
EDR platforms

---

# Final Summary

Today simulated real SOC threat intelligence workflow using Python automation and analyst logic.

Threat feeds were combined, correlated, enriched, and assigned confidence levels. IOC confidence scoring and enrichment simulated real SIEM intelligence pipelines.

Networking and CTI thinking tasks helped develop real analyst mindset for detecting, validating, and responding to confirmed malicious infrastructure.

This builds strong foundation for SOC analysis, threat intelligence, and security automation.

---
