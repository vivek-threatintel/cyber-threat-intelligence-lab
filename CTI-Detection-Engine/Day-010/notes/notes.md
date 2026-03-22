# Day 10 — IOC Enrichment, Risk Classification, and Structured SOC Pipeline

## Objective

The goal of Day 10 was to understand how raw Indicators of Compromise (IOCs) are enriched with threat intelligence data, classified based on risk, and processed using structured Python functions to simulate a real SOC (Security Operations Center) pipeline.

This exercise reflects how SOC analysts convert raw indicators into actionable threat intelligence.

---

# Part 1 — Understanding IOC Base Data

## What is an IOC?

IOC (Indicator of Compromise) is a suspicious artifact that may indicate a security breach.

Examples include:

* IP address (e.g., 45.33.32.156)
* Domain name (e.g., evil-domain.com)
* File hash
* URL

IOC alone does not provide enough context to determine whether it is malicious or safe.

Example raw IOC list:

```python
iocs = [
    {"value": "8.8.8.8", "type": "ip"},
    {"value": "45.33.32.156", "type": "ip"},
    {"value": "evil-domain.com", "type": "domain"},
    {"value": "192.168.1.10", "type": "ip"}
]
```

This represents raw detected indicators without threat intelligence.

---

# Part 2 — Enrichment Data (Threat Intelligence Simulation)

Enrichment adds contextual intelligence such as:

* Country origin
* Reputation (malicious, benign, safe, unknown)

Example enrichment database:

```python
enrichment = {
    "8.8.8.8": {"country": "US", "reputation": "benign"},
    "45.33.32.156": {"country": "RU", "reputation": "malicious"},
    "evil-domain.com": {"country": "Unknown", "reputation": "malicious"},
    "192.168.1.10": {"country": "Internal", "reputation": "safe"}
}
```

This simulates external threat intelligence feeds such as:

* VirusTotal
* AbuseIPDB
* ThreatFox
* AlienVault OTX

---

# Part 3 — IOC Enrichment Process

## Purpose

To merge raw IOC data with enrichment intelligence.

Without enrichment:

```
IOC: 45.33.32.156
```

With enrichment:

```
IOC: 45.33.32.156
Country: RU
Reputation: malicious
```

This makes the IOC actionable.

---

## Enrichment Function

```python
def enrich_ioc(iocs, enrichment):

    enriched_list = []

    for item in iocs:

        value = item["value"]
        type_ = item["type"]

        country = enrichment[value]["country"]
        reputation = enrichment[value]["reputation"]

        merged = {
            "value": value,
            "type": type_,
            "country": country,
            "reputation": reputation
        }

        enriched_list.append(merged)

    return enriched_list
```

This function:

* Reads IOC list
* Looks up enrichment data
* Creates a merged enriched IOC list

---

# Part 4 — Risk Classification Logic

## Purpose

To assign risk levels based on reputation.

Risk classification rules:

| Reputation | Risk Level |
| ---------- | ---------- |
| malicious  | HIGH       |
| benign     | LOW        |
| safe       | LOW        |
| unknown    | MEDIUM     |

---

## Risk Classification Function

```python
def classify_risk(reputation):

    if reputation == "malicious":
        return "HIGH"

    elif reputation == "benign" or reputation == "safe":
        return "LOW"

    else:
        return "MEDIUM"
```

This simulates real SOC threat prioritization logic.

---

# Part 5 — Report Generation Function

## Purpose

To display enriched IOC data and risk classification.

```python
def print_report(enriched_iocs):

    print("\nIOC REPORT\n")

    for item in enriched_iocs:

        value = item["value"]
        reputation = item["reputation"]

        risk = classify_risk(reputation)

        print("IOC:", value)
        print("Country:", item["country"])
        print("Reputation:", reputation)
        print("Risk Level:", risk)
        print()
```

---

# Part 6 — Main Execution Flow

```python
enriched_iocs = enrich_ioc(iocs, enrichment)

print_report(enriched_iocs)
```

---

# Final Output

```
IOC REPORT

IOC: 8.8.8.8
Country: US
Reputation: benign
Risk Level: LOW

IOC: 45.33.32.156
Country: RU
Reputation: malicious
Risk Level: HIGH

IOC: evil-domain.com
Country: Unknown
Reputation: malicious
Risk Level: HIGH

IOC: 192.168.1.10
Country: Internal
Reputation: safe
Risk Level: LOW
```

---

# Part 7 — Why Enrichment is Important (CTI Analyst Thinking)

Enrichment is critical because raw IOC data lacks context.

Without enrichment:

* Analyst cannot determine if IOC is malicious
* No threat prioritization possible
* Investigation becomes slow and inefficient

With enrichment:

* Threat reputation becomes clear
* Risk classification becomes possible
* Faster incident response
* Better threat prioritization

Enrichment converts raw data into actionable intelligence.

---

# Part 8 — SOC and SIEM Workflow Understanding

Real SOC pipeline works as follows:

```
Logs → IOC Detection → Enrichment → Risk Classification → Alert → Analyst Investigation
```

This Python pipeline simulates:

* Threat intelligence lookup
* IOC enrichment
* Risk classification
* SOC reporting

---

# Part 9 — Analyst Scenario Thinking (VPN Login Anomaly Case)

Scenario analyzed:

Multiple logins from different countries within 10 minutes using VPN.

SOC interpretation:

* Impossible travel anomaly detected
* Potential credential compromise
* Threat investigation required

SOC actions include:

* Checking IP reputation
* Monitoring login behavior
* Resetting credentials if compromised
* Blocking malicious IPs

Mapped MITRE Technique:

```
T1078 — Valid Accounts
```

---

# Part 10 — Key Concepts Learned

Technical skills gained:

* Working with list of dictionaries
* Working with nested dictionaries
* IOC enrichment process
* Risk classification logic
* Function-based modular Python design
* SOC threat analysis thinking
* Threat intelligence processing logic

Security concepts gained:

* IOC lifecycle
* Enrichment importance
* Threat prioritization
* SOC investigation workflow
* SIEM vs Analyst roles

---

# Part 11 — Real SOC Tool Simulation Achieved

This Python project successfully simulated core SOC processes:

* Threat intelligence lookup
* IOC enrichment
* Risk classification
* Threat reporting pipeline

This reflects real-world SOC automation logic.

---

# Day 10 Summary

Today’s work successfully implemented a structured IOC enrichment and risk classification pipeline using Python functions, simulating real-world SOC and CTI workflows. The exercise demonstrated how raw threat indicators become actionable intelligence through enrichment and risk analysis, enabling effective security decision-making.

---
