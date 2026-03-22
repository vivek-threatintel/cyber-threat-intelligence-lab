# 📘 Day 8 — Threat Intelligence Processing, Alert Generation, Structured Python Tool & MITRE Credential Access Understanding

---

# 🎯 Day Objective

The objective of Day 8 was to understand how real-world Threat Intelligence feeds are processed, how alerts are generated based on severity, and how security tools use structured logic to prioritize threats.

This day also focused on understanding MITRE ATT&CK Credential Access technique and how defenders detect credential attacks in real environments.

This lab simulated core SOC (Security Operations Center) pipeline logic using Python.

---

# 🧠 Concept 1 — Threat Feed Structure Understanding

Threat Intelligence feeds usually come in structured format containing indicators of compromise (IOCs).

Example structure used:

```python
threat_feed = [
    {
        "ioc": "evil-domain.com",
        "type": "domain",
        "severity": "high",
        "source": "OSINT"
    },
    {
        "ioc": "45.33.32.156",
        "type": "ip",
        "severity": "medium",
        "source": "ThreatFox"
    },
    {
        "ioc": "192.168.1.5",
        "type": "ip",
        "severity": "low",
        "source": "internal"
    }
]
```

This represents a list of threat indicators where each entry contains:

* IOC value (domain or IP)
* IOC type
* Threat severity
* Threat intelligence source

This format is used in real threat intelligence platforms such as:

* ThreatFox
* VirusTotal
* MISP
* OSINT feeds

---

# 💻 Python Code 1 — Threat Feed Filtering and Processing

## Objective

Filter high severity IOCs, count severity types, and separate internal vs external indicators.

## Code Implementation

```python
high_count = 0
medium_count = 0
low_count = 0

internal_iocs = []
external_iocs = []

for item in threat_feed:

    if item["severity"] == "high":
        print(item["ioc"])

    if item["severity"] == "high":
        high_count += 1

    elif item["severity"] == "medium":
        medium_count += 1

    elif item["severity"] == "low":
        low_count += 1

    if item["source"] == "internal":
        internal_iocs.append(item["ioc"])

    else:
        external_iocs.append(item["ioc"])
```

---

## Output

```
High Severity IOCs:
evil-domain.com

Severity Count:
High: 1
Medium: 1
Low: 1

Internal IOCs:
192.168.1.5

External IOCs:
evil-domain.com
45.33.32.156
```

---

## Concept Learned

Threat feeds must be filtered and categorized before alert generation.

---

# 💻 Python Code 2 — Alert Generation Logic

## Objective

Convert threat severity into security action.

Rules implemented:

```
HIGH → ALERT
MEDIUM → MONITOR
LOW → IGNORE
```

## Code

```python
for item in threat_feed:

    severity = item["severity"]
    ioc = item["ioc"]

    if severity == "high":
        action = "ALERT"

    elif severity == "medium":
        action = "MONITOR"

    else:
        action = "IGNORE"

    print(f"{ioc} -->> {action}")
```

---

## Output

```
evil-domain.com -->> ALERT
45.33.32.156 -->> MONITOR
192.168.1.5 -->> IGNORE
```

---

## Concept Learned

Security tools prioritize threats based on severity.

This logic is used in:

* SIEM alert engines
* Threat intelligence platforms
* SOC monitoring tools

---

# 💻 Python Code 3 — Structured Security Tool Using Functions

## Objective

Convert script into modular, structured security tool.

## Functions Created

### Filter Function

```python
def filter_high_severity(feed):

    high_list = []

    for item in feed:

        if item["severity"] == "high":
            high_list.append(item)

    return high_list
```

---

### Alert Generation Function

```python
def generate_alert(severity):

    if severity == "high":
        return "ALERT"

    elif severity == "medium":
        return "MONITOR"

    else:
        return "IGNORE"
```

---

### Summary Output Function

```python
def print_summary(feed):

    for item in feed:

        ioc = item["ioc"]
        severity = item["severity"]

        action = generate_alert(severity)

        print(f"{ioc} -->> {action}")
```

---

### Execution

```python
print_summary(threat_feed)
```

---

## Output

```
evil-domain.com -->> ALERT
45.33.32.156 -->> MONITOR
192.168.1.5 -->> IGNORE
```

---

# 🧠 Concept Learned — Structured Security Tool Design

Real security tools use modular functions for:

* IOC filtering
* Alert generation
* Output reporting

This improves maintainability and scalability.

---

# 🧠 Concept 2 — Alert Logic Understanding

Security systems use severity levels to determine response priority.

Example mapping:

| Severity | Action           |
| -------- | ---------------- |
| High     | Immediate alert  |
| Medium   | Monitor activity |
| Low      | Ignore or log    |

This helps SOC analysts prioritize investigation.

---

# 🧠 Concept 3 — MITRE ATT&CK Credential Access Understanding

MITRE Technique studied:

Brute Force (T1110)

---

## How attacker uses it

Attackers attempt multiple password combinations to gain access to user accounts.

Methods include:

* Password guessing
* Password spraying
* Credential stuffing

Goal is to obtain valid credentials.

---

## How defender detects it

Detection indicators include:

* Multiple failed login attempts
* Sudden successful login after failures
* Login from suspicious IP addresses
* Login attempts at unusual times

Detection sources include:

* Windows Event Logs
* SIEM alerts
* EDR telemetry

---

# 🌐 Networking Investigation Concept Learned

If system connects to malicious IP, logs will show:

* Firewall connection logs
* DNS query logs
* SIEM network telemetry

Defender should check:

* Which process initiated connection
* Frequency of connection
* IP reputation
* Data transfer activity

---

# 🧠 SOC Pipeline Understanding

Day 8 simulated real SOC pipeline:

```
Threat Feed Input
↓
IOC Filtering
↓
Severity Classification
↓
Alert Generation
↓
SOC Investigation
```

---

# 🧠 Skills Developed

Python Skills:

* List and dictionary handling
* Conditional logic
* Function creation
* Modular code design

Security Skills:

* IOC processing
* Threat severity classification
* Alert generation logic
* MITRE ATT&CK technique understanding
* SOC pipeline simulation

---

# 🎯 Final Learning Outcome

Day 8 provided hands-on understanding of how threat intelligence feeds are processed and converted into actionable alerts using structured Python logic and security concepts aligned with real SOC operations.

---

# ✅ Day 8 Status: Completed Successfully

---
