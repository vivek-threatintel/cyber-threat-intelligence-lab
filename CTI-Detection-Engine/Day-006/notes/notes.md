# 📘 Day 6 — Threat Intelligence Processing, Alert Logic Design & Structured Python Security Tool Development

---

## 🔹 Day Objective

The main goal of Day 6 was to understand how real-world Cyber Threat Intelligence (CTI) data is processed before it is used in security tools such as SIEM, EDR, or SOC monitoring platforms.

The focus was divided into three major areas:

1. Processing Threat Feed Style Data
2. Building Rule-Based Alert Logic
3. Converting Raw Scripts into Structured Tool-Style Python Code

Along with coding, Day 6 also included networking anomaly thinking and basic attacker profiling concepts.

---

# 💻 Python Practical Work Completed (3 Codes)

---

# ✅ Code 1 — Threat Feed Data Processing (day6.py — Feed Processing Logic)

---

## 🔹 Task Goal

Simulate real CTI threat feed data and perform preprocessing operations such as filtering and data extraction.

---

## 🔹 Threat Feed Data Structure Used

The threat feed was hardcoded as structured JSON-like Python dictionaries:

```
feed = [
 {"ioc": "evil.com", "type": "domain", "severity": "high"},
 {"ioc": "8.8.8.8", "type": "ip", "severity": "medium"},
 {"ioc": "bad.ru", "type": "domain", "severity": "high"},
 {"ioc": "192.168.1.5", "type": "ip", "severity": "low"}
]
```

This simulates real threat intelligence feeds that contain:

* IOC value
* IOC type
* Threat severity

---

## 🔹 Operations Performed

### ✔ High Severity Filtering

Extract only high priority threats from feed.

Reason:
SOC teams prioritize high severity indicators first.

---

### ✔ Domain IOC Extraction

Extract only domain IOCs from filtered data.

Reason:
Domains are often used for:

* Phishing detection
* DNS blocking
* Web filtering
* Threat hunting

---

### ✔ High Severity Count

Count total high severity indicators.

Reason:
Used in SOC dashboards and threat trending metrics.

---

## 🔹 Output Example

```
High Severity IOCs:
evil.com
bad.ru

High Severity Domains:
evil.com
bad.ru

Total High Severity Count: 2
```

---

## 🔹 Security Concept Learned

This simulates real CTI preprocessing pipeline:

```
Raw Threat Feed → Filter → Categorize → Prioritize
```

---

# ✅ Code 2 — Alert Decision Logic (day6_alert.py — Severity → SOC Action Mapping)

---

## 🔹 Task Goal

Convert threat severity levels into SOC action decisions.

---

## 🔹 Alert Mapping Logic Implemented

| Severity | SOC Action |
| -------- | ---------- |
| High     | ALERT      |
| Medium   | WATCH      |
| Low      | IGNORE     |

---

## 🔹 Why This Matters

Real security tools do not only store threat data.
They convert threat data into actionable decisions.

---

## 🔹 Output Example

```
evil.com → ALERT
8.8.8.8 → WATCH
192.168.1.5 → IGNORE
```

---

## 🔹 Security Concept Learned

Security pipeline thinking:

```
Threat Data → Risk Score → SOC Action → Alert Workflow
```

---

# ✅ Code 3 — Structured Tool Design (day6 Structured Version)

---

## 🔹 Task Goal

Convert raw scripts into clean, modular, professional tool-style Python code.

---

## 🔹 Structure Implemented

```
Feed Data
↓
Filter Function
↓
Alert Mapping Function
↓
Clean main()
```

---

## 🔹 Functions Implemented

---

### ✔ Feed Filter Function

Purpose:
Extract only high severity threat indicators.

Security Benefit:
Focus on high priority threats first.

---

### ✔ Alert Assign Function

Purpose:
Convert severity into SOC action level.

Security Benefit:
Automates alert decision workflow.

---

### ✔ Clean main() Function

Purpose:
Controls full program execution flow.

Development Benefit:
Improves readability, scalability, debugging ability.

---

## 🔹 Output Example

```
=== THREAT ALERT OUTPUT ===

evil.com → ALERT
bad.ru → ALERT
```

---

# 🌐 Networking & Security Thinking (Day 6 Theory Work)

---

# 🔹 DNS Behaviour Analysis Thinking

---

## Normal DNS Behaviour

* User browsing driven DNS queries
* Random domain query timing
* Multiple legitimate domain resolutions
* Burst DNS queries during browsing

---

## Suspicious DNS Behaviour Indicators

* Repeated DNS queries to same domain
* Fixed interval DNS queries
* Random or encoded domain names
* DNS activity during system idle time

---

# 🔹 Why Attackers Abuse DNS

Attackers use DNS for:

* Command & Control (C2 communication)
* Malware beaconing
* Data exfiltration (DNS tunneling)

---

# 🧠 CTI Learning — Attacker Profiling Introduction

---

## 🔹 Script Kiddie

Characteristics:

* Low technical skill
* Uses publicly available tools
* Random targets
* No deep exploit understanding
* High noise attack behaviour

---

## 🔹 Organized Threat Actor

Characteristics:

* High technical skill
* Uses custom or modified tools
* Performs targeted attacks
* Focuses on stealth and persistence
* Long-term attack campaigns

---

# ⭐ Technical Skills Developed (Day 6)

---

✔ Python list & dictionary data processing
✔ Function-based code design
✔ Security rule mapping logic
✔ Threat feed preprocessing concepts
✔ SOC alert logic simulation
✔ Modular tool development structure

---

# ⭐ Security Analyst Mindset Built

---

✔ Threat prioritization thinking
✔ IOC classification logic
✔ CTI feed understanding
✔ Detection pipeline awareness
✔ Pattern-based anomaly thinking

---

# 🚀 Real World Security Tool Connection

Real SOC tools perform similar logic but at larger scale using:

* Threat Intelligence APIs
* Machine Learning Risk Scoring
* Reputation Databases
* Behaviour Analytics
* Automated Alerting Systems

Day 6 focused on building the foundational logic behind these systems.

---

# 📌 Personal Learning Reflection

Day 6 helped build practical understanding of how raw threat intelligence data is processed, filtered, and converted into actionable alerts. It also helped improve structured programming skills which are required for building real-world security automation tools.

---
