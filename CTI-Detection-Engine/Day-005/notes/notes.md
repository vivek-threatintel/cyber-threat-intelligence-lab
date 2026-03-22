# 📘 Day 5 — Python Tool Building + IOC Processing + Security Tool Mindset

---

## 🔹 Overview

Day 5 focused on converting Python scripts into tool-like utilities.
The main objective was to move from static scripts to interactive tools that can process user input, classify security indicators, and produce clean, readable output.

Along with Python tool development, the focus was also on building a security mindset by understanding how real security tools process and classify Indicators of Compromise (IOC).

---

# 💻 Python Tasks Completed

---

## ✅ Task 1 — Mini IOC Checker (Static Version)

### Goal

* Detect IP vs Domain
* Detect Private vs Public IP
* Assign simple risk level

### Logic Used

| IOC Type   | Classification |
| ---------- | -------------- |
| Private IP | LOW Risk       |
| Public IP  | MEDIUM Risk    |
| Domain     | HIGH Risk      |

---

### Example Input

```
["8.8.8.8", "192.168.1.1", "evil.com", "10.0.0.5"]
```

---

### Example Output

```
8.8.8.8 → PUBLIC → MEDIUM
192.168.1.1 → PRIVATE → LOW
evil.com → DOMAIN → HIGH
10.0.0.5 → PRIVATE → LOW
```

---

### Key Concepts Learned

* IP detection using string logic
* Private IP range checking
* Basic IOC risk modeling

---

## ✅ Task 2 — User Input Based IOC Tool

### Goal

Convert script into interactive tool.

### Features Added

* User input support
* Real-time classification
* Dynamic output

---

### Example Run

```
Enter IOC: evil.com
evil.com → DOMAIN → HIGH
```

---

### Key Concepts Learned

* Input handling using `input()`
* Real tool workflow simulation
* Interactive script design

---

## ✅ Task 3 — Tool Cleanup and Structure Improvement

### Goal

Make script look like real security tool.

---

### Improvements Added

#### ✔ Functions

Separated logic into:

* IP detection
* Private IP check
* IOC classification
* Validation

---

#### ✔ Input Validation

Handled:

* Empty input
* Whitespace input

---

#### ✔ Clean Output Formatting

Structured output like real tools.

---

### Example Final Output

```
=== IOC CHECKER TOOL ===

Enter IOC: 8.8.8.8

Result:
IOC  : 8.8.8.8
Type : PUBLIC
Risk : MEDIUM
```

---

# 🌐 Networking + Security Thinking

---

## IOC Processing Mindset

Real security tools do:

* IOC normalization
* IOC classification
* Risk scoring
* Threat enrichment

Day 5 simulated basic version of this workflow.

---

# 🛡 Security Concepts Reinforced

---

## Private IP Ranges

```
10.x.x.x
192.168.x.x
172.16 – 172.31
```

---

## Loopback Concept

```
127.0.0.1 → Local machine only
```

---

## Exposure Awareness

```
127.0.0.1 → Local only
192.168.x.x → LAN only
0.0.0.0 → All interfaces
```

---

# 🧠 CTI Awareness (Day 5 Supporting Theory)

---

## MITRE ATT&CK — Brute Force (T1110)

Brute force attacks attempt to gain unauthorized access by repeatedly trying password combinations.

### Defender Detection Indicators

* Multiple failed logins
* Repeated authentication attempts
* Login success after many failures
* Same IP login attempts across accounts

---

# ⭐ Key Learning Outcomes

---

## Technical Skills

* Python function design
* Input validation basics
* Clean output formatting
* Tool-style script structure

---

## Security Mindset

* IOC classification logic
* Risk scoring basics
* Detection thinking approach
* Pattern recognition awareness

---

# 📌 Real-World Connection

Real security tools perform similar workflows but use:

Threat Intelligence Feeds
Machine Learning Risk Models
Reputation Databases
Behavior Analytics

Day 5 focused on building the base logic behind such systems.

---

# 🚀 Future Improvements (Next Learning Steps)

* File based IOC scanning
* API based threat enrichment
* Regex based IOC validation
* Logging support
* CLI argument based tools

---

# ⭐ Personal Learning Reflection

Day 5 helped in understanding how raw security data can be converted into usable security intelligence using simple logic.
It also helped in understanding how real security tools are structured internally.

---
