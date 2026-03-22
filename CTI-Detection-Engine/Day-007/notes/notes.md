# 📘 Day 7 — Security Event Pipeline, Risk Scoring & SOC Detection Logic Design

---

## 🔹 Day 7 Objective

The main objective of Day 7 was to understand how real Security Operation Center (SOC) monitoring pipelines work by simulating security event processing using Python.

The focus areas were:

* Security event detection logic
* Risk scoring model design
* Pipeline structure development
* Attack pattern thinking using network behavior
* Converting raw detection logic into structured tool-like code

Day 7 mainly focused on how multiple security signals are combined to detect suspicious behavior and assign risk levels.

---

# 💻 Python Practical Work Completed

---

# ✅ Code 1 — Mini Security Detection Pipeline (day7.py Basic Version)

---

## 🔹 Goal

Detect suspicious activity based on behavior rules:

* Failed logins > 10 → Suspicious
* High data transfer → Suspicious

---

## 🔹 Security Event Data Used

```
events = [
 {"ip": "8.8.8.8", "failed_logins": 2, "data_transfer": "low"},
 {"ip": "45.33.32.1", "failed_logins": 15, "data_transfer": "high"},
 {"ip": "192.168.1.10", "failed_logins": 1, "data_transfer": "low"},
 {"ip": "23.21.11.90", "failed_logins": 20, "data_transfer": "high"}
]
```

---

## 🔹 Detection Logic

### Rule 1 — Failed Login Spike

Possible Indicators:

* Brute force attack
* Password guessing
* Credential spraying

---

### Rule 2 — High Data Transfer

Possible Indicators:

* Data exfiltration
* Malware data upload
* Unauthorized backup copy

---

## 🔹 Output Example

```
Suspicious IPs:
45.33.32.1
23.21.11.90
```

---

# 🛡 SOC Concept Learned

SOC systems monitor behavior, not just IP reputation.

---

# ✅ Code 2 — Risk Score Model (day7_risk.py)

---

## 🔹 Goal

Convert multiple suspicious signals into a numerical risk score.

---

## 🔹 Risk Scoring Rules

| Condition          | Score |
| ------------------ | ----- |
| Failed Logins > 10 | +5    |
| High Data Transfer | +5    |

---

## 🔹 Risk Level Mapping

| Score | Level  |
| ----- | ------ |
| 0     | Low    |
| 5     | Medium |
| 10    | High   |

---

## 🔹 Output Example

```
45.33.32.1 → Score: 10 → Level: HIGH
```

---

# 🧠 Security Concept Learned

Real SOC tools use risk scoring instead of simple yes/no alerts.

---

# ✅ Code 3 — Structured Security Pipeline (Final Clean Version)

---

## 🔹 Goal

Convert detection logic into modular tool-like structure.

---

## 🔹 Structure Used

```
Event Data
↓
Detection Function
↓
Risk Score Function
↓
Risk Level Function
↓
Output Function
↓
Main Execution
```

---

## 🔹 Functions Created

---

### ✔ Detection Function

Detect suspicious behavior patterns.

---

### ✔ Risk Score Function

Convert suspicious signals into numeric score.

---

### ✔ Risk Level Function

Convert score into severity category.

---

### ✔ Output Function

Standardized reporting format.

---

# 🌐 Networking + Attack Pattern Thinking

---

## Scenario Pattern Studied

```
Multiple Failed Logins
↓
Sudden Login Success
↓
Large Data Transfer
```

---

## Possible Attack Chain

Brute Force → Account Takeover → Data Exfiltration

---

# 🧠 CTI + SOC Thinking Built

---

### Attack Stage Mapping Learned

| Behavior       | Possible Attack Stage |
| -------------- | --------------------- |
| Login Failures | Credential Attack     |
| Sudden Success | Account Compromise    |
| Large Transfer | Data Exfiltration     |

---

# ⭐ Technical Skills Developed

---

✔ Python structured coding
✔ Function-based logic design
✔ Risk scoring model creation
✔ Security event data processing
✔ Detection rule simulation
✔ SOC pipeline thinking

---

# ⭐ Security Analyst Mindset Developed

---

✔ Behavior-based detection thinking
✔ Multi-signal correlation logic
✔ Risk prioritization awareness
✔ Attack chain understanding
✔ Network anomaly detection thinking

---

# 🚀 Real World SOC Tool Connection

Real SOC tools perform similar logic using:

* SIEM correlation rules
* UEBA behavior scoring
* Threat intelligence enrichment
* Automated alert prioritization

Day 7 simulated base logic of real SOC detection pipelines.

---

# 📌 Personal Learning Reflection

Day 7 helped in understanding how raw security events can be converted into actionable risk intelligence. It also helped build understanding of detection pipelines, which are core components of real SOC monitoring systems.

---

# ⭐ Overall Day 7 Learning Outcome

Day 7 marked the transition from simple scripting to security pipeline thinking, combining detection logic, scoring models, and structured programming design.

---
