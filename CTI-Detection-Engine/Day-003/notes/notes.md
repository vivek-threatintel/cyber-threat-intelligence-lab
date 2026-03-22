# 📘 Day 3 — Practical Work Log (Python + Networking + Security Foundations)

---

## 🔹 Objective

Day 3 goal was to move from basic Python scripting to real-world data interaction, basic network observation, and introductory security framework understanding.

Focus Areas:

* API Data Handling
* JSON Parsing
* Data Processing (List → Dictionary → Frequency Count)
* Modular Python Code Design
* Basic Network Traffic Observation (Wireshark)
* MITRE ATT&CK Phishing Awareness

---

# 🐍 Section 1 — Python API Implementation (Hands-On)

---

## 🔹 Environment Setup

Virtual environment used:

```
python -m venv venv
source venv/bin/activate
pip install requests
```

Purpose:

* Dependency isolation
* Clean project environment

---

## 🔹 API Used

Random User Public API:

```
https://randomuser.me/api/?results=5
```

Reason:

* Free
* JSON structured
* Nested data (good for learning parsing)

---

## 🔹 Final Working Code (Day 3 Functional Design)

```python
import requests


def get_data():
    url = "https://randomuser.me/api/?results=5"
    response = requests.get(url)
    return response.json()


def get_countries(data):
    countries = []

    for user in data["results"]:
        country = user["location"]["country"]
        countries.append(country)

    return countries


def count_countries(country_list):
    freq = {}

    for c in country_list:
        if c in freq:
            freq[c] += 1
        else:
            freq[c] = 1

    return freq


def main():
    data = get_data()
    countries = get_countries(data)

    print("Raw Country List:", countries)

    result = count_countries(countries)

    print("\nCountry Frequency Count:")
    for k, v in result.items():
        print(k, v)


main()
```

---

## 🔹 Sample Real Output (Observed)

```
Raw Country List: ['France', 'Norway', 'France', 'Denmark', 'Finland']

Country Frequency Count:
France 2
Norway 1
Denmark 1
Finland 1
```

---

## 🔹 Debug Issue Encountered

Bug Found:
`return freq` placed inside loop.

Impact:

* Only first country processed.

Fix:
Moved return outside loop.

Learning:
Python indentation directly controls logic execution.

---

# 🧠 Section 2 — Data Structure Reality (Production Thinking)

---

## 🔹 Safe vs Unsafe API Data Cases

| Case            | Behavior                   |
| --------------- | -------------------------- |
| results = []    | Safe (no loop execution)   |
| results = None  | Crash (TypeError)          |
| results missing | Crash (KeyError)           |
| results = {}    | Crash during nested access |

---

## 🔹 Key Lesson

Never trust external data blindly.
Always validate structure before processing.

---

# 🌐 Section 3 — Network Packet Awareness (Wireshark)

---

## 🔹 Activity Performed

Captured normal browsing traffic for ~5 minutes.

Observed Protocol Distribution:

* TLS (Most Frequent)
* TCP (Transport Backbone)
* DNS (Domain Resolution)

---

## 🔹 Real Security Insight

TLS ≠ Always Safe
Modern malware also uses encrypted channels.

---

## 🔹 Suspicious Pattern Learning

Indicators that may require investigation:

* Unknown domain repeated connections
* Fixed interval outbound traffic
* Connections continuing after app closed

---

# 🛡 Section 4 — Security Thinking Development

---

## 🔹 Investigation Mindset

Correct SOC thinking progression:

Observe → Context → Reputation → Pattern → Hypothesis → Evidence

Not:
Pattern → Panic → Conclusion

---

# 🎯 Section 5 — MITRE ATT&CK Phishing Technique

---

## 🔹 What is Phishing

Phishing is a social engineering attack used to trick users into revealing credentials, downloading malware, or executing malicious actions through deceptive communication.

---

## 🔹 MITRE Mapping

Technique:
**T1566 — Phishing**

Sub-Techniques:

* T1566.001 Spearphishing Attachment
* T1566.002 Spearphishing Link
* T1566.003 Service-Based Phishing
* T1566.004 Callback / Voice Phishing

---

## 🔹 Defender Monitoring Areas

Email Layer:

* Malicious attachments
* URL reputation
* Spoofed sender detection

Network Layer:

* Newly registered domains
* Suspicious outbound connections
* Known malicious infrastructure

Endpoint Layer:

* Script execution from email/browser
* Unexpected process spawning

---

# ⭐ Day 3 Real Learning Outcomes

✔ Real API interaction
✔ JSON structure navigation
✔ Data processing using dictionaries
✔ Debugging real logical errors
✔ Understanding network protocol baseline
✔ Recognizing phishing as initial access vector
✔ Understanding importance of data validation

---

# 🧠 Personal Skill Progression (Honest Assessment Style)

Moved From:
Basic script execution

Moved Toward:
Data validation thinking
Structured code design
Security observation mindset

---

# 📌 Final Day 3 Summary

Day 3 connected programming, networking observation, and security fundamentals into one workflow. The focus shifted from writing code to understanding how real-world data behaves and how attackers can misuse the same infrastructure.

---
