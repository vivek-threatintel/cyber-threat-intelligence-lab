# 📘 Day 4 — Python + Networking + CTI Thinking

---

## 🔹 Overview

Today focused on combining Python basics with security mindset.
The main goal was understanding how security data (IOC) can be processed, classified, and risk scored using simple logic.
Along with coding, networking observation and CTI attack chain thinking were also practiced.

---

# 💻 Python Tasks Completed

---

## ✅ Code 1 — `day4.py` (IOC Data Handling)

### Goal

* Remove duplicate IOCs
* Separate Domains and IPs
* Count each type

### Key Concepts Learned

* Set → Remove duplicates
* Loop → Data processing
* Basic IOC classification

---

### Example Output

```
Unique IOCs: ['bad-domain.net', 'milicious.com', '192.168.1.5']

Domains: ['bad-domain.net', 'milicious.com']
IPs: ['192.168.1.5']

Counts:
Domains: 2
IPs: 1
```

---

## ✅ Code 2 — `day4_risk.py` (Basic IOC Risk Logic)

### Goal

Assign risk using simple rules:

| Type       | Risk   |
| ---------- | ------ |
| Private IP | LOW    |
| Domain     | MEDIUM |
| Public IP  | HIGH   |

---

### Key Concepts Learned

* Private IP ranges (10.x, 192.168.x, 172.16–31.x)
* Function based logic
* Basic detection mindset

---

### Example Output

```
IOC Risk:

milicious.com : MEDIUM
192.168.1.5 : LOW
8.8.8.8 : HIGH
bad-domain.net : MEDIUM
10.0.0.3 : LOW
```

---

## ✅ Code 3 — `day4clean.py` (Clean Function Structure)

### Goal

* Clean readable code
* Separate logic into functions
* Proper program flow using main()

---

### Key Concepts Learned

* Clean code structure
* Function separation
* Main execution flow

---

### Example Output

```
IOC Risk Output:

milicious.com : MEDIUM
192.168.1.5 : LOW
8.8.8.8 : HIGH
bad-domain.net : MEDIUM
10.0.0.3 : LOW
172.20.5.4 : LOW
```

---

# 🌐 Networking Tasks Completed

---

## ✅ Suspicious Port Thinking

Observed system ports using:

```
ss -tuln
```

Learned about:

* mDNS (5353) → Local discovery
* DNS (53) → Normal networking
* KDE Connect (1716) → Device communication
* Ephemeral ports → Temporary application use

---

## ✅ Exposure Concepts Learned

| Binding     | Meaning        |
| ----------- | -------------- |
| 127.0.0.1   | Local only     |
| 192.168.x.x | LAN only       |
| 0.0.0.0     | All interfaces |

---

## ✅ Security Thinking

Suspicious depends on:

* Port number
* Binding address
* Running process
* Environment context

---

# 🧠 CTI & Attack Chain Thinking

---

## Phishing → Malware → Data Theft Flow

Attackers often start with phishing emails or messages to gain initial access.
After entry, malware is executed when the victim runs malicious attachments or downloads infected files.
Attackers then establish persistence by creating startup tasks or hidden services to maintain long-term access.
Once stable access is achieved, attackers perform internal reconnaissance to find credentials, sensitive files, or network resources.
Finally, data exfiltration happens when attackers send stolen data outside the network using encrypted traffic or hidden channels.

---

# 🛡 Security Mindset Improvements

Today improved understanding of:

IOC preprocessing
Basic threat scoring logic
Network exposure risks
Attack chain flow thinking
SOC style investigation mindset

---

# ⭐ Key Learning Summary

* Raw IOC data must be cleaned before use
* Risk logic can be automated using simple rules
* Not all open ports are suspicious
* Context matters more than raw data
* Clean code improves debugging and scalability

---

# 📌 Next Learning Direction

* Regex based IOC validation
* URL and hash detection
* Threat feed integration
* Logging and file based IOC input
* More realistic threat scoring

---
