# 📚 **CYBER THREAT INTELLIGENCE (CTI) WITH PYTHON - DAY 12**
## *Building an IOC Alert System with Python*

---

## 🎯 **TODAY'S LEARNING OBJECTIVES**
1. Understanding IOC (Indicators of Compromise) matching
2. Building a threat detection pipeline
3. Implementing priority-based alerting
4. Understanding SOC analyst workflow
5. Python functions for security automation

---

## 🔍 **PART 1: UNDERSTANDING IOCS**

### **What are IOCs?**
Indicators of Compromise (IOCs) are forensic artifacts that indicate a potential security breach or malicious activity on a system or network.

### **Common IOC Types:**
| IOC Type | Example | Description |
|----------|---------|-------------|
| **IP Address** | `45.33.32.156` | Malicious server IP |
| **Domain** | `evil.com` | Malicious website domain |
| **Hash** | `5d41402abc...` | Malware file hash |
| **URL** | `http://malware.com/payload` | Malicious URL pattern |

### **Confidence Levels:**
```
🔴 HIGH   → Confirmed malicious (100% sure)
🟡 MEDIUM → Suspicious, needs investigation
🟢 LOW    → Possible indicator, low confidence
```

---

## 💻 **PART 2: PYTHON IMPLEMENTATION**

### **Step 1: Creating Log Data**
```python
# Network traffic logs (what happened)
network_log = [
    {"ip": "8.8.8.8", "action": "connect"},
    {"ip": "45.33.32.156", "action": "connect"},
    {"ip": "192.168.1.10", "action": "connect"},
    {"ip": "evil.com", "action": "dns_request"}
]

# Threat intelligence feed (known bad actors)
threat_feed = [
    {"ioc": "45.33.32.156", "confidence": "high"},
    {"ioc": "evil.com", "confidence": "high"},
    {"ioc": "23.21.11.90", "confidence": "medium"}
]
```

### **Step 2: Matching Logic**
```python
# Compare network logs with threat feed
for log_entry in network_log:
    for threat in threat_feed:
        if log_entry["ip"] == threat["ioc"]:
            # Alert generated here
            print(f"Match found: {threat['ioc']}")
```

### **Key Python Concepts Used:**
1. **Lists of Dictionaries** → Structured data storage
2. **Nested Loops** → Compare two datasets
3. **f-strings** → Formatted output
4. **String Multiplication** → `"-" * 30` for separators

---

## 🏗️ **PART 3: PIPELINE ARCHITECTURE**

### **Function-Based Structure:**
```
                    ┌─────────────────┐
                    │   match_ioc()   │
                    │  Compare IOC    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ assign_priority()│
                    │ Set alert level │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │generate_alert() │
                    │  Print output   │
                    └─────────────────┘
```

### **Function 1: match_ioc()**
```python
def match_ioc(log_entry, threat_entry):
    """
    Compares network log IP with threat feed IOC
    Returns: Match string if found, None otherwise
    """
    if log_entry['ip'] == threat_entry['ioc']:
        return "⚠️ IOC MATCH DETECTED"
    return None
```

### **Function 2: assign_priority()**
```python
def assign_priority(confidence):
    """
    Assigns priority based on confidence level
    High → CRITICAL
    Medium → HIGH  
    Low → MEDIUM
    """
    priority_map = {
        "high": "🔴 CRITICAL PRIORITY",
        "medium": "🟡 HIGH PRIORITY",
        "low": "🟢 MEDIUM PRIORITY"
    }
    return priority_map.get(confidence, "UNKNOWN")
```

### **Function 3: generate_alert()**
```python
def generate_alert(match, priority, log, threat):
    """
    Generates formatted alert output
    Includes all relevant information
    """
    print(f"\n{match}")
    print(f"IP Address: {log['ip']}")
    print(f"Action: {log['action']}")
    print(f"IOC Matched: {threat['ioc']}")
    print(f"Confidence: {threat['confidence']}")
    print(f"{priority}")
    print("=" * 50)
```

---

## 🚨 **PART 4: ALERT PRIORITIZATION**

### **Priority Matrix:**
| Confidence | Alert Level | Action Required |
|------------|-------------|-----------------|
| **HIGH** | 🔴 CRITICAL | Immediate investigation |
| **MEDIUM** | 🟡 HIGH | Investigate within 24hrs |
| **LOW** | 🟢 MEDIUM | Monitor and log |

### **Sample Output:**
```
🔴 CRITICAL ALERT: Malicious IOC Detected!
IP: 45.33.32.156
IOC: 45.33.32.156
Confidence: high
Action: connect
==================================================

🟡 HIGH ALERT: Malicious IOC Detected!
IP: evil.com
IOC: evil.com  
Confidence: medium
Action: dns_request
==================================================
```

---

## 👨‍💻 **PART 5: SOC ANALYST WORKFLOW**

### **Real-World Incident Response Process:**

```
┌─────────────────────────────────────────────────┐
│         INCIDENT RESPONSE LIFECYCLE             │
├─────────────────────────────────────────────────┤
│                                                  │
│  1️⃣  VALIDATE ALERT                              │
│      ↓                                           │
│  2️⃣  INVESTIGATE SYSTEM                          │
│      ↓                                           │
│  3️⃣  CHECK LOGS                                  │
│      ↓                                           │
│  4️⃣  ISOLATE HOST                                │
│      ↓                                           │
│  5️⃣  ESCALATE IF NEEDED                          │
│      ↓                                           │
│  6️⃣  DOCUMENT EVERYTHING                          │
│      ↓                                           │
│  7️⃣  REMEDIATE                                   │
│      ↓                                           │
│  8️⃣  POST-INCIDENT REVIEW                        │
│                                                  │
└─────────────────────────────────────────────────┘
```

### **Detailed Analyst Steps:**

#### **1. VALIDATE ALERT** ✅
- Verify if alert is genuine (not false positive)
- Check multiple data sources
- Correlate with other alerts

#### **2. INVESTIGATE SYSTEM** 🔍
- Identify affected hosts/users
- Check running processes
- Review active connections

#### **3. CHECK LOGS** 📋
- Network logs (firewall, proxy)
- System logs (Windows Event, syslog)
- Application logs
- Endpoint detection logs

#### **4. ISOLATE HOST** 🚫
- Disconnect from network
- Block IP at firewall
- Quarantine endpoint

#### **5. ESCALATE** ⚠️
- Inform incident response team
- Notify management
- Contact legal/compliance if needed

#### **6. DOCUMENT** 📝
- Timeline of events
- Actions taken
- Findings and evidence
- Screenshots saved

#### **7. REMEDIATE** 🔧
- Remove malware
- Apply patches
- Reset credentials
- Restore from backup

#### **8. POST-INCIDENT** 🔄
- Root cause analysis
- Lessons learned
- Update detection rules
- Improve security controls

---

## 🐍 **PART 6: PYTHON BEST PRACTICES LEARNED**

### **1. f-strings Usage:**
```python
# ✅ GOOD
print(f"IP: {ip_address}, Confidence: {confidence}")

# ❌ BAD
print("IP:", ip_address, "Confidence:", confidence)
```

### **2. String Multiplication:**
```python
# Create separators
print("-" * 50)  # 50 dashes
print("=" * 30)  # 30 equals signs
```

### **3. Dictionary Access:**
```python
# Always use quotes for keys
data["ip"]      # ✅ Correct
data[ip]        # ❌ Wrong (ip as variable)
```

### **4. Function Parameters:**
```python
# Pass what function needs
def process_data(log_entry, threat_data):
    # Function logic here
    pass
```

---

## 📊 **PART 7: COMPLETE FINAL CODE**

```python
"""
CYBER THREAT INTELLIGENCE SYSTEM
Author: Vivek Kumar
Date: Day 12 - 500 Days of Code Challenge
Description: IOC matching and alert system with priority levels
"""

# Network traffic logs
network_log = [
    {"ip": "8.8.8.8", "action": "connect"},
    {"ip": "45.33.32.156", "action": "connect"},
    {"ip": "192.168.1.10", "action": "connect"},
    {"ip": "evil.com", "action": "dns_request"}
]

# Threat intelligence feed
threat_feed = [
    {"ioc": "45.33.32.156", "confidence": "high"},
    {"ioc": "evil.com", "confidence": "high"},
    {"ioc": "23.21.11.90", "confidence": "medium"}
]

def match_ioc(log_entry, threat_entry):
    """Compare IP address with IOC"""
    if log_entry['ip'] == threat_entry['ioc']:
        return "IOC MATCH FOUND"
    return None

def assign_priority(confidence):
    """Assign priority based on confidence level"""
    if confidence == "high":
        return "🔴 CRITICAL PRIORITY"
    elif confidence == "medium":
        return "🟡 HIGH PRIORITY"
    else:
        return "🟢 MEDIUM PRIORITY"

def generate_alert(match_status, priority, log_data, threat_data):
    """Generate formatted alert"""
    print("\n" + "🚨" * 10)
    print(f"ALERT: {match_status}")
    print(f"IP: {log_data['ip']}")
    print(f"Action: {log_data['action']}")
    print(f"IOC: {threat_data['ioc']}")
    print(f"Confidence: {threat_data['confidence']}")
    print(f"Priority: {priority}")
    print("🚨" * 10)

def main():
    """Main program execution"""
    print("\n" + "="*50)
    print("CTI ALERT SYSTEM - STARTING MONITORING")
    print("="*50)
    
    alerts_generated = 0
    
    for log in network_log:
        for threat in threat_feed:
            match_result = match_ioc(log, threat)
            
            if match_result:
                priority = assign_priority(threat['confidence'])
                generate_alert(match_result, priority, log, threat)
                alerts_generated += 1
    
    print(f"\n✅ Monitoring Complete. Total Alerts: {alerts_generated}")

# Run the program
if __name__ == "__main__":
    main()
```

---
