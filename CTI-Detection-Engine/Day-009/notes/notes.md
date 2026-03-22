# 📘 Day 9 — Authentication Log Analysis, Brute Force Detection, CTI Mapping & Network Thinking

---

# 🎯 Objective

The goal of Day 9 was to simulate real-world authentication log analysis using Python and understand how SOC analysts detect brute force attacks. This included parsing authentication logs, counting login attempts per IP, detecting suspicious patterns, structuring the code into clean functions, and mapping the behavior to MITRE ATT&CK techniques.

Additionally, CTI (Cyber Threat Intelligence) and network analyst thinking were applied to understand attacker behavior and detection methods.

---

# 🧠 Concept 1 — Authentication Log Understanding

Authentication logs record login activity on systems such as Linux servers, SSH services, VPN gateways, and web applications.

Example log file created (`auth.log`):

```
192.168.1.10 SUCCESS
45.33.32.156 FAILED
45.33.32.156 FAILED
45.33.32.156 FAILED
45.33.32.156 SUCCESS
8.8.8.8 FAILED
8.8.8.8 FAILED
8.8.8.8 FAILED
```

Each line contains:

* Source IP address
* Login status (FAILED or SUCCESS)

This format is similar to real system logs such as:

```
/var/log/auth.log (Linux)
Windows Security Event Logs
SSH authentication logs
SIEM authentication telemetry
```

---

# 💻 Python Code 1 — Authentication Log Parser (day9.py)

## Objective

Parse authentication log file and extract login activity per IP.

## Code

```python
file = open("auth.log", "r")

log_data = {}

for line in file:

    parts = line.split()
    ip = parts[0]
    status = parts[1]

    if ip not in log_data:
        log_data[ip] = {"FAILED": 0, "SUCCESS": 0}

    log_data[ip][status] += 1

file.close()

for ip in log_data:

    print("IP:", ip)
    print("FAILED:", log_data[ip]["FAILED"])
    print("SUCCESS:", log_data[ip]["SUCCESS"])
    print()

print("Total unique IPs:", len(log_data))
```

---

## Output

```
IP: 192.168.1.10
FAILED: 0
SUCCESS: 1

IP: 45.33.32.156
FAILED: 3
SUCCESS: 1

IP: 8.8.8.8
FAILED: 3
SUCCESS: 0

Total unique IPs: 3
```

---

## Concept Learned

This simulates authentication monitoring systems that track login attempts per IP.

This allows defenders to identify suspicious login behavior.

---

# 💻 Python Code 2 — Suspicious IP Detection (Brute Force Pattern)

## Detection Logic

```
FAILED ≥ 3
AND
SUCCESS ≥ 1
```

This pattern indicates possible brute force attack success.

## Code

```python
suspicious_ips = []

for ip in log_data:

    failed = log_data[ip]["FAILED"]
    success = log_data[ip]["SUCCESS"]

    if failed >= 3 and success >= 1:
        suspicious_ips.append(ip)

print("\nSuspicious IPs:\n")

for ip in suspicious_ips:
    print(ip)
```

---

## Output

```
Suspicious IPs:

45.33.32.156
```

---

## Security Interpretation

Pattern observed:

```
FAILED
FAILED
FAILED
SUCCESS
```

Meaning:

Attacker tried multiple passwords and eventually gained access.

This indicates possible account compromise.

---

# 💻 Python Code 3 — Structured Security Log Analyzer (day9_clean.py)

## Functions Created

### parse_log()

Reads authentication log file.

```python
def parse_log(filename):

    file = open(filename, "r")
    lines = file.readlines()
    file.close()

    return lines
```

---

### count_attempts()

Counts FAILED and SUCCESS attempts per IP.

```python
def count_attempts(lines):

    log_data = {}

    for line in lines:

        parts = line.split()
        ip = parts[0]
        status = parts[1]

        if ip not in log_data:
            log_data[ip] = {"FAILED": 0, "SUCCESS": 0}

        log_data[ip][status] += 1

    return log_data
```

---

### detect_suspicious()

Detects brute force pattern.

```python
def detect_suspicious(log_data):

    suspicious_ips = []

    for ip in log_data:

        failed = log_data[ip]["FAILED"]
        success = log_data[ip]["SUCCESS"]

        if failed >= 3 and success >= 1:
            suspicious_ips.append(ip)

    return suspicious_ips
```

---

## Output

```
Login Summary:

IP: 45.33.32.156
FAILED: 3
SUCCESS: 1

Suspicious IPs:

45.33.32.156
```

---

# 🧠 CTI Thinking — MITRE ATT&CK Technique Mapping

Technique: Brute Force
Technique ID: T1110
Tactic: Credential Access

---

## Attacker Behavior

Attacker attempts multiple passwords to gain access.

Methods include:

* Password guessing
* Password spraying
* Credential stuffing

Goal:

Gain valid credentials and system access.

---

## Detection Indicators

Authentication logs show:

```
Multiple FAILED attempts
Followed by SUCCESS login
```

This indicates attacker guessed correct password.

---

## Why This Works

Attackers exploit:

* Weak passwords
* Lack of MFA
* No account lockout policies

Once successful, attacker gains system access.

---

# 🌐 Network Thinking — Analyst Perspective

Observed Pattern:

```
FAILED → FAILED → FAILED → SUCCESS
```

This is suspicious because normal users do not repeatedly fail login attempts many times before succeeding.

Multiple failed attempts indicate password guessing activity.

Final successful login suggests attacker found correct password.

This indicates possible account compromise.

---

## Defender Investigation Steps

SOC analyst should check:

* Source IP address
* Login timestamps
* Login frequency
* Activities after login
* Network connections initiated after login

Analyst may also check:

* Firewall logs
* SIEM alerts
* Network traffic logs

---

# 🧠 SOC Pipeline Simulation

This exercise simulated real SOC workflow:

```
Authentication Logs
↓
Log Parsing
↓
Attempt Counting
↓
Suspicious Pattern Detection
↓
Security Alert Generation
↓
SOC Investigation
```

---

# 🧠 Skills Developed

Python Skills:

* File handling
* Log parsing
* Dictionary tracking
* Function design
* Structured programming

Security Skills:

* Authentication monitoring
* Brute force detection
* Suspicious pattern identification
* MITRE ATT&CK mapping
* SOC investigation thinking

---

# 🛡 Real World Applications

This logic is used in:

* SIEM platforms (Splunk, Sentinel, Elastic)
* SSH brute force detection systems
* Authentication monitoring tools
* SOC alert pipelines
* Threat hunting tools

---

# 🎯 Key Learning Outcome

Day 9 provided practical experience in analyzing authentication logs, detecting brute force attacks, and building structured security log analysis tools using Python while applying CTI and network analyst thinking.

---

# ✅ Day 9 Status: Completed
