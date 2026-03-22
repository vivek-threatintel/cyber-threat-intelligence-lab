# Day 18 – Behaviour + Threat Intelligence Correlation  
(Week 3 – Advanced Detection Engineering)

Today we took the next logical step: moving beyond pure IOC matching to **hybrid detection** — combining **threat intelligence (known IOCs)** with **behavioural indicators** (failed logins, data transfer volume) to improve detection accuracy and reduce false positives.

This is exactly how real SOC tools work: SIEM + UEBA (User and Entity Behavior Analytics) + Threat Intelligence feeds.

## Project Goal

Build a pipeline that:
- Reads simulated event logs (failed logins + data transfer)
- Detects suspicious behaviour
- Correlates with threat intelligence (recent feed + lookup)
- Generates graded alerts (CRITICAL / HIGH / MEDIUM / LOW)
- Prints formatted alerts and final summary report

## Files Created

- `external_feed.json` – Recent IOCs from threat feeds
- `ioc_lookup.json` – Static IOC metadata (country, malware family, first seen)
- `day18_behavior_detection.py` – Main clean script with modular functions
- `day18_behavior_detection_simple.py` – Earlier monolithic version (for comparison)
- `day18_notes.md` – This file (documentation & reflection)

## Code Structure (Clean Version)

### 1. Data Loading
- `load_lookup()` → static IOC database
- `load_feed()` → recent threat feed

### 2. Behaviour Detection
- `detect_behavior(event)`  
  Input: single event dict  
  Output: (behaviour_risk: str, suspicious_reasons: list)  
  Logic:  
  - failed_logins > 5 → suspicious  
  - failed_logins > 10 or multiple indicators → CRITICAL  
  - data_transfer == "high" → suspicious  
  - No issues → LOW

### 3. Intelligence Matching
- `match_intelligence(ip, feed_iocs, lookup_db)`  
  Output: (intel_match: bool, enriched: dict)  
  Logic: Check if IOC in feed → pull enrichment from lookup

### 4. Alert Generation
- `generate_alert(behaviour_risk, intel_match)`  
  Output: final_alert string  
  Correlation rules:  
  - Intel YES + CRITICAL → CRITICAL ALERT  
  - Intel YES + HIGH/SUSPICIOUS → HIGH ALERT  
  - Intel YES + LOW → MEDIUM ALERT  
  - Intel NO + CRITICAL/HIGH → MEDIUM ALERT  
  - Intel NO + SUSPICIOUS → LOW ALERT  
  - All else → SAFE

### 5. Main Execution & Reporting
- Load data  
- Build feed_iocs set for fast lookup  
- Loop over event_log:  
  - Detect behaviour  
  - Match intelligence  
  - Generate final alert  
  - Print formatted alert (if not SAFE)  
  - Update counters  
- Print summary report (total logs, threat matches, alert counts)

## Why Behaviour + Intelligence Together Reduces False Positives

**Question:** Why does combining behavioural analytics with threat intelligence reduce false positives? (Think detection accuracy.)

**Detailed Answer:**

Using threat intelligence (IOC match) or behavioural analytics in isolation leads to high false positive rates and poor detection accuracy.

**Threat Intelligence (IOC match) alone**  
- Extremely noisy because many IOCs are benign or contextual:  
  - Legitimate IPs/domains (CDNs, cloud providers, shared hosting) appear in feeds  
  - Old/expired C2 infrastructure still triggers matches  
  - False positives from sinkholed, parked, or misclassified domains  
- Result: High alert volume → analyst fatigue → missed real threats

**Behavioural Analytics alone**  
- Generates alerts on normal user activity:  
  - Forgotten password → 6–10 failed logins  
  - Large legitimate file upload/download → high outbound transfer  
  - Remote work/VPN → unusual traffic patterns  
- Result: Low precision → legitimate actions flagged as malicious

**Combined (correlation) approach**  
- Only raises high-priority alerts when **both** conditions are true:  
  - IOC is known-bad (threat intelligence hit) **AND**  
  - Suspicious behaviour is observed  
- Example:  
  - Known AgentTesla C2 IP + 10 failed logins + high outbound data → **CRITICAL ALERT** (very high confidence)  
  - Same IP + normal behaviour → **MEDIUM/LOW** priority (false positive filtered)  
  - High failed logins but no IOC match → **MEDIUM** (low confidence)

**Key Benefits**  
- **False Positive Rate (FPR)** drops significantly → only correlated events alert  
- **True Positive Rate (TPR)** increases → real threats stand out clearly  
- **Signal-to-noise ratio** improves → fewer alerts, higher quality  
- **Detection accuracy** overall rises → better precision and recall  
- **Analyst efficiency** improves → focus on fewer, higher-confidence incidents

This exact correlation logic powers modern platforms:  
- Microsoft Sentinel (Analytics rules with TI + UEBA)  
- CrowdStrike Falcon (IOC + behavioural indicators)  
- Elastic SIEM (threat intel + anomaly detection)  
- Splunk Enterprise Security (correlation searches)

In short:  
Intelligence alone = too many alerts.  
Behaviour alone = too much noise.  
Together = **high-confidence, low-noise detection** — the foundation of effective modern SOC operations.

## Limitations of Current Implementation

- Hard-coded event_log (real-world: syslog, EDR, Windows Event Log stream)
- Fixed thresholds (failed_logins > 5) → future: dynamic baselines per entity
- No time-based correlation (e.g., failed logins in last 5 min)
- No user/entity context (admin vs normal user)
- No persistence (alerts not saved to file/DB/ticket)
- No external alerting (email, Slack, PagerDuty)

## Author
— Vivek | ThreatIntel
