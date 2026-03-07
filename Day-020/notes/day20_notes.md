# Day 20 – CTI Detection Engine  

Goal: Build one unified engine that combines  
- Threat Intelligence (IOC match + enrichment)  
- Behaviour Analysis (failed logins + data transfer)  
- Baseline Anomaly Detection  

into a single, modular script with prioritized alerts and summary.

## File
- `cti_detection_engine.py` – The complete engine

## Architecture & Functions

- `load_lookup()` – Static IOC metadata (country, malware family, first seen)
- `load_feed()` – Recent threat feed for IOC matching
- `load_baseline()` – Normal behaviour baseline (failed logins ≤ 2, data transfer = low)
- `detect_anomaly(event, baseline)` – Checks deviation and assigns risk level (CRITICAL/HIGH/SUSPICIOUS/LOW)
- `match_intelligence(ip, feed_iocs, lookup_db)` – IOC presence + enrichment
- `generate_alert(behaviour_risk, intel_match)` – Final alert level

## Alert Prioritization Rules

- Anomaly + IOC match → **CRITICAL**
- Anomaly only → **MEDIUM**
- IOC match only → **HIGH**
- None → **SAFE**

## Output Style

- Clean per-event alerts (if not SAFE):

  *** CRITICAL ***
  IP: 103.45.67.89
  Threat Feed Match: YES
  Behaviour Risk: CRITICAL
  Failed Logins: 10
  Data Transfer: high
  Country: China
  Malware Family: AgentTesla
  First Seen: 2025-01-05
  Reasons:
    - excessive failed logins
    - unusual data transfer (high)

- Final summary:

  === Detection Engine Summary ===
  Logs Processed: 4
  Threat Matches: 2
  Critical Alerts: 1
  High Alerts: 1
  Medium Alerts: 0
  Safe Events: 2

## Why This Engine is Effective

Threat intel catches known bad actors.  
Behaviour & anomaly catch suspicious actions even with unknown IOCs.  
Combined → fewer false positives, higher confidence, better prioritization.

## Limitations

- Static baseline (real-world: dynamic per-IP/user/time)
- No time-based correlation (e.g., last 5 min window)
- No user/entity context
- Simple rules (no scoring/ML yet)

Day 20 complete.  
Now we have a real, modular detection engine.

— Vivek | ThreatIntel
