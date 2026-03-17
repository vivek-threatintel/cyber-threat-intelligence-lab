# Day 23 – Anomaly Scoring Engine

Today we took the next real step toward data-driven detection: building a simple **anomaly scoring system** based on deviation from baseline averages.

## What the Script Does

1. Loads the dataset from JSON
2. Calculates baseline averages (avg_failed_logins, avg_data_transfer, avg_requests)
3. For each event computes an **anomaly score** (absolute deviation from baseline, scaled)
4. Classifies the score into levels (ANOMALY / SUSPICIOUS / NORMAL)
5. Prints per-event details + final summary with counts

## Key Function

- `load_dataset()` — safe JSON loading with error handling
- `calculate_baseline()` — computes average values across all events
- `compute_anomaly_score()` — deviation-based score (failed + scaled transfer + scaled requests)
- `classify_anomaly()` — threshold-based classification (score > 10 = ANOMALY, > 5 = SUSPICIOUS)

## Sample Output (from a run)

Total Events Loaded: 4
Baseline Failed Logins: 3.50
Baseline Data Transfer: 297.50
Baseline Requests: 20.75
---
IP: 103.45.67.89
  Failed Logins: 10
  Data Transfer: 900
  Requests: 50
  Anomaly Score: 24.40
  Status: ANOMALY
---
IP: 8.8.8.8
  Failed Logins: 0
  Data Transfer: 50
  Requests: 10
  Anomaly Score: 10.60
  Status: ANOMALY
---
IP: 23.21.11.90
  Failed Logins: 3
  Data Transfer: 200
  Requests: 15
  Anomaly Score: 3.60
  Status: NORMAL
---
IP: 192.168.1.10
  Failed Logins: 1
  Data Transfer: 40
  Requests: 8
  Anomaly Score: 10.20
  Status: ANOMALY
---

SUMMARY
Total Events: 4
Anomaly Events: 3
Suspicious Events: 0
Normal Events: 1

## Key Learning Points

- **Baseline calculation** is the heart of anomaly detection — average behaviour across data
- **Deviation scoring** (absolute difference) is a simple yet powerful way to quantify unusual activity
- Scaling deviations (dividing by 50 or 5) prevents one feature from dominating
- Thresholds turn continuous scores into actionable labels (ANOMALY / SUSPICIOUS / NORMAL)

## Why This is Powerful

Traditional rule-based detection needs predefined thresholds (failed > 5).  
Anomaly scoring is data-driven — it automatically adapts to the actual dataset average.  
This makes it more flexible and better at catching unknown attacks.

## Limitations

- Static averages (real-world: rolling / per-entity baseline)
- Simple absolute deviation (no standard deviation or z-score yet)
- Arbitrary scaling factors (50, 5) — real-world needs tuning
- No time correlation (e.g., failed logins over 5 min)

Day 23 complete.  
Now we have a proper mathematical anomaly scoring system — the bridge to actual ML detection.

— Vivek | ThreatIntel
