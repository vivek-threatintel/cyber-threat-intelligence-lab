=== DAY 34: THREAT SCORING CONFIGURATION (SOC-RULE-34) ===

[SCORING MATRIX]
- IOC Match (Threat Intel)        : +5 | Known blacklisted entity found.
- Brute Force Detected (T1110)    : +4 | High-volume failed auth attempts.
- C2 Beaconing (T1071)            : +6 | Active outbound heartbeat detected.
- Anomaly (Behavioral)            : +3 | Unusual data spikes/odd timing.
- Suspicious Upload (T1059)       : +5 | Potential malware deployment.
- Timeline Correlation Bonus      : +5 | Events linked in a sequence.

[INCIDENT TRIAGE THRESHOLDS]
- 🔴 CRITICAL (Score 10+) : Immediate P0 Incident Response.
- 🟠 HIGH     (Score 7-9) : P1 Investigation within 60 mins.
- 🟡 MEDIUM   (Score 4-6) : P2 Shift review required.
- 🟢 LOW      (Score 1-3) : P3 Logging & Baseline analysis.