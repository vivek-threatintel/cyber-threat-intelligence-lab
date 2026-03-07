

## Why This Matters – CTI Analyst Thinking

**Question:** Why is anomaly detection important when attackers use unknown infrastructure? (Think zero-day style attacks.)

**Answer:**

Attackers today are smart — they rotate infrastructure constantly: new IPs, new domains, new C2 servers, new malware variants, living-off-the-land techniques. Most of these have **zero matches** in any threat feed or IOC database.

**IOC-based detection alone fails here** because:
- No signature exists yet
- Zero-day malware, new phishing domains, compromised legitimate accounts — all look clean to signature rules

**Behaviour stays the same** — attackers still need to:
- Brute-force accounts (high failed logins)
- Steal data (unusual high outbound transfer)
- Move laterally (abnormal internal connections)
- Beacon back to C2 (periodic unusual traffic)

Anomaly detection catches these deviations from normal baseline — even when the IOC is completely unknown.

**Real example:**
- Normal user: 0–2 failed logins/day, low outbound transfer
- Attacker on new IP: 10 failed logins + sudden 50GB outbound → anomaly flagged (possible brute-force + exfil) even if IP is brand new and not in any feed

**How anomaly complements threat intel:**
- Threat intel = known threats (high precision, low recall for zero-days)
- Anomaly = unknown threats (lower precision, high recall for new TTPs)
- Together = best coverage: catch known bad actors **and** early warning for zero-days/unknown attacks

This is exactly why modern tools invest heavily in anomaly detection:
- Microsoft Sentinel UEBA
- CrowdStrike Falcon Behaviour Analytics
- Elastic Anomaly Detection
- Splunk User Behavior Analytics

**Limitations of this implementation:**
- Hard-coded static baseline (real: dynamic, per-IP/user, time-based)
- No time-window logic (e.g., failed logins in last 5 min)
- No user/entity context (admin vs normal user)
- No severity scoring beyond simple rules

Day 19 complete.  
We now have the foundation for real AI-style behavioural detection.

— Vivek | ThreatIntel
