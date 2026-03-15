# Day 25 – Threat Intelligence API Integration

Today we took the engine from local/static threat intel (JSON files) to **real-time, external threat intelligence** using APIs.  
This is one of the most valuable skills in CTI / SOC automation — no serious analyst manually looks up IOCs anymore; tools do it automatically.

## What We Built Today

- Simulated a real threat intelligence API call (AbuseIPDB style)
- Parsed the API response into clean, usable fields
- Created a combined enrichment function
- Integrated API enrichment into the main detection engine
- Added real-time lookup when IOC matches

## Files Created / Updated

- `src/threat_api_client.py` → API simulation, parsing, and enrichment functions
- `cti_detection_engine.py` → Main engine updated to call API when IOC matches

## Key Functions (threat_api_client.py)

1. `query_threat_api(ip)`  
   Simulates (or calls) threat intel API lookup.  
   Returns raw API response dict.

2. `parse_api_response(api_data)`  
   Cleans raw API response into usable fields: ip, abuse_score, country, isp, last_reported.

3. `enrich_ioc_data(ip)`  
   Combines query + parse → returns final enriched dict for alerts.

## Integration in Detection Engine

In `match_intelligence()` function:

- First checks local lookup (ioc_lookup.json)  
- If not found and intel_match is True → calls API  
- Adds API enrichment (abuse_score, country, isp) with source tag  
- Returns same format (intel_match, enriched) so existing code doesn't break

In alert printing:

```python
if enriched:
    print("  Enrichment:")
    for k, v in enriched.items():
        print(f"    {k}: {v}")

Sample Output (when IOC matches)

*** CRITICAL ***
IP: 103.45.67.89
  Anomaly Detected: Yes
  Threat Feed Match: YES
  Behaviour Risk: CRITICAL
  Failed Logins: 10
  Data Transfer: high
  Enrichment:
    Country: China
    Malware Family: AgentTesla
    First Seen: 2025-01-05
    source: Local Lookup
  Threat Intelligence Enrichment (API):
    ip: 103.45.67.89
    abuse_score: 90
    country: RU
    isp: Unknown ISP
    last_reported: 2026-03-10
  Anomaly Reasons:
    - excessive failed logins (10 > 2)
    - unusual data transfer (high != low)
------------------------------------------------------------

Why This Step is CriticalManual IOC lookup is slow and error-prone — SOC analysts can't do it for every alert
Automated API enrichment gives instant context (abuse score, country, ISP, reputation)  
Reduces false positives (high abuse_score confirms suspicion)  
Increases alert quality (context helps triage faster)  
Scales to thousands of alerts — real SOC requirement

LimitationsCurrently simulated response (no real API key yet)  
No rate limiting or error retry logic  
No multiple sources (only one API simulated)  
Abuse score not yet used to adjust alert level (future enhancement)

Day 25 complete.
Now the engine can pull real-time threat intelligence — huge upgrade in realism and value.— Vivek | ThreatIntel
