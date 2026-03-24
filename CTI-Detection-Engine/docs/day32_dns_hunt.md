=== DAY 32: DNS THREAT HUNTING & C2 BEACONING REPORT ===
Target Log: data/dns.log

During the manual inspection of DNS traffic, I identified the following indicators of a Command & Control (C2) communication:

1. REPEATED DOMAIN QUERIES
   - Observation: 'host1' is requesting 'evil-c2.com' multiple times.
   - Analysis: Normal users visit a site once and their browser caches the IP. 
     Repeatedly asking for the same domain's IP suggests a machine-to-machine 
     communication, likely a malware "beacon."

2. UNKNOWN OR NON-STANDARD DOMAINS
   - Observation: Domains like 'google.com' are trusted, but 'evil-c2.com' 
     has no known business purpose.
   - Analysis: Attackers use cheap or newly-registered domains. An analyst 
     must look for "Newly Observed Domains" (NODs) as they are often 
     malicious before they are even added to blocklists.

3. PERIODIC REQUESTS (TIME-BASED)
   - Observation: Requests at 10:01, 10:02, 10:03, 10:05... (1-minute gap).
   - Analysis: This is the 'Heartbeat' of a malware. Humans don't browse 
     at exact 60-second intervals. This "periodic" behavior is a signature 
     of a C2 server calling back to its host.

4. RARE DOMAIN (LONG TAIL ANALYSIS)
   - Observation: 'google.com' has millions of hits globally, but 
     'evil-c2.com' is only seen from one specific host in our network.
   - Analysis: If a domain is rare across the entire organization but 
     highly frequent on one specific host, it is a "Low-Volume, High-Risk" 
     indicator. This is often how targeted attacks (APTs) hide.

=== DAY 32: NETWORK DETECTION & MITRE MAPPING ===

DETECTION SUMMARY:
- Identified periodic DNS queries from 'host1' to 'evil-c2.com'.
- Pattern: 1-minute interval (Heartbeat/Beaconing).

MITRE ATT&CK CORRELATION:
- Tactic: Command and Control (TA0011)
- Technique: Application Layer Protocol (T1071)
- Sub-Technique: DNS (T1071.004)

ANALYST CONCLUSION:
The repeated querying of an unknown/untrusted domain at fixed intervals 
is a high-confidence indicator of T1071.004. This allows the attacker 
to bypass traditional port-blocking firewalls by tunneling C2 traffic 
through standard DNS queries.

=== DAY 32: MODULAR ENGINE UPGRADE ===

- INTEGRATION: Successfully added 'detect_c2_beaconing()' to the core engine.
- CAPABILITY: The engine now performs 'Multi-Vector Correlation'. 
- NEXT STEP: Standardizing all alerts into a single 'Incident Report' format.

"A secure network isn't one with no alerts, but one where the alerts tell a complete story."

=== DAY 32: DNS C2 INTEGRATION & ENGINE UPGRADE ===

- MILESTONE: Upgraded Engine to V2.1 with DNS Beaconing Detection.
- DETECTION LOGIC: 
  * Implemented stateful tracking for DNS queries using host-domain pairs.
  * Successfully filtered "Noise" (Google/Microsoft) while flagging "Unknown" domains.
- MITRE CORRELATION: 
  * Added T1071.004 (DNS Command and Control).
- RESULTS: 
  * Identified a critical compromise on IP 103.45.67.89.
  * Identified a high-risk C2 Beacon from host1 to evil-c2.com.

"Visibility is the first step of Defense."