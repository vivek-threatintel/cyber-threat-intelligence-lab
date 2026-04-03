=== DAY 36: CTI INCIDENT REPORTING & ANALYST WORKFLOW ===
Document ID: CTI-REPORTING-V1
Focus: Strategic Documentation & Remediation

--- 1. CTI REPORTING STRUCTURE (THE "SURGICAL" LAYOUT) ---
Ek professional report ko 5 core sections mein divide kiya jata hai taaki wo Technical 
aur Management dono ke liye actionable ho:

- SECTION 1: Incident Summary (The Gist)
  Quick overview: Host, Severity, and Timeline. "Kya hua aur kitna bura hua?"
  
- SECTION 2: Initial Access & C2 (The Entry)
  Detailing T1110 (Brute Force) and T1071 (Beaconing). Attacker ne rasta kaise banaya?

- SECTION 3: Execution & Persistence (The Payload)
  Identifying T1059 (Suspicious Uploads). Attacker ne system mein kya 'install' kiya?

- SECTION 4: Detection Logic (The Why)
  Explaining the rules (Brute force rule, DNS sensors, Anomaly scoring) that triggered 
  the alert. This proves the alert is a 'True Positive'.

- SECTION 5: Recommendations (The Fix)
  Action items: IP Blocking, Credential Reset, Forensic Scanning, and Monitoring.

--- 2. WHY DOCUMENTATION IS CRITICAL? ---
Security operations mein documentation 'Gold' hoti hai kyunki:
- Knowledge Base: Agli baar wahi attack hua toh solution pehle se pata hoga.
- Accountability: Management ko proof milta hai ki SOC team ne kya 'Value' add ki.
- Legal & Compliance: Major breaches mein legal teams ko forensic-ready reports chahiye hoti hain.
- Root Cause Analysis (RCA): Ye samajhne mein madad milti hai ki 'Weakness' kahan thi (e.g., Weak Passwords).



--- 3. ANALYST WORKFLOW (FROM ALERT TO CLOSURE) ---
Ek Senior Analyst ka daily workflow is pattern ko follow karta hai:
1. MONITOR  : Logs aur alerts ko lagatar scan karna.
2. TRIAGE   : Score ke basis par decide karna ki kaunsa alert 'Critical' hai (Day 34).
3. INVESTIGATE: Playbook use karke evidence (Artifacts) ikattha karna (Day 35).
4. VERDICT  : Confirm karna ki 'True Positive' hai ya 'False Positive'.
5. REPORT   : Professional incident report likhna aur action recommend karna (Day 36).
6. REMEDIATE: Attack ko rokna aur system ko clean karna.

"A breach without a report is a lesson never learned."
================================================================================