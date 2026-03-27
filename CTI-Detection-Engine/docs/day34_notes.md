=== DAY 34: STRATEGIC SCORING & PRIORITIZATION NOTES ===

1. WHY SCORING?
Real-world SOCs are flooded with "Alert Fatigue." Scoring acts as a noise filter. 
It ensures analysts prioritize a 750MB exfiltration (High Score) over 
background noise like a single failed login (Low Score).

2. PRIORITIZATION LOGIC (THE BRAIN)
We use a "Weighted Kill-Chain" approach. 
- Base Score: Based on MITRE Tactics (C2 gets the highest weight at +6).
- Correlation Bonus: If events are linked in time (Timeline), we add +5 
  because a coordinated attack is deadlier than isolated glitches.

3. SOC WORKFLOW (TRIAGE)
- CRITICAL (10+): Full-blown breach. Host isolation is mandatory.
- HIGH (7-9): Multi-stage suspicious activity. Investigate immediately.
- MEDIUM (4-6): Single phase detection. Monitor for further activity.
- LOW (1-3): Log collection only. No manual eyes needed.

"In security, a score is a story. Today, our engine learned how to read it."