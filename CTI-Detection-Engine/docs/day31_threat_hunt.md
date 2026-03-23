=== DAY 31: MANUAL THREAT HUNTING REPORT ===
Target Log: data/windows_auth.log

During the manual inspection of the Windows Authentication logs, I identified the following suspicious patterns that indicate a Targeted Attack:

1. MULTIPLE FAILED LOGINS (EventID: 4625)
   - Observation: There are 5 consecutive 'FAIL' events from the same IP.
   - Analysis: This is a classic sign of a Brute Force attack. A normal user might 
     forget their password once or twice, but 5+ failures in a row suggests 
     automated password guessing.

2. FAIL → SUCCESS SEQUENCE (The Most Critical Pattern)
   - Observation: After 5 'FAIL' events, there is a 'SUCCESS' (EventID: 4624).
   - Analysis: This indicates a "Successful Brute Force." It means the attacker 
     finally guessed the correct password. This is an IMMEDIATE CRITICAL ALERT 
     because the account is now compromised.

3. SAME IP REPEATED (Indicator of Persistence)
   - Observation: IP 103.45.67.89 appears in every failed and successful attempt for 'admin'.
   - Analysis: The attacker is not rotating their IP. This makes it easier for 
     us to block the source, but it also shows the attacker is focused on a 
     single entry point.

4. ADMIN ACCOUNT TARGETED (Privileged Access)
   - Observation: All failed attempts were directed at the 'admin' username.
   - Analysis: Attackers target 'admin' because it provides the highest level 
     of permissions. Once compromised, they can disable security tools, 
     install malware, or create new backdoor accounts.

5. MITRE ATT&CK Correlation:
>>Tactic: Credential Access (TA0006)
>>Technique: Brute Force (T1110)
>>Sub-Technique: Password Guessing (T1110.001)
>>Evidence: Detected via Windows Event ID 4625 (Logon Failure) followed by Event ID 4624 (Successful Logon) from source IP 103.45.67.89.
