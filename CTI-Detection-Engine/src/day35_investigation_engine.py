def run_investigation_engine(host, score, detections, timeline_found):
    """
    Day 35: Investigation Logic.
    Triggers a systematic check based on the Playbook steps if the score is CRITICAL.
    """

    print("\n" + "🔍" * 20)
    print("      INCIDENT INVESTIGATION ENGINE      ")
    print("🔍" * 20)

    # Logic: Only start investigation if score is Critical (>= 10)
    if score >= 10:
        print(f"\n[🚨] ALERT: CRITICAL SCORE ({score}) DETECTED on {host}!")
        print(f"[⚙️ ] STATUS: Investigation Started Automatically.")
        
        print(f"\n--- 📋 PLAYBOOK STEPS INITIATED for {host} ---")

        # Step 1: Identify Check
        if "Brute Force" in str(detections):
            print("  [STEP 1] Identify Audit: Reviewing AUTH logs for T1110...")

        # Step 2: Network Check
        if "C2 Beconing" in str(detections):
            print("  [Step 2] Network Audit: Analyze outbond DNS for T1071...")

        # Step 3: Execution Check
        if "Suspicious Upload" in str(detections):
            print("  [Step 3] Endpoint Audit: Checking File Integrity for T1059...")

        # Step 4: Timeline Check
        if timeline_found:
            print("  [STEP 4] Correlation Audit: finalizing Attack Timeline...")

        print(f"\n✅ Investigation Complete for {host}. Reason: Critical Alert.")
        print("-" * 40)

    else:
        print(f"\n[i] Score ({score}) is below Critical threshold.")
        print(f"[i] Status: logged for baseline monitoring. No manual IR needed.")

# --- Simulation (Testing Step 2) ---
if __name__ == "__main__":
    # Case: Critical Breach on host1
    current_host = "host1"
    current_score = 14   # from day 34 logic
    current_detections = ["Brute Force", "C2 Beacon", "Suspicious Upload"]
    is_timeline = True

    run_investigation_engine(current_host, current_score, current_detections, is_timeline)