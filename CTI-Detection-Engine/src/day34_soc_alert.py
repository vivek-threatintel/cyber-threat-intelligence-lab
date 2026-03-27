# src/day34_soc_alert.py

def generate_soc_alert(host, score, priority, detections):
    """
    Day 34: Final SOC Alert Output Format.
    Displays the summary, score, and specific MITRE tactics detected.
    """
    print("\n" + "!" * 40)
    print("🚨 SOC ALERT: CRITICAL INCIDENT DETECTED".center(40))
    print("!" * 40)
    
    print(f"\n🖥️  Host         : {host}")
    print(f"📊 Threat Score : {score}")
    print(f"🚩 Priority     : {priority}")
    
    print("\n🔍 DETECTED ACTIVITIES:")
    for item in detections:
        print(f"  - {item}")
        
    print("\n" + "!" * 40)
    if score >= 10:
        print("⚠️  ACTION REQUIRED: ISOLATE HOST IMMEDIATELY!")
    print("!" * 40 + "\n")

# --- Scenario Simulation (Step 5) ---
if __name__ == "__main__":
    # Data from Step 4 logic
    host_name = "host1"
    final_score = 14
    prio_level = "🔴 CRITICAL"
    detected_list = ["Brute Force", "C2 Beacon", "Suspicious Upload"]

    # Triggering the Alert
    generate_soc_alert(host_name, final_score, prio_level, detected_list)