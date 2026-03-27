def calculate_risk_score(attack_phases):
    """
    Day 34: Threat Scoring Engine
    Input: List of detected phases (e.g., ['brute_force', 'c2_detected'])
    Output: Final Risk Score + Priority Level
    """

    risk_score = 0

    if 'brute_force' in attack_phases:
        risk_score += 4

    if 'c2_detected' in attack_phases:
        risk_score += 6

    if 'anomaly' in attack_phases:
        risk_score += 3

    if 'file_upload' in attack_phases:
        risk_score += 5

    if 'ioc_match' in attack_phases:
        risk_score += 5

    # 2. Priority Logic
    priority = "🟢 LOW"
    if risk_score >= 15:
        priority = "🔴 CRITICAL"
    elif risk_score >= 10:
        priority = "🟠 HIGH"
    elif risk_score >= 5:
        priority = "🟡 MEDIUM"
    
    return risk_score, priority

# --- Simple Test ---
if __name__ == "__main__":
    # Case 1: Full Attack Chain (Kill-Chain)
    detected_activities = ['brute_force', 'c2_detected', 'file_upload']
    score, prio = calculate_risk_score(detected_activities)
    
    print("="*40)
    print("🛡️  THREAT SCORING RESULT")
    print("-" * 40)
    print(f"Detected Phases : {', '.join(detected_activities)}")
    print(f"Final Risk Score: {score}")
    print(f"Alert Priority  : {prio}")
    print("="*40)