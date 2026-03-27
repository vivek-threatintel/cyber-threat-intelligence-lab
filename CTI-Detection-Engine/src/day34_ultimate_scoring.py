def calculate_smart_score(detected_phases, timeline_found=False):
    """
    Day 34: Smart Scoring with Timeline Context.
    Adds +5 if the events are correlated in a sequence.
    """

    risk_score = 0

    mapping = {
        'brute_force': 4,
        'c2_detected': 6,
        'anomaly': 3,
        'file_upload': 5,
        'ioc_match': 5
    }

    for phase in detected_phases:
        risk_score += mapping.get(phase, 0)

    if timeline_found:
        print("🔗 [CONTEXT]: Attack Timeline Detected! Adding +5 correlation bonus.")
        risk_score += 5

    return risk_score

def get_priority(score):
    if score >= 10: return "🔴 CRITICAL"
    if score >= 7:  return "🟠 HIGH"
    if score >= 4:  return "🟡 MEDIUM"
    return "🟢 LOW"

if __name__ == "__main__":
    # Attacker only did Brute Force
    phases = ['brute_force']
    
    # Scenario A: No Timeline (Just random noise)
    score_a = calculate_smart_score(phases, timeline_found=False)
    
    # Scenario B: Timeline Found (Brute force leads to something else)
    # Even with just Brute Force + Correlation, the score jumps!
    score_b = calculate_smart_score(phases, timeline_found=True)

    print("\n" + "="*40)
    print(f"SCENARIO A (No Context): Score {score_a} -> {get_priority(score_a)}")
    print(f"SCENARIO B (Timeline):   Score {score_b} -> {get_priority(score_b)}")
    print("="*40)