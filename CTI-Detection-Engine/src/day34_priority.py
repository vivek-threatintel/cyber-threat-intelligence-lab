def get_alert_priority(score):
    """
    Day 34: Logic to categorize threats based on cumulative score.
    """
    if score >= 10:
        return "🔴 CRITICAL"
    elif score >= 7:
        return "🟠 HIGH"
    elif score >= 4:
        return "🟡 MEDIUM"
    else:
        return "🟢 LOW"

if __name__ == "__main__":
    current_score = 13
    priority_level = get_alert_priority(current_score)

    print("="*40)
    print("🚨 INCIDENT PRIORITIZATION REPORT")
    print("-" * 40)
    print(f"Final Threat Score: {current_score}")
    print(f"Priority Level     : {priority_level}")
    
    if current_score >= 10:
        print("\n📝 ACTION: Trigger Incident Response (IR) Protocol!")
    print("="*40)