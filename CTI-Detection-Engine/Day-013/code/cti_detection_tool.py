# ============================================
# MINI CTI DETECTION TOOL
# Day 13 - 500 Days of Code Challenge
# ============================================

# ---------- FUNCTION 1: LOAD THREAT FEED ----------
def load_feed():
    """
    Threat intelligence feed load karta hai
    Returns: Dictionary with IOCs and their risk levels
    """
    threat_feed = {
        "45.33.32.156": "high",
        "evil.com": "high",
        "23.21.11.90": "medium"
    }
    return threat_feed  # ✅ Dictionary return karo


# ---------- FUNCTION 2: ANALYZE LOGS ----------
def analyze_logs(logs, feed):
    """
    Network logs analyze karta hai
    Parameters:
        logs: List of IPs/domains to check
        feed: Threat feed dictionary
    Returns:
        alerts_count: Kitne malicious mile
        safe_count: Kitne safe the
    """
    alerts = 0
    safe = 0
    
    print("\n" + "="*50)
    print("🔍 ANALYZING NETWORK LOGS")
    print("="*50)
    
    # Har log entry check karo
    for item in logs:
        if item in feed:  # Agar threat feed mein hai
            risk = feed[item]  # Risk level nikaalo
            print(f"🚨 ALERT: {item} | Risk Level: {risk.upper()}")
            alerts += 1
        else:  # Safe hai
            print(f"✅ SAFE: {item}")
            safe += 1
    
    return alerts, safe  # ✅ Dono counts return karo


# ---------- FUNCTION 3: GENERATE SUMMARY ----------
def generate_summary(total, alerts, safe):
    """
    Final summary report generate karta hai
    Parameters:
        total: Total logs analyzed
        alerts: Total alerts generated
        safe: Total safe entries
    """
    print("\n" + "="*50)
    print("📊 FINAL SUMMARY REPORT")
    print("="*50)
    print(f"📝 Total logs analyzed: {total}")
    print(f"🚨 Total alerts detected: {alerts}")
    print(f"✅ Safe entries: {safe}")
    
    # Alert percentage bhi dikhao (optional)
    if total > 0:
        alert_percentage = (alerts / total) * 100
        print(f"📈 Alert rate: {alert_percentage:.1f}%")
    
    print("="*50)


# ---------- MAIN FUNCTION ----------
def main():
    """
    Main program execution
    Saare functions ko coordinate karta hai
    """
    # Step 1: Threat feed load karo
    print("\n🚀 STARTING CTI DETECTION TOOL...")
    threat_data = load_feed()
    print(f"✅ Threat feed loaded: {len(threat_data)} IOCs")
    
    # Network logs (real world mein ye file se aate)
    network_logs = [
        "192.168.1.10",
        "45.33.32.156",
        "8.8.8.8",
        "evil.com",
        "10.0.0.5",
        "23.21.11.90"  # Medium risk wala bhi add kiya
    ]
    print(f"✅ Network logs loaded: {len(network_logs)} entries")
    
    # Step 2: Logs analyze karo
    alert_count, safe_count = analyze_logs(network_logs, threat_data)
    
    # Step 3: Summary generate karo
    total_logs = len(network_logs)
    generate_summary(total_logs, alert_count, safe_count)
    
    print("\n✨ Analysis Complete!")


# ---------- PROGRAM START ----------
if __name__ == "__main__":
    main()
