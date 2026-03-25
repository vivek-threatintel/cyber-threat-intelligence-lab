import json

# ────────────────────────────────────────────────
# 1. DATA & BASELINES
# ────────────────────────────────────────────────

# Combined Logs: Isme saare types ke attack signs hain
event_log = [
    {"time": "10:01", "ip": "103.45.67.89", "user": "admin", "failed_attempts": 10, "data_mb": 600, "type": "AUTH", "status": "FAIL"},
    {"time": "10:02", "host": "host1", "domain": "evil-c2.com", "type": "DNS"},
    {"time": "10:03", "host": "host1", "domain": "evil-c2.com", "type": "DNS"},
    {"time": "10:04", "host": "host1", "domain": "evil-c2.com", "type": "DNS"},
    {"time": "10:05", "host": "host1", "domain": "evil-c2.com", "type": "DNS"}, # DNS Beacon Trigger
    {"time": "10:06", "host": "host1", "file": "suspicious.exe", "type": "HTTP"}, # Execution
    {"time": "10:07", "ip": "192.168.1.50", "user": "dev_user", "failed_attempts": 6, "data_mb": 50, "type": "AUTH", "status": "FAIL"}
]

baseline_activity = {
    "normal_failed_logins": 2,
    "normal_data_transfer": 100,
    "safe_domains": ["google.com", "microsoft.com", "github.com"]
}

# 🧠 Engine Memory (Trackers)
dns_tracker = {}
incident_timeline = []

# ────────────────────────────────────────────────
# 2. DETECTION MODULES
# ────────────────────────────────────────────────

def detect_c2_beaconing(event, baseline):
    """Day 32: DNS Pattern Recognition"""
    host, domain = event.get("host"), event.get("domain")
    if not host or not domain: return None

    key = (host, domain)
    dns_tracker[key] = dns_tracker.get(key, 0) + 1
    
    if domain not in baseline["safe_domains"] and dns_tracker[key] > 3:
        return {"level": "HIGH", "type": "DNS C2 (T1071.004)", "msg": f"Beaconing to {domain}"}
    return None

def detect_attack_timeline(event):
    """Day 33: Multi-Stage Correlation (The Detective)"""
    # Stage 1: Initial Access
    if event.get('type') == 'AUTH' and event.get('failed_attempts', 0) > 5:
        return {"stage": "Initial Access", "tech": "T1110 (Brute Force)"}
    
    # Stage 2: Command & Control
    if event.get('type') == 'DNS' and "evil" in event.get('domain', ''):
        return {"stage": "Command & Control", "tech": "T1071.004 (DNS Beacon)"}
    
    # Stage 3: Execution
    if event.get('type') == 'HTTP' and '.exe' in event.get('file', ''):
        return {"stage": "Execution", "tech": "T1059 (Malware Drop)"}
    
    return None

# ────────────────────────────────────────────────
# 3. MAIN INTEGRATED ENGINE
# ────────────────────────────────────────────────

def run_ultimate_engine(logs, baseline):
    print("="*60)
    print("🛡️  CTI DETECTION ENGINE - ULTIMATE V3.0".center(60))
    print("="*60)

    stats = {"CRITICAL": 0, "HIGH": 0, "SAFE": 0}

    for log in logs:
        alert_found = False
        
        # A. Check for Individual Rules (DNS/Auth/Exfil)
        dns_alert = detect_c2_beaconing(log, baseline)
        if dns_alert:
            print(f"[HIGH ALERT] {dns_alert['type']}: {dns_alert['msg']}")
            stats["HIGH"] += 1
            alert_found = True

        # B. Check for Timeline Correlation (The Chain)
        attack_step = detect_attack_timeline(log)
        if attack_step:
            print(f"🚩 [PHASE DETECTED]: {attack_step['stage']} | Tech: {attack_step['tech']}")
            incident_timeline.append(attack_step)
            alert_found = True

        if not alert_found and log.get('type') == 'AUTH':
            print(f"[SAFE] Activity from IP: {log.get('ip')} is normal.")
            stats["SAFE"] += 1

    # Final Verdict Logic
    if len(incident_timeline) >= 3:
        print("\n" + "!"*60)
        print("🚨 CRITICAL VERDICT: FULL ATTACK CHAIN IDENTIFIED!")
        print("⚠️  Status: SYSTEM BREACH CONFIRMED (Kill-Chain Complete)")
        print("!"*60)
        stats["CRITICAL"] += 1

    return stats

# ────────────────────────────────────────────────
# 4. EXECUTION & SUMMARY
# ────────────────────────────────────────────────

if __name__ == "__main__":
    results = run_ultimate_engine(event_log, baseline_activity)
    
    print("\n" + "="*60)
    print("DETECTION SUMMARY".center(60))
    print("-" * 60)
    print(f"Total Logs Analyzed : {len(event_log)}")
    print(f"Critical Breaches   : {results['CRITICAL']}")
    print(f"High Risk Alerts    : {results['HIGH']}")
    print(f"Clean Events        : {results['SAFE']}")
    print("="*60)