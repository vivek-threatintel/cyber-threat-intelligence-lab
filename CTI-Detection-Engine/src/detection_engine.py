import json

# 🚨 Mocking the missing imports for demonstration
# Asal mein aapka 'from threat_api_client import ...' yahan rahega
def query_threat_api(ip): return {"status": "success", "data": {}}
def parse_api_response(data): return {"abuse_score": 85, "country": "US", "isp": "Cloudflare"}

# ────────────────────────────────────────────────
# 1. Data & Baseline (Updated keys to match Rules)
# ────────────────────────────────────────────────

event_log = [
    {"ip": "103.45.67.89", "user": "admin", "failed_attempts": 10, "data_mb": 600},
    {"ip": "8.8.8.8", "user": "guest", "failed_attempts": 0, "data_mb": 10},
    {"ip": "192.168.1.50", "user": "dev_user", "failed_attempts": 6, "data_mb": 50},
    {"ip": "192.168.1.10", "user": "hr_mgr", "failed_attempts": 1, "data_mb": 5}
]

baseline_activity = {
    "normal_failed_logins": 2,
    "normal_data_transfer": 100  # MB mein
}

# ────────────────────────────────────────────────
# 2. Loading & Detection Functions
# ────────────────────────────────────────────────

def load_lookup():
    # Mock lookup for testing
    return {"103.45.67.89": {"country": "CN", "malware_family": "Mirai", "first_seen": "2023-10-01"}}

# Tracker to remember failed attempts per IP
failed_tracker = {} 

def detect_account_compromise(event):
    """
    Analyzes a single event and correlates it with past failures 
    to detect a successful breach.
    """
    ip = event.get('ip')
    event_id = event.get('id')
    user = event.get('user')

    # 1. Agar login FAIL hua, toh use register mein note karo
    if event_id == "4625":
        failed_tracker[ip] = failed_tracker.get(ip, 0) + 1
        return None # Abhi sirf failure hai, compromise nahi

    # 2. Agar login SUCCESS hua, toh check karo purana record
    if event_id == "4624":
        fail_count = failed_tracker.get(ip, 0)
        
        if fail_count >= 3:
            # MITRE Mapping: T1110 (Brute Force leading to compromise)
            alert = {
                "severity": "CRITICAL",
                "rule": "Possible Account Compromise (T1110)",
                "details": f"User '{user}' breached by IP {ip} after {fail_count} failed attempts."
            }
            # Success ke baad hum tracker ko reset kar sakte hain (optional)
            failed_tracker[ip] = 0 
            return alert
            
    return None

# --- Main Engine Integration ---
def process_logs(logs):
    print("🚀 Detection Engine is Processing Windows Logs...\n")
    for log in logs:
        alert = detect_account_compromise(log)
        if alert:
            print(f"[{alert['severity']}] {alert['rule']}")
            print(f"MSG: {alert['details']}\n")

def apply_rules(event):
    """Core Rule Engine: Checks specific security thresholds."""
    alerts = []
    if event.get('failed_attempts', 0) >= 5:
        alerts.append(f"🚨 [BRUTE FORCE] User '{event['user']}' exceeded threshold.")
    
    authorized_ips = ["192.168.1.1", "192.168.1.10", "8.8.8.8"]
    if event.get('ip') not in authorized_ips:
        alerts.append(f"⚠️  [NETWORK] Connection from unauthorized IP: {event['ip']}")

    if event.get('data_mb', 0) > 500:
        alerts.append(f"🔥 [EXFILTRATION] High data transfer ({event['data_mb']}MB)")
    return alerts

def detect_anomaly(event, baseline):
    reasons = []
    failed = event.get("failed_attempts", 0)
    data = event.get("data_mb", 0)

    if failed > baseline["normal_failed_logins"]:
        reasons.append(f"Excessive logins ({failed})")
    if data > baseline["normal_data_transfer"]:
        reasons.append(f"Unusual data volume ({data}MB)")

    risk = "LOW"
    if len(reasons) >= 2 or failed > 8: risk = "CRITICAL"
    elif len(reasons) == 1: risk = "HIGH"
    
    return len(reasons) > 0, reasons, risk

def match_intelligence(ip, lookup_db):
    # Simplified logic for local + API check
    if ip in lookup_db:
        info = lookup_db[ip]
        info["source"] = "Local Database"
        return True, info
    return False, {}

def generate_alert_level(is_anomaly, intel_match):
    if is_anomaly and intel_match: return "CRITICAL"
    if intel_match: return "HIGH"
    if is_anomaly: return "MEDIUM"
    return "SAFE"

# ────────────────────────────────────────────────
# 3. Main Engine Execution
# ────────────────────────────────────────────────

lookup_db = load_lookup()
critical_count = high_count = medium_count = safe_count = 0

print("="*60)
print("🛡️  CTI DETECTION ENGINE REPORT".center(60))
print("="*60 + "\n")

for event in event_log:
    ip = event['ip']
    
    # Run Detection Logic
    rule_alerts = apply_rules(event)
    is_anomaly, reasons, behaviour_risk = detect_anomaly(event, baseline_activity)
    intel_match, enriched = match_intelligence(ip, lookup_db)
    
    # Final Alert Level
    alert_level = generate_alert_level(is_anomaly, intel_match)

    # Counter Update
    if alert_level == "CRITICAL": critical_count += 1
    elif alert_level == "HIGH": high_count += 1
    elif alert_level == "MEDIUM": medium_count += 1
    else: safe_count += 1

    # Printing Logic
    if alert_level != "SAFE":
        print(f"[{alert_level} ALERT] IP: {ip}")
        
        # Print Rule matches
        for msg in rule_alerts:
            print(f"  {msg}")
            
        # Print Enrichment
        if enriched:
            print(f"  🔍 Intelligence Found ({enriched['source']}):")
            print(f"     Family: {enriched.get('malware_family', 'N/A')} | Country: {enriched.get('country', 'N/A')}")
        
        # Print Reasons
        if reasons:
            print(f"  📝 Analysis: {', '.join(reasons)}")
            
        print("-" * 50)
    else:
        print(f"[SAFE] IP: {ip} - No major threats detected.")
        print("-" * 50)

# Final Summary Table
print("\n" + "="*60)
print("DETECTION SUMMARY".center(60))
print("-" * 60)
print(f"Total Logs Analyzed : {len(event_log)}")
print(f"Critical Threats    : {critical_count}")
print(f"High/Medium Alerts  : {high_count + medium_count}")
print(f"Clean Events        : {safe_count}")
print("="*60)
