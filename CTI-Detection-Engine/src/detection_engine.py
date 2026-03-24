import json

# ────────────────────────────────────────────────
# 1. DATA & BASELINES (Updated for Day 32)
# ────────────────────────────────────────────────

# Mix of Auth logs (Day 31) and DNS logs (Day 32)
event_log = [
    {"ip": "103.45.67.89", "user": "admin", "failed_attempts": 10, "data_mb": 600}, # Critical (Exfil + Intel)
    {"host": "host1", "domain": "evil-c2.com", "time": "10:01"}, # DNS Beaconing Start
    {"host": "host1", "domain": "evil-c2.com", "time": "10:02"},
    {"host": "host1", "domain": "evil-c2.com", "time": "10:03"},
    {"host": "host1", "domain": "evil-c2.com", "time": "10:04"}, # Should Trigger DNS C2 Alert
    {"ip": "192.168.1.50", "user": "dev_user", "failed_attempts": 6, "data_mb": 50}, # Medium (Brute Force)
    {"host": "host1", "domain": "google.com", "time": "10:05"}  # Safe DNS
]

baseline_activity = {
    "normal_failed_logins": 2,
    "normal_data_transfer": 100,
    "safe_domains": ["google.com", "microsoft.com", "github.com", "apple.com"]
}

# ────────────────────────────────────────────────
# 2. DETECTION MODULES
# ────────────────────────────────────────────────

dns_tracker = {}  # Tracks (host, domain) hits

def detect_c2_beaconing(event, baseline):
    """
    Day 32: Detects repetitive queries to unknown domains.
    Rule: Unknown Domain + Frequency > 3 = HIGH Alert.
    """
    host = event.get("host")
    domain = event.get("domain")
    
    if not host or not domain:
        return None

    # Memory check: Count how many times this host queried this domain
    key = (host, domain)
    dns_tracker[key] = dns_tracker.get(key, 0) + 1
    count = dns_tracker[key]

    # Logic: Frequency check + Whitelist check
    if domain not in baseline["safe_domains"] and count > 3:
        return {
            "level": "HIGH",
            "type": "DNS C2 BEACONING (T1071.004)",
            "msg": f"Suspicious 'Heartbeat' detected to {domain} from {host} ({count} hits)."
        }
    return None

def apply_auth_rules(event):
    """Day 30/31: Identity & Data rules."""
    alerts = []
    if event.get('failed_attempts', 0) >= 5:
        alerts.append(f"🚨 [BRUTE FORCE] User '{event['user']}' exceeded threshold.")
    if event.get('data_mb', 0) > 500:
        alerts.append(f"🔥 [EXFILTRATION] High data transfer ({event['data_mb']}MB)")
    return alerts

# ────────────────────────────────────────────────
# 3. MAIN EXECUTION ENGINE
# ────────────────────────────────────────────────

print("="*60)
print("🛡️  CTI DETECTION ENGINE - VERSION 2.1 (DAY 32)".center(60))
print("="*60 + "\n")

critical_count = high_count = medium_count = safe_count = 0

for event in event_log:
    alert_triggered = False
    
    # --- CHECK 1: DNS C2 DETECTION ---
    dns_alert = detect_c2_beaconing(event, baseline_activity)
    if dns_alert:
        print(f"[{dns_alert['level']} ALERT] TYPE: {dns_alert['type']}")
        print(f"  📝 {dns_alert['msg']}")
        high_count += 1
        alert_triggered = True

    # --- CHECK 2: AUTH & DATA DETECTION ---
    auth_alerts = apply_auth_rules(event)
    if auth_alerts:
        # Check for Intelligence/Anomaly (Using your existing logic)
        ip = event.get('ip', 'Unknown')
        print(f"[CRITICAL/HIGH ALERT] IP: {ip}")
        for msg in auth_alerts:
            print(f"  {msg}")
        
        if event.get('data_mb', 0) > 500: critical_count += 1
        else: medium_count += 1
        alert_triggered = True

    # --- CHECK 3: SAFE LOGS ---
    if not alert_triggered:
        # Avoid printing safe internal DNS noise to keep report clean
        if 'domain' not in event:
            print(f"[SAFE] IP: {event.get('ip')} - No major threats detected.")
        else:
            # Silently count safe DNS
            pass
        safe_count += 1
    
    if alert_triggered:
        print("-" * 50)

# ────────────────────────────────────────────────
# 4. FINAL SUMMARY
# ────────────────────────────────────────────────
print("\n" + "="*60)
print("DETECTION SUMMARY".center(60))
print("-" * 60)
print(f"Total Events Analyzed : {len(event_log)}")
print(f"Critical Threats      : {critical_count}")
print(f"High/Medium Alerts    : {high_count + medium_count}")
print(f"Clean/Noise Events    : {safe_count}")
print("="*60)