# src/day30_rule_engine.py

def run_multi_rule_engine(logs):
    # --- THRESHOLDS (Settings) ---
    FAILED_LOGIN_LIMIT = 5
    DATA_TRANSFER_LIMIT = 500  # MB mein
    AUTHORIZED_IPS = ["192.168.1.1", "10.0.0.5"]

    # --- TRACKERS (Memory) ---
    user_failures = {}
    
    print("🚀 Multi-Rule Detection Engine Active...\n")

    for log in logs:
        user = log.get('user', 'Unknown')
        ip = log.get('ip', '0.0.0.0')
        status = log.get('status', 'N/A')
        data_size = log.get('data_mb', 0)

        # 1️⃣ RULE: BRUTE FORCE (Identity Protection)
        if status == "failed":
            user_failures[user] = user_failures.get(user, 0) + 1
            if user_failures[user] >= FAILED_LOGIN_LIMIT:
                print(f"🚨 [ALERT] Brute Force: User '{user}' exceeded {FAILED_LOGIN_LIMIT} failed attempts!")

        # 2️⃣ RULE: SUSPICIOUS IP (Network Protection)
        if ip not in AUTHORIZED_IPS:
            print(f"⚠️  [WARNING] Suspicious IP: Connection from unauthorized source [{ip}] for user [{user}]")

        # 3️⃣ RULE: HIGH DATA TRANSFER (Data Protection)
        if data_size > DATA_TRANSFER_LIMIT:
            print(f"🔥 [CRITICAL] Data Exfiltration: Unusual data transfer ({data_size}MB) detected from IP [{ip}]!")

    print("\n✅ All logs analyzed. System Secure.")

# --- MOCK LOGS (The Attack Scenario) ---
attack_scenario = [
    {'user': 'admin', 'status': 'failed', 'ip': '192.168.1.1'},
    {'user': 'finance_lead', 'status': 'success', 'ip': '103.45.67.89', 'data_mb': 850}, # Rule 2 & 3 Hit
    {'user': 'admin', 'status': 'failed', 'ip': '192.168.1.1'},
    {'user': 'admin', 'status': 'failed', 'ip': '192.168.1.1'},
    {'user': 'admin', 'status': 'failed', 'ip': '192.168.1.1'},
    {'user': 'admin', 'status': 'failed', 'ip': '192.168.1.1'}, # Rule 1 Hit
]

if __name__ == "__main__":
    run_multi_rule_engine(attack_scenario)