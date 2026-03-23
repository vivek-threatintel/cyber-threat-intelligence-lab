# src/day31_detection.py

def run_full_detection():
    log_data_list = []
    
    # 1. Real Log File se data extract karo (Parser Logic)
    try:
        with open("data/windows_auth.log", "r") as file:
            for line in file:
                line = line.strip()
                if not line: continue
                
                # Split karke data nikalo
                parts = line.split(" ")
                # Example: ['EventID:4625', 'User:admin', 'IP:103.45.67.89', 'Status:FAIL']
                
                log_entry = {
                    'id': parts[0].split(":")[1],
                    'user': parts[1].split(":")[1],
                    'ip': parts[2].split(":")[1],
                    'status': parts[3].split(":")[1]
                }
                log_data_list.append(log_entry)
        
        # 2. Extract hue data ko rules ke pass bhejo
        analyze_logs(log_data_list)

    except FileNotFoundError:
        print("❌ Error: 'data/windows_auth.log' file nahi mili!")

# --- Wahi purana Analysis Logic ---
failed_attempts = {}

def analyze_logs(log_data_list):
    print("--- 🕵️ Running Detection Rules ---")
    for log in log_data_list:
        ip = log['ip']
        eid = log['id']
        
        # Rule: Brute Force
        if eid == "4625":
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
            if failed_attempts[ip] == 5:
                print(f"⚠️  [BRUTE FORCE] IP {ip} exceeded 5 attempts!")

        # Rule: Compromise (Fail -> Success)
        if eid == "4624":
            if failed_attempts.get(ip, 0) >= 3:
                print(f"🚨 [CRITICAL] Possible Account Compromise Detected!")
                print(f"📍 IP: {ip} successfully logged in after failures.")

if __name__ == "__main__":
    run_full_detection()