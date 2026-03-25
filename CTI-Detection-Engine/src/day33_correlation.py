import os

# 1. PARSER FUNCTION (Pehle Define Karo)
def parse_combined_logs(file_path):
    timeline = []
    if not os.path.exists(file_path):
        print(f"❌ Error: {file_path} nahi mili!")
        return []

    with open(file_path, "r") as file:
        for line in file:
            parts = line.strip().split(" ")
            if len(parts) < 3: continue
            
            log_type = parts[1]
            entry = {"time": parts[0], "type": log_type}

            if log_type == "DNS":
                entry.update({"host": parts[2], "domain": parts[3]})
            elif log_type == "AUTH":
                entry.update({"user": parts[2], "ip": parts[3], "status": parts[4]})
            elif log_type == "HTTP":
                entry.update({"host": parts[2], "path": parts[3], "file": parts[4]})
            elif log_type == "DATA":
                entry.update({"host": parts[2], "dest_ip": parts[3], "size": parts[4]})
            
            timeline.append(entry)
    return timeline

# 2. CORRELATION LOGIC (Dots Connect Karo)
def correlate_attack_chain(timeline):
    has_brute_force = any(e['type'] == 'AUTH' and e['status'] == 'FAIL' for e in timeline)
    has_success = any(e['type'] == 'AUTH' and e['status'] == 'SUCCESS' for e in timeline)
    has_c2 = any(e['type'] == 'DNS' and "evil-c2.com" in e['domain'] for e in timeline)
    has_upload = any(e['type'] == 'HTTP' and '.exe' in e['file'] for e in timeline)

    print("\n" + "="*60)
    print("📜 ATTACK TIMELINE DETECTED".center(60))
    print("="*60)

    if has_brute_force: print("  ↳ [Initial Access] Brute Force activity found.")
    if has_success:     print("  ↳ [Privilege Escalation] SUCCESSFUL login detected.")
    if has_c2:          print("  ↳ [Command & Control] DNS Beaconing to evil-c2.com.")
    if has_upload:      print("  ↳ [Execution] Suspicious file upload (.exe) found.")

    print("-" * 60)
    if has_success and has_c2:
        print("🚩 VERDICT: CONFIRMED COMPROMISE! (System is breached)")
    elif has_brute_force:
        print("⚠️  VERDICT: ACTIVE ATTACK! (Brute force in progress)")
    print("="*60)

# 3. MAIN EXECUTION (Sabse Neeche Call Karo)
if __name__ == "__main__":
    log_file = "data/combined_logs.txt"
    print(f"🚀 Starting Unified Detection Engine on {log_file}...")
    
    # Direct Function Call (No Import Needed)
    parsed_logs = parse_combined_logs(log_file)
    
    if parsed_logs:
        correlate_attack_chain(parsed_logs)
    else:
        print("❌ Analyze karne ke liye koi logs nahi mile.")