def check_bruteforce(detections):
    if "Brute Force" in detections:
        return "[FOUND] T1110: 10+ Failed attempts detected from IP 103.45.67.89."
    return "[CLEAN] No significant failed login patterns."

def check_c2(detections):
    if "C2 Beacon" in detections:
        return "[Found] T1017: Outbound heartbeat to 'evil-c2.com' (Freq: 5/min)."
    return "[CLEAN] No suspicious outbound beaconing."

def check_execution(detections):
    if "Suspicious Upload" in detections:
        return "[FOUND] T1059: File 'suspicious.exe' uploaded via HTTP/80."
    return "[CLEAN] No unauthorized file execution found."

def check_ioc_match(detections):
    if "IOC Match" in detections:
        return "[FOUND] Known Malicious IP 103.45.67.89 matched in Blacklist."
    return "[CLEAN] No known IOCs matched."

def run_all_checks(host, detections):
    print(f"\n--- 🧪 Detailed Investigation Findings for {host} ---")

    findings = [
        check_bruteforce(detections),
        check_c2(detections),
        check_execution(detections),
        check_ioc_match(detections)
    ]

    for finding in findings:
        print(f"  {finding}")

    print("_" * 50)

# --- Simulation ---
if __name__ == "__main__":
    current_host = "host1"
    # Detections list from previous steps
    current_detections = ["Brute Force", "C2 Beacon", "Suspicious Upload", "IOC Match"]

    run_all_checks(current_host, current_detections)