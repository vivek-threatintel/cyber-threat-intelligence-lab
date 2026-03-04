import json

network_log = [
    "103.45.67.89",
    "8.8.8.8",
    "malicious-domain.com",
    "192.168.1.10"
]

def load_lookup(file_path="ioc_lookup.json"):
    try:
        with open (file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {file_path} not found")
        return{}
    except json.JSONDecodeError:
        print("The JSON formot is incorrect in the lookup file")
        return{}

def load_feed(file_path="external_feed.json"):
    try:
       with open (file_path, "r") as f:
        return json.load(f)
    except Exception as e:
        print(f"Feed load error: {e}")
        return []

def analyze_logs(network_log, lookup_db, feed_iocs):

    high_risk_count = 0
    medium_risk_count = 0
    threat_matches = 0

    for log_entry in network_log:
        log_entry = log_entry.strip()

        if log_entry not in feed_iocs:
            print(f"SAFE: {log_entry}")
            continue

        if log_entry in lookup_db:
            info = lookup_db[log_entry]
            confidence = "high"
            malware = info.get("malware_family", "N/A")

            if malware and malware != "N/A":
                risk = "HIGH RISK"
                high_risk_count += 1
            else:
                risk = "MEDIUM RISK"
                medium_risk_count += 1
            threat_matches += 1

            print("=== ALERT DETECTED ===")
            print(f"IOC: {log_entry}")
            print(f"Confidence: {confidence}")
            print(f"Country: {info.get('country', 'N/A')}")
            print(f"Malware Family: {malware}")
            print(f"Risk Level: {risk}")
            print()

    print("=" * 50)
    print("SUMMARY")
    print("-" * 50)
    print(f"Total Logs Analyzed   : {len(network_log)}")
    print(f"Threat Matches        : {threat_matches}")
    print(f"High Risk Alerts      : {high_risk_count}")
    print(f"Medium Risk Alerts    : {medium_risk_count}")

    return {
        "total_logs": len(network_log),
        "threat_matches": threat_matches,
        "high_risk": high_risk_count,
        "medium_risk": medium_risk_count
    }

if __name__ == "__main__":
    lookup = load_lookup()
    feed = load_feed()

    feed_iocs = []
    for entry in feed:
        if isinstance(entry, dict) and "ioc" in entry:
            ioc_val = str(entry["ioc"]).strip()
            if ioc_val:
                feed_iocs.append(entry["ioc"].strip())

    print("\nStarting network log analysis...\n")
    results = analyze_logs(network_log, lookup, feed_iocs)
