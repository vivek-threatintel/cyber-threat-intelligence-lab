import json

event_log = [
    {"ip": "103.45.67.89", "failed_logins": 10, "data_transfer": "high"},
    {"ip": "8.8.8.8", "failed_logins": 0, "data_transfer": "low"},
    {"ip": "malicious-domain.com", "failed_logins": 3, "data_transfer": "medium"},
    {"ip": "192.168.1.10", "failed_logins": 1, "data_transfer": "low"}
]

def load_lookup(file_path="ioc_lookup.json"):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {file_path} not found")
        return {}
    except json.JSONDecodeError:
        print("The JSON format is incorrect in the lookup file")
        return {}

def load_feed(file_path="external_feed.json"):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Feed load error: {e}")
        return []

def detect_behavior(event):
    failed = event.get("failed_logins", 0)
    transfer = event.get("data_transfer", "unknown")
    
    suspicious_reasons = []
    if failed > 5:
        suspicious_reasons.append("Excessive failed logins")
    if transfer == "high":
        suspicious_reasons.append("High data transfer")
    
    if suspicious_reasons:
        num_reasons = len(suspicious_reasons)
        if num_reasons >= 2 or failed > 10:
            risk = "CRITICAL"
        elif num_reasons == 1:
            risk = "HIGH"
        else:
            risk = "SUSPICIOUS"
    else:
        risk = "LOW"
    
    return risk, suspicious_reasons

def match_intelligence(ip, feed_iocs, lookup_db):
    intel_match = ip in feed_iocs
    enriched = {}
    if intel_match and ip in lookup_db:
        info = lookup_db[ip]
        enriched = {
            "country": info.get("country", "N/A"),
            "malware_family": info.get("malware_family", "N/A"),
            "first_seen": info.get("first_seen", "N/A")
        }
    return intel_match, enriched

def generate_alert(behaviour_risk, intel_match):
    final_alert = "SAFE"
    if intel_match:
        if behaviour_risk == "CRITICAL":
            final_alert = "CRITICAL ALERT"
        elif behaviour_risk in ["HIGH", "SUSPICIOUS"]:
            final_alert = "HIGH ALERT"
        else:
            final_alert = "MEDIUM ALERT"
    else:
        if behaviour_risk in ["CRITICAL", "HIGH"]:
            final_alert = "MEDIUM ALERT"
        elif behaviour_risk == "SUSPICIOUS":
            final_alert = "LOW ALERT"
    return final_alert

# Main execution
lookup_db = load_lookup()
feed = load_feed()

feed_iocs = set()
for entry in feed:
    ioc = entry.get("ioc")
    if isinstance(ioc, str) and ioc.strip():
        feed_iocs.add(ioc.strip())

critical_count = high_count = medium_count = low_count = threat_matches = 0

for event in event_log:
    ip = event.get("ip", "unknown")
    failed = event.get("failed_logins", 0)
    transfer = event.get("data_transfer", "unknown")

    print(f"IOC: {ip}")
    print(f"  Failed Logins: {failed}")
    print(f"  Data Transfer: {transfer}")

    behaviour_risk, suspicious_reasons = detect_behavior(event)

    if behaviour_risk != "LOW":
        print("--> Suspicious Behaviour!")
        for r in suspicious_reasons:
            print(f"   - {r}")
        print(f"  Behaviour Risk: {behaviour_risk}")
    else:
        print(" --> Clean Behaviour")
        print("  Behaviour Risk: LOW")

    intel_match, enriched = match_intelligence(ip, feed_iocs, lookup_db)

    print(f"  Threat Feed Match: {'YES' if intel_match else 'NO'}")
    if enriched:
        print(f"  Country: {enriched['country']}")
        print(f"  Malware Family: {enriched['malware_family']}")
        print(f"  First Seen: {enriched['first_seen']}")

    final_alert = generate_alert(behaviour_risk, intel_match)

    if final_alert != "SAFE":
        threat_matches += 1
        if final_alert == "CRITICAL ALERT":
            critical_count += 1
        elif final_alert == "HIGH ALERT":
            high_count += 1
        elif final_alert == "MEDIUM ALERT":
            medium_count += 1
        elif final_alert == "LOW ALERT":
            low_count += 1

        print(f"\n=== {final_alert} ===")
        print(f"IOC: {ip}")
        print(f"  Threat Feed Match: {'YES' if intel_match else 'NO'}")
        print(f"  Behaviour Risk: {behaviour_risk}")
        print(f"  Failed Logins: {failed}")
        print(f"  Data Transfer: {transfer}")
        if enriched:
            print(f"  Country: {enriched['country']}")
            print(f"  Malware Family: {enriched['malware_family']}")
            print(f"  First Seen: {enriched['first_seen']}")
        if suspicious_reasons:
            print("  Reasons:")
            for r in suspicious_reasons:
                print(f"    - {r}")
        print("-" * 60)
    else:
        print(f"SAFE: {ip}")
        print("---")

# Summary
print("\n" + "=" * 60)
print("SUMMARY REPORT".center(60))
print("=" * 60)
print(f"Total Logs Analyzed     : {len(event_log)}")
print(f"Threat Matches          : {threat_matches}")
print(f"Critical Alerts         : {critical_count}")
print(f"High Alerts             : {high_count}")
print(f"Medium Alerts           : {medium_count}")
print(f"Low Alerts              : {low_count}")
print("-" * 60)
