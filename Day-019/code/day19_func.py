import json

baseline_activity = {
    "normal_failed_logins": 2,
    "normal_data_transfer": "low"
}

event_log = [
 {"ip": "103.45.67.89", "failed_logins": 10, "data_transfer": "high"},
 {"ip": "8.8.8.8", "failed_logins": 1, "data_transfer": "low"},
 {"ip": "23.21.11.90", "failed_logins": 4, "data_transfer": "medium"}
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

lookup_db = load_lookup()
feed = load_feed()

feed_iocs = set()
for entry in feed:
    ioc = entry.get("ioc")
    if isinstance(ioc, str) and ioc.strip():
        feed_iocs.add(ioc.strip())

def load_baseline():
    return {
        "normal_failed_logins": 2,
        "normal_data_transfer": "low"
    }

def check_threat_feed(ip, feed_iocs, lookup_db):
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

def detect_anomaly(event, baseline):
    failed = event.get("failed_logins", 0)
    transfer = event.get("data_transfer", "unknown")

    reasons = []

    if failed > baseline["normal_failed_logins"]:
        reasons.append("excessive failed logins")
    if transfer != baseline["normal_data_transfer"]:
        reasons.append(f"unusual data transfer ({transfer})")

    is_anomaly = len(reasons) > 0
    return is_anomaly, reasons

critical_count = warning_count = alert_count = 0

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

critical_count = warning_count = alert_count = threat_matches = 0

for event in event_log:
    ip = event.get("ip", "unknown")
    failed = event.get("failed_logins", 0)
    transfer = event.get("data_transfer", "unknown")

    print(f"IP: {ip}")
    print(f"  Failed Logins: {failed}")
    print(f"  Data Transfer: {transfer}")

    # Behaviour
    behaviour_risk, reasons = detect_anomaly(event, baseline_activity)

    if behaviour_risk != "LOW":
        print("ANOMALY DETECTED")
        for r in reasons:
            print(f"  Reason: {r}")
    else:
        print("Normal activity")

    # Intel
    intel_match, enriched = match_intelligence(ip, feed_iocs, lookup_db)

    print(f"  Threat Feed Match: {'YES' if intel_match else 'NO'}")
    if enriched:
        print(f"  Country: {enriched['country']}")
        print(f"  Malware Family: {enriched['malware_family']}")
        print(f"  First Seen: {enriched['first_seen']}")

    # Generate alert
    final_alert = generate_alert(behaviour_risk, intel_match)

    if final_alert != "SAFE":
        threat_matches += 1
        if final_alert == "CRITICAL":
            critical_count += 1
        elif final_alert == "WARNING":
            warning_count += 1
        elif final_alert == "ALERT":
            alert_count += 1

        print(f"*** {final_alert} ***")
    else:
        print("SAFE")

    print("---")

print("\nSUMMARY")
print(f"Total Events: {len(event_log)}")
print(f"Critical: {critical_count}")
print(f"Warning: {warning_count}")
print(f"Alert: {alert_count}")
