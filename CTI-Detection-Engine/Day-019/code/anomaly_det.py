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

for event in event_log:
    ip = event.get("ip", "unknown")
    is_anomaly, reasons = detect_anomaly(event, baseline_activity)

    intel_match = ip in feed_iocs
    enriched = {}
    if intel_match and ip in lookup_db:
        info = lookup_db[ip]
        enriched = {
            "country": info.get("country", "N/A"),
            "malware_family": info.get("malware_family", "N/A"),
            "first_seen": info.get("first_seen", "N/A")
        }
    alert_level = "SAFE"

    if is_anomaly and intel_match:
            alert_level = "CRITICAL"
    elif is_anomaly:
            alert_level = "WARNING"
    elif intel_match:
            alert_level = "ALERT"

    if alert_level == "CRITICAL":
        critical_count += 1
    elif alert_level == "WARNING":
        warning_count += 1
    elif alert_level == "ALERT":
        alert_count += 1

    print(f"IP: {ip}")
    print(f"  Failed Logins: {event.get('failed_logins')}")
    print(f"  Data Transfer: {event.get('data_transfer')}")

    if is_anomaly:
        print("ANOMALY DETECTED")
        for r in reasons:
            print(f"  Reason: {r}")
    else:
        print("Normal activity")
    print(f"  Threat Feed Match: {'YES' if intel_match else 'NO'}")
    if enriched:
        print(f"  Country: {enriched['country']}")
        print(f"  Malware Family: {enriched['malware_family']}")
        print(f"  First Seen: {enriched['first_seen']}")

    if alert_level != "SAFE":
        print(f"*** {alert_level} ***")
    else:
        print("SAFE")

    print("---")

print("\nSUMMARY")
print(f"Total Events: {len(event_log)}")
print(f"Critical: {critical_count}")
print(f"Warning: {warning_count}")
print(f"Alert: {alert_count}")
