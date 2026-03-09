import json

# ────────────────────────────────────────────────
# 1. Data & Baseline
# ────────────────────────────────────────────────

event_log = [
    {"ip": "103.45.67.89", "failed_logins": 10, "data_transfer": "high"},
    {"ip": "8.8.8.8", "failed_logins": 0, "data_transfer": "low"},
    {"ip": "malicious-domain.com", "failed_logins": 2, "data_transfer": "medium"},
    {"ip": "192.168.1.10", "failed_logins": 1, "data_transfer": "low"}
]

baseline_activity = {
    "normal_failed_logins": 2,
    "normal_data_transfer": "low"
}


# ────────────────────────────────────────────────
# 2. Loading Functions
# ────────────────────────────────────────────────

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


def load_baseline():
    return baseline_activity


# ────────────────────────────────────────────────
# 3. Detection Functions
# ────────────────────────────────────────────────

def detect_anomaly(event, baseline):
    failed = event.get("failed_logins", 0)
    transfer = event.get("data_transfer", "unknown")

    reasons = []

    if failed > baseline["normal_failed_logins"]:
        reasons.append(f"excessive failed logins ({failed} > {baseline['normal_failed_logins']})")

    if transfer != baseline["normal_data_transfer"]:
        reasons.append(f"unusual data transfer ({transfer} != {baseline['normal_data_transfer']})")

    is_anomaly = len(reasons) > 0

    # Risk level for correlation
    if reasons:
        num_reasons = len(reasons)
        if num_reasons >= 2 or failed > 10:
            risk = "CRITICAL"
        elif num_reasons == 1:
            risk = "HIGH"
        else:
            risk = "SUSPICIOUS"
    else:
        risk = "LOW"

    return is_anomaly, reasons, risk


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


def generate_alert(is_anomaly, intel_match):
    if is_anomaly and intel_match:
        return "CRITICAL"
    elif is_anomaly:
        return "MEDIUM"
    elif intel_match:
        return "HIGH"
    else:
        return "SAFE"


# ────────────────────────────────────────────────
# 4. Main Engine
# ────────────────────────────────────────────────

lookup_db = load_lookup()
feed = load_feed()
baseline = load_baseline()

feed_iocs = set()
for entry in feed:
    ioc = entry.get("ioc")
    if isinstance(ioc, str) and ioc.strip():
        feed_iocs.add(ioc.strip())

critical_count = high_count = medium_count = safe_count = 0

print("=== CTI Detection Engine Report ===\n")

for event in event_log:
    ip = event.get("ip", "unknown")
    failed = event.get("failed_logins", 0)
    transfer = event.get("data_transfer", "unknown")

    is_anomaly, reasons, behaviour_risk = detect_anomaly(event, baseline)

    intel_match, enriched = match_intelligence(ip, feed_iocs, lookup_db)

    alert_level = generate_alert(is_anomaly, intel_match)

    # Update counters
    if alert_level == "CRITICAL":
        critical_count += 1
    elif alert_level == "HIGH":
        high_count += 1
    elif alert_level == "MEDIUM":
        medium_count += 1
    else:
        safe_count += 1

    # Print alert
    if alert_level != "SAFE":
        print(f"*** {alert_level} ALERT ***")
        print(f"IP: {ip}")
        print(f"  Anomaly Detected: {'Yes' if is_anomaly else 'No'}")
        print(f"  Threat Feed Match: {'YES' if intel_match else 'NO'}")
        print(f"  Behaviour Risk: {behaviour_risk}")
        print(f"  Failed Logins: {failed}")
        print(f"  Data Transfer: {transfer}")

        if enriched:
            print("  Enrichment:")
            print(f"    Country: {enriched['country']}")
            print(f"    Malware Family: {enriched['malware_family']}")
            print(f"    First Seen: {enriched['first_seen']}")

        if reasons:
            print("  Anomaly Reasons:")
            for r in reasons:
                print(f"    - {r}")

        print("-" * 60 + "\n")
    else:
        print(f"SAFE: {ip} (no anomaly, no threat match)")
        print("---\n")

# Final Summary
print("=" * 60)
print("DETECTION ENGINE SUMMARY".center(60))
print("=" * 60)
print(f"Logs Processed          : {len(event_log)}")
print(f"Total Threat Matches    : {critical_count + high_count + medium_count}")
print(f"  Critical Alerts       : {critical_count}")
print(f"  High Alerts           : {high_count}")
print(f"  Medium Alerts         : {medium_count}")
print(f"  Safe Events           : {safe_count}")
print("-" * 60)
