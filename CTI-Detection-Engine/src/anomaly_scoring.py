import json

def load_dataset(file_path="data/security_events.json"):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        print(f"Total Events Loaded: {len(data)}")
        return data
    except Exception as e:
        print(f"Error Loading Dataset: {e}")
        return[]

events = load_dataset()

def compute_anomaly_score(event, baseline):
    failed = event.get("failed_logins", 0)
    transfer = event.get("data_transfer", 0)
    requests = event.get("requests", 0)

    failed_dev = abs(failed - baseline["avg_failed_logins"])
    transfer_dev = abs(transfer - baseline["avg_data_transfer"]) / 50
    requests_dev = abs(requests - baseline["avg_requests"]) / 5

    score = failed_dev + transfer_dev + requests_dev
    return score

def classify_anomaly(score):
    if score > 10:
        return "ANOMALY"
    elif score > 5:
        return "SUSPICIOUS"
    else:
        return "NORMAL"

def calculate_baseline(events):
    if not events:
        return {
            "avg_failed_logins": 0,
            "avg_data_transfer": 0,
            "avg_requests": 0
        }

    total_failed = sum(event.get("failed_logins", 0) for event in events)
    total_transfer = sum(event.get("data_transfer", 0) for event in events)
    total_requests = sum(event.get("requests", 0) for event in events)

    count = len(events)

    return {
        "avg_failed_logins": total_failed / count,
        "avg_data_transfer": total_transfer / count,
        "avg_requests": total_requests / count
    }

    print(f"IP: {event['ip']}")
    print(f"  Anomaly Score: {score:.2f}")


baseline = calculate_baseline(events)
print(f"Baseline Failed Logins: {baseline['avg_failed_logins']:.2f}")
print(f"Baseline Data Transfer: {baseline['avg_data_transfer']:.2f}")
print(f"Baseline Requests: {baseline['avg_requests']:.2f}")
print("---")

anomaly_count = 0
suspicious_count = 0
normal_count = 0

for event in events:
    ip = event.get("ip", "unknown")
    failed = event.get("failed_logins", 0)
    transfer = event.get("data_transfer", 0)
    requests = event.get("requests", 0)

    score = compute_anomaly_score(event, baseline)
    level = classify_anomaly(score)

    level = classify_anomaly(score)

    if level == "ANOMALY":
       anomaly_count += 1
    elif level == "SUSPICIOUS":
       suspicious_count += 1
    else:
       normal_count += 1

    print(f"IP: {ip}")
    print(f"  Failed Logins: {failed}")
    print(f"  Data Transfer: {transfer}")
    print(f"  Requests: {requests}")
    print(f"  Anomaly Score: {score:.2f}")
    print(f"  Status: {level}")
    print("---")

print("\nSUMMARY")
print(f"Total Events: {len(events)}")
print(f"Anomaly Events: {anomaly_count}")
print(f"Suspicious Events: {suspicious_count}")
print(f"Normal Events: {normal_count}")
