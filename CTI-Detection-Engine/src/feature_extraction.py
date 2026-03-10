import json

def load_dataset(file_path="data/security_events.json"):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        print(f"Total Events Loaded: {len(data)}")
        return data
    except Exception as e:
        print(f"Error Loading dataset: {e}")
        return[]

events = load_dataset()

def calculate_risk_score(features):
    score = features["login_risk"]*2
    score += features["transfer_risk"]/100
    score += features["request_intensity"]/10
    return score

def extract_features(event):
    return {
         "login_risk": event.get("failed_logins", 0),
        "transfer_risk": event.get("data_transfer", 0),
        "request_intensity": event.get("requests", 0)
    }

def print_results(event, features, risk_score):
    print(f"IP: {event['ip']}")
    print(f"  Login Risk: {features['login_risk']}")
    print(f"  Transfer Risk: {features['transfer_risk']}")
    print(f"  Request Intensity: {features['request_intensity']}")
    print(f"  Risk Score: {risk_score:.2f}")
    print("---")

def get_risk_level(risk_score):
    if risk_score > 50:
        return "HIGH RISK"
    elif risk_score > 20:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"

high_risk_count = 0
medium_risk_count = 0
low_risk_count = 0

for event in events:
    features = extract_features(event)
    risk_score = calculate_risk_score(features)
    risk_level = get_risk_level(risk_score)
    print_results(event, features, risk_score)

    if risk_level == "HIGH RISK":
        high_risk_count += 1
    elif risk_level == "MEDIUM RISK":
        medium_risk_count += 1
    else:
        low_risk_count += 1

    print(f"  Risk Level: {risk_level}")

print("\nSUMMARY")
print(f"Total Events: {len(events)}")
print(f"High Risk Events: {high_risk_count}")
print(f"Medium Risk Events: {medium_risk_count}")
print(f"Low Risk Events: {len(events) - high_risk_count - medium_risk_count}")
