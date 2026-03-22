# fake security event data

events = [
    {"ip": "8.8.8.8", "failed_logins": 2, "data_transfer": "low"},
    {"ip": "45.33.32.1", "failed_logins": 15, "data_transfer": "high"},
    {"ip": "192.168.1.10", "failed_logins": 1, "data_transfer": "low"},
    {"ip": "23.21.11.90", "failed_logins": 20, "data_transfer": "high"}
]

#  calculate risk score
def calculate_risk(event):

    score = 0

    if event["failed_logins"] > 10:
        score += 5

    if event["data_transfer"] == "high":
        score += 5

    return score

def get_risk_level(score):

    if score >= 10:
        return "High"

    elif score >= 5:
        return "MEDIUM"

    else:
        return "LOW"

# main
def main():

    print("\n=== RISK SCORE OUTPUT ===\n")

    for event in events:

        score = calculate_risk(event)
        level = get_risk_level(score)

        print(f"{event['ip']} -->> Score: {score} -->> Level: {level}")

main()
