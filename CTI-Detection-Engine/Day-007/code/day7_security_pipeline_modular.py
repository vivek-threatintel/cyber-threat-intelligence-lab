# Fake Security Event Data

events = [
 {"ip": "8.8.8.8", "failed_logins": 2, "data_transfer": "low"},
 {"ip": "45.33.32.1", "failed_logins": 15, "data_transfer": "high"},
 {"ip": "192.168.1.10", "failed_logins": 1, "data_transfer": "low"},
 {"ip": "23.21.11.90", "failed_logins": 20, "data_transfer": "high"}
]


# Detection Function
def det_fun(event):

    if event["failed_logins"] > 10:
        return True

    if event["data_transfer"] == "high":
        return True

    return False


# Risk Score Function
def risk_scor_func(event):

    score = 0

    if event["failed_logins"] > 10:
        score += 5

    if event["data_transfer"] == "high":
        score += 5

    return score


# Risk Level Function
def risk_level(score):

    if score >= 10:
        return "HIGH"

    elif score >= 5:
        return "MEDIUM"

    else:
        return "LOW"


# Output Function
def print_output(event, score, level, suspicious):

    print(f"IP: {event['ip']}")
    print(f"Suspicious: {suspicious}")
    print(f"Risk Score: {score}")
    print(f"Risk Level: {level}")
    print("-" * 30)


# Main Pipeline
def main():

    print("\n=== SECURITY PIPELINE OUTPUT ===\n")

    for event in events:

        suspicious = det_fun(event)
        score = risk_scor_func(event)
        level = risk_level(score)   

        print_output(event, score, level, suspicious)


main()
