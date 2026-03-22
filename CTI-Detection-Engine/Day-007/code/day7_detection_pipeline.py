#  fake security event data

events = [
    {"ip": "8.8.8.8", "failed_logins": 2, "data_transfer": "low"},
    {"ip": "45.33.32.1", "failed_logins": 15, "data_transfer": "high"},
    {"ip": "192.168.1.10", "failed_logins": 1, "data_transfer": "low"},
    {"ip": "23.21.10.90", "failed_logins": 20, "data_transfer": "high"}
]

#  check if event is suspicious
def is_suspicious(event):

    # rule1 - too many failed logins
    if event["failed_logins"] > 10:
        return True

    # rule2- high data transfer
    if event["data_transfer"] == "high":
        return True

        return False

#  main pipeline
def main():

    print("\n=== MINI SECURITY PIPELINE ===\n")

    suspicious_ips = []

    for event in events:
        if is_suspicious(event):
            suspicious_ips.append(event["ip"])


    print("suspicious IPs: ")

    for ip in suspicious_ips:
        print(ip)

main()
