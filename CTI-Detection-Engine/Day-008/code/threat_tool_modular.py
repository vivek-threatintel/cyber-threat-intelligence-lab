# Filter Function
def filter_high_severity(feed):

    high_list = []

    for item in feed:

        if item["severity"] == "high":
            high_list.append(item)

    return high_list

# Alert Generation Function
def generate_alert(severity):

    if severity == "high":
        return "ALERT"

    elif severity == "medium":
        return "MONITOR"

    else:
        return "IGNORE"

# Summary Output Function
def print_summary(feed):

    for item in feed:

        ioc = item["ioc"]
        severity = item["severity"]

        action = generate_alert(severity)

        print(f"{ioc} -->> {action}")

# Execution
print_summary(threat_feed)
