for item in threat_feed:

    severity = item["severity"]
    ioc = item["ioc"]

    if severity == "high":
        action = "ALERT"

    elif severity == "medium":
        action = "MONITOR"

    else:
        action = "IGNORE"

    print(f"{ioc} -->> {action}")
