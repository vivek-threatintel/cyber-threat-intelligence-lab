high_count = 0
medium_count = 0
low_count = 0

internal_iocs = []
external_iocs = []

for item in threat_feed:

    if item["severity"] == "high":
        print(item["ioc"])

    if item["severity"] == "high":
        high_count += 1

    elif item["severity"] == "medium":
        medium_count += 1

    elif item["severity"] == "low":
        low_count += 1

    if item["source"] == "internal":
        internal_iocs.append(item["ioc"])

    else:
        external_iocs.append(item["ioc"])
