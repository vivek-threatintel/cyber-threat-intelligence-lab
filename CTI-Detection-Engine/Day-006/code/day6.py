#  Fake Threat Data

feed = [
    {"ioc": "evil.com", "type": "domain", "severity": "high"},
    {"ioc": "8.8.8.8", "type": "ip", "severity": "medium"},
    {"ioc": "bad.ru", "type": "domain", "severity": "high"},
    {"ioc": "192.168.1.5", "type": "ip", "severity": "low"}
]

# Get high Severity IOCs
def get_high_severity(feed_data):

    high_list = []

    for item in feed_data:
        if item["severity"] == "high":
            high_list.append(item)

    return high_list

# Get only Domain IOCs
def get_domain_iocs(feed_data):

    domain_list = []

    for item in feed_data:
        if item["type"] == "domain":
            domain_list.append(item["ioc"])

    return domain_list

# Main
def main():

    print("\n=== THREAT FEED PROCESSING ===\n")

    # step 1 - high severtiy filter
    high_iocs = get_high_severity(feed)

    # step 2 - only domains from high severity
    high_domains = get_domain_iocs(high_iocs)

    # step 3 - count
    high_count = len(high_iocs)


    print("High Severity IOCs:")
    for item in high_iocs:
        print(item["ioc"], "-", item["severity"])

    print("nHigh Severity Domains:")
    for domain in high_domains:
        print(domain)

    print("\nTotal high Severity Count:", high_count)

main()
