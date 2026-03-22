# Raw IOC data
iocs = [
    {"value": "8.8.8.8", "type": "ip"},
    {"value": "45.33.32.156", "type": "ip"},
    {"value": "evil-domain.com", "type": "domain"},
    {"value": "192.168.1.10", "type": "ip"}
]

# Enrichment database
enrichment = {
    "8.8.8.8": {"country": "US", "reputation": "benign"},
    "45.33.32.156": {"country": "RU", "reputation": "malicious"},
    "evil-domain.com": {"country": "Unknown", "reputation": "malicious"},
    "192.168.1.10": {"country": "Internal", "reputation": "safe"}
}

def enrich_ioc(iocs, enrichment):
    enriched_list = []

    for item in iocs:
        value = item["value"]
        type_ = item["type"]

        country = enrichment[value]["country"]
        reputation = enrichment[value]["reputation"]

        merged = {
            "value": value,
            "type": type_,
            "country": country,
            "reputation": reputation
        }

        enriched_list.append(merged)

    return enriched_list


def classify_risk(reputation):

    if reputation == "malicious":
        return "HIGH"

    elif reputation in ("benign", "safe"):
        return "LOW"

    else:
        return "MEDIUM"


def print_report(enriched_iocs):

    print("\nIOC REPORT\n")

    for item in enriched_iocs:

        risk = classify_risk(item["reputation"])

        print("IOC:", item["value"])
        print("Country:", item["country"])
        print("Reputation:", item["reputation"])
        print("Risk Level:", risk)
        print()


# Main execution
enriched_iocs = enrich_ioc(iocs, enrichment)
print_report(enriched_iocs)
