enrichment_db = {
    "evil.com": {"country": "Unknown", "reputation": "malicious"},
    "45.33.32.156": {"country": "RU", "reputation": "malicious"},
    "8.8.8.8": {"country": "US", "reputation": "benign"}
}

print("\nIOC ENRICHMENT:\n")

for ioc in enrichment_db:

    data = enrichment_db[ioc]

    print("IOC:", ioc)
    print("Country:", data["country"])
    print("Reputation:", data["reputation"])
    print()
