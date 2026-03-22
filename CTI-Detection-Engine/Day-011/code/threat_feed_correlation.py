feed1 = [
    {"ioc": "evil.com", "source": "ThreatFox"},
    {"ioc": "45.33.32.156", "source": "AlienVault"},
    {"ioc": "8.8.8.8", "source": "OSINT"}
]

feed2 = [
    {"ioc": "evil.com", "source": "VirusTotal"},
    {"ioc": "23.21.11.90", "source": "ThreatFox"},
    {"ioc": "8.8.8.8", "source": "Internal"}
]

combined = feed1 + feed2

ioc_count = {}

for item in combined:
    ioc = item["ioc"]

    if ioc not in ioc_count:
        ioc_count[ioc] = 0

    ioc_count[ioc] += 1

print("\nIOC COUNT:\n")

for ioc, count in ioc_count.items():
    print(ioc, "→", count, "sources")
