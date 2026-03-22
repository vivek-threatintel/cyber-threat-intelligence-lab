import json

def load_lookup(file_path="ioc_lookup.json"):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        print(f"[+] Lookup database loaded: {len(data)} IOCs")
        return data
    except Exception as e:
        print(f"[-] Lookup load failed: {e}")
        return {}

def load_feed(file_path="external_feed.json"):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        print(f"[+] Feed loaded: {len(data)} entries")
        return data
    except Exception as e:
        print(f"[-] Feed load failed: {e}")
        return []

def enrich_ioc(ioc_str, lookup_db, feed_conf="low"):
    if not ioc_str or not isinstance(ioc_str, str):
        return {
            "confidence": "low",
            "country": "N/A",
            "malware_family": "N/A",
            "first_seen": "N/A"
        }

    if ioc_str in lookup_db:
        info = lookup_db[ioc_str]
        return {
            "confidence": feed_conf.lower(),
            "country": info.get("country", "N/A"),
            "malware_family": info.get("malware_family", "N/A"),
            "first_seen": info.get("first_seen", "N/A")
        }
    else:
        return {
            "confidence": feed_conf.lower(),
            "country": "N/A",
            "malware_family": "N/A",
            "first_seen": "N/A"
        }

def assign_risk(enriched):
    conf = enriched.get("confidence", "low").lower()
    malware = enriched.get("malware_family", "N/A")

    if conf == "high" and malware != "N/A":
        return "HIGH RISK"
    elif conf == "high":
        return "MEDIUM RISK"
    elif conf == "medium":
        return "MEDIUM RISK"
    else:
        return "LOW RISK"

if __name__ == "__main__":
    lookup_db = load_lookup()
    feed = load_feed()

    if not lookup_db or not feed:
        print("[-] Cannot proceed – check JSON files")
    else:
        print("\n" + "="*60)
        print("        IOC ENRICHMENT & RISK REPORT")
        print("="*60 + "\n")

        for entry in feed:
            ioc = entry.get("ioc", "").strip()
            feed_conf = entry.get("confidence", "low")

            if not ioc:
                print(f"[!] Skipping invalid entry: {entry}")
                continue

            enriched = enrich_ioc(ioc, lookup_db, feed_conf)
            risk = assign_risk(enriched)

            print(f"IOC          : {ioc}")
            print(f"  Confidence : {enriched['confidence']}")
            print(f"  Country    : {enriched['country']}")
            print(f"  Malware    : {enriched['malware_family']}")
            print(f"  First Seen : {enriched['first_seen']}")
            print(f"  Risk Level : {risk}")
            print("-" * 60)
