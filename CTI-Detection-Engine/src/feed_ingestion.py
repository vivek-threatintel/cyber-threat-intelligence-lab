import json
import os

def load_feed(file_path="threat_feed.json"):
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found!")
        return set()

    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        iocs = set()

        # Agar data list of strings hai
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    cleaned = item.strip()
                    if cleaned:
                        iocs.add(cleaned)
                elif isinstance(item, dict):
                    ioc = item.get("ioc") or item.get("value")  # dono key try kar
                    if isinstance(ioc, str):
                        cleaned = ioc.strip()
                        if cleaned:
                            iocs.add(cleaned)

        print(f"Total Unique IOCs loaded: {len(iocs)}")
        return iocs

    except Exception as e:
        print(f"Unexpected error: {e}")
        return set()

if __name__ == "__main__":
    threat_set = load_feed()
    print("_" * 30)
    print(f"Total Unique IOCs: {len(threat_set)}")

    if threat_set:
        first_three = list(threat_set)[:3]
        print("First 3 IOCs:")
        for ioc in first_three:
            print(f"  - {ioc}")

    else:
        print("No IOCs Found.")
    print("_" * 30)
