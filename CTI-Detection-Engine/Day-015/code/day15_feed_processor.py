import json
import os

def load_feed(filename):
    if not os.path.exists(filename):
        print(f"Error: {filename} not found")
        return []

    try:
        with open(filename, "r") as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError:
        print("Invalid JSON format")
        return []

def assign_priority(confidence):
    priority_map = {
        "high": 3,
        "medium": 2,
        "low": 1
    }
    return priority_map.get(confidence.lower(), 1)

def process_feed(feed):
    print("\n=== CTI FEED REPORT ===")

    for item in feed:
        priority = assign_priority(item["confidence"])

        print(f"\nIOC: {item['ioc']}")
        print(f"Type: {item['type']}")
        print(f"Confidence: {item['confidence']}")
        print(f"Source: {item['source']}")
        print(f"Priority: {priority}")

    print(f"\nTotal IOCs: {len(feed)}")

def main():
    feed = load_feed("external_feed.json")

    if feed:
        process_feed(feed)
    else:
        print("No feed loaded")

if __name__ == "__main__":
    main()
