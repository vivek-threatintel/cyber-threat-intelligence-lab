import json
from typing import List, Dict, Any, Optional, Tuple

# ────────────────────────────────────────────────
# 1. Data Loading Layer
# ────────────────────────────────────────────────

def load_lookup(file_path: str = "ioc_lookup.json") -> Dict[str, Dict[str, str]]:
    """Load the static IOC lookup database."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Lookup file must contain a dictionary")
        return data
    except FileNotFoundError:
        print(f"[ERROR] Lookup file not found: {file_path}")
        return {}
    except (json.JSONDecodeError, ValueError) as e:
        print(f"[ERROR] Invalid lookup file format: {e}")
        return {}


def load_feed(file_path: str = "external_feed.json") -> List[Dict[str, Any]]:
    """Load the external IOC feed (list of dicts)."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("Feed file must contain a list")
        return data
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        print(f"[ERROR] Failed to load feed: {e}")
        return []


# ────────────────────────────────────────────────
# 2. Matching & Enrichment Layer
# ────────────────────────────────────────────────

def get_feed_iocs(feed: List[Dict[str, Any]]) -> set[str]:
    """Extract unique IOC strings from feed for fast lookup."""
    iocs = set()
    for entry in feed:
        if isinstance(entry, dict):
            ioc = entry.get("ioc")
            if isinstance(ioc, str) and ioc.strip():
                iocs.add(ioc.strip())
    return iocs


def match_log(
    network_log: List[str],
    feed_iocs: set[str]
) -> List[str]:
    """
    Return only those log entries that appear in the feed.
    (fast pre-filter before enrichment)
    """
    matched = []
    for entry in network_log:
        cleaned = entry.strip()
        if cleaned in feed_iocs:
            matched.append(cleaned)
    return matched


def enrich_match(
    ioc: str,
    lookup_db: Dict[str, Dict[str, str]]
) -> Dict[str, Any]:
    """Enrich a single matched IOC using the lookup database."""
    if ioc not in lookup_db:
        return {
            "ioc": ioc,
            "confidence": "low",
            "country": "N/A",
            "malware_family": "N/A",
            "first_seen": "N/A"
        }

    info = lookup_db[ioc]
    return {
        "ioc": ioc,
        "confidence": "high",
        "country": info.get("country", "N/A"),
        "malware_family": info.get("malware_family", "N/A"),
        "first_seen": info.get("first_seen", "N/A")
    }


# ────────────────────────────────────────────────
# 3. Risk Scoring Layer
# ────────────────────────────────────────────────

def assign_risk(enriched: Dict[str, Any]) -> str:
    """Assign risk level based on enrichment result."""
    conf = enriched.get("confidence", "low").lower()
    malware = enriched.get("malware_family", "N/A").strip()

    if conf == "high" and malware and malware != "N/A":
        return "HIGH RISK"
    if conf == "high" or conf == "medium":
        return "MEDIUM RISK"
    return "LOW RISK"


# ────────────────────────────────────────────────
# 4. Reporting Layer
# ────────────────────────────────────────────────

def generate_summary(
    enriched_results: List[Dict[str, Any]],
    total_logs: int
) -> Dict[str, Any]:
    """
    Generate final summary statistics.
    Returns dict that can be used for printing or saving.
    """
    high = sum(1 for r in enriched_results if r["risk"] == "HIGH RISK")
    medium = sum(1 for r in enriched_results if r["risk"] == "MEDIUM RISK")
    matches = len(enriched_results)

    return {
        "total_logs_analyzed": total_logs,
        "threat_matches": matches,
        "high_risk_alerts": high,
        "medium_risk_alerts": medium
    }


# ────────────────────────────────────────────────
# Main Execution Flow (Orchestration)
# ────────────────────────────────────────────────

if __name__ == "__main__":
    # 1. Load data sources
    lookup_db = load_lookup()
    feed_data = load_feed()

    if not lookup_db:
        print("Cannot continue without lookup database.")
        exit(1)

    # 2. Prepare fast lookup sets
    feed_iocs_set = get_feed_iocs(feed_data)

    # 3. Find matches in network log
    matched_iocs = match_log(network_log, feed_iocs_set)

    # 4. Enrich & score
    enriched_results = []
    for ioc in matched_iocs:
        enriched = enrich_match(ioc, lookup_db)
        risk = assign_risk(enriched)
        enriched["risk"] = risk
        enriched_results.append(enriched)

    # 5. Generate & print report
    summary = generate_summary(enriched_results, len(network_log))

    print("\n" + "="*70)
    print(" CTI INTEGRATED DETECTION REPORT ".center(70))
    print("="*70 + "\n")

    if not enriched_results:
        print("No threats detected in this log batch.\n")
    else:
        for item in enriched_results:
            print("=== THREAT DETECTED ===")
            print(f"IOC             : {item['ioc']}")
            print(f"Confidence      : {item['confidence']}")
            print(f"Country         : {item['country']}")
            print(f"Malware Family  : {item['malware_family']}")
            print(f"First Seen      : {item['first_seen']}")
            print(f"Risk Level      : {item['risk']}")
            print("-" * 60)

    print("\nSUMMARY")
    print("-" * 60)
    print(f"Total logs analyzed     : {summary['total_logs_analyzed']}")
    print(f"Threat matches          : {summary['threat_matches']}")
    print(f"High risk alerts        : {summary['high_risk_alerts']}")
    print(f"Medium risk alerts      : {summary['medium_risk_alerts']}")
    print("-" * 60)
