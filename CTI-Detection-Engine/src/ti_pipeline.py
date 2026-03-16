from feed_ingestion import load_feed
from ioc_processor import process_iocs
from threat_api_client import enrich_ioc_data

def run_pipeline():
    print("🚀 Starting Mini Threat Intelligence Pipeline...\n")

    # STEP 1: Ingestion
    print("[1/4] Ingesting Threat Feed...")
    raw_iocs = load_feed("data/threat_feed.json") # Path dhyan se dena
    if not raw_iocs:
        print("❌ No IOCs to process. Exiting.")
        return

    # STEP 2: Processing
    print(f"[2/4] Processing {len(raw_iocs)} IOCs...")
    processed_data = process_iocs(raw_iocs)
    
    # STEP 3: Enrichment (Focusing on IPs for now)
    print(f"[3/4] Enriching {len(processed_data['ip'])} IPs...")
    enriched_results = []
    for ip in processed_data['ip']:
        details = enrich_ioc_data(ip)
        enriched_results.append(details)

    # STEP 4: Final Output (Detection Ready)
    print("\n--- FINAL PIPELINE OUTPUT ---")
    for res in enriched_results:
        print(f"IOC: {res['ip']} | Score: {res['abuse_score']} | Country: {res['country']} | Status: {'HIGH RISK' if res['abuse_score'] > 80 else 'CLEAN'}")

    print("\n✅ Pipeline Completed Successfully.")

if __name__ == "__main__":
    run_pipeline()
