from feed_ingestion import load_feed
from ioc_processor import process_iocs
from threat_api_client import enrich_ioc_data
from ioc_database import init_db, insert_ioc, lookup_ioc # Naye imports

def run_pipeline():
    print("🚀 Starting DAY 27 Pipeline (With DB Storage)...\n")
    init_db() # Ensure DB is ready

    # 1. Ingestion
    raw_iocs = load_feed("data/threat_feed.json")
    if not raw_iocs: return

    # 2. Processing
    processed_data = process_iocs(raw_iocs)
    
    # 3. Enrichment & Storage
    print(f"[3/4] Checking and Storing {len(processed_data['ip'])} IPs...")
    
    for ip in processed_data['ip']:
        # Pehle DB mein check karo
        existing = lookup_ioc(ip)
        
        if existing:
            print(f"ℹ️  Cache Hit: {ip} already in Database.")
        else:
            print(f"🔍 New Threat: Enriching {ip} via API...")
            details = enrich_ioc_data(ip)
            # DB mein save karlo agle baar ke liye
            insert_ioc(ip, "ip", "AbuseIPDB", details['abuse_score'])

    print("\n✅ Pipeline with DB Storage Completed.")

if __name__ == "__main__":
    run_pipeline()
