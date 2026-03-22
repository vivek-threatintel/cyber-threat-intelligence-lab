import json
import os

def is_ip(ioc):
    parts = ioc.split('.')
    if len(parts) == 4 and all (p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False

def is_domain(ioc):
    if is_ip(ioc):
        return False
    return "." in ioc and "/" not in ioc and ":" not in ioc

def is_hash(ioc):
    return len(ioc) == 64 and all (c in '0123456789abcdefABCDEF' for c in ioc)

def process_iocs(iocs):
    results = {
        "ip": [],
        "domain": [],
        "hash": [],
        "unknown": []
    }

    for ioc in iocs:
        if is_ip(ioc):
            results["ip"].append(ioc)
        elif is_domain(ioc):
            results["domain"].append(ioc)
        elif is_hash(ioc):
            results["hash"].append(ioc)
        else:
            results["unknown"].append(ioc)

    return results

if __name__ == "__main__":
    # Test Data
    test_set = {"103.45.67.89", "malicious-domain.com", "evil-c2.net", "a"*64, "random_text"}
    
    processed_data = process_iocs(test_set)
    
    print("--- IOC Processing Summary ---")
    print(f"Total IOCs: {len(test_set)}")
    print(f"IPs: {len(processed_data['ip'])}")
    print(f"Domains: {len(processed_data['domain'])}")
    print(f"Hashes: {len(processed_data['hash'])}")
    print(f"Unknown: {len(processed_data['unknown'])}")
