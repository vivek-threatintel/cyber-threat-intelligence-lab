import requests

def simulate_threat_lookup(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip}
    print(f"Simulating lookup for {ip}...")
    # Real call (comment out if no key)
    # response = requests.get(url, params=params, headers={"Key": "YOUR_API_KEY"})
    # return response.json()

    # Simulated response (for now)
    return {
        "ip": ip,
        "abuseConfidenceScore": 90,
        "country": "RU",
        "isp": "Unknown ISP"
    }

# Test
result = simulate_threat_lookup("103.45.67.89")
print(result)

result = simulate_threat_lookup("103.45.67.89")

def parse_api_response(api_data):
    return {
        "ip": api_data.get("ip", "unknown"),
        "abuse_score": api_data.get("abuseConfidenceScore", 0),
        "country": api_data.get("country", "N/A"),
        "isp": api_data.get("isp", "N/A")
    }

parsed = parse_api_response(result)
print("Threat Intel Enrichment:")
for k, v in parsed.items():
    print(f"  {k}: {v}")


def query_threat_api(ip):
    # Yeh function real API call ke liye hai (abhi simulate kar rahe hain)
    print(f"Querying threat intel API for IP: {ip}")
    
    # Simulated response (real key daal ke uncomment kar sakta hai)
    return {
        "ip": ip,
        "abuseConfidenceScore": 90,
        "country": "RU",
        "isp": "Unknown ISP",
        "lastReported": "2026-03-10"
    }

def enrich_ioc_data(ip):
    api_data = query_threat_api(ip)  # ← yeh call sahi hai
    parsed = parse_api_response(api_data)
    return parsed

def query_threat_api(ip):
    print(f"Querying threat intel API for IP: {ip}")
    # Real call (comment out if no key)
    # url = "https://api.abuseipdb.com/api/v2/check"
    # params = {"ipAddress": ip}
    # headers = {"Key": "YOUR_KEY"}
    # response = requests.get(url, params=params, headers=headers)
    # return response.json() if response.status_code == 200 else {}

    # Simulated response
    return {
        "ip": ip,
        "abuseConfidenceScore": 90,
        "country": "RU",
        "isp": "Unknown ISP",
        "lastReported": "2026-03-10"
    }

if __name__ == "__main__":
    test_ip = "103.45.67.89"
    enriched = enrich_ioc_data(test_ip)
    print("Enriched IOC Data:")
    for k, v in enriched.items():
        print(f"  {k}: {v}")
