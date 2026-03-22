# The log of what actually happened on our network
network_log = [
    {"ip": "8.8.8.8", "action": "connect"},
    {"ip": "45.33.32.156", "action": "connect"},
    {"ip": "192.168.1.10", "action": "connect"},
    {"ip": "evil.com", "action": "dns_request"}
]

# Our "blacklist" of known bad actors
threat_feed = [
    {"ioc": "45.33.32.156", "confidence": "high"},
    {"ioc": "evil.com", "confidence": "high"},
    {"ioc": "23.21.11.90", "confidence": "medium"}
]

def match_ioc(log_entry, threat_entry):                    #fun 1 for compare 

    if log_entry['ip'] == threat_entry['ioc']:
        return "Match Found"
    return None

def assign_priority(confidence_level):          #fun 2 for priority assign
    if confidence_level == "high":
        return "Critical Priority"
    elif confidence_level == "medium":
        return "High Priority"
    else:
        return "Medium Priority"

def generate_alert(match_status, priority_level, log_data, threat_data):           # fun3 for generate alert
    print("\nALERT: Milicious IOC Detected!")
    print(f"IP:, {log_data['ip']}")
    print(f"IOC:, {threat_data['ioc']}")
    print(f"Compare:, {match_status}")
    print(f"Priority, {priority_level}")
    print(f"Confidence: {threat_data['confidence']}")
    print()

def main():
     for log in network_log:
        for threat in threat_feed:
            match_result = match_ioc(log, threat)

            if match_result:
                priority = assign_priority(threat['confidence'])
            
                generate_alert(match_result, priority, log, threat)

main()
