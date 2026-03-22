#  fake threat feed data

feed = [
    {"ioc": "evil.com", "type": "domain", "severity": "high"},
    {"ioc": "8.8.8.8", "type": "ip", "severity": "medium"},
    {"ioc": "bad.ru", "type": "domain", "severity": "high"},
    {"ioc": "192.168.1.5", "type": "ip", "severity": "low"}
]

# filter high severity feed 
def filter_high(feed_data):

    result = []

    for item in feed_data:
        if item["severity"] == "high":
            result.append(item)

    return result

# assign alear action
def get_alert(severity):

    if severity == "high":
        return "ALERT"

    elif severity == "medium":
        return "WATCH"

    else:
        return "IGNORE"

# main func
def main():

    print("\n=== THREAT ALERT OUTPUT ===\n")

    # step1 - filter high severity
    high_feed = filter_high(feed)

    # step2 - process alert logic
    for item in high_feed:
        action = get_alert(item["severity"])
        print(f"{item['ioc']} -->> {action}")

main()
