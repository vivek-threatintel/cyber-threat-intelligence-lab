#  fake threat feed

feed = [
    {"ioc": "evil.com", "type": "domain", "severity": "high"},
    {"ioc": "8.8.8.8", "type": "ip", "severity": "medium"},
    {"ioc": "bad.ru", "type": "domain", "severity": "high"},
    {"ioc": "192.168.1.5", "type": "ip", "severity": "low"}
]

# convert security action
def get_action(severity):

    if severity == "high":
        return "ALERT"

    elif severity == "medium":
        return "WATCH"

    else:
        return "IGNORE"


#  main function
def main():

    print("\n=== ALERT ACTION OUTPUT ===\n")

    for item in feed:
        
        action = get_action(item["severity"])

        print(f"{item['ioc']} -->> {action}")

main()
