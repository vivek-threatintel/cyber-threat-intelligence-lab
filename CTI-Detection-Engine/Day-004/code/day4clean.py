iocs = [
    "milicious.com",
    "192.168.1.5",
    "8.8.8.8",
    "bad-domain.net",
    "10.0.0.3",
    "172.20.5.4",
]

# check if strings look like IP
def is_ip(value):
    return value.replace(".", "").isdigit()

# check if ip is private
def is_private(ip):

    if ip.startswith("10."):
        return True
    
    if ip.startswith("192.168."):
        return True

    if ip.startswith("172."):
        second = int(ip.split(".")[1])
        if 16 <= second <= 31:
            return True

    return False

# decide risk
def get_risk(ioc):

    if is_ip(ioc):

        if is_private(ioc):
            return "LOW"
        else:
            return "HIGH"
    else:
        return "MEDIUM"

# Main run
def main():

    print("\nIOC Risk Output:\n")

    for ioc in iocs:
        print(ioc, ":", get_risk(ioc))

main()
