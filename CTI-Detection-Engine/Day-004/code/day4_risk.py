# IOC Risk Classification (Basic Logic)

# Private IP - LOW
# Domain - MEDIUM
# Public IP - HIGH

# raw IOC list
iocs = [
    "milicious.com",
    "192.168.1.5",
    "8.8.8.8",
    "bad-domain.net",
    "10.0.0.3"
]

# check if value looks like IP
def is_ip(value):
    return value.replace(".", "").isdigit()

# check private IP ranges
def is_private_ip(ip):

    # 10.x.x.x
    if ip.startswith("10."):
        return True
    
    # 192.168.x.x
    if ip.startswith("192.168."):
        return True

    # 172.16 - 172.31
    if ip.startswith("172."):
        second = int(ip.split(".")[1])
        if 16 <= second <= 31:
            return True

    return False

#  risk logic
def get_risk(ioc):

    if is_ip(ioc):
        if is_private_ip(ioc):
            return "LOW"
        else:
            return "HIGH"

    return "MEDIUM"

# output
print("\nIOC Risk:\n")

for ioc in iocs:
    print(ioc, ".", get_risk(ioc))
