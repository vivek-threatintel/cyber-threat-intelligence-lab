# Mini IOC Checker

#  IOC Input List
iocs = ["8.8.8.8", "192.168.1.1", "evil.com", "10.0.0.5"]

#  Check if value looks like ip
def is_ip(value):
    return value.replace(".", "").isdigit()

#  check if ip is private
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

#  Assign Risk
def get_risk(ioc):

    if is_ip(ioc):

        if is_private(ioc):
            return "LOW"

        else:
            return "MEDIUM"

     #  domain risk (simple model)
    return "HIGH"

#  main tool output
def main():

    print("\n=== MINI IOC CHECKER ===\n")

    for ioc in iocs:

        if is_ip(ioc):

            if is_private(ioc):
                print(ioc, "-->> PRIVATE -->> LOW")

            else:
                print(ioc, "-->> PUBLIC -->> MEDIUM")

        else:
            print(ioc, "-->> DOMAIN -->> HIGH")

main()
